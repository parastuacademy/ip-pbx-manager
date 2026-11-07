"""External REST API — /api/v1 — lets other software talk to the PBX.

Design rules (deliberate, keep them):
  - JSON only, consistent envelope: {"ok": true, "data": ...} on success,
    {"ok": false, "error": {"code", "message"}} on failure.
  - Auth via API key (Authorization: Bearer … or X-API-Key). Keys are
    sha256-hashed in the database, revocable, optionally IP-restricted.
    AMI is never exposed through this layer.
  - Small surface, versioned path, machine-readable English error codes
    (docs for integrators are Persian: docs/API.md).

Endpoints (v1, intentionally minimal):
  GET    /api/v1/ping                        service identity (no auth)
  POST   /api/v1/calls/click-to-call         agent phone rings, then the target
  GET    /api/v1/calls                       call log (filters + pagination)
  GET    /api/v1/calls/<uniqueid>            one call
  GET    /api/v1/calls/<uniqueid>/recording  recording file download
  GET    /api/v1/extensions                  extensions + online status
  GET    /api/v1/trunk                       trunk registration status
  GET    /api/v1/webhooks                    list webhooks
  POST   /api/v1/webhooks                    create webhook
  DELETE /api/v1/webhooks/<id>               delete webhook
  POST   /api/v1/webhooks/<id>/test          send a test event
"""
import hashlib
import ipaddress
import re
import threading
import time

from flask import Blueprint, g, jsonify, request, send_file

from . import cdr, config_gen, db, webhooks
from .ami import AMIClient, AMIError

bp = Blueprint("api", __name__, url_prefix="/api/v1")

RATE_LIMIT = 120          # requests per key per window
RATE_WINDOW = 60          # seconds

_EXT_RE = re.compile(r"[0-9]{3,20}")

_rate = {}          # key_id -> [count, window_start]
_rate_lock = threading.Lock()
_last_touch = {}    # key_id -> ts (throttle last_used DB writes)
_authfail_logged = {}  # ip -> ts (throttle security_log writes)


# ------------------------------------------------------------------ helpers
def _ok(data=None, meta=None, status=200):
    body = {"ok": True, "data": data}
    if meta is not None:
        body["meta"] = meta
    return jsonify(body), status


def _err(status, code, message, headers=None):
    resp = jsonify(ok=False, error={"code": code, "message": message})
    if headers:
        for k, v in headers.items():
            resp.headers[k] = v
    return resp, status


def _body_json():
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    if request.form:  # tolerate form posts
        return request.form.to_dict()
    return {}


def _ip_allowed(ip_allow, remote_ip):
    """ip_allow: comma-separated IPs/CIDRs ('' = any)."""
    if not ip_allow.strip():
        return True
    if not remote_ip:
        return False
    for item in ip_allow.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            if ipaddress.ip_address(remote_ip) in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue  # malformed entry never grants access
    return False


def _log_authfail_once(ip):
    now = time.time()
    if now - _authfail_logged.get(ip, 0) > 60:
        _authfail_logged[ip] = now
        db.log_event("api_auth_fail", f"IP {ip}")


# --------------------------------------------------------------------- auth
@bp.before_request
def _auth():
    if request.path.rstrip("/") == "/api/v1/ping":
        return None
    raw = None
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        raw = header[7:].strip()
    raw = raw or request.headers.get("X-API-Key", "").strip()
    if not raw:
        _log_authfail_once(request.remote_addr or "?")
        return _err(401, "missing_key",
                    "Provide the API key via 'Authorization: Bearer <key>' "
                    "or 'X-API-Key'.")
    key = db.get_api_key_by_secret(raw)
    if key is None:
        _log_authfail_once(request.remote_addr or "?")
        return _err(401, "invalid_key", "Unknown or revoked API key.")
    if not _ip_allowed(key["ip_allow"] or "", request.remote_addr):
        db.log_event("api_ip_denied", f"key {key['prefix']}… from "
                     f"IP {request.remote_addr}")
        return _err(403, "ip_not_allowed",
                    "This key is restricted to other source IPs.")
    now = time.time()
    with _rate_lock:
        count, started = _rate.get(key["id"], [0, now])
        if now - started > RATE_WINDOW:
            count, started = 0, now
        count += 1
        _rate[key["id"]] = [count, started]
        if len(_rate) > 500:
            _rate.clear()  # simple guard against unbounded growth
    if count > RATE_LIMIT:
        return _err(429, "rate_limited",
                    f"More than {RATE_LIMIT} requests per minute.",
                    headers={"Retry-After": str(int(RATE_WINDOW - (now - started)))})
    if now - _last_touch.get(key["id"], 0) > 30:
        _last_touch[key["id"]] = now
        db.touch_api_key(key["id"])
    g.api_key = key
    return None


# -------------------------------------------------------------------- ping
@bp.get("/ping")
def ping():
    from . import VERSION  # lazy — avoids a circular import at module load
    return _ok({"service": "ip-pbx-manager", "api": "v1", "version": VERSION})


# ----------------------------------------------------------- click-to-call
@bp.post("/calls/click-to-call")
def click_to_call():
    body = _body_json()
    agent = str(body.get("agent", "")).strip()
    dest = str(body.get("destination", "")).strip()
    timeout = str(body.get("timeout", "45")).strip()
    if not agent or not dest:
        return _err(422, "invalid_input",
                    "Fields 'agent' and 'destination' are required.")
    if not db.get_extension(agent):
        return _err(422, "unknown_extension",
                    f"Extension '{agent}' does not exist on this PBX.")
    if not (timeout.isdigit() and 5 <= int(timeout) <= 120):
        timeout = "45"
    if db.get_extension(dest):
        context = "internal"
    elif _EXT_RE.fullmatch(dest):
        context = "outbound"  # generated dialplan routes it via the trunk
    else:
        return _err(422, "invalid_destination",
                    "'destination' must be an existing extension number or "
                    "an external number (3-20 digits, e.g. 02112345678).")
    try:
        with AMIClient() as client:
            client.originate(f"PJSIP/{agent}", context, dest, timeout=int(timeout),
                             variable="CDR(userfield)=api")
    except AMIError as exc:
        return _err(503, "asterisk_unreachable",
                    f"Asterisk is not reachable: {exc}")
    db.log_event("api_c2c", f"key {g.api_key['prefix']}…: {agent} -> {dest}")
    return _ok({"agent": agent, "destination": dest, "context": context,
                "timeout": int(timeout)}, status=202)


# ----------------------------------------------------------------- calls
def _call_view(row):
    view = dict(row)
    view["direction"] = cdr.call_direction(row)
    return view


@bp.get("/calls")
def list_calls():
    args = request.args
    q = args.get("q", "").strip()
    date = args.get("date", "").strip()
    dispo = args.get("disposition", "").strip()
    try:
        limit = min(max(int(args.get("limit", "100")), 1), 1000)
        offset = max(int(args.get("offset", "0")), 0)
    except ValueError:
        return _err(422, "invalid_input", "'limit' and 'offset' must be integers.")
    if dispo and dispo not in cdr._KNOWN_DISPO:
        return _err(422, "invalid_input",
                    "'disposition' must be one of: " + ", ".join(sorted(cdr._KNOWN_DISPO)))
    rows, total = cdr.read_cdr(q=q, date=date, disposition=dispo,
                               limit=limit, offset=offset)
    return _ok([_call_view(r) for r in rows],
               meta={"total": total, "limit": limit, "offset": offset,
                     "note": "search covers the last 5000 calls"})


@bp.get("/calls/<string:uniqueid>")
def get_call(uniqueid):
    rows, total = cdr.read_cdr(limit=cdr.MAX_LINES)
    for row in rows:
        if row["uniqueid"] == uniqueid:
            return _ok(_call_view(row))
    return _err(404, "not_found", f"No call with uniqueid '{uniqueid}'.")


@bp.get("/calls/<string:uniqueid>/recording")
def call_recording(uniqueid):
    path = cdr.find_recording(uniqueid)
    if not path:
        return _err(404, "no_recording",
                    "No recording exists for this call (recording may be "
                    "disabled for the involved extensions).")
    return send_file(path, mimetype="audio/wav", as_attachment=False)


# ------------------------------------------------------------- extensions
@bp.get("/extensions")
def list_extensions():
    try:
        with AMIClient() as client:
            online = client.online_extensions()
        ami = True
    except AMIError:
        online, ami = set(), False
    out = [{"ext": e["ext"], "display_name": e["display_name"],
            "record": bool(int(e["record"] or 0)),
            "voicemail": bool(int(e["voicemail"] or 0)),
            "online": (e["ext"] in online) if ami else None}
           for e in db.list_extensions()]
    return _ok(out, meta={"ami_online": ami,
                          "online": None if not ami else [e["ext"] for e in out if e["online"]]})


@bp.get("/trunk")
def trunk_status():
    try:
        with AMIClient() as client:
            registered = client.trunk_registered()
        return _ok({"trunk": config_gen.TRUNK_NAME, "registered": registered,
                    "ami_online": True})
    except AMIError as exc:
        return _ok({"trunk": config_gen.TRUNK_NAME, "registered": None,
                    "ami_online": False}, meta={"detail": str(exc)[:120]})


# ---------------------------------------------------------------- webhooks
def _webhook_view(wh, include_secret=False):
    view = {"id": wh["id"], "url": wh["url"],
            "events": [e for e in (wh["events"] or "").split(",") if e],
            "active": bool(int(wh["active"] or 0)),
            "created_at": wh["created_at"],
            "last_status": wh["last_status"]}
    if include_secret:
        view["secret"] = wh["secret"]
    elif wh["secret"]:
        view["secret_hint"] = wh["secret"][:12] + "…"
    return view


@bp.get("/webhooks")
def list_webhooks():
    return _ok([_webhook_view(w) for w in db.list_webhooks()])


@bp.post("/webhooks")
def create_webhook():
    body = _body_json()
    url = str(body.get("url", "")).strip()
    if not url.startswith(("http://", "https://")) or len(url) < 12:
        return _err(422, "invalid_input", "'url' must be an http(s) URL.")
    events = body.get("events") or ["call.ended", "call.missed"]
    if isinstance(events, str):
        events = [e.strip() for e in events.split(",") if e.strip()]
    bad = [e for e in events if e not in db.WEBHOOK_EVENTS]
    if bad:
        return _err(422, "invalid_input",
                    "Unknown events: " + ", ".join(bad) +
                    ". Allowed: " + ", ".join(db.WEBHOOK_EVENTS))
    if not events:
        return _err(422, "invalid_input", "Pick at least one event.")
    secret = str(body.get("secret", "")).strip() or db.gen_webhook_secret()
    active = 0 if str(body.get("active", "1")).lower() in ("0", "false", "no") else 1
    wid = db.create_webhook(url, events, secret, active)
    db.log_event("api_webhook_add", f"key {g.api_key['prefix']}…: {url}")
    return _ok(_webhook_view(db.get_webhook(wid), include_secret=True),
               meta={"secret_note": "Save the secret now — it is returned "
                    "in full only once (at creation)."}, status=201)


@bp.delete("/webhooks/<int:webhook_id>")
def delete_webhook(webhook_id):
    if db.get_webhook(webhook_id) is None:
        return _err(404, "not_found", f"No webhook #{webhook_id}.")
    db.delete_webhook(webhook_id)
    return _ok({"deleted": webhook_id})


@bp.post("/webhooks/<int:webhook_id>/test")
def test_webhook(webhook_id):
    wh = db.get_webhook(webhook_id)
    if wh is None:
        return _err(404, "not_found", f"No webhook #{webhook_id}.")
    webhooks.emit_event("webhook.test", {"note": "test delivery from "
                        "ip-pbx-manager", "webhook_id": webhook_id},
                        webhook_id=webhook_id)
    return _ok({"queued": True, "webhook_id": webhook_id,
                "note": "Delivery happens in the background within seconds; "
                        "watch this webhook's 'last_status'."})
