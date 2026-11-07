"""Webhook engine — pushes call events to registered HTTP endpoints.

Flow: the CDR tailer (same robust pattern as the notifier) watches
Master.csv for new rows, derives events from each row, and queues one
delivery per subscribed webhook. A single background thread (guarded by an
flock so it never duplicates across processes) delivers due entries with
HMAC-SHA256 signatures and retries: 15s, 60s, 300s, then gives up.

Events (fire after the call has finished — CDR based, hence reliable):
  call.ended     every completed call
  call.answered  calls that were answered
  call.missed    calls that were not answered (busy / no answer / failed)

Delivery POST body (exact bytes are signed):
  {"event": "call.missed", "occurred_at": "...", "data": {...}}
Headers:
  Content-Type: application/json
  X-PBX-Event: call.missed
  X-PBX-Delivery-Id: <queue id>
  X-PBX-Signature: sha256=<hex hmac of body with the webhook secret>
"""
import fcntl
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.request

from . import cdr, db

_lock_path = os.path.join(db.DATA_DIR, "webhooks.lock")
_cdr_path = cdr.CDR_PATH

RETRY_DELAYS = {1: 15, 2: 60, 3: 300}  # attempt -> seconds until next try
MAX_ATTEMPTS = 4

_tick_lock = threading.Lock()
_start_lock = threading.Lock()
_last_size = None
_ticks = 0


# ------------------------------------------------------------------ emit
def emit_event(event, payload_data, webhook_id=None):
    """Queue an event for delivery to all subscribed (or one) webhooks."""
    body = json.dumps({
        "event": event,
        "occurred_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "data": payload_data,
    }, ensure_ascii=False)
    now = time.time()
    for wh in db.list_webhooks():
        if webhook_id is not None and wh["id"] != webhook_id:
            continue
        if not int(wh["active"] or 0):
            continue
        if event not in (wh["events"] or "").split(","):
            continue
        db.enqueue_webhook(wh["id"], event, body, now)


def emit_call_events(row):
    """Derive and queue the call.* events for one finished CDR row."""
    data = {k: row.get(k, "") for k in ("uniqueid", "src", "dst", "start",
                                        "answer", "end", "duration",
                                        "billsec", "disposition")}
    data["direction"] = cdr.call_direction(row)
    emit_event("call.ended", data)
    if (row.get("disposition") or "").strip() == "ANSWERED":
        emit_event("call.answered", data)
    else:
        emit_event("call.missed", data)


# ---------------------------------------------------------------- CDR tail
def _scan_cdr():
    global _last_size
    if not os.path.exists(_cdr_path):
        _last_size = 0
        return
    size = os.path.getsize(_cdr_path)
    if size < _last_size:  # rotated/truncated
        _last_size = 0
    if size == _last_size:
        return
    with open(_cdr_path, "rb") as fh:
        fh.seek(_last_size)
        chunk = fh.read(size - _last_size)
    nl = chunk.rfind(b"\n")
    if nl < 0:
        return  # wait for the rest of the line on the next tick
    complete, _partial = chunk[: nl + 1], chunk[nl + 1:]
    _last_size = size - len(_partial)
    import csv as _csv
    for line in complete.decode("utf-8", "replace").splitlines():
        try:
            row = next(_csv.reader([line]))
        except StopIteration:
            continue
        idx, dispo = None, ""
        for i, cell in enumerate(row):
            if cell.strip() in cdr._KNOWN_DISPO:
                idx, dispo = i, cell.strip()
                break
        if idx is None:
            continue  # header / malformed
        col = lambda off, _row=row, _i=idx: _row[off] if 0 <= off < len(_row) else ""  # noqa: E731
        emit_call_events({
            "src": col(idx - 13), "dst": col(idx - 12), "start": col(idx - 5),
            "answer": col(idx - 4), "end": col(idx - 3),
            "duration": col(idx - 2), "billsec": col(idx - 1),
            "disposition": dispo, "uniqueid": col(2), "userfield": col(3),
        })


# ---------------------------------------------------------------- delivery
def _deliver_one(entry):
    wh = db.get_webhook(entry["webhook_id"])
    if wh is None or not int(wh["active"] or 0):
        db.finish_webhook_delivery(entry["id"], ok=True)  # target gone — drop
        return
    body = entry["payload"].encode("utf-8")
    secret = (wh["secret"] or "").encode("utf-8")
    headers = {"Content-Type": "application/json",
               "X-PBX-Event": entry["event"],
               "X-PBX-Delivery-Id": str(entry["id"])}
    if secret:
        sig = hmac.new(secret, body, hashlib.sha256).hexdigest()
        headers["X-PBX-Signature"] = f"sha256={sig}"
    ok, err = False, ""
    try:
        req = urllib.request.Request(wh["url"], data=body, headers=headers,
                                     method="POST")
        with urllib.request.urlopen(req, timeout=8) as resp:
            ok = 200 <= resp.status < 300
            if not ok:
                err = f"HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001 — deliveries must never crash
        err = str(exc)[:120] or exc.__class__.__name__
    attempts = int(entry["attempts"]) + 1
    db.finish_webhook_delivery(entry["id"], ok=ok, error=err,
                               retry_in=RETRY_DELAYS.get(attempts, 0))
    db.set_webhook_last_status(
        wh["id"], ("ok " + entry["event"]) if ok else f"fail: {err}")


# ------------------------------------------------------------------- loop
def _loop():
    global _last_size, _ticks
    time.sleep(15)
    _last_size = os.path.getsize(_cdr_path) if os.path.exists(_cdr_path) else 0
    while True:
        time.sleep(5)
        if not _tick_lock.acquire(blocking=False):
            continue
        try:
            _ticks += 1
            _scan_cdr()
            for entry in db.due_webhook_deliveries(time.time(), limit=20):
                _deliver_one(entry)
            if _ticks % 60 == 0:  # every ~5 minutes
                db.prune_webhook_queue()
        except Exception:  # noqa: BLE001 — the engine must survive anything
            pass
        finally:
            _tick_lock.release()


def start_once():
    """Start the engine thread; no-op when another process already owns it."""
    global _last_size
    with _start_lock:
        try:
            os.makedirs(db.DATA_DIR, exist_ok=True)
            lock_fh = open(_lock_path, "w")
            try:
                fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_fh.write(str(os.getpid()))
                lock_fh.flush()
            except OSError:
                lock_fh.close()
                return
            if _last_size is None:
                _last_size = (os.path.getsize(_cdr_path)
                              if os.path.exists(_cdr_path) else 0)
            threading.Thread(target=_loop, daemon=True,
                             name="ipbx-webhooks").start()
        except Exception:  # noqa: BLE001 — never break app startup
            pass
