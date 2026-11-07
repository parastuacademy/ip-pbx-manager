"""Background notifier — alerts for missed calls, trunk state and security.

Deliverers (all optional, configured in panel settings):
  - Telegram bot API
  - generic webhook (POST JSON {"text": ...}) — works with Bale/Eitaa/ntfy/…
  - SMTP email

A single background thread (guarded by an flock so it never duplicates across
processes) tails the CDR file for new missed inbound calls and watches the
trunk state once a minute.
"""
import fcntl
import json
import os
import smtplib
import threading
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

from . import db, jalali

_lock_path = os.path.join(db.DATA_DIR, "notifier.lock")
_cdr_path = os.path.join(db.DATA_DIR, "log", "cdr-csv", "Master.csv")

_last_size = 0
_last_trunk_online = None
_start_lock = threading.Lock()

TEXT_DISCONNECTED = "⛔ ترانک پیشگامان قطع شد!"
TEXT_CONNECTED = "✅ ترانک پیشگامان دوباره وصل شد."
TEXT_BRUTEFORCE = "🚨 تلاش ناموفق زیاد برای ورود به پنل از IP: {ip}"


# ------------------------------------------------------------------ delivery
def send_async(text):
    """Fire-and-forget delivery from request handlers (never blocks)."""
    threading.Thread(target=_deliver, args=(text,), daemon=True).start()


def _deliver(text):
    settings = db.all_settings()
    errors = []
    url = (settings.get("webhook_url") or "").strip()
    if url:
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps({"text": text}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=8)
        except Exception as exc:  # noqa: BLE001 — alerts must never crash
            errors.append(f"webhook: {exc}")
    token = (settings.get("tg_bot_token") or "").strip()
    chat = (settings.get("tg_chat_id") or "").strip()
    if token and chat:
        try:
            api = f"https://api.telegram.org/bot{token}/sendMessage"
            data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
            urllib.request.urlopen(urllib.request.Request(api, data=data), timeout=8)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"telegram: {exc}")
    host = (settings.get("smtp_host") or "").strip()
    to = (settings.get("notify_email") or "").strip()
    if host and to:
        try:
            _send_mail(settings, to, "اعلان پنل تلفن آی‌پی", text)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"email: {exc}")
    if errors:
        db.log_event("notify_error", "; ".join(errors)[:400])


def _send_mail(settings, to, subject, body):
    msg = EmailMessage()
    msg["From"] = (settings.get("smtp_from") or "").strip() or "ip-pbx-manager"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    port = int(settings.get("smtp_port") or 587)
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if settings.get("smtp_tls") == "1":
            smtp.starttls()
        user = (settings.get("smtp_user") or "").strip()
        if user:
            smtp.login(user, settings.get("smtp_pass") or "")
        smtp.send_message(msg)


def notify_bruteforce(ip):
    settings = db.all_settings()
    if settings.get("notify_login") == "1":
        send_async(TEXT_BRUTEFORCE.format(ip=ip))


# --------------------------------------------------------------- watch loop
_KNOWN_DISPO = {"ANSWERED", "NO ANSWER", "BUSY", "FAILED", "CONGESTION"}


def _scan_cdr(settings):
    """Parse new CDR rows appended since the last tick; alert on missed inbound.

    Uses the same robust column detection as the panel (position of the
    disposition field): start = dispo-5, src = dispo-13, dst = dispo-12.
    """
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
    # keep the last (possibly partial) line for the next tick
    nl = chunk.rfind(b"\n")
    if nl < 0:
        return
    complete, _partial = chunk[: nl + 1], chunk[nl + 1:]
    _last_size = size - len(_partial)
    dest = (settings.get("inbound_dest") or "").strip()
    for line in complete.decode("utf-8", "replace").splitlines():
        row = next(__import__("csv").reader([line]))
        dispo_idx, dispo = None, ""
        for i, cell in enumerate(row):
            if cell.strip() in _KNOWN_DISPO:
                dispo_idx, dispo = i, cell.strip()
                break
        if dispo_idx is None or dispo_idx < 13 or dispo == "ANSWERED":
            continue
        def col(offset, _row=row, _i=dispo_idx):
            j = _i + offset
            return _row[j] if 0 <= j < len(_row) else ""
        src, dst, start = col(-13), col(-12), col(-5)
        if not dest or dst != dest:  # only inbound misses matter to the owner
            continue
        jdate = ""
        try:
            t = time.strptime(start[:19], "%Y-%m-%d %H:%M:%S")
            jdate = jalali.format_jalali_long(t.tm_year, t.tm_mon, t.tm_mday)
            hhmm = f"{t.tm_hour:02d}:{t.tm_minute:02d}"
        except ValueError:
            hhmm = start
        send_async(f"📵 تماس بی‌پاسخ: از {src} به داخلی {dst}\n"
                   f"🕒 {jdate} — ساعت {hhmm}")


def _tick():
    settings = db.all_settings()
    global _last_trunk_online
    if settings.get("notify_trunk") == "1":
        online = None
        try:
            from .ami import AMIClient
            with AMIClient() as client:
                online = client.trunk_registered()
        except Exception:  # noqa: BLE001
            online = None
        if online is not None and _last_trunk_online is not None \
                and online != _last_trunk_online:
            send_async(TEXT_CONNECTED if online else TEXT_DISCONNECTED)
        if online is not None:
            _last_trunk_online = online
    if settings.get("notify_missed") == "1":
        _scan_cdr(settings)


def _watch_loop():
    # settle once at boot so we do not alert on old state
    global _last_size
    time.sleep(15)
    _last_size = os.path.getsize(_cdr_path) if os.path.exists(_cdr_path) else 0
    while True:
        time.sleep(60)
        try:
            _tick()
        except Exception:  # noqa: BLE001 — the watcher must survive anything
            pass


def start_once():
    """Start the watcher thread; no-op when another process already owns it."""
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
                return  # another instance owns the watcher
            _last_size = os.path.getsize(_cdr_path) if os.path.exists(_cdr_path) else 0
            threading.Thread(target=_watch_loop, daemon=True, name="ipbx-notifier").start()
        except Exception:  # noqa: BLE001 — never break app startup
            pass
