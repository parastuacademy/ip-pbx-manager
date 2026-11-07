"""SQLite helpers for ip-pbx-manager.

All persistent panel state lives in one SQLite file inside the shared
/data volume, so both containers (panel + asterisk) and container rebuilds
keep the data intact. Only the panel writes to the database.
"""
import hashlib
import os
import re
import secrets
import sqlite3
import string
import time

DATA_DIR = os.environ.get("IPBX_DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "ipbx.db")

_MODELS = [
    ("generic", "عمومی (همه مدل‌ها)"),
    ("gxp16xx", "Grandstream GXP16xx (1620/1625/1630)"),
    ("gxp21xx", "Grandstream GXP21xx (2130/2140/2160)"),
    ("grp2600", "Grandstream GRP2600 (2601/2602/2603)"),
]


def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS settings (
                   key   TEXT PRIMARY KEY,
                   value TEXT
               )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS extensions (
                   ext         TEXT PRIMARY KEY,
                   display_name TEXT NOT NULL DEFAULT '',
                   secret      TEXT NOT NULL,
                   record      INTEGER NOT NULL DEFAULT 0,
                   mac         TEXT NOT NULL DEFAULT '',
                   model       TEXT NOT NULL DEFAULT 'generic',
                   created_at  TEXT DEFAULT (datetime('now','localtime'))
               )"""
        )
        # v2 migration: per-extension voicemail flag
        try:
            c.execute("ALTER TABLE extensions ADD COLUMN voicemail INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already exists
        c.execute(
            """CREATE TABLE IF NOT EXISTS ring_groups (
                   id       INTEGER PRIMARY KEY AUTOINCREMENT,
                   name     TEXT NOT NULL,
                   members  TEXT NOT NULL DEFAULT '',
                   timeout  INTEGER NOT NULL DEFAULT 20,
                   fallback TEXT NOT NULL DEFAULT ''
               )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS ivr_menus (
                   id        INTEGER PRIMARY KEY AUTOINCREMENT,
                   name      TEXT NOT NULL,
                   prompt    TEXT NOT NULL DEFAULT '',
                   timeout   INTEGER NOT NULL DEFAULT 6,
                   options   TEXT NOT NULL DEFAULT '{}',
                   fallback  TEXT NOT NULL DEFAULT ''
               )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS holidays (
                   gdate TEXT PRIMARY KEY,
                   label TEXT NOT NULL DEFAULT ''
               )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS security_log (
                   id        INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts        TEXT DEFAULT (datetime('now','localtime')),
                   event     TEXT NOT NULL,
                   detail    TEXT NOT NULL DEFAULT ''
               )"""
        )
        # v2.1: external REST API — keys + webhooks + delivery queue
        c.execute(
            """CREATE TABLE IF NOT EXISTS api_keys (
                   id        INTEGER PRIMARY KEY AUTOINCREMENT,
                   name      TEXT NOT NULL,
                   key_hash  TEXT NOT NULL UNIQUE,
                   prefix    TEXT NOT NULL,
                   ip_allow  TEXT NOT NULL DEFAULT '',
                   created_at TEXT DEFAULT (datetime('now','localtime')),
                   last_used TEXT NOT NULL DEFAULT '',
                   revoked   INTEGER NOT NULL DEFAULT 0
               )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS webhooks (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   url        TEXT NOT NULL,
                   events     TEXT NOT NULL DEFAULT 'call.ended,call.missed',
                   secret     TEXT NOT NULL DEFAULT '',
                   active     INTEGER NOT NULL DEFAULT 1,
                   created_at TEXT DEFAULT (datetime('now','localtime')),
                   last_status TEXT NOT NULL DEFAULT ''
               )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS webhook_queue (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   webhook_id INTEGER NOT NULL,
                   event      TEXT NOT NULL,
                   payload    TEXT NOT NULL,
                   attempts   INTEGER NOT NULL DEFAULT 0,
                   next_try   REAL NOT NULL,
                   last_error TEXT NOT NULL DEFAULT '',
                   created_at TEXT DEFAULT (datetime('now','localtime')),
                   done       INTEGER NOT NULL DEFAULT 0
               )"""
        )
        for key, value in (("admin_hash", ""), ("viewer_hash", ""), ("wizard_done", "0"),
                           ("codecs", "ulaw,alaw"), ("trunk_mode", "register"),
                           ("trunk_port", "5060"),
                           # business hours (weekly schedule, per weekday 0=Saturday .. 6=Friday)
                           ("wh_enabled", "0"),
                           # notifications
                           ("tg_bot_token", ""), ("tg_chat_id", ""), ("webhook_url", ""),
                           ("smtp_host", ""), ("smtp_port", "587"), ("smtp_user", ""),
                           ("smtp_pass", ""), ("smtp_tls", "1"), ("smtp_from", ""),
                           ("notify_email", ""), ("notify_missed", "1"),
                           ("notify_trunk", "1"), ("notify_login", "1")):
            c.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (key, value))
    _ensure_vm_main_pass()


def _ensure_vm_main_pass():
    """Voicemail mailbox 'main' password, generated once."""
    if not get_setting("vm_main_pass"):
        set_setting("vm_main_pass", gen_password(6))


# ------------------------------------------------------------- security log
def log_event(event, detail=""):
    with _conn() as c:
        c.execute("INSERT INTO security_log(event, detail) VALUES (?, ?)", (event, detail))


def list_security_log(limit=200):
    with _conn() as c:
        rows = c.execute("SELECT * FROM security_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------- settings
def get_setting(key, default=None):
    with _conn() as c:
        row = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row is not None else default


def set_setting(key, value):
    with _conn() as c:
        c.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, "" if value is None else str(value)),
        )


def all_settings():
    with _conn() as c:
        rows = c.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


# -------------------------------------------------------------- extensions
def _row_to_dict(r):
    return dict(r) if r is not None else None


def list_extensions():
    with _conn() as c:
        rows = c.execute("SELECT * FROM extensions ORDER BY ext").fetchall()
    return [_row_to_dict(r) for r in rows]


def get_extension(ext):
    with _conn() as c:
        return _row_to_dict(c.execute("SELECT * FROM extensions WHERE ext = ?", (str(ext),)).fetchone())


def get_extension_by_mac(mac):
    if not mac:
        return None
    with _conn() as c:
        return _row_to_dict(
            c.execute("SELECT * FROM extensions WHERE UPPER(mac) = ?", (mac.upper(),)).fetchone()
        )


def add_extension(ext, display_name, secret, record=0, mac="", model="generic"):
    with _conn() as c:
        c.execute(
            "INSERT INTO extensions(ext, display_name, secret, record, mac, model) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(ext), display_name, secret, int(record), (mac or "").upper(), model),
        )


def update_extension(ext, display_name=None, secret=None, record=None, mac=None, model=None,
                     voicemail=None):
    fields, vals = [], []
    if display_name is not None:
        fields.append("display_name = ?"); vals.append(display_name)
    if secret is not None:
        fields.append("secret = ?"); vals.append(secret)
    if record is not None:
        fields.append("record = ?"); vals.append(int(record))
    if mac is not None:
        fields.append("mac = ?"); vals.append(mac.upper())
    if model is not None:
        fields.append("model = ?"); vals.append(model)
    if voicemail is not None:
        fields.append("voicemail = ?"); vals.append(int(voicemail))
    if not fields:
        return
    vals.append(str(ext))
    with _conn() as c:
        c.execute(f"UPDATE extensions SET {', '.join(fields)} WHERE ext = ?", vals)


def delete_extension(ext):
    with _conn() as c:
        c.execute("DELETE FROM extensions WHERE ext = ?", (str(ext),))


# ------------------------------------------------------------------ utils
def gen_password(length=8):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def model_choices():
    return list(_MODELS)


def model_label(model):
    return dict(_MODELS).get(model, model)


def sane_ext_number(ext):
    """2..6 digit extension number not starting with 0."""
    return bool(re.fullmatch(r"[1-9][0-9]{1,5}", str(ext)))


# -------------------------------------------------------------- ring groups
def list_ring_groups():
    with _conn() as c:
        rows = c.execute("SELECT * FROM ring_groups ORDER BY id").fetchall()
    return [_row_to_dict(r) for r in rows]


def get_ring_group(rg_id):
    with _conn() as c:
        return _row_to_dict(c.execute("SELECT * FROM ring_groups WHERE id = ?", (rg_id,)).fetchone())


def add_ring_group(name, members, timeout=20, fallback=""):
    with _conn() as c:
        c.execute("INSERT INTO ring_groups(name, members, timeout, fallback) VALUES (?, ?, ?, ?)",
                  (name, members, int(timeout), fallback))


def update_ring_group(rg_id, name, members, timeout, fallback):
    with _conn() as c:
        c.execute("UPDATE ring_groups SET name = ?, members = ?, timeout = ?, fallback = ? "
                  "WHERE id = ?", (name, members, int(timeout), fallback, rg_id))


def delete_ring_group(rg_id):
    with _conn() as c:
        c.execute("DELETE FROM ring_groups WHERE id = ?", (rg_id,))


# --------------------------------------------------------------- IVR menus
def list_ivr_menus():
    with _conn() as c:
        rows = c.execute("SELECT * FROM ivr_menus ORDER BY id").fetchall()
    return [_row_to_dict(r) for r in rows]


def get_ivr_menu(ivr_id):
    with _conn() as c:
        return _row_to_dict(c.execute("SELECT * FROM ivr_menus WHERE id = ?", (ivr_id,)).fetchone())


def add_ivr_menu(name, prompt, timeout, options, fallback=""):
    with _conn() as c:
        c.execute("INSERT INTO ivr_menus(name, prompt, timeout, options, fallback) "
                  "VALUES (?, ?, ?, ?, ?)", (name, prompt, int(timeout), options, fallback))


def update_ivr_menu(ivr_id, name, prompt, timeout, options, fallback):
    with _conn() as c:
        c.execute("UPDATE ivr_menus SET name = ?, prompt = ?, timeout = ?, options = ?, "
                  "fallback = ? WHERE id = ?",
                  (name, prompt, int(timeout), options, fallback, ivr_id))


def delete_ivr_menu(ivr_id):
    with _conn() as c:
        c.execute("DELETE FROM ivr_menus WHERE id = ?", (ivr_id,))


# ----------------------------------------------------------------- holidays
def list_holidays():
    with _conn() as c:
        rows = c.execute("SELECT * FROM holidays ORDER BY gdate").fetchall()
    return [_row_to_dict(r) for r in rows]


def add_holiday(gdate, label=""):
    with _conn() as c:
        c.execute("INSERT INTO holidays(gdate, label) VALUES (?, ?) "
                  "ON CONFLICT(gdate) DO UPDATE SET label = excluded.label",
                  (gdate, label))


def delete_holiday(gdate):
    with _conn() as c:
        c.execute("DELETE FROM holidays WHERE gdate = ?", (gdate,))


# ------------------------------------------------------------- destinations
# A "destination" is encoded as "type:value" so IVR / ring groups / business
# hours can all point at the same target kinds:
#   ext:<number>       ring one extension
#   rg:<id>            ring a ring group
#   vm:main            main voicemail box
def sane_destination(dest, allow_vm=True):
    if not dest:
        return False
    kind, _, value = dest.partition(":")
    if kind == "ext":
        return bool(get_extension(value))
    if kind == "rg":
        return bool(get_ring_group(value))
    if kind == "vm" and allow_vm:
        return value in ("main",)
    return False


def destination_choices():
    """(value, label) pairs for dropdowns in the UI."""
    out = [(f"ext:{e['ext']}", f"داخلی {e['ext']} — {e['display_name']}")
           for e in list_extensions()]
    out += [(f"rg:{g['id']}", f"گروه زنگ: {g['name']}") for g in list_ring_groups()]
    out += [("vm:main", "صندوق پیام صوتی اصلی")]
    return out


# ----------------------------------------------------------------- API keys
KEY_PREFIX = "pbx_"

def gen_api_key():
    return KEY_PREFIX + secrets.token_hex(16)


def _hash_key(raw_key):
    return hashlib.sha256(raw_key.encode()).hexdigest()


def create_api_key(name, ip_allow=""):
    """Create a key; returns (row_id, raw_key). raw_key is shown only once."""
    raw = gen_api_key()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO api_keys(name, key_hash, prefix, ip_allow) VALUES (?, ?, ?, ?)",
            (name[:60], _hash_key(raw), raw[:12], (ip_allow or "").strip()),
        )
        return cur.lastrowid, raw


def list_api_keys(include_revoked=True):
    q = "SELECT id, name, prefix, ip_allow, created_at, last_used, revoked " \
        "FROM api_keys"
    if not include_revoked:
        q += " WHERE revoked = 0"
    q += " ORDER BY id DESC"
    with _conn() as c:
        rows = c.execute(q).fetchall()
    return [_row_to_dict(r) for r in rows]


def revoke_api_key(key_id):
    with _conn() as c:
        c.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,))


def delete_api_key(key_id):
    with _conn() as c:
        c.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))


def get_api_key_by_secret(raw_key):
    """Full row (incl. id/ip_allow) for a raw bearer key, or None."""
    if not raw_key:
        return None
    with _conn() as c:
        row = c.execute("SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0",
                        (_hash_key(raw_key),)).fetchone()
    return _row_to_dict(row)


def touch_api_key(key_id):
    with _conn() as c:
        c.execute("UPDATE api_keys SET last_used = datetime('now','localtime') "
                  "WHERE id = ?", (key_id,))


# ----------------------------------------------------------------- webhooks
WEBHOOK_EVENTS = ("call.ended", "call.missed", "call.answered", "webhook.test")


def gen_webhook_secret():
    return "whsec_" + secrets.token_hex(16)


def create_webhook(url, events, secret="", active=1):
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO webhooks(url, events, secret, active) VALUES (?, ?, ?, ?)",
            (url[:500], ",".join(events), secret, int(active)),
        )
        return cur.lastrowid


def list_webhooks():
    with _conn() as c:
        rows = c.execute("SELECT * FROM webhooks ORDER BY id DESC").fetchall()
    return [_row_to_dict(r) for r in rows]


def get_webhook(webhook_id):
    with _conn() as c:
        return _row_to_dict(
            c.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,)).fetchone())


def set_webhook_active(webhook_id, active):
    with _conn() as c:
        c.execute("UPDATE webhooks SET active = ? WHERE id = ?",
                  (int(active), webhook_id))


def delete_webhook(webhook_id):
    with _conn() as c:
        c.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        c.execute("DELETE FROM webhook_queue WHERE webhook_id = ?", (webhook_id,))


def set_webhook_last_status(webhook_id, status):
    with _conn() as c:
        c.execute("UPDATE webhooks SET last_status = ? WHERE id = ?",
                  (status[:160], webhook_id))


# --------------------------------------------------------------- webhook queue
def enqueue_webhook(webhook_id, event, payload, now):
    """Queue one delivery attempt. payload must be the JSON string body."""
    with _conn() as c:
        c.execute(
            "INSERT INTO webhook_queue(webhook_id, event, payload, next_try) "
            "VALUES (?, ?, ?, ?)", (webhook_id, event, payload, now))


def due_webhook_deliveries(now, limit=20):
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM webhook_queue WHERE done = 0 AND next_try <= ? "
            "ORDER BY id LIMIT ?", (now, limit)).fetchall()
    return [_row_to_dict(r) for r in rows]


def finish_webhook_delivery(qid, ok, error="", retry_in=0, now=None):
    """Mark a delivery finished, or schedule the next retry."""
    now = time.time() if now is None else now
    with _conn() as c:
        row = c.execute("SELECT attempts FROM webhook_queue WHERE id = ?",
                        (qid,)).fetchone()
        if row is None:
            return
        attempts = int(row["attempts"]) + 1
        if ok or attempts >= 4:
            c.execute("UPDATE webhook_queue SET done = 1, attempts = ?, "
                      "last_error = ? WHERE id = ?",
                      (attempts, error[:300], qid))
        else:
            c.execute("UPDATE webhook_queue SET attempts = ?, next_try = ?, "
                      "last_error = ? WHERE id = ?",
                      (attempts, now + retry_in, error[:300], qid))


def prune_webhook_queue(keep_done=500):
    with _conn() as c:
        c.execute("DELETE FROM webhook_queue WHERE done = 1 AND id NOT IN "
                  "(SELECT id FROM webhook_queue WHERE done = 1 "
                  "ORDER BY id DESC LIMIT ?)", (keep_done,))


def queue_depth():
    with _conn() as c:
        row = c.execute("SELECT COUNT(*) AS n FROM webhook_queue WHERE done = 0").fetchone()
    return int(row["n"])
