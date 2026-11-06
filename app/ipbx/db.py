"""SQLite helpers for ip-pbx-manager.

All persistent panel state lives in one SQLite file inside the shared
/data volume, so both containers (panel + asterisk) and container rebuilds
keep the data intact. Only the panel writes to the database.
"""
import os
import re
import secrets
import sqlite3
import string

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
        for key, value in (("admin_hash", ""), ("wizard_done", "0"),
                           ("codecs", "ulaw,alaw"), ("trunk_mode", "register"),
                           ("trunk_port", "5060")):
            c.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (key, value))


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


def update_extension(ext, display_name=None, secret=None, record=None, mac=None, model=None):
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
