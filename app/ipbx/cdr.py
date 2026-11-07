"""Call Detail Record (CDR) reading — shared by the panel UI and the API.

Asterisk writes one CSV file (/data/log/cdr-csv/Master.csv). Column position
is detected from the disposition field so both the standard 18-column layout
(with accountcode) and the 17-column one work:

    start = dispo-5, answer = dispo-4, end = dispo-3, duration = dispo-2,
    billsec = dispo-1, src = dispo-13, dst = dispo-12,
    uniqueid = dispo+2, userfield = dispo+3 (when present)

Only the last MAX_LINES lines are considered — enough for a small
organisation and keeps the panel fast forever.
"""
import csv
import glob
import os
from collections import deque

from . import db

MAX_LINES = 5000

CDR_PATH = os.path.join(db.DATA_DIR, "log", "cdr-csv", "Master.csv")
RECORDINGS_DIR = os.path.join(db.DATA_DIR, "recordings")

_KNOWN_DISPO = {"ANSWERED", "NO ANSWER", "BUSY", "FAILED", "CONGESTION"}


def read_cdr(q="", date="", disposition="", limit=400, offset=0):
    """Return (rows, total_matches). rows are newest-first, already sliced.

    Filters:
      q           substring match on src or dst
      date        YYYY-MM-DD prefix match on start time
      disposition one of _KNOWN_DISPO ("" = all)
    """
    if not os.path.exists(CDR_PATH):
        return [], 0
    with open(CDR_PATH, newline="", encoding="utf-8", errors="replace") as fh:
        lines = deque(fh, maxlen=MAX_LINES)
    matches = []
    for row in csv.reader(lines):
        dispo_idx, dispo = None, ""
        for i in range(len(row)):
            if row[i].strip() in _KNOWN_DISPO:
                dispo_idx, dispo = i, row[i].strip()
                break
        if dispo_idx is None or dispo_idx < 13:
            continue  # header / malformed line
        if disposition and dispo != disposition:
            continue

        def col(offset, _row=row, _i=dispo_idx):
            j = _i + offset
            return _row[j] if 0 <= j < len(_row) else ""

        src, dst, start = col(-13), col(-12), col(-5)
        if q and q not in src and q not in dst:
            continue
        if date and not start.startswith(date):
            continue
        matches.append({
            "src": src, "dst": dst, "start": start,
            "answer": col(-4), "end": col(-3),
            "duration": col(-2), "billsec": col(-1),
            "disposition": dispo, "uniqueid": col(2),
            "userfield": col(3),
        })
    matches.reverse()  # newest first
    total = len(matches)
    return matches[offset: offset + max(0, int(limit))], total


def call_direction(row, settings=None):
    """Best-effort direction: inbound / outbound / internal / unknown.

    Inbound calls carry CDR(userfield)=inbound (set by the generated
    dialplan); everything else is inferred from extension membership.
    """
    settings = settings if settings is not None else db.all_settings()
    exts = {e["ext"] for e in db.list_extensions()}
    src, dst = str(row.get("src") or ""), str(row.get("dst") or "")
    userfield = str(row.get("userfield") or "")
    src_ext, dst_ext = src in exts, dst in exts
    if userfield == "inbound":
        return "inbound"
    if src_ext and dst_ext:
        return "internal"
    if src_ext and not dst_ext:
        return "outbound"
    if dst_ext and not src_ext and src:
        return "inbound"
    inbound_dest = (settings.get("inbound_dest") or "").strip()
    if inbound_dest and dst == inbound_dest and not src_ext:
        return "inbound"
    return "unknown"


def find_recording(uniqueid):
    """Absolute path of the recording for a call, or None."""
    if not uniqueid:
        return None
    for ext in (".wav", ".mp3", ".wav49", ".gsm"):
        path = os.path.join(RECORDINGS_DIR, f"{uniqueid}{ext}")
        if os.path.isfile(path):
            return path
    hits = glob.glob(os.path.join(RECORDINGS_DIR, f"{glob.escape(uniqueid)}.*"))
    return hits[0] if hits else None
