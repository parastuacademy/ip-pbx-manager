"""Call Detail Record (CDR) reading — the single source of truth shared
by the panel UI, the external API, the webhook engine and the notifier.

Asterisk appends every call to one CSV file (/data/log/cdr-csv/Master.csv).
The panel generates asterisk/cdr.conf itself (usegmtime=no, accountcodes=yes,
loguniqueid=yes, loguserfield=yes), so the layout is fixed — exactly the 18
columns of asterisk/cdr/cdr_csv.c:

    0 accountcode    1 src           2 dst          3 dcontext
    4 clid           5 channel       6 dstchannel   7 lastapp
    8 lastdata       9 start        10 answer      11 end
   12 duration      13 billsec      14 disposition 15 amaflags
   16 uniqueid      17 userfield

If the layout ever changes, change it here (and in cdr.conf) — nowhere else.

Only the last MAX_LINES lines are considered — plenty for a small
organisation and keeps the panel fast forever.
"""
import csv
import os
from collections import deque

from . import db

MAX_LINES = 5000

CDR_PATH = os.path.join(db.DATA_DIR, "log", "cdr-csv", "Master.csv")
RECORDINGS_DIR = os.path.join(db.DATA_DIR, "recordings")

# Fixed column positions of the layout our cdr.conf produces (see above).
COL_SRC, COL_DST = 1, 2
COL_START, COL_ANSWER, COL_END = 9, 10, 11
COL_DURATION, COL_BILLSEC = 12, 13
COL_DISPO, COL_UNIQUEID, COL_USERFIELD = 14, 16, 17

DISPOSITIONS = ("ANSWERED", "NO ANSWER", "BUSY", "FAILED", "CONGESTION")


def parse_row(row):
    """One CSV row (list of cells) -> call dict, or None for the header
    line and anything malformed."""
    if len(row) != 18 or row[COL_DISPO].strip() not in DISPOSITIONS:
        return None
    return {
        "src": row[COL_SRC], "dst": row[COL_DST],
        "start": row[COL_START], "answer": row[COL_ANSWER],
        "end": row[COL_END], "duration": row[COL_DURATION],
        "billsec": row[COL_BILLSEC], "disposition": row[COL_DISPO].strip(),
        "uniqueid": row[COL_UNIQUEID], "userfield": row[COL_USERFIELD],
    }


def read_cdr(q="", date="", disposition="", limit=400, offset=0):
    """Return (rows, total_matches). rows are newest-first, already sliced.

    Filters:
      q           substring match on src or dst
      date        YYYY-MM-DD prefix match on start time
      disposition one of DISPOSITIONS ("" = all)
    """
    if not os.path.exists(CDR_PATH):
        return [], 0
    with open(CDR_PATH, newline="", encoding="utf-8", errors="replace") as fh:
        lines = deque(fh, maxlen=MAX_LINES)
    matches = []
    for row in csv.reader(lines):
        call = parse_row(row)
        if call is None:
            continue
        if disposition and call["disposition"] != disposition:
            continue
        if q and q not in call["src"] and q not in call["dst"]:
            continue
        if date and not call["start"].startswith(date):
            continue
        matches.append(call)
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


def current_size():
    """Current byte size of the CDR file (0 when it does not exist yet)."""
    return os.path.getsize(CDR_PATH) if os.path.exists(CDR_PATH) else 0


def tail_new_rows(last_size):
    """(calls, new_size) — calls appended since byte offset last_size.

    A trailing line without its newline yet is left for the next tick, so
    a row is only ever parsed once and only when complete. Used by the
    notifier and the webhook engine; last_size comes back from the
    previous call (or current_size() at startup).
    """
    if not os.path.exists(CDR_PATH):
        return [], 0
    size = os.path.getsize(CDR_PATH)
    if size < last_size:  # rotated/truncated — start over
        last_size = 0
    if size == last_size:
        return [], last_size
    with open(CDR_PATH, "rb") as fh:
        fh.seek(last_size)
        chunk = fh.read(size - last_size)
    nl = chunk.rfind(b"\n")
    if nl < 0:
        return [], last_size  # wait for the rest of the line on the next tick
    calls = []
    for line in chunk[: nl + 1].decode("utf-8", "replace").splitlines():
        call = parse_row(next(csv.reader([line]), []))
        if call is not None:
            calls.append(call)
    return calls, last_size + nl + 1


def find_recording(uniqueid):
    """Absolute path of the call recording, or None.

    The generated dialplan records every call as <uniqueid>.wav, so the
    lookup is one fixed path — no format guessing.
    """
    if not uniqueid:
        return None
    path = os.path.join(RECORDINGS_DIR, f"{uniqueid}.wav")
    return path if os.path.isfile(path) else None
