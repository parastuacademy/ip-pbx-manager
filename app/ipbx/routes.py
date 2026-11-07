"""All panel routes (Persian UI)."""
import csv
import glob
import hashlib
import io
import json
import os
import secrets
import tarfile
import time
from collections import deque

from flask import (Blueprint, abort, flash, jsonify, make_response, redirect,
                   render_template, request, send_file, send_from_directory,
                   session, url_for)

from . import config_gen, db, notifier, provisioning
from .ami import AMIClient, AMIError

bp = Blueprint("main", __name__)

RECORDINGS_DIR = os.path.join(db.DATA_DIR, "recordings")
CDR_PATH = os.path.join(db.DATA_DIR, "log", "cdr-csv", "Master.csv")
VM_SPOOL = config_gen.VM_SPOOL
SOUNDS_CUSTOM = config_gen.SOUNDS_CUSTOM

_LOGIN_ATTEMPTS = {}  # ip -> [count, window_start]

# Pages a "viewer" (reports-only) account may open. Everything else is admin.
VIEWER_ALLOWED_PREFIXES = ("/", "/cdr", "/api/status", "/health")


# ------------------------------------------------------------------ helpers
def _hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000).hex()
    return f"{salt}${digest}"


def _verify_password(password, stored):
    try:
        salt, digest = (stored or "").split("$", 1)
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000).hex()
        return secrets.compare_digest(calc, digest)
    except (ValueError, TypeError):
        return False


def _apply_changes():
    """Regenerate all configs and best-effort reload Asterisk.

    Returns True when the reload actually reached Asterisk.
    """
    settings = db.all_settings()
    exts = db.list_extensions()
    config_gen.apply_all(settings, exts)
    try:
        with AMIClient() as client:
            config_gen.sync_record_flags(client, exts)
            config_gen.sync_vm_flags(client, exts)
            config_gen.reload_asterisk(client)
        return True
    except AMIError:
        return False


def _is_admin():
    return session.get("role", "admin") == "admin"


def _flash_apply(reloaded, what="تغییرات"):
    if reloaded:
        flash(f"{what} اعمال و Asterisk بازخوانی شد ✅", "ok")
    else:
        flash(f"{what} ذخیره شد، اما Asterisk در دسترس نیست؛ به‌محض بالاآمدن آن اعمال می‌شود.", "warn")


def _status_snapshot():
    data = {"ami": False, "trunk_online": False, "online": {}, "active": []}
    try:
        with AMIClient() as client:
            data["ami"] = True
            data["trunk_online"] = client.trunk_registered()
            online = client.online_extensions()
            data["online"] = {e["ext"]: e["ext"] in online for e in db.list_extensions()}
            data["active"] = client.active_channels()
    except AMIError:
        pass
    return data


_KNOWN_DISPO = {"ANSWERED", "NO ANSWER", "BUSY", "FAILED", "CONGESTION"}


def _read_cdr(q="", date="", limit=400):
    """Parse Asterisk cdr-csv Master.csv.

    Column position is detected from the disposition field so both the
    standard 18-column layout (with accountcode) and the 17-column one work:
    start = dispo-5, answer = dispo-4, end = dispo-3, duration = dispo-2,
    billsec = dispo-1, src = dispo-13, dst = dispo-12, uniqueid = dispo+2.
    """
    if not os.path.exists(CDR_PATH):
        return []
    with open(CDR_PATH, newline="", encoding="utf-8", errors="replace") as fh:
        lines = deque(fh, maxlen=5000)
    rows = []
    for row in csv.reader(lines):
        dispo_idx = None
        dispo = ""
        for i in range(len(row)):
            if row[i].strip() in _KNOWN_DISPO:
                dispo_idx, dispo = i, row[i].strip()
                break
        if dispo_idx is None or dispo_idx < 13:
            continue  # header / malformed line
        def col(offset):
            i = dispo_idx + offset
            return row[i] if 0 <= i < len(row) else ""
        src, dst, start = col(-13), col(-12), col(-5)
        if q and q not in src and q not in dst:
            continue
        if date and not start.startswith(date):
            continue
        rows.append({
            "src": src, "dst": dst, "start": start,
            "answer": col(-4), "end": col(-3),
            "duration": col(-2), "billsec": col(-1),
            "disposition": dispo, "uniqueid": col(2),
        })
    return rows[-limit:][::-1]


# -------------------------------------------------------------------- system
@bp.get("/health")
def health():
    return jsonify(
        status="ok",
        initialized=bool(db.get_setting("admin_hash")),
        wizard_done=db.get_setting("wizard_done") == "1",
    )


# ---------------------------------------------------------------------- auth
@bp.route("/setup", methods=["GET", "POST"])
def setup():
    if db.get_setting("admin_hash"):
        return redirect(url_for("main.login"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        if len(pw) < 8:
            flash("رمز مدیر باید حداقل ۸ نویسه باشد.", "error")
        elif pw != pw2:
            flash("تکرار رمز مطابقت ندارد.", "error")
        else:
            db.set_setting("admin_hash", _hash_password(pw))
            flash("رمز مدیر ساخته شد. اکنون وارد شوید.", "ok")
            return redirect(url_for("main.login"))
    return render_template("setup.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if not db.get_setting("admin_hash"):
        return redirect(url_for("main.setup"))
    if session.get("user"):
        return redirect(url_for("main.dashboard"))
    ip = request.remote_addr or "?"
    now = time.time()
    count, started = _LOGIN_ATTEMPTS.get(ip, [0, now])
    if now - started > 600:
        count, started = 0, now
    if request.method == "POST":
        if count >= 8:
            if count == 8:  # first lockout only — alert + log once per window
                db.log_event("login_locked", f"IP {ip}")
                notifier.notify_bruteforce(ip)
            flash("تلاش‌های ناموفق زیاد است؛ ۱۰ دقیقه بعد دوباره امتحان کنید.", "error")
            return render_template("login.html"), 429
        pw = request.form.get("password", "")
        if _verify_password(pw, db.get_setting("admin_hash")):
            _LOGIN_ATTEMPTS.pop(ip, None)
            session.clear()
            session["user"] = "admin"
            session["role"] = "admin"
            session.permanent = True
            db.log_event("login_ok", f"admin from {ip}")
            return redirect(url_for("main.dashboard"))
        viewer_hash = db.get_setting("viewer_hash") or ""
        if viewer_hash and _verify_password(pw, viewer_hash):
            _LOGIN_ATTEMPTS.pop(ip, None)
            session.clear()
            session["user"] = "viewer"
            session["role"] = "viewer"
            session.permanent = True
            db.log_event("login_ok", f"viewer from {ip}")
            return redirect(url_for("main.dashboard"))
        _LOGIN_ATTEMPTS[ip] = [count + 1, started]
        db.log_event("login_fail", f"IP {ip}")
        flash("رمز نادرست است.", "error")
    return render_template("login.html")


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))


# ----------------------------------------------------------------- dashboard
@bp.get("/")
def dashboard():
    if db.get_setting("wizard_done") != "1":
        return redirect(url_for("main.wizard"))
    return render_template("dashboard.html", exts=db.list_extensions(),
                           rows=_read_cdr(limit=8))


@bp.get("/api/status")
def api_status():
    if not session.get("user"):
        return jsonify(error="unauthorized"), 401
    return jsonify(_status_snapshot())


# ------------------------------------------------------------------- wizard
@bp.route("/wizard", methods=["GET", "POST"])
def wizard():
    if db.get_setting("wizard_done") == "1":
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        mode = request.form.get("trunk_mode", "register").strip()
        host = request.form.get("trunk_host", "").strip()
        port = request.form.get("trunk_port", "5060").strip() or "5060"
        user = request.form.get("trunk_user", "").strip()
        tpass = request.form.get("trunk_pass", "").strip()
        codecs = [c for c in request.form.getlist("codecs")
                  if c in ("ulaw", "alaw", "g729", "gsm")] or ["ulaw", "alaw"]
        ext_start = request.form.get("ext_start", "101").strip()
        ext_count = request.form.get("ext_count", "10").strip()
        lan_ip = request.form.get("lan_ip", "").strip()
        nat_ip = request.form.get("nat_public_ip", "").strip()

        errors = []
        if mode not in ("register", "peer"):
            errors.append("حالت اتصال ترانک نامعتبر است.")
        if not host:
            errors.append("آدرس سرور ترانک (از مدارک پیشگامان) لازم است.")
        if mode == "register" and (not user or not tpass):
            errors.append("برای حالت Register، نام کاربری و رمز ترانک لازم است.")
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            errors.append("پورت ترانک نامعتبر است.")
        if not db.sane_ext_number(ext_start):
            errors.append("شماره شروع داخلی نامعتبر است (۲ تا ۶ رقم، بدون صفر ابتدایی).")
        if not (ext_count.isdigit() and 1 <= int(ext_count) <= 50):
            errors.append("تعداد داخلی باید بین ۱ و ۵۰ باشد.")
        if errors:
            for err in errors:
                flash(err, "error")
            return render_template("wizard.html", form=request.form, codecs=codecs)

        created = []
        for i in range(int(ext_count)):
            ext = str(int(ext_start) + i)
            if db.get_extension(ext):
                continue
            db.add_extension(ext, f"داخلی {ext}", db.gen_password())
            created.append(ext)
        dest = created[0] if created else (db.list_extensions() or [{"ext": ""}])[0]["ext"]

        db.set_setting("trunk_mode", mode)
        db.set_setting("trunk_host", host)
        db.set_setting("trunk_port", port)
        db.set_setting("trunk_user", user)
        db.set_setting("trunk_pass", tpass)
        db.set_setting("codecs", ",".join(codecs))
        db.set_setting("inbound_dest", dest)
        db.set_setting("lan_ip", lan_ip)
        db.set_setting("nat_public_ip", nat_ip)

        reloaded = _apply_changes()
        db.set_setting("wizard_done", "1")
        _flash_apply(reloaded, "راه‌اندازی")
        flash("داخلی‌ها ساخته شدند. حالا می‌توانید تلفن‌ها را پروویژن کنید.", "ok")
        return redirect(url_for("main.extensions"))

    return render_template("wizard.html", form={}, codecs=db.get_setting("codecs", "ulaw,alaw"))


# --------------------------------------------------------------- extensions
@bp.route("/extensions", methods=["GET", "POST"])
def extensions():
    if request.method == "POST":
        ext = request.form.get("ext", "").strip()
        name = request.form.get("display_name", "").strip() or f"داخلی {ext}"
        mac = request.form.get("mac", "").strip().replace(":", "").replace("-", "").upper()
        model = request.form.get("model", "generic")
        if not db.sane_ext_number(ext):
            flash("شماره داخلی نامعتبر است (۲ تا ۶ رقم، بدون صفر ابتدایی).", "error")
        elif db.get_extension(ext):
            flash(f"داخلی {ext} از قبل وجود دارد.", "error")
        elif mac and db.get_extension_by_mac(mac):
            flash("این MAC قبلاً برای داخلی دیگری ثبت شده است.", "error")
        else:
            db.add_extension(ext, name, db.gen_password(), mac=mac, model=model)
            _flash_apply(_apply_changes(), f"داخلی {ext}")
        return redirect(url_for("main.extensions"))

    return render_template(
        "extensions.html",
        exts=db.list_extensions(),
        models=db.model_choices(),
        provisioning_base=f"http://{request.host}/provisioning/",
    )


@bp.route("/extensions/<ext>/edit", methods=["GET", "POST"])
def edit_extension(ext):
    e = db.get_extension(ext)
    if not e:
        abort(404)
    if request.method == "POST":
        name = request.form.get("display_name", "").strip() or f"داخلی {ext}"
        mac = request.form.get("mac", "").strip().replace(":", "").replace("-", "").upper()
        model = request.form.get("model", "generic")
        record = 1 if request.form.get("record") == "on" else 0
        voicemail = 1 if request.form.get("voicemail") == "on" else 0
        secret = request.form.get("secret", "").strip()
        if mac and db.get_extension_by_mac(mac) and db.get_extension_by_mac(mac)["ext"] != str(ext):
            flash("این MAC قبلاً برای داخلی دیگری ثبت شده است.", "error")
            return render_template("edit_extension.html", e=e, models=db.model_choices())
        db.update_extension(ext, display_name=name, mac=mac, model=model, record=record,
                            secret=secret or None, voicemail=voicemail)
        _flash_apply(_apply_changes(), f"داخلی {ext}")
        return redirect(url_for("main.extensions"))
    return render_template("edit_extension.html", e=e, models=db.model_choices())


@bp.post("/extensions/<ext>/delete")
def delete_extension(ext):
    if db.get_extension(ext):
        db.delete_extension(ext)
        _flash_apply(_apply_changes(), f"حذف داخلی {ext}")
    return redirect(url_for("main.extensions"))


@bp.post("/extensions/<ext>/record")
def toggle_record(ext):
    e = db.get_extension(ext)
    if not e:
        abort(404)
    newval = 0 if int(e["record"] or 0) else 1
    db.update_extension(ext, record=newval)
    try:
        with AMIClient() as client:
            (client.db_put_record(ext) if newval else client.db_del_record(ext))
    except AMIError:
        flash("تغییر ذخیره شد اما Asterisk در دسترس نیست؛ بعداً «بازسازی کامل» بزنید.", "warn")
    flash("ضبط مکالمات این داخلی روشن شد ✅" if newval
          else "ضبط مکالمات این داخلی خاموش شد.", "ok")
    return redirect(url_for("main.extensions"))


@bp.post("/extensions/<ext>/voicemail")
def toggle_voicemail(ext):
    e = db.get_extension(ext)
    if not e:
        abort(404)
    newval = 0 if int(e["voicemail"] or 0) else 1
    db.update_extension(ext, voicemail=newval)
    _flash_apply(_apply_changes(), "صندوق پیام صوتی")
    flash("پیام صوتی این داخلی روشن شد ✅ (پیام‌های آفلاین به سمت وویس‌میل می‌روند)" if newval
          else "پیام صوتی این داخلی خاموش شد.", "ok")
    return redirect(url_for("main.extensions"))


# -------------------------------------------------------------------- trunk
@bp.route("/trunk", methods=["GET", "POST"])
def trunk():
    if request.method == "POST":
        mode = request.form.get("trunk_mode", "register").strip()
        host = request.form.get("trunk_host", "").strip()
        port = request.form.get("trunk_port", "5060").strip() or "5060"
        user = request.form.get("trunk_user", "").strip()
        tpass = request.form.get("trunk_pass", "").strip()
        codecs = [c for c in request.form.getlist("codecs")
                  if c in ("ulaw", "alaw", "g729", "gsm")] or ["ulaw", "alaw"]
        if mode not in ("register", "peer") or not host:
            flash("حالت و آدرس سرور ترانک لازم است.", "error")
            return redirect(url_for("main.trunk"))
        if mode == "register" and (not user or not tpass):
            flash("برای حالت Register، نام کاربری و رمز لازم است.", "error")
            return redirect(url_for("main.trunk"))
        db.set_setting("trunk_mode", mode)
        db.set_setting("trunk_host", host)
        db.set_setting("trunk_port", port)
        db.set_setting("trunk_user", user)
        db.set_setting("trunk_pass", tpass)
        db.set_setting("codecs", ",".join(codecs))
        _flash_apply(_apply_changes(), "مشخصات ترانک")
        return redirect(url_for("main.trunk"))
    return render_template("trunk.html", s=db.all_settings())


# ---------------------------------------------------------------------- CDR
@bp.get("/cdr")
def cdr_page():
    q = request.args.get("q", "").strip()
    date = request.args.get("date", "").strip()
    missed = request.args.get("missed") == "1"
    rows = _read_cdr(q=q, date=date)
    if missed:
        rows = [r for r in rows if r["disposition"] != "ANSWERED"]
    return render_template("cdr.html", rows=rows, q=q, date=date, missed=missed)


@bp.get("/cdr/export")
def cdr_export():
    """Excel-compatible export (CSV with UTF-8 BOM + Jalali dates)."""
    q = request.args.get("q", "").strip()
    date = request.args.get("date", "").strip()
    missed = request.args.get("missed") == "1"
    rows = _read_cdr(q=q, date=date, limit=5000)
    if missed:
        rows = [r for r in rows if r["disposition"] != "ANSWERED"]
    from .jalali import jalali_datetime
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["مبدأ", "مقصد", "زمان (شمسی)", "مدت گفتگو (ثانیه)", "وضعیت"])
    for r in rows:
        writer.writerow([r["src"], r["dst"], jalali_datetime(r["start"]),
                         r["billsec"],
                         "پاسخ داده شد" if r["disposition"] == "ANSWERED"
                         else {"NO ANSWER": "بی‌پاسخ", "BUSY": "مشغول",
                               "FAILED": "ناموفق"}.get(r["disposition"],
                                                      r["disposition"])])
    body = "\ufeff" + out.getvalue()
    stamp = time.strftime("%Y%m%d-%H%M")
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = \
        f"attachment; filename=cdr-{stamp}.csv"
    return resp


# --------------------------------------------------------------- recordings
@bp.get("/recordings")
def recordings():
    files = []
    if os.path.isdir(RECORDINGS_DIR):
        for path in glob.glob(os.path.join(RECORDINGS_DIR, "*.wav")):
            st = os.stat(path)
            files.append({"name": os.path.basename(path), "size": st.st_size,
                          "mtime": st.st_mtime})
    files.sort(key=lambda x: x["mtime"], reverse=True)
    return render_template("recordings.html", files=files[:300])


@bp.get("/recordings/<path:name>")
def recording_file(name):
    if "/" in name or ".." in name:
        abort(400)
    return send_from_directory(RECORDINGS_DIR, name)


# ----------------------------------------------------------------- settings
@bp.route("/settings", methods=["GET", "POST"])
def settings_page():
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "password":
            old = request.form.get("old_password", "")
            new = request.form.get("new_password", "")
            new2 = request.form.get("new_password2", "")
            if not _verify_password(old, db.get_setting("admin_hash")):
                flash("رمز فعلی نادرست است.", "error")
            elif len(new) < 8:
                flash("رمز جدید باید حداقل ۸ نویسه باشد.", "error")
            elif new != new2:
                flash("تکرار رمز جدید مطابقت ندارد.", "error")
            else:
                db.set_setting("admin_hash", _hash_password(new))
                flash("رمز مدیر تغییر کرد ✅", "ok")
        elif action == "viewer":
            clear = request.form.get("clear") == "1"
            new = request.form.get("viewer_password", "")
            new2 = request.form.get("viewer_password2", "")
            if clear:
                db.set_setting("viewer_hash", "")
                flash("حساب گزارش‌گیر حذف شد.", "ok")
            elif len(new) < 8:
                flash("رمز گزارش‌گیر باید حداقل ۸ نویسه باشد.", "error")
            elif new != new2:
                flash("تکرار رمز گزارش‌گیر مطابقت ندارد.", "error")
            else:
                db.set_setting("viewer_hash", _hash_password(new))
                flash("حساب گزارش‌گیر ساخته شد — این کاربر فقط گزارش تماس‌ها را می‌بیند ✅", "ok")
        elif action == "notify":
            for key in ("tg_bot_token", "tg_chat_id", "webhook_url", "smtp_host",
                        "smtp_port", "smtp_user", "smtp_pass", "smtp_tls",
                        "smtp_from", "notify_email"):
                db.set_setting(key, request.form.get(key, "").strip())
            for key in ("notify_missed", "notify_trunk", "notify_login"):
                db.set_setting(key, "1" if request.form.get(key) == "on" else "0")
            flash("تنظیمات اعلان ذخیره شد ✅", "ok")
        elif action == "notify_test":
            notifier.send_async("🔔 پیام آزمایشی از پنل تلفن — اگر این را می‌بینید، اعلان‌ها کار می‌کنند.")
            flash("پیام آزمایشی ارسال شد؛ چند لحظه صبر کنید و کانال‌های اعلان را چک کنید.", "ok")
        elif action == "pbx":
            dest = request.form.get("inbound_dest", "").strip()
            if dest and not db.get_extension(dest):
                flash("داخلی مقصد تماس ورودی وجود ندارد.", "error")
            else:
                db.set_setting("inbound_dest", dest)
                db.set_setting("nat_public_ip", request.form.get("nat_public_ip", "").strip())
                db.set_setting("lan_ip", request.form.get("lan_ip", "").strip())
                _flash_apply(_apply_changes(), "تنظیمات سانترال")
        elif action == "rebuild":
            _flash_apply(_apply_changes(), "بازسازی کامل کانفیگ‌ها")
        return redirect(url_for("main.settings_page"))
    return render_template("settings.html", s=db.all_settings(), exts=db.list_extensions(),
                           seclog=db.list_security_log(30))


# ------------------------------------------------------------- provisioning
@bp.get("/provisioning/<path:fname>")
def provisioning_file(fname):
    mac = provisioning.parse_mac(fname)
    ext = db.get_extension_by_mac(mac) if mac else None
    if not ext:
        abort(404)
    server_ip = db.get_setting("lan_ip") or request.host.split(":")[0]
    xml = provisioning.build_config(ext, server_ip)
    resp = make_response(xml, 200)
    resp.headers["Content-Type"] = "text/xml; charset=utf-8"
    return resp


# -------------------------------------------------------------- ring groups
@bp.route("/ringgroups", methods=["GET", "POST"])
def ringgroups():
    if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "delete":
            rg_id = request.form.get("id", "").strip()
            if rg_id.isdigit():
                db.delete_ring_group(int(rg_id))
                _flash_apply(_apply_changes(), "گروه زنگ")
        else:
            name = request.form.get("name", "").strip()[:60] or "گروه زنگ"
            raw = request.form.get("members", "").replace("،", ",")
            members, dropped = [], []
            for m in raw.split(","):
                m = m.strip()
                if not m:
                    continue
                if db.get_extension(m):
                    members.append(m)
                else:
                    dropped.append(m)
            timeout = request.form.get("timeout", "20").strip()
            timeout = timeout if timeout.isdigit() and 5 <= int(timeout) <= 120 else "20"
            fallback = request.form.get("fallback", "").strip()
            if not members:
                flash("حداقل یک داخلیِ موجود (با کاما جدا کنید) لازم است.", "error")
            elif fallback and not db.sane_destination(fallback):
                flash("مقصد پیش‌فرض نامعتبر است.", "error")
            else:
                if dropped:
                    flash(f"این شماره‌ها داخلی موجود نیستند و حذف شدند: {', '.join(dropped)}", "warn")
                rg_id = request.form.get("id", "").strip()
                what = "گروه زنگ"
                if rg_id.isdigit() and db.get_ring_group(int(rg_id)):
                    db.update_ring_group(int(rg_id), name, ",".join(members), timeout, fallback)
                else:
                    db.add_ring_group(name, ",".join(members), timeout, fallback)
                _flash_apply(_apply_changes(), what)
        return redirect(url_for("main.ringgroups"))
    return render_template("ringgroups.html", groups=db.list_ring_groups(),
                           dests=db.destination_choices(),
                           edit_group=db.get_ring_group(request.args.get("edit"))
                           if request.args.get("edit", "").isdigit() else None)


# --------------------------------------------------------------- IVR menus
@bp.route("/ivr", methods=["GET", "POST"])
def ivr_page():
    prompts = sorted(os.path.basename(p) for p in glob.glob(os.path.join(SOUNDS_CUSTOM, "*.wav")))
    if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "delete":
            ivr_id = request.form.get("id", "").strip()
            if ivr_id.isdigit():
                db.delete_ivr_menu(int(ivr_id))
                _flash_apply(_apply_changes(), "منوی صوتی")
        else:
            name = request.form.get("name", "").strip()[:60] or "منوی صوتی"
            timeout = request.form.get("timeout", "6").strip()
            timeout = timeout if timeout.isdigit() and 2 <= int(timeout) <= 30 else "6"
            fallback = request.form.get("fallback", "").strip()
            prompt = request.form.get("prompt_select", "").strip()
            upload = request.files.get("prompt_file")
            if upload is not None and upload.filename:
                base = "".join(ch for ch in os.path.splitext(upload.filename)[0]
                               if ch.isalnum() or ch in "-_")[:40] or "prompt"
                os.makedirs(SOUNDS_CUSTOM, exist_ok=True)
                fname = f"ivr-{secrets.token_hex(4)}-{base}.wav"
                upload.save(os.path.join(SOUNDS_CUSTOM, fname))
                prompt = fname
            digits = request.form.getlist("opt_digit")
            dests = request.form.getlist("opt_dest")
            options = {}
            for digit, d in zip(digits, dests):
                digit = digit.strip()
                d = d.strip()
                if digit.isdigit() and 0 <= int(digit) <= 9 and d and db.sane_destination(d):
                    options[digit] = d
            if fallback and not db.sane_destination(fallback):
                flash("مقصد پیش‌فرض نامعتبر است.", "error")
            else:
                ivr_id = request.form.get("id", "").strip()
                if ivr_id.isdigit() and db.get_ivr_menu(int(ivr_id)):
                    db.update_ivr_menu(int(ivr_id), name, prompt, timeout,
                                       json.dumps(options, ensure_ascii=False), fallback)
                else:
                    db.add_ivr_menu(name, prompt, timeout,
                                    json.dumps(options, ensure_ascii=False), fallback)
                _flash_apply(_apply_changes(), "منوی صوتی")
        return redirect(url_for("main.ivr_page"))
    menus = db.list_ivr_menus()
    for m in menus:
        try:
            m["options_dict"] = json.loads(m["options"] or "{}")
        except ValueError:
            m["options_dict"] = {}
    edit_id = request.args.get("edit", "")
    edit_menu = db.get_ivr_menu(int(edit_id)) if edit_id.isdigit() else None
    if edit_menu:
        try:
            edit_menu["options_dict"] = json.loads(edit_menu["options"] or "{}")
        except ValueError:
            edit_menu["options_dict"] = {}
    return render_template("ivr.html", menus=menus, dests=db.destination_choices(),
                           prompts=prompts, edit_menu=edit_menu)


# ----------------------------------------------------------- business hours
@bp.route("/hours", methods=["GET", "POST"])
def hours_page():
    if request.method == "POST":
        action = request.form.get("action", "hours")
        if action == "holiday_add":
            jdate = request.form.get("jdate", "").strip()
            label = request.form.get("label", "").strip()[:60]
            from .jalali import jalali_str_to_gregorian
            g = jalali_str_to_gregorian(jdate)
            if not g:
                flash("تاریخ شمسی نامعتبر است — مثل: ۱۴۰۵/۰۸/۱۶", "error")
            else:
                db.add_holiday(f"{g[0]:04d}-{g[1]:02d}-{g[2]:02d}", label)
                _flash_apply(_apply_changes(), "تعطیلی")
        elif action == "holiday_del":
            gdate = request.form.get("gdate", "").strip()
            if gdate:
                db.delete_holiday(gdate)
                _flash_apply(_apply_changes(), "حذف تعطیلی")
        else:
            import re as _re
            hhmm = r"([01]?\d|2[0-3]):[0-5]\d"
            db.set_setting("wh_enabled", "1" if request.form.get("wh_enabled") == "on" else "0")
            for i in range(7):
                for kind in ("open", "close"):
                    v = request.form.get(f"wh_{kind}_{i}", "").strip()
                    if not _re.fullmatch(hhmm, v):
                        v = ""
                    db.set_setting(f"wh_{kind}_{i}", v)
            closed_dest = request.form.get("closed_dest", "").strip()
            if closed_dest and not db.sane_destination(closed_dest):
                flash("مقصد خارج از ساعات کاری نامعتبر است.", "error")
            else:
                db.set_setting("closed_dest", closed_dest)
                _flash_apply(_apply_changes(), "ساعات کاری")
        return redirect(url_for("main.hours_page"))
    from .jalali import gregorian_to_jalali_str, WEEKDAYS_FA, ASTERISK_DAYS
    s = db.all_settings()
    days = [{"idx": i, "fa": WEEKDAYS_FA[i], "ast": ASTERISK_DAYS[i],
             "open": s.get(f"wh_open_{i}", ""), "close": s.get(f"wh_close_{i}", "")}
            for i in range(7)]
    holidays = [{"gdate": h["gdate"], "jdate": gregorian_to_jalali_str(h["gdate"]),
                 "label": h["label"]} for h in db.list_holidays()]
    return render_template("hours.html", s=s, days=days, holidays=holidays,
                           dests=db.destination_choices())


# ---------------------------------------------------------------- voicemail
def _vm_boxes():
    exts = [e for e in db.list_extensions() if int(e["voicemail"] or 0)]
    return ([{"ext": "main", "name": "صندوق اصلی"}]
            + [{"ext": e["ext"], "name": e["display_name"]} for e in exts])


@bp.get("/voicemail")
def voicemail_page():
    boxes = []
    for box in _vm_boxes():
        inbox = os.path.join(VM_SPOOL, box["ext"], "INBOX")
        msgs = []
        if os.path.isdir(inbox):
            for path in glob.glob(os.path.join(inbox, "*.wav")):
                st = os.stat(path)
                m = __import__("re").match(r"msg(\d{4})", os.path.basename(path))
                msgs.append({"name": os.path.basename(path), "size": st.st_size,
                             "mtime": st.st_mtime,
                             "num": int(m.group(1)) if m else 0})
        msgs.sort(key=lambda x: x["num"], reverse=True)
        boxes.append({**box, "messages": msgs[:100]})
    return render_template("voicemail.html", boxes=boxes)


@bp.get("/voicemail/<mbx>/<path:fname>")
def voicemail_audio(mbx, fname):
    if "/" in fname or ".." in fname:
        abort(400)
    if mbx not in {b["ext"] for b in _vm_boxes()}:
        abort(404)
    return send_from_directory(os.path.join(VM_SPOOL, mbx, "INBOX"), fname)


@bp.post("/voicemail/<mbx>/<fname>/delete")
def voicemail_delete(mbx, fname):
    if "/" in fname or ".." in fname:
        abort(400)
    if mbx not in {b["ext"] for b in _vm_boxes()}:
        abort(404)
    target = os.path.join(VM_SPOOL, mbx, "INBOX", fname)
    if os.path.isfile(target):
        os.remove(target)
        flash("پیام صوتی حذف شد.", "ok")
    return redirect(url_for("main.voicemail_page"))


# ---------------------------------------------------------- softphone QR
@bp.get("/extensions/<ext>/qr")
def extension_qr(ext):
    e = db.get_extension(ext)
    if not e:
        abort(404)
    try:
        import qrcode
        import qrcode.image.svg
        url = f"http://{request.host}/provisioning/"
        img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=12)
        buf = io.BytesIO()
        img.save(buf)
        svg = buf.getvalue().decode("utf-8")
    except ImportError:
        svg = ""
    server_ip = db.get_setting("lan_ip") or request.host.split(":")[0]
    return render_template("qr.html", e=e, svg=svg,
                           url=f"http://{request.host}/provisioning/",
                           sip=f"sip:{e['ext']}@{server_ip}")


# ---------------------------------------------------------- backup/restore
@bp.get("/backup")
def backup_download():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in os.listdir(db.DATA_DIR):
            if name in ("notifier.lock",):
                continue
            tar.add(os.path.join(db.DATA_DIR, name), arcname=f"./{name}")
    buf.seek(0)
    stamp = time.strftime("%Y%m%d-%H%M")
    return send_file(buf, as_attachment=True, download_name=f"ipbx-backup-{stamp}.tar.gz",
                     mimetype="application/gzip")


@bp.post("/backup/restore")
def backup_restore():
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith((".tar.gz", ".tgz")):
        flash("فایل پشتیبان (tar.gz) را انتخاب کنید.", "error")
        return redirect(url_for("main.settings_page"))
    try:
        tf = tarfile.open(fileobj=f.stream, mode="r:gz")
    except tarfile.TarError:
        flash("فایل پشتیبان قابل بازگشایی نیست.", "error")
        return redirect(url_for("main.settings_page"))
    safe = []
    for m in tf.getmembers():
        name = m.name.lstrip("./")
        if m.name.startswith("/") or ".." in m.name.split("/"):
            tf.close()
            flash("فایل پشتیبان نامعتبر است (مسیر خطرناک).", "error")
            return redirect(url_for("main.settings_page"))
        m.name = name
        if name:
            safe.append(m)
    tf.extractall(db.DATA_DIR, members=safe)
    tf.close()
    db.init_db()
    _flash_apply(_apply_changes(), "بازیابی پشتیبان")
    flash("پشتیبان بازیابی شد ✅ (اگر ضبط‌ها را بازگردانده‌اید، لحظه‌ای بعد به‌روز می‌شوند)", "ok")
    return redirect(url_for("main.settings_page"))
