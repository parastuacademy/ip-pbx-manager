"""All panel routes (Persian UI)."""
import csv
import glob
import hashlib
import os
import secrets
import time
from collections import deque

from flask import (Blueprint, abort, flash, jsonify, make_response, redirect,
                   render_template, request, send_from_directory, session,
                   url_for)

from . import config_gen, db, provisioning
from .ami import AMIClient, AMIError

bp = Blueprint("main", __name__)

RECORDINGS_DIR = os.path.join(db.DATA_DIR, "recordings")
CDR_PATH = os.path.join(db.DATA_DIR, "log", "cdr-csv", "Master.csv")

_LOGIN_ATTEMPTS = {}  # ip -> [count, window_start]


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
            config_gen.reload_asterisk(client)
        return True
    except AMIError:
        return False


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


def _read_cdr(q="", date="", limit=400):
    if not os.path.exists(CDR_PATH):
        return []
    with open(CDR_PATH, newline="", encoding="utf-8", errors="replace") as fh:
        lines = deque(fh, maxlen=5000)
    rows = []
    for row in csv.reader(lines):
        if len(row) < 14:
            continue
        src, dst, start, disposition = row[1], row[2], row[9], row[13]
        if q and q not in src and q not in dst:
            continue
        if date and not start.startswith(date):
            continue
        rows.append({
            "src": src, "dst": dst, "start": start, "answer": row[10],
            "end": row[11], "duration": row[12], "billsec": row[12],
            "disposition": disposition, "uniqueid": row[14] if len(row) > 14 else "",
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
            flash("تلاش‌های ناموفق زیاد است؛ ۱۰ دقیقه بعد دوباره امتحان کنید.", "error")
            return render_template("login.html"), 429
        if _verify_password(request.form.get("password", ""), db.get_setting("admin_hash")):
            _LOGIN_ATTEMPTS.pop(ip, None)
            session.clear()
            session["user"] = "admin"
            session.permanent = True
            return redirect(url_for("main.dashboard"))
        _LOGIN_ATTEMPTS[ip] = [count + 1, started]
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
        secret = request.form.get("secret", "").strip()
        if mac and db.get_extension_by_mac(mac) and db.get_extension_by_mac(mac)["ext"] != str(ext):
            flash("این MAC قبلاً برای داخلی دیگری ثبت شده است.", "error")
            return render_template("edit_extension.html", e=e, models=db.model_choices())
        db.update_extension(ext, display_name=name, mac=mac, model=model, record=record,
                            secret=secret or None)
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
    return render_template("cdr.html", rows=_read_cdr(q=q, date=date), q=q, date=date)


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
    return render_template("settings.html", s=db.all_settings(), exts=db.list_extensions())


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
