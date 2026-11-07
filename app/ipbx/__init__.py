"""ip-pbx-manager — management panel application factory."""
import os
import secrets
import time

from flask import Flask, abort, redirect, request, session, url_for

VERSION = "2.1"  # above the blueprint imports — app/ipbx/api.py reads it at load time

from . import db, notifier, webhooks  # noqa: E402
from .api import bp as api_bp  # noqa: E402
from .routes import bp  # noqa: E402

EXEMPT_PATHS = ("/login", "/setup", "/health")

# Paths (prefixes) the reports-only "viewer" account may open.
VIEWER_ALLOWED = ("/", "/cdr", "/api/status", "/health", "/logout")


def _datetime_fa(value):
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(value)))
    except (TypeError, ValueError):
        return str(value)


def _secret_key(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, "secret_key")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def create_app():
    base = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(base, "..", "templates"),
        static_folder=os.path.join(base, "..", "static"),
    )
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 12  # 12h
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # backup uploads
    app.secret_key = _secret_key(db.DATA_DIR)

    db.init_db()
    app.register_blueprint(bp)
    app.register_blueprint(api_bp)
    notifier.start_once()
    webhooks.start_once()

    @app.context_processor
    def _inject_csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": lambda: session.get("csrf", ""),
                "is_admin": lambda: session.get("role", "admin") == "admin"}

    @app.template_filter("datetime_fa")
    def _filter_datetime_fa(value):
        return _datetime_fa(value)

    @app.template_filter("jalali_dt")
    def _filter_jalali_dt(value):
        from .jalali import jalali_datetime
        return jalali_datetime(value)

    @app.template_filter("fa_digits")
    def _filter_fa_digits(value):
        from .jalali import fa_digits
        return fa_digits(value)

    @app.before_request
    def _guard():
        """First-run redirect + authentication + role check + CSRF check."""
        path = request.path
        if (
            path in EXEMPT_PATHS
            or path.startswith("/static/")
            or path.startswith("/provisioning/")
            or path.startswith("/api/v1/")  # external API: key-authenticated
            or path == "/favicon.ico"
        ):
            return None
        # First run: admin password must be created before anything else.
        if not db.get_setting("admin_hash"):
            if path != "/setup":
                return redirect(url_for("main.setup"))
            return None
        if not session.get("user"):
            return redirect(url_for("main.login"))
        # Viewer (reports-only) role: read-only pages only (logout always allowed).
        if session.get("role") == "viewer" and path != "/logout":
            allowed = any(path == p or path.startswith(p + "/") or path.startswith(p + "?")
                          for p in VIEWER_ALLOWED)
            if not allowed or request.method != "GET":
                return redirect(url_for("main.dashboard"))
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not token or token != session.get("csrf"):
                abort(400)
        return None

    return app
