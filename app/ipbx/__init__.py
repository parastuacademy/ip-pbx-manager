"""ip-pbx-manager — management panel application factory."""
import os
import secrets
import time

from flask import Flask, abort, redirect, request, session, url_for

from . import db
from .routes import bp

EXEMPT_PATHS = ("/login", "/setup", "/health")


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
    app.secret_key = _secret_key(db.DATA_DIR)

    db.init_db()
    app.register_blueprint(bp)

    @app.context_processor
    def _inject_csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": lambda: session.get("csrf", "")}

    @app.template_filter("datetime_fa")
    def _filter_datetime_fa(value):
        return _datetime_fa(value)

    @app.before_request
    def _guard():
        """First-run redirect + authentication + CSRF check."""
        path = request.path
        if (
            path in EXEMPT_PATHS
            or path.startswith("/static/")
            or path.startswith("/provisioning/")
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
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not token or token != session.get("csrf"):
                abort(400)
        return None

    return app
