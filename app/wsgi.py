"""WSGI entry point: gunicorn --bind 0.0.0.0:8080 wsgi:app"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipbx import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PANEL_PORT", "8080")))
