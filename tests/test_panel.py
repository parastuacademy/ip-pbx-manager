"""Panel (UI) smoke tests — the Persian admin interface.

Complements test_api.py: the API had 26 tests while the panel — the
surface the paying customer actually touches — had only a login-redirect
check. These 8 tests walk the real user paths:

  1. first-run /setup flow          5. add extension -> config regenerated
  2. login + dashboard render       6. CDR page renders
  3. CSRF blocks tokenless POST     7. viewer role restrictions + logout
  4. create API key from panel      8. backup download + restore round-trip

Run from the repo root:
    python3 -m unittest discover -s tests -v
"""
import io
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "app"))

os.environ.setdefault("IPBX_DATA_DIR", "/tmp/ipbx-test-data")

from ipbx import config_gen, create_app, db  # noqa: E402
from ipbx import routes  # noqa: E402

ADMIN_PW = "panel-admin-123"
VIEWER_PW = "panel-viewer-123"


class PanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        cls.app = create_app()
        cls.app.config["TESTING"] = True

    def setUp(self):
        # Deterministic state + fresh cookie jar per test, so the eight
        # tests are order-independent and the suite is re-runnable.
        routes._LOGIN_ATTEMPTS.clear()
        with db._conn() as c:
            c.execute("DELETE FROM settings WHERE key IN "
                      "('admin_hash', 'viewer_hash', 'wizard_done')")
        db.set_setting("admin_hash", routes._hash_password(ADMIN_PW))
        db.set_setting("wizard_done", "1")
        self.client = self.app.test_client()

    # ------------------------------------------------------------- helpers
    def _login(self, password=ADMIN_PW):
        r = self.client.post("/login", data={"password": password})
        self.assertEqual(r.status_code, 302, "login should succeed")
        return r

    def _csrf(self):
        # Rendering any page once makes the context processor store a
        # CSRF token in the session; read it back from the signed cookie.
        self.client.get("/cdr")
        with self.client.session_transaction() as s:
            return s["csrf"]

    # --------------------------------------------------------------- tests
    def test_first_run_setup_flow(self):
        with db._conn() as c:
            c.execute("DELETE FROM settings WHERE key = 'admin_hash'")
        try:
            r = self.client.get("/")          # no admin yet -> forced to /setup
            self.assertEqual(r.status_code, 302)
            self.assertIn("/setup", r.headers["Location"])
            r = self.client.post("/setup", data={"password": "short",
                                                 "password2": "short"})
            self.assertEqual(r.status_code, 200)          # stays on the form
            self.assertIsNone(db.get_setting("admin_hash"))
            r = self.client.post("/setup", data={"password": ADMIN_PW,
                                                 "password2": ADMIN_PW})
            self.assertEqual(r.status_code, 302)
            self.assertIn("/login", r.headers["Location"])
            self.assertIsNotNone(db.get_setting("admin_hash"))
        finally:
            db.set_setting("admin_hash", routes._hash_password(ADMIN_PW))

    def test_login_and_dashboard(self):
        r = self.client.post("/login", data={"password": "wrong-pass"})
        self.assertEqual(r.status_code, 200)              # back on the form
        with self.client.session_transaction() as s:
            self.assertNotIn("user", s)
        r = self._login()
        self.assertIn("/", r.headers["Location"])
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("داشبورد", html)
        self.assertIn("داخلی‌ها", html)                   # Persian RTL UI renders

    def test_csrf_blocks_post_without_token(self):
        self._login()
        r = self.client.post("/apikeys",
                             data={"action": "create_key", "name": "no-csrf"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual([k["name"] for k in db.list_api_keys()
                          if k["name"] == "no-csrf"], [])

    def test_create_api_key_from_panel(self):
        self._login()
        r = self.client.post("/apikeys", data={
            "action": "create_key", "name": "panel-smoke", "ip_allow": "",
            "csrf_token": self._csrf()})
        self.assertEqual(r.status_code, 302)
        self.assertIn("panel-smoke", [k["name"] for k in db.list_api_keys()])
        self.addCleanup(self._delete_keys_named, "panel-smoke")

    @staticmethod
    def _delete_keys_named(name):
        for k in db.list_api_keys():
            if k["name"] == name:
                db.delete_api_key(k["id"])

    def test_add_extension_generates_config(self):
        self._login()
        self.addCleanup(db.delete_extension, "150")
        r = self.client.post("/extensions", data={
            "ext": "150", "display_name": "تست پنل", "mac": "",
            "model": "generic", "csrf_token": self._csrf()})
        self.assertEqual(r.status_code, 302)
        self.assertIsNotNone(db.get_extension("150"))
        # The panel write path must have regenerated the Asterisk configs.
        with open(os.path.join(config_gen.AST_DIR,
                               "pjsip_endpoints.conf"), encoding="utf-8") as fh:
            self.assertIn("150", fh.read())
        # An invalid number (leading zero) is refused.
        r = self.client.post("/extensions", data={
            "ext": "0123", "display_name": "bad", "mac": "", "model": "generic",
            "csrf_token": self._csrf()})
        self.assertEqual(r.status_code, 302)
        self.assertIsNone(db.get_extension("0123"))

    def test_cdr_page_renders(self):
        self._login()
        r = self.client.get("/cdr")
        self.assertEqual(r.status_code, 200)
        self.assertIn("گزارش تماس‌ها", r.get_data(as_text=True))

    def test_viewer_role_restricted(self):
        db.set_setting("viewer_hash", routes._hash_password(VIEWER_PW))
        self._login(VIEWER_PW)
        with self.client.session_transaction() as s:
            self.assertEqual(s.get("role"), "viewer")
        self.assertEqual(self.client.get("/cdr").status_code, 200)   # reports OK
        self.assertEqual(self.client.get("/extensions").status_code, 302)
        self.assertEqual(self.client.post("/extensions/150/delete").status_code,
                         302)                                        # POST blocked
        r = self.client.post("/logout",                            # logout always OK
                             data={"csrf_token": self._csrf()})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        self.assertEqual(self.client.get("/").status_code, 302)      # session gone

    def test_backup_roundtrip(self):
        self._login()
        r = self.client.get("/backup")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data[:2], b"\x1f\x8b")                    # gzip magic
        r = self.client.post("/backup/restore", data={
            "file": (io.BytesIO(r.data), "backup.tar.gz"),
            "csrf_token": self._csrf()},
            content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/settings", r.headers["Location"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
