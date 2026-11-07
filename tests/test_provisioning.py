"""Phone provisioning tests — Grandstream (cfg<MAC>.xml) + Yealink (<MAC>.cfg).

The panel must serve the right format to the right phone: a phone that
receives a foreign format silently misconfigures itself, so unknown file
names must 404 instead of falling back to Grandstream XML.

Run from the repo root:
    python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "app"))

os.environ.setdefault("IPBX_DATA_DIR", "/tmp/ipbx-test-data")

from ipbx import create_app, db, provisioning  # noqa: E402

MAC = "001565aabbcc"          # Yealink OUI 00:15:65


class ProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()
        db.delete_extension("150")
        db.add_extension("150", "تست گوشی", "pw150", mac=MAC, model="yealink")

    @classmethod
    def tearDownClass(cls):
        db.delete_extension("150")

    # ------------------------------------------------------------ identify
    def test_identify_patterns(self):
        self.assertEqual(provisioning.identify("cfgAABBCCDDEEFF.xml"),
                         ("grandstream", "AABBCCDDEEFF"))
        self.assertEqual(provisioning.identify("001565aabbcc.cfg"),
                         ("yealink", "001565AABBCC"))
        self.assertEqual(provisioning.identify("/x/001565AABBCC.cfg"),
                         ("yealink", "001565AABBCC"))
        self.assertEqual(provisioning.identify("notes.txt"), (None, None))
        self.assertEqual(provisioning.identify("001565aabb.cfg"), (None, None))
        self.assertEqual(provisioning.identify(""), (None, None))

    def test_model_choices_include_yealink(self):
        self.assertIn("yealink", [value for value, _ in db.model_choices()])

    # --------------------------------------------------------------- route
    def test_unknown_name_or_mac_gets_404(self):
        self.assertEqual(
            self.client.get("/provisioning/001565000000.cfg").status_code, 404)
        self.assertEqual(
            self.client.get("/provisioning/notes.txt").status_code, 404)

    def test_yealink_file_served(self):
        r = self.client.get(f"/provisioning/{MAC}.cfg")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/plain", r.headers["Content-Type"])
        body = r.get_data(as_text=True)
        self.assertIn("#!version:1.0.0.1", body)
        self.assertIn("account.1.user_name = 150", body)
        self.assertIn("account.1.auth_name = 150", body)
        self.assertIn("account.1.password = pw150", body)
        self.assertIn("account.1.sip_server_host = ", body)

    def test_grandstream_file_served(self):
        r = self.client.get(f"/provisioning/cfg{MAC}.xml")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/xml", r.headers["Content-Type"])
        body = r.get_data(as_text=True)
        self.assertIn("<gs_provision", body)
        self.assertIn("<P35>150</P35>", body)
        self.assertIn("<P37>pw150</P37>", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
