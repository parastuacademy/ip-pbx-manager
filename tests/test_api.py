"""Tests for the external REST API (/api/v1), webhook engine and CDR reader.

Run from the repo root:
    python3 -m unittest discover -s tests -v
"""
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "app"))

os.environ.setdefault("IPBX_DATA_DIR", "/tmp/ipbx-test-data")
DATA_DIR = os.environ["IPBX_DATA_DIR"]
os.makedirs(DATA_DIR, exist_ok=True)

from ipbx import create_app, db, webhooks  # noqa: E402
from ipbx import cdr  # noqa: E402
from ipbx.ami import AMIError  # noqa: E402
from unittest import mock  # noqa: E402

CDR_SAMPLE = (
    # 18-column layout produced by the repo's cdr.conf (loguniqueid=yes,
    # loguserfield=yes): disposition at index 14, amaflags=15, uniqueid=+2,
    # userfield=+3 — verified against asterisk/cdr/cdr_csv.c build_csv_record()
    ',"101","09121234567","internal","admin <101>","PJSIP/101-1",'
    '"PJSIP/pishgaman-2","Dial","PJSIP/pishgaman/09121234567,120",'
    '"2026-11-07 10:00:00","2026-11-07 10:00:05","2026-11-07 10:00:30",'
    '"30","25","ANSWERED","DOCUMENTATION","1762498800.1","api"\n'
    ',"02188776655","02144001122","from-trunk","caller <02188776655>",'
    '"PJSIP/pishgaman-in-3","PJSIP/101-4","Dial","PJSIP/101,45,t",'
    '"2026-11-07 11:00:00","","2026-11-07 11:00:20","20","0",'
    '"NO ANSWER","DOCUMENTATION","1762499200.2","inbound"\n'
)


class _HookRecorder(BaseHTTPRequestHandler):
    last = {}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _HookRecorder.last = {
            "path": self.path,
            "body": body,
            "event": self.headers.get("X-PBX-Event", ""),
            "delivery_id": self.headers.get("X-PBX-Delivery-Id", ""),
            "signature": self.headers.get("X-PBX-Signature", ""),
        }
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):  # silence test server logs
        pass


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def _make_key(self, name="test", ip_allow=""):
        return db.create_api_key(name, ip_allow=ip_allow)[1]

    def _auth(self, key):
        return {"Authorization": f"Bearer {key}"}

    def _ensure_ext(self, ext, name="Ext", pw="pw"):
        db.delete_extension(ext)
        db.add_extension(ext, name, pw)

    def _drop_ext(self, ext):
        db.delete_extension(ext)


class AuthTests(Base):
    def test_ping_needs_no_key(self):
        r = self.client.get("/api/v1/ping")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["data"]["api"], "v1")

    def test_missing_key_rejected(self):
        r = self.client.get("/api/v1/calls")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_json()["error"]["code"], "missing_key")

    def test_bad_key_rejected(self):
        r = self.client.get("/api/v1/calls", headers=self._auth("pbx_wrong"))
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_json()["error"]["code"], "invalid_key")

    def test_x_api_key_header_works(self):
        key = self._make_key("xheader")
        r = self.client.get("/api/v1/calls", headers={"X-API-Key": key})
        self.assertEqual(r.status_code, 200)

    def test_ip_allowlist(self):
        key = self._make_key("restricted", ip_allow="10.99.99.99")
        r = self.client.get("/api/v1/calls", headers=self._auth(key))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["error"]["code"], "ip_not_allowed")
        kid = None
        for k in db.list_api_keys():
            if k["prefix"] == key[:12]:
                kid = k["id"]
        with db._conn() as c:
            c.execute("UPDATE api_keys SET ip_allow = '127.0.0.0/8' WHERE id = ?",
                      (kid,))
        r = self.client.get("/api/v1/calls", headers=self._auth(key))
        self.assertEqual(r.status_code, 200)

    def test_rate_limit(self):
        key = self._make_key("ratelimited")
        from ipbx import api as api_module
        with mock.patch.object(api_module, "RATE_LIMIT", 2):
            for _ in range(2):
                self.assertEqual(
                    self.client.get("/api/v1/calls",
                                    headers=self._auth(key)).status_code, 200)
            r = self.client.get("/api/v1/calls", headers=self._auth(key))
            self.assertEqual(r.status_code, 429)
            self.assertIn("Retry-After", r.headers)

    def test_panel_page_requires_login(self):
        r = self.client.get("/apikeys")
        self.assertEqual(r.status_code, 302)


class ClickToCallTests(Base):
    def test_missing_fields(self):
        key = self._make_key("c2c")
        r = self.client.post("/api/v1/calls/click-to-call", headers=self._auth(key),
                             json={"agent": "101"})
        self.assertEqual(r.status_code, 422)

    def test_unknown_agent(self):
        key = self._make_key("c2c")
        r = self.client.post("/api/v1/calls/click-to-call", headers=self._auth(key),
                             json={"agent": "999", "destination": "102"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.get_json()["error"]["code"], "unknown_extension")

    def test_invalid_destination(self):
        self._ensure_ext("101", "Agent One", "pw101")
        key = self._make_key("c2c")
        r = self.client.post("/api/v1/calls/click-to-call", headers=self._auth(key),
                             json={"agent": "101", "destination": "abc!!"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.get_json()["error"]["code"], "invalid_destination")

    def test_internal_destination_accepted(self):
        self._ensure_ext("101", "Agent One", "pw101")
        self._ensure_ext("102", "Agent Two", "pw102")
        key = self._make_key("c2c")
        with mock.patch("ipbx.api.AMIClient") as cls:
            inst = cls.return_value.__enter__.return_value
            inst.originate.return_value = True
            r = self.client.post("/api/v1/calls/click-to-call",
                                 headers=self._auth(key),
                                 json={"agent": "101", "destination": "102"})
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.get_json()["data"]["context"], "internal")
        inst.originate.assert_called_once()
        args, _kwargs = inst.originate.call_args
        self.assertEqual(args[0], "PJSIP/101")
        self.assertEqual(args[1], "internal")
        self.assertEqual(args[2], "102")

    def test_external_destination_routes_outbound(self):
        self._ensure_ext("101", "Agent One", "pw101")
        key = self._make_key("c2c")
        with mock.patch("ipbx.api.AMIClient") as cls:
            inst = cls.return_value.__enter__.return_value
            r = self.client.post("/api/v1/calls/click-to-call",
                                 headers=self._auth(key),
                                 json={"agent": "101",
                                       "destination": "02188776655"})
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.get_json()["data"]["context"], "outbound")

    def test_asterisk_down_returns_503(self):
        self._ensure_ext("101", "Agent One", "pw101")
        key = self._make_key("c2c")
        with mock.patch("ipbx.api.AMIClient") as cls:
            cls.return_value.__enter__.side_effect = AMIError("no connection")
            r = self.client.post("/api/v1/calls/click-to-call",
                                 headers=self._auth(key),
                                 json={"agent": "101", "destination": "102"})
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.get_json()["error"]["code"], "asterisk_unreachable")


class CallsTests(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = db.create_api_key("calls")[1]
        os.makedirs(os.path.dirname(cdr.CDR_PATH), exist_ok=True)
        with open(cdr.CDR_PATH, "w", encoding="utf-8") as fh:
            fh.write(CDR_SAMPLE)

    def test_list_calls_envelope(self):
        r = self.client.get("/api/v1/calls", headers=self._auth(self.key))
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["meta"]["total"], 2)
        self.assertEqual(len(body["data"]), 2)
        newest = body["data"][0]
        self.assertEqual(newest["uniqueid"], "1762499200.2")
        self.assertEqual(newest["direction"], "inbound")
        older = body["data"][1]
        self.assertEqual(older["direction"], "outbound")

    def test_filters_and_pagination(self):
        h = self._auth(self.key)
        r = self.client.get("/api/v1/calls?q=09121234567", headers=h)
        self.assertEqual(r.get_json()["meta"]["total"], 1)
        r = self.client.get("/api/v1/calls?disposition=NO%20ANSWER", headers=h)
        self.assertEqual(r.get_json()["meta"]["total"], 1)
        r = self.client.get("/api/v1/calls?limit=1&offset=1", headers=h)
        body = r.get_json()
        self.assertEqual(len(body["data"]), 1)
        self.assertEqual(body["data"][0]["uniqueid"], "1762498800.1")
        r = self.client.get("/api/v1/calls?disposition=JUNK", headers=h)
        self.assertEqual(r.status_code, 422)
        r = self.client.get("/api/v1/calls?limit=zzz", headers=h)
        self.assertEqual(r.status_code, 422)

    def test_single_call(self):
        h = self._auth(self.key)
        r = self.client.get("/api/v1/calls/1762498800.1", headers=h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["data"]["billsec"], "25")
        r = self.client.get("/api/v1/calls/nope.0", headers=h)
        self.assertEqual(r.status_code, 404)

    def test_recording_download(self):
        os.makedirs(cdr.RECORDINGS_DIR, exist_ok=True)
        path = os.path.join(cdr.RECORDINGS_DIR, "1762498800.1.wav")
        with open(path, "wb") as fh:
            fh.write(b"RIFFfake")
        r = self.client.get("/api/v1/calls/1762498800.1/recording",
                            headers=self._auth(self.key))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, b"RIFFfake")
        r = self.client.get("/api/v1/calls/1762499200.2/recording",
                            headers=self._auth(self.key))
        self.assertEqual(r.status_code, 404)

    def test_extensions_and_trunk(self):
        self._ensure_ext("101", "Agent One", "pw101")
        self._ensure_ext("201", "Ext Two", "pw201")
        with mock.patch("ipbx.api.AMIClient") as cls:
            inst = cls.return_value.__enter__.return_value
            inst.online_extensions.return_value = {"201"}
            inst.trunk_registered.return_value = True
            r = self.client.get("/api/v1/extensions", headers=self._auth(self.key))
        self.assertEqual(r.status_code, 200)
        data = {e["ext"]: e for e in r.get_json()["data"]}
        self.assertTrue(data["201"]["online"])
        self.assertFalse(data["101"]["online"])
        with mock.patch("ipbx.api.AMIClient") as cls:
            cls.return_value.__enter__.return_value.trunk_registered.return_value = True
            r = self.client.get("/api/v1/trunk", headers=self._auth(self.key))
        self.assertTrue(r.get_json()["data"]["registered"])


class WebhookApiTests(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = db.create_api_key("hooks")[1]

    def test_create_list_delete(self):
        h = self._auth(self.key)
        r = self.client.post("/api/v1/webhooks", headers=h,
                             json={"url": "https://crm.example.com/hook",
                                   "events": ["call.missed"]})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertTrue(body["data"]["secret"].startswith("whsec_"))
        wid = body["data"]["id"]
        r = self.client.get("/api/v1/webhooks", headers=h)
        listed = [w for w in r.get_json()["data"] if w["id"] == wid]
        self.assertEqual(len(listed), 1)
        self.assertNotIn("secret", listed[0])  # masked after creation
        self.assertIn("secret_hint", listed[0])
        r = self.client.delete(f"/api/v1/webhooks/{wid}", headers=h)
        self.assertEqual(r.status_code, 200)
        r = self.client.delete(f"/api/v1/webhooks/{wid}", headers=h)
        self.assertEqual(r.status_code, 404)

    def test_invalid_webhook_input(self):
        h = self._auth(self.key)
        r = self.client.post("/api/v1/webhooks", headers=h,
                             json={"url": "ftp://x.com"})
        self.assertEqual(r.status_code, 422)
        r = self.client.post("/api/v1/webhooks", headers=h,
                             json={"url": "https://x.com/y", "events": ["nope"]})
        self.assertEqual(r.status_code, 422)
        self.assertIn("Allowed:", r.get_json()["error"]["message"])

    def test_test_endpoint_queues_event(self):
        h = self._auth(self.key)
        wid = db.create_webhook("https://example.com/h", ["webhook.test"],
                                "whsec_test", 1)
        r = self.client.post(f"/api/v1/webhooks/{wid}/test", headers=h)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["data"]["queued"])
        due = db.due_webhook_deliveries(time.time() + 1)
        self.assertTrue(any(e["webhook_id"] == wid for e in due))
        db.delete_webhook(wid)


class WebhookEngineTests(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.httpd = HTTPServer(("127.0.0.1", 0), _HookRecorder)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.webhook_id = db.create_webhook(
            f"http://127.0.0.1:{cls.port}/pbx-hook",
            ["call.missed", "call.ended"], "whsec_engine_secret", 1)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        db.delete_webhook(cls.webhook_id)
        super().tearDownClass()

    def test_missed_call_delivery_with_signature(self):
        row = {"src": "02188776655", "dst": "101", "start": "2026-11-07 11:00:00",
               "answer": "", "end": "2026-11-07 11:00:20", "duration": "20",
               "billsec": "0", "disposition": "NO ANSWER",
               "uniqueid": "1762499999.9", "userfield": "inbound"}
        webhooks.emit_call_events(row)
        due = db.due_webhook_deliveries(time.time() + 1)
        mine = [e for e in due if e["webhook_id"] == self.webhook_id]
        self.assertEqual({e["event"] for e in mine},
                         {"call.ended", "call.missed"})
        for entry in mine:
            webhooks._deliver_one(entry)
        got = _HookRecorder.last
        self.assertEqual(got["path"], "/pbx-hook")
        payload = json.loads(got["body"])
        self.assertIn(payload["event"], ("call.ended", "call.missed"))
        self.assertEqual(payload["data"]["uniqueid"], "1762499999.9")
        self.assertEqual(payload["data"]["direction"], "inbound")
        expected = "sha256=" + hmac.new(b"whsec_engine_secret", got["body"],
                                        hashlib.sha256).hexdigest()
        self.assertEqual(got["signature"], expected)
        self.assertEqual(got["event"], payload["event"])

    def test_retry_then_give_up(self):
        wid = db.create_webhook("http://127.0.0.1:1/impossible", ["call.ended"],
                                "whsec_x", 1)
        webhooks.emit_event("call.ended", {"uniqueid": "x"}, webhook_id=wid)
        now = time.time()
        entry = next(e for e in db.due_webhook_deliveries(now)
                     if e["webhook_id"] == wid)
        db.finish_webhook_delivery(entry["id"], ok=False, error="refused",
                                   retry_in=0, now=now)
        with db._conn() as c:
            attempts = c.execute("SELECT attempts FROM webhook_queue WHERE id = ?",
                                 (entry["id"],)).fetchone()["attempts"]
        self.assertEqual(attempts, 1)
        for _ in range(3):  # attempts 2..4 -> done after 4th
            db.finish_webhook_delivery(entry["id"], ok=False, error="refused",
                                       retry_in=0, now=now)
        with db._conn() as c:
            done = c.execute("SELECT done FROM webhook_queue WHERE id = ?",
                             (entry["id"],)).fetchone()["done"]
        self.assertEqual(done, 1)
        db.delete_webhook(wid)


class CdrReaderTests(Base):
    def test_find_recording_fallbacks(self):
        os.makedirs(cdr.RECORDINGS_DIR, exist_ok=True)
        self.assertIsNone(cdr.find_recording("123.45"))
        path = os.path.join(cdr.RECORDINGS_DIR, "123.45.wav")
        with open(path, "wb") as fh:
            fh.write(b"x")
        self.assertEqual(cdr.find_recording("123.45"), path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
