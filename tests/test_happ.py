import base64
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import socket
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "happ"))
from server import Server, MAX_SUBSCRIPTION_BYTES, MAX_PROFILES


def uri(client="11111111-1111-4111-8111-111111111111", host="example.com", name="Server"):
    return (f"vless://{client}@{host}:443?type=tcp&security=reality"
            "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=1234"
            f"&sni=example.com&fp=firefox#{name}")


class Upstream(BaseHTTPRequestHandler):
    body = uri().encode()
    status = 200
    calls = []
    headers_to_send = {}
    required_host = None

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.calls.append(self.path)
        self.send_response(403 if self.required_host and self.headers.get("Host") != self.required_host
                           else self.status)
        for key, value in self.headers_to_send.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(self.body)


class SubscriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        cls.adapter = Server(("127.0.0.1", 0),
                             f"http://127.0.0.1:{cls.upstream.server_port}/sub/")
        cls.threads = [threading.Thread(target=s.serve_forever, daemon=True)
                       for s in (cls.upstream, cls.adapter)]
        for thread in cls.threads:
            thread.start()
        cls.base = f"http://127.0.0.1:{cls.adapter.server_port}"

    @classmethod
    def tearDownClass(cls):
        for server in (cls.adapter, cls.upstream):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join()

    def setUp(self):
        Upstream.body = uri().encode()
        Upstream.status = 200
        Upstream.calls.clear()
        Upstream.headers_to_send = {}
        Upstream.required_host = None
        self.adapter.upstream_host = ""
        real_resolve = socket.getaddrinfo
        def resolve(host, *args, **kwargs):
            if host.endswith("example.com"):
                return [(2, 1, 6, "", ("192.0.2.1", 443))]
            return real_resolve(host, *args, **kwargs)
        self.dns = patch("happ_profile.socket.getaddrinfo", side_effect=resolve)
        self.dns.start()
        self.addCleanup(self.dns.stop)

    def get(self, path="/happ/sample-token", method="GET"):
        request = urllib.request.Request(self.base + path, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def test_plain_and_base64_subscriptions(self):
        for body in (uri().encode(), base64.b64encode(uri().encode())):
            Upstream.body = body
            status, headers, data = self.get()
            self.assertEqual(status, 200)
            profile = json.loads(data)[0]
            self.assertEqual(profile["outbounds"][1]["settings"]["vnext"][0]["address"], "example.com")
            self.assertEqual(profile["outbounds"][2]["settings"]["fragment"], {
                "packets": "tlshello", "length": "1-3", "interval": "1-2"})
            routing = json.loads(base64.b64decode(headers["routing"].rsplit("/", 1)[1]))
            self.assertEqual(routing["UseChunkFiles"], "true")
            self.assertIn("runetfreedom", routing["Geositeurl"])
            self.assertEqual(routing["RemoteDNSIP"], "1.1.1.1")
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["profile-update-interval"], "1")
        self.assertEqual(Upstream.calls, ["/sub/sample-token", "/sub/sample-token"])

    def test_refresh_updates_credentials_address_and_server_list(self):
        _, _, first = self.get()
        Upstream.body = (uri("22222222-2222-4222-8222-222222222222", "new.example.com", "New")
                         + "\n" + uri(name="Second")).encode()
        status, _, second = self.get()
        self.assertEqual(status, 200)
        self.assertNotEqual(first, second)
        profiles = json.loads(second)
        self.assertEqual(len(profiles), 2)
        server = profiles[0]["outbounds"][1]["settings"]["vnext"][0]
        self.assertEqual(server["address"], "new.example.com")
        self.assertEqual(server["users"][0]["id"], "22222222-2222-4222-8222-222222222222")
        self.assertEqual(profiles[0]["dns"]["hosts"], {"new.example.com": "192.0.2.1"})

    def test_upstream_domain_restriction_uses_configured_host(self):
        Upstream.required_host = "subscription.example.com"
        self.assertEqual(self.get()[0], 403)
        self.adapter.upstream_host = Upstream.required_host
        self.assertEqual(self.get()[0], 200)

    def test_revoked_subscription_is_not_served_from_cache(self):
        self.assertEqual(self.get()[0], 200)
        Upstream.status = 404
        Upstream.body = b"secret upstream details"
        status, _, body = self.get()
        self.assertEqual(status, 404)
        self.assertNotIn(b"secret", body)
        self.assertNotIn(b"vless", body)

    def test_metadata_is_preserved_but_upstream_routing_is_replaced(self):
        Upstream.headers_to_send = {
            "subscription-userinfo": "upload=1; download=2; total=3; expire=4",
            "profile-update-interval": "6", "routing": "happ://routing/off",
            "set-cookie": "secret=unsafe",
        }
        _, headers, _ = self.get()
        self.assertEqual(headers["subscription-userinfo"], Upstream.headers_to_send["subscription-userinfo"])
        self.assertEqual(headers["profile-update-interval"], "6")
        self.assertTrue(headers["routing"].startswith("happ://routing/onadd/"))
        self.assertIsNone(headers.get("set-cookie"))

    def test_path_validation_prevents_upstream_url_injection(self):
        for path in ("/happ/../other", "/happ/%2fsecret", "/happ/token?url=http://evil.example",
                     "/happ/token/extra", "/happ/", "/sub/token"):
            self.assertEqual(self.get(path)[0], 404)
        self.assertEqual(Upstream.calls, [])

    def test_redirect_is_not_followed(self):
        Upstream.status = 302
        Upstream.headers_to_send = {"Location": self.base + "/health"}
        self.assertEqual(self.get()[0], 502)
        self.assertEqual(Upstream.calls, ["/sub/sample-token"])

    def test_unsupported_or_mixed_subscription_fails_as_a_whole(self):
        for body in (b"not base64", b"[]", uri().replace("type=tcp", "type=ws").encode(),
                     (uri() + "\nvmess://unsupported").encode(), b""):
            Upstream.body = body
            status, _, response = self.get()
            self.assertEqual(status, 422)
            self.assertNotIn(b"11111111", response)

    def test_oversized_subscription_is_rejected(self):
        Upstream.body = b"x" * (MAX_SUBSCRIPTION_BYTES + 1)
        self.assertEqual(self.get()[0], 502)

    def test_excessive_server_count_is_rejected_before_resolution(self):
        Upstream.body = ("\n".join([uri()] * (MAX_PROFILES + 1))).encode()
        with patch("happ_profile.vless_outbound") as parse:
            self.assertEqual(self.get()[0], 422)
            parse.assert_not_called()

    def test_head_has_metadata_without_body(self):
        status, headers, body = self.get(method="HEAD")
        self.assertEqual(status, 200)
        self.assertGreater(int(headers["Content-Length"]), 0)
        self.assertTrue(headers["routing"].startswith("happ://routing/onadd/"))
        self.assertEqual(body, b"")

    def test_tokens_are_not_logged(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), contextlib.redirect_stdout(output):
            self.assertEqual(self.get("/happ/private-secret-token")[0], 200)
        self.assertNotIn("private-secret-token", output.getvalue())


if __name__ == "__main__":
    unittest.main()
