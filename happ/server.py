"""Convert this 3x-ui deployment's /sub/<token> into a Happ JSON subscription."""

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import threading
import urllib.error
import urllib.parse
import urllib.request

from happ_profile import build

MAX_SUBSCRIPTION_BYTES = 1024 * 1024
MAX_PROFILES = 64
TOKEN_PATH = re.compile(r"/happ/([A-Za-z0-9_-]{1,128})\Z")
PASSTHROUGH_HEADERS = ("subscription-userinfo", "profile-update-interval")


class InvalidSubscription(ValueError):
    pass


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def routing_header():
    routing = json.loads(Path(__file__).with_name("routing.json").read_text())
    routing.update({
        "Name": "iPhone - YouTube DPI", "UseChunkFiles": "true",
        "RemoteDNSType": "DoH", "RemoteDNSDomain": "https://1.1.1.1/dns-query",
        "RemoteDNSIP": "1.1.1.1",
    })
    encoded = base64.b64encode(json.dumps(routing, separators=(",", ":")).encode()).decode()
    return "happ://routing/onadd/" + encoded


def convert(body):
    try:
        text = body.decode("utf-8-sig").strip()
        if not text.startswith("vless://"):
            compact = "".join(text.split())
            text = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True).decode()
        links = [line.strip() for line in text.splitlines() if line.strip()]
        if not 1 <= len(links) <= MAX_PROFILES:
            raise InvalidSubscription("Invalid server count")
        profiles = []
        for link in links:
            if not link.startswith("vless://"):
                raise InvalidSubscription("Only VLESS TCP REALITY is supported")
            profile = build(link)
            label = urllib.parse.unquote(urllib.parse.urlsplit(link).fragment)
            label = " ".join(label.split())[:100]
            profile["remarks"] = "iPhone - YouTube DPI" + (" | " + label if label else "")
            profiles.append(profile)
        return json.dumps(profiles, ensure_ascii=False, separators=(",", ":")).encode()
    except (ValueError, UnicodeError):
        # Do not include the source body, URI or tokens in exceptions or logs.
        raise InvalidSubscription("Unsupported subscription") from None


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, upstream, timeout=10, upstream_host=""):
        parsed = urllib.parse.urlsplit(upstream)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("Invalid HAPP_SUB_BASE_URL")
        self.upstream = upstream.rstrip("/") + "/"
        if upstream_host and not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", upstream_host):
            raise ValueError("Invalid HAPP_SUB_HOST")
        self.upstream_host = upstream_host
        self.upstream_timeout = timeout
        self.routing = routing_header()
        # No ambient HTTP_PROXY and no redirects to other subscription providers.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # BaseHTTPServer's traceback could expose a secret subscription path.
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "HappSubscription"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        # Subscription tokens are credentials. Never log request paths.
        pass

    def respond(self, status, body, content_type="text/plain; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (headers or {}).items():
            if len(value) <= 8192 and "\r" not in value and "\n" not in value:
                self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.path == "/health":
            self.respond(200, b"ok\n")
            return
        if self.path == "/":
            self.respond(200, "В ссылке подписки замените /sub/ на /happ/ и добавьте её в Happ.\n".encode())
            return
        match = TOKEN_PATH.fullmatch(self.path)
        if not match:
            self.respond(404, b"Not found\n")
            return
        request_headers = {
            "User-Agent": "Happ", "Accept-Encoding": "identity",
        }
        if self.server.upstream_host:
            request_headers["Host"] = self.server.upstream_host
        request = urllib.request.Request(self.server.upstream + match.group(1),
                                         headers=request_headers)
        try:
            with self.server.opener.open(request, timeout=self.server.upstream_timeout) as upstream:
                body = upstream.read(MAX_SUBSCRIPTION_BYTES + 1)
                headers = {name: upstream.headers[name] for name in PASSTHROUGH_HEADERS
                           if name in upstream.headers}
            if len(body) > MAX_SUBSCRIPTION_BYTES:
                self.respond(502, b"Subscription too large\n")
                return
            converted = convert(body)
        except urllib.error.HTTPError as error:
            status = error.code if error.code in (401, 403, 404, 410, 429) else 502
            error.close()
            self.respond(status, b"Subscription unavailable\n")
            return
        except (urllib.error.URLError, TimeoutError, OSError):
            self.respond(502, b"Subscription unavailable\n")
            return
        except InvalidSubscription:
            self.respond(422, b"VLESS TCP REALITY subscription required\n")
            return
        headers.setdefault("profile-update-interval", "1")
        headers["profile-title"] = "base64:" + base64.b64encode(b"Happ - YouTube DPI").decode()
        headers["routing"] = self.server.routing
        self.respond(200, converted, "application/json; charset=utf-8", headers)


if __name__ == "__main__":
    server = Server((os.environ.get("HAPP_BIND", "0.0.0.0"),
                     int(os.environ.get("HAPP_PORT", "8081"))),
                    os.environ.get("HAPP_SUB_BASE_URL", "http://vless:2096/sub/"),
                    upstream_host=os.environ.get("HAPP_SUB_HOST", ""))
    print("Happ subscription service started", flush=True)
    server.serve_forever()
