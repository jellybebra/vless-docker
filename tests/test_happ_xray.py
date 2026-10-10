"""Exercise IP-only routing with Xray; all outbounds are local blackhole sinks.

Set XRAY_BIN and XRAY_LOCATION_ASSET to run this optional integration test.
No packets are forwarded to the Internet and no real credentials are used.
"""

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "happ"))
from happ_profile import build


@unittest.skipUnless(os.environ.get("XRAY_BIN"), "Set XRAY_BIN to test real Xray routing")
class XrayRoutingTests(unittest.TestCase):
    def test_ip_only_game_connections_use_proxy(self):
        uri = ("vless://11111111-1111-4111-8111-111111111111@example.com:443"
               "?type=tcp&security=reality&sni=example.com"
               "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with patch("happ_profile.socket.getaddrinfo", return_value=[
                (2, 1, 6, "", ("192.0.2.1", 443))]):
            config = build(uri, port=port)
        with tempfile.TemporaryDirectory(prefix="happ-xray-") as folder:
            root = Path(folder)
            config_path = root / "config.json"
            # Validate the full generated configuration before replacing transports.
            config_path.write_text(json.dumps(config))
            validated = subprocess.run(
                [os.environ["XRAY_BIN"], "run", "-test", "-config", str(config_path)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(validated.returncode, 0, validated.stdout + validated.stderr)
            config["outbounds"] = [
                {"tag": out["tag"], "protocol": "blackhole", "settings": {}}
                for out in config["outbounds"]
            ]
            access = root / "access.log"
            config["log"] = {"access": str(access), "loglevel": "warning"}
            config_path.write_text(json.dumps(config))
            with (root / "stderr.log").open("w+") as errors:
                proc = subprocess.Popen(
                    [os.environ["XRAY_BIN"], "run", "-config", str(config_path)],
                    stdout=errors, stderr=errors)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                                break
                        except OSError:
                            if proc.poll() is not None or time.monotonic() > deadline:
                                errors.seek(0)
                                self.fail("Xray failed to start: " + errors.read())
                            time.sleep(.05)
                    cases = [
                        ("tcp", "93.184.216.34", 9339, "proxy"),
                        ("udp", "93.184.216.35", 9339, "proxy"),
                        ("tcp", "192.168.1.50", 9339, "direct"),
                        ("udp", "192.168.1.51", 9339, "direct"),
                        ("tcp", "93.184.216.36", 9440, "direct"),
                    ]
                    for network, address, destination_port, expected in cases:
                        with self.subTest(network=network, address=address, port=destination_port):
                            with socket.create_connection(("127.0.0.1", port), timeout=3) as control:
                                control.sendall(b"\x05\x01\x00")
                                self.assertEqual(self.read_exact(control, 2), b"\x05\x00")
                                target = b"\x01" + socket.inet_aton(address) + struct.pack("!H", destination_port)
                                command = b"\x01" if network == "tcp" else b"\x03"
                                request_target = target if network == "tcp" else b"\x01" + b"\0" * 6
                                control.sendall(b"\x05" + command + b"\x00" + request_target)
                                response = self.read_exact(control, 10)
                                self.assertEqual(response[:2], b"\x05\x00")
                                if network == "tcp":
                                    control.sendall(b"\x27\x74\x00\x00\x04\x00\x00test")
                                else:
                                    relay = (socket.inet_ntoa(response[4:8]), struct.unpack("!H", response[8:])[0])
                                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                                        datagram.sendto(b"\x00\x00\x00" + target + b"game-packet", relay)
                                destination = f"{network}:{address}:{destination_port}"
                                deadline = time.monotonic() + 5
                                while True:
                                    lines = access.read_text() if access.exists() else ""
                                    matches = [line for line in lines.splitlines() if destination in line]
                                    if matches or time.monotonic() > deadline:
                                        break
                                    time.sleep(.05)
                                self.assertTrue(matches, "Missing routing event for " + destination)
                                self.assertTrue(any(f"socks -> {expected}" in line or
                                                    f"socks >> {expected}" in line for line in matches), matches)
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)

    @staticmethod
    def read_exact(sock, count):
        result = b""
        while len(result) < count:
            chunk = sock.recv(count - len(result))
            if not chunk:
                raise AssertionError("Unexpected end of SOCKS response")
            result += chunk
        return result


if __name__ == "__main__":
    unittest.main()
