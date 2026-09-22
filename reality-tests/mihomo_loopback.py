"""Explicit local acceptance against an official Mihomo binary supplied by the caller.

Creates only loopback listeners, temporary fixtures, and child processes. No TUN,
system proxy, controller, remote target, Docker, or outside-repository imports.
"""

from __future__ import annotations

import argparse
import json
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path

# Public, throwaway fixture key pair already used in VCore acceptance; never
# suitable for actual deployment. No generated ephemeral TLS secrets are logged.
PRIVATE_KEY = "eNc1RW_wzi_qpuGZFwV-d6end6xbUyvVuKDrCpz5Z0Q"
PUBLIC_KEY = "TrotdL9Y_dMWo-eqNe5dGfx7AbY1vNJjuEvRs4WR2y4"
SHORT_ID = "0123456789abcdef"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.counter_lock:
            self.server.connections += 1
        self.request.settimeout(10)
        while data := self.request.recv(65536):
            with self.server.counter_lock:
                self.server.received_bytes += len(data)
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        self.counter_lock = threading.Lock()
        self.connections = 0
        self.received_bytes = 0
        super().__init__(address, handler)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def wait_ready(process, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("peer exited before listener was ready; inspect private run log")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("loopback peer startup timed out")


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run_case(args, mode, target_group, case, expect_success, short_id=SHORT_ID, expected_error=None, public_key=PUBLIC_KEY):
    with tempfile.TemporaryDirectory(prefix="rustls-reality-") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        cert, key = directory / "fixture.crt", directory / "fixture.key"
        subprocess.run([
            args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(cert), "-days", "1", "-subj", "/CN=fixture.invalid",
        ], check=True, capture_output=True, timeout=15)
        decoy_port, peer_port = free_port(), free_port()
        decoy = subprocess.Popen([
            args.openssl, "s_server", "-accept", f"127.0.0.1:{decoy_port}",
            "-cert", str(cert), "-key", str(key), "-tls1_3", "-groups", target_group,
            "-alpn", "h2,http/1.1", "-quiet", "-ign_eof",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(stop, decoy)
        wait_ready(decoy, decoy_port)
        config = {
            "mode": "rule", "log-level": "silent", "ipv6": False,
            "rules": ["MATCH,DIRECT"],
            "listeners": [{
                "name": "reality-probe", "type": "vless", "listen": "127.0.0.1", "port": peer_port,
                "users": [{"username": "fixture", "uuid": UUID}],
                "reality-config": {
                    "dest": f"127.0.0.1:{decoy_port}", "private-key": PRIVATE_KEY,
                    "short-id": [SHORT_ID], "server-names": ["fixture.invalid"],
                },
            }],
        }
        config_path = directory / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        peer = subprocess.Popen([
            str(args.mihomo), "-d", str(directory), "-f", str(config_path),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(stop, peer)
        wait_ready(peer, peer_port)
        echo = EchoServer(("127.0.0.1", 0), Echo)
        stack.callback(echo.server_close)
        thread = threading.Thread(target=echo.serve_forever, daemon=True)
        thread.start()
        stack.callback(thread.join, 3)
        stack.callback(echo.shutdown)
        result = subprocess.run([
            str(args.probe), "--peer", f"127.0.0.1:{peer_port}", "--sni", "fixture.invalid",
            "--public-key", public_key, "--short-id", short_id, "--uuid", UUID,
            "--target", f"127.0.0.1:{echo.server_address[1]}", "--mode", mode,
        ], capture_output=True, text=True, timeout=30)
        if (result.returncode == 0) != expect_success:
            raise RuntimeError(f"{case}: unexpected result {result.returncode}: {result.stdout} {result.stderr}")
        if expected_error and expected_error not in result.stderr:
            raise RuntimeError(f"{case}: expected {expected_error}, received {result.stderr}")
        with echo.counter_lock:
            connections, received_bytes = echo.connections, echo.received_bytes
        if expect_success and (connections, received_bytes) != (1, 31):
            raise RuntimeError(f"{case}: unexpected target traffic {connections=} {received_bytes=}")
        if not expect_success and (connections, received_bytes) != (0, 0):
            raise RuntimeError(f"{case}: rejected credentials leaked target traffic {connections=} {received_bytes=}")
        detail = result.stdout.strip() if expect_success else result.stderr.strip()
        print(f"PASS {case}: {detail}; target_connections={connections} target_bytes={received_bytes}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", required=True, type=Path, help="official latest binary, downloaded without source build")
    parser.add_argument("--openssl", required=True, help="OpenSSL with X25519MLKEM768 support")
    parser.add_argument("--probe", required=True, type=Path, help="compiled reality-hybrid-probe")
    args = parser.parse_args()
    print(subprocess.check_output([str(args.mihomo), "-v"], text=True).strip(), flush=True)
    print(subprocess.check_output([args.openssl, "version"], text=True).strip(), flush=True)
    run_case(args, "classic", "X25519", "classic-regression", True)
    run_case(args, "hybrid", "X25519MLKEM768", "hybrid-roundtrip", True)
    run_case(args, "fallback", "X25519", "explicitly-allowed-classic-fallback", True)
    run_case(args, "hybrid", "X25519", "hybrid-reject-classic-target", False, expected_error="AlertReceived(HandshakeFailure)")
    run_case(args, "hybrid", "X25519MLKEM768", "hybrid-reject-wrong-short-id", False, "fedcba9876543210", expected_error="InvalidCertificate")
    # RFC7748's valid X25519 basepoint is unrelated to the configured server key.
    run_case(args, "hybrid", "X25519MLKEM768", "hybrid-reject-wrong-public-key", False, expected_error="InvalidCertificate", public_key="CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")


if __name__ == "__main__":
    main()
