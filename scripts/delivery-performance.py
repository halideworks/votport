#!/usr/bin/env python3
"""Measure delivery preparation through CLI exit; verify every published byte.

Run each revision on the same machine and filesystem, alternating revisions.
Fixtures are created before timing. No production server or data is used.
"""

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--large-mib", type=int, default=256)
    parser.add_argument("--small-count", type=int, default=1000)
    parser.add_argument("--quic", action="store_true")
    parser.add_argument("--workflow", action="store_true")
    args = parser.parse_args()
    assert args.rounds > 0 and args.large_mib > 0 and args.small_count > 0
    args.root.mkdir(parents=True, exist_ok=True)
    fixture = args.root / "fixtures"
    for case in ("large", "small"):
        (fixture / case).mkdir(parents=True, exist_ok=True)
    large = fixture / "large" / "payload.bin"
    if not large.exists() or large.stat().st_size != args.large_mib * 1024 * 1024:
        with large.open("wb") as stream:
            for _ in range(args.large_mib):
                stream.write(os.urandom(1024 * 1024))
            stream.flush()
            os.fsync(stream.fileno())
    for index in range(args.small_count):
        path = fixture / "small" / f"{index:06}.bin"
        if not path.exists():
            path.write_bytes(os.urandom(4096))
    expected = {case: {path.name: digest(path) for path in (fixture / case).iterdir()}
                for case in ("large", "small")}
    with tempfile.TemporaryDirectory(prefix="run-", dir=args.root) as scratch:
        scratch = Path(scratch)
        tcp, udp = port(), port()
        base = f"http://127.0.0.1:{tcp}"
        env = os.environ | {
            "VOTPORT_BIND": f"127.0.0.1:{tcp}",
            "VOTPORT_PUBLIC_URL": base,
            "VOTPORT_DATA_DIR": str(scratch / "data"),
            "VOTPORT_RECEIVE_DIR": str(scratch / "received"),
            "VOTPORT_OUTBOUND_DIR": str(fixture),
            "VOTPORT_WEB_ROOT": str(Path(__file__).resolve().parent.parent / "web"),
            "VOTPORT_ADMIN_PASSWORD": "performance-fixture-only",
            "VOTPORT_MAX_UPLOAD_BYTES": str(1 << 40),
            "VOTPORT_SERVE_BIND": f"127.0.0.1:{udp}" if args.quic else "",
            "VOTPORT_SERVE_ADVERTISE": f"127.0.0.1:{udp}" if args.quic else "",
        }
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def api(path, body=None):
            request = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json", "X-Votport": "1"})
            with opener.open(request, timeout=300) as response:
                return json.load(response)

        with (scratch / "server.log").open("wb") as log:
            server = subprocess.Popen([str(args.server.resolve())], env=env, stdout=log, stderr=log)
            try:
                for _ in range(300):
                    try:
                        opener.open(base + "/healthz", timeout=1).close()
                        break
                    except OSError:
                        if server.poll() is not None:
                            raise RuntimeError((scratch / "server.log").read_text())
                        time.sleep(.1)
                else:
                    raise RuntimeError("server did not start")
                api("/api/admin/login", {"password": "performance-fixture-only"})
                if args.workflow:
                    for case in expected:
                        request = urllib.request.Request(base + "/api/workflows/projects", method="PUT",
                            data=json.dumps({"id": case, "directory": case, "label": case}).encode(),
                            headers={"Content-Type": "application/json", "X-Votport": "1"})
                        with opener.open(request) as response:
                            json.load(response)
                for repeat in range(args.rounds):
                    for case, hashes in expected.items():
                        start = time.perf_counter()
                        if args.workflow:
                            issued = api("/api/workflows/jobs", {"operation_id": f"{case}-{repeat}", "project_id": case,
                                         "label": case, "expires_days": 1})
                            for _ in range(15000):
                                if issued.get("url"):
                                    break
                                if issued["job"]["state"] == "failed":
                                    raise RuntimeError(issued["job"]["error"])
                                time.sleep(.01)
                                issued = api("/api/workflows/jobs/" + issued["job"]["id"])
                            else:
                                raise RuntimeError("job did not become ready")
                        else:
                            issued = api("/api/admin/outbound-grants", {"paths": [f"{case}/{name}" for name in hashes], "expires_days": 1})
                        prepared = time.perf_counter()
                        dest = scratch / f"receive-{case}-{repeat}"
                        completed = subprocess.run([str(args.client.resolve()), "receive", issued["url"], str(dest), "--json"],
                            env=os.environ | {"XDG_DATA_HOME": str(scratch / "client")}, capture_output=True, text=True, timeout=300)
                        finished = time.perf_counter()
                        if completed.returncode:
                            raise RuntimeError(completed.stdout + completed.stderr)
                        events = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith("{")]
                        done = next(event for event in reversed(events) if event.get("event") == "done")
                        received = {path.name: digest(path) for path in dest.rglob("*") if path.is_file()}
                        assert received == hashes, "published files differ"
                        print(json.dumps({"label": args.label, "case": case, "repeat": repeat, "workflow": args.workflow,
                              "transport": next((event["via"] for event in events if event.get("event") == "transport"), done.get("via", "unknown")), "quic_requested": args.quic,
                              "bytes": sum((fixture / case / name).stat().st_size for name in hashes), "files": len(hashes),
                              "prepare_seconds": prepared - start, "receive_seconds": finished - prepared,
                              "end_to_end_seconds": finished - start, "verified": True}), flush=True)
                        shutil.rmtree(dest)
            finally:
                server.terminate()
                try:
                    server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
