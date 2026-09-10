#!/usr/bin/env python3
"""Run with TMPDIR on the test volume; ffmpeg independently decodes each EXR."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    generator = Path(__file__).with_name("nas-fixtures.py")
    with tempfile.TemporaryDirectory(prefix="nas-fixtures-") as temporary:
        root = Path(temporary) / "sequence"
        command = [sys.executable, str(generator), str(root), "--case", "exr", "--frames", "3"]
        subprocess.run(command, check=True)
        expected = json.loads(root.with_name(root.name + ".sha256.json").read_text())
        assert len(expected) == len(set(expected.values())) == 3
        for name, digest in expected.items():
            path = root / name
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
            subprocess.run(["ffmpeg", "-v", "error", "-i", str(path), "-f", "null", "-"], check=True)
        before = {name: (root / name).read_bytes() for name in expected}
        assert subprocess.run(command, capture_output=True).returncode != 0
        assert subprocess.run(command + ["--frames", "0"], capture_output=True).returncode != 0
        assert before == {name: (root / name).read_bytes() for name in expected}
        print("EXR decoding, hashes, distinct frames and refusal checks passed")


if __name__ == "__main__":
    main()
