#!/usr/bin/env python3
"""Create EXR sequence or fully written large-file fixtures in an explicit directory.

Example: nas-fixtures.py /mnt/test-source --case exr --frames 100000
Example: nas-fixtures.py /mnt/test-source --case large --gib 32
The output directory must not exist. Keep sources separate from received files.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import time


def exr(frame, size=64):
    """Small uncompressed RGB half-float scanline image with a unique frame ID."""
    def attribute(name, kind, data):
        return name.encode() + b"\0" + kind.encode() + b"\0" + struct.pack("<I", len(data)) + data

    channels = b"".join(channel + b"\0" + struct.pack("<iB3xii", 1, 0, 1, 1)
                        for channel in (b"B", b"G", b"R")) + b"\0"
    window = struct.pack("<4i", 0, 0, size - 1, size - 1)
    header = struct.pack("<II", 20000630, 2) + b"".join([
        attribute("channels", "chlist", channels),
        attribute("compression", "compression", b"\0"),
        attribute("dataWindow", "box2i", window),
        attribute("displayWindow", "box2i", window),
        attribute("lineOrder", "lineOrder", b"\0"),
        attribute("pixelAspectRatio", "float", struct.pack("<f", 1)),
        attribute("screenWindowCenter", "v2f", struct.pack("<ff", 0, 0)),
        attribute("screenWindowWidth", "float", struct.pack("<f", 1)),
        attribute("frameNumber", "int", struct.pack("<i", frame)),
    ]) + b"\0"
    # Channel planes are ordered B, G, R within each scanline.
    row = b"".join(struct.pack("<e", value / (size - 1)) for value in range(size)) * 3
    first = len(header) + size * 8
    offsets = b"".join(struct.pack("<Q", first + y * (8 + len(row))) for y in range(size))
    chunks = b"".join(struct.pack("<iI", y, len(row)) + row for y in range(size))
    return header + offsets + chunks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--case", choices=("exr", "large"), required=True)
    parser.add_argument("--frames", type=int, default=100_000)
    parser.add_argument("--gib", type=int, default=32)
    args = parser.parse_args()
    if not 1 <= args.frames <= 1_000_000 or not 1 <= args.gib <= 1024:
        parser.error("frames must be 1..1000000 and GiB 1..1024")
    parent = args.root.parent.resolve(strict=True)
    manifest = args.root.with_name(args.root.name + ".sha256.json")
    if args.root.exists() or manifest.exists():
        parser.error("fixture directory and manifest must not already exist")
    required = args.frames * len(exr(0)) if args.case == "exr" else args.gib * (1 << 30)
    if shutil.disk_usage(parent).free < required + (1 << 30):
        parser.error("insufficient fixture capacity plus 1 GiB headroom")
    args.root.mkdir(mode=0o700)
    started = time.perf_counter()
    hashes = {}
    if args.case == "exr":
        for frame in range(args.frames):
            name = f"sequence.{frame:06}.exr"
            data = exr(frame)
            with (args.root / name).open("xb") as stream:
                stream.write(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
            if frame and frame % 10_000 == 0:
                print(json.dumps({"generated_frames": frame}), flush=True)
    else:
        name = "large-file.bin"
        digest = hashlib.sha256()
        remaining = required
        with (args.root / name).open("xb") as stream:
            while remaining:
                data = os.urandom(min(8 << 20, remaining))
                stream.write(data)
                digest.update(data)
                remaining -= len(data)
            stream.flush()
            os.fsync(stream.fileno())
        hashes[name] = digest.hexdigest()
    with manifest.open("x") as stream:
        json.dump(hashes, stream, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"case": args.case, "files": len(hashes), "bytes": required,
                      "source": str(args.root), "sha256_manifest": str(manifest),
                      "generation_seconds": time.perf_counter() - started}), flush=True)


if __name__ == "__main__":
    main()
