"""Resumable official Docker Desktop ARM64 download with a fixed HTTP identity.

The mutable main-channel URL is pinned to the observed length and ETag. Verify
Apple code signing and notarization on the Mac before installing the result.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import time
import urllib.request
from pathlib import Path


URL = "https://desktop.docker.com/mac/main/arm64/Docker.dmg"
SIZE = 586_074_635
ETAG = '"4fbf48c083e83963deafc2426c0bead2"'
CHUNK = 8 * 1024 * 1024


def download_part(parts: Path, index: int) -> int:
    start, end = index * CHUNK, min(SIZE, (index + 1) * CHUNK) - 1
    expected = end - start + 1
    target = parts / f"{index:04d}.part"
    if target.is_file() and target.stat().st_size == expected:
        return index
    for attempt in range(12):
        try:
            request = urllib.request.Request(URL, headers={
                "Range": f"bytes={start}-{end}", "If-Match": ETAG,
                "User-Agent": "SkillLoop-Mac-migration/1"})
            with urllib.request.urlopen(request, timeout=90) as response:
                if (response.status != 206 or
                        response.headers.get("Content-Range") != f"bytes {start}-{end}/{SIZE}" or
                        response.headers.get("ETag") != ETAG):
                    raise ValueError("range_identity_mismatch")
                data = response.read(expected + 1)
            if len(data) != expected:
                raise ValueError("range_size_mismatch")
            temporary = target.with_suffix(".temporary")
            with temporary.open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            return index
        except (OSError, ValueError):
            if attempt == 11:
                raise
            time.sleep(min(2 ** attempt, 30))
    raise AssertionError("unreachable")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=12)
    args = parser.parse_args()
    if not 1 <= args.workers <= 24 or args.output.exists():
        raise ValueError("invalid_workers_or_existing_output")
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parts = args.output.with_suffix(".parts")
    parts.mkdir(mode=0o700, exist_ok=True)
    count = (SIZE + CHUNK - 1) // CHUNK
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(download_part, parts, i) for i in range(count)]
        for finished, future in enumerate(concurrent.futures.as_completed(futures), 1):
            future.result()
            print(f"downloaded {finished}/{count} chunks", flush=True)
    temporary = args.output.with_suffix(".assembling")
    digest = hashlib.sha256()
    with temporary.open("wb") as stream:
        for index in range(count):
            with (parts / f"{index:04d}.part").open("rb") as part:
                for chunk in iter(lambda: part.read(1024 * 1024), b""):
                    digest.update(chunk)
                    stream.write(chunk)
        stream.flush()
        os.fsync(stream.fileno())
    if temporary.stat().st_size != SIZE:
        raise ValueError("installer_size_mismatch")
    os.replace(temporary, args.output)
    metadata = {"url": URL, "size": SIZE, "etag": ETAG, "sha256": digest.hexdigest(),
                "signature_verified": False}
    args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata), flush=True)


if __name__ == "__main__":
    main()
