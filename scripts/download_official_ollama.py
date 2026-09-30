"""Resumable ranged download of a pinned official Ollama macOS release asset."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import os
import time
import urllib.request
from pathlib import Path


URL = "https://github.com/ollama/ollama/releases/download/v0.33.3/ollama-darwin.tgz"
SIZE = 159_236_337
SHA256 = "342db03df80bb9db84ff64246031bd5f70c09b59ff52fa5cc9aaae3476cc4a9d"
CHUNK = 2 * 1024 * 1024


def download_part(parts: Path, index: int) -> int:
    start, end = index * CHUNK, min(SIZE, (index + 1) * CHUNK) - 1
    expected = end - start + 1
    target = parts / f"{index:04d}.part"
    if target.is_file() and target.stat().st_size == expected:
        return index
    for attempt in range(12):
        try:
            request = urllib.request.Request(URL, headers={
                "Range": f"bytes={start}-{end}", "User-Agent": "SkillLoop-Mac-migration/1"})
            with urllib.request.urlopen(request, timeout=60) as response:
                if response.status != 206 or response.headers.get("Content-Range") != f"bytes {start}-{end}/{SIZE}":
                    raise ValueError("range_response_mismatch")
                data = response.read(expected + 1)
            if len(data) != expected:
                raise ValueError("range_length_mismatch")
            temporary = target.with_suffix(".tmp")
            temporary.write_bytes(data)
            os.replace(temporary, target)
            return index
        except (OSError, ValueError):
            if attempt == 11:
                raise
            time.sleep(min(20, attempt + 1))
    raise AssertionError("unreachable")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if args.workers < 1 or args.workers > 16 or args.output.exists():
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
    if temporary.stat().st_size != SIZE or digest.hexdigest() != SHA256:
        raise ValueError("official_release_checksum_mismatch")
    os.replace(temporary, args.output)
    print(f"verified {args.output} sha256:{SHA256}", flush=True)


if __name__ == "__main__":
    main()
