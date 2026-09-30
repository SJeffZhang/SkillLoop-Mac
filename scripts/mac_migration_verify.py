"""Verify an imported DGX snapshot without loading private evidence into Git."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path


def verify(root: Path) -> dict:
    root = root.resolve()
    manifest = root / "SHA256SUMS.dgx"
    if not manifest.is_file():
        raise ValueError("missing_dgx_manifest")
    checked = 0
    bytes_checked = 0
    failures = []
    seen = set()
    for number, line in enumerate(manifest.read_text().splitlines(), 1):
        if len(line) < 67 or line[64:66] != "  ":
            failures.append({"line": number, "error": "invalid_manifest_record"})
            continue
        digest, name = line[:64], line[66:]
        try:
            bytes.fromhex(digest)
        except ValueError:
            failures.append({"line": number, "error": "invalid_digest"})
            continue
        rel = Path(name)
        if not rel.parts or rel.is_absolute() or ".." in rel.parts or rel.parts[0] not in {
                "skillloop", "skillloop-mac-migration-snapshot"} or name in seen:
            failures.append({"line": number, "error": "invalid_path"})
            continue
        seen.add(name)
        path = root / rel
        if not path.is_file() or path.is_symlink():
            failures.append({"line": number, "path": name, "error": "missing_or_symlink"})
            continue
        actual = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                actual.update(chunk)
                bytes_checked += len(chunk)
        checked += 1
        if actual.hexdigest() != digest:
            failures.append({"line": number, "path": name, "error": "digest_mismatch"})
    links_path = root / "SYMLINKS.dgx.json"
    links = json.loads(links_path.read_text()) if links_path.exists() else []
    expected_links = {}
    for link in links:
        name, target = link.get("path"), link.get("target")
        if (not isinstance(name, str) or not isinstance(target, str) or
                name in expected_links or name in seen):
            failures.append({"path": name, "error": "invalid_symlink_record"})
            continue
        rel = Path(name)
        if not rel.parts or rel.is_absolute() or ".." in rel.parts or rel.parts[0] not in {
                "skillloop", "skillloop-mac-migration-snapshot"}:
            failures.append({"path": name, "error": "invalid_symlink_path"})
            continue
        expected_links[name] = target
        link_path = root / rel
        if not link_path.is_symlink() or os.readlink(link_path) != target:
            failures.append({"path": name, "error": "symlink_mismatch"})
    backup_index = root / "skillloop-mac-migration-snapshot/sqlite-backup-index.json"
    for top in ("skillloop", "skillloop-mac-migration-snapshot"):
        for path in (root / top).rglob("*"):
            relative = str(path.relative_to(root))
            if path.is_symlink() and relative not in expected_links:
                failures.append({"path": relative, "error": "unexpected_symlink"})
            elif path.is_file() and not path.is_symlink() and relative not in seen:
                failures.append({"path": str(path.relative_to(root)),
                                 "error": "unexpected_file"})
    backup_rows = json.loads(backup_index.read_text())["items"] if backup_index.exists() else []
    backup_errors = [row for row in backup_rows if row.get("status") != "ok"]
    if len(backup_rows) != 593 or backup_errors:
        failures.append({"error": "sqlite_backup_index_incomplete", "count": len(backup_rows),
                         "backup_errors": len(backup_errors)})
    free = shutil.disk_usage(root).free
    return {"status": "verified" if not failures else "incomplete",
            "files_checked": checked, "bytes_checked": bytes_checked,
            "symlinks_checked": len(expected_links),
            "sqlite_backups": len(backup_rows), "free_bytes": free,
            "at_least_50_gib_free": free >= 50 * 1024 ** 3,
            "failures": failures[:100], "failure_count": len(failures)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = verify(args.root)
    report = json.dumps(result, indent=2) + "\n"
    if args.report:
        args.report.write_text(report)
        args.report.chmod(0o600)
    print(report, end="")
    if result["status"] != "verified" or not result["at_least_50_gib_free"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
