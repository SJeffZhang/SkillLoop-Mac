"""Bounded, data-only import of an exact Git commit's Markdown Skill package."""
from __future__ import annotations

import os
import hashlib
import re
import selectors
import subprocess
import time
from pathlib import Path

from .families.fixtures import parse_frontmatter
from .protocol import ProtocolError, digest_bytes, digest_jcs, make_envelope

LOADER_PROFILE = {
    "profile_id": "api4-git-markdown-package-v1", "api_major": 4,
    "source_kind": "git_commit", "max_files": 32, "max_file_bytes": 4096,
    "max_package_bytes": 131072, "entrypoint": "SKILL.md",
    "reference_pattern": "references/[A-Za-z0-9._-]+.md",
    "paths": "ASCII_relative_no_dot_segments_or_casefold_conflicts",
    "git_objects_only": True, "execute_package": False,
    "skill_digest_projection": "JCS_path_sorted_path_bytes_digest_list",
    "frontmatter": "fixed_five_single_line_keys_API4_UTF8_NFC_LF",
    "runtime_references": "separate_approved_manifest_and_token_preflight_required",
}
_SEGMENT = re.compile(r"[A-Za-z0-9._-]+\Z")
_OID = re.compile(r"[0-9a-f]{40}\Z")


def _path(value: str) -> list[str]:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ProtocolError("source_path")
    parts = value.split("/")
    if any(p in {"", ".", ".."} or not _SEGMENT.fullmatch(p) for p in parts):
        raise ProtocolError("source_path")
    return parts


class GitObjectReader:
    """No checkout, archive, filters, hooks, replacement refs, or network operation."""
    def __init__(self, repository: Path, *, timeout_seconds: float = 30):
        root = repository.absolute()
        self.git_dir = root / ".git" if (root / ".git").is_dir() else root
        if self.git_dir.is_symlink() or not (self.git_dir / "objects").is_dir():
            raise ProtocolError("unsupported_repository")
        self.deadline = time.monotonic() + timeout_seconds
        objects = self.git_dir / "objects"
        if objects.is_symlink():
            raise ProtocolError("external_object_store")
        # Git alternates can escape this object store; do not inherit them.
        if (objects / "info" / "alternates").exists() or (objects / "info" / "http-alternates").exists():
            raise ProtocolError("external_object_store")
        for child in objects.iterdir():
            if child.is_symlink():
                raise ProtocolError("external_object_store")
            if child.name in {"pack", "info"} and child.is_dir():
                if any(p.is_symlink() for p in child.iterdir()):
                    raise ProtocolError("external_object_store")
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                    "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}

    def command(self, args: list[str], limit: int = 65536) -> bytes:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("git_import_deadline")
        proc = subprocess.Popen(["/usr/bin/git", "--no-replace-objects", "--git-dir=" + str(self.git_dir),
                                 "-c", "extensions.partialClone=", "-c", "protocol.allow=never",
                                 "-c", "core.hooksPath=/dev/null",
                                 *args], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        selector = selectors.DefaultSelector()
        streams = {proc.stdout: bytearray(), proc.stderr: bytearray()}
        try:
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("git_import_deadline")
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), 8192)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    streams[key.fileobj].extend(data)
                    if len(streams[key.fileobj]) > limit:
                        raise ProtocolError("git_object_output_limit")
            if proc.wait(timeout=max(0.001, self.deadline - time.monotonic())):
                raise ProtocolError("invalid_git_object")
            return bytes(streams[proc.stdout])
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            selector.close()
            proc.stdout.close()
            proc.stderr.close()

    def check_oid(self, oid: str):
        if not _OID.fullmatch(oid):
            raise ProtocolError("git_object_id")
        loose = self.git_dir / "objects" / oid[:2] / oid[2:]
        if loose.is_symlink():
            raise ProtocolError("external_object_store")

    def object(self, oid: str, kind: str, limit: int) -> bytes:
        self.check_oid(oid)
        raw = self.command(["cat-file", kind, oid], limit)
        header = (kind + " " + str(len(raw))).encode("ascii") + b"\0"
        if hashlib.sha1(header + raw).hexdigest() != oid:
            raise ProtocolError("git_object_identity_mismatch")
        return raw

    def tree(self, oid: str) -> list[tuple[str, str, str, str]]:
        raw = self.object(oid, "tree", 65536)
        entries = []
        while raw:
            try:
                meta, rest = raw.split(b"\0", 1)
                mode, path = meta.split(b" ", 1)
                name = path.decode("utf-8")
                if len(rest) < 20 or "/" in name:
                    raise ValueError("tree_shape")
                child, raw = rest[:20].hex(), rest[20:]
            except (ValueError, UnicodeError) as exc:
                raise ProtocolError("source_tree_encoding") from exc
            mode = mode.decode("ascii").zfill(6)
            kind = "tree" if mode == "040000" else "blob" if mode in {"100644", "100755", "120000"} else "commit"
            entries.append((mode, kind, child, name))
        if len({x[3] for x in entries}) != len(entries):
            raise ProtocolError("duplicate_git_tree_path")
        return entries

    def blob(self, oid: str) -> bytes:
        self.check_oid(oid)
        size = int(self.command(["cat-file", "-s", oid], 64))
        if size > LOADER_PROFILE["max_file_bytes"]:
            raise ProtocolError("package_file_limit")
        return self.object(oid, "blob", LOADER_PROFILE["max_file_bytes"])


def import_git_package(repository: Path, commit: str, skill_path: str) -> tuple[dict, dict[str, bytes]]:
    if not isinstance(commit, str) or not _OID.fullmatch(commit):
        raise ProtocolError("exact_commit_required")
    reader = GitObjectReader(repository)
    reader.check_oid(commit)
    if reader.command(["cat-file", "-t", commit], 64) != b"commit\n":
        raise ProtocolError("exact_commit_required")
    commit_raw = reader.object(commit, "commit", 65536)
    first = commit_raw.split(b"\n", 1)[0]
    if not first.startswith(b"tree "):
        raise ProtocolError("git_commit_shape")
    tree = first[5:].decode("ascii")
    for segment in _path(skill_path):
        matches = [entry for entry in reader.tree(tree) if entry[3] == segment]
        if len(matches) != 1 or matches[0][:2] != ("040000", "tree"):
            raise ProtocolError("skill_directory_missing_or_unsafe")
        tree = matches[0][2]
    selected = []
    for mode, kind, oid, name in reader.tree(tree):
        if name == "SKILL.md" and mode in {"100644", "100755"} and kind == "blob":
            selected.append((name, oid))
        elif name == "references" and mode == "040000" and kind == "tree":
            for ref_mode, ref_kind, ref_oid, ref_name in reader.tree(oid):
                if ref_mode not in {"100644", "100755"} or ref_kind != "blob" or not ref_name.endswith(".md"):
                    raise ProtocolError("unsupported_package_entry")
                _path(ref_name)
                selected.append(("references/" + ref_name, ref_oid))
        else:
            raise ProtocolError("unsupported_package_entry")
    paths = [p for p, _ in selected]
    if "SKILL.md" not in paths or len(paths) > 32 or len({p.casefold() for p in paths}) != len(paths):
        raise ProtocolError("package_count_identity_or_case_conflict")
    files = {path: reader.blob(oid) for path, oid in sorted(selected)}
    if sum(map(len, files.values())) > 131072:
        raise ProtocolError("package_byte_limit")
    for raw in files.values():
        try:
            raw.decode("utf-8")
        except UnicodeError as exc:
            raise ProtocolError("package_utf8") from exc
    parse_frontmatter(files["SKILL.md"])
    index = [{"path": path, "bytes_digest": digest_bytes(raw), "size_bytes": len(raw)}
             for path, raw in files.items()]
    snapshot = make_envelope("SourceSnapshot", {
        "source_kind": "git_commit", "source_commit_sha": commit, "immutable": True,
        "files": index, "skill_digest": digest_jcs([{k: row[k] for k in ("path", "bytes_digest")} for row in index]),
        "loader_profile_digest": digest_jcs(LOADER_PROFILE),
    })
    return snapshot, files
