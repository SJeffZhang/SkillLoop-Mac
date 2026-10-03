"""Bounded, data-only import of an exact Git commit's Markdown Skill package."""
from __future__ import annotations

import re
from pathlib import Path

from .families.fixtures import parse_frontmatter
from .git_objects import GitObjectStore, READER_PROFILE
from .protocol import ProtocolError, digest_bytes, digest_jcs, make_envelope

LOADER_PROFILE = {
    "profile_id": "api4-git-markdown-package-v2", "api_major": 4,
    "source_kind": "git_commit", "max_files": 32, "max_file_bytes": 4096,
    "max_package_bytes": 131072, "entrypoint": "SKILL.md",
    "reference_pattern": "references/[A-Za-z0-9._-]+.md",
    "paths": "ASCII_relative_no_dot_segments_or_casefold_conflicts",
    "git_objects_only": True, "execute_package": False,
    "skill_digest_projection": "JCS_path_sorted_path_bytes_digest_list",
    "frontmatter": "fixed_five_single_line_keys_API4_UTF8_NFC_LF",
    "object_reader": READER_PROFILE,
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


class GitObjectReader(GitObjectStore):
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
        return self.object(oid, "blob", LOADER_PROFILE["max_file_bytes"])


def import_git_package(repository: Path, commit: str, skill_path: str) -> tuple[dict, dict[str, bytes]]:
    if not isinstance(commit, str) or not _OID.fullmatch(commit):
        raise ProtocolError("exact_commit_required")
    with GitObjectReader(repository) as reader:
        return _import_package(reader, commit, skill_path)


def _import_package(reader, commit, skill_path):
    commit_raw = reader.object(commit, "commit", 65536)
    first = commit_raw.split(b"\n", 1)[0]
    if not first.startswith(b"tree "):
        raise ProtocolError("git_commit_shape")
    try:
        tree = first[5:].decode("ascii")
    except UnicodeError as exc:
        raise ProtocolError("git_commit_tree_id") from exc
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
