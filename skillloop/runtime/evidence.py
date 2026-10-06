"""Private content-addressed trace with an explicit 4 MiB completeness limit."""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Any

from skillloop.protocol import canonical_json_line, digest_bytes, digest_jcs, make_envelope


MAX_TRACE_BYTES = 4 * 1024 * 1024


class TraceLimit(RuntimeError):
    pass


class PrivateTrace:
    def __init__(self, root: Path, run_id: str):
        self.root = Path(root)
        if not self.root.is_absolute() or '..' in self.root.parts:
            raise PermissionError('trace_absolute_private_root_required')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._directory(self.root)
        self.contexts = self.root / "contexts"
        self.contexts.mkdir(exist_ok=True, mode=0o700)
        self._directory(self.contexts)
        self.path = self.root / ("run-" + digest_jcs(run_id).removeprefix("sha256:") + ".jsonl")
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.original = os.fstat(fd)
        self.file = os.fdopen(fd, "wb")
        self.size = 0
        self.context_bytes = 0
        self.context_digests: set[str] = set()
        self.event_digests: list[str] = []

    @staticmethod
    def _directory(path: Path) -> None:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise PermissionError('trace_private_directory_custody')

    @staticmethod
    def _original(path: Path, digest: str, length: int) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size != length or digest_bytes(stream.read(length + 1)) != digest):
                raise PermissionError('trace_original_bytes_changed')

    def context(self, messages: list[dict[str, Any]]) -> str:
        raw = canonical_json_line(messages)
        digest = digest_bytes(raw)
        target = self.contexts / digest.removeprefix("sha256:")
        if digest not in self.context_digests:
            if self.size + self.context_bytes + len(raw) > MAX_TRACE_BYTES:
                raise TraceLimit("trace_limit")
            if not os.path.lexists(target):
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
            self._original(target, digest, len(raw))
            self.context_bytes += len(raw)
            self.context_digests.add(digest)
        return digest

    def append(self, event: dict[str, Any]) -> str:
        raw = canonical_json_line(event)
        if self.size + self.context_bytes + len(raw) > MAX_TRACE_BYTES:
            raise TraceLimit("trace_limit")
        self.file.write(raw)
        self.file.flush()
        os.fsync(self.file.fileno())
        self.size += len(raw)
        digest = digest_bytes(raw)
        self.event_digests.append(digest)
        return digest

    def finish(self, *, run_id: str, task_instance_id: str, subject_digest: str,
               trust_revision: int, complete: bool) -> dict[str, Any]:
        self.file.close()
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (self.original.st_dev, self.original.st_ino)
                or info.st_size != self.size):
            raise PermissionError('trace_original_file_changed')
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                    (info.st_dev, info.st_ino, info.st_size)):
                raise PermissionError('trace_original_file_changed')
            raw = stream.read(self.size + 1)
            closed = os.fstat(stream.fileno())
        if (len(raw) != self.size or
                (closed.st_dev, closed.st_ino, closed.st_size, closed.st_mtime_ns) !=
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)):
            raise PermissionError('trace_original_bytes_changed')
        return make_envelope("EvidenceIndex", {"run_id": run_id,
            "task_instance_id": task_instance_id, "subject_digest": subject_digest,
            "event_digests": self.event_digests, "trace_digest": digest_bytes(raw),
            "complete": complete, "issuer": "trusted-collector",
            "trust_revision": trust_revision})
