"""Read local SHA-1 Git objects as bounded data through non-following directory fds.

Format source: https://git-scm.com/docs/gitformat-pack and gitformat-loose.
No Git executable, config, hook, filter, replacement ref, or network is invoked.
"""
from __future__ import annotations
import errno
import hashlib
import os
import re
import stat
import struct
import time
import zlib

from .protocol import ProtocolError

READER_PROFILE = {
    "backend": "bounded_python_git_objects_v1", "object_format": "sha1",
    "pack_versions": [2, 3], "index_version": 2,
    "delta_types": ["ofs_delta", "ref_delta_same_pack"],
    "max_object_bytes": 65536, "max_loose_compressed_bytes": 1048576,
    "max_total_index_bytes": 8388608, "max_total_pack_bytes": 67108864,
    "max_packs": 32, "max_delta_depth": 32, "max_cache_bytes": 16777216,
    "deadline_seconds": 30, "path_resolution": "directory_fd_O_NOFOLLOW_every_component",
    "index_pack_CRC_and_object_hash_verified": True,
}
_OID = re.compile(r"[0-9a-f]{40}\Z")
_PACK = re.compile(r"pack-[0-9a-f]{40}\.idx\Z")
_KINDS = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}


def _inflate(raw: bytes, maximum: int) -> bytes:
    try:
        decoder = zlib.decompressobj()
        body = decoder.decompress(raw, maximum + 1)
        if len(body) > maximum or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ProtocolError("git_compressed_object_limit_or_trailing_data")
        return body
    except zlib.error as exc:
        raise ProtocolError("git_object_compression") from exc


def _size(data: bytes, at: int) -> tuple[int, int]:
    value = shift = 0
    for _ in range(10):
        if at >= len(data):
            raise ProtocolError("git_delta_truncated")
        byte = data[at]; at += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, at
        shift += 7
    raise ProtocolError("git_delta_integer_limit")


def _delta(base: bytes, data: bytes) -> bytes:
    source_size, at = _size(data, 0)
    target_size, at = _size(data, at)
    if source_size != len(base) or target_size > READER_PROFILE["max_object_bytes"]:
        raise ProtocolError("git_delta_size")
    output = bytearray()
    while at < len(data):
        instruction = data[at]; at += 1
        if instruction & 128:
            offset = size = 0
            for bit in range(7):
                if instruction & (1 << bit):
                    if at >= len(data):
                        raise ProtocolError("git_delta_truncated")
                    if bit < 4:
                        offset |= data[at] << (8 * bit)
                    else:
                        size |= data[at] << (8 * (bit - 4))
                    at += 1
            size = size or 65536
            if offset + size > len(base) or len(output) + size > target_size:
                raise ProtocolError("git_delta_copy_range")
            output.extend(base[offset:offset + size])
        elif instruction:
            if at + instruction > len(data) or len(output) + instruction > target_size:
                raise ProtocolError("git_delta_insert_range")
            output.extend(data[at:at + instruction]); at += instruction
        else:
            raise ProtocolError("git_delta_reserved_instruction")
    if len(output) != target_size:
        raise ProtocolError("git_delta_target_size")
    return bytes(output)


class GitObjectStore:
    def __init__(self, repository, *, timeout_seconds=30):
        self.deadline = time.monotonic() + timeout_seconds
        self.fd = None
        self.cache = {}
        self.cache_bytes = self.index_bytes = self.pack_bytes = 0
        self.packs = None
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            absolute = os.path.abspath(repository)
            for part in absolute.split("/"):
                if not part:
                    continue
                following = self._directory(fd, part)
                os.close(fd); fd = following
            try:
                following = self._directory(fd, ".git")
            except FileNotFoundError:
                following = os.dup(fd)  # Bare object store.
            os.close(fd); fd = following
            self.fd = self._directory(fd, "objects")
            for name in ["info/alternates", "info/http-alternates"]:
                try:
                    self._read(name, 1)
                except FileNotFoundError:
                    continue
                raise ProtocolError("external_object_store")
        except BaseException:
            self.close()
            raise
        finally:
            os.close(fd)

    @staticmethod
    def _directory(fd, name):
        try:
            return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ProtocolError("git_unsafe_directory") from exc
            raise

    def _time(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("git_import_deadline")

    def _read(self, path, maximum):
        self._time()
        parts = path.split("/")
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                following = self._directory(fd, part)
                os.close(fd); fd = following
            try:
                file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise ProtocolError("git_unsafe_object_file") from exc
                raise
            try:
                before = os.fstat(file_fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                    raise ProtocolError("git_file_type_or_size_limit")
                output = bytearray()
                while True:
                    self._time()
                    chunk = os.read(file_fd, min(65536, maximum + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > maximum:
                        raise ProtocolError("git_file_size_limit")
                after = os.fstat(file_fd)
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ProtocolError("git_object_changed_during_read")
                return bytes(output)
            finally:
                os.close(file_fd)
        finally:
            os.close(fd)

    def _indexes(self):
        if self.packs is not None:
            return
        self.packs = []
        try:
            pack_fd = self._directory(self.fd, "pack")
        except FileNotFoundError:
            return
        try:
            names = sorted(os.listdir(pack_fd))
        finally:
            os.close(pack_fd)
        selected = [n for n in names if _PACK.fullmatch(n)]
        if len(selected) > READER_PROFILE["max_packs"] or any(n.endswith(".promisor") for n in names):
            raise ProtocolError("git_pack_count_or_promisor_unsupported")
        for name in selected:
            data = self._read("pack/" + name, READER_PROFILE["max_total_index_bytes"] - self.index_bytes)
            self.index_bytes += len(data)
            if len(data) < 1072 or data[:8] != b"\xfftOc\x00\x00\x00\x02" or hashlib.sha1(data[:-20]).digest() != data[-20:]:
                raise ProtocolError("git_index_header_or_checksum")
            fan = struct.unpack(">256I", data[8:1032]); count = fan[-1]
            if list(fan) != sorted(fan) or count > 262144:
                raise ProtocolError("git_index_fanout")
            minimum = 1032 + count * 28 + 40
            if len(data) < minimum or (len(data) - minimum) % 8:
                raise ProtocolError("git_index_size")
            names_at = 1032; crc_at = names_at + count * 20; offsets_at = crc_at + count * 4
            large_at = offsets_at + count * 4
            rows = {}; previous = b""; actual_fan = [0] * 256
            for i in range(count):
                oid = data[names_at + i * 20:names_at + (i + 1) * 20]
                if oid <= previous:
                    raise ProtocolError("git_index_name_order")
                previous = oid; actual_fan[oid[0]] += 1
                offset = struct.unpack_from(">I", data, offsets_at + i * 4)[0]
                if offset & 0x80000000:
                    large_index = offset & 0x7fffffff
                    if large_at + (large_index + 1) * 8 > len(data) - 40:
                        raise ProtocolError("git_index_large_offset")
                    offset = struct.unpack_from(">Q", data, large_at + large_index * 8)[0]
                rows[oid.hex()] = (offset, struct.unpack_from(">I", data, crc_at + i * 4)[0])
            running = 0
            for i in range(256):
                running += actual_fan[i]
                if running != fan[i]:
                    raise ProtocolError("git_index_fanout")
            offsets = sorted(x[0] for x in rows.values())
            if len(offsets) != len(set(offsets)):
                raise ProtocolError("git_index_offset_duplicate")
            self.packs.append({"name": name[:-4] + ".pack", "rows": rows, "offsets": offsets,
                               "pack_checksum": data[-40:-20], "data": None})
            self._time()

    def _load_pack(self, pack):
        if pack["data"] is not None:
            return
        raw = self._read("pack/" + pack["name"], READER_PROFILE["max_total_pack_bytes"] - self.pack_bytes)
        self.pack_bytes += len(raw)
        if len(raw) < 32 or raw[:4] != b"PACK" or struct.unpack_from(">I", raw, 4)[0] not in [2, 3]:
            raise ProtocolError("git_pack_header")
        count = struct.unpack_from(">I", raw, 8)[0]
        if count != len(pack["rows"]) or hashlib.sha1(raw[:-20]).digest() != raw[-20:] or raw[-20:] != pack["pack_checksum"]:
            raise ProtocolError("git_pack_checksum_or_count")
        offsets = pack["offsets"]
        if not offsets or offsets[0] != 12 or offsets[-1] >= len(raw) - 20:
            raise ProtocolError("git_pack_offset_range")
        pack["data"] = raw
        pack["end"] = {start: finish for start, finish in zip(offsets, offsets[1:] + [len(raw) - 20])}
        pack["oid_by_offset"] = {v[0]: k for k, v in pack["rows"].items()}

    def _packed(self, pack, oid, seen):
        self._load_pack(pack)
        offset, crc = pack["rows"][oid]
        data = pack["data"][offset:pack["end"][offset]]
        if zlib.crc32(data) & 0xffffffff != crc or not data:
            raise ProtocolError("git_pack_object_CRC")
        byte = data[0]; at = 1; kind = (byte >> 4) & 7; size = byte & 15; shift = 4
        while byte & 128:
            if at >= len(data) or shift > 60:
                raise ProtocolError("git_pack_size_header")
            byte = data[at]; at += 1; size |= (byte & 127) << shift; shift += 7
        if size > READER_PROFILE["max_object_bytes"]:
            raise ProtocolError("git_object_size_limit")
        base_oid = None
        if kind == 6:
            if at >= len(data):
                raise ProtocolError("git_delta_offset")
            byte = data[at]; at += 1; distance = byte & 127; steps = 1
            while byte & 128:
                if at >= len(data) or steps >= 10:
                    raise ProtocolError("git_delta_offset")
                byte = data[at]; at += 1; distance = ((distance + 1) << 7) + (byte & 127); steps += 1
            base_oid = pack["oid_by_offset"].get(offset - distance)
            if distance <= 0 or base_oid is None:
                raise ProtocolError("git_delta_base_offset")
        elif kind == 7:
            if at + 20 > len(data):
                raise ProtocolError("git_delta_base_reference")
            base_oid = data[at:at + 20].hex(); at += 20
            if base_oid not in pack["rows"]:
                raise ProtocolError("git_thin_pack_unsupported")
        elif kind not in _KINDS:
            raise ProtocolError("git_pack_object_type")
        body = _inflate(data[at:], READER_PROFILE["max_object_bytes"])
        if len(body) != size:
            raise ProtocolError("git_pack_object_size")
        if base_oid:
            base_kind, base_body = self._resolve(base_oid, seen, required_pack=pack)
            return base_kind, _delta(base_body, body)
        return _KINDS[kind], body

    def _resolve(self, oid, seen=frozenset(), required_pack=None):
        self._time()
        if not isinstance(oid, str) or not _OID.fullmatch(oid):
            raise ProtocolError("git_object_id")
        if oid in seen or len(seen) >= READER_PROFILE["max_delta_depth"]:
            raise ProtocolError("git_delta_cycle_or_depth")
        if oid in self.cache:
            return self.cache[oid]
        if required_pack is not None:
            kind, body = self._packed(required_pack, oid, seen | {oid})
        else:
            try:
                compressed = self._read(oid[:2] + "/" + oid[2:], READER_PROFILE["max_loose_compressed_bytes"])
            except FileNotFoundError:
                self._indexes()
                pack = next((p for p in self.packs if oid in p["rows"]), None)
                if pack is None:
                    raise ProtocolError("git_object_missing")
                kind, body = self._packed(pack, oid, seen | {oid})
            else:
                raw = _inflate(compressed, READER_PROFILE["max_object_bytes"] + 32)
                try:
                    header, body = raw.split(b"\0", 1)
                    kind_raw, size = header.split(b" ", 1)
                    kind = kind_raw.decode("ascii")
                except (ValueError, UnicodeError) as exc:
                    raise ProtocolError("git_loose_header") from exc
                if kind not in _KINDS.values() or size != str(len(body)).encode() or len(body) > READER_PROFILE["max_object_bytes"]:
                    raise ProtocolError("git_loose_type_or_size")
        if hashlib.sha1((kind + " " + str(len(body))).encode() + b"\0" + body).hexdigest() != oid:
            raise ProtocolError("git_object_identity_mismatch")
        if self.cache_bytes + len(body) <= READER_PROFILE["max_cache_bytes"]:
            self.cache[oid] = kind, body; self.cache_bytes += len(body)
        return kind, body

    def object(self, oid, kind, limit):
        actual_kind, body = self._resolve(oid)
        if actual_kind != kind:
            raise ProtocolError("git_object_kind")
        if len(body) > limit:
            raise ProtocolError("git_object_size_limit")
        return body

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
