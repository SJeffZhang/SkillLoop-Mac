"""Load only approved V2.2 profile bytes from the versioned registry."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from skillloop.protocol import ProtocolError, decode_json, digest_bytes, digest_jcs

FAMILY_SPEC = Path(__file__).resolve().parents[2] / "specs" / "v2.2" / "families"
PROFILE_IDS = frozenset({"orders_total", "refunds_total", "markdown_index"})


class FamilyRegistry:
    def __init__(self, root: Path = FAMILY_SPEC):
        registry_raw = (root / "registry.json").read_bytes()
        registry = decode_json(registry_raw)
        if registry.get("api_major") != 4 or registry.get("family_ids") != ["markdown-index", "table-report"]:
            raise ProtocolError("family_registry_version")
        profiles: dict[str, dict[str, Any]] = {}
        for record in registry["profiles"]:
            path = record["path"]
            if path not in {f"profiles/{name}.json" for name in PROFILE_IDS}:
                raise ProtocolError("unregistered_profile_path")
            raw = (root / path).read_bytes()
            if len(raw) != record["size_bytes"] or digest_bytes(raw) != record["bytes_digest"]:
                raise ProtocolError("profile_bytes_mismatch")
            profile = decode_json(raw)
            profile_id = profile["profile_id"]
            if profile_id in profiles or path != f"profiles/{profile_id}.json" or profile["api_major"] != 4:
                raise ProtocolError("profile_identity")
            profiles[profile_id] = profile
        if set(profiles) != PROFILE_IDS:
            raise ProtocolError("missing_profile")
        if any(profiles[name]["operation"] != "group_sum_join"
               for name in ("orders_total", "refunds_total")):
            raise ProtocolError("table_operation_mismatch")
        if profiles["markdown_index"]["operation"] != "local_heading_link_index":
            raise ProtocolError("markdown_operation_mismatch")
        self._profiles = profiles
        self._registry_digest = digest_bytes(registry_raw)
        self._profile_digests = {record["path"].removeprefix("profiles/").removesuffix(".json"):
                                 record["bytes_digest"] for record in registry["profiles"]}
        schema_raw = (root / "tool-args.schema.json").read_bytes()
        self._schema_digest = digest_bytes(schema_raw)
        self._build_schemas = decode_json(schema_raw)["$defs"]
        if set(self._build_schemas) != PROFILE_IDS:
            raise ProtocolError("tool_schema_profiles")

    def capability_handshake(self) -> dict[str, Any]:
        """Data-only capability declaration; M3 must authenticate its sender."""
        source_root = Path(__file__).resolve().parent
        source_digests = {name: digest_bytes((source_root / name).read_bytes())
                          for name in ("builders.py", "fixtures.py", "oracle.py", "registry.py")}
        source_digests["protocol.py"] = digest_bytes((source_root.parent / "protocol.py").read_bytes())
        return {
            "api_major": 4,
            "registry_digest": self._registry_digest,
            "build_args_schema_digest": self._schema_digest,
            "implementation_digest": digest_jcs(source_digests),
            "roles_declared": ["trusted_builder", "trusted_oracle", "dev_fixture_factory"],
            "profiles": [{"profile_id": name, "family_id": self._profiles[name]["family_id"],
                          "transform_id": self._profiles[name]["operation"],
                          "profile_digest": self._profile_digests[name],
                          "input_bindings": deepcopy(self._profiles[name]["input_bindings"]),
                          "max_output_bytes": self._profiles[name]["max_output_bytes"]}
                         for name in sorted(PROFILE_IDS)],
        }

    def profile(self, profile_id: str) -> dict[str, Any]:
        try:
            return deepcopy(self._profiles[profile_id])
        except KeyError as exc:
            raise ProtocolError("unknown_profile") from exc

    def validate_build_args(self, profile_id: str, args: dict[str, Any]) -> dict[str, Any]:
        self.profile(profile_id)
        errors = list(Draft202012Validator(self._build_schemas[profile_id]).iter_errors(args))
        if errors:
            raise ProtocolError("build_args_schema") from errors[0]
        return args
