"""Trusted approved-manifest selection before task resources reach ProxyStore.

Approval pins are provisioned by the trusted controller, never read from a
Skill's self-declared role or manifest. Token/context admission is separate.
"""
from __future__ import annotations
from dataclasses import dataclass
from copy import deepcopy
import re
from .protocol import ProtocolError, digest_bytes, digest_jcs, validate_envelope
from .source import LOADER_PROFILE
from .families.fixtures import parse_frontmatter

_MANIFEST_KEYS = {"api_major", "skill_id", "family_id", "profile_id", "entrypoint",
                  "reference_files", "dependencies", "files", "policy_slot_ids"}
_RESOURCE = re.compile(r"skill:[A-Za-z0-9_-]+\Z")

@dataclass(frozen=True)
class RuntimePackageSelection:
    source_snapshot_digest: str
    subject_digest: str
    manifest_digest: str
    profile_id: str
    files: tuple[tuple[str, str, bytes], ...]

    def check_binding(self, binding: dict) -> None:
        validate_envelope(binding)
        if binding["kind"] != "TaskBinding":
            raise ProtocolError("loader_task_binding_kind")
        body = binding["body"]
        if body["subject_digest"] != self.subject_digest:
            raise ProtocolError("loader_subject_binding")
        expected = {rid: digest_bytes(raw) for _, rid, raw in self.files}
        actual = [item for item in body["resources"] if item["resource_class"] == "skill"]
        if (len(actual) != len(expected) or {item["resource_id"] for item in actual} != set(expected)
                or any(item["access"] != "read" or item["bytes_digest"] != expected[item["resource_id"]]
                       for item in actual)):
            raise ProtocolError("loader_selected_resource_binding")

    def resource_bytes(self) -> dict[str, bytes]:
        return {rid: raw for _, rid, raw in self.files}

class ApprovedPackageLoader:
    def __init__(self, *, approved_sources: dict[str, str], reference_resource_ids: dict[str, str],
                 instruction_resource_id: str = "skill:instruction",
                 approved_subjects: dict[str, dict] | None = None):
        # These maps belong to trusted control-plane configuration.
        self.approved_sources = dict(approved_sources)
        self.reference_resource_ids = dict(reference_resource_ids)
        self.instruction_resource_id = instruction_resource_id
        self.approved_subjects = deepcopy(approved_subjects or {})
        for source, candidate in self.approved_subjects.items():
            validate_envelope(candidate)
            if source not in self.approved_sources or candidate['kind'] != 'CandidateBundle':
                raise ProtocolError('loader_candidate_catalog')

    def select(self, snapshot: dict, package: dict[str, bytes], manifest: dict,
               *, profile_id: str, family_id: str) -> RuntimePackageSelection:
        validate_envelope(snapshot)
        if snapshot["kind"] != "SourceSnapshot" or type(manifest) is not dict:
            raise ProtocolError("loader_source_kind")
        if set(manifest) != _MANIFEST_KEYS or manifest["api_major"] != 4:
            raise ProtocolError("loader_manifest_shape")
        mh = digest_jcs(manifest)
        if self.approved_sources.get(snapshot["digest"]) != mh:
            raise ProtocolError("loader_manifest_not_approved")
        b = snapshot["body"]
        if (not b["immutable"] or b["source_kind"] != "git_commit"
                or b["loader_profile_digest"] != digest_jcs(LOADER_PROFILE)):
            raise ProtocolError("loader_source_profile")
        index = b["files"]
        if len(index) > 32 or len({x["path"] for x in index}) != len(index):
            raise ProtocolError("loader_package_file_count")
        paths = {x["path"] for x in index}
        if set(package) != paths or sum(len(raw) for raw in package.values()) > 131072:
            raise ProtocolError("loader_package_bytes_set")
        for item in index:
            raw = package[item["path"]]
            if (type(raw) is not bytes or len(raw) > 4096 or item["size_bytes"] != len(raw)
                    or digest_bytes(raw) != item["bytes_digest"]):
                raise ProtocolError("loader_package_bytes_digest")
        projection = [{k: item[k] for k in ("path", "bytes_digest")} for item in sorted(index,key=lambda x:x["path"])]
        if b["skill_digest"] != digest_jcs(projection):
            raise ProtocolError("loader_package_subject_digest")
        if (manifest["entrypoint"] != "SKILL.md" or "SKILL.md" not in package
                or manifest["profile_id"] != profile_id or manifest["family_id"] != family_id
                or manifest["dependencies"] != [] or manifest["files"] != index):
            raise ProtocolError("loader_manifest_source_identity")
        fields = parse_frontmatter(package["SKILL.md"])
        if (fields["name"] != manifest["skill_id"] or fields["profile_id"] != profile_id
                or fields["family_id"] != family_id):
            raise ProtocolError("loader_frontmatter_profile")
        refs = manifest["reference_files"]
        if (type(refs) is not list or any(type(n) is not str for n in refs)
                or len(set(refs)) != len(refs) or set(refs) != set(self.reference_resource_ids)
                or any(not re.fullmatch(r"references/[A-Za-z0-9._-]+\.md", n)
                       or n not in package for n in refs)):
            raise ProtocolError("loader_reference_selection")
        slots = manifest["policy_slot_ids"]
        if type(slots) is not list or any(type(n) is not str for n in slots) or len(set(slots)) != len(slots):
            raise ProtocolError("loader_policy_slots")
        selected = [("SKILL.md", self.instruction_resource_id, package["SKILL.md"])]
        selected += [(n, self.reference_resource_ids[n], package[n]) for n in sorted(refs)]
        ids = [rid for _,rid,_ in selected]
        if any(type(rid) is not str or not _RESOURCE.fullmatch(rid) for rid in ids) or len(set(ids)) != len(ids):
            raise ProtocolError("loader_reference_resource_identity")
        candidate = self.approved_subjects.get(snapshot['digest'])
        if candidate is not None and candidate['body']['skill_digest'] != b['skill_digest']:
            raise ProtocolError('loader_candidate_package_binding')
        subject = b['skill_digest'] if candidate is None else candidate['digest']
        return RuntimePackageSelection(snapshot["digest"], subject, mh, profile_id, tuple(selected))


def validate_source_admission(admission: dict, config: dict, subject_digest: str) -> None:
    """Bind a complete internal package projection to the shared frozen config.

    A paired campaign may pin several subjects in one configuration. This does
    not authorize a package: the trusted loader still checks the source catalog.
    The old single-package configuration remains an explicit legacy path.
    """
    fields = {'source_snapshot', 'manifest', 'approved_sources',
              'reference_resource_ids', 'package_files'}
    if type(admission) is not dict or set(admission) not in (fields, fields | {'approved_subjects'}):
        raise ProtocolError('source_admission_shape')
    authority=config.get('source_admission_authority')
    catalog = config.get('source_admission_digests')
    if authority is not None:
        # The shared configuration freezes the authority mechanism, not a
        # digest of prose that the bounded patcher has not generated yet.
        # This is structural preflight ONLY. The actual Proxy must resolve the
        # subject/package digest against its Admin-issued durable catalog before
        # staging a task; Runtime effects still require its authenticated Lease
        # and exact TaskBinding bytes. Caller maps confer no authorization.
        if (authority!='admin_campaign_catalog_v1' or config.get('whole_flow_required') is not True
                or 'source_admission_digest' in config or 'source_admission_digests' in config):
            raise ProtocolError('source_admission_authority_configuration')
        pin=digest_jcs(admission)
    elif catalog is not None:
        if (type(catalog) is not dict or not catalog or len(catalog) > 128
                or 'source_admission_digest' in config):
            raise ProtocolError('source_admission_config_catalog')
        pin = catalog.get(subject_digest)
    else:
        pin = config.get('source_admission_digest')
    if pin != digest_jcs(admission):
        raise ProtocolError('source_admission_config_binding')
    candidates = admission.get('approved_subjects', {})
    if type(candidates) is not dict or len(candidates) > 32:
        raise ProtocolError('source_admission_candidate_catalog')
    if candidates:
        snapshot = admission['source_snapshot']['digest']
        candidate = candidates.get(snapshot)
        if set(candidates) != {snapshot} or type(candidate) is not dict:
            raise ProtocolError('source_admission_candidate_selection')
        validate_envelope(candidate)
        if candidate['kind'] != 'CandidateBundle' or candidate['digest'] != subject_digest:
            raise ProtocolError('source_admission_candidate_subject')
