"""Validate approved actions and expand task-local resource capabilities."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from skillloop.families.registry import FamilyRegistry
from skillloop.protocol import ProtocolError, digest_jcs, make_envelope, validate_envelope


class AuthorizationError(ProtocolError):
    """A signed object is valid JSON but does not grant the requested action."""


_FIXED_BINDINGS: dict[str, dict[str, str]] = {
    "read_resource": {"resource_id": "read"},
    "write_artifact": {"output_id": "write"},
    "validate_artifact": {"output_id": "read"},
    "prepare_publication": {"output_id": "read", "destination_id": "publish"},
    "publish_artifact": {"output_id": "read", "destination_id": "publish"},
}


def _unique(values: list[str], reason: str) -> None:
    if len(values) != len(set(values)):
        raise AuthorizationError(reason)


def _action(action: dict[str, Any], *, profile_id: str, registry: FamilyRegistry) -> dict[str, Any]:
    """Normalize a registered tool tuple; unknown bindings or checks fail closed."""
    name = action["tool"]
    bindings = action["bindings"]
    _unique([item["parameter"] for item in bindings], "duplicate_action_parameter")
    actual = {item["parameter"]: item["access"] for item in bindings}
    profile = registry.profile(profile_id)
    if name == "build_artifact":
        expected = {"output_id": "write"}
        expected.update({f"input_bindings.{key}": "read" for key in profile["input_bindings"]})
        if actual != expected or action["transform_id"] != profile["operation"]:
            raise AuthorizationError("invalid_build_action")
    elif actual != _FIXED_BINDINGS.get(name):
        raise AuthorizationError("invalid_tool_action")
    if (name in ("prepare_publication", "publish_artifact")) != (action["destination_slot"] is not None):
        raise AuthorizationError("destination_binding")
    if name in ("prepare_publication", "publish_artifact"):
        destination = next(item for item in bindings if item["parameter"] == "destination_id")
        if destination["slot"] != action["destination_slot"]:
            raise AuthorizationError("destination_binding")
    if (name == "build_artifact") != (action["transform_id"] is not None):
        raise AuthorizationError("transform_binding")
    expected_check = f"{profile_id}-strict-v1"
    if name in ("validate_artifact", "prepare_publication", "publish_artifact"):
        if action["check_set_id"] != expected_check:
            raise AuthorizationError("unregistered_check_set")
    elif action["check_set_id"] is not None:
        raise AuthorizationError("unexpected_check_set")
    canonical = deepcopy(action)
    canonical["bindings"].sort(key=lambda x: (x["parameter"], x["slot"], x["access"]))
    return canonical


def _action_set(actions: list[dict[str, Any]], *, profile_id: str,
                registry: FamilyRegistry) -> dict[str, dict[str, Any]]:
    values = [_action(action, profile_id=profile_id, registry=registry) for action in actions]
    keyed = {digest_jcs(item): item for item in values}
    if len(keyed) != len(values):
        raise AuthorizationError("duplicate_action")
    return keyed


def compile_capability(
    domain: dict[str, Any], binding: dict[str, Any], policy: dict[str, Any],
    profile_id: str, *, parent_policy: dict[str, Any] | None = None,
    registry: FamilyRegistry | None = None,
) -> dict[str, Any]:
    """Return the effective ApprovedCap after strict domain/parent subset checks."""
    loaded = registry or FamilyRegistry()
    for item, kind in ((domain, "AuthorizationDomain"), (binding, "TaskBinding"), (policy, "Policy")):
        if validate_envelope(item)["kind"] != kind:
            raise AuthorizationError("identity_kind")
    if parent_policy is not None and validate_envelope(parent_policy)["kind"] != "Policy":
        raise AuthorizationError("parent_policy_kind")
    d, b, p = domain["body"], binding["body"], policy["body"]
    if b["domain_digest"] != domain["digest"] or b["tenant_id"] != d["tenant_id"]:
        raise AuthorizationError("domain_binding")
    if p["domain_digest"] != domain["digest"] or p["contract_digest"] != d["contract_digest"]:
        raise AuthorizationError("policy_domain")
    if p["prerequisites_profile"] != d["prerequisites_profile"] or p["max_tool_calls"] > d["max_tool_calls"]:
        raise AuthorizationError("policy_expansion")
    approved = _action_set(d["approved_actions"], profile_id=profile_id, registry=loaded)
    allowed = _action_set(p["allowed_actions"], profile_id=profile_id, registry=loaded)
    if not allowed.keys() <= approved.keys():
        raise AuthorizationError("policy_not_subset_of_domain")
    if parent_policy is not None:
        parent = parent_policy["body"]
        if any(p[key] != parent[key] for key in ("contract_digest", "domain_digest", "prerequisites_profile")):
            raise AuthorizationError("parent_identity")
        parent_actions = _action_set(parent["allowed_actions"], profile_id=profile_id, registry=loaded)
        if p["max_tool_calls"] > parent["max_tool_calls"] or not allowed.keys() <= parent_actions.keys():
            raise AuthorizationError("policy_not_subset_of_parent")

    if len(b["resources"]) > 32:
        raise AuthorizationError("task_resource_limit")

    slots = {item["slot"]: item for item in d["slots"]}
    resources = {item["resource_id"]: item for item in b["resources"]}
    mapping = {item["slot"]: item["resource_id"] for item in b["slot_bindings"]}
    _unique([item["slot"] for item in d["slots"]], "duplicate_domain_slot")
    _unique([item["resource_id"] for item in b["resources"]], "duplicate_task_resource")
    _unique([item["slot"] for item in b["slot_bindings"]], "duplicate_slot_binding")
    if set(mapping) != set(slots) or not set(mapping.values()) <= set(resources):
        raise AuthorizationError("slot_binding_exactness")
    if not any(item["resource_class"] in ("skill", "input") and "read" in item["allowed_access"]
               for item in slots.values()):
        raise AuthorizationError("empty_read_binding")
    for resource in resources.values():
        if resource["tenant_id"] != d["tenant_id"] or not resource["resource_id"].startswith(resource["resource_class"] + ":"):
            raise AuthorizationError("resource_identity")
    concrete: list[dict[str, Any]] = []
    for action in allowed.values():
        expanded: list[dict[str, str]] = []
        for item in action["bindings"]:
            slot = slots.get(item["slot"])
            resource = resources.get(mapping.get(item["slot"], ""))
            if slot is None or resource is None:
                raise AuthorizationError("missing_action_slot")
            permitted = {"read", "write"} if resource["access"] == "read_write" else {resource["access"]}
            if (resource["resource_class"] != slot["resource_class"] or
                resource["tenant_id"] != slot["tenant_id"] or
                item["access"] not in slot["allowed_access"] or item["access"] not in permitted):
                raise AuthorizationError("capability_slot_access")
            expanded.append({"parameter": item["parameter"], "resource_id": resource["resource_id"],
                             "access": item["access"]})
        concrete.append({"tool": action["tool"],
                         "bindings": sorted(expanded, key=lambda x: x["parameter"]),
                         "destination_id": mapping[action["destination_slot"]] if action["destination_slot"] else None,
                         "check_set_id": action["check_set_id"], "transform_id": action["transform_id"]})
    return make_envelope("ApprovedCap", {
        "domain_digest": domain["digest"], "task_binding_digest": binding["digest"],
        "task_instance_id": b["task_instance_id"], "run_id": b["run_id"],
        "actions": sorted(concrete, key=digest_jcs), "max_tool_calls": p["max_tool_calls"],
    })


def permits(capability: dict[str, Any], tool: str, args: dict[str, Any]) -> bool:
    """Compare exact concrete resource bindings against one permitted action."""
    for action in capability["body"]["actions"]:
        if action["tool"] != tool:
            continue
        matched = True
        for binding in action["bindings"]:
            param = binding["parameter"]
            actual = (args.get("input_bindings") or {}).get(param.removeprefix("input_bindings.")) \
                if param.startswith("input_bindings.") else args.get(param)
            if actual != binding["resource_id"]:
                matched = False
                break
        if matched:
            return True
    return False
