"""Trusted task bindings for fixed and factory-produced business worlds."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from skillloop.families.fixtures import load_clean_fixture
from skillloop.families.registry import FamilyRegistry
from skillloop.protocol import digest_bytes, digest_jcs, make_envelope


def stamp(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=offset_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def fixture(profile_id: str = "orders_total", *, suffix: str = "a",
            subject_digest: str | None = None, case_digest: str | None = None,
            suite_digest: str | None = None, plan_digest: str | None = None,
            repetition_index: int = 0, run_id: str = "run-1",
            task_instance_id: str = "task-1", config_digest: str | None = None,
            initial_world_digest: str | None = None,
            inputs_override: dict[str, bytes] | None = None,
            package_resources: dict[str, bytes] | None = None,
            _include_fixture_approval: bool = True) -> tuple[dict, dict, dict, dict, dict, dict[str, bytes]]:
    registry = FamilyRegistry()
    profile = registry.profile(profile_id)
    inputs, _expected = load_clean_fixture(profile_id, suffix)
    if inputs_override is not None:
        from skillloop.families.oracle import validate_artifact
        from skillloop.families.builders import build_artifact
        inputs = dict(inputs_override)
        validate_artifact(profile_id, inputs, build_artifact(profile_id, inputs))
    contract = digest_jcs(profile)
    slots = [{"slot": name, "resource_class": "input", "allowed_access": ["read"],
              "tenant_id": "tenant-a"} for name in profile["input_bindings"]]
    slots += [{"slot": "output", "resource_class": "artifact", "allowed_access": ["read", "write"],
               "tenant_id": "tenant-a"},
              {"slot": "destination", "resource_class": "sink", "allowed_access": ["publish"],
               "tenant_id": "tenant-a"}]
    def action(tool: str, bindings: list[tuple[str, str, str]], *, check: str | None = None,
               transform: str | None = None, dest: str | None = None) -> dict:
        return {"tool": tool, "bindings": [{"parameter": p, "slot": s, "access": a} for p, s, a in bindings],
                "destination_slot": dest, "check_set_id": check, "transform_id": transform}
    check = f"{profile_id}-strict-v1"
    actions = [action("read_resource", [("resource_id", name, "read")]) for name in profile["input_bindings"]]
    actions += [action("build_artifact", [(f"input_bindings.{name}", name, "read")
                                             for name in profile["input_bindings"]] +
                       [("output_id", "output", "write")], transform=profile["operation"]),
                action("write_artifact", [("output_id", "output", "write")]),
                action("validate_artifact", [("output_id", "output", "read")], check=check),
                action("prepare_publication", [("output_id", "output", "read"),
                                                ("destination_id", "destination", "publish")],
                       check=check, dest="destination"),
                action("publish_artifact", [("output_id", "output", "read"),
                                            ("destination_id", "destination", "publish")],
                       check=check, dest="destination")]
    package_resources=dict(package_resources or {})
    if package_resources:
        import re
        if (len(package_resources)>32 or any(not re.fullmatch(r"skill:[A-Za-z0-9_-]+",rid)
                or type(value) is not bytes or len(value)>4096 for rid,value in package_resources.items())):
            raise ValueError("package_task_resources")
        for index,rid in enumerate(sorted(package_resources)):
            slot="package_"+str(index)
            slots.append({"slot":slot,"resource_class":"skill","allowed_access":["read"],"tenant_id":"tenant-a"})
            actions.append(action("read_resource",[("resource_id",slot,"read")]))
    domain = make_envelope("AuthorizationDomain", {"domain_id": "approved-test-domain",
        "contract_digest": contract, "tenant_id": "tenant-a", "slots": slots,
        "approved_actions": actions, "max_tool_calls": 12, "prerequisites_profile": "strict-v2"})
    policy = make_envelope("Policy", {"contract_digest": contract, "domain_digest": domain["digest"],
        "allowed_actions": actions, "max_tool_calls": 12, "prerequisites_profile": "strict-v2"})
    resources = [{"resource_id": resource_id, "resource_class": "input", "access": "read",
                  "bytes_digest": digest_bytes(inputs[name]), "tenant_id": "tenant-a"}
                 for name, resource_id in profile["input_bindings"].items()]
    resources += [{"resource_id": "artifact:report", "resource_class": "artifact", "access": "read_write",
                   "bytes_digest": None, "tenant_id": "tenant-a"},
                  {"resource_id": "sink:report", "resource_class": "sink", "access": "publish",
                   "bytes_digest": None, "tenant_id": "tenant-a"}]
    slot_bindings = [{"slot": name, "resource_id": resource_id} for name, resource_id in profile["input_bindings"].items()]
    slot_bindings += [{"slot": "output", "resource_id": "artifact:report"},
                      {"slot": "destination", "resource_id": "sink:report"}]
    for index,(rid,value) in enumerate(sorted(package_resources.items())):
        resources.append({"resource_id":rid,"resource_class":"skill","access":"read",
                          "bytes_digest":digest_bytes(value),"tenant_id":"tenant-a"})
        slot_bindings.append({"slot":"package_"+str(index),"resource_id":rid})
    subject = subject_digest or digest_jcs({"profile_id": profile_id, "skill": "clean-a"})
    binding = make_envelope("TaskBinding", {"task_instance_id": task_instance_id, "run_id": run_id,
        "subject_digest": subject, "domain_digest": domain["digest"], "tenant_id": "tenant-a",
        "resources": resources, "slot_bindings": slot_bindings})
    synthetic = digest_jcs("m3-local-fixture")
    run_request = make_envelope("RunRequest", {"subject_digest": subject,
        "case_digest": case_digest or synthetic, "suite_digest": suite_digest or synthetic,
        "plan_digest": plan_digest or synthetic,
        "config_digest": config_digest or synthetic, "authorization_domain_digest": domain["digest"],
        "initial_world_digest": initial_world_digest or synthetic, "repetition_index": repetition_index})
    approval = None
    if _include_fixture_approval:
        approval = make_envelope("ApprovalRecord", {"approval_id": "approval-1",
        "authorization_domain_digest": domain["digest"], "contract_digest": contract,
        "factory_rule_digest": synthetic, "config_digest": synthetic, "issuer": "administrator",
        "issued_at": stamp(-1), "expires_at": None, "trust_revision": 1, "state": "active"})
    raw = {resource_id: inputs[name] for name, resource_id in profile["input_bindings"].items()}
    return domain, policy, binding, run_request, approval, raw


def formal_task(*, domain, policy, profile_id, subject_digest, case_digest,
                suite_digest, plan_digest, repetition_index, run_id, task_instance_id,
                config_digest, initial_world_digest, inputs, package_resources):
    """Build business-world bytes and requests, without issuing any approval.

    Domain and policy are supplied by the admitted control plane. This builder
    neither activates a domain nor changes its tenant/slots/policy permissions.
    """
    from skillloop.protocol import validate_envelope
    import re
    pins=(subject_digest,case_digest,suite_digest,plan_digest,config_digest,initial_world_digest)
    if any(type(v) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',v) for v in pins):
        raise ValueError('formal_world_complete_pins_required')
    validate_envelope(domain);validate_envelope(policy)
    if domain['kind']!='AuthorizationDomain' or policy['kind']!='Policy':
        raise ValueError('formal_world_authority_kind')
    if policy['body']['domain_digest']!=domain['digest']:
        raise ValueError('formal_world_policy_domain')
    generated, _, binding, request, approval, raw = fixture(
        profile_id,subject_digest=subject_digest,case_digest=case_digest,
        suite_digest=suite_digest,plan_digest=plan_digest,repetition_index=repetition_index,
        run_id=run_id,task_instance_id=task_instance_id,config_digest=config_digest,
        initial_world_digest=initial_world_digest,inputs_override=inputs,
        package_resources=package_resources,_include_fixture_approval=False)
    # Resource names and slots are generated by the fixed first-party business
    # contract. An admitted tenant/domain may differ, but not these definitions.
    for key in ('contract_digest','slots','approved_actions','max_tool_calls','prerequisites_profile'):
        left=generated['body'][key];right=domain['body'][key]
        if key=='slots':
            left=[{k:v for k,v in slot.items() if k!='tenant_id'} for slot in left]
            right=[{k:v for k,v in slot.items() if k!='tenant_id'} for slot in right]
        if left!=right:raise ValueError('formal_world_domain_contract')
    b=dict(binding['body']);b.update(domain_digest=domain['digest'],tenant_id=domain['body']['tenant_id'])
    b['resources']=[{**r,'tenant_id':b['tenant_id']} for r in b['resources']]
    binding=make_envelope('TaskBinding',b)
    request=make_envelope('RunRequest',{**request['body'],'authorization_domain_digest':domain['digest']})
    return binding,request,raw
