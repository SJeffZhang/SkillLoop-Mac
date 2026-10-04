"""Compile the frozen public development matrix into API 4 authority objects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillloop.families.fixtures import load_clean_fixture, load_example_skill
from skillloop.families.registry import FAMILY_SPEC, PROFILE_IDS
from skillloop.protocol import ProtocolError, digest_bytes, digest_jcs, make_envelope, validate_envelope

from .mutation import make_dev_mutation


def development_config() -> dict[str, Any]:
    return {"config_id": "m5-development-fixed-v1", "model_id": "Qwen/Qwen3.8-27B-FP8",
        "deployment_epoch": "m5-development-1", "temperature": 1.0, "top_p": 0.95,
        "context_tokens": 16384, "output_tokens": 2048,
        "backend_template_overhead_tokens": 66, "provider_timeout_seconds": 180,
        "agent_deadline_seconds": 300, "proxy_deadline_seconds": 360,
        "max_rounds": 16, "max_tool_calls": 12, "max_trace_bytes": 4194304,
        "instruction_suffix": "", "concurrency": 1, "attempts_reserved": 2}


def m5b_config() -> dict[str, Any]:
    """Isolated diagnostic configuration; never replaces accepted M5."""
    return {**development_config(), "config_id": "m5b-qwen-nonthinking-v1",
            "thinking": False}


def _objectives() -> list[dict[str, Any]]:
    raw = json.loads((FAMILY_SPEC / "objectives.json").read_text())
    result = []
    for item in raw["objectives"]:
        utility = item["objective_id"].startswith("utility.")
        result.append(make_envelope("ObjectiveDefinition", {
            "objective_id": item["objective_id"], "version": 1,
            "category": "utility" if utility else "security",
            "prohibited": item["prohibited"], "event_type": "effect",
            "allowed_channels": (["mock_publication"] if utility else item.get("sinks", ["mock_publication"])) + ["private_evidence"],
            "predicate_id": item["predicate"],
            "observer_role": "oracle" if utility else "evaluator",
        }))
    return result


def _projection(profile_id: str, inputs: dict[str, bytes]) -> str:
    return digest_jcs({"profile_id": profile_id, "inputs": {
        slot: digest_bytes(value) for slot, value in inputs.items() if slot != "notes"}})


def compile_dev_suite(profile_id: str, *, skill_root: Path = FAMILY_SPEC) -> dict[str, Any]:
    if profile_id not in PROFILE_IDS:
        raise ProtocolError("unknown_profile")
    source = json.loads((FAMILY_SPEC / "dev-suite.json").read_text())
    rows = [row for row in source["cases"] if row["profile_id"] == profile_id]
    if len(rows) != 5 or sum(row["kind"] == "clean" for row in rows) != 2:
        raise ProtocolError("dev_matrix_shape")
    objectives = _objectives()
    objective_ids = {obj["body"]["objective_id"] for obj in objectives}
    cases: dict[str, dict[str, Any]] = {}
    mutations: dict[str, dict[str, Any]] = {}
    for row in rows:
        suffix = Path(row["fixture"]).parent.name.removeprefix("clean-")
        inputs, _expected = load_clean_fixture(profile_id, suffix)
        mutation = row["mutation"]
        mutation_digest = None
        if mutation is not None:
            payload_record = mutation["payload"]
            path = Path(payload_record["path"])
            if path.is_absolute() or ".." in path.parts:
                raise ProtocolError("payload_path")
            payload = (FAMILY_SPEC / path).read_bytes()
            source_bytes = inputs["notes"]
            rendered = source_bytes + payload if mutation["mode"] == "append" else payload
            if (len(payload) != payload_record["size_bytes"] or digest_bytes(payload) != payload_record["bytes_digest"]
                    or digest_bytes(source_bytes) != mutation["source_bytes_digest"]
                    or len(rendered) != mutation["rendered_size_bytes"]
                    or digest_bytes(rendered) != mutation["rendered_bytes_digest"]):
                raise ProtocolError("dev_mutation_manifest_mismatch")
            obj = make_dev_mutation(profile_id=profile_id, source_bytes=source_bytes,
                                    payload_bytes=payload, mode=mutation["mode"])
            mutation_digest = obj["digest"]
            mutations[row["case_id"]] = obj
        if any(obj not in objective_ids for obj in row["objective_ids"]):
            raise ProtocolError("unknown_objective")
        cases[row["case_id"]] = make_envelope("CaseTemplate", {
            "case_id": row["case_id"], "case_kind": row["kind"], "split": "dev",
            "fixture_digest": digest_bytes((FAMILY_SPEC / row["fixture"]).read_bytes()),
            "business_projection_digest": _projection(profile_id, inputs),
            "mutation_digest": mutation_digest,
            "clean_pair_digest": None, "objective_ids": row["objective_ids"],
            "repetitions": row["repetitions"],
        })
    for row in rows:
        if row["kind"] != "attack":
            continue
        pair = cases.get(row["clean_pair_id"])
        if pair is None or pair["body"]["case_kind"] != "clean":
            raise ProtocolError("clean_pair_missing")
        body = dict(cases[row["case_id"]]["body"])
        body["clean_pair_digest"] = pair["digest"]
        cases[row["case_id"]] = make_envelope("CaseTemplate", body)
    entries = [{"case_digest": case["digest"], **{key: case["body"][key] for key in (
        "case_kind", "split", "repetitions", "objective_ids", "clean_pair_digest",
        "business_projection_digest", "fixture_digest", "mutation_digest")}}
        for case in cases.values()]
    suite = make_envelope("SuiteManifest", {"suite_id": source["suite_id"] + "." + profile_id,
        "profile_id": profile_id, "epoch_id": None, "visibility": "public_dev",
        "objective_registry_digest": digest_jcs(objectives), "cases": entries,
        "base_case_digests": [case["digest"] for case in cases.values()],
        "history_case_digests": []})
    validate_envelope(suite)
    if len(set(suite["body"]["base_case_digests"])) != 5:
        raise ProtocolError("duplicate_dev_case")
    return {"profile_id": profile_id,
            "skill_digest": digest_bytes(load_example_skill(profile_id, root=skill_root)),
            "objectives": objectives, "cases": cases, "mutations": mutations,
            "suite": suite}


def make_dev_plan(compiled: dict[str, Any], *, campaign_id: str,
                  config: dict[str, Any] | None = None) -> dict[str, Any]:
    if config is not None and config.get('whole_flow_required') is True:
        return append_formal_dev_plan(compiled,campaign_id=campaign_id,config=config,role='submitted')
    suite = compiled["suite"]
    items = []
    for case in compiled["cases"].values():
        for repetition in range(case["body"]["repetitions"]):
            items.append({"item_id": f"{case['body']['case_id']}.{repetition}",
                "subject_digest": compiled["skill_digest"], "case_digest": case["digest"],
                "repetition_index": repetition, "phase": "dev", "subject_role": "submitted",
                "requirement": "required", "reason_code": None,
                "attempts_reserved": 2, "timeout_ms": 360_000})
    return make_envelope("ExecutionPlan", {"campaign_id": campaign_id, "revision": 1,
        "parent_plan_digest": None, "suite_digest": suite["digest"],
        "config_digest": digest_jcs(config if config is not None else development_config()), "phase": "dev",
        "items": items, "reserved_rollouts": len(items) * 2,
        "reserved_execution_ms": len(items) * 2 * 360_000,
        "reserved_auxiliary_ms": 120_000, "terminal_reserve_ms": 120_000,
        "max_campaign_rollouts": len(items) * 2,
        "max_campaign_execution_ms": len(items) * 2 * 360_000 + 240_000,
        "runtime_profile_digest": digest_bytes((FAMILY_SPEC.parent / "operations/runtime-profile.json").read_bytes())})


def append_formal_dev_plan(compiled, *, campaign_id, config, role, parent=None):
    """Append explicit same-round subject rows without legacy retry defaults.

    New finding/history templates must retain every old case. This function
    produces a plan, not source authorization or full capacity admission; the
    live Proxy catalog and whole-round manifest remain independent authorities.
    """
    from scripts.spec_v22_core import validate_plan, validate_suite
    if (config.get('whole_flow_required') is not True
            or role not in {'submitted','candidate','finalist','active_baseline'}):
        raise ValueError('formal_development_role_or_configuration')
    suite=compiled['suite']
    validate_suite(suite,list(compiled['cases'].values()),compiled['objectives'])
    if suite['body']['visibility']!='public_dev':raise ValueError('formal_development_public_suite_required')
    subject=compiled.get('subject_digest')
    import re
    if type(subject) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',subject):
        raise ValueError('formal_development_candidate_bundle_required')
    seconds=config.get('worker_deadline_seconds');budget=config.get('development_budget')
    if (type(seconds) is not int or not 1<=seconds<=300
            or type(budget) is not dict or set(budget)!={'reserved_auxiliary_ms','terminal_reserve_ms'}
            or any(type(v) is not int or v<1 for v in budget.values())
            or budget['terminal_reserve_ms']<120000):
        raise ValueError('formal_development_complete_budget_required')
    items=[]
    if parent is not None:
        validate_envelope(parent)
        if (parent['kind']!='ExecutionPlan' or parent['body']['phase']!='dev'
                or parent['body']['campaign_id']!=campaign_id
                or parent['body']['config_digest']!=digest_jcs(config)):
            raise ValueError('formal_development_parent_identity_changed')
        # Validate against the appended suite; absence of an old template or
        # change to its digest is rejected before any execution begins.
        parent_for_suite={**parent,'body':{**parent['body'],'suite_digest':suite['digest']}}
        parent_for_suite=make_envelope('ExecutionPlan',parent_for_suite['body'])
        validate_plan(parent_for_suite,suite)
        items=[dict(i) for i in parent['body']['items']]
    existing={(i['subject_digest'],i['case_digest'],i['repetition_index']):i for i in items}
    for case in compiled['cases'].values():
        if case['body']['split']!='dev':raise ValueError('formal_development_private_case_forbidden')
        for rep in range(case['body']['repetitions']):
            key=(subject,case['digest'],rep)
            if key in existing:
                if existing[key]['requirement']!='required':raise ValueError('formal_development_omitted_item_reintroduced')
                continue
            item={'item_id':role+'.'+subject[7:]+'.'+case['digest'][7:]+'.'+str(rep),
                  'subject_digest':subject,'case_digest':case['digest'],'repetition_index':rep,
                  'phase':'dev','subject_role':role,'requirement':'required','reason_code':None,
                  'attempts_reserved':1,'timeout_ms':seconds*1000}
            items.append(item);existing[key]=item
    if parent is not None and items==parent['body']['items']:
        if suite['digest']!=parent['body']['suite_digest']:
            raise ValueError('formal_development_suite_changed_without_new_rows')
        return parent
    plan=make_envelope('ExecutionPlan',{'campaign_id':campaign_id,
        'revision':parent['body']['revision']+1 if parent else 1,
        'parent_plan_digest':parent['digest'] if parent else None,'suite_digest':suite['digest'],
        'config_digest':digest_jcs(config),'phase':'dev','items':items,
        'reserved_rollouts':sum(i['attempts_reserved'] for i in items if i['requirement']=='required'),
        'reserved_execution_ms':sum(i['timeout_ms']*i['attempts_reserved'] for i in items if i['requirement']=='required'),
        'reserved_auxiliary_ms':budget['reserved_auxiliary_ms'],'terminal_reserve_ms':budget['terminal_reserve_ms'],
        'max_campaign_rollouts':128,'max_campaign_execution_ms':28800000,
        'runtime_profile_digest':digest_bytes((FAMILY_SPEC.parent/'operations/runtime-profile.json').read_bytes())})
    validate_plan(plan,suite)
    return plan
