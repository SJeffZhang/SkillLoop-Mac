"""Bind scanner-backed red-team findings to executable development cases."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from scripts.spec_v22_core import validate_plan, validate_suite
from skillloop.families import load_clean_fixture
from skillloop.families.registry import FAMILY_SPEC
from skillloop.protocol import make_envelope

from .mutation import compile_mutation, make_dev_mutation
from .planning import attack_plan, generate_finding_attacks
from .suite import compile_dev_suite, make_dev_plan


def compile_finding_suite(profile_id: str, finding: dict, *, count_tokens: Callable[[str], int],
                          skill_root: Path = FAMILY_SPEC,
                          campaign_id: str = "m5b-qwen-discovery",
                          llm_payload: bytes | None = None,
                          generator_config_digest: str | None = None,
                          config: dict | None = None, subject_digest: str | None = None) -> tuple[dict, dict]:
    base = compile_dev_suite(profile_id, skill_root=skill_root)
    generated = generate_finding_attacks(profile_id=profile_id, finding=finding,
                                         count_tokens=count_tokens)
    if llm_payload is not None:
        if generator_config_digest is None:
            raise ValueError("llm_generator_identity_required")
        source = load_clean_fixture(profile_id, "a")[0]["notes"]
        for item in generated:
            original = item["original"]
            original_spec = make_dev_mutation(profile_id=profile_id, source_bytes=source,
                                              payload_bytes=llm_payload)
            rendered = compile_mutation(original_spec, source_bytes=source,
                                        profile_id=profile_id, count_tokens=count_tokens)
            original_case = make_envelope("CaseTemplate", {
                **original["case"]["body"], "mutation_digest": original_spec["digest"]})
            original.update(case=original_case, rendered=rendered,
                plan=attack_plan(case=original_case, mutation=rendered, finding=finding,
                                 generator_config_digest=generator_config_digest))
            variant = item["variant"]
            variant["plan"] = attack_plan(case=variant["case"], mutation=variant["rendered"],
                finding=finding, variant_of=original_case, original_mutation=rendered,
                generator_config_digest=generator_config_digest)
    cases = dict(base["cases"])
    mutations = dict(base["mutations"])
    plans = {}
    for item in generated:
        for label in ("original", "variant"):
            candidate = item[label]
            case = candidate["case"]
            case_id = case["body"]["case_id"]
            if case_id in cases:
                raise ValueError("finding_case_collides_with_base")
            cases[case_id] = case
            mutations[case_id] = candidate["rendered"].spec
            plans[case_id] = candidate["plan"]
    entries = [{"case_digest": case["digest"], **{key: case["body"][key] for key in (
        "case_kind", "split", "repetitions", "objective_ids", "clean_pair_digest",
        "business_projection_digest", "fixture_digest", "mutation_digest")}}
        for case in cases.values()]
    body = dict(base["suite"]["body"], suite_id="m5b.qwen.finding." + profile_id,
                cases=entries)
    compiled = dict(base, cases=cases, mutations=mutations,
                    suite=make_envelope("SuiteManifest", body))
    validate_suite(compiled["suite"], list(cases.values()), compiled["objectives"])
    if config is not None:
        if subject_digest is None:raise ValueError('finding_campaign_formal_subject_required')
        compiled={**compiled,'subject_digest':subject_digest}
    validate_plan(make_dev_plan(compiled, campaign_id=campaign_id, config=config), compiled["suite"])
    return compiled, plans


def compile_finding_campaign(profile_id: str, finding_inputs: list[dict], *,
                             count_tokens: Callable[[str], int],
                             skill_root: Path = FAMILY_SPEC,
                             campaign_id: str = "m5b-qwen-discovery",
                             config: dict | None = None, subject_digest: str | None = None) -> tuple[dict, dict]:
    """Build one base matrix plus original/variant cases for every mapped finding."""
    if not finding_inputs:
        raise ValueError("finding_inputs_required")
    base = compile_dev_suite(profile_id, skill_root=skill_root)
    cases = dict(base["cases"])
    mutations = dict(base["mutations"])
    plans: dict[str, dict] = {}
    seen_findings: set[str] = set()
    for row in finding_inputs:
        finding = row["finding"]
        finding_digest = finding["digest"]
        if finding_digest in seen_findings:
            raise ValueError("duplicate_mapped_finding")
        seen_findings.add(finding_digest)
        generated_compiled, generated_plans = compile_finding_suite(
            profile_id, finding, count_tokens=count_tokens, skill_root=skill_root,
            campaign_id=campaign_id, llm_payload=row["llm_payload"],
            generator_config_digest=row["generator_config_digest"],config=config,subject_digest=subject_digest)
        for case_id, case in generated_compiled["cases"].items():
            if case_id in cases:
                # Base cases are shared; finding-specific cases must be unique.
                if cases[case_id]["digest"] != case["digest"]:
                    raise ValueError("case_identity_collision")
                continue
            cases[case_id] = case
            mutations[case_id] = generated_compiled["mutations"][case_id]
        for case_id, plan in generated_plans.items():
            if case_id in plans:
                raise ValueError("finding_plan_collision")
            plans[case_id] = plan

    entries = [{"case_digest": case["digest"], **{key: case["body"][key] for key in (
        "case_kind", "split", "repetitions", "objective_ids", "clean_pair_digest",
        "business_projection_digest", "fixture_digest", "mutation_digest")}}
        for case in cases.values()]
    body = dict(base["suite"]["body"],
        suite_id="m5b.qwen.finding." + profile_id,
        cases=entries)
    compiled = dict(base, cases=cases, mutations=mutations,
                    suite=make_envelope("SuiteManifest", body))
    validate_suite(compiled["suite"], list(cases.values()), compiled["objectives"])
    if config is not None:
        if subject_digest is None:raise ValueError('finding_campaign_formal_subject_required')
        compiled={**compiled,'subject_digest':subject_digest}
    validate_plan(make_dev_plan(compiled, campaign_id=campaign_id, config=config), compiled["suite"])
    return compiled, plans
