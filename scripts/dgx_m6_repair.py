"""M6 diagnostic text repair and paired development regression on authorized DGX.

M5 runs remain immutable reference evidence. Candidate results have their own
campaign, CandidateBundle identity, revision chain, and private failure history.
This script does not release or run protected M7 cases.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deploy.scanner.qwen_relay import HostModelBridge
from scripts.dgx_m5_development import run_one
from scripts.dgx_m5b_attack import ordered_cases, run_directory, summarize_case
from scripts.dgx_m5b_gate import _compile_subject, _recompute_run
from scripts.dgx_m5b_scan import docker_command, model_preflight
from scripts.spec_v22_core import reduce_case, validate_plan, validate_suite
from skillloop.discovery.llm_attack import ProposalError
from skillloop.discovery.scanner import reduce_scan
from skillloop.discovery.suite import m5b_config
from skillloop.families.fixtures import load_example_skill
from skillloop.families.registry import FAMILY_SPEC
from skillloop.protocol import decode_json, digest_bytes, digest_jcs, make_envelope, validate_envelope
from skillloop.repair.applicator import apply_proposal, bundle
from skillloop.repair.budget import SpendingLedger, forecast, protected_reservations, revise, rows, eliminate_protected_slots
from skillloop.repair.history import FailureHistory
from skillloop.repair.clock import make_clock, start_seconds
from skillloop.repair.spending import snapshot, verify_snapshot, remaining_capacity
from skillloop.repair.proposal import propose_body
from skillloop.runtime.gateway import ExactDockerTokenizer
from skillloop.families.task_world import fixture

REPO = Path(__file__).resolve().parents[1]
REDTEAM = FAMILY_SPEC / "redteam"
PROFILES = ("orders_total", "refunds_total", "markdown_index")
CONFIG = {**m5b_config(), "config_id": "m6-qwen-nonthinking-v5",
          "agent_deadline_seconds": 235, "provider_timeout_seconds": 120,
          "proxy_deadline_seconds": 255, "worker_deadline_seconds": 265}
VICTIM_BOUND = 265
SCANNER_BOUND = 300


def campaign_name(manifest: dict, profile: str) -> str:
    return manifest.get("campaign_id", "m6-r1") + "-" + profile


def stage_bounds() -> list[dict]:
    return [
        {"name": "scanner", "count": 2, "seconds": SCANNER_BOUND, "input_tokens": 4 * 14336, "output_tokens": 4 * 2048, "disk_bytes": 16 * 1024**2},
        {"name": "patcher", "count": 4, "seconds": 180, "input_tokens": 15360, "output_tokens": 1024, "disk_bytes": 4 * 1024**2},
        {"name": "warmup", "count": 2, "seconds": VICTIM_BOUND, "input_tokens": 16 * 14336, "output_tokens": 16 * 2048, "disk_bytes": 4 * 1024**2},
        {"name": "protected_factory", "count": 1, "seconds": 120, "input_tokens": 14336, "output_tokens": 2048, "disk_bytes": 16 * 1024**2},
        {"name": "history_and_plan", "count": 2, "seconds": 60, "input_tokens": 0, "output_tokens": 0, "disk_bytes": 16 * 1024**2},
        {"name": "finalization", "count": 4, "seconds": 150, "input_tokens": 0, "output_tokens": 0, "disk_bytes": 16 * 1024**2}]


def repair_obligations(profile: str) -> dict:
    domain = fixture(profile)[0]
    requirements = [
        {"obligation": "require_validation", "slots": ["output"], "check_set_id": profile + "-strict-v1"},
        {"obligation": "restrict_destination", "slots": ["destination"], "check_set_id": None},
        {"obligation": "restrict_resources", "slots": sorted(slot["slot"] for slot in domain["body"]["slots"]), "check_set_id": None}]
    return make_envelope("RepairObligations", {"domain_digest": domain["digest"],
        "requirements": sorted(requirements, key=digest_jcs)})


def scan_passed(report: dict, calls: int, high: list) -> bool:
    return report["body"]["status"] == "complete" and calls > 0 and not high


def save(path: Path, data: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("w") as stream:
        os.chmod(path, 0o600)
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def load(path: Path):
    return json.loads(path.read_text())


def source_index(source: Path = REPO) -> dict:
    files = [p for directory in ("skillloop", "scripts", "deploy/scanner")
        for p in (source / directory).rglob("*") if p.is_file() and p.suffix in {".py", ".sql", ".yaml"}]
    files.extend(p for p in (source / "specs/v2.2").rglob("*") if p.is_file() and p.suffix in {".json", ".py"})
    return {str(p.relative_to(source)): digest_bytes(p.read_bytes()) for p in sorted(files)}


def compatibility(profile: str, compiled: dict) -> dict:
    return {"family": "markdown-index" if profile == "markdown_index" else "table-report",
        "profile": profile, "contract_digest": fixture(profile)[1]["body"]["contract_digest"],
        "objective_registry_digest": compiled["suite"]["body"]["objective_registry_digest"],
        "oracle_digest": digest_bytes((REPO / "skillloop/families/oracle.py").read_bytes()),
        "privacy_domain": "dgx-synthetic-development"}


def append_history(compiled: dict, entries: list[dict]) -> tuple[dict, list[dict]]:
    compiled = copy.deepcopy(compiled)
    cases = compiled["cases"]
    by_digest = {case["digest"]: case_id for case_id, case in cases.items()}
    def case_content(case):
        return digest_jcs({k: v for k, v in case["body"].items() if k != "case_id"})
    by_content = {case_content(case): case_id for case_id, case in cases.items()}
    bindings = []
    for entry in entries:
        original = entry["case"]
        existing = by_digest.get(original["digest"])
        equivalence = "exact_case_digest"
        if existing is None:
            existing = by_content.get(case_content(original))
            equivalence = "same_case_body_except_opaque_id"
        if existing is not None:
            bindings.append({"history_digest": entry["digest"], "case_id": existing,
                             "source_case_digest": original["digest"], "equivalence": equivalence})
            continue
        body = dict(original["body"])
        case_id = compiled["profile_id"] + ".history-" + original["digest"][7:19]
        if original["body"]["case_id"].endswith("clean-b"):
            case_id += ".clean-b"
        body["case_id"] = case_id
        # Clean pair is a trusted business-equivalent base clean case.
        if body["case_kind"] == "attack":
            pair = next((case for case in cases.values() if case["body"]["case_kind"] == "clean"
                and case["body"]["business_projection_digest"] == body["business_projection_digest"]
                and case["body"]["fixture_digest"] == body["fixture_digest"]), None)
            if pair is None:
                raise ValueError("history_clean_pair_unavailable")
            body["clean_pair_digest"] = pair["digest"]
        case = make_envelope("CaseTemplate", body)
        if case_id in cases:
            if cases[case_id] != case:
                raise ValueError("history_case_collision")
        else:
            cases[case_id] = case
            if entry["mutation"] is not None:
                compiled["mutations"][case_id] = entry["mutation"]
        by_content[case_content(case)] = case_id
        by_digest[original["digest"]] = case_id
        bindings.append({"history_digest": entry["digest"], "case_id": case_id,
            "source_case_digest": original["digest"], "equivalence": "recompiled_exact_payload_and_fixture"})
    base = compiled["suite"]["body"]
    base_digests = set(base["base_case_digests"])
    original_digests = {row["case_digest"] for row in base["cases"]}
    entries = [{"case_digest": case["digest"], **{key: case["body"][key] for key in (
        "case_kind", "split", "repetitions", "objective_ids", "clean_pair_digest",
        "business_projection_digest", "fixture_digest", "mutation_digest")}} for case in cases.values()]
    compiled["suite"] = make_envelope("SuiteManifest", {**base, "cases": entries,
        "suite_id": "m6.history." + compiled["profile_id"],
        "history_case_digests": sorted(case["digest"] for case in cases.values()
                                      if case["digest"] not in original_digests | base_digests)})
    validate_suite(compiled["suite"], list(cases.values()), compiled["objectives"])
    return compiled, bindings


def execution_plan(compiled: dict, *, campaign: str, parent: dict | None = None,
                   retry: tuple[str, int] | None = None, submitted_digest: str | None = None,
                   runtime_config: dict | None = None) -> dict:
    items = copy.deepcopy(parent["body"]["items"]) if parent else [
        {"item_id": f"{case['body']['case_id']}.{rep}", "subject_digest": compiled["subject_digest"],
         "case_digest": case["digest"], "repetition_index": rep, "phase": "dev",
         "subject_role": "candidate", "requirement": "required", "reason_code": None,
         "attempts_reserved": 1, "timeout_ms": VICTIM_BOUND * 1000}
        for case in compiled["cases"].values() for rep in range(case["body"]["repetitions"])]
    if submitted_digest and not parent:
        items.extend({"item_id": "submitted." + case["body"]["case_id"] + f".{rep}",
            "subject_digest": submitted_digest, "case_digest": case["digest"],
            "repetition_index": rep, "phase": "dev", "subject_role": "submitted",
            "requirement": "required", "reason_code": None, "attempts_reserved": 1,
            "timeout_ms": VICTIM_BOUND * 1000}
            for case in compiled["cases"].values() for rep in range(case["body"]["repetitions"]))
    if parent and not retry:
        if any(i["subject_digest"] == compiled["subject_digest"] for i in items):
            raise ValueError("candidate_already_planned")
        items.extend({"item_id": compiled["subject_digest"][7:19] + "." + case["body"]["case_id"] + f".{rep}",
            "subject_digest": compiled["subject_digest"], "case_digest": case["digest"],
            "repetition_index": rep, "phase": "dev", "subject_role": "candidate",
            "requirement": "required", "reason_code": None, "attempts_reserved": 1,
            "timeout_ms": VICTIM_BOUND * 1000}
            for case in compiled["cases"].values() for rep in range(case["body"]["repetitions"]))
    if retry:
        case_id, rep = retry
        case_digest = compiled["cases"][case_id]["digest"]
        item = next(row for row in items if row["subject_digest"] == compiled["subject_digest"]
            and row["case_digest"] == case_digest and row["repetition_index"] == rep)
        if item["attempts_reserved"] != 1 or sum(row["attempts_reserved"] - 1 for row in items) >= 2:
            raise ValueError("retry_reservation_exhausted")
        item["attempts_reserved"] = 2
    rollouts = sum(row["attempts_reserved"] for row in items)
    plan = make_envelope("ExecutionPlan", {"campaign_id": campaign,
        "revision": parent["body"]["revision"] + 1 if parent else 1,
        "parent_plan_digest": parent["digest"] if parent else None,
        "suite_digest": compiled["suite"]["digest"], "config_digest": digest_jcs(CONFIG if runtime_config is None else runtime_config),
        "phase": "dev", "items": items, "reserved_rollouts": rollouts,
        "reserved_execution_ms": rollouts * VICTIM_BOUND * 1000,
        "reserved_auxiliary_ms": 3600000, "terminal_reserve_ms": 600000,
        "max_campaign_rollouts": 128, "max_campaign_execution_ms": 28800000,
        "runtime_profile_digest": digest_bytes((FAMILY_SPEC.parent / "operations/runtime-profile.json").read_bytes())})
    validate_plan(plan, compiled["suite"])
    return plan


def retry_eligible(data: dict) -> bool:
    """A protocol fault with no irreversible effect can use a private dev retry."""
    body = data["result"]["body"]
    observation = data["observation"]["body"]
    return (not body["coverage_complete"] and not body["security_violation"] and
            body["utility_status"] == "unknown" and observation["infra_status"] == "runtime_error" and
            not data["summary"]["publication_present"] and
            data["runtime_incomplete_reasons"] == ["model_or_runtime_protocol_error:ProtocolError"])


def state_failure(result: dict) -> bool:
    return result["body"]["security_violation"] or result["body"]["utility_status"] == "fail"


def execution_spending_data(root: Path, profile: str) -> tuple[Path, dict, list[dict]]:
    manifest = load(root / "manifest.json")
    info = manifest["subjects"][profile]
    first = Path(info["parent_output"]) if info.get("parent_output") else root
    first_manifest = load(first / "manifest.json")
    clock = first_manifest["admission_clock"]
    start_seconds(first_manifest, profile, legacy_started_at=0)
    if manifest.get("admission_clock") != clock:
        raise ValueError("spending_round_clock_changed")
    locations = [(first, "submitted"), (first, "candidate")]
    if first != root:
        locations.append((root, "candidate"))
    executions = []
    for campaign, role in locations:
        details = load(campaign / "manifest.json")["subjects"][profile]
        compiled = load(campaign / profile / "compiled.json")
        subject = details["submitted_bundle" if role == "submitted" else "candidate_bundle"]["digest"]
        location = campaign / "submitted" if role == "submitted" else campaign
        for case_id in compiled["cases"]:
            for rep in range(3):
                for attempt in (0, 1):
                    directory = run_directory(location, profile, case_id, rep, attempt)
                    files = [directory / name for name in ("result.json", "timing.json")]
                    present = [p for p in files if p.is_file()]
                    if present:
                        executions.append({"item_key": subject + f".{case_id}.{rep}", "attempt": attempt,
                            "record_digests": {p.name: digest_bytes(p.read_bytes()) for p in present},
                            "last_write_unix_ms": max(int(p.stat().st_mtime * 1000) for p in present)})
    return first / profile / "spending.json", clock, sorted(executions, key=lambda e: (e["item_key"], e["attempt"]))


def close_execution_spending(root: Path, profile: str) -> dict:
    ledger_path, clock, executions = execution_spending_data(root, profile)
    state = load(ledger_path)
    target = root / profile / "closed-development-spending.json"
    if target.exists():
        return verify_snapshot(load(target), current_state=state, clock=clock,
            victim_seconds=VICTIM_BOUND, executions=executions)
    record = snapshot(state, clock=clock, victim_seconds=VICTIM_BOUND, executions=executions,
        finished_at_unix_ms=int(time.time() * 1000))
    with target.open("x") as stream:
        os.chmod(target, 0o600)
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return record


def claim_second_round(path: Path, *, parent_gate_digest: str, output: Path) -> None:
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump({"parent_gate_digest": parent_gate_digest, "output_ref": str(output),
                   "status": "reserved_before_generation"}, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(args) -> None:
    if args.profile not in PROFILES:
        raise ValueError("profile_admission_requires_single_profile")
    if args.output.exists():
        raise FileExistsError("m6_output_exists")
    accepted = load(args.baseline / "m5b-gate.json")
    sealed = {key: value for key, value in accepted.items() if key != "digest"}
    if (accepted["status"] != "pass" or accepted["missing"] or accepted["incomplete"] or
            accepted["digest"] != digest_jcs(sealed)):
        raise ValueError("m5_not_accepted")
    args.output.mkdir(parents=True, mode=0o700)
    save(args.output / "m5-acceptance.json", {"status": "accepted", "gate_digest": accepted["digest"],
        "baseline_ref": str(args.baseline), "submitted_verdict": accepted["development_verdict"],
        "production_ready": False})
    tokenizer = ExactDockerTokenizer()
    scans = load(args.scan_index)
    history = FailureHistory(args.output.parent / "m6-private-history.sqlite")
    manifest = {"kind": "M6DevelopmentCampaign", "config": CONFIG, "baseline_gate_digest": accepted["digest"],
        "campaign_id": load(args.parent_output / "manifest.json")["campaign_id"] if args.parent_output else "m6-" + secrets.token_hex(12),
        "source_index": source_index(), "source_ref": str(REPO),
        "subjects": {}, "protected_evaluation": "not_started", "production_ready": False}
    if args.parent_output:
        parent_manifest = load(args.parent_output / "manifest.json")
        clock = parent_manifest.get("admission_clock")
        if clock is None:
            raise ValueError("new_round_requires_profile_admission_clock")
        start_seconds(parent_manifest, args.profile, legacy_started_at=0)
        manifest["admission_clock"] = clock
    else:
        manifest["admission_clock"] = make_clock(manifest["campaign_id"], args.profile,
            int(time.time() * 1000))
    for profile in (args.profile,) if args.profile else PROFILES:
        base, _, _, _, _ = _compile_subject(profile, scans["subjects"][profile], args.baseline, tokenizer)
        key = compatibility(profile, base)
        imported = []
        if args.parent_output:
            from scripts.dgx_m6_gate import gate
            previous_manifest = load(args.parent_output / "manifest.json")
            prior_source = Path(previous_manifest.get("source_ref") or args.parent_source)
            verified = gate(args.parent_output, baseline=args.baseline, scan_index=args.scan_index,
                runtime_source=prior_source)
            if verified["subjects"][profile]["missing"] or verified["subjects"][profile]["frozen"]:
                raise ValueError("second_round_parent_not_evaluable")
            closed = load(args.parent_output / profile / "closed-development-spending.json")
            current_spending = load(args.parent_output / profile / "spending.json")
            if current_spending["executions"] != closed["ledger"]["executions"]:
                raise ValueError("parent_development_phase_already_extended")
            for path in sorted((args.parent_output / profile / "runs").glob("*/result.json")):
                data = load(path)
                if state_failure(data["result"]):
                    imported.append(history.add(compatibility=key, case=data["case"], mutation=data["mutation"],
                        result=data["result"], evidence_ref=str(path), gate_digest=verified["digest"]))
        for source_root in ([] if args.parent_output else [args.baseline, *args.history_root]):
            old, _, _, _, _ = _compile_subject(profile, scans["subjects"][profile], source_root, tokenizer)
            run_ids, task_ids = set(), set()
            for result_path in sorted((source_root / profile / "runs").glob("*/result.json")):
                data = load(result_path)
                result = data["result"]
                if not (result["body"]["security_violation"] or result["body"]["utility_status"] == "fail"):
                    continue
                body = result["body"]
                case_id = data["case"]["body"]["case_id"]
                # Independently recompute the particular confirmed failure, including trace and DB.
                from skillloop.discovery.suite import make_dev_plan
                result = _recompute_run(result_path, profile=profile, case_id=case_id,
                    repetition=body["repetition_index"], attempt=body["attempt_index"], case=data["case"],
                    compiled=old, suite=old["suite"], plan=make_dev_plan(old,
                        campaign_id="m5b-qwen-discovery-" + profile, config=m5b_config()),
                    run_ids=run_ids, task_ids=task_ids, tokenizer=tokenizer)
                imported.append(history.add(compatibility=key, case=data["case"], mutation=data["mutation"],
                    result=result, evidence_ref=str(result_path), gate_digest=(accepted["digest"]
                    if source_root == args.baseline else None)))
        for prior_root in args.retained_development:
            rejected = load(prior_root / "configuration-rejection.json")
            prior_manifest = load(prior_root / "manifest.json")
            if rejected.get("status") != "not_accepted" or rejected.get("evidence_retained") is not True:
                raise ValueError("retained_development_not_rejected")
            if prior_manifest["source_index"] != source_index(Path(prior_manifest["source_ref"])):
                raise ValueError("retained_development_source_changed")
            prior_info = prior_manifest["subjects"][profile]
            prior_compiled = load(prior_root / profile / "compiled.json")
            prior_plans = {load(p)["digest"]: load(p) for p in (prior_root / profile).glob("plan-*.json")}
            prior_runs, prior_tasks = set(), set()
            for role in ("submitted", "candidate"):
                current = dict(prior_compiled)
                location = prior_root / profile if role == "candidate" else prior_root / "submitted" / profile
                if role == "submitted":
                    current.update(skill_digest=digest_bytes(load_example_skill(profile, root=REDTEAM)),
                        subject_digest=prior_info["submitted_bundle"]["digest"])
                for path in sorted(location.glob("runs/*/result.json")):
                    data = load(path)
                    if not state_failure(data["result"]):
                        continue
                    if data.get("runner_source_digest") != digest_jcs(prior_manifest["source_index"]):
                        raise ValueError("retained_failure_runner_source")
                    body = data["result"]["body"]
                    case_id = data["case"]["body"]["case_id"]
                    rebuilt = _recompute_run(path, profile=profile, case_id=case_id,
                        repetition=body["repetition_index"], attempt=body["attempt_index"],
                        case=data["case"], compiled=current, suite=current["suite"],
                        plan=prior_plans[data["plan_digest"]], run_ids=prior_runs, task_ids=prior_tasks,
                        tokenizer=tokenizer, expected_config=prior_manifest["config"])
                    imported.append(history.add(compatibility=key, case=data["case"], mutation=data["mutation"],
                        result=rebuilt, evidence_ref=str(path), gate_digest=None))
        history_snapshot = history.applicable(key)
        base, bindings = append_history(base, history_snapshot)
        root = args.output / profile
        root.mkdir(mode=0o700)
        save(root / "history-snapshot.json", history_snapshot)
        original = load_example_skill(profile, root=REDTEAM)
        policy = fixture(profile)[1]
        obligations = repair_obligations(profile)
        save(root / "obligations.json", obligations)
        fixed = {"obligation_digest": obligations["digest"],
                 "compiler_digest": digest_bytes((REPO / "skillloop/proxy/policy.py").read_bytes())}
        files = {"SKILL.md": original.decode()}
        parent = bundle(files, policy, **fixed)
        submitted_bundle = parent
        repair_history = []
        previous_info = previous_plan = previous_capacity = None
        if args.parent_output:
            parent_manifest = load(args.parent_output / "manifest.json")
            previous_info = parent_manifest["subjects"][profile]
            previous_gate = load(args.parent_output / "m6-gate.json")
            if (previous_gate["digest"] != digest_jcs({k: v for k, v in previous_gate.items() if k != "digest"})
                    or previous_gate["subjects"][profile]["missing"] or previous_info.get("repair_round", 1) != 1
                    or previous_gate["subjects"][profile]["frozen"]):
                raise ValueError("second_round_requires_complete_unfrozen_first_round")
            prior_application = load(args.parent_output / previous_info["applied_proposal"] / "application.json")
            repair_history = [prior_application["history_entry"]]
            files = prior_application["files"]
            policy = prior_application["policy"]
            parent = bundle(files, policy, **fixed)
            if parent != previous_info["candidate_bundle"]:
                raise ValueError("second_round_parent_bundle")
            original = files["SKILL.md"].encode()
            revisions = sorted((args.parent_output / profile).glob("plan-*.json"), key=lambda p: int(p.stem.split("-")[1]))
            previous_plan = load(revisions[-1])
            previous_capacity = load(args.parent_output / profile / "capacity-plan-1.json")
            pending_subject = "pending-second-candidate:" + profile
            additions = rows(pending_subject, base["cases"]) + protected_reservations(pending_subject, role="finalist")
            prospective = eliminate_protected_slots(previous_capacity, previous_info["candidate_bundle"]["digest"], additions)
            preflight = forecast(prospective["items"], calibration={"ready": True,
                "victim_seconds": VICTIM_BOUND, "evidence_digests": [digest_jcs(CONFIG)]}, stages=stage_bounds())
            save(root / "second-round-budget-preflight.json", {"forecast": preflight,
                "capacity_plan": prospective, "pre_generation_only": True, "production_admission": False})
            if preflight["admission"] != "ready":
                manifest["subjects"][profile] = {"status": "budget_rejected_before_generation",
                    "generated_proposals": previous_info["generated_proposals"], "applications_succeeded": previous_info["applications_succeeded"],
                    "reason_codes": preflight["reasons"], "new_model_calls": 0}
                save(args.output / "manifest.json", manifest)
                continue
            wall = remaining_capacity(current_spending,
                started_at_unix_ms=manifest["admission_clock"]["started_at_unix_ms"],
                at_unix_ms=int(time.time() * 1000), planned_attempts=preflight["reserved_attempts"],
                auxiliary_seconds=2 * 180 + SCANNER_BOUND + 120 + 600 + 60)
            save(root / "second-round-wall-preflight.json", wall)
            if wall["admission"] != "ready":
                manifest["subjects"][profile] = {"status": "budget_rejected_before_generation",
                    "generated_proposals": previous_info["generated_proposals"],
                    "applications_succeeded": previous_info["applications_succeeded"],
                    "reason_codes": wall["reasons"], "new_model_calls": 0}
                save(args.output / "manifest.json", manifest)
                continue
            claim_second_round(args.parent_output / profile / "second-round-claim.json",
                parent_gate_digest=previous_gate["digest"], output=args.output)
        diagnosis = {"submitted_cases": [row for row in load(args.baseline / "development-summary.json")["subjects"][profile]["cases"]],
                     "findings": [{"rule": f["body"]["rule_id"], "description": f["body"]["description"]}
                                  for f in scans["subjects"][profile]["findings"]],
                     "history_failures": len(bindings)}
        if previous_info:
            previous_row = previous_gate["subjects"][profile]
            diagnosis.update(previous_development={"verdict": previous_row["verdict"],
                "case_results": [{k: c["body"][k] for k in ("case_digest", "utility_status",
                    "security_status", "coverage_complete")} for c in previous_row["case_results"]],
                "unresolved_high": previous_row["unresolved_high"]},
                scanner_diagnosis=[{"rule": f["body"]["rule_id"], "description": f["body"]["description"]}
                    for f in load(args.parent_output / profile / "scan/index.json")["findings"]],
                repair_request="Use affirmative authority and confidentiality rules. Preserve registered business workflow and private-input confidentiality. Avoid ambiguous quotations of forbidden commands.")
        save(root / "diagnosis.json", diagnosis)
        errors = []
        applied = None
        valid_proposals = previous_info.get("valid_patch_proposals", previous_info.get("repair_round", 1)) if previous_info else 0
        generation_attempts = 0
        for attempt in range(2):
            if valid_proposals >= 2:
                break
            generation_attempts += 1
            attempt_root = root / f"proposal-{attempt + 1}"
            attempt_root.mkdir(mode=0o700)
            try:
                started = time.monotonic()
                if args.reuse_proposals:
                    source = args.reuse_proposals / profile / f"proposal-{attempt + 1}"
                    if (source / "rejected.json").is_file():
                        failure = load(source / "rejected.json")
                        save(attempt_root / "rejected.json", {**failure, "retained_source_ref": str(source)})
                        if (source / "response.bin").is_file():
                            raw = (source / "response.bin").read_bytes()
                            (attempt_root / "response.bin").write_bytes(raw)
                            os.chmod(attempt_root / "response.bin", 0o600)
                        errors.append(failure)
                        continue
                    previous = validate_envelope(load(source / "proposal.json"))
                    evidence = load(source / "evidence.json")
                    raw = (source / "response.bin").read_bytes()
                    parsed = decode_json(decode_json(raw)["choices"][0]["message"]["content"].encode())
                    edit = previous["body"]["edits"][0]
                    if (previous["body"]["repair_kind"] != "text_only" or len(previous["body"]["edits"]) != 1 or
                            edit["path"] != "SKILL.md" or edit["parent_bytes_digest"] != digest_bytes(original) or
                            edit["start_byte"] != original.index(b"\n---\n", 4) + 5 or edit["end_byte"] != len(original) or
                            parsed != {"replacement_body": edit["replacement_utf8"]} or
                            evidence["response_digest"] != digest_bytes(raw) or
                            evidence["diagnosis_digest"] != digest_jcs(load(args.reuse_proposals / profile / "diagnosis.json"))):
                        raise ValueError("reused_proposal_binding")
                    proposal = make_envelope("PatchProposal", {**previous["body"], "parent_subject_digest": parent["digest"]})
                    evidence.update(proposal_digest=proposal["digest"], source_proposal_digest=previous["digest"],
                                    source_ref=str(source), new_model_call=False,
                                    current_diagnosis_digest=digest_jcs(diagnosis), proposal_diagnosis_reused=True)
                else:
                    proposal, evidence, raw = propose_body(profile=profile, skill_bytes=original,
                        parent_subject_digest=parent["digest"], diagnosis=diagnosis)
                    evidence["elapsed_seconds"] = time.monotonic() - started
                (attempt_root / "response.bin").write_bytes(raw)
                os.chmod(attempt_root / "response.bin", 0o600)
                save(attempt_root / "proposal.json", proposal)
                save(attempt_root / "evidence.json", evidence)
                valid_proposals += 1
                file_set = {"files": files, "subject_digest": parent["digest"], "policies": {}, **fixed}
                applied = apply_proposal(proposal, file_set, repair_history, policy)
                save(attempt_root / "application.json", applied)
                save(root / "file-set.json", file_set)
                save(root / "parent-policy.json", policy)
                break
            except (ValueError, OSError) as error:
                if isinstance(error, ProposalError) and error.raw_response:
                    (attempt_root / "response.bin").write_bytes(error.raw_response)
                    os.chmod(attempt_root / "response.bin", 0o600)
                failure = {"error_type": type(error).__name__, "code": str(error)[:120]}
                save(attempt_root / "rejected.json", failure)
                errors.append(failure)
        info = {"parent_bundle": parent, "generated_proposals": generation_attempts + (previous_info["generated_proposals"] if previous_info else 0),
                "submitted_bundle": submitted_bundle,
                "applications_succeeded": int(applied is not None) + (previous_info["applications_succeeded"] if previous_info else 0),
                "evaluable_candidates": int(applied is not None) + (previous_info["evaluable_candidates"] if previous_info else 0),
                "repair_round": valid_proposals, "valid_patch_proposals": valid_proposals,
                "generation_attempts_per_round": 2,
                "history_bindings": bindings, "history_imported": imported, "proposal_failures": errors,
                "compatibility": key, "fixed": fixed, "obligations": obligations,
                "reused_proposals_ref": str(args.reuse_proposals) if args.reuse_proposals else None}
        if previous_info:
            info.update(parent_output=str(args.parent_output), parent_manifest_digest=digest_jcs(parent_manifest),
                parent_gate_digest=previous_gate["digest"], repair_history=repair_history)
        if applied is not None:
            skill_dir = args.output / "candidate" / "skills" / profile.replace("_", "-")
            skill_dir.mkdir(parents=True, mode=0o700)
            raw = applied["files"]["SKILL.md"].encode()
            (skill_dir / "SKILL.md").write_bytes(raw)
            os.chmod(skill_dir / "SKILL.md", 0o600)
            package = load(REDTEAM / "skills" / profile.replace("_", "-") / "manifest.json")
            package["files"][0].update(bytes_digest=digest_bytes(raw), size_bytes=len(raw))
            save(skill_dir / "manifest.json", package)
            base.update(skill_digest=digest_bytes(raw), subject_digest=applied["candidate_subject_digest"])
            save(root / "compiled.json", base)
            save(root / "suite.json", base["suite"])
            plan = execution_plan(base, campaign=campaign_name(manifest, profile), parent=previous_plan,
                submitted_digest=submitted_bundle["digest"])
            save(root / f"plan-{plan['body']['revision']}.json", plan)
            full_items = rows(base["subject_digest"], base["cases"])
            full_items += rows(submitted_bundle["digest"], base["cases"], role="submitted")
            full_items += protected_reservations(base["subject_digest"], role="finalist")
            full_items += protected_reservations(parent["digest"], role="submitted")
            if previous_capacity:
                full_items = rows(base["subject_digest"], base["cases"]) + protected_reservations(base["subject_digest"], role="finalist")
                capacity = eliminate_protected_slots(previous_capacity, previous_info["candidate_bundle"]["digest"], full_items)
            else:
                capacity = revise(None, full_items)
            save(root / "capacity-plan-1.json", capacity)
            # Pending calibration never qualifies a finalist. The forecast still
            # makes every required future capacity slot explicit before execution.
            stages = stage_bounds()
            budget = forecast(capacity["items"], calibration={"ready": False, "victim_seconds": VICTIM_BOUND,
                "evidence_digests": [accepted["digest"]]}, stages=stages)
            save(root / "budget-pending.json", {"forecast": budget, "stages": stages,
                "reason": "maximum_load_and_stage_calibration_required", "production_admission": False})
            info.update(candidate_bundle=applied["candidate_bundle"], applied_proposal=str(attempt_root.relative_to(args.output)),
                status="applied", case_count=len(base["cases"]), required_runs=len(plan["body"]["items"]))
        else:
            info["status"] = "no_evaluable_candidate"
        manifest["subjects"][profile] = info
        save(args.output / "manifest.json", manifest)
        print(json.dumps({"profile": profile, "stage": "prepare", "status": info["status"],
            "proposals": info["generated_proposals"], "cases": info.get("case_count"),
            "history_failures": len(bindings)}), flush=True)


def rescan(args) -> None:
    model_preflight("http://127.0.0.1:30000")
    for profile in (args.profile,) if args.profile else PROFILES:
        manifest = load(args.output / "manifest.json")
        if manifest["subjects"][profile]["status"] != "applied":
            continue
        report_dir = args.output / profile / "scan"
        report_dir.mkdir(mode=0o700, exist_ok=False)
        with tempfile.TemporaryDirectory(prefix="sl-m6-") as temporary:
            bridge_dir = Path(temporary)
            os.chmod(bridge_dir, 0o700)
            started = time.monotonic()
            with HostModelBridge(bridge_dir / "qwen.sock", max_chat_requests=4) as bridge:
                command = docker_command(image=args.image, osv_data=args.osv_data, bridge_dir=bridge_dir,
                    skill_dir=args.output / "candidate" / "skills" / profile.replace("_", "-"), report_dir=report_dir)
                try:
                    result = subprocess.run(command, capture_output=True, timeout=SCANNER_BOUND)
                    exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
                except subprocess.TimeoutExpired as error:
                    exit_code, stdout, stderr = 124, error.stdout or b"", error.stderr or b""
                calls = bridge.chat_requests
                usages = bridge.usage_records
        for name, raw in (("stdout.log", stdout), ("stderr.log", stderr)):
            (report_dir / name).write_bytes(raw)
            os.chmod(report_dir / name, 0o600)
        raw = load_example_skill(profile, root=args.output / "candidate")
        record = {"exit_code": exit_code, "elapsed_seconds": time.monotonic() - started,
                  "qwen_calls": calls, "model_usage": usages, "subject_digest": digest_bytes(raw)}
        save(report_dir / "invocation.json", record)
        if (report_dir / "report.json").is_file():
            report, findings, dispositions = reduce_scan(profile, (report_dir / "report.json").read_bytes(),
                exit_code, subject_digest=digest_bytes(raw), require_llm=True, allow_risk_exit=True)
            high = [f["digest"] for f in findings if f["body"]["severity"].lower() in {"critical", "high", "p0", "p1"}]
            record.update(scanner_report=report, findings=findings, dispositions=dispositions, unresolved_high=high,
                status="pass" if scan_passed(report, calls, high) else "incomplete_or_open")
        else:
            record.update(status="incomplete_or_open", unresolved_high=["raw_scan_missing"])
        save(report_dir / "index.json", record)
        print(json.dumps({"profile": profile, "stage": "rescan", "status": record["status"],
            "qwen_calls": calls, "unresolved_high": len(record["unresolved_high"])}), flush=True)


def worker(args) -> None:
    compiled = load(args.output / args.profile / "compiled.json")
    plan = load(args.plan)
    info = load(args.output / "manifest.json")["subjects"][args.profile]
    run_root, skill_root = args.output, args.output / "candidate"
    if args.subject_role == "submitted":
        compiled.update(skill_digest=digest_bytes(load_example_skill(args.profile, root=REDTEAM)),
            subject_digest=info["submitted_bundle"]["digest"])
        run_root, skill_root = args.output / "submitted", REDTEAM
    directory = run_directory(run_root, args.profile, args.case, args.repetition, args.attempt)
    run_one(args.case, args.repetition, directory,
        args.attempt, compiled_suite=compiled, skill_root=skill_root,
        campaign_id=campaign_name(load(args.output / "manifest.json"), args.profile),
        runtime_config=CONFIG, execution_plan=plan)
    data = load(directory / "result.json")
    data["runner_source_digest"] = digest_jcs(source_index())
    save(directory / "result.json", data)


def regress(args) -> None:
    for profile in (args.profile,) if args.profile else PROFILES:
        root = args.output / profile
        if not (root / "compiled.json").is_file():
            continue
        compiled = load(root / "compiled.json")
        admission_path = root / "budget-admission.json"
        if not admission_path.is_file() or load(admission_path).get("admission") != "ready":
            raise ValueError("m6_regression_requires_calibrated_budget:" + profile)
        revisions = sorted(root.glob("plan-*.json"), key=lambda p: int(p.stem.split("-")[1]))
        plan_path = revisions[-1]
        plan = load(plan_path)
        info = load(args.output / "manifest.json")["subjects"][profile]
        if args.subject_role == "submitted":
            if info.get("parent_output"):
                raise ValueError("submitted_execution_already_required_in_first_round")
            compiled.update(skill_digest=digest_bytes(load_example_skill(profile, root=REDTEAM)),
                subject_digest=info["submitted_bundle"]["digest"])
        run_root = args.output / "submitted" if args.subject_role == "submitted" else args.output
        ledger_root = Path(info["parent_output"]) / profile if info.get("parent_output") else root
        first_manifest = load(ledger_root.parent / "manifest.json")
        started_at = start_seconds(first_manifest, profile,
            legacy_started_at=(ledger_root.parent / "m5-acceptance.json").stat().st_mtime)
        ledger = SpendingLedger(ledger_root / "spending.json", victim_seconds=VICTIM_BOUND,
            campaign_started_at=started_at)
        from scripts.dgx_m6_admit import check_admission
        check_admission(args.output, profile)
        stage_rows = []
        for case_id in ordered_cases(compiled["cases"]):
            case = compiled["cases"][case_id]
            for rep in range(3):
                for attempt in (0, 1):
                    directory = run_directory(run_root, profile, case_id, rep, attempt)
                    path = directory / "result.json"
                    if attempt and not path.exists():
                        first = run_directory(run_root, profile, case_id, rep, 0) / "result.json"
                        if not first.is_file() or not retry_eligible(load(first)) or ledger.read()["retries"] >= 2:
                            break
                        plan = execution_plan(compiled, campaign=campaign_name(load(args.output / "manifest.json"), profile), parent=plan, retry=(case_id, rep))
                        plan_path = root / f"plan-{plan['body']['revision']}.json"
                        save(plan_path, plan)
                    if not directory.exists():
                        ledger.consume(compiled["subject_digest"] + f".{case_id}.{rep}", attempt)
                        started = time.monotonic()
                        command = [sys.executable, str(Path(__file__).resolve()), "worker", "--output", str(args.output),
                            "--profile", profile, "--case", case_id, "--repetition", str(rep), "--attempt", str(attempt),
                            "--subject-role", args.subject_role,
                            "--plan", str(plan_path)]
                        try:
                            execution = subprocess.run(command, capture_output=True, timeout=VICTIM_BOUND)
                            exit_code = execution.returncode
                            failure_output = execution.stderr
                        except subprocess.TimeoutExpired as error:
                            exit_code = 124
                            failure_output = error.stderr or b""
                        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                        (directory / "worker-stderr.log").write_bytes(failure_output)
                        os.chmod(directory / "worker-stderr.log", 0o600)
                        timing = {"elapsed_seconds": time.monotonic() - started, "exit_code": exit_code,
                                  "case_id": case_id, "repetition": rep, "attempt": attempt,
                                  "plan_digest": plan["digest"]}
                        save(directory / "timing.json", timing)
                        stage_rows.append(timing)
                    if path.is_file():
                        result = load(path)["result"]["body"]
                        print(json.dumps({"profile": profile, "subject_role": args.subject_role, "case": case_id, "repetition": rep, "attempt": attempt,
                            "complete": result["coverage_complete"], "utility": result["utility_status"],
                            "security_violation": result["security_violation"]}), flush=True)
                        if result["coverage_complete"] or not retry_eligible(load(path)):
                            break
                    else:
                        break  # Unknown side effects or missing evidence cannot earn a retry.
        save(root / (args.subject_role + "-execution-timings.json"), stage_rows)
        if args.subject_role == "candidate":
            close_execution_spending(args.output, profile)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "rescan", "regress", "worker"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--scan-index", type=Path)
    parser.add_argument("--history-root", type=Path, action="append", default=[])
    parser.add_argument("--retained-development", type=Path, action="append", default=[])
    parser.add_argument("--reuse-proposals", type=Path)
    parser.add_argument("--parent-output", type=Path)
    parser.add_argument("--parent-source", type=Path)
    parser.add_argument("--subject-role", choices=("submitted", "candidate"), default="candidate")
    parser.add_argument("--image")
    parser.add_argument("--osv-data", type=Path)
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--case")
    parser.add_argument("--repetition", type=int)
    parser.add_argument("--attempt", type=int, default=0)
    parser.add_argument("--plan", type=Path)
    args = parser.parse_args()
    args.output = args.output.resolve()
    for name in ("baseline", "scan_index", "osv_data", "plan", "reuse_proposals", "parent_output"):
        if getattr(args, name) is not None:
            setattr(args, name, getattr(args, name).resolve())
    args.history_root = [path.resolve() for path in args.history_root]
    args.retained_development = [path.resolve() for path in args.retained_development]
    {"prepare": prepare, "rescan": rescan, "regress": regress, "worker": worker}[args.stage](args)


if __name__ == "__main__":
    main()
