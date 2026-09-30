"""Independent private M6 application/rescan/regression recomputation."""

from __future__ import annotations

import argparse
import json
import sys
import sqlite3
import signal
import time
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.dgx_m5b_gate import _compile_subject, _recompute_run
from scripts.dgx_m6_repair import (CONFIG, PROFILES, REPO, append_history, compatibility,
                                  execution_plan, load, save)
from scripts.dgx_m6_repair import REDTEAM, repair_obligations, scan_passed, source_index
from scripts.dgx_m6_repair import campaign_name, retry_eligible, stage_bounds
from scripts.dgx_m6_repair import execution_spending_data, VICTIM_BOUND
from scripts.dgx_m5b_attack import run_directory
from scripts.spec_v22_core import reduce_case, validate_plan, canonical_policy
from skillloop.discovery.scanner import reduce_scan
from skillloop.families.fixtures import load_example_skill
from skillloop.protocol import decode_json, digest_bytes, digest_jcs
from skillloop.repair.applicator import apply_proposal, bundle
from skillloop.repair.history import FailureHistory
from skillloop.repair.budget import forecast, freeze
from skillloop.repair.spending import verify_snapshot, remaining_capacity
from skillloop.runtime.gateway import ExactDockerTokenizer, ExactLocalTokenizer
from skillloop.families.task_world import fixture


def state(results: list[dict]) -> str:
    if any(r["body"]["security_violation"] or r["body"]["utility_status"] == "fail" for r in results):
        return "fail"
    if not any(r["body"]["coverage_complete"] for r in results):
        return "unknown"
    return "pass"


def gate(root: Path, *, baseline: Path, scan_index: Path, runtime_source: Path = REPO,
         expected_config: dict | None = None, runtime_profile_path: Path | None = None,
         tokenizer_path: Path | None = None, calibration_verifier=None) -> dict:
    def timeout(signum, frame):
        raise TimeoutError("independent_gate_150_second_bound")
    previous = signal.signal(signal.SIGALRM, timeout)
    remaining = signal.alarm(150)
    started = time.monotonic()
    try:
        return _gate(root, baseline=baseline, scan_index=scan_index, runtime_source=runtime_source,
            expected_config=expected_config, runtime_profile_path=runtime_profile_path,
            tokenizer_path=tokenizer_path, calibration_verifier=calibration_verifier)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        if remaining:
            signal.alarm(max(1, remaining - int(time.monotonic() - started)))


def _gate(root: Path, *, baseline: Path, scan_index: Path, runtime_source: Path = REPO,
          expected_config: dict | None = None, runtime_profile_path: Path | None = None,
          tokenizer_path: Path | None = None, calibration_verifier=None) -> dict:
    config = CONFIG if expected_config is None else expected_config
    manifest = load(root / "manifest.json")
    if manifest["config"] != config:
        raise ValueError("m6_config_binding")
    for relative, digest in manifest["source_index"].items():
        if digest_bytes((runtime_source / relative).read_bytes()) != digest:
            raise ValueError("m6_source_binding:" + relative)
    accepted = load(baseline / "m5b-gate.json")
    if manifest["baseline_gate_digest"] != accepted["digest"]:
        raise ValueError("m5_acceptance_binding")
    if config.get("gateway_backend") == "ollama":
        if tokenizer_path is None or runtime_profile_path is None:
            raise ValueError("mac_gate_requires_pinned_tokenizer_and_runtime_profile")
        tokenizer = ExactLocalTokenizer(str(tokenizer_path))
    else:
        tokenizer = ExactDockerTokenizer()
    history = FailureHistory(root.parent / "m6-private-history.sqlite")
    report = {"kind": "M6IndependentGate", "subjects": {}, "baseline_gate_digest": accepted["digest"],
              "campaign_id": manifest["campaign_id"], "campaign_manifest_digest": digest_jcs(manifest),
              "config_digest": digest_jcs(manifest["config"]),
              "parent_gate_digests": sorted({i["parent_gate_digest"] for i in manifest["subjects"].values() if i.get("parent_gate_digest")}),
              "reducer_source_digest": digest_jcs(source_index()), "runtime_source_ref": str(runtime_source),
              "production_ready": False, "protected_evaluation": "not_started"}
    scans = load(scan_index)
    for profile in manifest["subjects"]:
        info = manifest["subjects"][profile]
        directory = root / profile
        if info["status"] != "applied":
            report["subjects"][profile] = {"verdict": "inconclusive", "reason": "no_evaluable_candidate",
                "generated_proposals": info["generated_proposals"], "applications_succeeded": 0,
                "evaluable_candidates": 0, "frozen": False}
            continue
        base, _, _, _, _ = _compile_subject(profile, scans["subjects"][profile], baseline, tokenizer)
        obligations = repair_obligations(profile)
        if (info.get("obligations") != obligations or load(directory / "obligations.json") != obligations or
                info["fixed"]["obligation_digest"] != obligations["digest"]):
            raise ValueError("repair_obligation_binding")
        applicable = history.applicable(compatibility(profile, base))
        recorded_history = {b["history_digest"] for b in info["history_bindings"]}
        snapshot_path = directory / "history-snapshot.json"
        snapshot = load(snapshot_path) if snapshot_path.is_file() else [e for e in applicable if e["digest"] in recorded_history]
        if ({e["digest"] for e in snapshot} != recorded_history or
                any(e not in applicable for e in snapshot)):
            raise ValueError("history_snapshot_reference")
        compiled, bindings = append_history(base, snapshot)
        if bindings != info["history_bindings"]:
            raise ValueError("history_binding_changed")
        proposal_root = root / info["applied_proposal"]
        parent_policy = fixture(profile)[1]
        parent_files = {"SKILL.md": load_example_skill(profile, root=REDTEAM).decode()}
        fixed = {"obligation_digest": obligations["digest"],
                 "compiler_digest": digest_bytes((REPO / "skillloop/proxy/policy.py").read_bytes())}
        submitted_bundle = bundle(parent_files, parent_policy, **fixed)
        if info.get("submitted_bundle") != submitted_bundle:
            raise ValueError("submitted_bundle_binding")
        repair_history = []
        previous_plan = None
        if info.get("parent_output"):
            previous_root = Path(info["parent_output"])
            prior_manifest = load(previous_root / "manifest.json")
            prior_info = prior_manifest["subjects"][profile]
            if digest_jcs(prior_manifest) != info["parent_manifest_digest"] or prior_info.get("repair_round", 1) != 1:
                raise ValueError("second_round_chain_binding")
            parent_gate = load(previous_root / "m6-gate.json")
            if (parent_gate["digest"] != digest_jcs({k: v for k, v in parent_gate.items() if k != "digest"})
                    or parent_gate["digest"] != info["parent_gate_digest"]
                    or parent_gate["campaign_id"] != manifest["campaign_id"]
                    or parent_gate["config_digest"] != digest_jcs(config)
                    or parent_gate["subjects"][profile]["subject_digest"] != prior_info["candidate_bundle"]["digest"]
                    or manifest.get("admission_clock") != prior_manifest.get("admission_clock")):
                raise ValueError("second_round_parent_gate_or_clock_binding")
            prior_proposal = load(previous_root / prior_info["applied_proposal"] / "proposal.json")
            prior_bundle = bundle(parent_files, parent_policy, **fixed)
            prior_set = {"files": parent_files, "subject_digest": prior_bundle["digest"], "policies": {}, **fixed}
            first = apply_proposal(prior_proposal, prior_set, [], parent_policy)
            if first != load(previous_root / prior_info["applied_proposal"] / "application.json"):
                raise ValueError("first_round_application_changed")
            repair_history = [first["history_entry"]]
            if repair_history != info["repair_history"]:
                raise ValueError("second_round_history_changed")
            parent_files, parent_policy = first["files"], first["policy"]
            prior_plans = sorted((previous_root / profile).glob("plan-*.json"), key=lambda p: int(p.stem.split("-")[1]))
            previous_plan = load(prior_plans[-1])
        parent_bundle = bundle(parent_files, parent_policy, **fixed)
        file_set = {"files": parent_files, "subject_digest": parent_bundle["digest"], "policies": {}, **fixed}
        if (load(directory / "file-set.json") != file_set or load(directory / "parent-policy.json") != parent_policy
                or info["parent_bundle"] != parent_bundle or info["fixed"] != fixed):
            raise ValueError("repair_exact_parent_binding")
        applied = apply_proposal(load(proposal_root / "proposal.json"), file_set, repair_history, parent_policy)
        if applied != load(proposal_root / "application.json") or applied["candidate_bundle"] != info["candidate_bundle"]:
            raise ValueError("m6_application_recompute")
        actual = load_example_skill(profile, root=root / "candidate")
        if actual != applied["files"]["SKILL.md"].encode():
            raise ValueError("candidate_files_changed")
        generation_directories = list(directory.glob("proposal-*"))
        proposal_count = sum((p / "proposal.json").is_file() for p in generation_directories)
        attempt_count = len(generation_directories)
        if info.get("parent_output"):
            previous_directories = list((Path(info["parent_output"]) / profile).glob("proposal-*"))
            proposal_count += sum((p / "proposal.json").is_file() for p in previous_directories)
            attempt_count += len(previous_directories)
            generation_directories += previous_directories
        if (proposal_count != info.get("valid_patch_proposals", info.get("repair_round", 1)) or
                attempt_count != info["generated_proposals"] or not 1 <= proposal_count <= 2):
            raise ValueError("repair_generation_accounting")
        for generation in generation_directories:
            raw_path = generation / "response.bin"
            if not raw_path.is_file():
                raise ValueError("patcher_raw_response_missing")
            raw = raw_path.read_bytes()
            response = decode_json(raw)
            usage = response.get("usage") or {}
            if usage.get("reasoning_tokens") != 0 or response["choices"][0]["message"].get("reasoning_content"):
                raise ValueError("patcher_thinking_mode_evidence")
            if (generation / "proposal.json").is_file():
                proposal = load(generation / "proposal.json")
                evidence = load(generation / "evidence.json")
                body = decode_json(response["choices"][0]["message"]["content"].encode())
                if (evidence["response_digest"] != digest_bytes(raw) or evidence["proposal_digest"] != proposal["digest"] or
                        evidence["usage"] != usage or len(proposal["body"]["edits"]) != 1 or
                        body != {"replacement_body": proposal["body"]["edits"][0]["replacement_utf8"]} or
                        evidence["patcher_config"].get("chat_template_kwargs") != {"enable_thinking": False}):
                    raise ValueError("patcher_response_proposal_binding")
        compiled.update(skill_digest=digest_bytes(actual), subject_digest=applied["candidate_subject_digest"])
        if compiled != load(directory / "compiled.json"):
            raise ValueError("candidate_suite_recompile")
        revisions = sorted(directory.glob("plan-*.json"), key=lambda p: int(p.stem.split("-")[1]))
        plans = {}
        parent = None
        for path in revisions:
            plan = load(path)
            validate_plan(plan, compiled["suite"])
            if parent is None:
                if plan != execution_plan(compiled, campaign=campaign_name(manifest, profile), parent=previous_plan,
                        submitted_digest=submitted_bundle["digest"], runtime_config=config,
                        runtime_profile_path=runtime_profile_path):
                    raise ValueError("initial_plan_recompute")
            else:
                before = parent["body"]["items"]
                after = plan["body"]["items"]
                changed = [(a, b) for a, b in zip(before, after) if a != b]
                if (len(before) != len(after) or len(changed) != 1 or plan["body"]["parent_plan_digest"] != parent["digest"]):
                    raise ValueError("plan_revision_chain")
                item = changed[0][0]
                case_id = next(cid for cid, case in compiled["cases"].items() if case["digest"] == item["case_digest"])
                revised_subject = dict(compiled)
                revised_subject["subject_digest"] = item["subject_digest"]
                expected = execution_plan(revised_subject, campaign=campaign_name(manifest, profile), parent=parent,
                    retry=(case_id, item["repetition_index"]), runtime_config=config,
                    runtime_profile_path=runtime_profile_path)
                if expected != plan:
                    raise ValueError("retry_revision_recompute")
            plans[plan["digest"]] = plan
            parent = plan
        missing, failures, case_results, candidate_pairs = [], [], [], {}
        run_ids, task_ids = set(), set()
        reasoning_tokens, responses, incomplete_attempts = 0, 0, []
        expected_runner_digest = digest_jcs(source_index(runtime_source))
        for case_id, case in compiled["cases"].items():
            attempts = []
            for rep in range(3):
                pair = []
                for attempt in (0, 1):
                    run_root = run_directory(root, profile, case_id, rep, attempt)
                    result_path = run_root / "result.json"
                    if result_path.is_file():
                        data = load(result_path)
                        if attempt:
                            first_path = run_directory(root, profile, case_id, rep, 0) / "result.json"
                            if not first_path.is_file() or not retry_eligible(load(first_path)):
                                raise ValueError("candidate_retry_not_qualified")
                        if data.get("runner_source_digest") != expected_runner_digest:
                            raise ValueError("execution_runner_source_binding")
                        plan = plans.get(data["plan_digest"])
                        if plan is None:
                            raise ValueError("run_plan_not_authorized")
                        item = next(i for i in plan["body"]["items"] if i["subject_digest"] == compiled["subject_digest"]
                            and i["case_digest"] == case["digest"] and i["repetition_index"] == rep)
                        if attempt >= item["attempts_reserved"]:
                            raise ValueError("unreserved_attempt")
                        rebuilt = _recompute_run(result_path, profile=profile, case_id=case_id,
                            repetition=rep, attempt=attempt, case=case, compiled=compiled, suite=compiled["suite"], plan=plan,
                            run_ids=run_ids, task_ids=task_ids, tokenizer=tokenizer, expected_config=config,
                            deployment_epoch=config.get("deployment_epoch", "m5-development-1"))
                        with closing(sqlite3.connect(f"file:{run_root / 'authority.db'}?mode=ro", uri=True)) as db:
                            stored = db.execute("SELECT policy_json,subject_digest FROM tasks WHERE run_id=?",
                                (rebuilt["body"]["run_id"],)).fetchone()
                        if (stored is None or stored[1] != compiled["subject_digest"] or
                                canonical_policy(json.loads(stored[0]))["digest"] != applied["candidate_bundle"]["body"]["policy_digest"]):
                            raise ValueError("executed_candidate_policy_binding")
                        attempts.append(rebuilt)
                        pair.append(rebuilt)
                        if state([rebuilt]) == "fail":
                            failures.append(f"{case_id}:{rep}:{attempt}")
                        if not rebuilt["body"]["coverage_complete"]:
                            incomplete_attempts.append(f"{case_id}:{rep}:{attempt}")
                        traces = list((run_root / "evidence").glob("*.jsonl"))
                        for context in (run_root / "evidence/contexts").iterdir():
                            messages = load(context)
                            if (len(messages) < 2 or messages[1].get("role") != "user" or
                                not messages[1].get("content", "").startswith(actual.decode() + "\n\nTask input bindings: ")):
                                raise ValueError("candidate_bytes_not_in_model_context")
                        for line in traces[0].read_text().splitlines():
                            event = json.loads(line)
                            if event.get("type") == "model_response":
                                responses += 1
                                count = event["response"].get("usage", {}).get("reasoning_tokens")
                                if count != 0:
                                    raise ValueError("thinking_mode_evidence_invalid")
                                reasoning_tokens += count
                    elif run_root.exists():
                        missing.append(f"{case_id}:{rep}:{attempt}:result_missing")
                candidate_pairs[(case["digest"], rep)] = state(pair)
            reduced = reduce_case(attempts, case) if attempts else None
            if reduced is None or not reduced["body"]["coverage_complete"]:
                missing.append(case_id)
            if reduced:
                case_results.append(reduced)
        scan_path = directory / "scan/index.json"
        high, scan_complete = ["rescan_missing"], False
        if scan_path.is_file():
            scan = load(scan_path)
            raw_path = directory / "scan/report.json"
            report_obj, findings, dispositions = reduce_scan(profile, raw_path.read_bytes(), scan["exit_code"],
                subject_digest=digest_bytes(actual), require_llm=True, allow_risk_exit=True)
            if (report_obj, findings, dispositions) != (scan["scanner_report"], scan["findings"], scan["dispositions"]):
                raise ValueError("candidate_rescan_recompute")
            high = [f["digest"] for f in findings if f["body"]["severity"].lower() in {"critical", "high", "p0", "p1"}]
            scan_complete = scan_passed(report_obj, scan["qwen_calls"], [])
        baseline_pairs, submitted_failures, submitted_incomplete, submitted_missing = {}, [], [], []
        submitted_absent_items = []
        submitted_executed_required_runs = 0
        submitted_root = Path(info["parent_output"]) if info.get("parent_output") else root
        submitted_info = load(submitted_root / "manifest.json")["subjects"][profile]
        submitted_compiled = load(submitted_root / profile / "compiled.json")
        submitted_compiled.update(skill_digest=digest_bytes(load_example_skill(profile, root=REDTEAM)),
            subject_digest=submitted_bundle["digest"])
        submitted_plans = {load(p)["digest"]: load(p) for p in (submitted_root / profile).glob("plan-*.json")}
        submitted_cases = []
        for case_id, case in submitted_compiled["cases"].items():
            attempts = []
            for repetition in range(3):
                pair = []
                for attempt in (0, 1):
                    folder = run_directory(submitted_root / "submitted", profile, case_id, repetition, attempt)
                    path = folder / "result.json"
                    if not path.is_file():
                        continue
                    data = load(path)
                    if attempt:
                        first_path = run_directory(submitted_root / "submitted", profile, case_id, repetition, 0) / "result.json"
                        if not first_path.is_file() or not retry_eligible(load(first_path)):
                            raise ValueError("submitted_retry_not_qualified")
                    plan = submitted_plans.get(data["plan_digest"])
                    if plan is None or data.get("runner_source_digest") != expected_runner_digest:
                        # First-round source is immutable even when round two uses a new runner.
                        prior_source = Path(load(submitted_root / "manifest.json")["source_ref"])
                        if plan is None or data.get("runner_source_digest") != digest_jcs(source_index(prior_source)):
                            raise ValueError("submitted_execution_source_or_plan")
                    item = next(i for i in plan["body"]["items"] if i["subject_digest"] == submitted_bundle["digest"]
                        and i["case_digest"] == case["digest"] and i["repetition_index"] == repetition)
                    if attempt >= item["attempts_reserved"]:
                        raise ValueError("submitted_unreserved_attempt")
                    rebuilt = _recompute_run(path, profile=profile, case_id=case_id, repetition=repetition,
                        attempt=attempt, case=case, compiled=submitted_compiled,
                        suite=submitted_compiled["suite"], plan=plan, run_ids=run_ids, task_ids=task_ids,
                        tokenizer=tokenizer, expected_config=config,
                            deployment_epoch=config.get("deployment_epoch", "m5-development-1"))
                    with closing(sqlite3.connect(f"file:{folder / 'authority.db'}?mode=ro", uri=True)) as db:
                        stored = db.execute("SELECT policy_json,subject_digest FROM tasks WHERE run_id=?",
                            (rebuilt["body"]["run_id"],)).fetchone()
                    if stored is None or stored[1] != submitted_bundle["digest"] or canonical_policy(json.loads(stored[0]))["digest"] != submitted_bundle["body"]["policy_digest"]:
                        raise ValueError("submitted_policy_binding")
                    original_bytes = load_example_skill(profile, root=REDTEAM)
                    for context in (folder / "evidence/contexts").iterdir():
                        messages = load(context)
                        if not messages[1].get("content", "").startswith(original_bytes.decode() + "\n\nTask input bindings: "):
                            raise ValueError("submitted_bytes_not_in_model_context")
                    for trace in (folder / "evidence").glob("*.jsonl"):
                        for line in trace.read_text().splitlines():
                            event = json.loads(line)
                            if event.get("type") == "model_response" and event["response"].get("usage", {}).get("reasoning_tokens") != 0:
                                raise ValueError("submitted_thinking_mode_evidence")
                    pair.append(rebuilt)
                    attempts.append(rebuilt)
                    if state([rebuilt]) == "fail":
                        submitted_failures.append(f"{case_id}:{repetition}:{attempt}")
                    if not rebuilt["body"]["coverage_complete"]:
                        submitted_incomplete.append(f"{case_id}:{repetition}:{attempt}")
                baseline_pairs[(case["digest"], repetition)] = pair
                if pair:
                    submitted_executed_required_runs += 1
                else:
                    submitted_absent_items.append(f"{case_id}:{repetition}")
            reduced = reduce_case(attempts, case) if attempts else None
            if reduced is None or not reduced["body"]["coverage_complete"]:
                submitted_missing.append(case_id)
            if reduced is not None:
                submitted_cases.append(reduced)
        paired = {"improved": 0, "regressed": 0, "unchanged": 0, "unknown": 0}
        for key, results in baseline_pairs.items():
            before, after = state(results), candidate_pairs.get(key, "unknown")
            if "unknown" in (before, after):
                paired["unknown"] += 1
            elif before == after:
                paired["unchanged"] += 1
            elif before == "fail":
                paired["improved"] += 1
            else:
                paired["regressed"] += 1
        budget = {"admission": "rejected", "reasons": ["maximum_load_budget_calibration_required"]}
        admission_path = directory / "budget-admission.json"
        if admission_path.is_file():
            admitted = load(admission_path)
            if admitted["digest"] != digest_jcs({k: v for k, v in admitted.items() if k != "digest"}):
                raise ValueError("budget_admission_digest")
            calibration = load(Path(admitted["calibration_ref"]) / "calibration.json")
            if (calibration["digest"] != digest_jcs({k: v for k, v in calibration.items() if k != "digest"})
                    or calibration["digest"] != admitted["calibration_digest"]
                    or calibration["config_digest"] != digest_jcs(config) or not calibration["ready"]):
                raise ValueError("calibration_binding")
            from scripts.dgx_m6_admit import verify_calibration
            if config.get("gateway_backend") == "ollama" and calibration_verifier is None:
                raise ValueError("mac_calibration_verifier_required")
            verifier = calibration_verifier or verify_calibration
            verifier(Path(admitted["calibration_ref"]), Path(calibration["campaign_ref"]))
            capacity = load(directory / "capacity-plan-1.json")
            if (capacity["digest"] != digest_jcs({k: v for k, v in capacity.items() if k != "digest"})
                    or capacity["digest"] != admitted["capacity_plan_digest"]):
                raise ValueError("capacity_plan_binding")
            budget = forecast(capacity["items"], calibration={**calibration,
                "evidence_digests": [calibration["digest"]]}, stages=admitted["stages"])
            if any(admitted.get(k) != v for k, v in budget.items()):
                raise ValueError("budget_forecast_recompute")
        budget_correction = None
        if admission_path.is_file() and admitted["stages"] != stage_bounds():
            original_budget = budget
            budget = forecast(capacity["items"], calibration={**calibration,
                "evidence_digests": [calibration["digest"]]}, stages=stage_bounds())
            budget_correction = {"reason":"auxiliary_multiturn_token_bounds_corrected",
                "original_admission_digest":admitted["digest"],
                "original_stage_bounds_digest":digest_jcs(admitted["stages"]),
                "reviewed_stage_bounds_digest":digest_jcs(stage_bounds()),
                "original_input_tokens":original_budget["input_tokens"],
                "reviewed_input_tokens":budget["input_tokens"],
                "original_output_tokens":original_budget["output_tokens"],
                "reviewed_output_tokens":budget["output_tokens"]}
        spending = {"admission": "pending", "reasons": ["actual_spending_snapshot_missing"]}
        spending_path = directory / "closed-development-spending.json"
        if manifest.get("admission_clock") and spending_path.is_file():
            ledger_path, clock, executions = execution_spending_data(root, profile)
            closed = verify_snapshot(load(spending_path), current_state=load(ledger_path),
                clock=clock, victim_seconds=VICTIM_BOUND, executions=executions)
            spending = {"admission": closed["admission"], "reasons": closed["reasons"],
                "snapshot_digest": closed["digest"], "actual_attempts": closed["ledger"]["victim_attempts"],
                "actual_retries": closed["ledger"]["retries"], "clock_digest": clock["digest"],
                "finished_at_unix_ms": closed["finished_at_unix_ms"]}
            if budget["admission"] == "ready":
                wall = remaining_capacity(closed["ledger"], started_at_unix_ms=clock["started_at_unix_ms"],
                    at_unix_ms=closed["finished_at_unix_ms"], planned_attempts=budget["reserved_attempts"],
                    auxiliary_seconds=600 + 120)
                spending.update({k: v for k, v in wall.items() if k not in ("admission", "reasons")})
                if wall["admission"] != "ready":
                    spending["admission"] = "rejected"
                    spending["reasons"] = [*spending["reasons"], *wall["reasons"]]
        verdict = "fail" if failures else "inconclusive" if missing or high or not scan_complete or budget["admission"] != "ready" or spending["admission"] != "ready" else "pass"
        report["subjects"][profile] = {"verdict": verdict, "subject_digest": compiled["subject_digest"],
            "generated_proposals": info["generated_proposals"], "applications_succeeded": info["applications_succeeded"],
            "evaluable_candidates": info["evaluable_candidates"], "required_cases": len(compiled["cases"]),
            "required_runs": len(candidate_pairs), "missing": missing, "known_failures": failures,
            "incomplete_attempts_retained": incomplete_attempts, "case_results": case_results,
            "unresolved_high": high, "scan_complete": scan_complete, "historical_bindings": len(bindings),
            "paired_to_submitted": paired, "paired_reference_is_cross_campaign": False,
            "submitted_verdict": "fail" if submitted_failures else "inconclusive" if
                submitted_missing else "pass",
            "submitted_missing": submitted_missing,
            "submitted_required_runs": len(submitted_compiled["cases"]) * 3,
            "submitted_executed_required_runs": submitted_executed_required_runs,
            "submitted_absent_items": submitted_absent_items,
            "paired_development_coverage_complete": not missing and not submitted_missing,
            "submitted_known_failures": submitted_failures,
            "submitted_incomplete_attempts_retained": submitted_incomplete,
            "submitted_case_results": submitted_cases,
            "model_responses": responses, "reasoning_tokens": reasoning_tokens,
            "budget": budget, "budget_bound_correction":budget_correction,
            "spending_audit": spending, "frozen": False}
        evidence_digest = digest_jcs(report["subjects"][profile])
        sealed = freeze(subject=compiled["subject_digest"], development_verdict=verdict,
            missing=missing, unresolved_high=high, budget=budget,
            proposal_attempts=info["generated_proposals"], applied_candidates=info["applications_succeeded"],
            evaluable_candidates=info["evaluable_candidates"], repair_rounds=info.get("repair_round", 1),
            evidence_digest=evidence_digest)
        report["subjects"][profile].update(frozen=sealed["status"] == "frozen", freeze=sealed)
        save(directory / "freeze.json", sealed)
    report["digest"] = digest_jcs(report)
    save(root / "m6-gate.json", report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--scan-index", required=True, type=Path)
    parser.add_argument("--runtime-source", type=Path, default=REPO)
    args = parser.parse_args()
    report = gate(args.output.resolve(), baseline=args.baseline.resolve(), scan_index=args.scan_index.resolve(),
        runtime_source=args.runtime_source.resolve())
    print(json.dumps({profile: {key: row.get(key) for key in
        ("verdict", "required_cases", "required_runs", "paired_to_submitted", "submitted_verdict", "frozen")}
        for profile, row in report["subjects"].items()}))


if __name__ == "__main__":
    main()
