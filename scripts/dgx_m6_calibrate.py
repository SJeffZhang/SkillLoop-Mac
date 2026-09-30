"""Measure the supported non-thinking workload before admitting M6 execution.

Probes use separate identities and never supply candidate regression results.
Admission combines observed boundary probes with enforced termination limits;
it is scoped to this deployment and config, not an unbounded throughput claim.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.dgx_m5_development import run_one
from scripts.dgx_m5b_gate import _recompute_run
from scripts.dgx_m6_repair import CONFIG, PROFILES, REPO, VICTIM_BOUND, SCANNER_BOUND, execution_plan, load, save, source_index
from scripts.spec_v22_core import validate_suite
from skillloop.discovery.mutation import make_dev_mutation
from skillloop.discovery.suite import compile_dev_suite
from skillloop.families.builders import build_artifact
from skillloop.families.fixtures import load_clean_fixture
from skillloop.families.oracle import validate_artifact
from skillloop.families.registry import FamilyRegistry
from skillloop.protocol import digest_bytes, digest_jcs, make_envelope
from skillloop.repair.budget import forecast
from skillloop.runtime.gateway import ExactDockerTokenizer


def maximum_inputs(profile_id: str) -> dict[str, bytes]:
    profile = FamilyRegistry().profile(profile_id)
    source_notes = load_clean_fixture(profile_id, "a")[0]["notes"]
    notes = source_notes + (b"N " * 512)[:1024 - len(source_notes)]
    if profile["family_id"] == "table-report":
        mapping = profile["mapping"]
        directory = ",".join(mapping["directory_header"]) + "\n" + "".join(
            f"a{i:031d},{'A' * 64}\n" for i in range(20))
        records = ",".join(mapping["records_header"]) + "\n" + "".join(
            f"r{i:031d},a{i:031d},1000000000,{mapping['included_state']}\n" for i in range(20))
        inputs = {"directory": directory.encode(), "records": records.encode(), "notes": notes}
    else:
        inputs = {"document": (b"# " + b"X" * 38 + b"\n") * 96 +
            (b"# " + b"X" * 37 + b"\n") * 4, "notes": notes}
    expected = build_artifact(profile_id, inputs)
    validate_artifact(profile_id, inputs, expected)
    return inputs


def probe_suite(profile: str, candidate_root: Path, *, campaign_id: str | None = None, runtime_config: dict | None = None, runtime_profile_path: Path | None = None) -> tuple[dict, dict[str, bytes], dict]:
    compiled = compile_dev_suite(profile, skill_root=candidate_root)
    inputs = maximum_inputs(profile)
    mutation = make_dev_mutation(profile_id=profile, source_bytes=inputs["notes"],
        payload_bytes=b" P" * 1024, mode="append")
    fixture_digest = digest_jcs({slot: digest_bytes(raw) for slot, raw in inputs.items()})
    projection = digest_jcs({"profile_id": profile,
        "inputs": {slot: digest_bytes(raw) for slot, raw in inputs.items() if slot != "notes"}})
    clean = {}
    for cid, case in compiled["cases"].items():
        if case["body"]["case_kind"] == "clean":
            clean[cid] = make_envelope("CaseTemplate", {**case["body"],
                "fixture_digest": fixture_digest, "business_projection_digest": projection})
    for cid, case in list(compiled["cases"].items()):
        if cid in clean:
            compiled["cases"][cid] = clean[cid]
        else:
            compiled["mutations"][cid] = mutation
            compiled["cases"][cid] = make_envelope("CaseTemplate", {**case["body"],
                "fixture_digest": fixture_digest, "business_projection_digest": projection,
                "mutation_digest": mutation["digest"], "clean_pair_digest": clean[profile + ".clean-a"]["digest"]})
    cases = list(compiled["cases"].values())
    entries = [{"case_digest": c["digest"], **{k: c["body"][k] for k in
        ("case_kind", "split", "repetitions", "objective_ids", "clean_pair_digest",
         "business_projection_digest", "fixture_digest", "mutation_digest")}} for c in cases]
    compiled["suite"] = make_envelope("SuiteManifest", {**compiled["suite"]["body"],
        "suite_id": "m6.calibration." + profile, "cases": entries,
        "base_case_digests": [c["digest"] for c in cases]})
    validate_suite(compiled["suite"], cases, compiled["objectives"])
    compiled["subject_digest"] = compiled["skill_digest"]
    plan = execution_plan(compiled, campaign=campaign_id or "m6-calibration-" + profile, runtime_config=runtime_config, runtime_profile_path=runtime_profile_path)
    selected = {profile + ".clean-a", profile + ".secret-leak"}
    body = copy.deepcopy(plan["body"])
    for row in body["items"]:
        if row["repetition_index"] != 0 or not any(row["item_id"] == cid + ".0" for cid in selected):
            row.update(requirement="not_applicable", reason_code="separate_capacity_probe_not_regression")
    body["reserved_rollouts"] = 2
    body["reserved_execution_ms"] = 2 * VICTIM_BOUND * 1000
    return compiled, inputs, make_envelope("ExecutionPlan", body)


def worker(args):
    campaign_id = "m6-calibration-" + args.output.name + "-" + args.profile
    compiled, inputs, plan = probe_suite(args.profile, args.campaign / "candidate", campaign_id=campaign_id)
    run_one(args.case, 0, args.output / args.profile / args.case, compiled_suite=compiled,
        skill_root=args.campaign / "candidate", campaign_id=campaign_id,
        runtime_config=CONFIG, execution_plan=plan, inputs_override=inputs)
    result_path = args.output / args.profile / args.case / "result.json"
    data = load(result_path)
    data["runner_source_digest"] = digest_jcs(source_index())
    save(result_path, data)


def calibrate(args):
    if args.output.exists():
        raise FileExistsError("calibration_exists")
    args.output.mkdir(mode=0o700)
    rows, reasons = [], []
    tokenizer = ExactDockerTokenizer()
    profiles = tuple(load(args.campaign / "manifest.json")["subjects"])
    if not profiles or not set(profiles).issubset(PROFILES):
        raise ValueError("calibration_profile_scope")
    for profile in profiles:
        compiled, inputs, plan = probe_suite(profile, args.campaign / "candidate",
            campaign_id="m6-calibration-" + args.output.name + "-" + profile)
        save(args.output / profile / "compiled.json", compiled)
        save(args.output / profile / "plan.json", plan)
        for case_id in (profile + ".clean-a", profile + ".secret-leak"):
            started = time.monotonic()
            command = [sys.executable, str(Path(__file__).resolve()), "worker",
                "--campaign", str(args.campaign), "--output", str(args.output),
                "--profile", profile, "--case", case_id]
            try:
                result = subprocess.run(command, capture_output=True, timeout=VICTIM_BOUND)
                exit_code, stderr = result.returncode, result.stderr
            except subprocess.TimeoutExpired as error:
                exit_code, stderr = 124, error.stderr or b""
            directory = args.output / profile / case_id
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            (directory / "worker-stderr.log").write_bytes(stderr)
            os.chmod(directory / "worker-stderr.log", 0o600)
            elapsed = time.monotonic() - started
            row = {"profile": profile, "case": case_id, "elapsed_seconds": elapsed,
                "exit_code": exit_code, "input_sizes": {s: len(v) for s, v in inputs.items()},
                "max_payload_bytes": 2048, "max_rendered_bytes": 3072, "worker_bound_seconds": VICTIM_BOUND}
            path = directory / "result.json"
            if path.exists():
                rebuilt = _recompute_run(path, profile=profile, case_id=case_id, repetition=0,
                    attempt=0, case=compiled["cases"][case_id], compiled=compiled,
                    suite=compiled["suite"], plan=plan, run_ids=set(), task_ids=set(),
                    tokenizer=tokenizer, expected_config=CONFIG, inputs_override=inputs)
                data = load(path)
                row.update(result_digest=rebuilt["digest"], complete=rebuilt["body"]["coverage_complete"],
                    utility=rebuilt["body"]["utility_status"], security_violation=rebuilt["body"]["security_violation"])
                events = [json.loads(line) for trace in (directory / "evidence").glob("*.jsonl") for line in trace.read_text().splitlines()]
                responses = [e for e in events if e.get("type") == "model_response"]
                row.update(model_responses=len(responses), prompt_tokens_max=max(
                    (e["response"]["usage"]["prompt_tokens"] for e in responses), default=0),
                    output_tokens=sum(e["response"]["usage"]["completion_tokens"] for e in responses),
                    reasoning_tokens=sum(e["response"]["usage"].get("reasoning_tokens", -1) for e in responses),
                    evidence_bytes=sum(p.stat().st_size for p in directory.rglob("*") if p.is_file()),
                    bindings_match=data["task_binding"]["body"]["subject_digest"] == compiled["subject_digest"])
            else:
                row.update(complete=False, utility="unknown", error="result_missing")
            if not (exit_code == 0 and row["complete"] and row["utility"] == "pass"
                    and not row.get("security_violation", True) and row.get("reasoning_tokens") == 0):
                reasons.append(profile + ":" + case_id + ":boundary_probe_incomplete")
            rows.append(row)
            save(directory / "measurement.json", row)
            print(json.dumps({k: row.get(k) for k in ("profile", "case", "elapsed_seconds", "complete", "utility", "reasoning_tokens")}), flush=True)
    auxiliary = []
    from skillloop.families.fixtures import make_dev_fixture
    for profile in profiles:
        started = time.monotonic()
        for index in range(4):
            inputs, expected, canary = make_dev_fixture(profile, bytes([index + 1]) * 32)
            validate_artifact(profile, inputs, expected)
            if canary in expected or any(canary in value for slot, value in inputs.items() if slot != "notes"):
                raise ValueError("calibration_canary_collision")
        auxiliary.append({"stage": "factory_calibration_only", "profile": profile,
            "cases": 4, "elapsed_seconds": time.monotonic() - started, "bound_seconds": 120,
            "protected_epoch_created": False})
    started = time.monotonic()
    io_path = args.output / "durability-probe.bin"
    with io_path.open("xb") as stream:
        os.chmod(io_path, 0o600)
        for _ in range(4):
            stream.write(bytes(16 * 1024**2))
        stream.flush()
        os.fsync(stream.fileno())
    auxiliary.append({"stage": "write_and_fsync", "bytes": io_path.stat().st_size,
        "elapsed_seconds": time.monotonic() - started, "bound_seconds": 150,
        "digest": digest_bytes(io_path.read_bytes())})
    scanner_evidence = []
    for profile in profiles:
        invocation = load(args.campaign / profile / "scan/invocation.json")
        scanner_evidence.append({"profile": profile, "invocation_digest": digest_jcs(invocation),
            "elapsed_seconds": invocation["elapsed_seconds"], "model_calls": invocation["qwen_calls"]})
        if invocation["elapsed_seconds"] > SCANNER_BOUND or not 0 < invocation["qwen_calls"] <= 4:
            reasons.append(profile + ":scanner_bound_not_supported")
        for item in invocation.get("model_usage", []):
            usage = item["usage"]
            if usage.get("reasoning_tokens") != 0 or usage.get("prompt_tokens", 14337) > 14336 or usage.get("completion_tokens", 2049) > 2048:
                reasons.append(profile + ":scanner_model_boundary")
    if any(item["elapsed_seconds"] >= item["bound_seconds"] for item in auxiliary):
        reasons.append("auxiliary_boundary_not_supported")
    record = {"kind": "M6CapacityCalibration", "config_digest": digest_jcs(CONFIG),
        "campaign_ref": str(args.campaign),
        "campaign_manifest_digest": digest_jcs(load(args.campaign / "manifest.json")),
        "rows": rows, "scanner_evidence": scanner_evidence, "auxiliary_measurements": auxiliary, "ready": not reasons,
        "reasons": reasons, "victim_seconds": VICTIM_BOUND, "scope": "bounded_fixed_deployment_nonthinking",
        "production_ready": False, "enforced_limits": {"worker_seconds": VICTIM_BOUND,
            "agent_seconds": CONFIG["agent_deadline_seconds"], "scanner_seconds": SCANNER_BOUND,
            "max_input_tokens_per_turn": 14336, "max_output_tokens_per_turn": 2048,
            "max_turns": 16, "trace_bytes": 4194304}}
    record["digest"] = digest_jcs(record)
    save(args.output / "calibration.json", record)
    from scripts.spec_v22_operations import expand_plan
    representatives = []
    stages = load(args.campaign / profiles[0] / "budget-pending.json")["stages"]
    for name, parameters in (("no_finding", {}), ("one_finding", {"findings": 1}),
        ("two_rounds_active", {"abandoned": 1, "active": 1}),
        ("near_capacity", {"history": 11}), ("history_over_capacity", {"history": 13})):
        items = [{"subject": e["subject"], "case": e["case"], "repetition": e["repetition"],
            "phase": e["phase"], "role": e["subject"], "requirement": "required"} for e in expand_plan(**parameters)]
        representatives.append({"name": name, "parameters": parameters,
            "forecast": forecast(items, calibration={**record, "evidence_digests": [record["digest"]]}, stages=stages)})
    save(args.output / "representative-plans.json", representatives)
    for profile in profiles:
        capacity = load(args.campaign / profile / "capacity-plan-1.json")
        pending = load(args.campaign / profile / "budget-pending.json")
        budget = forecast(capacity["items"], calibration={**record, "evidence_digests": [record["digest"]]}, stages=pending["stages"])
        admission = {**budget, "calibration_digest": record["digest"], "calibration_ref": str(args.output),
            "capacity_plan_digest": capacity["digest"], "config_digest": digest_jcs(CONFIG),
            "stages": pending["stages"], "production_ready": False}
        admission["digest"] = digest_jcs(admission)
        save(args.campaign / profile / "budget-admission.json", admission)
        print(json.dumps({"profile": profile, "admission": budget["admission"], "reserved_attempts": budget["reserved_attempts"], "reasons": budget["reasons"]}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("calibrate", "worker"))
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--case")
    args = parser.parse_args()
    args.output, args.campaign = args.output.resolve(), args.campaign.resolve()
    {"worker": worker, "calibrate": calibrate}[args.stage](args)


if __name__ == "__main__":
    main()
