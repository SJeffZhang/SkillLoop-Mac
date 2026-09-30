"""Verify the actual calibration and source binding before M6 work starts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.dgx_m5b_gate import _recompute_run
from scripts.dgx_m6_calibrate import probe_suite
from scripts.dgx_m6_repair import CONFIG, PROFILES, REPO, load, save, source_index
from skillloop.protocol import digest_bytes, digest_jcs
from skillloop.families.fixtures import load_example_skill
from skillloop.repair.budget import forecast
from skillloop.runtime.gateway import ExactDockerTokenizer, ExactLocalTokenizer


def verify_calibration(calibration_root: Path, campaign: Path, *, expected_config: dict | None = None,
                       tokenizer_path: str | None = None, runtime_profile_path: Path | None = None) -> dict:
    config = CONFIG if expected_config is None else expected_config
    native = config.get("gateway_backend") == "ollama"
    if native and (tokenizer_path is None or runtime_profile_path is None):
        raise ValueError("mac_calibration_requires_pinned_inputs")
    record = load(calibration_root / "calibration.json")
    campaign_manifest = load(campaign / "manifest.json")
    profiles = tuple(campaign_manifest["subjects"])
    if not profiles or not set(profiles).issubset(PROFILES):
        raise ValueError("calibration_profile_scope")
    if (record["digest"] != digest_jcs({k: v for k, v in record.items() if k != "digest"})
            or record["config_digest"] != digest_jcs(config) or not record["ready"]
            or record["campaign_manifest_digest"] != digest_jcs(campaign_manifest)
            or len(record["rows"]) != 2 * len(profiles)):
        raise ValueError("calibration_record_invalid")
    tokenizer = ExactLocalTokenizer(tokenizer_path) if native else ExactDockerTokenizer()
    runs, tasks = set(), set()
    expected_keys = {(p, p + suffix) for p in profiles for suffix in (".clean-a", ".secret-leak")}
    if {(r["profile"], r["case"]) for r in record["rows"]} != expected_keys:
        raise ValueError("calibration_matrix_incomplete")
    for row in record["rows"]:
        profile, case_id = row["profile"], row["case"]
        compiled, inputs, plan = probe_suite(profile, campaign / "candidate",
            campaign_id="m6-calibration-" + calibration_root.name + "-" + profile, runtime_config=config, runtime_profile_path=runtime_profile_path)
        directory = calibration_root / profile / case_id
        if row != load(directory / "measurement.json"):
            raise ValueError("calibration_measurement_changed")
        result = _recompute_run(directory / "result.json", profile=profile, case_id=case_id,
            repetition=0, attempt=0, case=compiled["cases"][case_id], compiled=compiled,
            suite=compiled["suite"], plan=plan, run_ids=runs, task_ids=tasks,
            tokenizer=tokenizer, expected_config=config, inputs_override=inputs,
            deployment_epoch=config.get("deployment_epoch", "m5-development-1"))
        if load(directory / "result.json").get("runner_source_digest") != digest_jcs(load(campaign / "manifest.json")["source_index"]):
            raise ValueError("calibration_execution_source_binding")
        actual_skill = load_example_skill(profile, root=campaign / "candidate").decode()
        for path in (directory / "evidence/contexts").iterdir():
            messages = load(path)
            if len(messages) < 2 or not messages[1].get("content", "").startswith(actual_skill + "\n\nTask input bindings: "):
                raise ValueError("calibration_candidate_context_binding")
        for path in (directory / "evidence").glob("*.jsonl"):
            for line in path.read_text().splitlines():
                event = json.loads(line)
                if event.get("type") == "model_response" and event["response"].get("usage", {}).get("reasoning_tokens") != 0:
                    raise ValueError("calibration_thinking_mode_evidence")
        if (result["digest"] != row["result_digest"] or not result["body"]["coverage_complete"]
                or result["body"]["utility_status"] != "pass" or result["body"]["security_violation"]):
            raise ValueError("calibration_outcome_invalid")
    for measurement in record["auxiliary_measurements"]:
        if measurement["elapsed_seconds"] >= measurement["bound_seconds"]:
            raise ValueError("calibration_auxiliary_bound")
    io_path = calibration_root / "durability-probe.bin"
    io = next(m for m in record["auxiliary_measurements"] if m["stage"] == "write_and_fsync")
    if io_path.stat().st_size != io["bytes"] or digest_bytes(io_path.read_bytes()) != io["digest"]:
        raise ValueError("calibration_durability_evidence")
    return record


def check_admission(campaign: Path, profile: str) -> dict:
    admission = load(campaign / profile / "budget-admission.json")
    if (admission["digest"] != digest_jcs({k: v for k, v in admission.items() if k != "digest"})
            or admission["admission"] != "ready" or admission["config_digest"] != digest_jcs(CONFIG)):
        raise ValueError("budget_not_admitted")
    capacity = load(campaign / profile / "capacity-plan-1.json")
    if (capacity["digest"] != digest_jcs({k: v for k, v in capacity.items() if k != "digest"})
            or capacity["digest"] != admission["capacity_plan_digest"]):
        raise ValueError("capacity_plan_changed")
    calibration = load(Path(admission["calibration_ref"]) / "calibration.json")
    if calibration["digest"] != admission["calibration_digest"]:
        raise ValueError("calibration_admission_binding")
    rebuilt = forecast(capacity["items"], calibration={**calibration,
        "evidence_digests": [calibration["digest"]]}, stages=admission["stages"])
    if any(admission.get(k) != v for k, v in rebuilt.items()):
        raise ValueError("budget_recompute_mismatch")
    manifest = load(campaign / "manifest.json")
    for relative, digest in manifest["source_index"].items():
        if digest_bytes((REPO / relative).read_bytes()) != digest:
            raise ValueError("runtime_source_changed:" + relative)
    return admission


def admit(campaign: Path, calibration_root: Path, *, profile: str | None = None):
    manifest = load(campaign / "manifest.json")
    if manifest["source_index"] != source_index():
        raise ValueError("runtime_source_index")
    calibration_data = load(calibration_root / "calibration.json")
    calibration = verify_calibration(calibration_root, Path(calibration_data["campaign_ref"]))
    for current in (profile,) if profile else manifest["subjects"]:
        capacity = load(campaign / current / "capacity-plan-1.json")
        pending = load(campaign / current / "budget-pending.json")
        result = forecast(capacity["items"], calibration={**calibration,
            "evidence_digests": [calibration["digest"]]}, stages=pending["stages"])
        record = {**result, "calibration_ref": str(calibration_root), "calibration_digest": calibration["digest"],
            "capacity_plan_digest": capacity["digest"], "config_digest": digest_jcs(CONFIG),
            "stages": pending["stages"], "production_ready": False, "independently_verified": True}
        record["digest"] = digest_jcs(record)
        save(campaign / current / "budget-admission.json", record)
        print(current, record["admission"], record["reserved_attempts"], flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--profile", choices=PROFILES)
    args = parser.parse_args()
    admit(args.campaign.resolve(), args.calibration.resolve(), profile=args.profile)


if __name__ == "__main__":
    main()
