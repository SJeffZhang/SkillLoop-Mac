"""Independently recompute M5b findings coverage and per-run trusted evidence."""

from __future__ import annotations

import json
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.spec_v22_core import evaluate_run as reference_evaluate_run
from scripts.spec_v22_core import reduce_case, validate_plan, validate_suite, validate_record
from skillloop.discovery.evaluator import evaluate_run
from skillloop.discovery.finding_suite import compile_finding_suite
from skillloop.discovery.finding_targets import map_redteam_finding
from skillloop.discovery.llm_attack import GENERATOR_CONFIG
from skillloop.discovery.mutation import compile_mutation
from skillloop.discovery.scanner import reduce_scan
from skillloop.discovery.suite import m5b_config, make_dev_plan
from skillloop.families.fixtures import load_clean_fixture, load_example_skill
from skillloop.protocol import digest_bytes, digest_jcs, validate_envelope
from skillloop.proxy.store import ProxyStore
from skillloop.runtime.gateway import ExactDockerTokenizer

REPO = Path(__file__).resolve().parents[1]
REDTEAM = REPO / "specs/v2.2/families/redteam"
PROFILES = ("refunds_total", "markdown_index", "orders_total")
SOURCE_FILES = (
    "scripts/dgx_m5_development.py", "scripts/dgx_m5b_scan.py",
    "scripts/dgx_m5b_attack.py", "scripts/dgx_m5b_gate.py", "scripts/spec_v22_core.py",
    "deploy/scanner/qwen_relay.py", "deploy/scanner/qwen_scan_guest.py",
    "deploy/scanner/qwen-model-registry.yaml", "deploy/scanner/Dockerfile.offline",
    "skillloop/discovery/evaluator.py", "skillloop/discovery/finding_suite.py",
    "skillloop/discovery/finding_targets.py", "skillloop/discovery/llm_attack.py",
    "skillloop/discovery/mutation.py", "skillloop/discovery/planning.py",
    "skillloop/discovery/scanner.py", "skillloop/discovery/suite.py",
    "skillloop/protocol.py", "skillloop/proxy/server.py", "skillloop/proxy/store.py",
    "skillloop/runtime/adapter.py", "skillloop/runtime/client.py",
    "skillloop/runtime/gateway.py",
)

try:
    from skillloop.discovery.finding_suite import compile_finding_campaign
except ImportError:
    compile_finding_campaign = None


def run_directory(output: Path, profile: str, case_id: str,
                  repetition: int, attempt: int) -> Path:
    tag = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:10]
    path = output / profile / "runs" / f"r{tag}-{repetition}{attempt}"
    if len(str(path / "sockets" / "proxy.sock").encode("utf-8")) > 107:
        raise ValueError("socket_path_too_long")
    return path


def summarize_case(case: dict, attempts: list[dict]) -> dict:
    reduced = reduce_case(attempts, case) if attempts else None
    body = reduced["body"] if reduced else None
    outcomes = sorted({outcome["objective_id"] for item in attempts
        for outcome in item["body"]["objective_outcomes"] if outcome["effect"] == "pass"})
    return {"case_id": case["body"]["case_id"], "kind": case["body"]["case_kind"],
        "complete_repetitions": body["completed_repetitions"] if body else 0,
        "attempts": len(attempts),
        "utility_status": body["utility_status"] if body else "unknown",
        "security_status": body["security_status"] if body else "unknown",
        "sticky_fail": any(item["body"]["utility_status"] == "fail" or
                            item["body"]["security_violation"] for item in attempts),
        "observed_effect_objectives": outcomes}


def _compile_subject(profile: str, scan: dict, root: Path, tokenizer: ExactDockerTokenizer) -> tuple[dict, dict, dict, set[str], str]:
    subject = load_example_skill(profile, root=REDTEAM)
    if scan.get("status") != "ready_for_attack" or scan.get("subject_digest") != digest_bytes(subject):
        raise ValueError("scan_subject_binding:" + profile)
    mapped = []
    for raw in scan.get("findings", []):
        candidate = map_redteam_finding(profile, raw, subject)
        if candidate is not None:
            mapped.append((raw, candidate))
    mapped.sort(key=lambda item: item[1]["digest"])
    if [item[1] for item in mapped] != sorted(scan.get("mapped_findings", []),
                                                key=lambda item: item["digest"]):
        raise ValueError("mapped_finding_recompute:" + profile)
    legacy_payload = root / profile / "llm-payload.txt"
    legacy_evidence = root / profile / "generator-evidence.json"
    inputs = []
    if not legacy_payload.is_file() and not legacy_evidence.is_file():
        for raw, finding in mapped:
            finding_dir = root / profile / "findings" / finding["digest"][7:23]
            payload_path = finding_dir / "llm-payload.txt"
            evidence_path = finding_dir / "generator-evidence.json"
            if not payload_path.is_file() or not evidence_path.is_file():
                raise ValueError("finding_payload_evidence_missing:" + finding["digest"])
            payload = payload_path.read_bytes()
            generator = json.loads(evidence_path.read_text())
            if (generator.get("finding_digest") != finding["digest"] or
                generator.get("payload_digest") != digest_bytes(payload) or
                generator.get("generator_config_digest") != digest_jcs(GENERATOR_CONFIG)):
                raise ValueError("finding_generator_binding:" + finding["digest"])
            inputs.append({"finding": finding, "llm_payload": payload,
                           "generator_config_digest": generator["generator_config_digest"]})
    if legacy_payload.is_file() or legacy_evidence.is_file():
        if not legacy_payload.is_file() or not legacy_evidence.is_file():
            raise ValueError("partial_legacy_generator_evidence")
        generator = json.loads(legacy_evidence.read_text())
        chosen = next((item for item in mapped
                       if item[1]["digest"] == generator.get("finding_digest")), None)
        if chosen is None:
            raise ValueError("legacy_finding_not_in_scan")
        payload = legacy_payload.read_bytes()
        if (generator.get("payload_digest") != digest_bytes(payload) or
            generator.get("generator_config_digest") != digest_jcs(GENERATOR_CONFIG)):
            raise ValueError("legacy_generator_binding")
        compiled, plans = compile_finding_suite(profile, chosen[1],
            count_tokens=tokenizer.count_text, skill_root=REDTEAM,
            campaign_id="m5b-qwen-discovery-" + profile,
            llm_payload=payload,
            generator_config_digest=generator["generator_config_digest"])
        covered = {chosen[1]["digest"]}
        mode = "legacy_single_finding"
    else:
        if compile_finding_campaign is None:
            raise ValueError("all_finding_compiler_unavailable")
        compiled, plans = compile_finding_campaign(profile, inputs,
            count_tokens=tokenizer.count_text, skill_root=REDTEAM,
            campaign_id="m5b-qwen-discovery-" + profile)
        covered = {item["finding"]["digest"] for item in inputs}
        mode = "all_mapped_findings"
    stored_suite = json.loads((root / profile / "suite.json").read_text())
    stored_plans = json.loads((root / profile / "attack-plans.json").read_text())
    if stored_suite != compiled["suite"] or stored_plans != plans:
        raise ValueError("compiled_suite_or_plan_mismatch:" + profile)
    raw_digests = {raw["digest"] for raw, _ in mapped}
    mapped_raw_digests = {raw["digest"] for raw in scan.get("findings", [])
                          if map_redteam_finding(profile, raw, subject) is not None}
    if raw_digests != mapped_raw_digests:
        raise ValueError("finding_coverage_set_mismatch:" + profile)
    return (compiled, plans,
            {finding["digest"]: raw["digest"] for raw, finding in mapped},
            covered, mode)


def _recompute_run(path: Path, *, profile: str, case_id: str, repetition: int,
                    attempt: int, case: dict, compiled: dict, suite: dict, plan: dict,
                    run_ids: set[str], task_ids: set[str], tokenizer: ExactDockerTokenizer,
                    expected_config: dict | None = None,
                    inputs_override: dict[str, bytes] | None = None,
                    deployment_epoch: str = "m5-development-1", source_admission: dict | None = None) -> dict:
    data = json.loads(path.read_text())
    result = data["result"]
    validate_record(result)
    for key in ("case", "evidence_index", "runtime_evidence_index", "observation",
                "run_request", "task_binding"):
        validate_envelope(data[key])
    request, binding = data["run_request"]["body"], data["task_binding"]["body"]
    observation = data["observation"]["body"]
    expected_config = expected_config or m5b_config()
    expected_plan = (plan if "execution_plan" in data else make_dev_plan(compiled,
        campaign_id="m5b-qwen-discovery-" + profile, config=m5b_config()))
    if "execution_plan" in data and data["execution_plan"] != plan:
        raise ValueError("execution_plan_binding")
    validate_plan(expected_plan, suite)
    expected_subject = compiled.get("subject_digest", compiled["skill_digest"])
    expected_case = compiled["cases"][case_id]
    expected_mutation = compiled["mutations"].get(case_id)
    if (data["case"] != expected_case or data["config"] != expected_config or
        data["suite_digest"] != suite["digest"] or data["plan_digest"] != expected_plan["digest"] or
        request["suite_digest"] != suite["digest"] or request["plan_digest"] != expected_plan["digest"] or
        request["config_digest"] != expected_plan["body"]["config_digest"] or
        request["case_digest"] != expected_case["digest"] or
        request["repetition_index"] != repetition or
        request["subject_digest"] != expected_subject or
        binding["subject_digest"] != expected_subject or
        observation["case_digest"] != expected_case["digest"] or
        observation["repetition_index"] != repetition or observation["attempt_index"] != attempt or
        observation["subject_digest"] != expected_subject or
        observation["run_id"] != binding["run_id"] or
        observation["task_instance_id"] != binding["task_instance_id"] or
        data["mutation"] != expected_mutation):
        raise ValueError("execution_identity_mismatch:" + case_id)
    run_folder = path.parent
    traces = list((run_folder / "evidence").glob("*.jsonl"))
    if len(traces) != 1:
        raise ValueError("trace_count:" + case_id)
    if source_admission is not None:
        # Rebuild approved selection from the frozen entry, then compare the
        # actual authority transaction and every model context. Raw result labels
        # cannot stand in for package-source or registered-read evidence.
        import base64,sqlite3
        from contextlib import closing
        from skillloop.loader import ApprovedPackageLoader, validate_source_admission
        from skillloop.families.registry import FamilyRegistry
        from skillloop.protocol import decode_json
        admission=source_admission
        validate_source_admission(admission, expected_config, expected_subject)
        package={name:base64.b64decode(raw,validate=True) for name,raw in admission['package_files'].items()}
        loader=ApprovedPackageLoader(approved_sources=admission['approved_sources'],
                                     reference_resource_ids=admission['reference_resource_ids'],
                                     approved_subjects=admission.get('approved_subjects'))
        selected=loader.select(admission['source_snapshot'],package,admission['manifest'],profile_id=profile,
                              family_id=FamilyRegistry().profile(profile)['family_id'])
        selected.check_binding(data['task_binding'])
        if selected.subject_digest!=expected_subject or digest_bytes(package['SKILL.md'])!=compiled['skill_digest']:
            raise ValueError('imported_recompute_subject')
        expected_admission={'source_snapshot':admission['source_snapshot'],'manifest':admission['manifest'],
            'source_snapshot_digest':selected.source_snapshot_digest,'manifest_digest':selected.manifest_digest,
            'subject_digest':selected.subject_digest,'profile_id':profile,
            'selected_resources':[{'path':name,'resource_id':rid,'bytes_digest':digest_bytes(raw)}
                                  for name,rid,raw in selected.files],
            'scope':'controller_approved_source_not_formal_qualification'}
        if admission.get('approved_subjects'):
            expected_admission['candidate_bundle']=admission['approved_subjects'][selected.source_snapshot_digest]
        with closing(sqlite3.connect((run_folder/'authority.db').absolute().as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
            row=db.execute('SELECT source_snapshot_digest,manifest_digest,admission_json FROM imported_admissions WHERE task_instance_id=?',
                           (binding['task_instance_id'],)).fetchone()
            if row is None or row[:2]!=(selected.source_snapshot_digest,selected.manifest_digest) or decode_json(row[2])!=expected_admission:
                raise ValueError('imported_recompute_authority_admission')
            for name,rid,raw in selected.files:
                stored=db.execute('SELECT bytes_digest,content FROM resources WHERE task_instance_id=? AND resource_id=?',
                                  (binding['task_instance_id'],rid)).fetchone()
                if stored!=(digest_bytes(raw),raw):raise ValueError('imported_recompute_authority_bytes')
        model_events=[json.loads(line) for line in traces[0].read_bytes().splitlines() if line]
        model_events=[event for event in model_events if event.get('type')=='model_response']
        if result['body']['coverage_complete'] and not model_events:raise ValueError('imported_recompute_missing_model_context')
        references=[{'role':'user','content':'Approved reference material: '+
                     json.dumps({'resource_id':rid,'content_utf8':raw.decode('utf-8')},ensure_ascii=False)}
                    for name,rid,raw in sorted(selected.files,key=lambda item:item[1]) if name!='SKILL.md']
        for event in model_events:
            context_raw=(traces[0].parent/'contexts'/event['context_digest'][7:]).read_bytes()
            if digest_bytes(context_raw)!=event['context_digest']:raise ValueError('imported_recompute_context_digest')
            context=decode_json(context_raw)
            if (len(context)<2 or context[1].get('role')!='user' or
                    not context[1].get('content','').startswith(package['SKILL.md'].decode('utf-8')+'\n\nTask input bindings: ') or
                    any(reference not in context for reference in references)):
                raise ValueError('imported_recompute_full_model_materials')
    suffix = "b" if case_id.endswith("clean-b") else "a"
    inputs, expected = load_clean_fixture(profile, suffix)
    if inputs_override is not None:
        from skillloop.families.builders import build_artifact
        from skillloop.families.oracle import validate_artifact
        inputs = dict(inputs_override)
        expected = build_artifact(profile, inputs)
        validate_artifact(profile, inputs, expected)
    world = digest_jcs({"profile_id": profile,
        "inputs": {slot: digest_bytes(value) for slot, value in inputs.items()},
        "expected_digest": digest_bytes(expected)})
    if request["initial_world_digest"] != world:
        raise ValueError("initial_world_mismatch:" + case_id)
    expected_rendered_digest = None
    if expected_mutation is not None:
        rendered = compile_mutation(expected_mutation, source_bytes=inputs["notes"],
            profile_id=profile, count_tokens=tokenizer.count_text)
        expected_rendered_digest = rendered.rendered_digest
    if data.get("rendered_digest") != expected_rendered_digest:
        raise ValueError("rendered_payload_binding:" + case_id)
    adapter_result = {"observation": data["observation"],
        "trace_path": str(traces[0]), "evidence_index": data["runtime_evidence_index"],
        "incomplete_reasons": data["runtime_incomplete_reasons"]}
    store = ProxyStore(run_folder / "authority.db", deployment_epoch=deployment_epoch)
    rebuilt, events, summary, evidence = evaluate_run(case=expected_case,
        objectives=compiled["objectives"], adapter_result=adapter_result, store=store,
        expected=expected, notes=inputs["notes"], mutation_spec=expected_mutation)
    if (rebuilt != result or events != data["trusted_events"] or
        summary != data["summary"] or evidence != data["evidence_index"]):
        raise ValueError("trusted_evidence_recompute_mismatch:" + case_id)
    reference = reference_evaluate_run(data["observation"], compiled["objectives"], events, evidence)
    for field in ("coverage_complete", "utility_status", "security_violation", "objective_outcomes"):
        if reference["body"][field] != rebuilt["body"][field]:
            raise ValueError("reference_semantics_mismatch:" + case_id + ":" + field)
    body = result["body"]
    if body["attempt_index"] != attempt:
        raise ValueError("result_attempt_index_mismatch:" + case_id)
    if body["evidence_index_digest"] != evidence["digest"]:
        raise ValueError("evidence_index_binding:" + case_id)
    run_id, task_id = body["run_id"], body["task_instance_id"]
    if run_id in run_ids or task_id in task_ids:
        raise ValueError("duplicate_run_or_task_identity")
    run_ids.add(run_id)
    task_ids.add(task_id)
    return result


def gate(scan_index_path: Path, root: Path) -> dict:
    scan_bytes = scan_index_path.read_bytes()
    scans = json.loads(scan_bytes)
    if scans.get("status") != "ready_for_attack":
        raise ValueError("scanner_campaign_incomplete")
    if (root / "scan-index-digest.txt").read_text().strip() != digest_bytes(scan_bytes):
        raise ValueError("scan_index_binding_mismatch")
    summary_path = root / "development-summary.json"
    campaign_summary_missing = not summary_path.is_file()
    saved = (json.loads(summary_path.read_text()) if not campaign_summary_missing
             else {"runtime_config": m5b_config(), "subjects": {}})
    if saved.get("runtime_config") != m5b_config():
        raise ValueError("diagnostic_config_mismatch")
    recorded_sources = saved.get("source_index", {})
    if not recorded_sources:
        source_binding_missing = True
    else:
        source_binding_missing = False
        if (set(recorded_sources) != set(SOURCE_FILES) or
            saved.get("source_index_digest") != digest_jcs(recorded_sources)):
            raise ValueError("source_index_binding_missing_or_invalid")
        for relative, expected_digest in recorded_sources.items():
            path = (REPO / relative).resolve()
            if REPO not in path.parents or not path.is_file() or digest_bytes(path.read_bytes()) != expected_digest:
                raise ValueError("source_index_mismatch:" + relative)
    tokenizer = ExactDockerTokenizer()
    missing, incomplete, known_failures, case_results = [], [], [], []
    if campaign_summary_missing:
        incomplete.append("campaign_summary_not_finalized")
    if source_binding_missing:
        incomplete.append("source_index_missing_from_campaign")
    run_ids, task_ids = set(), set()
    scanner_findings = {}
    for profile in PROFILES:
        scan = scans["subjects"][profile]
        raw_scan_path = scan_index_path.parent / profile / "report.json"
        if not raw_scan_path.is_file():
            raise ValueError("raw_scanner_report_missing:" + profile)
        rebuilt_scan = reduce_scan(profile, raw_scan_path.read_bytes(), scan["cli_exit_code"],
            subject_digest=scan["subject_digest"], require_llm=True, allow_risk_exit=True)
        if (scan.get("scanner_report"), scan.get("findings"), scan.get("dispositions")) != rebuilt_scan:
            raise ValueError("scanner_report_reduction_mismatch:" + profile)
        if scan.get("qwen_chat_requests", 0) < 1:
            raise ValueError("qwen_semantic_call_missing:" + profile)
        compiled, plans, finding_binding, covered_findings, coverage_mode = _compile_subject(
            profile, scan, root, tokenizer)
        suite = compiled["suite"]
        validate_suite(suite, list(compiled["cases"].values()), compiled["objectives"])
        plan = make_dev_plan(compiled,
            campaign_id="m5b-qwen-discovery-" + profile, config=m5b_config())
        validate_plan(plan, suite)
        source = saved.get("subjects", {}).get(profile)
        if source is None:
            profile_summary_path = root / profile / "development-summary.json"
            source = json.loads(profile_summary_path.read_text()) if profile_summary_path.is_file() else {}
        if source.get("subject_digest") not in (None, compiled["skill_digest"]):
            incomplete.append(profile + ":subject_binding")
        if source.get("case_count") not in (None, len(compiled["cases"])):
            incomplete.append(profile + ":case_count")
        if not source:
            incomplete.append(profile + ":subject_summary_not_finalized")
        raw_by_digest = {item["digest"]: item for item in scan.get("findings", [])}
        uncovered_high = []
        for mapped_digest, raw_digest in finding_binding.items():
            raw = raw_by_digest.get(raw_digest, {})
            if (mapped_digest not in covered_findings and
                str(raw.get("body", {}).get("severity", "")).lower()
                in {"critical", "high", "p0", "p1"}):
                uncovered_high.append(raw_digest)
        unmapped_high = [item["digest"] for item in scan.get("findings", [])
            if map_redteam_finding(profile, item,
                load_example_skill(profile, root=REDTEAM)) is None and
            str(item.get("body", {}).get("severity", "")).lower()
            in {"critical", "high", "p0", "p1"}]
        if uncovered_high or unmapped_high:
            incomplete.append(profile + ":high_risk_finding_coverage")
        planned_cases = []
        for case_id, case in compiled["cases"].items():
            attempt_results = []
            complete_results = []
            for repetition in range(case["body"]["repetitions"]):
                for attempt in (0, 1):
                    run_path = run_directory(root, profile, case_id, repetition, attempt)
                    result_path = run_path / "result.json"
                    if run_path.exists() and not result_path.is_file():
                        incomplete.append(f"{profile}:{case_id}:{repetition}:{attempt}:result_missing")
                    if result_path.is_file():
                        try:
                            result = _recompute_run(result_path, profile=profile, case_id=case_id,
                                repetition=repetition, attempt=attempt, case=case,
                                compiled=compiled, suite=suite, plan=plan,
                                run_ids=run_ids, task_ids=task_ids, tokenizer=tokenizer)
                            attempt_results.append(result)
                            if result["body"]["coverage_complete"]:
                                complete_results.append(result)
                            if result["body"]["security_violation"] or result["body"]["utility_status"] == "fail":
                                known_failures.append(f"{profile}:{case_id}:{repetition}:{attempt}")
                        except (OSError, KeyError, TypeError, ValueError) as error:
                            incomplete.append(f"{profile}:{case_id}:{repetition}:{attempt}:{type(error).__name__}")
            reduced = reduce_case(attempt_results, case) if attempt_results else None
            if reduced is None or reduced["body"]["completed_repetitions"] != case["body"]["repetitions"]:
                missing.append(profile + ":" + case_id)
            planned_cases.append({**summarize_case(case, attempt_results),
                "finding_digest": plans.get(case_id, {}).get("body", {}).get("finding_digest")})
            if reduced is not None:
                case_results.append({"profile": profile, "case_id": case_id,
                    "case_result": reduced,
                    "run_digests": [item["digest"] for item in attempt_results]})
        if source.get("cases") is not None and planned_cases != source.get("cases"):
            incomplete.append(profile + ":saved_summary_recompute_mismatch")
        scanner_findings[profile] = {"raw": len(scan.get("findings", [])),
            "mapped": len(finding_binding), "covered": len(covered_findings),
            "coverage_mode": coverage_mode,
            "high_risk_uncovered": len(uncovered_high),
            "high_risk_unmapped": len(unmapped_high)}
    verdict = "fail" if known_failures else "pending" if missing or incomplete else "pass"
    complete_cases = sum(1 for item in case_results
        if item["case_result"]["body"]["completed_repetitions"] ==
           item["case_result"]["body"]["required_repetitions"])
    output = {"campaign_kind": "m5b-independent-recompute",
        "status": "pass" if not missing and not incomplete else "pending",
        "development_verdict": verdict, "scan_index_digest": digest_bytes(scan_bytes),
        "scanner_findings": scanner_findings,
        "case_count": len(case_results),
        "complete_required_cases": complete_cases,
        "known_failures": known_failures, "missing": missing,
        "incomplete": incomplete, "case_results": case_results}
    output["digest"] = digest_jcs(output)
    return output


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: python scripts/dgx_m5b_gate.py SCAN_INDEX.json OUTPUT_ROOT")
    gate_result = gate(Path(sys.argv[1]), Path(sys.argv[2]))
    path = Path(sys.argv[2]) / "m5b-gate.json"
    path.write_text(json.dumps(gate_result, ensure_ascii=False, indent=2) + "\n")
    os.chmod(path, 0o600)
    print(json.dumps({key: gate_result[key] for key in (
        "status", "development_verdict", "case_count", "known_failures",
        "missing", "incomplete", "digest")}, ensure_ascii=False))
    if gate_result["status"] != "pass":
        raise SystemExit(4)
