"""Run one frozen M5 development case on the isolated DGX loopback stack."""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skillloop.discovery.evaluator import evaluate_run
from skillloop.discovery.mutation import compile_mutation
from skillloop.discovery.suite import compile_dev_suite, development_config, make_dev_plan
from skillloop.families import load_clean_fixture, load_example_skill
from skillloop.families.registry import FAMILY_SPEC
from skillloop.protocol import digest_bytes, digest_jcs
from skillloop.proxy.server import ProxyServer
from skillloop.proxy.store import ProxyStore
from skillloop.runtime.adapter import AgentAdapter
from skillloop.runtime.client import ProxyClient
from skillloop.runtime.gateway import ExactDockerTokenizer, ExactLocalTokenizer, OllamaGateway, SGLangGateway
from skillloop.families.task_world import fixture, stamp


def run_one(case_id: str, repetition: int, output: Path, attempt_index: int = 0,
            *, compiled_suite: dict | None = None, skill_root: Path = FAMILY_SPEC,
            campaign_id: str | None = None, runtime_config: dict | None = None,
            execution_plan: dict | None = None,
            inputs_override: dict[str, bytes] | None = None,
            deployment_epoch: str = "m5-development-1",
            gateway_url: str = "http://127.0.0.1:30000",
            tokenizer_container: str = "skillloop-m4-sglang",
            gateway_backend: str = "sglang",
            approval_factory_digest: str | None = None,
            runtime_executor=None, runtime_uid: int | None = None,
            socket_directory: Path | None = None, imported_admission: dict | None = None) -> dict:
    if runtime_config and runtime_config.get('whole_flow_required'):
        # Until the shared Controller dispatcher is connected, this legacy
        # local fixture path must never masquerade as a formal whole campaign.
        raise ValueError('formal_shared_proxy_dispatch_required')
    profile_id = compiled_suite["profile_id"] if compiled_suite else case_id.split(".")[0]
    compiled = compiled_suite or compile_dev_suite(profile_id, skill_root=skill_root)
    case = compiled["cases"][case_id]
    if repetition < 0 or repetition >= case["body"]["repetitions"] or attempt_index not in (0, 1):
        raise ValueError("repetition_out_of_range")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    actual_campaign_id = campaign_id or "m5-development-1-" + profile_id
    config = runtime_config or development_config()
    plan = execution_plan or make_dev_plan(compiled, campaign_id=actual_campaign_id, config=config)
    suffix = "b" if case_id.endswith("clean-b") else "a"
    inputs, expected = load_clean_fixture(profile_id, suffix)
    if inputs_override is not None:
        from skillloop.families.builders import build_artifact
        from skillloop.families.oracle import validate_artifact
        inputs = dict(inputs_override)
        expected = build_artifact(profile_id, inputs)
        validate_artifact(profile_id, inputs, expected)
    selection=None
    if imported_admission is not None:
        from skillloop.loader import ApprovedPackageLoader
        from skillloop.families.registry import FamilyRegistry
        admission=imported_admission
        loader=ApprovedPackageLoader(approved_sources=admission['approved_sources'],
                                     reference_resource_ids=admission['reference_resource_ids'],
                                     approved_subjects=admission.get('approved_subjects'))
        selection=loader.select(admission['source_snapshot'],admission['package_files'],admission['manifest'],
                                profile_id=profile_id,family_id=FamilyRegistry().profile(profile_id)['family_id'])
        skill_bytes=admission['package_files']['SKILL.md']
        if compiled.get('subject_digest')!=selection.subject_digest:raise ValueError('imported_subject_identity')
    else:
        skill_bytes = load_example_skill(profile_id, root=skill_root)
    if digest_bytes(skill_bytes) != compiled["skill_digest"]:
        raise ValueError("compiled_subject_mismatch")
    tokenizer = (ExactLocalTokenizer(config["tokenizer_path"]) if gateway_backend == "ollama"
                 else ExactDockerTokenizer(tokenizer_container))
    try:
        mutation_spec = compiled["mutations"].get(case_id)
        mutation = (compile_mutation(mutation_spec, source_bytes=inputs["notes"],
                                     profile_id=profile_id, count_tokens=tokenizer.count_text)
                    if mutation_spec else None)
        subject_digest = compiled.get("subject_digest", digest_bytes(skill_bytes))
        identity_prefix = ("m5" if execution_plan is None else
            digest_jcs([actual_campaign_id, subject_digest])[7:19])
        domain, policy, binding, request, approval, raw = fixture(
            profile_id, suffix=suffix, inputs_override=inputs_override, subject_digest=subject_digest,
            case_digest=case["digest"], suite_digest=compiled["suite"]["digest"],
            plan_digest=plan["digest"], repetition_index=repetition,
            config_digest=plan["body"]["config_digest"],
            initial_world_digest=digest_jcs({"profile_id": profile_id,
                "inputs": {slot: digest_bytes(value) for slot, value in inputs.items()},
                "expected_digest": digest_bytes(expected)}),
            run_id=f"run-{identity_prefix}-{case_id}-{repetition}-attempt-{attempt_index}",
            task_instance_id=f"task-{identity_prefix}-{case_id}-{repetition}-attempt-{attempt_index}",
            package_resources=None if selection is None else selection.resource_bytes())
        if approval_factory_digest is not None:
            from skillloop.protocol import make_envelope
            approved = dict(approval["body"])
            approved.update(factory_rule_digest=approval_factory_digest, config_digest=digest_jcs(config))
            approval = make_envelope("ApprovalRecord", approved)
        if execution_plan is not None:
            from scripts.spec_v22_core import validate_plan
            validate_plan(plan, compiled["suite"])
            if plan["body"]["config_digest"] != digest_jcs(config):
                raise ValueError("execution_plan_config")
            item = next((row for row in plan["body"]["items"] if row["case_digest"] == case["digest"]
                         and row["subject_digest"] == subject_digest and row["repetition_index"] == repetition), None)
            if item is None or item["requirement"] != "required" or attempt_index >= item["attempts_reserved"]:
                raise ValueError("execution_not_reserved")
        store = ProxyStore(output / "authority.db", deployment_epoch=deployment_epoch)
        store.stage_approval(domain, approval)
        store.activate_approval(approval["digest"], 0, operation_id="activate-m5",
                                request_digest=digest_jcs("activate-m5"))
        task_setup=dict(domain=domain,policy=policy,binding=binding,run_request=request,
                        profile_id=profile_id,approval_digest=approval['digest'],
                        run_deadline=stamp(config.get('proxy_deadline_seconds',360)),campaign_id=actual_campaign_id)
        if selection is not None:
            selection.check_binding(binding)
            store.stage_imported_task(loader=loader,source_snapshot=admission['source_snapshot'],
                package_files=admission['package_files'],skill_manifest=admission['manifest'],input_resources=raw,**task_setup)
        else:
            store.stage_task(resources=raw,**task_setup)
        run_lease=store.start_run(request["digest"], binding["digest"], operation_id="start-m5",
                        request_digest=digest_jcs("start-m5"))
        socket_directory = socket_directory or output / "sockets"
        server = ProxyServer(store, socket_directory, controller_uid=os.getuid(),
                             runtime_uid=os.getuid() if runtime_uid is None else runtime_uid,
                             socket_mode=0o600 if runtime_uid is None else 0o666)
        with server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                if runtime_executor is not None:
                    lease_options=({'run_lease':run_lease,'trust_revision':approval['body']['trust_revision']}
                                   if gateway_backend=='ollama' else {})
                    if selection is None:
                        result = runtime_executor(output, profile_id, skill_bytes, request, binding, config, mutation, attempt_index, deployment_epoch,**lease_options)
                    else:
                        result = runtime_executor(output, profile_id, skill_bytes, request, binding, config, mutation, attempt_index,
                                                  deployment_epoch,imported_selection=selection,**lease_options)
                else:
                    if gateway_backend == "ollama":
                        gateway = OllamaGateway(gateway_url, tokenizer,
                            model=config["model_id"],
                            template_overhead_tokens=config.get("ollama_template_overhead_tokens"),
                            max_context_tokens=config.get("max_context_tokens", 16384),
                            max_output_tokens=config.get("max_output_tokens", 2048),
                            timeout_seconds=config.get("provider_timeout_seconds", 180))
                    elif gateway_backend == "sglang":
                        gateway = SGLangGateway(gateway_url, tokenizer,
                            enable_thinking=config.get("thinking", True),
                            max_context_tokens=config.get("max_context_tokens", 16384),
                            max_output_tokens=config.get("max_output_tokens", 2048),
                            timeout_seconds=config.get("provider_timeout_seconds", 180))
                    else:
                        raise ValueError("unknown_gateway_backend")
                    adapter=AgentAdapter(proxy=ProxyClient(socket_directory,expected_server_uid=os.geteuid()),gateway=gateway,
                                         private_root=output/'evidence')
                    execute_adapter=adapter.run if selection is None else adapter.run_imported
                    materials=({'skill_bytes':skill_bytes} if selection is None else
                        {'instruction_resource_id':loader.instruction_resource_id,
                         'reference_resource_ids':sorted(loader.reference_resource_ids.values())})
                    result = execute_adapter(
                        profile_id=profile_id, **materials, run_request=request,
                        task_binding=binding, fence=run_lease['body']['fencing_token'], trust_revision=approval['body']['trust_revision'],
                        deployment_epoch=deployment_epoch, deadline_seconds=config.get("agent_deadline_seconds", 300),
                        rendered_mutation=mutation, attempt_index=attempt_index)
            finally:
                server.stop()
                worker.join(timeout=2)
        capture = {"case": case, "config": config, "run_request": request, "task_binding": binding,
            "mutation": mutation_spec, "observation": result["observation"],
            "runtime_evidence_index": result["evidence_index"],
            "runtime_incomplete_reasons": result["incomplete_reasons"],
            "trace_filename": Path(result["trace_path"]).name}
        (output / "runtime-capture.json").write_text(json.dumps(capture, ensure_ascii=False, indent=2) + "\n")
        os.chmod(output / "runtime-capture.json", 0o600)
        evaluated, events, summary, evaluation_evidence = evaluate_run(case=case, objectives=compiled["objectives"],
            adapter_result=result, store=store, expected=expected, notes=inputs["notes"], mutation_spec=mutation_spec)
        private = {"case": case, "suite_digest": compiled["suite"]["digest"],
            "plan_digest": plan["digest"], "config": config,
            "run_request": request, "task_binding": binding, "mutation": mutation_spec,
            "rendered_digest": mutation.rendered_digest if mutation else None,
            "observation": result["observation"], "evidence_index": evaluation_evidence,
            "runtime_evidence_index": result["evidence_index"],
            "runtime_incomplete_reasons": result["incomplete_reasons"],
            "result": evaluated, "trusted_events": events, "summary": summary,
            "rounds": result["rounds"]}
        if execution_plan is not None:
            private["execution_plan"] = execution_plan
        (output / "result.json").write_text(json.dumps(private, ensure_ascii=False, indent=2) + "\n")
        os.chmod(output / "result.json", 0o600)
        return {"case_id": case_id, "repetition": repetition,
            "coverage_complete": evaluated["body"]["coverage_complete"],
            "utility_status": evaluated["body"]["utility_status"],
            "security_violation": evaluated["body"]["security_violation"],
            "exposure_status": evaluated["body"]["exposure_status"],
            "objective_outcomes": [{key: row[key] for key in ("objective_id", "attempt", "effect")}
                                   for row in evaluated["body"]["objective_outcomes"]],
            "incomplete_reasons": evaluated["body"]["incomplete_reasons"],
            "rounds": result["rounds"], "result_digest": evaluated["digest"]}

    finally:
        primary=sys.exc_info()[1]
        try:tokenizer.close()
        except BaseException as error:
            if primary is None:raise
            primary.add_note("tokenizer_cleanup_error:"+type(error).__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True)
    parser.add_argument("--repetition", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--attempt-index", type=int, default=0)
    args = parser.parse_args()
    print(json.dumps(run_one(args.case, args.repetition, args.output,
                             args.attempt_index), ensure_ascii=False))


if __name__ == "__main__":
    main()
