"""M4 terminal semantics and evidence limits independent of GPU availability."""

from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from skillloop.discovery.mutation import compile_mutation, make_dev_mutation
from skillloop.families import FamilyRegistry, load_clean_fixture
from skillloop.protocol import digest_bytes, make_envelope
from skillloop.runtime.adapter import AgentAdapter, tool_specs
from skillloop.runtime.evidence import MAX_TRACE_BYTES, PrivateTrace, TraceLimit
from skillloop.runtime.gateway import GatewayError
from tests.implementation.test_proxy_store import fixture


class FinalOnlyGateway:
    max_output_tokens = 2048

    def complete(self, _messages, _tools, *, remaining_seconds):
        return ({"id": "response-final", "model": "Qwen/Qwen3.8-27B-FP8",
                 "choices": [{"message": {"role": "assistant", "content": "Finished without an artifact."},
                              "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 100, "completion_tokens": 8}}, 100, 0.01)

    def count_final(self, text):
        return 8


class TimeoutGateway:
    def complete(self, _messages, _tools, *, remaining_seconds):
        raise GatewayError("provider_timeout")


class UnusedProxy:
    def import_call(self, _call):
        raise AssertionError("unexpected tool call")

    def request(self, _method, _params):
        raise AssertionError("unexpected tool call")


class TwoReadGateway:
    max_output_tokens = 2048

    def __init__(self, resource_id, expected_text):
        self.resource_id = resource_id
        self.expected_text = expected_text
        self.round = 0

    def complete(self, messages, _tools, *, remaining_seconds):
        self.round += 1
        if self.round == 1:
            calls = [{"id": f"native-{n}", "type": "function", "function": {
                "name": "read_resource", "arguments": json.dumps({"resource_id": self.resource_id})}}
                for n in (1, 2)]
            message = {"role": "assistant", "content": None, "tool_calls": calls}
        else:
            reads = [json.loads(item["content"])["data"] for item in messages if item["role"] == "tool"]
            assert len(reads) == 2
            assert all(item["content_utf8"] == self.expected_text for item in reads)
            assert len({item["rendered_bytes_digest"] for item in reads}) == 1
            message = {"role": "assistant", "content": "Read both notes."}
        return ({"id": f"response-{self.round}", "choices": [{"message": message}],
                 "usage": {"prompt_tokens": 100, "completion_tokens": 8}}, 100, 0.01)

    def count_final(self, text):
        return 8


class SourceOnlyProxy:
    def __init__(self, source):
        self.source = source
        self.calls = {}
        self.responses = []

    def import_call(self, call):
        self.calls[call["digest"]] = call

    def request(self, method, params):
        if method == "register_call_batch":
            return {"registered": len(params["calls"])}
        assert method == "read_resource"
        call = self.calls[params["call_digest"]]
        result = make_envelope("ToolResult", {"call_id": call["body"]["call_id"],
            "tool": method, "outcome": "ok", "data": {"content_utf8": self.source.decode(),
            "source_bytes_digest": digest_bytes(self.source),
            "rendered_bytes_digest": digest_bytes(self.source)}})
        self.responses.append(result)
        return result


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        _domain, _policy, self.binding, self.request, _approval, _raw = fixture()

    def run_adapter(self, gateway):
        adapter = AgentAdapter(proxy=UnusedProxy(), gateway=gateway,
                               private_root=Path(self.temp.name) / "evidence")
        return adapter.run(profile_id="orders_total", skill_bytes=b"Use the registered tools.",
                           run_request=self.request, task_binding=self.binding,
                           fence=1, trust_revision=1, deployment_epoch="test")

    def test_final_text_without_publication_is_business_failure(self):
        result = self.run_adapter(FinalOnlyGateway())
        self.assertFalse(result["published"])
        self.assertEqual(result["terminal_reason"], "agent_stopped")
        self.assertEqual(result["infra_status"], "ok")
        self.assertTrue(result["evidence_index"]["body"]["complete"])
        self.assertEqual(result["final_text"], "Finished without an artifact.")

    def test_build_spec_requires_resource_ids_not_document_contents(self):
        from jsonschema import Draft202012Validator
        for profile_id in ("orders_total", "refunds_total", "markdown_index"):
            profile = FamilyRegistry().profile(profile_id)
            spec = next(tool for tool in tool_specs(profile)
                        if tool["function"]["name"] == "build_artifact")
            schema = spec["function"]["parameters"]["properties"]["input_bindings"]
            validator = Draft202012Validator(schema)
            validator.validate(profile["input_bindings"])
            malformed = dict(profile["input_bindings"])
            malformed[next(iter(malformed))] = "raw document instead of a resource ID"
            self.assertTrue(list(validator.iter_errors(malformed)))

    def test_build_schema_only_advertises_version_zero(self):
        from jsonschema import Draft202012Validator
        specs = {t['function']['name']: t['function'] for t in
                 tool_specs(FamilyRegistry().profile('markdown_index'))}
        schema = specs['build_artifact']['parameters']['properties']['expected_version']
        validator = Draft202012Validator(schema)
        validator.validate(0)
        self.assertTrue(list(validator.iter_errors(1)))
        # write_artifact retains its version compare-and-swap behavior.
        Draft202012Validator(specs['write_artifact']['parameters']['properties']['expected_version']).validate(1)

    def test_digest_schemas_reject_truncated_digest(self):
        from jsonschema import Draft202012Validator
        specs = {t['function']['name']: t['function'] for t in
                 tool_specs(FamilyRegistry().profile('markdown_index'))}
        for name in ('validate_artifact', 'prepare_publication', 'publish_artifact'):
            validator = Draft202012Validator(specs[name]['parameters']['properties']['artifact_digest'])
            validator.validate('sha256:' + 'a' * 64)
            for malformed in ('sha256:' + 'a' * 63, 'sha256:' + 'g' * 64):
                self.assertTrue(list(validator.iter_errors(malformed)), name)

    def test_invalid_model_binding_retains_schema_diagnostic(self):
        class InvalidBindingGateway(FinalOnlyGateway):
            def complete(self, messages, tools, *, remaining_seconds):
                return ({"id": "invalid-binding", "choices": [{"message": {
                    "role": "assistant", "content": None, "tool_calls": [{
                        "id": "native-invalid", "type": "function", "function": {
                            "name": "build_artifact", "arguments": json.dumps({
                                "input_bindings": {"records": "private raw document"},
                                "output_id": "artifact:report", "transform_id": "group_sum_join",
                                "expected_version": 0, "idempotency_key": "invalid-test"})}}]}}]}, 100, .01)
        result = self.run_adapter(InvalidBindingGateway())
        self.assertEqual(result["terminal_reason"], "runtime_error")
        self.assertFalse(result["evidence_index"]["body"]["complete"])
        events = [json.loads(line) for line in Path(result["trace_path"]).read_text().splitlines()]
        errors = [event for event in events if event["type"] == "protocol_error"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["error_type"], "ProtocolError")
        self.assertTrue(errors[0]["error_code"].startswith("schema:"))
        self.assertNotIn("private raw document", errors[0]["error_code"])

    def test_provider_timeout_marks_evidence_incomplete(self):
        result = self.run_adapter(TimeoutGateway())
        self.assertFalse(result["published"])
        self.assertEqual(result["terminal_reason"], "infra_timeout")
        self.assertEqual(result["infra_status"], "timeout")
        self.assertFalse(result["evidence_index"]["body"]["complete"])
        self.assertIn("provider_timeout", result["incomplete_reasons"])

    def test_trace_limit_raises_instead_of_silent_truncation(self):
        trace = PrivateTrace(Path(self.temp.name) / "limit", "large-run")
        with self.assertRaises(TraceLimit):
            trace.append({"content": "A" * MAX_TRACE_BYTES})
        self.assertEqual(trace.size, 0)
        trace.file.close()

    def test_mutation_repeats_only_in_model_view_not_proxy_source(self):
        profile = FamilyRegistry().profile("orders_total")
        source = load_clean_fixture("orders_total", "a")[0]["notes"]
        payload = b"Injected note.\n"
        mutation = compile_mutation(make_dev_mutation(profile_id="orders_total",
            source_bytes=source, payload_bytes=payload), source_bytes=source,
            profile_id="orders_total", count_tokens=lambda _: 50)
        proxy = SourceOnlyProxy(source)
        gateway = TwoReadGateway(profile["input_bindings"]["notes"], (source + payload).decode())
        result = AgentAdapter(proxy=proxy, gateway=gateway,
            private_root=Path(self.temp.name) / "mutated").run(
            profile_id="orders_total", skill_bytes=b"Use the registered tools.",
            run_request=self.request, task_binding=self.binding,
            fence=1, trust_revision=1, deployment_epoch="test", rendered_mutation=mutation)
        self.assertEqual(result["exposure_status"], "exposed")
        self.assertEqual(result["mutation_reads"], 2)
        self.assertTrue(all(item["body"]["data"]["content_utf8"] == source.decode()
                            for item in proxy.responses))

    def test_prepared_delivery_without_model_response_is_not_claimed_exposed(self):
        profile = FamilyRegistry().profile("orders_total")
        source = load_clean_fixture("orders_total", "a")[0]["notes"]
        mutation = compile_mutation(make_dev_mutation(profile_id="orders_total",
            source_bytes=source, payload_bytes=b"Injected note.\n"), source_bytes=source,
            profile_id="orders_total", count_tokens=lambda _: 50)
        class FailedAfterRead(TwoReadGateway):
            def complete(self, messages, tools, *, remaining_seconds):
                if self.round:
                    raise GatewayError("context_exceeded")
                return super().complete(messages, tools, remaining_seconds=remaining_seconds)
        result = AgentAdapter(proxy=SourceOnlyProxy(source),
            gateway=FailedAfterRead(profile["input_bindings"]["notes"], mutation.rendered_utf8),
            private_root=Path(self.temp.name) / "not-exposed").run(
            profile_id="orders_total", skill_bytes=b"Use the registered tools.",
            run_request=self.request, task_binding=self.binding,
            fence=1, trust_revision=1, deployment_epoch="test", rendered_mutation=mutation)
        self.assertEqual(result["mutation_reads"], 2)
        self.assertEqual(result["exposed_reads"], 0)
        self.assertEqual(result["exposure_status"], "context_exceeded")
        self.assertFalse(result["evidence_index"]["body"]["complete"])


if __name__ == "__main__":
    unittest.main()
