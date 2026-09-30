"""Measure Ollama chat-template drift before admitting a Mac experiment config."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skillloop.runtime.gateway import ExactLocalTokenizer


def fetch(url: str, payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=300) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("unexpected_ollama_response")
    return value


def calibrate(endpoint: str, model: str, tokenizer_path: str) -> dict:
    tokenizer = ExactLocalTokenizer(tokenizer_path)
    tool = {"type": "function", "function": {"name": "read_resource",
            "description": "Read a resource", "parameters": {"type": "object",
            "properties": {"resource_id": {"type": "string"}},
            "required": ["resource_id"], "additionalProperties": False}}}
    long_block = "Order 12345, quantity 7, refund 0.\n"
    long_count = 1
    while tokenizer.count([{"role": "user", "content": long_block * long_count}], [],
                          enable_thinking=False) < 14_000:
        long_count *= 2
    lower, upper = long_count // 2, long_count
    while lower + 1 < upper:
        middle = (lower + upper) // 2
        if tokenizer.count([{"role": "user", "content": long_block * middle}], [],
                           enable_thinking=False) <= 14_200:
            lower = middle
        else:
            upper = middle
    shapes = [
        ("plain", [{"role": "system", "content": "Answer briefly."},
                   {"role": "user", "content": "Say ready."}], []),
        ("single_tool", [{"role": "system", "content": "Use the available tool."},
                         {"role": "user", "content": "Read resource notes."}], [tool]),
        ("multi_tool", [{"role": "user", "content": "Read resources A and B."},
                        {"role": "assistant", "content": "", "tool_calls": [
                            {"function": {"name": "read_resource", "arguments": {"resource_id": "A"}}},
                            {"function": {"name": "read_resource", "arguments": {"resource_id": "B"}}}]},
                        {"role": "tool", "tool_name": "read_resource", "content": "A is available."},
                        {"role": "tool", "tool_name": "read_resource", "content": "B is available."}], [tool]),
        ("tool_return", [{"role": "user", "content": "Read resource A."},
                         {"role": "assistant", "content": "", "tool_calls": [
                             {"function": {"name": "read_resource", "arguments": {"resource_id": "A"}}}]},
                         {"role": "tool", "tool_name": "read_resource", "content": "A is available."}], [tool]),
        ("near_profile_limit", [{"role": "user", "content": long_block * lower}], []),
    ]
    records = []
    for name, messages, tools in shapes:
        local = tokenizer.count(messages, tools, enable_thinking=False)
        response = fetch(endpoint + "/api/chat", {"model": model, "messages": messages,
            "tools": tools, "stream": False, "think": False,
            "options": {"num_ctx": 16384, "num_predict": 16, "temperature": 0}})
        if response.get("model") != model or type(response.get("prompt_eval_count")) is not int:
            raise ValueError("model_identity_or_usage_missing")
        records.append({"shape": name, "local_tokens": local,
            "ollama_prompt_tokens": response["prompt_eval_count"],
            "offset": response["prompt_eval_count"] - local,
            "done_reason": response.get("done_reason")})
    offsets = {row["offset"] for row in records}
    version = fetch(endpoint + "/api/version")
    snapshot = Path(tokenizer_path)
    tokenizer_files = [snapshot / name for name in ("tokenizer.json", "tokenizer_config.json", "chat_template.jinja", "config.json")]
    if not all(path.is_file() for path in tokenizer_files):
        raise ValueError("tokenizer_snapshot_identity_incomplete")
    identity = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in tokenizer_files}
    return {"status": "ready_for_extended_admission" if len(offsets) == 1 else "template_drift",
            "model": model, "ollama_version": version.get("version"),
            "tokenizer_sha256": identity, "template_overhead_tokens": next(iter(offsets)) if len(offsets) == 1 else None,
            "records": records}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="qwen3.8:27b-mxfp8")
    parser.add_argument("--tokenizer-path", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.endpoint not in {"http://127.0.0.1:11434", "http://host.docker.internal:11434"}:
        raise ValueError("local_ollama_endpoint_required")
    if args.output.exists():
        raise FileExistsError(args.output)
    report = calibrate(args.endpoint, args.model, args.tokenizer_path)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"],
                      "template_overhead_tokens": report["template_overhead_tokens"]}))
    if report["status"] != "ready_for_extended_admission":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
