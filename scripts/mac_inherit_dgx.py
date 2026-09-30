"""Index historical DGX outcomes without issuing any new model requests."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def index(root: Path) -> dict:
    if not (root / "m6-n11o").is_dir():
        raise ValueError("dgx_archive_incomplete")
    groups = collections.defaultdict(lambda: {"runs": 0, "complete": 0,
        "incomplete": 0, "security_violations": 0, "source_files": []})
    errors = []
    for campaign in sorted(root.glob("m6-*")):
        if not campaign.is_dir():
            continue
        for path in sorted(campaign.rglob("result.json")):
            try:
                record = json.loads(path.read_text())
                observation = record["observation"]["body"]
                evaluation = record["result"]["body"]
                config = record["config"]["config_id"]
                case_id = record["case"]["body"]["case_id"]
                profile = case_id.split(".", 1)[0]
                if (observation["run_id"] != evaluation["run_id"] or
                        observation["case_digest"] != evaluation["case_digest"]):
                    raise ValueError("observation_evaluation_mismatch")
                group = groups[(campaign.name, config, profile)]
                group["runs"] += 1
                complete = observation["evidence_complete"] and evaluation["coverage_complete"]
                group["complete" if complete else "incomplete"] += 1
                group["security_violations"] += bool(evaluation["security_violation"])
                group["source_files"].append({"path": str(path.relative_to(root)), "sha256": digest(path)})
            except (KeyError, TypeError, ValueError, OSError) as exc:
                errors.append({"path": str(path.relative_to(root)), "error": type(exc).__name__})
    historical_gates = []
    for path in sorted(root.glob("m5*/m5b-gate.json")):
        historical_gates.append({"path": str(path.relative_to(root)), "sha256": digest(path)})
    return {"kind": "DGXHistoricalInheritanceIndex", "source": "gx10-b489",
        "reuse_policy": "historical_evidence_only; zero Ollama Gate credit",
        "new_model_calls": 0,
        "historical_m5_gates": historical_gates,
        "m6_groups": [{"campaign": campaign, "config_id": config, "profile": profile, **values}
                      for (campaign, config, profile), values in sorted(groups.items())],
        "total_m6_result_files": sum(value["runs"] for value in groups.values()),
        "errors": errors}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    result = index(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"historical_runs": result["total_m6_result_files"],
                      "groups": len(result["m6_groups"]), "errors": len(result["errors"])}))
    if result["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
