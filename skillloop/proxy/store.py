"""SQLite authority for approvals, tool calls, artifacts and publication effects."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from skillloop.families.builders import build_artifact
from skillloop.families.oracle import validate_artifact
from skillloop.families.registry import FamilyRegistry
from skillloop.protocol import (ProtocolError, canonical_json_line, decode_json, digest_bytes,
                                digest_jcs, make_envelope, validate_envelope)

from .policy import AuthorizationError, compile_capability, permits


MIGRATION = Path(__file__).with_name("migrations") / "001_initial.sql"
TOOL_NAMES = frozenset({"read_resource", "build_artifact", "write_artifact",
                        "validate_artifact", "prepare_publication", "publish_artifact"})


class ProxyError(Exception):
    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ProxyError("invalid_args") from exc
    return parsed


def _json(value: Any) -> bytes:
    return canonical_json_line(value)


def _load(raw: bytes) -> dict[str, Any]:
    value = decode_json(raw)
    if not isinstance(value, dict):
        raise ProxyError("runtime_error")
    return value


class ProxyStore:
    """One durable database; every effect and revocation commits in this file."""

    def __init__(self, path: Path, *, deployment_epoch: str, registry: FamilyRegistry | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.registry = registry or FamilyRegistry()
        self.deployment_epoch = deployment_epoch
        self.fault_hook: Callable[[str], None] | None = None
        with closing(self._connect()) as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                db.execute("BEGIN IMMEDIATE")
                try:
                    for statement in MIGRATION.read_text().split(";\n"):
                        if statement.strip():
                            db.execute(statement)
                    db.execute("INSERT INTO schema_migrations VALUES (1, ?)", (_stamp(_now()),))
                    db.execute("INSERT INTO trust_state VALUES (1, ?, 0)", (deployment_epoch,))
                    db.execute("PRAGMA user_version = 1")
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
            elif version != 1:
                raise ProxyError("unsupported_database_version")
            row = db.execute("SELECT deployment_epoch FROM trust_state WHERE singleton=1").fetchone()
            if row is None or row[0] != deployment_epoch:
                raise ProxyError("deployment_epoch_mismatch")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            else:
                if self.fault_hook is not None:
                    self.fault_hook("before_commit")
                db.execute("COMMIT")
                if self.fault_hook is not None:
                    self.fault_hook("after_commit")
        finally:
            db.close()

    @staticmethod
    def _one(db: sqlite3.Connection, sql: str, params: tuple[Any, ...], code: str = "not_found") -> sqlite3.Row:
        row = db.execute(sql, params).fetchone()
        if row is None:
            raise ProxyError(code)
        return row

    def stage_object(self, record: dict[str, Any], *, trusted_role: str) -> str:
        """Trusted bootstrap/adapter ingress; intentionally absent from tool RPC."""
        if trusted_role not in {"admin", "controller", "runtime"}:
            raise AuthorizationError("staging_role")
        validate_envelope(record)
        if record["kind"] not in {"AuthorizationDomain", "ApprovalRecord", "Policy", "TaskBinding",
                                  "RunRequest", "ToolCall"}:
            raise AuthorizationError("staging_kind")
        if ((trusted_role == "runtime") != (record["kind"] == "ToolCall") or
            (trusted_role == "admin" and record["kind"] not in {"AuthorizationDomain", "ApprovalRecord", "Policy"}) or
            (trusted_role == "controller" and record["kind"] not in {"TaskBinding", "RunRequest"})):
            raise AuthorizationError("staging_role_kind")
        raw = _json(record)
        with self._transaction() as db:
            previous = db.execute("SELECT raw_json FROM staged_objects WHERE digest=?", (record["digest"],)).fetchone()
            if previous is not None and previous[0] != raw:
                raise ProxyError("digest_collision")
            db.execute("INSERT OR IGNORE INTO staged_objects VALUES (?, ?, ?, ?)",
                       (record["digest"], record["kind"], raw, trusted_role))
        return record["digest"]

    def stage_approval(self, domain: dict[str, Any], approval: dict[str, Any]) -> None:
        validate_envelope(domain)
        validate_envelope(approval)
        if domain["kind"] != "AuthorizationDomain" or approval["kind"] != "ApprovalRecord":
            raise AuthorizationError("approval_kind")
        d, a = domain["body"], approval["body"]
        if a["authorization_domain_digest"] != domain["digest"] or a["contract_digest"] != d["contract_digest"]:
            raise AuthorizationError("approval_domain")
        if a["state"] != "active" or a["issuer"] != "administrator":
            raise AuthorizationError("approval_issuer")
        with self._transaction() as db:
            current = self._one(db, "SELECT trust_revision FROM trust_state WHERE singleton=1", ())
            if a["trust_revision"] != current[0] + 1:
                raise AuthorizationError("approval_trust_revision")
            db.execute("INSERT INTO approvals VALUES (?, ?, ?, ?, ?, 'staged', ?, ?, NULL)",
                       (approval["digest"], domain["digest"], d["contract_digest"], d["tenant_id"],
                        _json(domain), a["expires_at"], a["trust_revision"]))
            db.execute("INSERT OR IGNORE INTO staged_objects VALUES (?, ?, ?, 'admin')",
                       (domain["digest"], "AuthorizationDomain", _json(domain)))
            db.execute("INSERT OR IGNORE INTO staged_objects VALUES (?, ?, ?, 'admin')",
                       (approval["digest"], "ApprovalRecord", _json(approval)))

    def activate_approval(self, approval_digest: str, expected_revision: int,
                          *, operation_id: str, request_digest: str) -> dict[str, Any]:
        with self._transaction() as db:
            previous = self._operation_replay(db, operation_id, request_digest)
            if previous is not None:
                return previous
            current = self._one(db, "SELECT trust_revision FROM trust_state WHERE singleton=1", ())
            approval = self._one(db, "SELECT * FROM approvals WHERE approval_digest=?", (approval_digest,))
            if current[0] != expected_revision or approval["trust_revision"] != current[0] + 1 or approval["state"] != "staged":
                raise ProxyError("version_conflict")
            if approval["expires_at"] is not None and _parse(approval["expires_at"]) <= _now():
                raise ProxyError("expired")
            now = _stamp(_now())
            db.execute("UPDATE trust_state SET trust_revision=? WHERE singleton=1", (approval["trust_revision"],))
            db.execute("UPDATE approvals SET state='active', committed_at=? WHERE approval_digest=?", (now, approval_digest))
            result = {"approval_digest": approval_digest, "state": "active",
                      "trust_revision": approval["trust_revision"], "committed_at": now,
                      "expires_at": approval["expires_at"]}
            self._record_operation(db, operation_id, "controller", None, request_digest,
                                   "activate_approval", result)
            return result

    def stage_imported_task(self, *, loader, source_snapshot: dict[str, Any],
                            package_files: dict[str, bytes], skill_manifest: dict[str, Any],
                            input_resources: dict[str, bytes], **task_setup) -> dict[str, Any]:
        """Trusted controller admission: selected package bytes only, then atomic stage.

        This is an in-process trusted setup API; it adds no caller-authorized RPC.
        Context/token preflight and remote controller role service remain separate.
        """
        profile_id = task_setup["profile_id"]
        family_id = self.registry.profile(profile_id)["family_id"]
        selection = loader.select(source_snapshot, package_files, skill_manifest,
                                  profile_id=profile_id, family_id=family_id)
        selection.check_binding(task_setup["binding"])
        selected = selection.resource_bytes()
        if set(selected) & set(input_resources):
            raise AuthorizationError("loader_resource_class_overlap")
        capability = self.stage_task(resources={**input_resources, **selected}, **task_setup)
        return {"capability": capability, "source_snapshot_digest": selection.source_snapshot_digest,
                "manifest_digest": selection.manifest_digest,
                "selected_paths": [path for path, _, _ in selection.files]}

    def stage_task(self, *, domain: dict[str, Any], policy: dict[str, Any],
                   binding: dict[str, Any], run_request: dict[str, Any],
                   profile_id: str, resources: dict[str, bytes], approval_digest: str,
                   run_deadline: str, campaign_id: str,
                   parent_policy: dict[str, Any] | None = None) -> dict[str, Any]:
        """Trusted setup verifies exact resource bytes before any run starts."""
        cap = compile_capability(domain, binding, policy, profile_id,
                                 parent_policy=parent_policy, registry=self.registry)
        validate_envelope(run_request)
        if run_request["kind"] != "RunRequest":
            raise AuthorizationError("run_request_kind")
        b, rr = binding["body"], run_request["body"]
        if rr["subject_digest"] != b["subject_digest"] or rr["authorization_domain_digest"] != domain["digest"]:
            raise AuthorizationError("run_request_binding")
        if _parse(run_deadline) <= _now():
            raise AuthorizationError("run_deadline")
        by_id = {item["resource_id"]: item for item in b["resources"]}
        if set(resources) != {name for name, item in by_id.items() if item["resource_class"] in ("skill", "input")}:
            raise AuthorizationError("resource_bytes_set")
        for name, raw in resources.items():
            if type(raw) is not bytes or digest_bytes(raw) != by_id[name]["bytes_digest"]:
                raise AuthorizationError("resource_bytes_digest")
        with self._transaction() as db:
            approval = self._one(db, "SELECT * FROM approvals WHERE approval_digest=?", (approval_digest,))
            if approval["state"] != "active" or approval["domain_digest"] != domain["digest"]:
                raise AuthorizationError("approval_inactive")
            db.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (b["task_instance_id"], b["run_id"], b["tenant_id"], profile_id,
                        domain["digest"], approval_digest, binding["digest"], b["subject_digest"],
                        policy["digest"], run_request["digest"], run_deadline, campaign_id,
                        _json(binding), _json(policy), _json(cap)))
            for item in b["resources"]:
                raw = resources.get(item["resource_id"])
                db.execute("INSERT INTO resources VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                           (b["task_instance_id"], item["resource_id"], item["tenant_id"],
                            item["resource_class"], item["access"], item["bytes_digest"], raw))
            db.execute("INSERT OR IGNORE INTO staged_objects VALUES (?, ?, ?, 'controller')",
                       (binding["digest"], "TaskBinding", _json(binding)))
            db.execute("INSERT OR IGNORE INTO staged_objects VALUES (?, ?, ?, 'controller')",
                       (run_request["digest"], "RunRequest", _json(run_request)))
        return cap

    def start_run(self, run_request_digest: str, binding_digest: str,
                  *, operation_id: str, request_digest: str) -> dict[str, Any]:
        with self._transaction() as db:
            previous = self._operation_replay(db, operation_id, request_digest)
            if previous is not None:
                return previous
            task = self._one(db, "SELECT * FROM tasks WHERE binding_digest=? AND run_request_digest=?",
                             (binding_digest, run_request_digest))
            approval = self._one(db, "SELECT * FROM approvals WHERE approval_digest=?", (task["approval_digest"],))
            if approval["state"] != "active":
                raise ProxyError("approval_required")
            deadline = _parse(task["run_deadline"])
            lease = min(deadline, _now() + timedelta(minutes=5))
            if approval["expires_at"] is not None:
                lease = min(lease, _parse(approval["expires_at"]))
            if lease <= _now():
                raise ProxyError("expired")
            cap = _load(task["cap_json"])
            db.execute("INSERT INTO runs VALUES (?, ?, ?, 1, 'active', ?, ?, ?, ?, 0, ?)",
                       (task["run_id"], task["task_instance_id"], task["approval_digest"],
                        task["run_deadline"], _stamp(lease), approval["trust_revision"],
                        cap["body"]["max_tool_calls"], task["campaign_id"]))
            result = make_envelope("Lease", {"campaign_id": task["campaign_id"],
                       "run_id": task["run_id"], "worker_id": "trusted-runtime",
                       "fencing_token": 1, "expires_at": _stamp(lease), "state": "active"})
            self._record_operation(db, operation_id, "controller", task["run_id"], request_digest,
                                   "start_run", result)
            return result

    def register_call_batch(self, run_id: str, fence: int, response_id: str,
                            calls: list[dict[str, Any]]) -> dict[str, Any]:
        if not calls or len(calls) > 12:
            raise ProxyError("invalid_args")
        if len({item["native_tool_call_id"] for item in calls}) != len(calls):
            raise ProxyError("invalid_args")
        if sorted(item["batch_index"] for item in calls) != list(range(len(calls))):
            raise ProxyError("invalid_args")
        with self._transaction() as db:
            run, _task, approval = self._active_run(db, run_id, fence)
            existing = db.execute("SELECT call_digest, native_tool_call_id, batch_index FROM call_registration WHERE run_id=? AND response_id=? ORDER BY batch_index",
                                  (run_id, response_id)).fetchall()
            ordered = sorted(calls, key=lambda x: x["batch_index"])
            expected = [item["call_digest"] for item in ordered]
            if existing:
                if [(row["call_digest"], row["native_tool_call_id"], row["batch_index"])
                    for row in existing] != [(item["call_digest"], item["native_tool_call_id"],
                                               item["batch_index"]) for item in ordered]:
                    raise ProxyError("version_conflict")
                return self._registration_result(run, expected)
            duplicates = db.execute(
                "SELECT call_digest FROM call_registration WHERE run_id=? AND call_digest IN (" +
                ",".join("?" for _ in expected) + ")", (run_id, *expected)).fetchall()
            if duplicates:
                if len(duplicates) != len(expected):
                    raise ProxyError("version_conflict")
                return self._registration_result(run, expected)
            self._check_live(run, approval)
            if run["consumed_calls"] + len(calls) > run["max_tool_calls"]:
                raise ProxyError("budget_exhausted")
            prepared = []
            for item in calls:
                staged = self._one(db, "SELECT kind, raw_json, staged_role FROM staged_objects WHERE digest=?",
                                   (item["call_digest"],))
                if staged["kind"] != "ToolCall" or staged["staged_role"] != "runtime":
                    raise ProxyError("denied")
                call = _load(staged["raw_json"])
                body = call["body"]
                if (body["run_id"] != run_id or body["task_instance_id"] != run["task_instance_id"] or
                    body["fencing_token"] != fence or body["tool"] not in TOOL_NAMES):
                    raise ProxyError("denied")
                previous = db.execute("SELECT call_digest, args_digest FROM call_registration WHERE run_id=? AND internal_call_id=?",
                                      (run_id, body["call_id"])).fetchone()
                if previous is not None:
                    raise ProxyError("version_conflict")
                prepared.append((item, body))
            for item, body in prepared:
                db.execute("INSERT INTO call_registration VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'registered', NULL)",
                           (item["call_digest"], run_id, body["call_id"], fence, response_id,
                            item["native_tool_call_id"], item["batch_index"], body["tool"],
                            digest_jcs(body["args"])))
            db.execute("UPDATE runs SET consumed_calls=consumed_calls+? WHERE run_id=?", (len(calls), run_id))
            updated = self._one(db, "SELECT * FROM runs WHERE run_id=?", (run_id,))
            return self._registration_result(updated, expected)

    @staticmethod
    def _registration_result(run: sqlite3.Row, digests: list[str]) -> dict[str, Any]:
        return {"run_id": run["run_id"], "fence": run["fence"],
                "registered_call_digests": digests, "consumed_calls": run["consumed_calls"],
                "remaining_calls": run["max_tool_calls"] - run["consumed_calls"]}

    @staticmethod
    def _operation_replay(db: sqlite3.Connection, operation_id: str,
                          request_digest: str) -> dict[str, Any] | None:
        row = db.execute("SELECT request_digest, result_json FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return None
        if row["request_digest"] != request_digest:
            raise ProxyError("version_conflict")
        return _load(row["result_json"])

    @staticmethod
    def _record_operation(db: sqlite3.Connection, operation_id: str, role: str,
                          run_id: str | None, request_digest: str, method: str,
                          result: dict[str, Any]) -> None:
        db.execute("INSERT INTO operations VALUES (?, ?, ?, ?, ?, 'completed', ?, ?)",
                   (operation_id, role, run_id, request_digest, method, _json(result), _stamp(_now())))

    @staticmethod
    def _active_run(db: sqlite3.Connection, run_id: str, fence: int) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        run = ProxyStore._one(db, "SELECT * FROM runs WHERE run_id=?", (run_id,))
        if run["fence"] != fence:
            raise ProxyError("stale_fence")
        if run["state"] == "cancelled":
            raise ProxyError("cancelled")
        task = ProxyStore._one(db, "SELECT * FROM tasks WHERE task_instance_id=?", (run["task_instance_id"],))
        approval = ProxyStore._one(db, "SELECT * FROM approvals WHERE approval_digest=?", (run["approval_digest"],))
        return run, task, approval

    @staticmethod
    def _result(call_id: str, tool: str, data: dict[str, Any] | None = None,
                error: ProxyError | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"call_id": call_id, "tool": tool}
        if error is None:
            body.update(outcome="ok", data=data)
        else:
            body.update(outcome="error", error_code=error.code, retryable=error.retryable)
        return make_envelope("ToolResult", body)

    @staticmethod
    def _strict_args(tool: str, args: dict[str, Any], registry: FamilyRegistry,
                     profile_id: str) -> str | None:
        if type(args) is not dict:
            raise ProxyError("invalid_args")
        expected = {
            "read_resource": {"resource_id"},
            "write_artifact": {"output_id", "expected_version", "content_utf8", "idempotency_key"},
            "validate_artifact": {"output_id", "artifact_digest", "check_set_id"},
            "prepare_publication": {"output_id", "artifact_digest", "destination_id",
                                    "validation_receipt_id", "idempotency_key"},
            "publish_artifact": {"output_id", "artifact_digest", "destination_id",
                                "validation_receipt_id", "grant_ref", "idempotency_key"},
        }
        if tool == "build_artifact":
            try:
                registry.validate_build_args(profile_id, args)
            except ProtocolError as exc:
                raise ProxyError("invalid_args") from exc
        elif set(args) != expected.get(tool):
            raise ProxyError("invalid_args")
        if tool == "read_resource":
            if type(args["resource_id"]) is not str:
                raise ProxyError("invalid_args")
            return None
        if tool == "validate_artifact":
            if any(type(args[name]) is not str or not args[name]
                   for name in ("output_id", "artifact_digest", "check_set_id")):
                raise ProxyError("invalid_args")
            return None
        key = args["idempotency_key"]
        if type(key) is not str or not 1 <= len(key) <= 128:
            raise ProxyError("invalid_args")
        if tool == "write_artifact" and (type(args["expected_version"]) is not int or
                                          type(args["content_utf8"]) is not str):
            raise ProxyError("invalid_args")
        if tool in ("prepare_publication", "publish_artifact"):
            required = {"validation_receipt_id", "artifact_digest", "destination_id"}
            if tool == "publish_artifact":
                required.add("grant_ref")
            if any(type(args[name]) is not str or not args[name] for name in required):
                raise ProxyError("invalid_args")
        return key

    @staticmethod
    def _resource(db: sqlite3.Connection, task_id: str, resource_id: str,
                  resource_class: str | None = None) -> sqlite3.Row:
        resource = ProxyStore._one(db,
            "SELECT * FROM resources WHERE task_instance_id=? AND resource_id=?",
            (task_id, resource_id))
        if resource_class is not None and resource["resource_class"] != resource_class:
            raise ProxyError("denied")
        return resource

    @staticmethod
    def _input_bytes(db: sqlite3.Connection, task: sqlite3.Row,
                     bindings: dict[str, str]) -> dict[str, bytes]:
        inputs: dict[str, bytes] = {}
        for name, resource_id in bindings.items():
            row = ProxyStore._resource(db, task["task_instance_id"], resource_id, "input")
            if row["content"] is None or digest_bytes(row["content"]) != row["bytes_digest"]:
                raise ProxyError("runtime_error")
            inputs[name] = row["content"]
        return inputs

    @staticmethod
    def _read_ids(db: sqlite3.Connection, run_id: str) -> set[str]:
        records = db.execute(
            "SELECT o.raw_json, c.result_json FROM call_registration c JOIN staged_objects o ON c.call_digest=o.digest "
            "WHERE c.run_id=? AND c.tool='read_resource' AND c.status='completed' AND c.result_json IS NOT NULL",
            (run_id,)).fetchall()
        return {_load(row["raw_json"])["body"]["args"]["resource_id"] for row in records
                if _load(row["result_json"])["body"]["outcome"] == "ok"}

    @staticmethod
    def _check_live(run: sqlite3.Row, approval: sqlite3.Row) -> None:
        if run["state"] != "active":
            raise ProxyError("skipped_after_failure")
        if approval["state"] != "active":
            raise ProxyError("approval_required")
        if _parse(run["deadline"]) <= _now() or _parse(run["approval_lease_expiry"]) <= _now():
            raise ProxyError("expired")
        if approval["expires_at"] is not None and _parse(approval["expires_at"]) <= _now():
            raise ProxyError("expired")

    @staticmethod
    def _prior_batch_failure(db: sqlite3.Connection, registration: sqlite3.Row) -> bool:
        previous = db.execute("SELECT result_json FROM call_registration WHERE run_id=? AND response_id=? "
                              "AND batch_index<? ORDER BY batch_index",
                              (registration["run_id"], registration["response_id"],
                               registration["batch_index"])).fetchall()
        for row in previous:
            if row[0] is None:
                raise ProxyError("invalid_args")
            if _load(row[0])["body"]["outcome"] == "error":
                return True
        return False

    def execute_call(self, call_digest: str, requested_tool: str) -> dict[str, Any]:
        """Execute one pre-registered call; stored result survives lost replies."""
        if requested_tool not in TOOL_NAMES:
            raise ProxyError("unknown_tool")
        with self._transaction() as db:
            registration = self._one(db, "SELECT * FROM call_registration WHERE call_digest=?", (call_digest,))
            if registration["tool"] != requested_tool:
                raise ProxyError("denied")
            run, task, approval = self._active_run(db, registration["run_id"], registration["fence"])
            if registration["result_json"] is not None:
                return _load(registration["result_json"])
            call = _load(self._one(db, "SELECT raw_json FROM staged_objects WHERE digest=?", (call_digest,))[0])
            body = call["body"]
            args = body["args"]
            key: str | None = None
            try:
                key = self._strict_args(requested_tool, args, self.registry, task["profile_id"])
                if not permits(_load(task["cap_json"]), requested_tool, args):
                    raise ProxyError("denied")
                if self._prior_batch_failure(db, registration):
                    raise ProxyError("skipped_after_failure")
                if key is not None:
                    previous = db.execute("SELECT args_digest, result_json FROM idempotency_results "
                                          "WHERE run_id=? AND tool=? AND idempotency_key=?",
                                          (run["run_id"], requested_tool, key)).fetchone()
                    if previous is not None:
                        if previous["args_digest"] != registration["args_digest"]:
                            raise ProxyError("version_conflict")
                        saved = _load(previous["result_json"])["body"]
                        result = (self._result(body["call_id"], requested_tool, data=saved["data"])
                                  if saved["outcome"] == "ok" else
                                  self._result(body["call_id"], requested_tool,
                                               error=ProxyError(saved["error_code"],
                                                                retryable=saved["retryable"])))
                        db.execute("UPDATE call_registration SET status='completed', result_json=? WHERE call_digest=?",
                                   (_json(result), call_digest))
                        return result
                self._check_live(run, approval)
                db.execute("SAVEPOINT tool_effect")
                try:
                    data = self._perform(db, run, task, approval, requested_tool, args)
                except (ProxyError, ProtocolError, UnicodeError, ValueError) as exc:
                    db.execute("ROLLBACK TO tool_effect")
                    db.execute("RELEASE tool_effect")
                    if isinstance(exc, ProxyError):
                        raise
                    raise ProxyError("validation_failed") from exc
                else:
                    db.execute("RELEASE tool_effect")
                result = self._result(body["call_id"], requested_tool, data=data)
            except ProxyError as error:
                result = self._result(body["call_id"], requested_tool, error=error)
            if key is not None:
                db.execute("INSERT OR IGNORE INTO idempotency_results VALUES (?, ?, ?, ?, ?)",
                           (run["run_id"], requested_tool, key, registration["args_digest"], _json(result)))
            status = "skipped" if result["body"].get("error_code") == "skipped_after_failure" else "completed"
            db.execute("UPDATE call_registration SET status=?, result_json=? WHERE call_digest=?",
                       (status, _json(result), call_digest))
            return result

    def _perform(self, db: sqlite3.Connection, run: sqlite3.Row, task: sqlite3.Row,
                 approval: sqlite3.Row, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        task_id = task["task_instance_id"]
        if tool == "read_resource":
            resource = self._resource(db, task_id, args["resource_id"])
            if resource["content"] is None or resource["access"] not in ("read", "read_write"):
                raise ProxyError("denied")
            raw = resource["content"]
            if digest_bytes(raw) != resource["bytes_digest"]:
                raise ProxyError("runtime_error")
            return {"content_utf8": raw.decode("utf-8"),
                    "source_bytes_digest": resource["bytes_digest"],
                    "rendered_bytes_digest": resource["bytes_digest"]}
        if tool == "build_artifact":
            output = self._resource(db, task_id, args["output_id"], "artifact")
            if output["version"] != 0 or output["content"] is not None:
                raise ProxyError("version_conflict")
            if args["transform_id"] != self.registry.profile(task["profile_id"])["operation"]:
                raise ProxyError("denied")
            bindings = args["input_bindings"]
            if not set(bindings.values()) <= self._read_ids(db, run["run_id"]):
                raise ProxyError("denied")
            inputs = self._input_bytes(db, task, bindings)
            raw = build_artifact(task["profile_id"], inputs, self.registry)
            db.execute("UPDATE resources SET content=?, bytes_digest=?, version=1 WHERE task_instance_id=? AND resource_id=?",
                       (raw, digest_bytes(raw), task_id, args["output_id"]))
            return {"artifact_version": 1, "artifact_digest": digest_bytes(raw)}
        if tool == "write_artifact":
            output = self._resource(db, task_id, args["output_id"], "artifact")
            if args["expected_version"] != output["version"]:
                raise ProxyError("version_conflict")
            raw = args["content_utf8"].encode("utf-8")
            if len(raw) > self.registry.profile(task["profile_id"])["max_output_bytes"]:
                raise ProxyError("invalid_args")
            version = output["version"] + 1
            db.execute("UPDATE resources SET content=?, bytes_digest=?, version=? WHERE task_instance_id=? AND resource_id=?",
                       (raw, digest_bytes(raw), version, task_id, args["output_id"]))
            return {"artifact_version": version, "artifact_digest": digest_bytes(raw)}
        if tool == "validate_artifact":
            output = self._resource(db, task_id, args["output_id"], "artifact")
            if output["content"] is None or output["version"] <= 0:
                raise ProxyError("not_found")
            if args["artifact_digest"] != output["bytes_digest"]:
                raise ProxyError("version_conflict")
            if args["check_set_id"] != f"{task['profile_id']}-strict-v1":
                raise ProxyError("denied")
            profile = self.registry.profile(task["profile_id"])
            inputs = self._input_bytes(db, task, profile["input_bindings"])
            validate_artifact(task["profile_id"], inputs, output["content"])
            issued = _now()
            expiry = min(issued + timedelta(seconds=300), _parse(run["deadline"]),
                         _parse(run["approval_lease_expiry"]))
            if expiry <= issued:
                raise ProxyError("expired")
            snapshot = digest_jcs([{ "resource_id": resource_id,
                                      "bytes_digest": digest_bytes(inputs[name])}
                                   for name, resource_id in sorted(profile["input_bindings"].items())])
            receipt_id = "receipt-" + uuid.uuid4().hex
            receipt = make_envelope("ValidationReceipt", {
                "receipt_id": receipt_id,
                "binding": {"artifact_id": args["output_id"], "artifact_version": output["version"],
                            "artifact_digest": output["bytes_digest"], "task_instance_id": task_id,
                            "run_id": run["run_id"], "subject_digest": task["subject_digest"]},
                "input_snapshot_digest": snapshot, "check_set_id": args["check_set_id"],
                "validator_digest": self.registry.capability_handshake()["implementation_digest"],
                "issued_at": _stamp(issued), "expires_at": _stamp(expiry),
                "run_deadline": run["deadline"], "approval_expiry": approval["expires_at"],
                "trust_revision": run["trust_revision"],
            })
            db.execute("INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (receipt_id, run["run_id"], args["output_id"], output["version"],
                        output["bytes_digest"], snapshot, args["check_set_id"], _stamp(expiry),
                        run["trust_revision"], _json(receipt)))
            return {"validation_receipt_id": receipt_id, "artifact_digest": output["bytes_digest"]}
        if tool == "prepare_publication":
            output = self._resource(db, task_id, args["output_id"], "artifact")
            self._resource(db, task_id, args["destination_id"], "sink")
            if args["artifact_digest"] != output["bytes_digest"]:
                raise ProxyError("version_conflict")
            receipt = self._one(db, "SELECT * FROM receipts WHERE receipt_id=? AND run_id=?",
                                (args["validation_receipt_id"], run["run_id"]))
            if (receipt["artifact_id"] != args["output_id"] or receipt["artifact_version"] != output["version"] or
                receipt["artifact_digest"] != output["bytes_digest"] or receipt["trust_revision"] != run["trust_revision"]):
                raise ProxyError("validation_failed")
            issued = _now()
            expiry = min(issued + timedelta(seconds=600), _parse(receipt["expires_at"]),
                         _parse(run["deadline"]), _parse(run["approval_lease_expiry"]))
            if expiry <= issued:
                raise ProxyError("expired")
            grant_ref = "grant-" + uuid.uuid4().hex
            action_digest = digest_jcs({"run_id": run["run_id"], "artifact_id": args["output_id"],
                                        "artifact_version": output["version"],
                                        "artifact_digest": output["bytes_digest"],
                                        "destination_id": args["destination_id"],
                                        "receipt_id": receipt["receipt_id"]})
            db.execute("INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                       (grant_ref, run["run_id"], args["output_id"], output["version"],
                        output["bytes_digest"], args["destination_id"], receipt["receipt_id"],
                        action_digest, _stamp(expiry)))
            return {"grant_ref": grant_ref, "action_digest": action_digest}
        if tool == "publish_artifact":
            output = self._resource(db, task_id, args["output_id"], "artifact")
            self._resource(db, task_id, args["destination_id"], "sink")
            if args["artifact_digest"] != output["bytes_digest"]:
                raise ProxyError("version_conflict")
            grant = self._one(db, "SELECT * FROM grants WHERE grant_ref=? AND run_id=?",
                              (args["grant_ref"], run["run_id"]))
            if grant["consumed"] or db.execute("SELECT 1 FROM publications WHERE task_instance_id=?", (task_id,)).fetchone():
                raise ProxyError("denied")
            if (grant["artifact_id"] != args["output_id"] or grant["destination_id"] != args["destination_id"] or
                grant["artifact_version"] != output["version"] or grant["artifact_digest"] != output["bytes_digest"] or
                grant["receipt_id"] != args["validation_receipt_id"]):
                raise ProxyError("validation_failed")
            if _parse(grant["expires_at"]) <= _now():
                raise ProxyError("expired")
            receipt = self._one(db, "SELECT * FROM receipts WHERE receipt_id=?", (grant["receipt_id"],))
            if _parse(receipt["expires_at"]) <= _now() or receipt["trust_revision"] != run["trust_revision"]:
                raise ProxyError("expired")
            publication_id = "publication-" + uuid.uuid4().hex
            now = _stamp(_now())
            db.execute("INSERT INTO publications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (task_id, publication_id, run["run_id"], args["grant_ref"], args["output_id"],
                        output["version"], output["bytes_digest"], args["destination_id"],
                        output["content"], now))
            db.execute("UPDATE grants SET consumed=1 WHERE grant_ref=?", (args["grant_ref"],))
            event_digest = digest_jcs({"publication_id": publication_id,
                                       "artifact_digest": output["bytes_digest"]})
            cursor = db.execute("INSERT INTO accepted_events(run_id,event_type,event_digest,committed_at) VALUES (?, 'publication', ?, ?)",
                                (run["run_id"], event_digest, now))
            db.execute("INSERT INTO outbox VALUES (?, ?, ?, NULL)",
                       (cursor.lastrowid, args["destination_id"], event_digest))
            db.execute("UPDATE runs SET state='finalizing' WHERE run_id=?", (run["run_id"],))
            return {"publication_id": publication_id, "artifact_digest": output["bytes_digest"]}
        raise ProxyError("unknown_tool")

    def revoke_approval(self, approval_digest: str, expected_revision: int,
                        *, operation_id: str, request_digest: str) -> dict[str, Any]:
        with self._transaction() as db:
            previous = self._operation_replay(db, operation_id, request_digest)
            if previous is not None:
                return previous
            current = self._one(db, "SELECT trust_revision FROM trust_state WHERE singleton=1", ())
            approval = self._one(db, "SELECT * FROM approvals WHERE approval_digest=?", (approval_digest,))
            if current[0] != expected_revision or approval["state"] != "active":
                raise ProxyError("version_conflict")
            new_revision = current[0] + 1
            now = _stamp(_now())
            db.execute("UPDATE trust_state SET trust_revision=? WHERE singleton=1", (new_revision,))
            db.execute("UPDATE approvals SET state='revoked', trust_revision=?, committed_at=? WHERE approval_digest=?",
                       (new_revision, now, approval_digest))
            event = digest_jcs({"approval_digest": approval_digest, "trust_revision": new_revision,
                                "state": "revoked"})
            db.execute("INSERT INTO accepted_events(run_id,event_type,event_digest,committed_at) VALUES (NULL,'approval_revoked',?,?)",
                       (event, now))
            result = {"approval_digest": approval_digest, "state": "revoked",
                      "trust_revision": new_revision, "committed_at": now,
                      "expires_at": approval["expires_at"]}
            self._record_operation(db, operation_id, "controller", None, request_digest, "revoke_approval", result)
            return result

    def cancel_run(self, run_id: str, expected_fence: int, *, operation_id: str,
                   request_digest: str) -> dict[str, Any]:
        with self._transaction() as db:
            previous = self._operation_replay(db, operation_id, request_digest)
            if previous is not None:
                return previous
            run = self._one(db, "SELECT * FROM runs WHERE run_id=?", (run_id,))
            if run["fence"] != expected_fence:
                raise ProxyError("stale_fence")
            new_fence = expected_fence + 1
            now = _stamp(_now())
            db.execute("UPDATE runs SET state='cancelled', fence=? WHERE run_id=?", (new_fence, run_id))
            event = digest_jcs({"run_id": run_id, "fence": new_fence, "state": "cancelled"})
            db.execute("INSERT INTO accepted_events(run_id,event_type,event_digest,committed_at) VALUES (?, 'run_cancelled', ?, ?)",
                       (run_id, event, now))
            result = {"run_id": run_id, "fence": new_fence, "committed_at": now,
                      "campaign_id": run["campaign_id"]}
            self._record_operation(db, operation_id, "controller", run_id, request_digest, "cancel_run", result)
            return result

    def recover_tool(self, run_id: str, tool: str, idempotency_key: str) -> dict[str, Any]:
        if tool not in TOOL_NAMES or not idempotency_key:
            raise ProxyError("invalid_args")
        # A WAL snapshot alone could report absence while a writer is about to
        # commit. Taking the writer lock makes absence authoritative.
        try:
            with self._transaction() as db:
                self._one(db, "SELECT run_id FROM runs WHERE run_id=?", (run_id,))
                row = db.execute("SELECT result_json FROM idempotency_results WHERE run_id=? AND tool=? AND idempotency_key=?",
                                 (run_id, tool, idempotency_key)).fetchone()
                return {"run_id": run_id, "state": "committed" if row else "proven_not_started",
                        "tool_result_digest": _load(row[0])["digest"] if row else None}
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                raise
            return {"run_id": run_id, "state": "unknown", "tool_result_digest": None}

    def get_operation(self, operation_id: str, role: str) -> dict[str, Any]:
        with closing(self._connect()) as db:
            row = self._one(db, "SELECT role, method, state, result_json FROM operations WHERE operation_id=?",
                            (operation_id,))
            if row["role"] != role:
                raise ProxyError("denied")
            kind = {"activate_approval": "ApprovalResult", "revoke_approval": "ApprovalResult",
                    "start_run": "Lease", "cancel_run": "CancellationResult"}.get(row["method"])
            result = _load(row["result_json"]) if row["result_json"] is not None else None
            return {"operation_ref": operation_id, "state": row["state"],
                    "result_kind": kind if row["state"] == "completed" else None,
                    "result_digest": digest_jcs(result) if result is not None and row["state"] == "completed" else None,
                    "error_code": None}

    def inspect_publication(self, task_instance_id: str) -> dict[str, Any] | None:
        """Trusted evaluator inspection; not mounted on runtime or model."""
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM publications WHERE task_instance_id=?", (task_instance_id,)).fetchone()
            return dict(row) if row is not None else None

    def inspect_publication_proof(self, task_instance_id: str) -> dict[str, Any] | None:
        """Read the committed publication and its durable grant and receipt chain."""
        with closing(self._connect()) as db:
            publication = db.execute("SELECT * FROM publications WHERE task_instance_id=?",
                                     (task_instance_id,)).fetchone()
            if publication is None:
                return None
            grant = db.execute("SELECT * FROM grants WHERE grant_ref=?",
                               (publication["grant_ref"],)).fetchone()
            receipt = db.execute("SELECT * FROM receipts WHERE receipt_id=?",
                                 (grant["receipt_id"],)).fetchone() if grant else None
            return {"publication": dict(publication),
                    "grant": dict(grant) if grant else None,
                    "receipt": dict(receipt) if receipt else None}
