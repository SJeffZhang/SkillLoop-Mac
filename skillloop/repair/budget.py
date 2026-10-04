"""Explicit forecast, append-only execution spending, and finalist admission."""

from __future__ import annotations

import json
import os
import time
import fcntl
import stat
from copy import deepcopy
from pathlib import Path

from skillloop.protocol import digest_jcs

MiB = 1024 ** 2
LIMITS = {"victim_attempts": 128, "retry_reserve": 2, "patch_rounds": 2,
          "input_tokens": 32000000, "output_tokens": 4300000,
          "wall_seconds": 28800, "disk_bytes": 2048 * MiB}


def _remaining_whole_seconds(state, reservation):
    """Retain every unused original slot, including later campaign stages."""
    if (type(reservation) is not dict or set(reservation)!=
            {'manifest_digest','campaign','victim_attempts','victim_seconds','terminal_seconds','stages'}
            or type(reservation['victim_attempts']) is not int
            or not 1<=reservation['victim_attempts']<=128
            or type(reservation['victim_seconds']) is not int or reservation['victim_seconds']<1
            or type(reservation['terminal_seconds']) is not int or reservation['terminal_seconds']<120
            or type(reservation['stages']) is not dict):
        raise ValueError('whole_round_complete_cost_reservation_required')
    victims=state['executions'];auxiliary=state.get('auxiliary_executions',[])
    if (len(victims)!=state['victim_attempts'] or len(victims)>reservation['victim_attempts']
            or any(e['stage'] not in reservation['stages'] for e in auxiliary)):
        raise ValueError('whole_round_actual_spending_count_changed')
    seconds=(reservation['victim_attempts']-len(victims))*reservation['victim_seconds']
    for stage,bound in reservation['stages'].items():
        if (type(bound) is not dict or set(bound)!={'count','seconds'}
                or any(type(n) is not int or n<1 for n in bound.values())):
            raise ValueError('whole_round_remaining_stage_bound')
        used=sum(e['stage']==stage for e in auxiliary)
        if used>bound['count']:raise ValueError('whole_round_remaining_stage_slots_exceeded')
        seconds+=(bound['count']-used)*bound['seconds']
    return seconds+reservation['terminal_seconds']


def forecast(items: list[dict], *, calibration: dict, stages: list[dict],
             retries_used: int = 0) -> dict:
    if type(calibration.get("victim_seconds")) not in (int, float) or calibration["victim_seconds"] <= 0:
        raise ValueError("invalid_calibration_bound")
    for stage in stages:
        if (type(stage.get("count")) is not int or stage["count"] < 0 or
                type(stage.get("seconds")) not in (int, float) or stage["seconds"] < 0 or
                any(type(stage.get(key)) is not int or stage[key] < 0
                    for key in ("input_tokens", "output_tokens", "disk_bytes"))):
            raise ValueError("invalid_stage_bound")
    keys = [(i["subject"], i["case"], i["repetition"], i["phase"]) for i in items]
    if len(keys) != len(set(keys)) or any(i["requirement"] not in {"required", "abandoned", "not_applicable"} for i in items):
        raise ValueError("plan_duplicate_or_requirement")
    if type(retries_used) is not int or not 0 <= retries_used <= 2:
        raise ValueError("retry_budget")
    required = [item for item in items if item["requirement"] == "required"]
    runs = len(required) + 2  # Both consumed retry slots and remaining slots count.
    input_tokens = runs * 16 * 14336 + sum(s["count"] * s["input_tokens"] for s in stages)
    output_tokens = runs * 16 * 2048 + sum(s["count"] * s["output_tokens"] for s in stages)
    wall = runs * calibration["victim_seconds"] + sum(s["count"] * s["seconds"] for s in stages)
    disk = runs * 8 * MiB + sum(s["count"] * s["disk_bytes"] for s in stages) + 512 * MiB
    reasons = []
    for key, value in {"victim_attempts": runs, "input_tokens": input_tokens,
                       "output_tokens": output_tokens, "wall_seconds": wall, "disk_bytes": disk}.items():
        if value > LIMITS[key]:
            reasons.append(key + "_exceeded")
    if not calibration.get("ready") or not calibration.get("evidence_digests"):
        reasons.append("calibration_pending")
    return {"planned_runs": len(required), "reserved_attempts": runs,
        "retries_consumed": retries_used, "retry_reserve_remaining": 2 - retries_used,
        "input_tokens": input_tokens, "output_tokens": output_tokens,
        "wall_seconds": wall, "disk_bytes": disk, "reasons": reasons,
        "admission": "ready" if not reasons else "rejected"}


def rows(subject: str, cases: dict, *, role: str = "candidate") -> list[dict]:
    return [{"subject": subject, "case": case["digest"], "repetition": rep,
             "phase": "dev", "role": role, "requirement": "required", "result_ref": None}
            for case in cases.values() for rep in range(case["body"]["repetitions"])]


def protected_reservations(subject: str, *, role: str) -> list[dict]:
    # Opaque capacity slots convey no M7 payload or guessed protected hashes.
    return [{"subject": subject, "case": f"protected-capacity-{index}", "repetition": rep,
             "phase": "protected", "role": role, "requirement": "required", "result_ref": None}
            for index in range(4) for rep in range(3)]


def revise(parent: dict | None, additions: list[dict]) -> dict:
    if parent and parent["digest"] != digest_jcs({key: value for key, value in parent.items() if key != "digest"}):
        raise ValueError("parent_plan_digest")
    items = deepcopy(parent["items"]) if parent else []
    items.extend(deepcopy(additions))
    keys = [(i["subject"], i["case"], i["repetition"], i["phase"]) for i in items]
    if len(keys) != len(set(keys)):
        raise ValueError("plan_revision_duplicate")
    result = {"revision": parent["revision"] + 1 if parent else 1,
        "parent_digest": parent["digest"] if parent else None, "items": items}
    return {**result, "digest": digest_jcs(result)}


def eliminate_protected_slots(parent: dict, subject: str, additions: list[dict]) -> dict:
    """Retain the eliminated subject's opaque reservations and all execution facts."""
    if parent["digest"] != digest_jcs({k: v for k, v in parent.items() if k != "digest"}):
        raise ValueError("parent_plan_digest")
    retained = deepcopy(parent)
    for item in retained["items"]:
        if item["subject"] == subject and item["phase"] == "protected":
            if item.get("result_ref") is not None:
                raise ValueError("protected_started_search_closed")
            item.update(requirement="abandoned", reason_code="eliminated_development_candidate")
    retained["digest"] = digest_jcs({k: v for k, v in retained.items() if k != "digest"})
    result = revise(retained, additions)
    result["parent_digest"] = parent["digest"]
    result["digest"] = digest_jcs({k: v for k, v in result.items() if k != "digest"})
    return result


class SpendingLedger:
    """Persist before execution; process restart never restores consumed slots."""
    def __init__(self, path: Path, *, victim_seconds: int = 200, campaign_started_at: float | None = None):
        if type(victim_seconds) is not int or victim_seconds <= 0:
            raise ValueError("invalid_execution_bound")
        if campaign_started_at is not None and (type(campaign_started_at) not in (int,float)
                or not 0<campaign_started_at<=time.time()):
            raise ValueError('campaign_original_real_clock_required')
        self.victim_seconds = victim_seconds
        self.campaign_started_at = campaign_started_at
        self.path = path
        self.started = time.monotonic()
        self.initial = self.read()
        if (self.initial['executions'] or self.initial.get('auxiliary_executions')) and self.initial.get('campaign_started_at') != campaign_started_at:
            raise ValueError('campaign_clock_changed')

    def read(self) -> dict:
        if os.path.lexists(self.path):
            fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'r') as stream:
                info=os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                        or info.st_mode&0o077 or info.st_size>2097152):
                    raise PermissionError('spending_ledger_custody')
                return json.load(stream)
        return {
            "victim_attempts": 0, "retries": 0, "elapsed_seconds": 0.0,
            "charged_wall_seconds": 0.0, "executions": []}

    def consume(self, item_key: str, attempt: int) -> dict:
        # All Controller processes share the same append-only spending decision.
        # Atomic rename alone did not prevent two readers spending the same slot.
        parent=self.path.parent.lstat()
        if self.path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.geteuid():
            raise PermissionError('spending_ledger_parent_custody')
        fd=os.open(str(self.path)+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
                raise PermissionError('spending_ledger_lock_custody')
            fcntl.flock(fd,fcntl.LOCK_EX)
            return self._consume_locked(item_key,attempt)
        finally:os.close(fd)

    def _consume_locked(self, item_key: str, attempt: int) -> dict:
        if type(attempt) is not int or attempt not in (0, 1):
            raise ValueError("invalid_attempt")
        state = self.read()
        if (state['executions'] or state.get('auxiliary_executions')) and state.get('campaign_started_at')!=self.campaign_started_at:
            raise ValueError('campaign_clock_changed')
        if state.get('execution_bound_seconds',self.victim_seconds)!=self.victim_seconds:
            raise ValueError('campaign_execution_bound_changed')
        scope=state.get('whole_round_victim_reservation')
        if scope is not None:
            if (type(scope) is not dict or set(scope)!={'attempts','terminal_seconds'}
                    or type(scope['attempts']) is not int or not 1<=scope['attempts']<=128
                    or type(scope['terminal_seconds']) is not int or scope['terminal_seconds']<120):
                raise ValueError('campaign_frozen_victim_reservation_invalid')
            if (state['victim_attempts']>=scope['attempts']
                    or time.time()-self.campaign_started_at+self.victim_seconds+scope['terminal_seconds']>28800
                    or state['charged_wall_seconds']+self.victim_seconds+scope['terminal_seconds']>28800):
                raise ValueError('campaign_frozen_victim_reservation_exhausted')
            complete=state.get('whole_round_cost_reservation')
            if (complete is None or complete['victim_seconds']!=self.victim_seconds
                    or time.time()-self.campaign_started_at+_remaining_whole_seconds(state,complete)>28800):
                raise ValueError('campaign_remaining_whole_round_cost_exhausted')
        if any(e["item_key"] == item_key and e["attempt"] == attempt for e in state["executions"]):
            raise ValueError("execution_already_spent")
        elapsed = self.initial["elapsed_seconds"] + time.monotonic() - self.started
        if self.campaign_started_at is not None:
            elapsed = max(elapsed, time.time() - self.campaign_started_at)
        if (state["victim_attempts"] >= 128 or elapsed >= 28800 or
                state["charged_wall_seconds"] + self.victim_seconds > 28800 or (attempt > 0 and state["retries"] >= 2)):
            raise ValueError("execution_budget_exhausted")
        state["victim_attempts"] += 1
        state["retries"] += int(attempt > 0)
        state["elapsed_seconds"] = max(state['elapsed_seconds'],elapsed)
        state['execution_bound_seconds']=self.victim_seconds
        state["campaign_started_at"] = self.campaign_started_at
        state["charged_wall_seconds"] += self.victim_seconds  # Conservative charge is durable before the worker starts.
        state["executions"].append({"item_key": item_key, "attempt": attempt})
        self._write(state)
        return state

    def _write(self, state):
        temporary = self.path.with_suffix(".tmp")
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as output:
            json.dump(state, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.path)
        directory_fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)

    def consume_auxiliary(self, *, manifest, campaign, stage, operation_key,
                          seconds, input_tokens, output_tokens, disk_bytes):
        """Spend an original whole-round auxiliary slot before external effects.

        The same durable clock/lock covers victims and auxiliary processes.
        Unknown creates and native responses remain spent. No automatic retry
        or new phase may replenish these slots.
        """
        from skillloop.runtime.round_manifest import validate_round_manifest
        validate_round_manifest(manifest)
        if os.geteuid()!=21001 or self.campaign_started_at is None:
            raise PermissionError('formal_auxiliary_original_controller_clock_required')
        if (type(operation_key) is not str or not 1<=len(operation_key)<=256
                or any(type(n) is not int or n<0 for n in
                       (seconds,input_tokens,output_tokens,disk_bytes)) or seconds<1):
            raise ValueError('formal_auxiliary_bound_required')
        scope=next((c for c in manifest['campaigns'] if c['campaign_digest']==campaign),None)
        if scope is None or stage not in scope['stages'] or self.victim_seconds!=scope['victim_seconds']:
            raise ValueError('formal_auxiliary_whole_round_scope')
        bounds=scope['stages'][stage]
        if any(n>bounds[k] for k,n in [('seconds',seconds),('input_tokens',input_tokens),
                                       ('output_tokens',output_tokens),('disk_bytes',disk_bytes)]):
            raise ValueError('formal_auxiliary_unreserved_cost')
        parent=self.path.parent.lstat()
        if self.path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=21001 or parent.st_mode&0o077:
            raise PermissionError('formal_auxiliary_ledger_custody')
        fd=os.open(str(self.path)+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=21001 or info.st_mode&0o077:
                raise PermissionError('spending_ledger_lock_custody')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            state=self.read()
            if ((state['executions'] or state.get('auxiliary_executions'))
                    and state.get('campaign_started_at')!=self.campaign_started_at):
                raise ValueError('campaign_clock_changed')
            binding={'manifest_digest':manifest['digest'],'campaign':campaign}
            if state.get('whole_round_binding',binding)!=binding:
                raise ValueError('formal_auxiliary_whole_round_changed')
            victim_reservation={'attempts':scope['reserved_victim_attempts'],
                                'terminal_seconds':scope['terminal_seconds']}
            if state.get('whole_round_victim_reservation',victim_reservation)!=victim_reservation:
                raise ValueError('formal_auxiliary_victim_reservation_changed')
            if state['victim_attempts']>victim_reservation['attempts']:
                raise ValueError('formal_auxiliary_prior_victim_reservation_exceeded')
            complete_reservation={'manifest_digest':manifest['digest'],'campaign':campaign,
                'victim_attempts':scope['reserved_victim_attempts'],'victim_seconds':scope['victim_seconds'],
                'terminal_seconds':scope['terminal_seconds'],
                'stages':{stage:{'count':cost['count'],'seconds':cost['seconds']}
                          for stage,cost in scope['stages'].items()}}
            if state.get('whole_round_cost_reservation',complete_reservation)!=complete_reservation:
                raise ValueError('formal_auxiliary_complete_cost_reservation_changed')
            executions=state.setdefault('auxiliary_executions',[])
            if any(e['operation_key']==operation_key for e in executions):
                raise ValueError('formal_auxiliary_already_spent_requires_recovery')
            if sum(e['stage']==stage for e in executions)>=bounds['count']:
                raise ValueError('formal_auxiliary_stage_slots_exhausted')
            elapsed=max(state['elapsed_seconds'],time.time()-self.campaign_started_at)
            if elapsed+_remaining_whole_seconds(state,complete_reservation)>28800:
                raise ValueError('formal_auxiliary_remaining_whole_round_cost_exhausted')
            # Charge the full frozen slot, including unused capacity, rather
            # than allowing smaller calls to expand the original reservation.
            if (elapsed+bounds['seconds']+scope['terminal_seconds']>28800
                    or state['charged_wall_seconds']+bounds['seconds']+scope['terminal_seconds']>28800):
                raise ValueError('formal_auxiliary_original_budget_exhausted')
            state.update(campaign_started_at=self.campaign_started_at,
                         whole_round_binding=binding,elapsed_seconds=elapsed,
                         whole_round_victim_reservation=victim_reservation,
                         whole_round_cost_reservation=complete_reservation)
            state['charged_wall_seconds']+=bounds['seconds']
            executions.append({'operation_key':operation_key,'stage':stage,
                'reserved_cost':deepcopy({k:v for k,v in bounds.items() if k!='count'}),
                'requested_cost':{'seconds':seconds,'input_tokens':input_tokens,
                                  'output_tokens':output_tokens,'disk_bytes':disk_bytes}})
            self._write(state)
            return deepcopy(executions[-1])
        finally:os.close(fd)


def freeze(*, subject: str, development_verdict: str, missing: list,
           unresolved_high: list, budget: dict, proposal_attempts: int,
           applied_candidates: int, evaluable_candidates: int, evidence_digest: str, repair_rounds: int = 1) -> dict:
    reasons = []
    if development_verdict != "pass" or missing or unresolved_high:
        reasons.append("development_gate_not_passed")
    if budget["admission"] != "ready":
        reasons.append("final_protected_matrix_not_admitted")
    if not (1 <= evaluable_candidates <= applied_candidates <= proposal_attempts and 1 <= repair_rounds <= 2
            and applied_candidates <= repair_rounds and proposal_attempts <= 2 * repair_rounds):
        reasons.append("repair_accounting_invalid")
    body = {"subject": subject, "status": "frozen" if not reasons else "not_frozen",
            "reasons": reasons, "development_gate_digest": evidence_digest,
            "budget_digest": digest_jcs(budget), "protected_evaluation": "not_started"}
    return {**body, "digest": digest_jcs(body)}
