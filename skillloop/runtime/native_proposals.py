"""Real role-owned native inference for untrusted development proposals."""
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import stat
import re

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs
from skillloop.runtime.gateway import OllamaGateway, ExactLocalTokenizer, GatewayError


class NativeProposalSession:
    def __init__(self, *, policy_path, gateway, evidence_directory):
        uid = os.geteuid()
        if uid not in {21006,21007} or type(gateway) is not OllamaGateway:
            raise PermissionError('native_proposal_actual_role_and_gateway_required')
        path = Path(policy_path)
        parent = path.parent.lstat()
        if (not path.is_absolute() or path.parent.is_symlink() or parent.st_uid != 21001
                or parent.st_gid != uid or stat.S_IMODE(parent.st_mode) != 0o750):
            raise PermissionError('native_proposal_controller_policy_required')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21001 or info.st_gid!=uid
                    or stat.S_IMODE(info.st_mode)!=0o640 or info.st_size>262144):
                raise PermissionError('native_proposal_policy_custody')
            policy = decode_json(stream.read(262145))
        if (type(policy) is not dict or set(policy)!= {'kind','role_uid','whole_round_manifest_digest',
                'campaign_deadline','max_requests','request_timeout_seconds','model_config',
                'source_digest','model_manifest_digest','tokenizer_hashes','digest'}
                or policy['kind']!='NativeProposalPolicy' or policy['role_uid']!=uid
                or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
                or type(policy['max_requests']) is not int or not 1<=policy['max_requests']<=128
                or type(policy['request_timeout_seconds']) is not int
                or not 1<=policy['request_timeout_seconds']<=180):
            raise ValueError('native_proposal_policy_binding')
        for name in ('whole_round_manifest_digest','source_digest','model_manifest_digest'):
            if type(policy[name]) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',policy[name]):
                raise ValueError('native_proposal_identity_digest_required')
        from scripts.dgx_m6_repair import source_index
        if digest_jcs(source_index(Path(__file__).resolve().parents[2]))!=policy['source_digest']:
            raise ValueError('native_proposal_actual_source_changed')
        deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
        if (deadline.tzinfo is None or not 0<(deadline-datetime.now(timezone.utc)).total_seconds()<=28800):
            raise ValueError('native_proposal_original_clock_required')
        model=policy['model_config']
        expected={'model':gateway.model,'max_context_tokens':gateway.max_context_tokens,
            'max_output_tokens':gateway.max_output_tokens,'template_overhead_tokens':gateway.template_overhead_tokens,
            'temperature':gateway.temperature,'top_p':gateway.top_p,'thinking':False,'gateway_uid':21011}
        if (model!=expected or type(gateway.tokenizer) is not ExactLocalTokenizer
                or gateway.expected_server_uid!=21011
                or gateway.max_context_tokens!=16384
                or not gateway.tokenizer.snapshot_hashes
                or gateway.tokenizer.snapshot_hashes!=policy['tokenizer_hashes']
                or gateway.max_output_tokens!=(512 if uid==21006 else 1024)
                or gateway.temperature!=(0.7 if uid==21006 else 0.2) or gateway.top_p!=0.9):
            raise ValueError('native_proposal_frozen_model_mismatch')
        from skillloop.runtime.gateway import verify_tokenizer_snapshot
        verify_tokenizer_snapshot(gateway.tokenizer.model_path,policy['tokenizer_hashes'])
        self.root=Path(evidence_directory);info=self.root.lstat()
        if (not self.root.is_absolute() or self.root.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o700):
            raise PermissionError('native_proposal_evidence_owner')
        identity=self.root/'session-policy.json'
        if os.path.lexists(identity):
            info=identity.lstat()
            if (identity.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=uid
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>262144
                    or decode_json(identity.read_bytes())!=policy):
                raise ValueError('native_proposal_session_policy_changed')
        else:self._save(identity,policy)
        self.policy,self.gateway,self.deadline=policy,gateway,deadline

    def _save(self, path, value):
        raw=canonical_json_line(value)
        if len(raw)>8388608:raise ValueError('native_proposal_evidence_capacity')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

    def _original(self, name):
        path=self.root/name
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid()
                    or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600
                    or not 0<before.st_size<=8388608):
                raise PermissionError('native_proposal_original_record_custody')
            raw=stream.read(8388609);after=os.fstat(stream.fileno());current=path.lstat()
        identity=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if len(raw)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(current):
            raise ValueError('native_proposal_original_record_changed')
        return decode_json(raw)

    def _next_slot(self,messages):
        names={p.name for p in self.root.iterdir()}
        requests={name for name in names if name.startswith('request-')}
        if requests!={'request-'+str(i)+'.json' for i in range(len(requests))}:
            raise ValueError('native_proposal_noncontiguous_original_attempts')
        for slot in range(len(requests)):
            intent=self._original('request-'+str(slot)+'.json')
            if (type(intent) is not dict or intent.get('kind')!='NativeProposalIntent'
                    or intent.get('policy_digest')!=self.policy['digest'] or intent.get('slot')!=slot):
                raise ValueError('native_proposal_original_attempt_identity')
            response_name='response-'+str(slot)+'.json'
            if response_name not in names or 'response-'+str(slot)+'-unknown.json' in names:
                raise RuntimeError('native_proposal_original_attempt_unknown_no_dispatch')
            response=self._original(response_name)
            if (type(response) is not dict or response.get('policy_digest')!=self.policy['digest']
                    or response.get('spent') is not True or type(response.get('response')) is not dict):
                raise ValueError('native_proposal_original_response_identity')
            if intent.get('messages')==messages:
                raise RuntimeError('native_proposal_original_completed_request_no_redelivery')
        responses={name for name in names if name.startswith('response-')}
        if responses!={'response-'+str(i)+'.json' for i in range(len(requests))}:
            raise RuntimeError('native_proposal_unmatched_original_response_no_dispatch')
        return len(requests)

    def complete(self, messages):
        left=(self.deadline-datetime.now(timezone.utc)).total_seconds()
        timeout=self.policy['request_timeout_seconds']
        if left<=timeout+60:raise TimeoutError('native_proposal_full_original_budget_required')
        fd=os.open(self.root/'spending.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
                raise PermissionError('native_proposal_spending_owner')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            slot=self._next_slot(messages)
            if slot>=self.policy['max_requests']:raise ValueError('native_proposal_reserved_budget_exhausted')
            self._save(self.root/('request-'+str(slot)+'.json'), {'kind':'NativeProposalIntent',
                'policy_digest':self.policy['digest'],'slot':slot,'messages':messages,
                'reserved_input_tokens':self.gateway.max_context_tokens-self.gateway.max_output_tokens,
                'reserved_output_tokens':self.gateway.max_output_tokens,'reserved_seconds':timeout})
            # Keep the lock through the real request: this role cannot create a
            # second concurrent native inference or reclaim an unknown attempt.
            try:
                response,prompt,latency=self.gateway.complete(messages,[],remaining_seconds=timeout)
            except GatewayError as error:
                self._save(self.root/('response-'+str(slot)+'-unknown.json'),
                    {'error_code':str(error),'response':error.response,'spent':True,'retry_allowed':False})
                raise
            self._save(self.root/('response-'+str(slot)+'.json'),
                {'policy_digest':self.policy['digest'],'response':response,
                 'actual_prompt_tokens':prompt,'latency_seconds':latency,'spent':True})
            return response, canonical_json_line(response)
        finally:os.close(fd)
