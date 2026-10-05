"""Native Mac model data transport in the actual frozen gateway UID.

This process owns no tool socket, task DB or private suite. It does not issue
qualification or establish fresh backend lifecycle merely by reading tags.
"""
from datetime import datetime,timezone
import os
from pathlib import Path
import signal
import threading
import stat
import time

from deploy.scanner.qwen_relay import HostModelBridge
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line, decode_json, digest_jcs
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.runtime.round_manifest import read_round_manifest


def backend_identity(policy):
    observed={}
    campaign_end=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if campaign_end.tzinfo is None:raise ValueError('native_backend_identity_original_clock')
    allowance=min(10,(campaign_end-datetime.now(timezone.utc)).total_seconds()-120)
    if allowance<=0:raise TimeoutError('native_backend_identity_original_clock')
    end=time.monotonic()+allowance
    for name,path in (('version','/api/version'),('models','/api/tags')):
        from skillloop.runtime.model_http import request_model
        remaining=end-time.monotonic()
        if remaining<=0:raise TimeoutError('native_backend_identity_original_clock')
        status, raw = request_model(f"http://{policy['model_host']}:{policy['model_port']}",
            path, None, timeout=min(5,remaining), method='GET', maximum_bytes=1048576)
        if time.monotonic()>=end:raise TimeoutError('native_backend_identity_original_clock')
        if status!=200 or len(raw)>1048576:raise ValueError('native_backend_identity_unavailable')
        observed[name]=decode_json(raw)
    if observed['version'].get('version')!=policy['backend_version']:
        raise ValueError('native_backend_version_changed')
    matched=[m for m in observed['models']['models'] if m.get('name')==policy['model_id']]
    if len(matched)!=1 or 'sha256:'+matched[0]['digest']!=policy['model_manifest_digest']:
        raise ValueError('native_backend_model_manifest_changed')
    return {'backend_version':observed['version']['version'],'model_id':policy['model_id'],
            'model_manifest_digest':policy['model_manifest_digest']}


def main():
    os.umask(0o077)
    if os.geteuid()!=21011:raise PermissionError('native_model_gateway_actual_uid')
    policy=read_owned('/gateway-policy/policy.json',uid=21010,gid=21011,limit=262144)
    required={'kind','whole_round_manifest_digest','source_digest','model_id','model_manifest_digest',
        'backend_version','model_host','model_port','allowed_client_uid','max_chat_requests','campaign_deadline',
        'request_timeout_seconds','tokenizer_hashes','temperature','top_p','max_output_tokens','digest'}
    protected = policy.get('kind') == 'ProtectedNativeModelBridgePolicy'
    protected_fields = {'campaign_id', 'deployment_epoch', 'config_digest', 'source_index_digest', 'lifecycle_grant_digest'}
    if (set(policy)!=(required | protected_fields if protected else required)
            or policy['kind'] not in {'NativeModelBridgePolicy', 'ProtectedNativeModelBridgePolicy'}
            or policy['model_host'] not in {'127.0.0.1','host.docker.internal'}
            or type(policy['model_port']) is not int or not 1024<=policy['model_port']<=65535
            or policy['allowed_client_uid'] not in {21002,21006,21007}
            or type(policy['request_timeout_seconds']) is not int or not 1<=policy['request_timeout_seconds']<=180
            or policy['backend_version']!='0.33.3'):
        raise ValueError('native_model_gateway_policy')
    whole=read_round_manifest('/whole-round/manifest.json')
    from scripts.dgx_m6_repair import source_index
    if (policy['whole_round_manifest_digest']!=whole['digest'] or policy['source_digest']!=whole['source_digest']
            or policy['source_digest']!=digest_jcs(source_index(Path(__file__).resolve().parents[2]))):
        raise ValueError('native_model_gateway_source_or_whole_round_changed')
    lifecycle_grant = None
    if protected:
        if policy['allowed_client_uid'] != 21002:
            raise PermissionError('protected_gateway_runtime_only')
        lifecycle_grant = read_owned('/lifecycle-review/backend-grant.json', uid=21005, gid=21011, limit=262144)
        if (lifecycle_grant.get('kind') != 'GateNativeBackendGrant'
                or lifecycle_grant.get('phase') != 'protected' or lifecycle_grant.get('gate_uid') != 21005
                or lifecycle_grant['digest'] != policy['lifecycle_grant_digest']
                or any(lifecycle_grant.get(k) != policy[k] for k in ('campaign_id', 'deployment_epoch',
                    'config_digest', 'source_index_digest', 'campaign_deadline', 'backend_version', 'model_id',
                    'model_manifest_digest', 'tokenizer_hashes', 'model_port'))
                or lifecycle_grant.get('qualification_issued') is not False):
            raise ValueError('protected_gateway_independent_native_lifecycle_required')
        campaigns = [c for c in whole['campaigns'] if c['campaign_digest'] == policy['campaign_id']]
        if len(campaigns) != 1 or policy['deployment_epoch'] != whole['deployment_epoch']:
            raise ValueError('protected_gateway_whole_campaign_binding')
    deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['request_timeout_seconds']+120:
        raise TimeoutError('native_model_gateway_original_budget')
    # Native tokenizer pins are checked BEFORE the model snapshot is loaded.
    tokenizer=ExactLocalTokenizer('/model',expected_hashes=policy['tokenizer_hashes'])
    stop=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
    try:
        observed=backend_identity(policy)
        record={'kind':'NativeModelBackendIdentity','policy_digest':policy['digest'],
            'gateway_uid':21011,'observed':observed,'tokenizer_hashes':tokenizer.snapshot_hashes,
            'observed_at':datetime.now(timezone.utc).isoformat(),'fresh_backend_lifecycle_verified':protected,
            'lifecycle_grant_digest': None if lifecycle_grant is None else lifecycle_grant['digest'],
            'lifecycle_review_digest': None if lifecycle_grant is None else lifecycle_grant['lifecycle_review_digest']}
        record['digest']=digest_jcs(record)
        root=Path('/model-bridge')
        info=root.lstat()
        if (root.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=21011
                or info.st_gid!=policy['allowed_client_uid'] or stat.S_IMODE(info.st_mode)!=0o750):
            raise PermissionError('native_gateway_bridge_directory_custody')
        fd=os.open(root/'backend-identity.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
        with os.fdopen(fd,'wb') as stream:
            os.fchown(stream.fileno(),-1,policy['allowed_client_uid']);os.fchmod(stream.fileno(),0o640)
            stream.write(canonical_json_line(record));stream.flush();os.fsync(stream.fileno())
        with HostModelBridge(root/'model.sock',model_host=policy['model_host'],model_port=policy['model_port'],
                model_id=policy['model_id'],backend='ollama',native_chat=True,tokenizer=tokenizer,
                allowed_client_uid=policy['allowed_client_uid'],max_chat_requests=policy['max_chat_requests'],
                temperature=policy['temperature'],top_p=policy['top_p'],max_output_tokens=policy['max_output_tokens'],
                request_timeout_seconds=policy['request_timeout_seconds'],campaign_deadline=policy['campaign_deadline']) as bridge:
            while not stop.is_set():
                left=(deadline-datetime.now(timezone.utc)).total_seconds()
                if left<=60:break
                stop.wait(min(1,left-60))
            if bridge._inference_lock.locked() or bridge.inference_unresolved.is_set():
                raise RuntimeError('native_model_inference_unresolved_preserve_backend_lifecycle')
    finally:tokenizer.close()


if __name__=='__main__':
    try:
        main()
    except BaseException as error:
        # Preserve detailed failure locally; protected Docker logs are disabled.
        import traceback
        try:
            root=Path('/model-bridge');info=root.lstat()
            if (root.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=21011
                    or info.st_gid not in {21002,21006,21007} or stat.S_IMODE(info.st_mode)!=0o750):
                raise PermissionError('gateway_failure_bridge_custody')
            fd=os.open(root/'gateway-failure.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:
                os.fchown(stream.fileno(),-1,info.st_gid);os.fchmod(stream.fileno(),0o640)
                stream.write(''.join(traceback.format_exception(error)).encode('utf-8')[:1048576])
                stream.flush();os.fsync(stream.fileno())
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        except BaseException as secondary:
            error.add_note('gateway_failure_custody_requires_recovery:'+type(secondary).__name__)
        raise
