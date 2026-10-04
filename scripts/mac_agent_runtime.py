"""Agent entry: one immutable request, restricted sockets, private evidence."""
import json,os,sys,stat,re
from pathlib import Path
from skillloop.discovery.mutation import RenderedMutation
from skillloop.runtime.adapter import AgentAdapter
from skillloop.runtime.client import ProxyClient
from skillloop.runtime.gateway import ExactLocalTokenizer,OllamaGateway
from skillloop.protocol import decode_json,digest_jcs,validate_envelope

def read_current_request():
    """Read one Runtime-owned task; never accept a suite or future-task list."""
    fd=os.open('/current/current-request.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode)
                or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode)) not in
                    {(21002,21002,0o400),(21004,21002,0o640)} or before.st_nlink!=1
                or not 1<=before.st_size<=8388608):
            raise PermissionError('runtime_current_request_custody')
        raw=stream.read(8388609);after=os.fstat(stream.fileno())
    if (len(raw)!=before.st_size or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            !=(after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
        raise ValueError('runtime_current_request_changed')
    current=decode_json(raw)
    parent=Path('/current').lstat()
    if before.st_uid==21004 and (Path('/current').is_symlink() or not stat.S_ISDIR(parent.st_mode)
            or (parent.st_uid,parent.st_gid,stat.S_IMODE(parent.st_mode))!=(21004,21002,0o750)):
        raise PermissionError('private_runtime_current_directory_custody')
    if type(current) is not dict or type(current.get('config')) is not dict:
        raise ValueError('runtime_current_request_shape')
    config=current['config']
    if 'whole_flow_required' in config and type(config['whole_flow_required']) is not bool:
        raise ValueError('runtime_whole_flow_flag')
    if config.get('whole_flow_required') is True:
        fields={'kind','digest','profile','skill','request','binding','config','mutation','attempt',
                'deployment','proxy_server_uid','run_lease','trust_revision','package_resources'}
        private = current.get('kind') == 'FormalPrivateCurrentRuntimeRequest'
        if private:
            fields.add('model_lifecycle_digest')
        expected_custody = (21004,21002,0o640) if private else (21002,21002,0o400)
        if (set(current)!=fields or current['kind'] not in
                {'FormalCurrentRuntimeRequest','FormalPrivateCurrentRuntimeRequest'}
                or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode)) != expected_custody
                or current['digest']!=digest_jcs({k:v for k,v in current.items() if k!='digest'})
                or os.geteuid()!=21002 or current['proxy_server_uid']!=21003
                or current['skill'] is not None or current['deployment']!=config.get('deployment_epoch')
                or type(current['attempt']) is not int or current['attempt']!=0):
            raise ValueError('formal_runtime_current_request_identity')
        request=validate_envelope(current['request']);binding=validate_envelope(current['binding'])
        lease=validate_envelope(current['run_lease'])
        if (request['kind']!='RunRequest' or binding['kind']!='TaskBinding' or lease['kind']!='Lease'
                or request['body']['config_digest']!=digest_jcs(config)
                or request['body']['subject_digest']!=binding['body']['subject_digest']
                or request['body']['authorization_domain_digest']!=binding['body']['domain_digest']
                or lease['body']['run_id']!=binding['body']['run_id']):
            raise ValueError('formal_runtime_current_request_pins')
    elif before.st_uid != 21002:
        raise PermissionError('private_runtime_requires_formal_contract')
    return current

def main():
    os.umask(0o077)
    current=read_current_request();config=current['config']
    if current.get('kind') == 'FormalPrivateCurrentRuntimeRequest':
        from skillloop.discovery.formal_task_gate import read_owned
        identity = read_owned('/model-bridge/backend-identity.json', uid=21011, gid=21002, limit=262144)
        if (not re.fullmatch(r'sha256:[0-9a-f]{64}',current.get('model_lifecycle_digest',''))
                or identity.get('kind') != 'NativeModelBackendIdentity'
                or identity.get('gateway_uid') != 21011
                or identity.get('fresh_backend_lifecycle_verified') is not True
                or identity.get('lifecycle_review_digest') != current['model_lifecycle_digest']
                or identity.get('tokenizer_hashes') != config['tokenizer_hashes']):
            raise ValueError('private_runtime_reviewed_model_lifecycle_required')
    context=config.get('max_context_tokens',config.get('context_tokens',16384))
    output=config.get('max_output_tokens',config.get('output_tokens',2048))
    if (type(context) is not int or type(output) is not int or not 0<output<context
            or ('context_tokens' in config and config['context_tokens']!=context)
            or ('output_tokens' in config and config['output_tokens']!=output)
            or config.get('max_rounds',16)!=16 or config.get('max_tool_calls',12)!=12):
        raise ValueError('runtime_frozen_limits_mismatch')
    native_peer=config.get('model_gateway_uid')
    if config.get('whole_flow_required') and native_peer!=21011:
        raise ValueError('formal_native_gateway_peer_required')
    pins=config.get('tokenizer_hashes')
    if config.get('whole_flow_required') and not pins:
        raise ValueError('formal_frozen_tokenizer_snapshot_required')
    tokenizer=ExactLocalTokenizer('/model',expected_hashes=pins if config.get('whole_flow_required') else None)
    try:
        gateway=OllamaGateway('http://127.0.0.1:11434',tokenizer,
            model=config['model_id'],template_overhead_tokens=config['ollama_template_overhead_tokens'],
            max_context_tokens=context,max_output_tokens=output,
            timeout_seconds=config['provider_timeout_seconds'],unix_socket_path='/model-bridge/model.sock',expected_server_uid=native_peer)
        peer_uid=current.get('proxy_server_uid')
        if type(peer_uid) is not int or peer_uid<0:raise ValueError('trusted_proxy_server_uid_required')
        adapter=AgentAdapter(proxy=ProxyClient(Path('/socket'),expected_server_uid=peer_uid),gateway=gateway,private_root=Path('/evidence'))
        selected=current.get('package_resources')
        execute=adapter.run if selected is None else adapter.run_imported
        if selected is None:
            materials={'skill_bytes':current['skill'].encode()}
        else:
            if type(selected) is not dict or set(selected)!={'instruction','references'}:
                raise ValueError('runtime_selected_package_shape')
            materials={'instruction_resource_id':selected['instruction'],'reference_resource_ids':selected['references']}
        lease=current.get('run_lease')
        if lease is not None:
            from skillloop.proxy.store import _parse,_now
            validate_envelope(lease)
            if (lease['kind']!='Lease' or lease['body']['run_id']!=current['binding']['body']['run_id']
                    or lease['body']['state']!='active' or _parse(lease['body']['expires_at'])<=_now()):
                raise ValueError('runtime_expired_or_wrong_lease')
            if config.get('whole_flow_required') is True:
                seconds=config.get('agent_deadline_seconds')
                if (type(seconds) is not int or not 1<=seconds<=300
                        or (_parse(lease['body']['expires_at'])-_now()).total_seconds()<=seconds):
                    raise ValueError('runtime_actual_lease_cannot_fit_agent')
            fence=lease['body']['fencing_token'];revision=current['trust_revision']
            if type(revision) is not int or revision<1:raise ValueError('runtime_trust_revision')
        elif config.get('whole_flow_required'):
            raise ValueError('runtime_actual_lease_required')
        else:
            fence=revision=1  # Explicit legacy-only path, never a formal whole round.
        result=execute(
            profile_id=current['profile'],**materials,run_request=current['request'],
            task_binding=current['binding'],fence=fence,trust_revision=revision,deployment_epoch=current['deployment'],
            deadline_seconds=config['agent_deadline_seconds'],attempt_index=current['attempt'],
            instruction_suffix=config.get('agent_instruction_suffix',''),
            record_terminal_output=config.get('whole_flow_required') is True,
            rendered_mutation=RenderedMutation(**current['mutation']) if current['mutation'] else None)
        from skillloop.protocol import canonical_json_line
        fd=os.open('/evidence/adapter-result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(result));stream.flush();os.fsync(stream.fileno())
        fd=os.open('/evidence',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        primary=sys.exc_info()[1]
        try:tokenizer.close()
        except BaseException as error:
            if primary is None:raise
            primary.add_note('runtime_tokenizer_cleanup_error:'+type(error).__name__)

if __name__=='__main__':
    try:
        main()
    except BaseException as error:
        # Docker logs are deliberately unavailable to Controller for private
        # tasks. Preserve details in Runtime's current evidence custody instead.
        import traceback
        try:
            root=Path('/evidence');info=root.lstat()
            if (root.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=21002
                    or info.st_mode & 0o077):
                raise PermissionError('runtime_failure_private_evidence_directory')
            fd=os.open(root/'runtime-failure.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            details=''.join(traceback.format_exception(error)).encode('utf-8')
            with os.fdopen(fd,'wb') as stream:
                stream.write(details[:1048576]);stream.flush();os.fsync(stream.fileno())
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        except BaseException as secondary:
            error.add_note('runtime_failure_custody_requires_recovery:'+type(secondary).__name__)
        raise
