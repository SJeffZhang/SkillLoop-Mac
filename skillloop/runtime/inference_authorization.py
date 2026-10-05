"""Minimal Gateway-to-Proxy inference custody, without DB or private plan mounts."""
from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import stat
from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs
from skillloop.runtime.local_packet import exchange_packet


class RuntimeInferenceAuthorization:
    def __init__(self, policy, path='/inference-authority/inference.sock'):
        if os.geteuid() != 21011 or policy['allowed_client_uid'] != 21002:
            raise PermissionError('runtime_inference_authorization_gateway_only')
        self.policy = policy
        self.path = Path(path)
        info = self.path.parent.lstat()
        if (not self.path.is_absolute() or self.path.parent.is_symlink()
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != 21003
                or info.st_gid != 21011 or stat.S_IMODE(info.st_mode) != 0o750):
            raise PermissionError('runtime_inference_authority_socket_custody')

    def _exchange(self, request, seconds):
        raw = exchange_packet(self.path, canonical_json_line(request), timeout=min(9, seconds),
            expected_server_uid=21003, maximum_bytes=262144)
        value = decode_json(raw)
        if type(value) is not dict or set(value) != {'ok','result'} or value['ok'] is not True:
            raise PermissionError('runtime_inference_authority_denied_or_unknown')
        if type(value['result']) is not dict:
            raise ValueError('runtime_inference_authority_response_shape')
        return value['result']

    def reserve(self, context, payload, input_tokens, seconds):
        fields = {'run_id','fencing_token','run_request_digest','task_binding_digest','round_index'}
        if type(context) is not dict or set(context) != fields:
            raise ValueError('runtime_inference_current_context_shape')
        request = {'kind':'RuntimeInferenceReservationRequest',**context,
            'deployment_epoch':self.policy['deployment_epoch'],'campaign_id':self.policy['campaign_id'],
            'config_digest':self.policy['config_digest'],
            'phase':'protected' if self.policy['kind']=='ProtectedNativeModelBridgePolicy' else 'dev',
            'messages_digest':digest_jcs(payload['messages']),'tools_digest':digest_jcs(payload['tools']),
            'payload_digest':digest_bytes(canonical_json_line(payload)),
            'deadline':(datetime.now(timezone.utc)+timedelta(seconds=min(9,seconds))).isoformat(),
            'input_tokens':input_tokens,'output_tokens':self.policy['max_output_tokens'],
            'model_identity':{k:self.policy[k] for k in ('model_id','model_manifest_digest','tokenizer_hashes')}}
        request['digest'] = digest_jcs(request)
        result = self._exchange(request, seconds)
        if (set(result) != {'kind','request_digest','deployment_epoch','run_id','round_index','fencing_token',
                'phase','deadline','reserved_at','redispatch_allowed','qualification_issued','request','digest'}
                or result['kind'] != 'ProxyRuntimeInferenceReserved'
                or result['digest'] != digest_jcs({k:v for k,v in result.items() if k != 'digest'})
                or any(result[k] != request[k] for k in
                       ('deployment_epoch','run_id','round_index','fencing_token','phase'))
                or result['request_digest'] != request['digest'] or result['request'] != request
                or result['redispatch_allowed'] is not False or result['qualification_issued'] is not False):
            raise ValueError('runtime_inference_original_reservation_binding')
        deadline = datetime.fromisoformat(result['deadline'].replace('Z','+00:00'))
        if deadline.tzinfo is None or deadline <= datetime.now(timezone.utc):
            raise TimeoutError('runtime_inference_reservation_expired_no_dispatch')
        return result

    def complete(self, reservation, raw, seconds):
        request = {'kind':'RuntimeInferenceCompletion',
            'deadline':(datetime.now(timezone.utc)+timedelta(seconds=min(9,seconds))).isoformat(),
            'request_digest':reservation['request_digest'],
                   'response_digest':digest_jcs(decode_json(raw)),'raw_response_digest':digest_bytes(raw)}
        result = self._exchange(request, seconds)
        if result != {'kind':'ProxyRuntimeInferenceRecorded','request_digest':request['request_digest'],
                      'response_digest':request['response_digest'],'raw_response_digest':request['raw_response_digest'],'redispatch_allowed':False}:
            raise ValueError('runtime_inference_original_response_binding')


def validate_inference_transport_manifest(plan):
    """Prove both actual mounts resolve to the same separately granted UDS root."""
    from pathlib import PurePosixPath
    roles = plan['roles']; directories = {d['path']:d for d in plan['directories']}
    proxy = roles['proxy']['config']
    gateway = roles['model_gateway']['config']
    if gateway['Cmd'] != ['-m','skillloop.runtime.model_bridge_service']:
        return
    def mounted(config, target):
        candidates = [m for m in config['HostConfig']['Mounts']
            if PurePosixPath(target).is_relative_to(PurePosixPath(m['Target']))]
        if not candidates:
            raise ValueError('inference_authority_actual_mount_required')
        mount = max(candidates, key=lambda m:len(PurePosixPath(m['Target']).parts))
        if mount.get('Type') != 'volume' or mount.get('Source') != plan['volume']:
            raise ValueError('inference_authority_same_deployment_volume_required')
        relative = PurePosixPath(target).relative_to(PurePosixPath(mount['Target']))
        original = PurePosixPath(mount['VolumeOptions']['Subpath']) / relative
        return mount, str(original)
    environment = dict(item.split('=',1) for item in proxy['Env'])
    config_path = environment.get('SKILLLOOP_PROXY_DEPLOYMENT')
    if not config_path:
        raise ValueError('inference_authority_proxy_deployment_document_required')
    _, original = mounted(proxy, config_path)
    matches = [d for d in plan['documents'] if
        str(PurePosixPath(d['directory'])/d['name']) == original]
    if len(matches) != 1 or matches[0]['value'].get('kind') != 'ProxyServiceDeployment':
        raise ValueError('inference_authority_proxy_document_binding')
    path = matches[0]['value'].get('inference_socket_directory')
    if type(path) is not str or not PurePosixPath(path).is_absolute():
        raise ValueError('inference_authority_proxy_endpoint_required')
    proxy_mount, proxy_root = mounted(proxy, path)
    gateway_mount, gateway_root = mounted(gateway, '/inference-authority')
    directory = directories.get(proxy_root)
    if (proxy_root != gateway_root or directory is None
            or directory['uid'] != 21003 or directory['gid'] != 21011
            or directory['mode'] != 0o750 or directory['privacy'] != 'opaque'
            or proxy_mount['ReadOnly'] is not False or gateway_mount['ReadOnly'] is not True
            or '21011' not in proxy['HostConfig']['GroupAdd']
            or gateway_mount['Target'] != '/inference-authority'
            or gateway_mount['VolumeOptions']['Subpath'] != proxy_root):
        raise PermissionError('inference_authority_separate_actual_socket_grant')
    if any(name != proxy_root and PurePosixPath(name).is_relative_to(PurePosixPath(proxy_root))
           for name in directories):
        raise PermissionError('inference_authority_no_private_descendants')
    _, policy_original = mounted(gateway, '/gateway-policy/policy.json')
    policies = [d['value'] for d in plan['documents'] if
        str(PurePosixPath(d['directory'])/d['name']) == policy_original]
    if len(policies)!=1:
        raise ValueError('inference_authority_actual_gateway_policy')
    policy=policies[0]
    if (policy.get('kind') not in {'NativeModelBridgePolicy','ProtectedNativeModelBridgePolicy'}
            or policy.get('campaign_id')!=plan['campaign_digest']
            or policy.get('deployment_epoch')!=plan['deployment_epoch']):
        raise ValueError('inference_authority_gateway_campaign_scope')
    if policy.get('allowed_client_uid') in {21006,21007}:
        mount,root=mounted(gateway,'/proposal-authority')
        owner=directories.get(root)
        if (owner is None or owner['uid']!=21001 or owner['gid']!=21011
                or owner['mode']!=0o750 or owner['privacy']!='development'
                or mount['ReadOnly'] is not True or mount['Target']!='/proposal-authority'
                or mount['VolumeOptions']['Subpath']!=root):
            raise PermissionError('proposal_authority_trusted_controller_directory')
        proposals=[d['value'] for d in plan['documents'] if d['value'].get('kind')=='FrozenNativeProposalDispatch'
            and d['value'].get('role_uid')==policy['allowed_client_uid']]
        for proposal in proposals:
            controller_mount,controller_root=mounted(roles['controller']['config'],proposal['inference_authority_directory'])
            if controller_root!=root or controller_mount['ReadOnly'] is not False:
                raise PermissionError('proposal_authority_actual_controller_gateway_binding')
        if not proposals:raise ValueError('proposal_authority_current_producer_required')



class ProposalInferenceAuthorization(RuntimeInferenceAuthorization):
    """Read a Controller-owned budget grant, then obtain live Proxy authority."""
    def __init__(self, policy, path='/inference-authority/inference.sock'):
        if os.geteuid()!=21011 or policy['allowed_client_uid'] not in {21006,21007}:
            raise PermissionError('proposal_inference_authorization_gateway_only')
        self.policy=policy;self.path=Path(path)
        info=self.path.parent.lstat()
        if (not self.path.is_absolute() or self.path.parent.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid!=21003 or info.st_gid!=21011 or stat.S_IMODE(info.st_mode)!=0o750):
            raise PermissionError('proposal_inference_authority_socket_custody')

    def reserve(self, context, payload, input_tokens, seconds):
        from skillloop.discovery.formal_task_gate import read_owned
        import re
        if (type(context) is not dict or set(context)!={'grant_digest','slot'} or context['slot']!=0
                or type(context['slot']) is not int or type(context['grant_digest']) is not str
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',context['grant_digest'])):
            raise ValueError('proposal_inference_current_grant_reference')
        grant=read_owned(Path('/proposal-authority')/(context['grant_digest'][7:]+'.json'),
            uid=21001,gid=21011,limit=262144)
        if (grant['digest']!=context['grant_digest'] or grant.get('kind')!='ControllerProposalInferenceGrant'
                or grant.get('role_uid')!=self.policy['allowed_client_uid']
                or any(grant.get(k)!=self.policy[k] for k in
                    ('deployment_epoch','campaign_id','config_digest','whole_round_manifest_digest'))
                or grant.get('deadline')!=self.policy['campaign_deadline']
                or grant.get('model_identity')!={k:self.policy[k] for k in ('model_id','model_manifest_digest','tokenizer_hashes')}
                or payload.get('tools')!=[]):
            raise PermissionError('proposal_inference_exact_controller_grant')
        request={'kind':'ProposalInferenceReservationRequest','grant':grant,
            'messages_digest':digest_jcs(payload['messages']),'tools_digest':digest_jcs(payload['tools']),
            'payload_digest':digest_bytes(canonical_json_line(payload)),'input_tokens':input_tokens,
            'deadline':(datetime.now(timezone.utc)+timedelta(seconds=min(9,seconds))).isoformat()}
        request['digest']=digest_jcs(request)
        result=self._exchange(request,seconds)
        if (set(result)!={'kind','request_digest','request','deadline','reserved_at','redispatch_allowed','qualification_issued','digest'}
                or result['kind']!='ProxyProposalInferenceReserved' or result['request']!=request
                or result['request_digest']!=request['digest']
                or result['digest']!=digest_jcs({k:v for k,v in result.items() if k!='digest'})
                or result['redispatch_allowed'] is not False or result['qualification_issued'] is not False):
            raise ValueError('proposal_inference_original_reservation_binding')
        deadline=datetime.fromisoformat(result['deadline'].replace('Z','+00:00'))
        if deadline.tzinfo is None or deadline<=datetime.now(timezone.utc):
            raise TimeoutError('proposal_inference_original_grant_expired')
        return result

    def complete(self,reservation,raw,seconds):
        request={'kind':'ProposalInferenceCompletion','request_digest':reservation['request_digest'],
            'response_digest':digest_jcs(decode_json(raw)),'raw_response_digest':digest_bytes(raw),
            'deadline':(datetime.now(timezone.utc)+timedelta(seconds=min(9,seconds))).isoformat()}
        result=self._exchange(request,seconds)
        if result!={'kind':'ProxyProposalInferenceRecorded','request_digest':request['request_digest'],
                'response_digest':request['response_digest'],'raw_response_digest':request['raw_response_digest'],'redispatch_allowed':False}:
            raise ValueError('proposal_inference_original_response_binding')
