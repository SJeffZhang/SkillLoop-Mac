"""Gate rechecks actual semantic HTTP evidence and the pinned raw scanner report."""
import base64,os,stat
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.discovery.scanner import reduce_scan
from skillloop.protocol import decode_json,digest_bytes
from skillloop.runtime.gateway import ExactLocalTokenizer


def review_semantic(directory,*,snapshot,profile,whole,raw_sink=None):
    if os.geteuid()!=21005:raise PermissionError('semantic_review_actual_gate')
    root=Path(directory)
    job=read_owned(root/'assignment.json',uid=21011,gid=21001,limit=2097152)
    value=read_owned(root/'discovery.json',uid=21011,gid=21001,limit=8388608)
    originals=[{'path':root/'assignment.json','uid':21011,'gid':21001,'limit':2097152,'value':job},
        {'path':root/'discovery.json','uid':21011,'gid':21001,'limit':8388608,'value':value}]
    policy=job['model_policy']
    if (job['kind']!='FormalGatewaySemanticDiscovery' or job['source_snapshot']!=snapshot
            or job['profile']!=profile or job['whole_round_manifest_digest']!=whole['digest']
            or value.get('kind')!='GatewaySemanticDiscoveryEvidence'
            or value['assignment_digest']!=job['digest'] or value['source_snapshot_digest']!=snapshot['digest']
            or value['backend_identity']['model_manifest_digest']!=policy['model_manifest_digest']
            or type(value['model_requests']) is not int or not 1<=value['model_requests']<=policy['max_chat_requests']
            or len(value['usage_records'])!=value['model_requests']):
        raise ValueError('semantic_review_current_model_source_binding')
    expected_files={'assignment.json','discovery.json','raw-report.json'}|{prefix+str(slot)+'.json' for slot in range(value['model_requests']) for prefix in ('request-','response-')}
    if {p.name for p in root.iterdir()}!=expected_files:
        raise ValueError('semantic_review_unknown_or_unreviewed_attempt')
    tokenizer=ExactLocalTokenizer('/model',expected_hashes=policy['tokenizer_hashes'])
    try:
        for slot in range(value['model_requests']):
            request=read_owned(root/('request-'+str(slot)+'.json'),uid=21011,gid=21001,limit=2097152)
            response=read_owned(root/('response-'+str(slot)+'.json'),uid=21011,gid=21001,limit=12582912)
            for prefix,document,limit in (('request-',request,2097152),('response-',response,12582912)):
                originals.append({'path':root/(prefix+str(slot)+'.json'),'uid':21011,
                                  'gid':21001,'limit':limit,'value':document})
            raw=base64.b64decode(request['raw_b64'],validate=True);body=decode_json(raw)
            actual=decode_json(base64.b64decode(response['raw_b64'],validate=True))
            tokens=tokenizer.count(body['messages'],[],enable_thinking=False)
            if (request.get('scope_digest')!=job['digest'] or response.get('scope_digest')!=job['digest']
                    or request['slot']!=slot or response['slot']!=slot or response['http_status']!=200
                    or response['request_digest']!=digest_bytes(raw) or body.get('tools') or body.get('think') is not False
                    or body.get('options')!={'temperature':policy['temperature'],'top_p':policy['top_p'],'num_ctx':16384,'num_predict':policy['max_output_tokens']}
                    or body.get('stream') is not False or body.get('model')!=policy['model_id'] or actual.get('model')!=policy['model_id']
                    or actual.get('done') is not True or actual.get('done_reason')!='stop'
                    or actual.get('message',{}).get('thinking') or actual.get('message',{}).get('tool_calls')
                    or actual.get('prompt_eval_count')!=tokens or tokens+policy['max_output_tokens']>16384
                    or type(actual.get('eval_count')) is not int or not 0<=actual['eval_count']<=policy['max_output_tokens']):
                raise ValueError('semantic_review_original_inference_incomplete')
    finally:tokenizer.close()
    from skillloop.discovery.raw_evidence import read_granted_raw
    raw=read_granted_raw(root/'raw-report.json',uid=21011,gid=21001,limit=33554432)
    report,findings,_=reduce_scan(profile,raw,value['scanner_report']['body']['upstream_exit_code'],
        subject_digest=snapshot['body']['skill_digest'],require_llm=True,allow_risk_exit=True)
    if report!=value['scanner_report'] or findings!=value['findings'] or report['body']['status']!='complete':
        raise ValueError('semantic_review_real_analyzer_coverage_incomplete')
    originals.append({'path':root/'raw-report.json','uid':21011,'gid':21001,
                      'limit':33554432,'bytes_digest':digest_bytes(raw)})
    if raw_sink is not None:raw_sink(originals)
    return report,findings,value['digest']
