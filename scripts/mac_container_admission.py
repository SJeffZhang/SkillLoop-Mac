"""Trusted controller for one real Mac container admission run."""
import argparse,json,os,sqlite3
from pathlib import Path
from deploy.scanner.qwen_relay import HostModelBridge
from scripts.dgx_m5_development import run_one
from skillloop.discovery.suite import m5b_config
from skillloop.protection.mac_runtime import container_execute
from scripts.dgx_m6_calibrate import probe_suite
from skillloop.runtime.gateway import ExactLocalTokenizer

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);parser.add_argument('--socket-volume',required=True);parser.add_argument('--model-volume',required=True);parser.add_argument('--profile',default='orders_total');parser.add_argument('--candidate-root',type=Path);parser.add_argument('--capacity-case',choices=['clean-a','secret-leak']);parser.add_argument('--config-file',type=Path);parser.add_argument('--model-port',type=int,default=11434);args=parser.parse_args()
    os.umask(0o077)
    config={**m5b_config(),'config_id':'mac-network-none-admission-v1','model_id':'qwen3.8:27b-mxfp8',
        'deployment_epoch':'mac-network-none-admission-1','tokenizer_path':'/model','ollama_template_overhead_tokens':0,'agent_deadline_seconds':235,
        'proxy_deadline_seconds':255,'worker_deadline_seconds':265,'mac_runtime_image':args.image,
        'gateway_backend':'ollama'}
    if args.config_file:config=json.loads(args.config_file.read_text())
    resources={'socket_volume':args.socket_volume,'model_volume':args.model_volume}
    def execute(*positional):return container_execute(*positional,resource_context=resources)
    case=args.profile+'.'+(args.capacity_case or 'clean-a')
    options={}
    if args.capacity_case:
        if args.candidate_root is None:raise ValueError('capacity_candidate_required')
        compiled,inputs,plan=probe_suite(args.profile,args.candidate_root,runtime_config=config,runtime_profile_path=Path('/code/specs/mac/runtime-profile.json'))
        options={'compiled_suite':compiled,'skill_root':args.candidate_root,'execution_plan':plan,'inputs_override':inputs,'campaign_id':'m6-calibration-'+args.profile}
    output=Path('/work')/case
    with HostModelBridge(Path('/bridge/model.sock'),model_port=args.model_port,model_id=config['model_id'],
                         backend='ollama',native_chat=True,max_chat_requests=16,tokenizer=ExactLocalTokenizer('/model')) as bridge:
        os.chown('/bridge/model.sock',21002,21002)
        result=run_one(case,0,output,runtime_config=config,gateway_backend='ollama',
            gateway_url='http://127.0.0.1:11434',runtime_executor=execute,runtime_uid=21002,
            socket_directory=Path('/interfaces'),deployment_epoch=config['deployment_epoch'],**options)
    with sqlite3.connect(output/'authority.db') as source,sqlite3.connect(output/'authority.backup.db') as target:
        source.backup(target)
        if target.execute('PRAGMA integrity_check').fetchone()!=('ok',):raise ValueError('backup_integrity_failure')
    (output/'admission-result.json').write_text(json.dumps({'scope':'diagnostic_not_formal_M6','result':result,'model_requests':bridge.chat_requests,'consistent_sqlite_backup':True},indent=2))
    print(json.dumps(result),flush=True)

if __name__=='__main__':main()
