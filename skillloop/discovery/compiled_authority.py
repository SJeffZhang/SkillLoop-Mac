"""Read the actual Gate-produced current public development compilation."""
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs


def current_compilation(path,*,campaign_id,config):
    value=read_owned(path,uid=21005,gid=21001,limit=8388608)
    if (value.get('kind')!='GateProducedDevelopmentSuite' or value.get('campaign_id')!=campaign_id
            or value.get('config_digest')!=digest_jcs(config)
            or value.get('deployment_epoch')!=config.get('deployment_epoch')
            or value.get('qualification_issued') is not False
            or value['scanner_report']['body']['status']!='complete'
            or value['compiled']['suite']['body']['visibility']!='public_dev'):
        raise ValueError('development_current_gate_compilation_required')
    return value['compiled']
