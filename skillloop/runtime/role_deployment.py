"""Shared production deployment policy for isolated private role actions.

This producer builds the actual Engine configuration used by the dispatcher.
It does not provision missing services or grant arbitrary role/entry access.
"""
import re
from skillloop.protocol import digest_jcs

ROLE_UIDS={'controller':21001,'runtime':21002,'proxy':21003,'evaluator':21004,
    'gate':21005,'generator':21006,'patcher':21007,'scanner':21008,'reporter':21009,
    'admin':21010,'gateway':21011}
PRIVATE_ENTRIES={
    'session':('evaluator','skillloop.protection.formal_session'),
    'task_gate':('gate','skillloop.discovery.formal_task_gate'),
    'retirement_gate':('gate','skillloop.runtime.private_retirement'),
}


def private_role_configuration(*,entry,image,deployment_epoch,action_digest,mounts,groups,maximum_bytes,timeout_seconds):
    if (entry not in PRIVATE_ENTRIES or not re.fullmatch(r'sha256:[0-9a-f]{64}',image)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',action_digest)
            or type(deployment_epoch) is not str or not deployment_epoch
            or type(maximum_bytes) is not int or maximum_bytes<=0
            or type(timeout_seconds) is not int or not 1<=timeout_seconds<=300):
        raise ValueError('private_deployment_frozen_identity')
    role,module=PRIVATE_ENTRIES[entry];uid=ROLE_UIDS[role]
    if (type(mounts) is not list or not mounts or len({m['Target'] for m in mounts})!=len(mounts)
            or type(groups) is not list or any(g not in {'21001','21002','21003','21004','21005'} for g in groups)):
        raise ValueError('private_deployment_mount_or_group_policy')
    # Gate receives only read mounts except its own separately granted output.
    writable={'/reviews','/retirement-grants'} if role=='gate' else {
        '/private','/session-projection','/evaluation','/private-task-inbox',
        '/private-launch-inbox','/runtime-current','/gate-authority','/private-raw','/evaluation-assignment','/archive'}
    for mount in mounts:
        if (set(mount)!={'Type','Source','Target','ReadOnly','VolumeOptions'} or mount['Type']!='volume'
                or type(mount['ReadOnly']) is not bool or mount['Target'] not in writable and not mount['ReadOnly']):
            raise ValueError('private_deployment_role_write_boundary')
    return {'Image':image,'User':str(uid)+':'+str(uid),'Entrypoint':['python'],'Cmd':['-m',module],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code',
            'SKILLLOOP_PRIVATE_ACTION_DIGEST='+action_digest,
            'SKILLLOOP_PRIVATE_MAX_EVIDENCE_BYTES='+str(maximum_bytes),
            'SKILLLOOP_PRIVATE_TIMEOUT_SECONDS='+str(timeout_seconds)],
        'Labels':{'skillloop.deployment_epoch':deployment_epoch,'skillloop.role':'private_session',
                  'skillloop.action':action_digest},
        'HostConfig':{'GroupAdd':sorted(set(groups)),'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,'NanoCpus':2000000000,
            'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'LogConfig':{'Type':'none','Config':{}},'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
