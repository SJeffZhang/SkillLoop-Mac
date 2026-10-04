"""Native controller transport into a separately bound Linux resource proxy.

Docker exec runs the existing UDS client in its Linux kernel. The inspected
container ID prevents name reuse between inspect and exec. This transport
requires trusted Docker access and is never exposed to an agent.
"""
import json
import re
import subprocess
from skillloop.protocol import canonical_json_line, decode_json, digest_jcs


class DockerExecResourceAdmission:
    def __init__(self, *, container, image, plan_digest, source_digest,
                 deployment_epoch):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', container):
            raise ValueError('resource_container_name')
        self.container = container
        self.image = image
        self.labels = {'skillloop.role': 'resource-controller',
            'skillloop.resource-plan': plan_digest,
            'skillloop.dispatcher-source': source_digest,
            'skillloop.deployment-epoch': deployment_epoch}
        self.plan_digest = plan_digest

    def _call(self, operation, entry):
        if entry['digest'] != digest_jcs({k: v for k, v in entry.items() if k != 'digest'}):
            raise ValueError('resource_entry_digest')
        inspected = subprocess.run(['docker', 'inspect', self.container],
            capture_output=True, text=True, timeout=10)
        if inspected.returncode:
            raise ValueError('resource_container_identity')
        values = json.loads(inspected.stdout)
        if len(values) != 1:
            raise ValueError('resource_container_identity')
        c = values[0]
        identifier = c.get('Id', '')
        if (not re.fullmatch(r'[0-9a-f]{64}', identifier) or
                c.get('Image') != self.image or not c.get('State', {}).get('Running') or
                c.get('Config', {}).get('User') != '21001:21001' or
                any(c.get('Config', {}).get('Labels', {}).get(k) != v for k, v in self.labels.items()) or
                not c.get('HostConfig', {}).get('ReadonlyRootfs') or
                c.get('HostConfig', {}).get('NetworkMode') != 'none'):
            raise ValueError('resource_container_identity')
        message = {'operation': operation, 'entry': entry,
                   'expected_plan_digest': self.plan_digest}
        result = subprocess.run(['docker', 'exec', '-i', '--user', '21001:21001', identifier,
                                 'python', '/resource-client.py'],
            input=canonical_json_line(message).decode(), capture_output=True,
            text=True, timeout=20)
        if result.returncode:
            # No local state claims success; the Linux journal preserves unknowns.
            raise RuntimeError('resource_exec_failed')
        response = decode_json(result.stdout.encode())
        if (response.get('digest') != digest_jcs({k: v for k, v in response.items() if k != 'digest'}) or
                response.get('operation') != operation or
                response.get('entry_digest') != entry['digest'] or
                response.get('plan_digest') != self.plan_digest):
            raise ValueError('resource_exec_response')
        return response['result']

    def reserve(self, entry):
        return self._call('reserve', entry)

    def release(self, entry):
        return self._call('release', entry)
