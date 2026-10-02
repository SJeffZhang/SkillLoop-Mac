"""Agent entry: one immutable request, restricted sockets, private evidence."""
import json,os
from pathlib import Path
from skillloop.discovery.mutation import RenderedMutation
from skillloop.runtime.adapter import AgentAdapter
from skillloop.runtime.client import ProxyClient
from skillloop.runtime.gateway import ExactLocalTokenizer,OllamaGateway

def main():
    os.umask(0o077)
    current=json.loads(Path('/current/current-request.json').read_text());config=current['config']
    gateway=OllamaGateway('http://127.0.0.1:11434',ExactLocalTokenizer('/model'),
        model=config['model_id'],template_overhead_tokens=config['ollama_template_overhead_tokens'],
        timeout_seconds=config['provider_timeout_seconds'],unix_socket_path='/model-bridge/model.sock')
    result=AgentAdapter(proxy=ProxyClient(Path('/socket')),gateway=gateway,private_root=Path('/evidence')).run(
        profile_id=current['profile'],skill_bytes=current['skill'].encode(),run_request=current['request'],
        task_binding=current['binding'],fence=1,trust_revision=1,deployment_epoch=current['deployment'],
        deadline_seconds=config['agent_deadline_seconds'],attempt_index=current['attempt'],
        instruction_suffix=config.get('agent_instruction_suffix',''),
        rendered_mutation=RenderedMutation(**current['mutation']) if current['mutation'] else None)
    Path('/evidence/adapter-result.json').write_text(json.dumps(result))

if __name__=='__main__':main()
