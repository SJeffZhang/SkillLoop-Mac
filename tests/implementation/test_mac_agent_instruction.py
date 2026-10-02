"""Trusted frozen runtime config instruction forwarding; no model calls."""
import json,unittest
from unittest.mock import patch,MagicMock
from scripts import mac_agent_runtime as module

class AgentInstructionTests(unittest.TestCase):
 def run_main(self, extra):
  current={'config':{'model_id':'model','ollama_template_overhead_tokens':0,'provider_timeout_seconds':1,'agent_deadline_seconds':2,**extra},'profile':'orders_total','skill':'synthetic','request':{},'binding':{},'deployment':'new-epoch','attempt':0,'mutation':None}
  adapter=MagicMock();adapter.run.return_value={'synthetic':True}
  with patch.object(module.Path,'read_text',return_value=json.dumps(current)),patch.object(module.Path,'write_text'),patch.object(module,'AgentAdapter',return_value=adapter),patch.object(module,'OllamaGateway'),patch.object(module,'ExactLocalTokenizer'),patch.object(module,'ProxyClient'):
   module.main()
  return adapter.run.call_args.kwargs
 def test_default_preserves_empty_instruction(self):
  self.assertEqual(self.run_main({})['instruction_suffix'],'')
 def test_frozen_instruction_forwarded_exactly(self):
  instruction='After publish_artifact succeeds, return a final answer. Do not call tools again.'
  self.assertEqual(self.run_main({'agent_instruction_suffix':instruction})['instruction_suffix'],instruction)

if __name__=='__main__':unittest.main()
