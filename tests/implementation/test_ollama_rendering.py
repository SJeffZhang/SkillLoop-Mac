import unittest
from skillloop.runtime.gateway import ExactLocalTokenizer

class RenderingTests(unittest.TestCase):
    def test_nested_tool_arguments_match_native_renderer_without_mutating_source(self):
        class Tokenizer:
            def apply_chat_template(self, messages, **kwargs):
                self.messages = messages
                return [1]
        tokenizer=ExactLocalTokenizer.__new__(ExactLocalTokenizer)
        tokenizer._tokenizer=Tokenizer()
        messages=[{'role':'assistant','content':'build','tool_calls':[{'function':{'name':'build_artifact','arguments':{'input_bindings':{'z':'<&>','a':'资源'},'expected_version':0}}}]}]
        tokenizer.count(messages,[],enable_thinking=False)
        args=tokenizer._tokenizer.messages[0]['tool_calls'][0]['function']['arguments']
        self.assertEqual(args['input_bindings'],'{"a":"资源","z":"\\u003c\\u0026\\u003e"}')
        self.assertIsInstance(messages[0]['tool_calls'][0]['function']['arguments']['input_bindings'],dict)

    def test_native_failed_response_remains_observable(self):
        from skillloop.discovery.evaluator import response_output_bytes
        raw={'message':{'role':'assistant','content':'DEV_ONLY_MARKER','tool_calls':[{'function':{'name':'build_artifact','arguments':{'secret':'DEV_ONLY_MARKER'}}}]}}
        self.assertIn(b'DEV_ONLY_MARKER',response_output_bytes(raw))
        self.assertEqual(response_output_bytes({'error':'provider failed'}),b'')

    def test_openai_response_remains_observable(self):
        from skillloop.discovery.evaluator import response_output_bytes
        raw={'choices':[{'message':{'content':'hello','tool_calls':[{'function':{'arguments':'{"secret":"DEV_ONLY_MARKER"}'}}]}}]}
        self.assertIn(b'DEV_ONLY_MARKER',response_output_bytes(raw))
