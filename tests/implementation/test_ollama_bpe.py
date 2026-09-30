import unittest
from skillloop.runtime.ollama_bpe import split_native_chunks

PATTERN=r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?[\p{L}\p{M}]+|\p{N}| ?[^\s\p{L}\p{M}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+"

class NativeBPETests(unittest.TestCase):
    def test_qwen38_punctuation_boundary(self):
        self.assertEqual(split_native_chunks('rs\n  (e.g. ',PATTERN),['rs','\n','  ','(e','.g','.',' '])
    def test_letters_retain_last_whitespace(self):
        self.assertEqual(split_native_chunks('x  hello',PATTERN),['x',' ',' hello'])

    def test_native_encoder_keeps_decomposed_unicode(self):
        import json,tempfile
        from pathlib import Path
        from tokenizers import Tokenizer,models,pre_tokenizers,normalizers,AddedToken
        from skillloop.runtime.ollama_bpe import OllamaPinnedBPE
        vocab={character:index for index,character in enumerate(pre_tokenizers.ByteLevel.alphabet())}
        tokenizer=Tokenizer(models.BPE(vocab=vocab,merges=[]));tokenizer.normalizer=normalizers.NFC()
        tokenizer.add_special_tokens([AddedToken('[marker]',special=True)])
        value=json.loads(tokenizer.to_str());value['pre_tokenizer']={'type':'Sequence','pretokenizers':[{'type':'Split','pattern':{'Regex':PATTERN},'behavior':'Isolated','invert':False},{'type':'ByteLevel','add_prefix_space':False,'trim_offsets':False,'use_regex':False}]}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory,'tokenizer.json').write_text(json.dumps(value))
            self.assertEqual(OllamaPinnedBPE(directory).count('e\u0301'),3)

    def test_go_contractions_do_not_use_unicode_case_folding(self):
        self.assertEqual(split_native_chunks("'ſomething",PATTERN),["'ſomething"])
