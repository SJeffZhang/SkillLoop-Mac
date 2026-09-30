import unittest
from skillloop.runtime.ollama_bpe import split_native_chunks

PATTERN=r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?[\p{L}\p{M}]+|\p{N}| ?[^\s\p{L}\p{M}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+"

class NativeBPETests(unittest.TestCase):
    def test_qwen38_punctuation_boundary(self):
        self.assertEqual(split_native_chunks('rs\n  (e.g. ',PATTERN),['rs','\n','  ','(e','.g','.',' '])
    def test_letters_retain_last_whitespace(self):
        self.assertEqual(split_native_chunks('x  hello',PATTERN),['x',' ',' hello'])
