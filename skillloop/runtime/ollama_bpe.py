"""Count the pinned Ollama 0.33.3 x/tokenizer BPE implementation.

Its RE2 whitespace-boundary repair differs from the Hugging Face Split
pretokenizer for the Qwen3.8 pattern. Keep the original snapshot unchanged.
Reference: ollama/ollama v0.33.3 x/tokenizer/tokenizer_encode.go and _load.go.
"""
import json
import re
import unicodedata
from pathlib import Path
import regex
from tokenizers import Tokenizer


def split_native_chunks(text, pattern):
    rewritten=pattern.replace(r'\s+(?!\S)|\s+',r'\s+')
    # Go RE2's \s is ASCII; Unicode categories still follow the snapshot.
    converted=[];in_class=False;i=0
    while i<len(rewritten):
        if rewritten[i]=='\\' and i+1<len(rewritten):
            escaped=rewritten[i+1]
            if escaped=='s':converted.append(r'\t\n\f\r ' if in_class else r'[\t\n\f\r ]')
            else:converted.append(rewritten[i:i+2])
            i+=2;continue
        if rewritten[i]=='[':in_class=True
        elif rewritten[i]==']':in_class=False
        converted.append(rewritten[i]);i+=1
    rewritten=''.join(converted)
    matches=[[m.start(),m.end()] for m in regex.finditer(rewritten,text)]
    space_before_punctuation=r' ?[^\s\p{L}\p{N}]' in pattern
    for current,next_match in zip(matches,matches[1:]):
        current_text=text[current[0]:current[1]];next_text=text[next_match[0]:next_match[1]]
        if not current_text or not next_text or '\n' in current_text or '\r' in current_text or not current_text.isspace():continue
        first=next_text[0];shift_ascii=not unicodedata.category(first).startswith('L')
        if shift_ascii and (not space_before_punctuation or first.isnumeric() or first.isspace()):continue
        last=text[current[1]-1]
        if shift_ascii and last!=' ':continue
        current[1]-=1;next_match[0]=current[1]
    return [text[start:end] for start,end in matches if end>start]


class OllamaPinnedBPE:
    def __init__(self,path):
        snapshot=json.loads((Path(path)/'tokenizer.json').read_text())
        pre=snapshot['pre_tokenizer']
        self.pattern=next(p['pattern']['Regex'] for p in pre['pretokenizers'] if p['type']=='Split')
        self.special={p['content']:p['id'] for p in snapshot['added_tokens']}
        self.special_pattern=re.compile('('+'|'.join(re.escape(s) for s in sorted(self.special,key=len,reverse=True))+')')
        snapshot['pre_tokenizer']={'type':'ByteLevel','add_prefix_space':False,'trim_offsets':False,'use_regex':False}
        self.encoder=Tokenizer.from_str(json.dumps(snapshot))

    def count(self,text):
        count=0
        for part in self.special_pattern.split(text):
            if part in self.special:count+=1
            else:
                for chunk in split_native_chunks(part,self.pattern):
                    count+=len(self.encoder.encode(chunk,add_special_tokens=False).ids)
        return count
