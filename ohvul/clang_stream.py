"""Stream Clang JSON, retaining main-file bodies and function declarations.

This is a lossless projection for clang_facts' declared main-file scope, not a
replacement full AST. Header bodies become CompoundStmt sentinels so a defined
function still disables builtin assumptions. Every JSON token is validated;
unselected bodies are parsed and discarded, never truncated into a success.
Clang's repeated type fields in DISCARDED subtrees are counted but neither value
is interpreted. Retained evidence and all other duplicate fields stay strict.
"""
import codecs
import hashlib
import json
import re

FUNCTIONS = {'FunctionDecl','CXXMethodDecl','CXXConstructorDecl','CXXDestructorDecl'}
WS = re.compile(r'[ \t\r\n]*')
WORD = re.compile(r'[^ \t\r\n,\]}:{\[]+')
# Measured camera C++ dependencies exceed 512 MiB of pretty-printed tokens.
# Only a bounded projection is resident; raw stream, tokens, depth, strings,
# retained nodes/output, and compiler wall time remain independently bounded.
MAX_RAW_BYTES = 1024 * 1024 * 1024
MAX_STRING_CHARS = 2 * 1024 * 1024
MAX_TOKENS = 60000000
MAX_DEPTH = 300


class Reader:
    def __init__(self, stream):
        self.stream=stream
        self.buffer=''
        self.pos=0
        self.eof=False
        self.decoder=codecs.getincrementaldecoder('utf-8')('strict')
        self.raw_bytes=0
        self.raw_hash=hashlib.sha256()
        self.tokens=0
        self.discarded_duplicate_types=0

    def more(self):
        if self.eof: return False
        raw=self.stream.read(65536)
        self.raw_bytes+=len(raw)
        self.raw_hash.update(raw)
        if self.raw_bytes>MAX_RAW_BYTES:
            raise ValueError('streaming AST raw byte limit')
        self.eof=not raw
        self.buffer=self.buffer[self.pos:]+self.decoder.decode(raw,final=self.eof)
        self.pos=0
        return bool(raw)

    def peek(self):
        while True:
            self.pos=WS.match(self.buffer,self.pos).end()
            if self.pos<len(self.buffer): return self.buffer[self.pos]
            if not self.more(): return ''

    def take(self,char):
        if self.peek()!=char: raise ValueError('invalid streaming JSON punctuation')
        self.pos+=1
        self.tokens+=1
        if self.tokens>MAX_TOKENS: raise ValueError('AST token budget')

    def string(self):
        if self.peek()!='"': raise ValueError('JSON key/string required')
        while True:
            try:
                value,end=json.decoder.scanstring(self.buffer,self.pos+1)
            except ValueError:
                if len(self.buffer)-self.pos>MAX_STRING_CHARS or not self.more():
                    raise ValueError('invalid or excessive JSON string') from None
            else:
                if end-self.pos>MAX_STRING_CHARS: raise ValueError('AST string limit')
                self.pos=end
                self.tokens+=1
                return value

    def value(self,keep=True,depth=0):
        if depth>MAX_DEPTH: raise ValueError('streaming AST depth limit')
        char=self.peek()
        if char=='{':
            self.take('{'); result={} if keep else None; seen=set()
            if self.peek()=='}': self.take('}'); return result
            while True:
                key=self.string()
                if key in seen:
                    if not keep and key=='type':
                        self.discarded_duplicate_types+=1
                    else:
                        raise ValueError('duplicate JSON key '+key[:80]+' retained='+str(keep))
                seen.add(key)
                self.take(':'); item=self.value(keep,depth+1)
                if keep: result[key]=item
                if self.peek()=='}': self.take('}'); return result
                self.take(',')
        if char=='[':
            self.take('['); result=[] if keep else None
            if self.peek()==']': self.take(']'); return result
            while True:
                item=self.value(keep,depth+1)
                if keep: result.append(item)
                if self.peek()==']': self.take(']'); return result
                self.take(',')
        if char=='"':
            value=self.string(); return value if keep else None
        if not char: raise ValueError('unexpected JSON EOF')
        while True:
            match=WORD.match(self.buffer,self.pos)
            if not match: raise ValueError('invalid JSON primitive')
            if match.end()==len(self.buffer) and not self.eof:
                self.more(); continue
            text=match.group(); self.pos=match.end(); self.tokens+=1
            def invalid(x): raise ValueError('nonfinite JSON value')
            value=json.loads(text,parse_constant=invalid)
            return value if keep else None


def capture_main_ast(stream, source_bytes, compiler_file, *, output_limit, observation=None):
    reader=Reader(stream)
    observation={} if observation is None else observation
    retained=[]
    stats={'main_bodies':0,'header_bodies_omitted':0,'function_declarations':0}
    def main_function(value):
        loc=value.get('loc',{}); name=value.get('name',''); off=loc.get('offset')
        return (value.get('kind') in FUNCTIONS and isinstance(name,str) and name and
                'includedFrom' not in loc and 'spellingLoc' not in loc and
                loc.get('file',compiler_file)==compiler_file and type(off) is int and
                0<=off<len(source_bytes) and source_bytes[off:off+len(name.encode())]==name.encode())
    def node(depth=0):
        if depth>MAX_DEPTH: raise ValueError('streaming AST node depth limit')
        reader.take('{'); value={}; seen=set()
        if reader.peek()=='}': reader.take('}'); return value
        while True:
            key=reader.string()
            duplicate=key in seen
            unused_type=key=='type' and value.get('kind') not in FUNCTIONS|{'ParmVarDecl'}
            if duplicate and not unused_type:
                raise ValueError('duplicate AST node field '+key[:60]+' kind='+str(value.get('kind'))[:60])
            if duplicate:
                reader.discarded_duplicate_types+=1
            seen.add(key); reader.take(':')
            if key=='inner':
                # Clang's field order places identity/location before children.
                # Reject an unknown order instead of silently selecting no bodies.
                if 'kind' not in value: raise ValueError('AST kind must precede children')
                kind=value['kind']
                if main_function(value):
                    value['inner']=reader.value(True,depth+1)
                    stats['main_bodies']+=sum(x.get('kind')=='CompoundStmt' for x in value['inner'])
                elif kind.endswith('Decl'):
                    reader.take('['); inner=[]
                    if reader.peek()!=']':
                        while True:
                            child=node(depth+1)
                            if kind in FUNCTIONS and child.get('kind') in ('ParmVarDecl','BuiltinAttr','CompoundStmt'):
                                inner.append(child)
                            if reader.peek()==']': break
                            reader.take(',')
                    reader.take(']')
                    if kind in FUNCTIONS: value['inner']=inner
                else:
                    reader.value(False,depth+1)
                    if kind=='CompoundStmt':
                        stats['header_bodies_omitted']+=1
                        value['inner']=[]
            else:
                if unused_type:
                    reader.value(False,depth+1)
                else:
                    value[key]=reader.value(True,depth+1)
            if reader.peek()=='}': reader.take('}'); break
            reader.take(',')
        if value.get('kind') in FUNCTIONS:
            retained.append(value)
            if len(retained)>100000: raise ValueError('function declaration limit')
            stats['function_declarations']+=1
        return value
    try:
        root=node()
        if root.get('kind')!='TranslationUnitDecl' or reader.peek():
            raise ValueError('complete single translation unit required')
        projected={'kind':'TranslationUnitDecl','inner':retained}
        raw=json.dumps(projected,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
        if len(raw)>output_limit: raise ValueError('projected AST byte limit')
    except (ValueError,TypeError,RecursionError) as exc:
        observation['capture_error']=type(exc).__name__+': '+str(exc)[:200]
        raise
    finally:
        stats['discarded_duplicate_type_fields']=reader.discarded_duplicate_types
        observation.update(raw_bytes=reader.raw_bytes,raw_sha256=reader.raw_hash.hexdigest(),
                           projection='main_file_bodies_and_function_declarations',statistics=stats)
    return raw,observation
