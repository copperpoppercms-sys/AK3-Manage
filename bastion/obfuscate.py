"""Static source obfuscation. Uploaded code is parsed, never executed here."""
import hashlib
import re
import secrets
from dataclasses import dataclass

from . import _lua_parser as a

MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 8 * MAX_INPUT
PROTECTION = "source-v1"


class ObfuscationError(ValueError):
    pass


@dataclass(frozen=True)
class Protected:
    source: bytes
    original_size: int
    original_sha256: str
    renamed: int
    encoded_strings: int
    protection: str = PROTECTION


class BindingParser(a.Parser):
    def __init__(self, source):
        super().__init__(source)
        if len(self.toks) > 200000:
            raise ObfuscationError("The script exceeds the 200,000-token protection limit.")
        self.bindings = {}

    def declare_at(self, token):
        local = self.declare(token[1])
        self.bindings.setdefault(local, []).append(token[2])
        return local

    def name_expr(self, name):
        node = super().name_expr(name)
        local = getattr(node, "local")
        if local in self.bindings:
            self.bindings[local].append(self.toks[self.p - 1][2])
        return node

    def statement(self):
        if self.kw("local"):
            self.next()
            if self.accept("kw", "function"):
                token = self.expect("name")
                local = self.declare_at(token)
                return a.LocalFunc(local, self.funcbody(False))
            tokens = [self.expect("name")]
            while self.accept("op", ","):
                tokens.append(self.expect("name"))
            expressions = self.exprlist() if self.accept("op", "=") else []
            return a.LocalStmt([self.declare_at(token) for token in tokens], expressions)
        if self.kw("goto") or self.check("op", "::"):
            raise ObfuscationError("Labels, goto and type assertions are not supported by this source protector.")
        return super().statement()

    def funcbody(self, is_method):
        self.expect("op", "(")
        self.nfunc += 1
        saved, self.func = self.func, self.nfunc
        fid = self.nfunc
        self.scopes.append({})
        params, vararg = [], False
        if is_method:
            # Colon syntax implicitly declares self; leave that binding intact.
            params.append(self.declare("self"))
        if not self.check("op", ")"):
            while True:
                if self.accept("op", "..."):
                    vararg = True
                    break
                params.append(self.declare_at(self.expect("name")))
                if not self.accept("op", ","):
                    break
        self.expect("op", ")")
        body = self.block()
        self.expect("kw", "end")
        self.scopes.pop()
        self.func = saved
        return a.Func(params, vararg, body, is_method, fid)

    def forstat(self):
        self.next()
        first = self.expect("name")
        if self.accept("op", "="):
            start = self.expr()
            self.expect("op", ",")
            stop = self.expr()
            step = self.expr() if self.accept("op", ",") else None
            self.expect("kw", "do")
            self.scopes.append({})
            var = self.declare_at(first)
            body = self.block()
            self.scopes.pop()
            self.expect("kw", "end")
            return a.NumFor(var, start, stop, step, body)
        tokens = [first]
        while self.accept("op", ","):
            tokens.append(self.expect("name"))
        self.expect("kw", "in")
        expressions = self.exprlist()
        self.expect("kw", "do")
        self.scopes.append({})
        variables = [self.declare_at(token) for token in tokens]
        body = self.block()
        self.scopes.pop()
        self.expect("kw", "end")
        return a.GenFor(variables, expressions, body)


def protect(source):
    if not isinstance(source, bytes) or not 1 <= len(source) <= MAX_INPUT or b"\0" in source:
        raise ObfuscationError("Protect a text Lua/Luau script between 1 byte and 1 MB.")
    try:
        source.decode("utf-8")
    except UnicodeError:
        raise ObfuscationError("The uploaded file must be UTF-8 text.") from None
    text = source.removeprefix(b"\xef\xbb\xbf").decode("latin1")
    try:
        parser = BindingParser(text)
        tree = parser.parse_chunk()
    except ObfuscationError:
        raise
    except (a.ParseError, ValueError, OverflowError, RecursionError):
        raise ObfuscationError("Unsupported or invalid Lua/Luau syntax. This version does not support type annotations, backtick strings or Luau if-expressions. The original file was not changed.") from None
    tokens = parser.toks[:-1]
    # Name-dependent debugger operations cannot preserve their original meaning.
    if any(tokens[i][1] == "debug" and tokens[i+1][1] == "." and tokens[i+2][1] in ("getlocal", "setlocal") for i in range(max(0,len(tokens)-2))):
        raise ObfuscationError("Scripts using debug.getlocal/debug.setlocal are not supported by local-variable renaming.")
    reserved = {token[1] for token in tokens if token[0] == "name"}
    replacements = {}
    renamed = 0
    for local, positions in parser.bindings.items():
        if local.name == "_ENV":
            continue
        name = "_0x" + secrets.token_hex(5)
        while name in reserved:
            name = "_0x" + secrets.token_hex(5)
        reserved.add(name)
        renamed += 1
        for position in positions:
            replacements[position] = name
    out, encoded = [], 0
    for kind, value, position in tokens:
        if kind == "str":
            out.append('"' + ''.join('\\%03d' % ord(char) for char in value) + '"')
            encoded += 1
        elif position in replacements:
            out.append(replacements[position])
        else:
            match = a._TOKEN.match(text, position)
            if not match:
                raise ObfuscationError("Could not safely preserve a source token.")
            out.append(text[position:match.end()])
    # Spaces separate all tokens, including '- -', numeric concatenation, and
    # adjacent keywords. No expression or compound assignment is reprinted.
    result = ('-- A3K Bastion | source obfuscation v1\n' + ' '.join(out) + '\n').encode("ascii")
    if len(result) > MAX_OUTPUT:
        raise ObfuscationError("Protected output exceeds 8 MB. Split the script into smaller files.")
    return Protected(result,len(source),hashlib.sha256(source).hexdigest(),renamed,encoded)
