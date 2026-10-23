"""Lua/Luau subset parser with scope resolution, adapted from A3K Deobfuscator.

Source text is latin-1 (one char per byte). Every identifier that resolves to a `local` points at a shared `Local`
object, so passes can reason about reads, writes and captures instead of guessing from names.
This module does not generate code; the protector preserves original expression tokens.
"""
import re

from . import _lua_strings as passes

KEYWORDS = frozenset(
    "and break do else elseif end false for function goto if in local nil not or repeat return then true until while continue".split()
)


class ParseError(Exception):
    pass


class Local:
    __slots__ = ("name", "func", "reads", "writes", "captured", "assigned_in_closure", "uid")
    _n = 0

    def __init__(self, name, func):
        self.name, self.func = name, func
        self.reads = self.writes = 0
        self.captured = self.assigned_in_closure = False
        Local._n += 1
        self.uid = Local._n


class Node:
    __slots__ = ()

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, ", ".join("%s=%r" % (k, getattr(self, k)) for k in self.__slots__))


def _node(name, *fields):
    def init(self, *a):
        for f, v in zip(fields, a):
            setattr(self, f, v)

    return type(name, (Node,), {"__slots__": fields, "__init__": init})


# expressions
Nil = _node("Nil")
Bool = _node("Bool", "value")
Num = _node("Num", "value")
Str = _node("Str", "value")
Vararg = _node("Vararg")
Func = _node("Func", "params", "vararg", "body", "is_method", "fid")
Name = _node("Name", "local", "name")  # local is a Local or None (global)
Index = _node("Index", "obj", "key")
Call = _node("Call", "func", "args")
Method = _node("Method", "obj", "name", "args")
Table = _node("Table", "items")  # items: ("pos", None, v) | ("named", Str, v) | ("expr", k, v)
Bin = _node("Bin", "op", "l", "r")
Un = _node("Un", "op", "e")
Paren = _node("Paren", "e")
# statements
LocalStmt = _node("LocalStmt", "vars", "exprs")
Assign = _node("Assign", "targets", "exprs")
CallStmt = _node("CallStmt", "call")
Do = _node("Do", "body")
While = _node("While", "cond", "body")
Repeat = _node("Repeat", "body", "cond")
If = _node("If", "clauses", "orelse")  # clauses: [(cond, body)]
NumFor = _node("NumFor", "var", "start", "stop", "step", "body")
GenFor = _node("GenFor", "vars", "exprs", "body")
FuncStmt = _node("FuncStmt", "target", "func")
LocalFunc = _node("LocalFunc", "var", "func")
Return = _node("Return", "exprs")
Break = _node("Break")
Continue = _node("Continue")
Goto = _node("Goto", "label")
Label = _node("Label", "label")

_TOKEN = re.compile(
    r"""(?P<ws>[ \t\r\n\v\f]+)
    |(?P<num>""" + passes.NUMBER_PATTERN + r""")
    |(?P<name>[A-Za-z_][A-Za-z0-9_]*)
    |(?P<op>\.\.\.|\.\.=|\.\.|==|~=|!=|<=|>=|::|//=|//|\+=|-=|\*=|/=|%=|\^=|[-+*/%^#<>=(){}\[\];:,.])""",
    re.X,
)
_LONG = re.compile(r"\[(=*)\[")


def lex(src):
    toks, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("--", i):
            m = _LONG.match(src, i + 2)
            if m:
                close = "]" + m.group(1) + "]"
                j = src.find(close, m.end())
                if j < 0:
                    raise ParseError("unfinished long comment")
                i = j + len(close)
            else:
                j = src.find("\n", i)
                i = n if j < 0 else j
            continue
        if c in "\"'":
            j = passes.quoted_end(src, i) - 1
            try:
                value = passes.parse_quoted(src[i:j + 1])
            except ValueError as e:
                raise ParseError(str(e)) from e
            toks.append(("str", value, i))
            i = j + 1
            continue
        if c == "[":
            m = _LONG.match(src, i)
            if m:
                close = "]" + m.group(1) + "]"
                j = src.find(close, m.end())
                if j < 0:
                    raise ParseError("unfinished long string")
                body = src[m.end():j]
                body = body.replace("\r\n", "\n")
                if body.startswith("\n"):
                    body = body[1:]
                toks.append(("str", body, i))
                i = j + len(close)
                continue
        m = _TOKEN.match(src, i)
        if not m:
            raise ParseError("bad character %r at %d" % (c, i))
        kind = m.lastgroup
        text = m.group(kind)
        if kind == "num":
            toks.append(("num", _number(text), i))
        elif kind == "name":
            toks.append(("kw" if text in KEYWORDS else "name", text, i))
        elif kind == "op":
            toks.append(("op", text, i))
        i = m.end()
    toks.append(("eof", "<eof>", n))
    return toks


def _number(text):
    text = text.replace("_", "")
    try:
        if text[:2] in ("0b", "0B"):
            v = int(text[2:], 2)
        elif text[:2] in ("0x", "0X"):
            if "." in text or "p" in text or "P" in text:
                return float.fromhex(text)
            v = int(text, 16)
        elif re.fullmatch(r"\d+", text):
            v = int(text)
        else:
            v = float(text)
    except ValueError:
        raise ParseError("malformed number %r" % text)
    if isinstance(v, int) and v > 2 ** 53:
        v = float(v)
    if isinstance(v, float) and v == v and abs(v) < 2 ** 53 and v == int(v):
        v = int(v)
    return v


_BIN = {
    "or": (1, 1), "and": (2, 2),
    "<": (3, 3), ">": (3, 3), "<=": (3, 3), ">=": (3, 3), "~=": (3, 3), "==": (3, 3),
    "..": (5, 4), "+": (6, 6), "-": (6, 6), "*": (7, 7), "/": (7, 7), "%": (7, 7), "//": (7, 7), "^": (10, 9),
}
_UNARY = 8
_COMPOUND = {"+=": "+", "-=": "-", "*=": "*", "/=": "/", "//=": "//", "%=": "%", "^=": "^", "..=": ".."}


class Parser:
    def __init__(self, src):
        self.toks = lex(src)
        self.p = 0
        self.scopes = [{}]
        self.func = 0
        self.nfunc = 0

    # token helpers
    def peek(self, k=0):
        return self.toks[min(self.p + k, len(self.toks) - 1)]

    def next(self):
        t = self.toks[self.p]
        self.p += 1
        return t

    def check(self, kind, value=None):
        t = self.toks[self.p]
        return t[0] == kind and (value is None or t[1] == value)

    def accept(self, kind, value=None):
        if self.check(kind, value):
            return self.next()
        return None

    def expect(self, kind, value=None):
        t = self.accept(kind, value)
        if not t:
            raise ParseError("expected %s %r near %r at %d" % (kind, value, self.toks[self.p][1], self.toks[self.p][2]))
        return t

    def kw(self, v):
        return self.check("kw", v)

    # scopes
    def declare(self, name):
        loc = Local(name, self.func)
        self.scopes[-1][name] = loc
        return loc

    def resolve(self, name):
        for sc in reversed(self.scopes):
            if name in sc:
                return sc[name]
        return None

    # grammar
    def parse_chunk(self):
        body = self.block()
        if not self.check("eof"):
            raise ParseError("unexpected %r at %d" % (self.peek()[1], self.peek()[2]))
        return body

    def block_follow(self):
        t = self.peek()
        return t[0] == "eof" or (t[0] == "kw" and t[1] in ("end", "else", "elseif", "until"))

    def block(self, scope=True):
        if scope:
            self.scopes.append({})
        out = []
        while not self.block_follow():
            if self.kw("return"):
                out.append(self.retstat())
                break
            st = self.statement()
            if st is not None:
                out.append(st)
        if scope:
            self.scopes.pop()
        return out

    def retstat(self):
        self.next()
        exprs = []
        if not self.block_follow() and not self.check("op", ";"):
            exprs = self.exprlist()
        self.accept("op", ";")
        return Return(exprs)

    def statement(self):
        t = self.peek()
        if t[0] == "op" and t[1] == ";":
            self.next()
            return None
        if t[0] == "op" and t[1] == "::":
            self.next()
            name = self.expect("name")[1]
            self.expect("op", "::")
            return Label(name)
        if t[0] == "kw":
            v = t[1]
            if v == "if":
                return self.ifstat()
            if v == "while":
                self.next()
                cond = self.expr()
                self.expect("kw", "do")
                body = self.block()
                self.expect("kw", "end")
                return While(cond, body)
            if v == "do":
                self.next()
                body = self.block()
                self.expect("kw", "end")
                return Do(body)
            if v == "for":
                return self.forstat()
            if v == "repeat":
                self.next()
                self.scopes.append({})
                body = self.block(scope=False)
                self.expect("kw", "until")
                cond = self.expr()
                self.scopes.pop()
                return Repeat(body, cond)
            if v == "function":
                return self.funcstat()
            if v == "local":
                self.next()
                if self.accept("kw", "function"):
                    name = self.expect("name")[1]
                    var = self.declare(name)
                    return LocalFunc(var, self.funcbody(False))
                names = [self.expect("name")[1]]
                while self.accept("op", ","):
                    names.append(self.expect("name")[1])
                exprs = self.exprlist() if self.accept("op", "=") else []
                return LocalStmt([self.declare(n) for n in names], exprs)
            if v == "break":
                self.next()
                return Break()
            if v == "continue":
                self.next()
                return Continue()
            if v == "goto":
                self.next()
                return Goto(self.expect("name")[1])
            if v == "return":
                raise ParseError("return in the middle of a block")
        return self.exprstat()

    def ifstat(self):
        clauses = []
        self.next()
        cond = self.expr()
        self.expect("kw", "then")
        clauses.append((cond, self.block()))
        orelse = None
        while True:
            if self.accept("kw", "elseif"):
                cond = self.expr()
                self.expect("kw", "then")
                clauses.append((cond, self.block()))
            elif self.accept("kw", "else"):
                orelse = self.block()
                self.expect("kw", "end")
                break
            else:
                self.expect("kw", "end")
                break
        return If(clauses, orelse)

    def forstat(self):
        self.next()
        n1 = self.expect("name")[1]
        if self.check("op", "="):
            self.next()
            start = self.expr()
            self.expect("op", ",")
            stop = self.expr()
            step = self.expr() if self.accept("op", ",") else None
            self.expect("kw", "do")
            self.scopes.append({})
            var = self.declare(n1)
            body = self.block()
            self.scopes.pop()
            self.expect("kw", "end")
            return NumFor(var, start, stop, step, body)
        names = [n1]
        while self.accept("op", ","):
            names.append(self.expect("name")[1])
        self.expect("kw", "in")
        exprs = self.exprlist()
        self.expect("kw", "do")
        self.scopes.append({})
        vars_ = [self.declare(n) for n in names]
        body = self.block()
        self.scopes.pop()
        self.expect("kw", "end")
        return GenFor(vars_, exprs, body)

    def funcstat(self):
        self.next()
        n = self.expect("name")[1]
        target = self.name_expr(n)
        is_method = False
        while True:
            if self.accept("op", "."):
                target = Index(target, Str(self.expect("name")[1]))
            elif self.accept("op", ":"):
                target = Index(target, Str(self.expect("name")[1]))
                is_method = True
                break
            else:
                break
        return FuncStmt(target, self.funcbody(is_method))

    def funcbody(self, is_method):
        self.expect("op", "(")
        self.nfunc += 1
        saved = self.func
        self.func = self.nfunc
        fid = self.nfunc
        self.scopes.append({})
        params, vararg = [], False
        if is_method:
            params.append(self.declare("self"))
        if not self.check("op", ")"):
            while True:
                if self.accept("op", "..."):
                    vararg = True
                    break
                params.append(self.declare(self.expect("name")[1]))
                if not self.accept("op", ","):
                    break
        self.expect("op", ")")
        body = self.block()
        self.expect("kw", "end")
        self.scopes.pop()
        self.func = saved
        return Func(params, vararg, body, is_method, fid)

    def exprstat(self):
        e = self.suffixedexp()
        if self.check("op", "=") or self.check("op", ","):
            targets = [e]
            while self.accept("op", ","):
                targets.append(self.suffixedexp())
            self.expect("op", "=")
            for t in targets:
                if not isinstance(t, (Name, Index)):
                    raise ParseError("cannot assign to expression")
            return Assign(targets, self.exprlist())
        t = self.peek()
        if t[0] == "op" and t[1] in _COMPOUND:
            self.next()
            if not isinstance(e, (Name, Index)):
                raise ParseError("cannot assign to expression")
            return Assign([e], [Bin(_COMPOUND[t[1]], e, self.expr())])
        if not isinstance(e, (Call, Method)):
            raise ParseError("syntax error near %r at %d" % (self.peek()[1], self.peek()[2]))
        return CallStmt(e)

    def exprlist(self):
        out = [self.expr()]
        while self.accept("op", ","):
            out.append(self.expr())
        return out

    def name_expr(self, name):
        loc = self.resolve(name)
        if loc is not None and loc.func != self.func:
            loc.captured = True
        return Name(loc, name)

    def primaryexp(self):
        t = self.next()
        if t[0] == "name":
            return self.name_expr(t[1])
        if t == ("op", "(", t[2]):
            e = self.expr()
            self.expect("op", ")")
            return Paren(e)
        raise ParseError("unexpected symbol %r at %d" % (t[1], t[2]))

    def suffixedexp(self):
        e = self.primaryexp()
        while True:
            t = self.peek()
            if t[0] == "op" and t[1] == ".":
                self.next()
                e = Index(e, Str(self.expect("name")[1]))
            elif t[0] == "op" and t[1] == "[":
                self.next()
                k = self.expr()
                self.expect("op", "]")
                e = Index(e, k)
            elif t[0] == "op" and t[1] == ":":
                self.next()
                name = self.expect("name")[1]
                e = Method(e, name, self.callargs())
            elif (t[0] == "op" and t[1] in ("(", "{")) or t[0] == "str":
                e = Call(e, self.callargs())
            else:
                return e

    def callargs(self):
        t = self.peek()
        if t[0] == "str":
            self.next()
            return [Str(t[1])]
        if t[0] == "op" and t[1] == "{":
            return [self.table()]
        self.expect("op", "(")
        if self.accept("op", ")"):
            return []
        args = self.exprlist()
        self.expect("op", ")")
        return args

    def table(self):
        self.expect("op", "{")
        items = []
        while not self.check("op", "}"):
            t = self.peek()
            if t[0] == "op" and t[1] == "[":
                self.next()
                k = self.expr()
                self.expect("op", "]")
                self.expect("op", "=")
                items.append(("expr", k, self.expr()))
            elif t[0] == "name" and self.peek(1) == ("op", "=", self.peek(1)[2]):
                self.next()
                self.next()
                items.append(("named", Str(t[1]), self.expr()))
            else:
                items.append(("pos", None, self.expr()))
            if not (self.accept("op", ",") or self.accept("op", ";")):
                break
        self.expect("op", "}")
        return Table(items)

    def simpleexp(self):
        t = self.peek()
        k, v = t[0], t[1]
        if k == "num":
            self.next()
            return Num(v)
        if k == "str":
            self.next()
            return Str(v)
        if k == "kw" and v == "nil":
            self.next()
            return Nil()
        if k == "kw" and v == "true":
            self.next()
            return Bool(True)
        if k == "kw" and v == "false":
            self.next()
            return Bool(False)
        if k == "op" and v == "...":
            self.next()
            return Vararg()
        if k == "op" and v == "{":
            return self.table()
        if k == "kw" and v == "function":
            self.next()
            return self.funcbody(False)
        return self.suffixedexp()

    def expr(self, limit=0):
        t = self.peek()
        if (t[0] == "kw" and t[1] == "not") or (t[0] == "op" and t[1] in ("-", "#")):
            self.next()
            e = Un(t[1], self.expr(_UNARY))
        else:
            e = self.simpleexp()
        while True:
            t = self.peek()
            op = t[1] if t[0] in ("op", "kw") else None
            if op == "!=":
                op = "~="
            if op not in _BIN or _BIN[op][0] <= limit:
                return e
            self.next()
            r = self.expr(_BIN[op][1])
            e = Bin(op, e, r)


def parse(src):
    """Parse a chunk; returns the statement list. Raises ParseError."""
    try:
        return Parser(src).parse_chunk()
    except RecursionError:
        raise ParseError("nesting too deep")


