"""Byte-preserving Lua/Luau literal codec for the static obfuscator."""
import re

NUMBER_PATTERN = (
    r"(?:0[xX][0-9a-fA-F][0-9a-fA-F_]*(?:\.[0-9a-fA-F_]*)?(?:[pP][+-]?[0-9][0-9_]*)?"
    r"|0[bB][01][01_]*|[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9][0-9_]*)?"
    r"|\.[0-9][0-9_]*(?:[eE][+-]?[0-9][0-9_]*)?)"
)
ESCAPES = {"a":"\a", "b":"\b", "f":"\f", "n":"\n", "r":"\r", "t":"\t", "v":"\v", "\\":"\\", '"':'"', "'":"'"}
WHITESPACE = " \t\r\n\v\f"


def quoted_end(source, start):
    quote, i = source[start], start + 1
    while i < len(source):
        char = source[i]
        if char == quote:
            return i + 1
        if char in "\r\n":
            raise ValueError("unfinished string")
        if char == "\\":
            if i + 1 >= len(source):
                break
            escape = source[i + 1]
            i += 2
            if escape == "z":
                while i < len(source) and source[i] in WHITESPACE:
                    i += 1
            elif escape in "\r\n" and i < len(source) and source[i] in "\r\n" and source[i] != escape:
                i += 1
        else:
            i += 1
    raise ValueError("unfinished string")


def parse_quoted(literal):
    if quoted_end(literal, 0) != len(literal):
        raise ValueError("malformed quoted string")
    body, out, i = literal[1:-1], [], 0
    while i < len(body):
        char = body[i]
        if char != "\\":
            out.append(char)
            i += 1
            continue
        escape = body[i + 1]
        if escape in ESCAPES:
            out.append(ESCAPES[escape]); i += 2
        elif escape in "\r\n":
            out.append("\n"); i += 2
            if i < len(body) and body[i] in "\r\n" and body[i] != escape:
                i += 1
        elif escape == "z":
            i += 2
            while i < len(body) and body[i] in WHITESPACE:
                i += 1
        elif escape.isdigit():
            match = re.match(r"[0-9]{1,3}", body[i + 1:])
            value = int(match.group())
            if value > 255:
                raise ValueError("decimal escape exceeds one byte")
            out.append(chr(value)); i += 1 + len(match.group())
        elif escape == "x":
            value = body[i + 2:i + 4]
            if not re.fullmatch(r"[0-9a-fA-F]{2}", value):
                raise ValueError("invalid hex escape")
            out.append(chr(int(value,16))); i += 4
        elif escape == "u":
            match = re.match(r"u\{([0-9a-fA-F]{1,6})\}", body[i + 1:])
            if not match:
                raise ValueError("invalid unicode escape")
            value = int(match.group(1),16)
            if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                raise ValueError("invalid unicode code point")
            out.append(chr(value).encode("utf-8").decode("latin1")); i += 1 + len(match.group())
        else:
            raise ValueError("unsupported string escape")
    return ''.join(out)
