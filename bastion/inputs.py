"""Read source attachments, pasted code and public URLs without executing Lua."""
import asyncio
import ipaddress
import re
import socket
import zlib
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from aiohttp.resolver import DefaultResolver

from .store import MAX_SOURCE


class InputError(ValueError):
    pass


LOADER = re.compile(
    r'''\s*loadstring\s*\(\s*game\s*:\s*HttpGet(?:Async)?\s*\(\s*(["'])(https?://[^\s"'\\]+)\1\s*(?:,\s*true\s*)?\)\s*\)\s*\(\s*\)\s*;?\s*'''
)


def unfence(text):
    text = text.strip()
    match = re.fullmatch(r"```(?:lua|luau)?[ \t]*\n([\s\S]*?)\n?```", text, re.IGNORECASE)
    return match.group(1) if match else text


def public_address(value):
    address = ipaddress.ip_address(value)
    address = getattr(address, "ipv4_mapped", None) or address
    return address.is_global and not address.is_multicast and not address.is_reserved and not address.is_unspecified


def normalize_url(value):
    value = value.strip()
    match = LOADER.fullmatch(unfence(value))
    if match:
        value = match.group(2)
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    if len(value) > 4096 or any(ord(char) <= 32 for char in value) or "\\" in value:
        raise InputError("Use a complete public HTTP/HTTPS script link.")
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise InputError("That script link is malformed.") from None
    if parsed.scheme not in ("https", "http") or not host or parsed.username is not None or parsed.password is not None:
        raise InputError("Use an HTTP/HTTPS link without a username or password.")
    if port not in (None, 80, 443) or host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise InputError("Only public website links using standard web ports are supported.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            host.encode("idna")
        except UnicodeError:
            raise InputError("That script hostname is invalid.") from None
    else:
        if not public_address(host):
            raise InputError("Private and local network addresses are not supported.")
    path = parsed.path
    parts = path.strip("/").split("/")
    if host.lower() in ("github.com", "www.github.com") and len(parts) >= 5 and parts[2] == "blob":
        return normalize_url(urlunsplit(("https", "raw.githubusercontent.com", "/" + "/".join(parts[:2] + parts[3:]), parsed.query, "")))
    if host.lower() in ("pastebin.com", "www.pastebin.com") and len(parts) == 1 and re.fullmatch(r"[A-Za-z0-9]+", parts[0]):
        path = "/raw/" + parts[0]
    if host.lower() in ("pastefy.app", "www.pastefy.app") and len(parts) == 1 and re.fullmatch(r"[A-Za-z0-9_-]+", parts[0]):
        path = "/" + parts[0] + "/raw"
    if host.lower() == "gist.github.com" and len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F]+", parts[1]):
        path += "/raw"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


class PublicResolver(DefaultResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        addresses = await super().resolve(host, port, family)
        if not addresses or any(not public_address(address["host"]) for address in addresses):
            raise InputError("The script link resolves to a private or unsupported network address.")
        # The connector uses these exact resolved addresses. There is no second
        # unvalidated DNS lookup, including after redirects.
        return addresses


def validate_source(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_SOURCE:
        raise InputError("Scripts must be between 1 byte and 1 MB.")
    if b"\0" in data or data.startswith((b"PK\x03\x04", b"%PDF-", b"\x89PNG", b"\x7fELF")):
        raise InputError("Send Lua/Luau text, not an archive, document or binary file.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise InputError("Scripts must be UTF-8 text; .lua, .luau and .txt files are supported.") from None
    if text.lstrip().lower().startswith(("<!doctype html", "<html", "<head", "<body", "<?xml", "<svg")):
        raise InputError("This is a webpage, not script source. Use its raw/download link or attach the script file.")
    if not text.strip():
        raise InputError("The source is empty.")
    return text.encode("utf-8")


async def _fetch(session, value):
    current = normalize_url(value)
    visited = set()
    for _ in range(6):
        if current in visited:
            raise InputError("The script link repeats a redirect.")
        visited.add(current)
        async with session.get(current, allow_redirects=False) as response:
            if response.status in (301,302,303,307,308):
                location = response.headers.get("Location")
                if not location:
                    raise InputError("The script server returned an incomplete redirect.")
                from urllib.parse import urljoin
                current = normalize_url(urljoin(current,location))
                continue
            if response.status != 200:
                raise InputError(f"The script server returned HTTP {response.status}. Use a public raw link or upload the file.")
            if response.content_type in ("text/html", "application/xhtml+xml"):
                raise InputError("That link returned a webpage. Use the raw/download link instead.")
            if response.content_length is not None and response.content_length > MAX_SOURCE:
                raise InputError("The linked script exceeds the 1 MB limit.")
            encoding = response.headers.get("Content-Encoding", "identity").lower()
            if encoding not in ("identity", "gzip", "deflate"):
                raise InputError("The script server uses an unsupported compression format. Use a raw link or attach the file.")
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS) if encoding != "identity" else None
            data, received = bytearray(), 0
            async for chunk in response.content.iter_chunked(16384):
                received += len(chunk)
                if received > MAX_SOURCE:
                    raise InputError("The linked script exceeds the 1 MB download limit.")
                if decoder:
                    try:
                        chunk = decoder.decompress(chunk,MAX_SOURCE + 1 - len(data))
                    except zlib.error:
                        raise InputError("The script server returned invalid compressed data.") from None
                    if decoder.unconsumed_tail:
                        raise InputError("The decompressed script exceeds the 1 MB limit.")
                data.extend(chunk)
                if len(data) > MAX_SOURCE:
                    raise InputError("The linked script exceeds the 1 MB limit.")
            if decoder and (not decoder.eof or decoder.unused_data):
                raise InputError("The script server returned incomplete or unsupported compressed data.")
            return validate_source(bytes(data))
    raise InputError("The script link has too many redirects.")


async def fetch_script(url):
    try:
        async with asyncio.timeout(20):
            connector = aiohttp.TCPConnector(resolver=PublicResolver(),use_dns_cache=False,limit=2)
            async with aiohttp.ClientSession(connector=connector,trust_env=False,auto_decompress=False,cookie_jar=aiohttp.DummyCookieJar(),
                                             timeout=aiohttp.ClientTimeout(total=15),
                                             headers={"User-Agent":"A3K-Bastion/1.2","Accept-Encoding":"gzip, deflate","Accept":"text/plain, application/octet-stream;q=0.9, */*;q=0.1"}) as session:
                seen = set()
                for _ in range(3):
                    url = normalize_url(url)
                    if url in seen:
                        raise InputError("The script repeats a loader link.")
                    seen.add(url)
                    data = await _fetch(session,url)
                    loader = LOADER.fullmatch(data.decode("utf-8"))
                    if not loader:
                        return data
                    url = loader.group(2)
                raise InputError("The script has too many nested loader links. Attach the final Lua file instead.")
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        raise InputError("Could not download this script. Check that the link is public or attach the file instead.") from None


async def read_source(*, file=None, url=None, code=None):
    selected = [file is not None,url is not None,code is not None]
    if sum(selected) != 1:
        raise InputError("Choose exactly one input: file, url, or code.")
    if file is not None:
        if file.size > MAX_SOURCE:
            raise InputError("The attached script exceeds the 1 MB limit.")
        data = validate_source(await file.read())
        loader = LOADER.fullmatch(data.decode("utf-8"))
        return await fetch_script(loader.group(2)) if loader else data
    if url is not None:
        return await fetch_script(url)
    text = unfence(code)
    if text.startswith(("https://","http://","<https://","<http://")) or LOADER.fullmatch(text):
        return await fetch_script(text)
    return validate_source(text.encode("utf-8"))
