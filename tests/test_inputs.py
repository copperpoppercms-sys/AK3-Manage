import gzip
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock,MagicMock,patch

from bastion.inputs import InputError,LOADER,PublicResolver,_fetch,fetch_script,normalize_url,read_source,validate_source
from bastion.store import MAX_SOURCE,Store
from bastion.bot import Bastion


class UrlTests(unittest.TestCase):
    def test_common_raw_link_conversions(self):
        cases={
            'https://github.com/user/repo/blob/main/script.lua':'https://raw.githubusercontent.com/user/repo/main/script.lua',
            'https://pastebin.com/ABC123':'https://pastebin.com/raw/ABC123',
            'https://pastefy.app/ABC123':'https://pastefy.app/ABC123/raw',
            'https://gist.github.com/user/abcdef':'https://gist.github.com/user/abcdef/raw',
            '<https://cdn.example.com/test>':'https://cdn.example.com/test',
            'loadstring(game:HttpGet("https://cdn.example.com/script.lua"))()':'https://cdn.example.com/script.lua',
        }
        for source,expected in cases.items():
            with self.subTest(source=source):self.assertEqual(normalize_url(source),expected)

    def test_private_malformed_and_credential_urls_are_rejected(self):
        for url in ('file:///etc/passwd','https://localhost/a','https://127.0.0.1/a','https://169.254.169.254/a',
                    'https://[::1]/','https://[::ffff:127.0.0.1]/','https://224.0.0.1/',
                    'https://user:pass@example.com/a','https://example.com:444/a','https://service.railway.internal/a',
                    'https://example.com/space here','https://example.com:wrong/','https://example.com/\\foo'):
            with self.subTest(url=url):
                with self.assertRaises(InputError):normalize_url(url)

    def test_loader_detection_never_drops_extra_statements(self):
        self.assertIsNone(LOADER.fullmatch('print("extra"); loadstring(game:HttpGet("https://example.com/script"))()'))
        self.assertIsNone(LOADER.fullmatch('loadstring(game:HttpGet(variable))()'))

    def test_webpages_binary_empty_and_invalid_encoding_are_rejected(self):
        for data in (b'<html>error</html>',b'<!DOCTYPE html>',b'PK\x03\x04archive',b'%PDF-1.7',b'\0binary',b'\xff',b'  ',b'x'*(MAX_SOURCE+1)):
            with self.subTest(data=data[:20]):
                with self.assertRaises(InputError):validate_source(data)


class FakeResponse:
    def __init__(self,data=b'return 42',status=200,headers=None,content_type='text/plain',content_length=None):
        self.data,self.status,self.headers,self.content_type,self.content_length=data,status,headers or {},content_type,content_length
        self.content=self
    async def __aenter__(self):return self
    async def __aexit__(self,*args):pass
    async def iter_chunked(self,size):
        for start in range(0,len(self.data),size):yield self.data[start:start+size]


class FetchTests(unittest.IsolatedAsyncioTestCase):
    async def test_raw_text_without_filename_extension(self):
        session=SimpleNamespace(get=MagicMock(return_value=FakeResponse(b'local x=1; return x')))
        self.assertEqual(await _fetch(session,'https://cdn.example.com/download?id=1'),b'local x=1; return x')
        self.assertFalse(session.get.call_args.kwargs['allow_redirects'])

    async def test_relative_redirect_and_safe_destination(self):
        session=SimpleNamespace(get=MagicMock(side_effect=[FakeResponse(status=302,headers={'Location':'/raw'}),FakeResponse()]))
        self.assertEqual(await _fetch(session,'https://example.com/start'),b'return 42')
        self.assertEqual(session.get.call_args.args[0],'https://example.com/raw')

    async def test_redirect_to_private_network_is_blocked_before_request(self):
        session=SimpleNamespace(get=MagicMock(return_value=FakeResponse(status=302,headers={'Location':'http://127.0.0.1/secret'})))
        with self.assertRaises(InputError):await _fetch(session,'https://example.com/start')
        self.assertEqual(session.get.call_count,1)

    async def test_redirect_cycle_is_bounded(self):
        session=SimpleNamespace(get=MagicMock(return_value=FakeResponse(status=302,headers={'Location':'/start'})))
        with self.assertRaisesRegex(InputError,'repeats'):await _fetch(session,'https://example.com/start')

    async def test_content_length_and_stream_size_limits(self):
        for response in (FakeResponse(content_length=MAX_SOURCE+1),FakeResponse(b'x'*(MAX_SOURCE+1))):
            session=SimpleNamespace(get=MagicMock(return_value=response))
            with self.assertRaises(InputError):await _fetch(session,'https://example.com/raw')

    async def test_compressed_source_and_bomb_limit(self):
        session=SimpleNamespace(get=MagicMock(return_value=FakeResponse(gzip.compress(b'return 42'),headers={'Content-Encoding':'gzip'})))
        self.assertEqual(await _fetch(session,'https://example.com/raw'),b'return 42')
        session.get.return_value=FakeResponse(gzip.compress(b'x'*(MAX_SOURCE+50000)),headers={'Content-Encoding':'gzip'})
        with self.assertRaises(InputError):await _fetch(session,'https://example.com/raw')

    async def test_html_response_is_not_treated_as_source(self):
        session=SimpleNamespace(get=MagicMock(return_value=FakeResponse(content_type='text/html')))
        with self.assertRaisesRegex(InputError,'webpage'):await _fetch(session,'https://example.com/raw')

    async def test_dns_resolver_rejects_private_and_mixed_answers(self):
        resolver=PublicResolver()
        try:
            for records in ([{'host':'127.0.0.1'}],[{'host':'1.1.1.1'},{'host':'10.0.0.1'}],[{'host':'::ffff:10.0.0.1'}]):
                with patch('bastion.inputs.DefaultResolver.resolve',new=AsyncMock(return_value=records)):
                    with self.assertRaises(InputError):await resolver.resolve('attacker.example',443,socket.AF_UNSPEC)
            records=[{'host':'1.1.1.1'}]
            with patch('bastion.inputs.DefaultResolver.resolve',new=AsyncMock(return_value=records)):
                self.assertEqual(await resolver.resolve('public.example',443),records)
        finally:await resolver.close()

    async def test_nested_loader_fetches_are_static_and_bounded(self):
        manager=MagicMock(); manager.__aenter__.return_value=SimpleNamespace()
        with patch('bastion.inputs.aiohttp.ClientSession',return_value=manager),patch('bastion.inputs.aiohttp.TCPConnector'),patch('bastion.inputs._fetch',new=AsyncMock(side_effect=[b'loadstring(game:HttpGet("https://example.com/next"))()',b'return 77'])) as fetch:
            self.assertEqual(await fetch_script('https://example.com/start'),b'return 77')
            self.assertEqual(fetch.await_count,2)


class SourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_text_attachments_and_code(self):
        file=SimpleNamespace(filename='script.txt',size=9,read=AsyncMock(return_value=b'return 42'))
        self.assertEqual(await read_source(file=file),b'return 42')
        self.assertEqual(await read_source(code='```lua\nreturn 42\n```'),b'return 42')

    async def test_missing_or_ambiguous_inputs_are_explicit_errors(self):
        with self.assertRaisesRegex(InputError,'exactly one'):await read_source()
        with self.assertRaisesRegex(InputError,'exactly one'):await read_source(url='https://example.com',code='return 1')

    async def test_urls_in_code_or_loader_files_are_fetched(self):
        with patch('bastion.inputs.fetch_script',new=AsyncMock(return_value=b'return 5')) as fetch:
            self.assertEqual(await read_source(code='https://example.com/raw'),b'return 5')
            file=SimpleNamespace(size=80,read=AsyncMock(return_value=b'loadstring(game:HttpGet("https://example.com/raw"))()'))
            self.assertEqual(await read_source(file=file),b'return 5')
            self.assertEqual(fetch.await_count,2)

    async def test_attachment_actual_size_is_checked(self):
        file=SimpleNamespace(size=5,read=AsyncMock(return_value=b'x'*(MAX_SOURCE+1)))
        with self.assertRaises(InputError):await read_source(file=file)

    async def test_commands_accept_links_and_pasted_code_privately(self):
        store=Store(':memory:','test-source-input-secret'*3)
        bot=Bastion(123,store,'https://bastion.example')
        interaction=SimpleNamespace(response=SimpleNamespace(defer=AsyncMock(),send_message=AsyncMock()),followup=SimpleNamespace(send=AsyncMock()))
        try:
            with patch('bastion.inputs.fetch_script',new=AsyncMock(return_value=b'local value=3; return value')):
                await bot.tree.get_command('upload').callback(interaction,'From a link',url='https://example.com/raw')
            self.assertEqual(len(store.scripts()),1)
            self.assertEqual(store.scripts()[0]['protection'],'source-v1')
            await bot.tree.get_command('obfuscate').callback(interaction,code='local x=1; return x')
            self.assertTrue(interaction.followup.send.call_args.kwargs['ephemeral'])
            for name in ('upload','obfuscate'):
                options={option.name:option for option in bot.tree.get_command(name).parameters}
                for option in ('file','url','code'):self.assertFalse(options[option].required)
        finally:
            await bot.close();store.close()
