import hashlib
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from lupa.lua51 import LuaRuntime

from bastion.bot import Bastion
from bastion.obfuscate import ObfuscationError, PROTECTION, protect
from bastion.store import AccessDenied, Store

SECRET = "test-only-source-obfuscation-secret" * 3
DEVICE = "test-device-12345"

CASES = [
    'local count=7; return count*3',
    'local count=2; do local count=count+1; if count~=3 then error("scope") end end; return count',
    'local a,b=2,3; local a,b=b,a; return a,b',
    'local function factorial(n) if n==0 then return 1 end return n*factorial(n-1) end return factorial(7)',
    'local counter=0; local function bump() counter=counter+1; return counter end return bump(),bump()',
    'local function f(value,...) return value,select("#",...),... end return f(1,2,nil,4)',
    'local t={value=4}; function t:add(value) return self.value+value end return t:add(3),t.value',
    'local t={}; function t.f(a) return a*2 end return t.f(8)',
    'local sum=0; for i=1,5 do sum=sum+i end return sum',
    'local sum=0; for k,v in ipairs({2,4,6}) do sum=sum+k+v end return sum',
    'local n=0; repeat local done=n>=3; n=n+1 until done; return n',
    'local t={}; do local x=9; t.f=function() return x end end return t.f()',
    'local function a() return function(b) return function(c) return b+c end end end return a()(2)(3)',
    'local key="value"; local value=8; local t={value=value}; return t.value,t[key]',
    'local a,b,c=1,2,3; a,b,c=c,a,b; return a,b,c',
    'local _ENV=23; return _ENV',
    'local function f(self) return self end return f(12)',
    'local t={}; function t:f(self) return self end return t:f(42)',
    'local count=0; while count<4 do count=count+1 end return count',
    'local t={1,2,3}; local function f(...) return ... end return f(unpack(t))',
    'return ("hello"):sub(2), string.byte("\\000\\255",2)',
    'local function f(x) return x end return f "hello"',
    'return [=[\nhello\r\nworld]=]',
    'return "line\\\nnext", "decimal\\1234", "quote\\\"slash\\\\"',
]


class ObfuscatorTests(unittest.TestCase):
    def test_supported_programs_preserve_results(self):
        for source in CASES:
            with self.subTest(source=source):
                protected=protect(source.encode())
                self.assertEqual(LuaRuntime(encoding=None,unpack_returned_tuples=True).execute(source.encode()),
                                 LuaRuntime(encoding=None,unpack_returned_tuples=True).execute(protected.source))

    def test_source_is_transformed_without_a_packed_loader(self):
        source=b'-- private comment\nlocal descriptiveName="secret message"; print(descriptiveName)'
        result=protect(source)
        self.assertNotIn(b'private comment',result.source)
        self.assertNotIn(b'descriptiveName',result.source)
        self.assertNotIn(b'secret message',result.source)
        self.assertNotIn(b'loadstring',result.source)
        self.assertEqual(result.renamed,1)
        self.assertEqual(result.encoded_strings,1)
        self.assertEqual(result.original_sha256,hashlib.sha256(source).hexdigest())

    def test_variants_have_fresh_local_names(self):
        source=b'local counter=5; return counter'
        self.assertNotEqual(protect(source).source,protect(source).source)

    def test_globals_and_property_names_are_not_renamed(self):
        result=protect(b'local value=7; local t={value=value}; game:GetService("Players"); return t.value')
        self.assertIn(b'game : GetService',result.source)
        self.assertIn(b'value =',result.source)
        self.assertIn(b'. value',result.source)

    def test_utf8_and_unicode_escape_bytes(self):
        result=protect('return "雪🙂", "\\u{1F642}"'.encode())
        first,second=LuaRuntime(encoding=None,unpack_returned_tuples=True).execute(result.source)
        self.assertEqual(first,'雪🙂'.encode())
        self.assertEqual(second,'🙂'.encode())

    def test_hex_z_and_decimal_escape_bytes(self):
        result=protect(b'return "A\\z \n\t B\\x43\\000\\255"')
        self.assertEqual(LuaRuntime(encoding=None).execute(result.source),b'ABC\0\xff')

    def test_bom_and_comments_inside_strings(self):
        source=b'\xef\xbb\xbf--[=[ comment ]=]\nlocal text="-- not comment"; return text'
        self.assertEqual(LuaRuntime(encoding=None).execute(protect(source).source),b'-- not comment')

    def test_untrusted_source_is_never_executed_by_protect(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'should-not-exist'
            source=('local f=io.open("'+str(path)+'","w"); f:write("bad")').encode()
            protect(source)
            self.assertFalse(path.exists())

    def test_unsupported_and_invalid_inputs_raise_explicit_errors(self):
        sources=[b'local value: number=4',b'return `hello`',b'local x=if true then 1 else 2',
                 b'--[[unterminated',b'return "unterminated',b'local = broken',b'goto label',
                 b'return debug.getlocal(1,2)',b'',b'x'*(1024*1024+1)]
        for source in sources:
            with self.subTest(source=source[:60]):
                with self.assertRaises(ObfuscationError): protect(source)


class StoreProtectionTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(':memory:',SECRET)
        self.source=b'local originalValue="private value"; return originalValue'
        self.script=self.store.upload('Existing hub',self.source)
        self.key=self.store.issue(self.script,24)[0]

    def tearDown(self): self.store.close()

    def test_existing_script_and_key_survive_protection(self):
        pending=self.store.authenticate(self.script,self.key['key'],DEVICE)
        result=protect(self.store.source_for_protection(self.script))
        self.store.apply_protection(self.script,result)
        with self.assertRaises(AccessDenied): self.store.consume(self.script,pending,DEVICE)
        token=self.store.authenticate(self.script,self.key['key'],DEVICE)
        payload=self.store.consume(self.script,token,DEVICE)
        self.assertEqual(payload,result.source)
        self.assertEqual(LuaRuntime(encoding=None).execute(payload),b'private value')
        self.assertEqual(self.store.script(self.script)['protection'],PROTECTION)
        self.assertEqual(self.store.script(self.script)['original_size'],len(self.source))

    def test_duplicate_protection_is_rejected(self):
        self.store.apply_protection(self.script,protect(self.source))
        with self.assertRaises(ValueError): self.store.source_for_protection(self.script)

    def test_stale_result_cannot_replace_another_script(self):
        with self.assertRaises(ValueError): self.store.apply_protection(self.script,protect(b'print(123)'))
        self.assertEqual(self.store.source_for_protection(self.script),self.source)

    def test_upload_prepared_source_metadata(self):
        result=protect(self.source)
        script=self.store.upload('Protected hub',result.source,protection=result.protection,original_size=result.original_size)
        self.assertEqual(self.store.script(script)['protection'],PROTECTION)
        self.assertNotIn(b'originalValue',self.store.cipher.decrypt(self.store.db.execute('SELECT payload FROM scripts WHERE id=?',(script,)).fetchone()[0]))

    def test_legacy_database_migrates_without_losing_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'legacy.sqlite3'
            old=Store(path,SECRET)
            script=old.upload('Old hub',self.source)
            key=old.issue(script,24)[0]['key']
            old.db.execute('ALTER TABLE scripts DROP COLUMN protection')
            old.db.execute('ALTER TABLE scripts DROP COLUMN original_size')
            old.close()
            new=Store(path,SECRET)
            self.assertEqual(new.script(script)['protection'],'none')
            self.assertEqual(new.script(script)['original_size'],len(self.source))
            new.apply_protection(script,protect(new.source_for_protection(script)))
            token=new.authenticate(script,key,DEVICE)
            self.assertEqual(LuaRuntime(encoding=None).execute(new.consume(script,token,DEVICE)),b'private value')
            new.close()


class CommandProtectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store=Store(':memory:',SECRET)
        self.bot=Bastion(123,self.store,'https://bastion.example')

    async def asyncTearDown(self):
        await self.bot.close(); self.store.close()

    def interaction(self):
        return SimpleNamespace(response=SimpleNamespace(defer=AsyncMock(),send_message=AsyncMock()),followup=SimpleNamespace(send=AsyncMock()))

    async def test_upload_defaults_to_obfuscated(self):
        file=SimpleNamespace(filename='test.lua',size=30,read=AsyncMock(return_value=b'local name="payload"; return name'))
        interaction=self.interaction()
        await self.bot.tree.get_command('upload').callback(interaction,'Hub',file)
        row=self.store.scripts()[0]
        self.assertEqual(row['protection'],PROTECTION)
        self.assertTrue(interaction.followup.send.call_args.kwargs['ephemeral'])

    async def test_upload_can_explicitly_keep_unsupported_source_unmodified(self):
        file=SimpleNamespace(filename='test.luau',size=30,read=AsyncMock(return_value=b'local name: string="payload"'))
        interaction=self.interaction()
        await self.bot.tree.get_command('upload').callback(interaction,'Hub',file,obfuscate=False)
        self.assertEqual(self.store.scripts()[0]['protection'],'none')

    async def test_failed_upload_does_not_create_a_hub(self):
        file=SimpleNamespace(filename='test.luau',size=30,read=AsyncMock(return_value=b'local name: string="payload"'))
        interaction=self.interaction()
        await self.bot.tree.get_command('upload').callback(interaction,'Hub',file)
        self.assertEqual(self.store.scripts(),[])
        self.assertIn('Unsupported',interaction.followup.send.call_args.args[0])

    async def test_standalone_download_is_private(self):
        file=SimpleNamespace(filename='test.lua',size=25,read=AsyncMock(return_value=b'local text="hello"; return text'))
        interaction=self.interaction()
        await self.bot.tree.get_command('obfuscate').callback(interaction,file)
        response=interaction.followup.send.call_args.kwargs
        self.assertTrue(response['ephemeral'])
        self.assertEqual(LuaRuntime(encoding=None).execute(response['file'].fp.read()),b'hello')


@unittest.skipUnless(os.environ.get('LUAU_BIN'),'Set LUAU_BIN to run native Luau tests')
class NativeLuauTests(unittest.TestCase):
    def test_luau_semantics_match_original(self):
        cases=CASES+[
            'local n=0; for i=1,0b101 do if i==2 then continue end n+=i end return n',
            'local n=0; for _,v in {1,3,5} do n+=v end return n',
            'local n=0; repeat n+=1; if n<4 then continue end until n==4; return n',
            'local n=0; local a={10}; local function index() n+=1; return 1 end; a[index()] += 5; return a[1],n',
            'return "\\u{1F642}","hello\\z \n  world",0xF_F,0b1_01',
            'return [=[\nhello\r\nworld\rbye]=]',
            'return [=[\rleading carriage return]=],[=[\n\rpair]=]',
        ]
        with tempfile.TemporaryDirectory() as folder:
            for index,source in enumerate(cases):
                with self.subTest(index=index):
                    original=Path(folder)/'original.luau'; protected=Path(folder)/'protected.luau'
                    # CLI prints returned values only through this tiny trusted harness.
                    original.write_text('local function run(...) '+source+' end; print(run())')
                    protected.write_bytes(protect(original.read_bytes()).source)
                    reference=subprocess.run([os.environ['LUAU_BIN'],str(original)],capture_output=True,timeout=5)
                    actual=subprocess.run([os.environ['LUAU_BIN'],str(protected)],capture_output=True,timeout=5)
                    self.assertEqual(reference.returncode,0,reference.stderr)
                    self.assertEqual(actual.returncode,0,actual.stderr)
                    self.assertEqual(actual.stdout,reference.stdout)
