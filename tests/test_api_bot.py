import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp.test_utils import TestClient, TestServer

from bastion.api import make_app
from bastion.bot import Bastion, OwnerPanel
from bastion.loader import bootstrap, public_url, quote, short_loader
from bastion.store import Store

SECRET = "test-secret-not-for-production" * 3
DEVICE = "test-device-00001"


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = Store(":memory:", SECRET)
        self.script = self.store.upload("My Hub", b'print("Private payload")')
        self.key = self.store.issue(self.script, 24)[0]
        self.client = TestClient(TestServer(make_app(self.store, "https://bastion.example")))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.store.close()

    async def test_complete_flow_and_replay_denial(self):
        loader = await self.client.get('/v1/loader/'+self.script)
        self.assertEqual(loader.status, 200)
        self.assertNotIn("Private payload", await loader.text())
        self.assertEqual(loader.headers['Cache-Control'], 'no-store')
        response = await self.client.post('/v1/auth/'+self.script, json={"key":self.key["key"],"device":DEVICE})
        self.assertEqual(response.status, 200)
        token = (await response.json())["access_token"]
        headers = {"Authorization":"Bearer "+token,"X-Bastion-Device":DEVICE}
        delivered = await self.client.get('/v1/payload/'+self.script, headers=headers)
        self.assertEqual(delivered.status, 200)
        self.assertEqual(await delivered.read(), b'print("Private payload")')
        replay = await self.client.get('/v1/payload/'+self.script, headers=headers)
        self.assertEqual(replay.status, 403)

    async def test_no_administrative_http_routes(self):
        for method, path in (("get","/admin"),("post","/upload"),("post","/keys"),("get","/data/bastion.sqlite3")):
            response = await getattr(self.client,method)(path)
            self.assertEqual(response.status,404)

    async def test_payload_cannot_be_downloaded_without_authorization(self):
        response = await self.client.get('/v1/payload/'+self.script)
        self.assertEqual(response.status,403)
        self.assertNotIn("Private payload",await response.text())

    async def test_malformed_and_invalid_auth_are_not_success(self):
        path='/v1/auth/'+self.script
        for payload in ([],{}, {"key":"invalid","device":DEVICE}, {"key":self.key["key"],"device":False}):
            response=await self.client.post(path,json=payload)
            self.assertIn(response.status,(400,403))
        response=await self.client.post(path,data='broken JSON',headers={"Content-Type":"application/json"})
        self.assertEqual(response.status,400)

    async def test_pause_hides_bootstrap(self):
        self.store.set_enabled(self.script,False)
        response=await self.client.get('/v1/loader/'+self.script)
        self.assertEqual(response.status,403)

    async def test_rate_limit_is_bounded(self):
        for _ in range(60):
            response=await self.client.get('/v1/loader/'+self.script)
            self.assertEqual(response.status,200)
            await response.read()
        response=await self.client.get('/v1/loader/'+self.script)
        self.assertEqual(response.status,429)
        self.assertEqual(response.headers["Retry-After"],"60")

    async def test_request_size_limit(self):
        response=await self.client.post('/v1/auth/'+self.script,json={"key":"x"*9000,"device":DEVICE})
        self.assertEqual(response.status,413)


class OwnerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store=Store(":memory:",SECRET)
        self.bot=Bastion(123,self.store,"https://bastion.example")

    async def asyncTearDown(self):
        await self.bot.close()
        self.store.close()

    def interaction(self,user_id):
        return SimpleNamespace(user=SimpleNamespace(id=user_id),response=SimpleNamespace(is_done=lambda:False,send_message=AsyncMock()),followup=SimpleNamespace(send=AsyncMock()))

    async def test_only_owner_can_use_commands(self):
        self.assertTrue(await self.bot.tree.interaction_check(self.interaction(123)))
        other=self.interaction(456)
        self.assertFalse(await self.bot.tree.interaction_check(other))
        self.assertTrue(other.response.send_message.call_args.kwargs['ephemeral'])

    async def test_only_owner_can_use_panel_buttons(self):
        view=OwnerPanel(self.bot)
        self.assertTrue(await view.interaction_check(self.interaction(123)))
        self.assertFalse(await view.interaction_check(self.interaction(456)))

    async def test_all_expected_commands_are_registered(self):
        self.assertEqual({cmd.name for cmd in self.bot.tree.get_commands()},
            {'panel','scripts','upload','obfuscate','protect','customize','issue','keys','revoke','reset_device','enable','loader','activity'})

    async def test_missing_owner_never_defaults_to_public_access(self):
        with self.assertRaises(ValueError): Bastion(None,self.store,'https://bastion.example')


class LoaderTests(unittest.TestCase):
    def test_template_is_not_reprocessed_through_user_name(self):
        generated=bootstrap('https://bastion.example',{'id':'a'*16,'name':'__BASE__"; error("injection")','accent':'#34D399'})
        self.assertIn(quote('__BASE__"; error("injection")'),generated)
        self.assertIn('Authorization="Bearer "',generated)
        self.assertNotIn('KeyForge',generated)

    def test_short_loader_points_to_public_bootstrap(self):
        self.assertEqual(short_loader('https://bastion.example','a'*16),
                         'loadstring(game:HttpGet("https://bastion.example/v1/loader/aaaaaaaaaaaaaaaa"))()')

    def test_public_url_requires_https_origin(self):
        for url in ('http://example.com','https://user:pass@example.com','https://example.com/path','https://example.com?x=1'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError): public_url(url)
