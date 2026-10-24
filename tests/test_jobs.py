import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from bastion.bot import Bastion
from bastion.jobs import ProtectionJobs
from bastion.obfuscate import ObfuscationError
from bastion.store import Store


class JobTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_worker_protects_source_and_reports_invalid_syntax(self):
        jobs = ProtectionJobs()
        result = await jobs.run(b'local message="hello"; return message')
        self.assertEqual(result.renamed, 1)
        self.assertEqual(result.encoded_strings, 1)
        self.assertNotIn(b'message', result.source)
        with self.assertRaisesRegex(ObfuscationError, 'Unsupported'):
            await jobs.run(b'local value: number = 1')
        self.assertFalse(jobs.busy)

    async def test_timeout_kills_worker_and_next_job_succeeds(self):
        async def hanging(_):
            await asyncio.Event().wait()
        process = SimpleNamespace(returncode=None,communicate=AsyncMock(side_effect=hanging),kill=MagicMock(),wait=AsyncMock())
        jobs = ProtectionJobs()
        with patch('bastion.jobs.asyncio.create_subprocess_exec',new=AsyncMock(return_value=process)),patch('bastion.jobs.WORKER_TIMEOUT',0.02):
            with self.assertRaisesRegex(ObfuscationError,'stopped after'):
                await jobs.run(b'return 1')
        process.kill.assert_called_once()
        process.wait.assert_awaited_once()
        self.assertFalse(jobs.busy)
        self.assertIn(b'2', (await jobs.run(b'return 2')).source)

    async def test_cancelled_job_kills_worker_and_releases_slot(self):
        started = asyncio.Event()
        async def hanging(_):
            started.set()
            await asyncio.Event().wait()
        process = SimpleNamespace(returncode=None,communicate=AsyncMock(side_effect=hanging),kill=MagicMock(),wait=AsyncMock())
        jobs = ProtectionJobs()
        with patch('bastion.jobs.asyncio.create_subprocess_exec',new=AsyncMock(return_value=process)):
            task = asyncio.create_task(jobs.run(b'return 1'))
            await started.wait()
            with self.assertRaisesRegex(ObfuscationError,'Another script'):
                await jobs.run(b'return 2')
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        process.kill.assert_called_once()
        self.assertFalse(jobs.busy)

    async def test_deferred_failure_replaces_thinking_response(self):
        store = Store(':memory:', 'test-job-secret'*5)
        bot = Bastion(123, store, 'https://bastion.example')
        interaction = SimpleNamespace(response=SimpleNamespace(is_done=lambda:True),edit_original_response=AsyncMock())
        try:
            await bot.tree.on_error(interaction,TimeoutError())
            self.assertIn('download timed out',interaction.edit_original_response.call_args.kwargs['content'])
            await bot.tree.on_error(interaction,ObfuscationError('Unsupported syntax'))
            self.assertEqual(interaction.edit_original_response.call_args.kwargs['content'],'Unsupported syntax')
        finally:
            await bot.close()
            store.close()

    async def test_command_attachment_download_has_deadline(self):
        store = Store(':memory:', 'test-job-secret'*5)
        bot = Bastion(123, store, 'https://bastion.example')
        interaction = SimpleNamespace(response=SimpleNamespace(defer=AsyncMock()))
        async def hanging(**kwargs):
            await asyncio.Event().wait()
        try:
            with patch('bastion.bot.read_source',new=hanging),patch('bastion.bot.INPUT_TIMEOUT',0.02):
                with self.assertRaises(TimeoutError):
                    await bot.tree.get_command('obfuscate').callback(interaction,code='return 1')
            self.assertFalse(bot.protection_jobs.busy)
        finally:
            await bot.close()
            store.close()
