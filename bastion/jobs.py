"""Bounded, disposable source-protection workers; never execute uploaded Lua."""
import asyncio
import base64
import json
import os
from pathlib import Path
import sys

from .obfuscate import ObfuscationError, Protected

INPUT_TIMEOUT = 25
WORKER_TIMEOUT = 30


class ProtectionJobs:
    def __init__(self):
        self.busy = False

    async def run(self, source):
        if self.busy:
            raise ObfuscationError("Another script is being obfuscated. Wait for it to finish, then retry.")
        self.busy = True
        process = None
        try:
            # The child does not inherit bot tokens, master secrets or database paths.
            process = await asyncio.create_subprocess_exec(
                sys.executable, '-m', 'bastion.worker',
                cwd=str(Path(__file__).resolve().parent.parent),
                env={key: os.environ[key] for key in ('PATH', 'SYSTEMROOT') if key in os.environ},
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL)
            try:
                output, _ = await asyncio.wait_for(process.communicate(source), WORKER_TIMEOUT)
            except TimeoutError:
                raise ObfuscationError("Obfuscation stopped after 30 seconds. Try a smaller script. Your original was not changed.") from None
            if process.returncode:
                raise ObfuscationError("The obfuscation worker stopped, possibly because the script exceeded its memory limit. Try a smaller script.")
            data = json.loads(output)
            if 'error' in data:
                raise ObfuscationError(data['error'])
            data['source'] = base64.b64decode(data['source'], validate=True)
            return Protected(**data)
        finally:
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.wait()
            self.busy = False
