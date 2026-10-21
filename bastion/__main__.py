import asyncio
import logging
import os

from aiohttp import web

from .api import make_app
from .bot import Bastion
from .loader import public_url
from .store import Store


async def main():
    required = ("DISCORD_TOKEN", "OWNER_ID", "MASTER_SECRET", "PUBLIC_BASE_URL")
    missing = [name for name in required if not os.environ.get(name, "").strip()]
    if missing:
        raise ValueError("Set these hosting variables first: " + ", ".join(missing))
    owner_id = int(os.environ["OWNER_ID"])
    base = public_url(os.environ["PUBLIC_BASE_URL"].strip())
    guild_id = int(os.environ["DISCORD_GUILD_ID"]) if os.environ.get("DISCORD_GUILD_ID", "").strip() else None
    port = int(os.environ.get("PORT", "8080"))
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be between 1 and 65535")
    store = Store(os.environ.get("DATABASE_PATH", "data/bastion.sqlite3"), os.environ["MASTER_SECRET"])
    runner = web.AppRunner(make_app(store, base), access_log=None)
    bot = Bastion(owner_id, store, base, guild_id)
    try:
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()
        async with bot:
            await bot.start(os.environ["DISCORD_TOKEN"].strip())
    finally:
        await runner.cleanup()
        store.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    try:
        asyncio.run(main())
    except (ValueError, KeyError) as error:
        raise SystemExit(str(error)) from None
