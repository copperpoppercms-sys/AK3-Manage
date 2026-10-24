import asyncio
import io
import logging

import discord
from discord import app_commands

from . import VERSION
from .loader import short_loader
from .store import AccessDenied
from .jobs import INPUT_TIMEOUT, ProtectionJobs
from .inputs import read_source

BRAND = 0x34D399


async def owner_check(interaction, owner_id):
    if interaction.user.id == owner_id:
        return True
    if interaction.response.is_done():
        await interaction.followup.send("This is a private bot.", ephemeral=True)
    else:
        await interaction.response.send_message("This is a private bot.", ephemeral=True)
    return False


class OwnerTree(app_commands.CommandTree):
    async def interaction_check(self, interaction):
        return await owner_check(interaction, self.client.owner_id)


def embed(title, description):
    value = discord.Embed(title=title, description=description, color=BRAND)
    value.set_author(name="A3K BASTION")
    value.set_footer(text=f"Private control • v{VERSION}")
    return value


class OwnerPanel(discord.ui.View):
    def __init__(self, client):
        super().__init__(timeout=300)
        self.client = client

    async def interaction_check(self, interaction):
        return await owner_check(interaction, self.client.owner_id)

    @discord.ui.button(label="My scripts", style=discord.ButtonStyle.success)
    async def scripts(self, interaction, button):
        await show_scripts(interaction, self.client.store)

    @discord.ui.button(label="Recent activity", style=discord.ButtonStyle.secondary)
    async def activity(self, interaction, button):
        await show_activity(interaction, self.client.store)

    @discord.ui.button(label="Command guide", style=discord.ButtonStyle.secondary)
    async def guide(self, interaction, button):
        await interaction.response.send_message(embed=embed("Your control room", GUIDE), ephemeral=True)


GUIDE = """**Start a hub**
`/upload` — add a script from a file, public link or pasted code.
`/obfuscate` — download an obfuscated copy without creating a hub.
`/protect` — obfuscate an existing unprotected script, keeping its keys.
`/customize` — set your hub name and accent color.
`/loader` — get the loader and key-screen script.

**Control access**
`/issue` — create expiring keys, individually or in batches.
`/keys` — inspect key IDs, expiry and device status.
`/revoke` — deny future access for a key.
`/reset_device` — let a key bind to a new device.
`/enable` — enable or pause a complete script.

**Review**
`/scripts` — list your hubs.
`/activity` — see recent access events.

Only your configured Discord account can use these controls."""


async def send_text(interaction, text, filename):
    await interaction.response.send_message(
        file=discord.File(io.BytesIO(text.encode("utf-8")), filename=filename),
        ephemeral=True, allowed_mentions=discord.AllowedMentions.none())


async def show_scripts(interaction, store):
    rows = store.scripts()
    if not rows:
        await interaction.response.send_message(embed=embed("Your first hub", "Use `/upload` to add a Lua or Luau file. Your script ID will appear here."), ephemeral=True)
        return
    text = "\n".join(f"{row['id']} | {row['name']} | {'enabled' if row['enabled'] else 'paused'} | {row['protection']} | {row['size']} bytes" for row in rows)
    await send_text(interaction, text, "bastion-scripts.txt")


async def show_activity(interaction, store):
    rows = store.activity()
    if not rows:
        await interaction.response.send_message("No activity yet.", ephemeral=True)
        return
    from datetime import datetime, timezone
    text = "\n".join(f"{datetime.fromtimestamp(row['at'], timezone.utc).isoformat()} | {row['kind']} | script={row['script_id'] or '-'} | key={row['key_id'] or '-'}" for row in rows)
    await send_text(interaction, text, "bastion-activity.txt")


class Bastion(discord.Client):
    def __init__(self, owner_id, store, base_url, guild_id=None):
        if type(owner_id) is not int or owner_id <= 0:
            raise ValueError("A valid OWNER_ID is required. Access never defaults to everyone.")
        super().__init__(intents=discord.Intents.none(), allowed_mentions=discord.AllowedMentions.none())
        self.owner_id, self.store, self.base_url, self.guild_id = owner_id, store, base_url, guild_id
        self.protection_jobs = ProtectionJobs()
        self.tree = OwnerTree(self)
        self._commands()

    async def setup_hook(self):
        if self.guild_id:
            guild = discord.Object(id=self.guild_id)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()

    def _commands(self):
        @self.tree.command(name="panel", description="Open your private Bastion control room")
        async def panel(interaction: discord.Interaction):
            await interaction.response.send_message(
                embed=embed("Your scripts. Your rules.", "Create a hub, issue keys, and control access from one private panel.\n\nStart with `/upload`, or choose an option below."),
                view=OwnerPanel(self), ephemeral=True)

        @self.tree.command(name="scripts", description="List your script IDs and their status")
        async def scripts(interaction: discord.Interaction):
            await show_scripts(interaction, self.store)

        @self.tree.command(name="upload", description="Upload a Lua or Luau script to a new hub")
        @app_commands.describe(file="Script attachment (.lua, .luau, .txt or another text filename)",url="Public script link or standalone loadstring/HttpGet loader",code="Paste the Lua/Luau source directly")
        async def upload(interaction: discord.Interaction, name: str, file: discord.Attachment | None = None, obfuscate: bool = True, url: str | None = None, code: str | None = None):
            await interaction.response.defer(ephemeral=True, thinking=True)
            try:
                source = await asyncio.wait_for(read_source(file=file,url=url,code=code), INPUT_TIMEOUT)
                if obfuscate:
                    result = await self.protection_jobs.run(source)
                    script_id = self.store.upload(name, result.source, protection=result.protection, original_size=result.original_size)
                    detail = f"Source obfuscation enabled: {result.renamed} locals renamed, {result.encoded_strings} strings encoded."
                else:
                    script_id = self.store.upload(name, source)
                    detail = "Source obfuscation disabled."
                value = embed("Hub created", f"Script ID: `{script_id}`\n{detail}\n\nUse `/customize` to style the key screen, `/issue` to create access keys, and `/loader` to get the loader.")
                await interaction.followup.send(embed=value, ephemeral=True)
            except (ValueError, UnicodeError) as exc:
                await interaction.followup.send(str(exc) if not isinstance(exc, UnicodeError) else "The file must be UTF-8 text.", ephemeral=True)

        @self.tree.command(name="obfuscate", description="Obfuscate a Lua/Luau file and privately download the result")
        @app_commands.describe(file="Script attachment (.lua, .luau, .txt or another text filename)",url="Public script link or standalone loadstring/HttpGet loader",code="Paste the Lua/Luau source directly")
        async def obfuscate_file(interaction: discord.Interaction, file: discord.Attachment | None = None, url: str | None = None, code: str | None = None):
            await interaction.response.defer(ephemeral=True, thinking=True)
            source = await asyncio.wait_for(read_source(file=file,url=url,code=code), INPUT_TIMEOUT)
            result = await self.protection_jobs.run(source)
            await interaction.followup.send(
                content=f"Source obfuscation complete: {result.renamed} locals renamed; {result.encoded_strings} strings encoded. This is source protection, not a VM.",
                file=discord.File(io.BytesIO(result.source),filename="bastion-protected.lua"),ephemeral=True)

        @self.tree.command(name="protect", description="Obfuscate an existing script while preserving its ID and keys")
        async def protect_existing(interaction: discord.Interaction, script_id: str):
            await interaction.response.defer(ephemeral=True, thinking=True)
            source = self.store.source_for_protection(script_id)
            result = await self.protection_jobs.run(source)
            self.store.apply_protection(script_id,result)
            await interaction.followup.send("Source obfuscation enabled. Your script ID, loader and issued keys stay the same. Pending downloads were cancelled; run the loader again.",ephemeral=True)

        @self.tree.command(name="customize", description="Set the name and accent for a script's key screen")
        async def customize(interaction: discord.Interaction, script_id: str, name: str, accent: str = "#34D399"):
            self.store.customize(script_id, name, accent)
            await interaction.response.send_message(embed=embed("Hub updated", "The new name and color will appear the next time the loader is opened."), ephemeral=True)

        @self.tree.command(name="issue", description="Issue expiring keys; raw keys are shown only once")
        async def issue(interaction: discord.Interaction, script_id: str, hours: app_commands.Range[int, 1, 8760] = 24,
                        amount: app_commands.Range[int, 1, 25] = 1, label: str = ""):
            keys = self.store.issue(script_id, hours, amount, label)
            text = "A3K Bastion — keep this file private. Keys expire from the time of issue.\n\n"
            text += "\n".join(f"ID: {key['id']}\nKey: {key['key']}\nExpires (UTC Unix seconds): {key['expires']}\n" for key in keys)
            await send_text(interaction, text, "bastion-new-keys.txt")

        @self.tree.command(name="keys", description="List key IDs, expiration and device status for a script")
        async def keys(interaction: discord.Interaction, script_id: str):
            import time
            rows = self.store.keys(script_id)
            now = time.time()
            text = "\n".join(f"{row['id']} | {row['label'] or '-'} | {'revoked' if row['revoked'] else 'expired' if row['expires'] <= now else 'active'} | expires={row['expires']} | {row['device']} | checks={row['uses']}" for row in rows)
            await send_text(interaction, text or "No keys issued for this script.", "bastion-key-status.txt")

        @self.tree.command(name="revoke", description="Revoke a key by ID and cancel its pending download grants")
        async def revoke(interaction: discord.Interaction, key_id: str):
            self.store.change_key(key_id)
            await interaction.response.send_message("Key revoked. Future authentication and downloads are denied.", ephemeral=True)

        @self.tree.command(name="reset_device", description="Reset a key's device binding and cancel pending grants")
        async def reset_device(interaction: discord.Interaction, key_id: str):
            self.store.change_key(key_id, reset=True)
            await interaction.response.send_message("Device binding reset. The next successful use binds the key again.", ephemeral=True)

        @self.tree.command(name="enable", description="Enable or pause a script's loader and downloads")
        async def enable(interaction: discord.Interaction, script_id: str, enabled: bool):
            self.store.set_enabled(script_id, enabled)
            await interaction.response.send_message("Script enabled." if enabled else "Script paused. New access is denied.", ephemeral=True)

        @self.tree.command(name="loader", description="Get a loader and a copy of your hub's key-screen script")
        async def loader(interaction: discord.Interaction, script_id: str):
            from .loader import bootstrap
            script = self.store.script(script_id, enabled=True)
            snippet = short_loader(self.base_url, script_id)
            await interaction.response.send_message(
                content=f"Your loader:\n```lua\n{snippet}\n```",
                files=[discord.File(io.BytesIO(snippet.encode()), filename="bastion-loader.lua"),
                       discord.File(io.BytesIO(bootstrap(self.base_url, script).encode()), filename="bastion-key-screen.lua")],
                ephemeral=True)

        @self.tree.command(name="activity", description="Review recent key and script-access events")
        async def activity(interaction: discord.Interaction):
            await show_activity(interaction, self.store)

        @self.tree.error
        async def on_error(interaction, error):
            cause = getattr(error, "original", error)
            if isinstance(cause, TimeoutError):
                text = "The script download timed out. Try attaching the file or using a direct raw link."
            else:
                if not isinstance(cause, (ValueError, AccessDenied)):
                    logging.getLogger(__name__).error("Discord command failed", exc_info=(type(cause), cause, cause.__traceback__))
                text = str(cause) if isinstance(cause, (ValueError, AccessDenied)) else "The command could not finish. Check Railway deployment logs and try again."
            if interaction.response.is_done():
                await interaction.edit_original_response(content=text)
            else:
                await interaction.response.send_message(text, ephemeral=True)
