# AK3 Manage — A3K Bastion

An original, owner-only Discord control room for your Lua/Luau script hubs.
Create timed access keys, customize a key screen, export loaders, bind keys to a
client-reported device ID, and revoke future access. The bot and access API run
as one application. There is no KeyForge connection, code, account, or API.

New uploads now use built-in **source obfuscation** by default: local-variable
renaming with lexical scope tracking, comment/formatting removal, and encoded
string literals. This is not VM virtualization or unbreakable protection.

## What is private

Every Discord command and panel button checks **your exact Discord user ID**.
Server administrators, server owners, other members, and other application team
members receive no management access unless they are that configured user.
All management responses and key files are ephemeral. Missing `OWNER_ID` stops
startup; access never defaults to everyone.

This implements **only you manage the bot; people you give keys to may run the
scripts**. If you want to be the only script user too, keep your generated keys
and loaders to yourself. The API has no public administrative routes. The loader
and key-authentication endpoints must be reachable so your clients can connect.

Other people may see the bot's name or command names in a shared server. A
user-ID check controls use; it cannot hide a Discord member from other members.
For a private workspace, invite the bot only to your own server.

## Features

| Command | What it does |
| --- | --- |
| `/panel` | Private control panel with buttons |
| `/upload name file/url/code obfuscate` | Add source from one attachment, public link or pasted code; obfuscation defaults to true |
| `/obfuscate file/url/code` | Privately download an obfuscated copy from one of those input sources |
| `/protect script_id` | Obfuscate an existing raw hub without changing its ID, loader or keys |
| `/scripts` | List script IDs and status |
| `/customize script_id name accent` | Set the hub name and hex accent color |
| `/issue script_id hours amount label` | Generate 1–25 keys, valid for 1–8760 hours |
| `/keys script_id` | Inspect key IDs, expiry, device status and usage |
| `/revoke key_id` | Revoke a key and its pending download grants |
| `/reset_device key_id` | Clear a device binding and pending grants |
| `/enable script_id enabled` | Pause or resume a script's access |
| `/loader script_id` | Get the one-line loader and original Bastion key-screen code |
| `/activity` | Review recent successful access and management events |

New keys bind to their first client-reported device ID. Expiry starts **when you
issue the key**, rather than when it is first redeemed. Raw keys are shown once
in a private file; only keyed hashes are kept in the database. A forgotten raw
key cannot be recovered: revoke its key ID and issue another.

## Obfuscation

After deploying this update, use `/obfuscate` with a source input to get a
`bastion-protected.lua` file. `/upload` automatically obfuscates new scripts;
select `obfuscate: false` if you deliberately want the original source served.
Use `/scripts` to see each hub's protection status (`source-v1` or `none`).

For a previously uploaded script, run `/protect` with its script ID. Existing
keys and the loader continue to work; pending one-use download grants are
cancelled. Running `/protect` again on an already protected script is rejected.
Existing database rows migrate automatically to `none`, so the update does not
silently alter old scripts. No new environment variables or secret changes are
needed. Keep your original source file separately; uploaded protected hubs store
the transformed script, not a recoverable copy of the original variable names
and comments.

### Files, links and pasted code

For `/upload` or `/obfuscate`, choose **exactly one** option:

- `file`: attach UTF-8 script text, including `.lua`, `.luau`, `.txt`, or another
  text filename. Content is checked rather than requiring a particular extension.
- `url`: provide a public HTTP/HTTPS raw script link. Standard GitHub `blob`
  links, simple GitHub Gist links, and Pastebin/Pastefy paste-page links are
  converted to raw endpoints automatically. Direct CDN/download links do not
  need a filename extension.
- `code`: paste the source directly. Lua/Luau fenced code blocks are accepted.

A standalone `loadstring(game:HttpGet("https://…"))()` snippet can be supplied as
`url` or `code`, or inside a text attachment. Its literal public URL is fetched
without executing the loader. Up to three standalone loader stages and five
HTTP redirects per stage are supported within a shared 20-second download
deadline. Mixed programs, computed URLs and authenticated key flows are not
executed or bypassed; ordinary Lua around a loader is retained as source.

Input source has a 1 MB limit. Links must be publicly reachable without account
cookies or credentials. HTML pages, archives, PDFs, binary files and invalid text
are rejected. Links to login pages or unsupported sharing sites require their
raw/download URL or an attached source file. Compressed HTTP responses are
decoded with the same size limit. Every redirect and DNS answer is checked for
private/local network targets, and connections use the checked DNS addresses.
Proxy environment variables are not used for these downloads.

These input choices do not expand the obfuscator's supported language syntax.

The static protector parses the file without executing it on the host. It
renames bound locals and explicit parameters while preserving captured variables,
shadowed declarations, member names, globals and implicit method `self`. It
preserves original expression/operator tokens, so indexed compound assignments
are not expanded into duplicate evaluations. Strings are replaced with byte
escapes; there is no base64 loader or whole-file encoding wrapper.

The current target is Roblox Luau's untyped Lua-style subset, including
`continue`, compound assignments, binary literals and generalized iteration.
**Type annotations, type declarations/assertions, backtick interpolation,
Luau if-expressions and goto/labels are unsupported.** Known name-dependent
debugger operations are rejected; dynamically looking up locals by name or
depending on original source/line numbers is incompatible. Unsupported files
fail explicitly and do not create or replace a stored hub. Parsing has a
200,000-token limit; protected output is capped at 8 MB. Different Lua dialects
can disagree on edge cases such as bare carriage returns inside long strings;
the encoder follows Luau behavior.

This protection makes casual reading harder. Variable names and strings can
still be recovered with analysis, and globals/member names remain recognizable.
It is not comparable to a dedicated VM obfuscator and cannot prevent an
authorized client from saving code.

Scripts are encrypted in storage. An accepted key produces a device-bound,
single-use download grant that expires after 60 seconds. The server checks key
expiry, revocation and script status again before returning the script. The
database persists encrypted scripts, licenses, hashed device IDs and the latest
1000 events. Activity exports show the latest 25 events; script and key lists
show up to 100 entries each.

## Setup on an iPhone

1. In Safari, open https://discord.com/developers/applications and create a **new**
   application named **A3K Bastion**. On its **Bot** page, obtain the new bot token.
   Put it directly in your hosting secret settings as `DISCORD_TOKEN`.
2. Find your Discord user ID: Discord **Settings → Advanced → Developer Mode**,
   then open your own profile and use **Copy User ID**. Set that number as
   `OWNER_ID`. This is your user ID, not the bot ID or server ID.
3. The application code is in your `copperpoppercms-sys/AK3-Manage` repository.
   Connect that repository to your host. Keep real `.env` files, tokens, uploaded
   scripts, database files and the master secret out of GitHub; use hosting
   secrets and the persistent volume for runtime data.
4. Deploy the repository to a host with persistent Python/Docker processes and
   an HTTPS domain. The included Dockerfile runs `python -m bastion`. The same
   process handles Discord and the HTTP access API; do not deploy it as a static
   website or a sleeping scheduled job.
5. Mount a persistent disk/volume at `/data`, and set
   `DATABASE_PATH=/data/bastion.sqlite3`. Without persistent storage, a redeploy
   may lose your uploaded scripts and issued keys.
6. Generate a random master secret in a trusted host terminal:
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
   Save it privately as `MASTER_SECRET`. Keep an offline copy alongside your
   database backup. Keep the same value on every restart and redeploy.
7. Set `PUBLIC_BASE_URL` to your host's HTTPS origin, for example
   `https://your-bastion.example`, with no path or query. The host normally sets
   `PORT`; otherwise set `PORT=8080` and route HTTPS to that internal port.
8. Optional: set `DISCORD_GUILD_ID` to your private server ID so slash commands
   register in that server immediately. Without it, global commands can take
   time to appear.
9. In the Developer Portal, use **OAuth2 → URL Generator** with `bot` and
   `applications.commands`, then open the invite link and select your private
   server. No Administrator permission or privileged intents are needed. Keep
   Discord's **Public Bot** setting disabled when using a personal application.
10. Run `/panel`, then `/upload`. Copy the resulting script ID, run `/issue`, and
    use `/loader` to get the loader. Test first with a harmless script such as
    `print("Bastion access works")`.

Hosting and any third-party runtime are separate from this project. There is no
promise of free always-on hosting. No live account or deployment is created by
downloading these files, and no token should be sent in chat.

## Local development

Python 3.11 or newer is required. Install `requirements.txt` in a virtual
environment. Set the variables listed in `.env.example` using your shell or
secret manager, then run:

```sh
python -m bastion
```

The application does not automatically load `.env` files. The health endpoint is
`GET /health`; it exposes only the service name, version and online status.
Install `requirements-dev.txt` for tests. Tests require no Discord token or
external application API:

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Practical limits

- This is an access-management service with a **source obfuscator**, not a VM
  obfuscator. Encryption at rest, source transforms and an authenticated loader
  do not make client-side Lua impossible to copy.
- Device binding uses the client's reported ID. It is not an unspoofable hardware
  identity or verified Discord/Roblox account identity.
- Revocation blocks future authentication and downloads. It does not terminate
  code already downloaded or running, and cannot erase a saved copy.
- Uploaded Lua is stored and delivered, never executed on the host. The generated
  GUI runs on a Roblox client and requires an HTTP request function supporting
  headers and POST, plus `loadstring`. It is not a Roblox server publishing API.
- The loader does not save access keys to client files. A key entered on a client
  is still visible to that client/runtime; there is no end-to-end source secrecy.
- The API limits callers to 60 requests per minute by socket peer address.
  Behind a reverse proxy, this may be a shared address. It intentionally does not
  trust arbitrary forwarded-IP headers. Larger deployments need a configured
  trusted proxy and a shared rate limiter.
- A host with filesystem access and the master secret can decrypt stored
  scripts. Keep backups and deployment access private. Changing the master
  secret without retaining the old value makes existing data unusable; startup
  rejects a secret that does not match the database.

## Validation

Tests cover private Discord command/button access, encrypted storage, raw-key
non-retention, expiry, device binding/reset, revocation, cross-script denial,
one-use grants, replay rejection, request size limits, rate limiting, persistence,
and the complete HTTP loader/authentication/download flow.

Input tests cover attachments, pasted code, raw-link conversion, static loader
snippets, redirects, pinned DNS checks, private-address rejection,
compressed-response size limits, and command integration.

Obfuscation tests compare original and protected program results under Lua 5.1
and official Luau 0.743, including closures, shadowed locals, recursion, methods,
multi-return/varargs, string bytes and indexed compound assignments. Set
`LUAU_BIN` to your local official Luau interpreter to enable native Luau tests;
CI installs the pinned official release and runs them. The parser is adapted
from the user's A3K Deobfuscator scope parser, with a separate source-preserving
transformation pass.

The generated Lua is checked for syntax separately in the development workspace.
Live Discord login, host deployment, real Roblox GUI rendering and actual device
behavior still require your configured bot and runtime. Those are not claimed as
tested by the offline checks.
