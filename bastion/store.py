import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.fernet import Fernet

MAX_SOURCE = 1024 * 1024


class AccessDenied(Exception):
    pass


class Store:
    def __init__(self, path, secret, clock=time.time):
        if len(secret) < 32:
            raise ValueError("MASTER_SECRET must contain at least 32 characters")
        self.secret = secret.encode()
        self.clock = clock
        self.cipher = Fernet(base64.urlsafe_b64encode(hmac.digest(self.secret, b"bastion:encryption:v1", "sha256")))
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scripts(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, accent TEXT NOT NULL,
          payload BLOB NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1, updated INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS licenses(
          id TEXT PRIMARY KEY, script_id TEXT NOT NULL REFERENCES scripts(id),
          digest TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
          issued INTEGER NOT NULL, expires INTEGER NOT NULL,
          revoked INTEGER NOT NULL DEFAULT 0, device TEXT,
          last_used INTEGER, uses INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS grants(
          digest TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES licenses(id),
          script_id TEXT NOT NULL, device TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS activity(
          id INTEGER PRIMARY KEY, at INTEGER NOT NULL, kind TEXT NOT NULL,
          script_id TEXT, key_id TEXT);
        ''')
        verifier = self.digest("configuration", "master-secret-check")
        row = self.db.execute("SELECT value FROM settings WHERE name='secret_check'").fetchone()
        if row and not hmac.compare_digest(row[0], verifier):
            self.db.close()
            raise ValueError("MASTER_SECRET does not match this database. Restore the original secret.")
        self.db.execute("INSERT OR IGNORE INTO settings VALUES('secret_check',?)", (verifier,))

    def close(self):
        self.db.close()

    def digest(self, purpose, value):
        return hmac.new(self.secret, (purpose + "\0" + value).encode(), hashlib.sha256).hexdigest()

    def event(self, kind, script_id=None, key_id=None):
        self.db.execute("INSERT INTO activity(at,kind,script_id,key_id) VALUES(?,?,?,?)",
                        (int(self.clock()), kind, script_id, key_id))
        self.db.execute("DELETE FROM activity WHERE id <= (SELECT COALESCE(MAX(id),0)-1000 FROM activity)")

    def upload(self, name, source):
        name = self.clean_name(name)
        if not source or len(source) > MAX_SOURCE or b"\0" in source:
            raise ValueError("Upload a text Lua/Luau script between 1 byte and 1 MB.")
        source.decode("utf-8")
        script_id = secrets.token_hex(8)
        self.db.execute("INSERT INTO scripts(id,name,accent,payload,sha256,size,updated) VALUES(?,?,?,?,?,?,?)",
                        (script_id, name, "#34D399", self.cipher.encrypt(source), hashlib.sha256(source).hexdigest(), len(source), int(self.clock())))
        self.event("script-uploaded", script_id)
        return script_id

    @staticmethod
    def clean_name(name):
        name = name.strip()
        if not 1 <= len(name) <= 64 or any(ord(c) < 32 for c in name):
            raise ValueError("Use a name between 1 and 64 characters without control characters.")
        return name

    def script(self, script_id, enabled=False):
        row = self.db.execute("SELECT id,name,accent,sha256,size,enabled,updated FROM scripts WHERE id=?", (script_id,)).fetchone()
        if not row or enabled and not row["enabled"]:
            raise AccessDenied("Script unavailable.")
        return dict(row)

    def scripts(self):
        return [dict(row) for row in self.db.execute("SELECT id,name,size,enabled,updated FROM scripts ORDER BY updated DESC LIMIT 100")]

    def customize(self, script_id, name, accent):
        self.script(script_id)
        name = self.clean_name(name)
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", accent):
            raise ValueError("Accent must be a hex color such as #34D399.")
        self.db.execute("UPDATE scripts SET name=?,accent=?,updated=? WHERE id=?", (name, accent.upper(), int(self.clock()), script_id))
        self.event("hub-customized", script_id)

    def set_enabled(self, script_id, enabled):
        self.script(script_id)
        self.db.execute("UPDATE scripts SET enabled=? WHERE id=?", (int(enabled), script_id))
        if not enabled:
            self.db.execute("DELETE FROM grants WHERE script_id=?", (script_id,))
        self.event("script-enabled" if enabled else "script-disabled", script_id)

    def issue(self, script_id, hours, amount=1, label=""):
        self.script(script_id, enabled=True)
        if not 1 <= hours <= 8760 or not 1 <= amount <= 25:
            raise ValueError("Duration: 1–8760 hours. Batch size: 1–25.")
        if len(label) > 64 or any(ord(c) < 32 for c in label):
            raise ValueError("Labels must be at most 64 characters without control characters.")
        now = int(self.clock())
        issued = []
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for _ in range(amount):
                key, key_id = "BAS-" + secrets.token_urlsafe(24), secrets.token_hex(6)
                expires = now + hours * 3600
                self.db.execute("INSERT INTO licenses(id,script_id,digest,label,issued,expires) VALUES(?,?,?,?,?,?)",
                                (key_id, script_id, self.digest("license", key), label, now, expires))
                self.event("key-issued", script_id, key_id)
                issued.append({"id": key_id, "key": key, "expires": expires})
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return issued

    def keys(self, script_id):
        self.script(script_id)
        rows = self.db.execute("SELECT id,label,issued,expires,revoked,device,last_used,uses FROM licenses WHERE script_id=? ORDER BY issued DESC,id LIMIT 100", (script_id,))
        return [{**dict(row), "device": "bound" if row["device"] else "unbound"} for row in rows]

    def change_key(self, key_id, reset=False):
        row = self.db.execute("SELECT script_id FROM licenses WHERE id=?", (key_id,)).fetchone()
        if not row:
            raise ValueError("Key ID not found.")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if reset:
                self.db.execute("UPDATE licenses SET device=NULL WHERE id=?", (key_id,))
            else:
                self.db.execute("UPDATE licenses SET revoked=1 WHERE id=?", (key_id,))
            self.db.execute("DELETE FROM grants WHERE key_id=?", (key_id,))
            self.event("device-reset" if reset else "key-revoked", row[0], key_id)
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def device_digest(self, device):
        if not isinstance(device, str) or not 8 <= len(device) <= 256 or any(ord(c) < 32 for c in device):
            raise AccessDenied("Invalid device identifier.")
        return self.digest("device", device)

    def authenticate(self, script_id, key, device):
        if not isinstance(key, str) or not 20 <= len(key) <= 100:
            raise AccessDenied("Invalid or inactive key.")
        device_hash = self.device_digest(device)
        now = int(self.clock())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.script(script_id, enabled=True)
            row = self.db.execute("SELECT * FROM licenses WHERE digest=? AND script_id=?", (self.digest("license", key), script_id)).fetchone()
            if not row or row["revoked"] or row["expires"] <= now:
                raise AccessDenied("Invalid or inactive key.")
            if row["device"] and not hmac.compare_digest(row["device"], device_hash):
                raise AccessDenied("This key is bound to a different device.")
            self.db.execute("UPDATE licenses SET device=?,last_used=?,uses=uses+1 WHERE id=?", (device_hash, now, row["id"]))
            token = secrets.token_urlsafe(32)
            self.db.execute("DELETE FROM grants WHERE expires<=?", (now,))
            self.db.execute("INSERT INTO grants VALUES(?,?,?,?,?)", (self.digest("grant", token), row["id"], script_id, device_hash, now + 60))
            self.event("authenticated", script_id, row["id"])
            self.db.execute("COMMIT")
            return token
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def consume(self, script_id, token, device):
        if not isinstance(token, str) or not 20 <= len(token) <= 100:
            raise AccessDenied("Invalid download grant.")
        device_hash = self.device_digest(device)
        now = int(self.clock())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute('''SELECT g.*,k.revoked,k.expires AS key_expires,k.device AS key_device,s.enabled,s.payload
                FROM grants g JOIN licenses k ON k.id=g.key_id JOIN scripts s ON s.id=g.script_id
                WHERE g.digest=? AND g.script_id=?''', (self.digest("grant", token), script_id)).fetchone()
            if not row or row["expires"] <= now or row["key_expires"] <= now or row["revoked"] or not row["enabled"]:
                raise AccessDenied("Download access denied.")
            if not hmac.compare_digest(row["device"], device_hash) or not hmac.compare_digest(row["key_device"] or "", device_hash):
                raise AccessDenied("Download access denied.")
            source = self.cipher.decrypt(row["payload"])
            self.db.execute("DELETE FROM grants WHERE digest=?", (row["digest"],))
            self.event("script-delivered", script_id, row["key_id"])
            self.db.execute("COMMIT")
            return source
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def activity(self):
        return [dict(row) for row in self.db.execute("SELECT at,kind,script_id,key_id FROM activity ORDER BY id DESC LIMIT 25")]
