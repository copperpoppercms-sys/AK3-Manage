import sqlite3
import tempfile
import unittest
from pathlib import Path

from bastion.store import AccessDenied, Store

SECRET = "test-only-secret-" * 4
DEVICE = "test-device-00001"


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000000
        self.store = Store(":memory:", SECRET, clock=lambda: self.now)
        self.script = self.store.upload("My Hub", b'print("original private script")')
        self.key = self.store.issue(self.script, 24)[0]

    def tearDown(self):
        self.store.close()

    def authorize(self):
        return self.store.authenticate(self.script, self.key["key"], DEVICE)

    def test_payload_is_encrypted_and_raw_keys_are_not_stored(self):
        dump = '\n'.join(self.store.db.iterdump())
        self.assertNotIn("original private script", dump)
        self.assertNotIn(self.key["key"], dump)
        self.assertNotIn(SECRET, dump)

    def test_valid_grant_delivers_exact_source_once(self):
        grant = self.authorize()
        self.assertEqual(self.store.consume(self.script, grant, DEVICE), b'print("original private script")')
        with self.assertRaises(AccessDenied): self.store.consume(self.script, grant, DEVICE)

    def test_key_binds_on_first_use(self):
        self.authorize()
        self.assertEqual(self.store.keys(self.script)[0]["device"], "bound")
        with self.assertRaisesRegex(AccessDenied, "different device"):
            self.store.authenticate(self.script, self.key["key"], "a-different-device")

    def test_wrong_device_cannot_consume_or_destroy_a_valid_grant(self):
        grant = self.authorize()
        with self.assertRaises(AccessDenied): self.store.consume(self.script, grant, "a-different-device")
        self.assertTrue(self.store.consume(self.script, grant, DEVICE))

    def test_expired_key_cannot_authenticate(self):
        self.now = self.key["expires"]
        with self.assertRaises(AccessDenied): self.authorize()

    def test_expired_key_invalidates_existing_grant(self):
        self.now = self.key["expires"] - 5
        grant = self.authorize()
        self.now += 5
        with self.assertRaises(AccessDenied): self.store.consume(self.script, grant, DEVICE)

    def test_grant_expires_after_sixty_seconds(self):
        grant = self.authorize()
        self.now += 60
        with self.assertRaises(AccessDenied): self.store.consume(self.script, grant, DEVICE)

    def test_revoking_cancels_grants_and_new_authentication(self):
        grant = self.authorize()
        self.store.change_key(self.key["id"])
        with self.assertRaises(AccessDenied): self.store.consume(self.script, grant, DEVICE)
        with self.assertRaises(AccessDenied): self.authorize()

    def test_reset_cancels_grants_then_allows_a_new_device(self):
        grant = self.authorize()
        self.store.change_key(self.key["id"], reset=True)
        with self.assertRaises(AccessDenied): self.store.consume(self.script, grant, DEVICE)
        new = self.store.authenticate(self.script, self.key["key"], "new-device-0000002")
        self.assertTrue(self.store.consume(self.script, new, "new-device-0000002"))

    def test_pause_blocks_loader_and_download(self):
        grant = self.authorize()
        self.store.set_enabled(self.script, False)
        with self.assertRaises(AccessDenied): self.store.script(self.script, enabled=True)
        with self.assertRaises(AccessDenied): self.store.consume(self.script, grant, DEVICE)
        with self.assertRaises(AccessDenied): self.authorize()

    def test_reenabling_does_not_restore_a_cancelled_grant(self):
        grant = self.authorize()
        self.store.set_enabled(self.script, False)
        self.store.set_enabled(self.script, True)
        with self.assertRaises(AccessDenied): self.store.consume(self.script, grant, DEVICE)
        self.assertTrue(self.store.consume(self.script, self.authorize(), DEVICE))

    def test_reset_does_not_unrevoke_a_key(self):
        self.store.change_key(self.key['id'])
        self.store.change_key(self.key['id'], reset=True)
        with self.assertRaises(AccessDenied): self.authorize()

    def test_cross_script_keys_and_grants_fail(self):
        other = self.store.upload("Other", b"print(2)")
        with self.assertRaises(AccessDenied): self.store.authenticate(other, self.key["key"], DEVICE)
        grant = self.authorize()
        with self.assertRaises(AccessDenied): self.store.consume(other, grant, DEVICE)

    def test_customization_rejects_code_injection_color(self):
        with self.assertRaises(ValueError): self.store.customize(self.script, "Hub", '#123456);evil()')
        self.store.customize(self.script, "New Hub", "#00ffaa")
        self.assertEqual(self.store.script(self.script)["accent"], "#00FFAA")

    def test_invalid_device_does_not_bind_a_key(self):
        with self.assertRaises(AccessDenied): self.store.authenticate(self.script, self.key["key"], "short")
        self.assertEqual(self.store.keys(self.script)[0]["device"], "unbound")

    def test_wrong_key_does_not_bind_a_device(self):
        with self.assertRaises(AccessDenied): self.store.authenticate(self.script, "BAS-incorrect-key-value-123", DEVICE)
        self.assertEqual(self.store.keys(self.script)[0]["device"], "unbound")

    def test_batches_have_distinct_keys(self):
        batch = self.store.issue(self.script, 1, 25, "new batch")
        self.assertEqual(len({row["key"] for row in batch}), 25)
        self.assertEqual(len({row["id"] for row in batch}), 25)

    def test_upload_bounds_and_types(self):
        for source in (b"", b"x" * (1024*1024+1), b"\0not text"):
            with self.subTest(size=len(source)):
                with self.assertRaises(ValueError): self.store.upload("Hub", source)
        with self.assertRaises(UnicodeError): self.store.upload("Hub", b"\xff")

    def test_activity_contains_ids_but_no_raw_credentials(self):
        grant = self.authorize()
        self.store.consume(self.script, grant, DEVICE)
        text = str(self.store.activity())
        self.assertIn("script-delivered", text)
        for secret in (DEVICE, self.key["key"], grant): self.assertNotIn(secret, text)

    def test_persistence_and_secret_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"bastion.db"
            first = Store(path, SECRET)
            script = first.upload("Persistent", b"print(123)")
            key = first.issue(script, 1)[0]["key"]
            first.close()
            with self.assertRaisesRegex(ValueError, "does not match"):
                Store(path, "another-long-and-different-secret" * 3)
            second = Store(path, SECRET)
            token = second.authenticate(script, key, DEVICE)
            self.assertEqual(second.consume(script, token, DEVICE), b"print(123)")
            second.close()
