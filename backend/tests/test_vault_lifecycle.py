import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from backend.app.security.vault_lifecycle import (
    EncryptedRenameBlocked,
    VaultLifecycleError,
    delete_owned_document_and_ciphertext,
    reject_encrypted_rename,
)


class TestVaultLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "test.db"
        self.storage = self.root / "encrypted"
        self.storage.mkdir()
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("CREATE TABLE owned_documents (id INTEGER PRIMARY KEY, owner_user_id INTEGER NOT NULL, filename TEXT NOT NULL)")
            db.execute("CREATE TABLE encrypted_document_keys (document_id INTEGER PRIMARY KEY, storage_id TEXT NOT NULL, FOREIGN KEY(document_id) REFERENCES owned_documents(id))")
            db.executemany("INSERT INTO owned_documents VALUES (?,?,?)", [(1,101,"one.txt"),(2,102,"two.txt")])
            db.commit()

    def rows(self, sql):
        with closing(sqlite3.connect(self.database)) as db:
            return db.execute(sql).fetchall()

    def add_encrypted(self, document_id=1, storage_id="a"*32, create_file=True):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("INSERT INTO encrypted_document_keys VALUES (?,?)", (document_id,storage_id))
            db.commit()
        if create_file:
            path = self.storage / (storage_id + ".svenc")
            path.write_bytes(b"fictional-ciphertext")

    def test_plain_document_deletes_without_touching_other_owner(self):
        self.assertTrue(delete_owned_document_and_ciphertext(1,101,self.database))
        self.assertEqual(self.rows("SELECT id FROM owned_documents"), [(2,)])

    def test_cross_owner_delete_is_rejected(self):
        snapshot = self.database.read_bytes()
        self.assertFalse(delete_owned_document_and_ciphertext(1,102,self.database))
        self.assertEqual(self.rows("SELECT COUNT(*) FROM owned_documents"), [(2,)])
        self.assertEqual(self.database.read_bytes(), snapshot)

    def test_encrypted_rename_is_blocked_but_plain_rename_check_passes(self):
        self.add_encrypted()
        with self.assertRaises(EncryptedRenameBlocked):
            reject_encrypted_rename(1,101,self.database)
        reject_encrypted_rename(2,102,self.database)
        self.assertEqual(self.rows("SELECT COUNT(*) FROM owned_documents"), [(2,)])

    def test_encrypted_delete_removes_ciphertext_and_both_records(self):
        self.add_encrypted()
        # Isolate storage ID validation here: the repository exercises its
        # actual ID validator in earlier dedicated tests.
        with patch("backend.app.security.vault_lifecycle.validate_storage_id", return_value=None):
            self.assertTrue(delete_owned_document_and_ciphertext(1,101,self.database,self.storage))
        self.assertEqual(self.rows("SELECT id FROM owned_documents"), [(2,)])
        self.assertEqual(self.rows("SELECT * FROM encrypted_document_keys"), [])
        self.assertEqual(list(self.storage.iterdir()), [])

    def test_missing_ciphertext_preserves_metadata_and_key_record(self):
        self.add_encrypted(create_file=False)
        with patch("backend.app.security.vault_lifecycle.validate_storage_id", return_value=None):
            with self.assertRaises(VaultLifecycleError):
                delete_owned_document_and_ciphertext(1,101,self.database,self.storage)
        self.assertEqual(self.rows("SELECT id FROM owned_documents ORDER BY id"), [(1,),(2,)])
        self.assertEqual(self.rows("SELECT document_id FROM encrypted_document_keys"), [(1,)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
