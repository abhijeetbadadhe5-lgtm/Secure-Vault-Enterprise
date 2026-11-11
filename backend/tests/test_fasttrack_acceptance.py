"""Isolated encrypted-upload/download acceptance tests.

Uses the already passing Lesson 67 fixture. The fixture creates a disposable
SQLite DB, protected KEK, and fictional user lookup; it never accesses the
real application DB or protected keys. Run on Windows with pywin32/DPAPI.
"""

import sqlite3
import unittest
from contextlib import closing

import test_jwt_encrypted_upload_integration as fixture_module

from backend.app.security.encrypted_download_router import (
    create_jwt_encrypted_download_router,
)


class TestFastTrackAcceptance(unittest.TestCase):
    def setUp(self):
        fixture_module.TestJWTEncryptedUploadIntegration.setUp(self)
        self.app.include_router(
            create_jwt_encrypted_download_router(
                db_path=self.db_path,
                storage_dir=self.storage_dir,
                key_directory=self.key_directory,
            )
        )

    def token_for(self, user_id):
        return fixture_module.TestJWTEncryptedUploadIntegration.token_for(
            self, user_id
        )

    def upload_alice(self):
        return fixture_module.TestJWTEncryptedUploadIntegration.upload(
            self, token=self.token_for(101)
        )

    def download(self, user_id=None):
        headers = (
            {}
            if user_id is None
            else {"Authorization": f"Bearer {self.token_for(user_id)}"}
        )
        return self.client.get("/documents/1/encrypted-content", headers=headers)

    def test_owner_encrypts_and_downloads_identical_content(self):
        response = self.upload_alice()
        self.assertEqual(response.status_code, 201, response.text)
        self.assertTrue(response.json()["encrypted"])
        result = self.download(user_id=101)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.content, self.content)
        self.assertEqual(result.headers.get("cache-control"), "no-store")
        self.assertEqual(result.headers.get("x-content-type-options"), "nosniff")
        self.assertNotIn(self.content, b"".join(
            path.read_bytes() for path in self.storage_dir.glob("*.svenc")
        ))

    def test_other_owner_and_anonymous_request_cannot_download(self):
        self.assertEqual(self.upload_alice().status_code, 201)
        anonymous = self.download()
        outsider = self.download(user_id=102)
        self.assertEqual(anonymous.status_code, 401)
        self.assertEqual(outsider.status_code, 404)
        self.assertNotIn(self.content, anonymous.content)
        self.assertNotIn(self.content, outsider.content)

    def test_no_key_record_or_ciphertext_before_upload(self):
        with closing(sqlite3.connect(self.db_path)) as connection:
            count_before = connection.execute(
                "SELECT COUNT(*) FROM encrypted_document_keys"
            ).fetchone()[0]
        self.assertEqual(count_before, 0)
        self.assertEqual(list(self.storage_dir.glob("*.svenc")), [])
        self.assertEqual(self.download(user_id=101).status_code, 404)
        with closing(sqlite3.connect(self.db_path)) as connection:
            count_after = connection.execute(
                "SELECT COUNT(*) FROM encrypted_document_keys"
            ).fetchone()[0]
        self.assertEqual(count_after, 0)
        self.assertEqual(list(self.storage_dir.glob("*.svenc")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
