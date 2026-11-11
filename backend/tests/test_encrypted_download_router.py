"""Five download integration tests reusing the already-passing Lesson 67 fixture.

This module imports the fixture module (not its TestCase class) to avoid adding
another copy of the Lesson 67 tests to unittest discovery.
"""

import unittest

import test_jwt_encrypted_upload_integration as existing_upload_tests

from backend.app.security.encrypted_download_router import (
    create_jwt_encrypted_download_router,
)


class TestEncryptedDownloadRouter(unittest.TestCase):
    def setUp(self):
        # Reuse Lesson 67's disposable DB, storage, DPAPI KEK, JWT secret,
        # and fictional users. Its addCleanup callbacks remain on this TestCase.
        existing_upload_tests.TestJWTEncryptedUploadIntegration.setUp(self)
        self.app.include_router(
            create_jwt_encrypted_download_router(
                db_path=self.db_path,
                storage_dir=self.storage_dir,
                key_directory=self.key_directory,
            )
        )

    def token_for(self, user_id):
        return existing_upload_tests.TestJWTEncryptedUploadIntegration.token_for(
            self, user_id
        )

    def upload_alice(self):
        return existing_upload_tests.TestJWTEncryptedUploadIntegration.upload(
            self, token=self.token_for(101)
        )

    def download(self, document_id=1, token=None):
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        return self.client.get(
            f"/documents/{document_id}/encrypted-content", headers=headers
        )

    def test_valid_owner_recovers_exact_plaintext(self):
        self.assertEqual(self.upload_alice().status_code, 201)
        result = self.download(token=self.token_for(101))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content, self.content)
        self.assertEqual(result.headers["cache-control"], "no-store")
        self.assertEqual(result.headers["content-type"], "application/octet-stream")

    def test_anonymous_download_rejected(self):
        self.assertEqual(self.download().status_code, 401)

    def test_invalid_jwt_download_rejected(self):
        self.assertEqual(self.download(token="invalid.jwt.value").status_code, 401)

    def test_cross_owner_download_not_found(self):
        self.assertEqual(self.upload_alice().status_code, 201)
        self.assertEqual(self.download(token=self.token_for(102)).status_code, 404)

    def test_missing_encrypted_record_not_found(self):
        self.assertEqual(self.download(token=self.token_for(101)).status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
