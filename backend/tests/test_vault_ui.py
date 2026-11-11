"""Small, isolated tests for public dashboard delivery, never touches the real DB."""
import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from backend.app.api.vault_ui import router


class TestVaultUI(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def test_dashboard_serves_without_jwt(self):
        response = self.client.get('/vault')
        self.assertEqual(response.status_code, 200)
        self.assertIn('SecureVault Enterprise', response.text)
        self.assertIn('no-store', response.headers['cache-control'])
        self.assertIn('script-src', response.headers['content-security-policy'])

    def test_assets_and_no_path_traversal(self):
        for name in ('vault.js','vault.css'):
            with self.subTest(name=name):
                response = self.client.get('/vault/assets/'+name)
                self.assertEqual(response.status_code, 200)
                self.assertIn('no-store', response.headers['cache-control'])
        self.assertEqual(self.client.get('/vault/assets/unknown.txt').status_code, 404)

    def test_disabled_status_default(self):
        response = self.client.get('/vault/status')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'encrypted_upload_enabled': False})
        self.assertEqual(response.headers['cache-control'], 'no-store')

    def test_status_reports_only_explicit_enabled_boolean(self):
        # Access via another isolated app to avoid global state.
        app = FastAPI()
        app.state.securevault_encrypted_upload_registered = True
        app.include_router(router)
        with TestClient(app) as client:
            self.assertEqual(client.get('/vault/status').json(), {'encrypted_upload_enabled': True})


if __name__ == '__main__':
    unittest.main(verbosity=2)
