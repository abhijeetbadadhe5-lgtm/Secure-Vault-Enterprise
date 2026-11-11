<div align="center">

# SecureVault Enterprise

### A Windows-first document vault with authenticated APIs and guarded encrypted storage.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows&logoColor=white)](https://www.microsoft.com/windows)

**[Repository](https://github.com/abhijeetbadadhe5-lgtm/Secure-Vault-Enterprise) · [API overview](#api-overview) · [Local setup](#run-locally) · [Screenshots](#screenshots)**

</div>

---

## Overview

SecureVault Enterprise is a local-first document-management project built around a Python/FastAPI backend, a browser-based dashboard, and security controls for authentication, document ownership, file integrity, and encrypted storage.

The project explores how a document vault can combine short-lived access tokens, authenticated encryption, protected key material, and owner-scoped API operations. Encrypted upload and download routes are deliberately **guarded and disabled by default**; they are registered only after explicit configuration and server-side preflight checks.

> **Project status:** Development / local MVP. This repository is not presented as a production-audited service. Review the configuration and limitations below before enabling encrypted storage or using real documents.

## Features

| Area | Current implementation |
|---|---|
| Web dashboard | Browser UI served at `/vault`, with document metadata, search, sorting, folders, tags, favorites, and activity views |
| Authentication | Username/password verification, Argon2id password hashing, and short-lived JWT Bearer tokens |
| Authorization | Protected document routes resolve the authenticated identity and use owner-scoped database queries |
| File encryption | AES-256-GCM encryption modules with authenticated associated data |
| Key protection | Windows DPAPI protects a Key Encryption Key (KEK) for the current Windows user; key-wrapping code protects document keys |
| Integrity metadata | SHA-256 fingerprints for document content and upload validation |
| Data layer | SQLite repositories and migration modules for user and document metadata |
| Upload safeguards | Filename, file-type, content, and size checks; encrypted upload activation includes configuration and key-recovery preflight |
| Binary-file module | Guarded PDF, DOCX, XLSX, PNG, and JPEG handling with structural checks and a 5 MiB limit |

### Security design highlights

- **Argon2id password hashing:** passwords are verified against stored hashes rather than stored as plaintext.
- **JWT Bearer authentication:** tokens use HS256, include an issuer and expiry, and have a configured 15-minute lifetime.
- **AES-256-GCM:** authenticated encryption detects changes to ciphertext, authentication tags, keys, or associated context.
- **Owner-bound context:** encryption metadata can bind content to a document owner and filename or storage identifier.
- **Windows DPAPI:** a 256-bit KEK is protected for the current Windows user. A protected key file is not a portable substitute for a secure key backup.
- **SHA-256:** content fingerprints support integrity checking; a hash by itself is not encryption or proof of authenticity.
- **Browser protections:** the dashboard keeps its access token in tab memory and UI responses set controls such as `Cache-Control: no-store`, `X-Content-Type-Options`, and a Content Security Policy.

## Architecture

The high-level authenticated document flow is:

~~~mermaid
flowchart TD
    A[Browser dashboard] --> B[POST /auth/token]
    B --> C[Verify password hash]
    C --> D[Issue short-lived JWT]
    D --> E[Protected API request with Bearer token]
    E --> F[Verify token and resolve user]
    F --> G[Check document ownership]
    G --> H[(SQLite metadata)]
    G --> I{Encrypted routes enabled?}
    I -- No --> J[Encrypted storage remains unavailable]
    I -- Yes, after preflight --> K[AES-256-GCM file encryption]
    K --> L[Wrap document key with protected KEK]
    L --> M[Ciphertext storage]
    M --> N[Owner-checked download and authenticated decryption]
~~~

This diagram describes the guarded encrypted-storage path. Encrypted routes are not available in the default configuration.

## Technology stack

- **Backend:** Python 3.10+, FastAPI, Pydantic
- **Authentication:** PyJWT, Argon2
- **Cryptography:** `cryptography` (AES-GCM), SHA-256, Windows DPAPI via `pywin32`
- **Database:** SQLite
- **Frontend:** HTML, CSS, vanilla JavaScript
- **API style:** REST with JSON and Bearer-token authentication
- **Development platform:** Windows 10/11

## Repository structure

~~~text
Secure-Vault-Enterprise/
├── backend/
│   ├── api_main.py                 # FastAPI application entry point
│   ├── app/
│   │   ├── api/                    # Authentication, documents, vault UI and APIs
│   │   ├── core/                   # Core application configuration
│   │   ├── database/               # SQLite access, repositories and migrations
│   │   ├── security/               # JWT, password, encryption and key protection
│   │   └── services/               # Document services
│   └── tests/                      # Available focused test modules
├── frontend/
│   ├── index.html                  # Vault dashboard
│   ├── vault.css                   # Dashboard styling
│   └── vault.js                    # Dashboard interactions and API calls
└── README.md
~~~

## Run locally

The repository currently does not include a pinned dependency manifest or a complete first-run provisioning script. The commands below install the main runtime dependencies in a Windows virtual environment; they are a development starting point, not a reproducible locked build.

### 1. Prerequisites

- Windows 10 or Windows 11
- Python 3.10 or later
- PowerShell and Git

Windows is required for the DPAPI-backed key-store implementation.

### 2. Clone and create a virtual environment

~~~powershell
git clone https://github.com/abhijeetbadadhe5-lgtm/Secure-Vault-Enterprise.git
cd Secure-Vault-Enterprise

py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
~~~

### 3. Install the main dependencies

~~~powershell
.\.venv\Scripts\python.exe -m pip install fastapi "uvicorn[standard]" cryptography PyJWT argon2-cffi pywin32 python-multipart httpx
~~~

### 4. Set a development JWT secret

The token service requires `SECUREVAULT_JWT_SECRET` to contain at least 32 characters. Generate a fresh local value; do not commit or share it.

~~~powershell
$env:SECUREVAULT_JWT_SECRET = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))")
~~~

### 5. Start the API

~~~powershell
.\.venv\Scripts\python.exe -m uvicorn backend.api_main:app --reload --host 127.0.0.1 --port 8000
~~~

Open these local addresses:

- Dashboard: http://127.0.0.1:8000/vault
- Health check: http://127.0.0.1:8000/health
- Interactive API documentation: http://127.0.0.1:8000/docs

**Account note:** the current API exposes token issuance and identity routes, but does not expose a public sign-up screen or public registration endpoint. A local account and the required document database schema must be provisioned before authenticated document operations can be exercised.

## Encrypted-storage configuration

Encrypted upload is **off by default**. Do not enable it against real data just to make the dashboard show an enabled status.

The guarded activation path requires all of the following:

1. `SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD=1`
2. `SECUREVAULT_UPLOAD_DB_PATH` — an existing SQLite database with the expected document and encrypted-key tables.
3. `SECUREVAULT_UPLOAD_STORAGE_DIR` — an existing trusted ciphertext directory.
4. `SECUREVAULT_UPLOAD_KEK_DIR` — an existing protected-key directory.
5. `SECUREVAULT_UPLOAD_KEK_ID` — the identifier of an existing DPAPI-protected KEK that the current Windows user can recover.

The application checks the paths, database schema, and protected key before registering encrypted routes. It does not create replacement keys or silently initialize encrypted storage during this preflight. Keep the ciphertext directory separate from the protected-key directory.

The optional binary-document API has additional existing-storage and database prerequisites. Its file checks are structural validation, **not antivirus or malware scanning**.

## API overview

| Method | Endpoint | Purpose | Access |
|---|---|---|---|
| GET | `/health` | Application health response | Public |
| POST | `/auth/token` | Verify credentials and issue a JWT | Credentials required |
| GET | `/auth/me` | Return the authenticated account identity | Bearer token |
| GET / POST | `/documents/private` | List owned document metadata / create a metadata record | Bearer token |
| GET / PATCH / DELETE | `/documents/private/{document_id}` | Read, rename, or delete an owned document record | Bearer token |
| POST | `/documents/private/upload/check` | Validate a text upload without storing it | Bearer token |
| GET | `/vault` | Serve the browser dashboard | Public UI shell |
| GET | `/vault/status` | Report whether guarded encrypted upload was registered | Public capability flag |
| GET / PUT | `/vault/organize/...` | Read or update folder, tag, favorite, and activity metadata | Bearer token |
| POST / GET | `/documents/{document_id}/encrypted-content` | Encrypted upload / download | Only when guarded registration succeeds |
| POST / GET | `/vault/binary/...` | Optional encrypted binary-document operations | Conditional; requires its prerequisites |

For exact request and response schemas, run the app locally and open `/docs`.

## Tests and current project status

Focused test modules currently present in the repository:

- `test_vault_ui.py`
- `test_vault_lifecycle.py`
- `test_encrypted_download_router.py`
- `test_fasttrack_acceptance.py`

The two encrypted-download / acceptance modules import a shared fixture named `test_jwt_encrypted_upload_integration.py`, which is not currently included in this repository snapshot. Restore that fixture before treating those modules as runnable. The earlier full regression count is not claimed as verified by this repository snapshot.

Before using the project beyond a local development environment:

- Restore and run the complete regression suite.
- Add a pinned dependency file and first-run database/account provisioning.
- Review every route and deployment guard.
- Add automated secret scanning and dependency/security checks.
- Test backup, restore, key recovery, and failure cases using disposable data.
- Complete a security review before enabling encrypted uploads.

## Screenshots

**Real application screenshots are not included yet.** The current repository contains no image assets. Add genuine captures from the running application rather than mockups so the README accurately represents the implementation.

Save the images under `docs/screenshots/` using these suggested names:

| Suggested file | What to capture |
|---|---|
| `01-dashboard-overview.png` | Full dashboard at `/vault`, with sample data only |
| `02-sign-in.png` | Login panel; do not show or enter a real password in the capture |
| `03-document-library.png` | Authenticated document table with fictional filenames and IDs |
| `04-organization-filters.png` | Folder, tag, favorite, search, and sorting controls |
| `05-activity-security.png` | Activity / security panel, with identifying details redacted |
| `06-api-docs.png` | FastAPI `/docs` page showing the main endpoint groups |
| `07-encrypted-flow.png` | Optional successful test upload/download demonstration from an isolated test environment |

After the real image files are added, embed them in this section using relative Markdown image links. For example:

~~~markdown
![SecureVault dashboard](docs/screenshots/01-dashboard-overview.png)
~~~

**Screenshot safety:** use fictional test accounts and documents. Never include passwords, JWTs, API keys, DPAPI files, private keys, real personal documents, database contents, or sensitive filesystem paths.

## Security and responsible use

This repository is for learning, demonstration, and local development. It has not been independently security-audited or certified for regulated or production workloads. Do not expose the development server to the public internet. Do not commit `.env` files, signing secrets, private keys, DPAPI-protected key files, SQLite databases, ciphertext, or real customer documents.

Cryptographic primitives do not by themselves make an application production-secure. Production use would require threat modelling, hardened deployment, access-control review, key lifecycle and recovery procedures, logging controls, backups, monitoring, and independent security testing.

## Author

**Abhijeet Badadhe**

- GitHub: [@abhijeetbadadhe5-lgtm](https://github.com/abhijeetbadadhe5-lgtm)
- Project: [SecureVault Enterprise](https://github.com/abhijeetbadadhe5-lgtm/Secure-Vault-Enterprise)

---

<div align="center">

**SecureVault Enterprise** · Built to explore practical application security, encryption, and secure document workflows.

</div>
