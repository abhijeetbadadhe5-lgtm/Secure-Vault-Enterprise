<div align="center">

<h1 align="center"><img src="docs/assets/securevault-logo.png" width="68" alt="SecureVault shield logo" />&nbsp; SecureVault Enterprise</h1>

### A Windows-first document vault with authenticated APIs and guarded encrypted storage.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-API-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![JavaScript](https://img.shields.io/badge/JavaScript-Vanilla-F7DF1E?logo=javascript&logoColor=222)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Windows](https://img.shields.io/badge/Windows-First-0078D4?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--GCM-6C43A3?logo=letsencrypt&logoColor=white)](https://cryptography.io/)
[![JWT](https://img.shields.io/badge/Auth-JWT-000000?logo=jsonwebtokens&logoColor=white)](https://jwt.io/)
[![Status](https://img.shields.io/badge/Status-Development-orange)](#project-status)

**[Repository](https://github.com/abhijeetbadadhe5-lgtm/Secure-Vault-Enterprise) · [Features](#feature-tour) · [Architecture](#architecture) · [Setup](#run-locally) · [Security](#security-model) · [Screenshots](#screenshots)**

<img src="https://img.shields.io/badge/BUILT_WITH-Python_%7C_FastAPI_%7C_Cryptography-202A44?style=for-the-badge" alt="Built with Python, FastAPI and cryptography" />

</div>

---

## Overview

SecureVault Enterprise is a local-first document-management project built around a Python/FastAPI backend, a browser-based dashboard, and security controls for authentication, document ownership, file integrity, and encrypted storage.

The project explores how a document vault can combine short-lived access tokens, authenticated encryption, protected key material, and owner-scoped API operations. Encrypted upload and download routes are deliberately **guarded and disabled by default**; they are registered only after explicit configuration and server-side preflight checks.

> **Project status:** Development / local MVP. This repository is not presented as a production-audited service. Review the configuration and limitations below before enabling encrypted storage or using real documents.

## Why this project?

Sensitive documents need more than a file upload button. A document vault must authenticate users, enforce ownership, protect encryption keys, detect tampering, and fail safely when its storage prerequisites are missing.

SecureVault Enterprise is a hands-on implementation project exploring those responsibilities together. It brings together backend API design, browser UI development, authentication, cryptographic building blocks, Windows-specific key protection, and database-backed document metadata.

### At a glance

| Focus | What the project demonstrates |
|---|---|
| 🔐 Identity | Password verification and short-lived JWT access tokens |
| 🛡️ Access control | Authenticated, owner-scoped document operations |
| 🔒 Confidentiality | AES-256-GCM encryption modules and key-wrapping logic |
| 🧩 Key protection | Windows DPAPI-backed KEK storage |
| 🧪 Integrity | SHA-256 fingerprints and authenticated-encryption checks |
| 🗂️ Usability | Browser dashboard, document organization, search and filters |
| ⚙️ Engineering | FastAPI routes, SQLite repositories, migrations and focused tests |

### Contents

- [Feature tour](#feature-tour)
- [Security model](#security-model)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Repository structure](#repository-structure)
- [Run locally](#run-locally)
- [Encrypted-storage configuration](#encrypted-storage-configuration)
- [API overview](#api-overview)
- [Tests and project status](#tests-and-current-project-status)
- [Screenshots](#screenshots)
- [Roadmap](#roadmap)

## Feature tour

| Capability | Description | Implementation note |
|---|---|---|
| 🖥️ Vault dashboard | Browser-based interface for navigating document metadata | Served at `/vault` |
| 👤 Authentication | Credential verification and JWT issuance | Argon2id hashes; 15-minute token lifetime |
| 🧭 Authorization | User identity resolution and document ownership checks | Protected API routes |
| 📁 Organization | Folder, tag, favorite, search and sorting workflows | Metadata-oriented operations |
| 🔐 Authenticated encryption | AES-256-GCM file encryption primitives | Encryption and authentication are combined |
| 🗝️ Key hierarchy | Data-key wrapping and protected KEK storage | Windows DPAPI-backed key store |
| 🧾 Integrity checks | SHA-256 content fingerprints and validation helpers | Hashing is separate from encryption |
| 📄 File validation | Structural checks for supported document/image formats | Not malware scanning |
| 🚦 Safe activation | Preflight checks before encrypted routes are registered | Encrypted upload is disabled by default |

> **Important distinction:** the repository contains security modules and guarded routes, but encrypted upload/download is not automatically enabled. Do not describe the application as offering active end-to-end encrypted uploads unless you have enabled the guarded path in a controlled environment and verified a complete round trip.

|
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

## Security model

SecureVault is organized around several security boundaries. Each one addresses a different risk; no single control replaces the others.

| Layer | Control | Security purpose |
|---|---|---|
| Credential storage | Argon2id password hashing | Makes offline password guessing more expensive than storing plaintext or a fast hash |
| API authentication | Signed, expiring JWT Bearer tokens | Establishes the caller identity on protected requests |
| Authorization | Owner-scoped repository queries | Prevents a user from accessing another user's document records through normal API paths |
| File confidentiality | AES-256-GCM | Encrypts content and authenticates ciphertext |
| Key protection | Key wrapping + Windows DPAPI | Separates document encryption keys from the protected KEK |
| Integrity | SHA-256 and GCM authentication | Detects content changes; GCM also authenticates encrypted payloads |
| Upload activation | Configuration and recovery preflight | Keeps encrypted routes unavailable if required storage/key prerequisites are absent |
| Browser response handling | No-store and related response headers | Reduces caching and common browser-side exposure |

### Simplified key hierarchy

~~~mermaid
flowchart TB
    A[Windows user context] --> B[DPAPI-protected KEK]
    B --> C[Wrap / unwrap document key]
    C --> D[Document Encryption Key]
    D --> E[AES-256-GCM]
    E --> F[Encrypted document]
    G[SHA-256 fingerprint] -. integrity metadata .-> F
~~~

**Security boundaries and limitations**

- DPAPI protection is tied to the Windows user and machine context. Plan and test key recovery before moving data to another machine or account.
- JWT signing secrets must be generated and stored outside source control.
- SHA-256 alone does not authenticate a file. Use authenticated encryption or a trusted signature when authenticity is required.
- File-extension and structural validation do not replace malware scanning or content-disarm-and-reconstruction.
- The project has not undergone an independent penetration test or formal cryptographic review.

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

### Request lifecycle

1. The browser submits credentials to the token endpoint.
2. The API verifies the stored password hash and issues a short-lived JWT.
3. The browser sends the token as a Bearer token on protected requests.
4. The API validates the token and resolves the authenticated user.
5. The repository operation is scoped to that user.
6. If an encrypted route is requested, it is available only when its guarded registration checks have passed.
7. On a valid encrypted-storage path, the document key is used for AES-GCM and key material is protected through the configured key hierarchy.

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

## Project status

<details>
<summary><strong>Current repository snapshot and honest status</strong></summary>

- The repository includes the FastAPI application, API modules, security modules, SQLite repositories/migrations, frontend assets, and four focused test modules.
- The encrypted upload feature is guarded and disabled by default.
- Two test modules reference a shared fixture that is not present in this repository snapshot; restore that fixture before treating those modules as runnable.
- The README's setup commands are a development starting point. A pinned dependency lockfile and complete first-run provisioning flow are still recommended.
- No production-readiness, compliance, or independent security-audit claim is made.

</details>

## Roadmap

The following are sensible next engineering milestones, not claims that they are already complete.

- [ ] Add a pinned `requirements.txt` or lockfile and documented supported Python version.
- [ ] Add a repeatable database migration and first-user provisioning command.
- [ ] Restore the missing shared test fixture and make the complete test suite reproducible from a clean clone.
- [ ] Add CI to run tests, linting, dependency checks and secret scanning on each pull request.
- [ ] Add automated tests for cross-user access denial and key-recovery failure cases.
- [ ] Add backup/restore and key-rotation procedures with documented recovery drills.
- [ ] Capture real dashboard screenshots and a short end-to-end demo using disposable sample data.
- [ ] Complete an independent security review before any production deployment.

## Screenshots

**Real application screenshots are not included yet.** The repository includes branding assets under `docs/assets/`; add genuine captures from the running application under `docs/screenshots/` rather than mockups so the README accurately represents the implementation.

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

## Demo walkthrough checklist

When preparing a portfolio demo, a useful 60–90 second walkthrough is:

1. Open the vault dashboard and explain the main navigation.
2. Show the document library using fictional sample records.
3. Demonstrate search, sorting, tags, folders or favorites.
4. Open the API documentation and identify the authentication and document routes.
5. Explain the token → identity → ownership-check request path.
6. Explain the guarded encrypted-storage design and why it is disabled by default in the checked-in configuration.

Do not demonstrate with real personal or customer documents.

## Engineering concepts demonstrated

- REST API design and request validation
- Authentication versus authorization
- Password hashing and token-based sessions
- Authenticated encryption and key hierarchy concepts
- Windows-specific key protection with DPAPI
- SQLite data access, repositories and schema migrations
- Frontend-to-backend integration
- Feature flags, startup preflight checks and fail-closed activation
- Focused automated tests and regression-oriented development

## Security and responsible use

This repository is for learning, demonstration, and local development. It has not been independently security-audited or certified for regulated or production workloads. Do not expose the development server to the public internet. Do not commit `.env` files, signing secrets, private keys, DPAPI-protected key files, SQLite databases, ciphertext, or real customer documents.

Cryptographic primitives do not by themselves make an application production-secure. Production use would require threat modelling, hardened deployment, access-control review, key lifecycle and recovery procedures, logging controls, backups, monitoring, and independent security testing.

## Author

**Abhijeet Badadhe**

- GitHub: [@abhijeetbadadhe5-lgtm](https://github.com/abhijeetbadadhe5-lgtm)
- Project: [SecureVault Enterprise](https://github.com/abhijeetbadadhe5-lgtm/Secure-Vault-Enterprise)

[![GitHub repository](https://img.shields.io/badge/GitHub-View_Repository-181717?logo=github&logoColor=white)](https://github.com/abhijeetbadadhe5-lgtm/Secure-Vault-Enterprise)
[![Explore code](https://img.shields.io/badge/Explore-Source_Code-2563EB?style=flat&logo=github)](https://github.com/abhijeetbadadhe5-lgtm/Secure-Vault-Enterprise/tree/main)

---

<div align="center">

**SecureVault Enterprise** · Built to explore practical application security, encryption, and secure document workflows.

</div>
