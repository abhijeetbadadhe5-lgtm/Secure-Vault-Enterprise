import os

from fastapi import FastAPI, Depends



from backend.app.security.encrypted_upload_identity_guard import (
    activate_encrypted_upload_with_identity
)


from backend.app.api.health import (
    router as health_router
)

from backend.app.api.documents import (
    router as documents_router
)

from backend.app.api.document_metadata import (
    router as metadata_router
)

from backend.app.api.auth import (
    router as auth_router
)

from backend.app.api.private_documents import (
    router as private_documents_router
)

from backend.app.security.legacy_routes import (
    reject_legacy_document_access
)


app = FastAPI(
    title="SecureVault Enterprise API",
    version="0.7.0"
)


# Health endpoint
app.include_router(health_router)


# OLD DOCUMENT APIS — RETIRED
# The dependency rejects every request with HTTP 410.
# The routes are also hidden from Swagger.
app.include_router(
    documents_router,
    dependencies=[Depends(reject_legacy_document_access)],
    include_in_schema=False
)

app.include_router(
    metadata_router,
    dependencies=[Depends(reject_legacy_document_access)],
    include_in_schema=False
)


# Authentication routes
app.include_router(auth_router)


# NEW JWT-PROTECTED DOCUMENT ROUTES
app.include_router(private_documents_router)

# LESSON 69:
# Encrypted uploads are disabled by default.
#
# Explicit activation requires:
# SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD=1
#
# Registration validates trusted database,
# storage and DPAPI key configuration.
#
# Do not suppress configuration exceptions.


encrypted_upload_activation = activate_encrypted_upload_with_identity(
    app=app,
    environment=os.environ
)




@app.get("/")
def home():
    return {
        "message": "Welcome to SecureVault Enterprise API"
    }
