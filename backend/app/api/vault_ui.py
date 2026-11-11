"""Public static SecureVault UI; JWT still required for all protected APIs."""
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

router = APIRouter(tags=["Vault UI"])
_UI_DIR = Path(__file__).resolve().parents[3] / "frontend"
_ASSETS = {"vault.css": "text/css", "vault.js": "text/javascript"}
_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
}


@router.get("/vault", include_in_schema=False)
def vault_page():
    path = _UI_DIR / "index.html"
    if not path.is_file():
        raise HTTPException(503, "Vault UI unavailable")
    return FileResponse(path, media_type="text/html", headers=_HEADERS)


@router.get("/vault/assets/{filename}", include_in_schema=False)
def vault_asset(filename: str):
    if filename not in _ASSETS:
        raise HTTPException(404, "Not found")
    path = _UI_DIR / filename
    if not path.is_file():
        raise HTTPException(503, "Vault UI unavailable")
    return FileResponse(path, media_type=_ASSETS[filename], headers={
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"
    })


@router.get("/vault/status", include_in_schema=False)
def vault_status(request: Request):
    # This is a public capability flag, not sensitive configuration.
    enabled = getattr(request.app.state, "securevault_encrypted_upload_registered", False) is True
    return JSONResponse({"encrypted_upload_enabled": enabled}, headers={
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"
    })
