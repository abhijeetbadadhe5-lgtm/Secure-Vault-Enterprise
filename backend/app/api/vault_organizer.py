"""Isolated-demo organizational metadata and best-effort server-observed event log.

No original database schema changes. Do not use as a compliance audit trail.
"""
from __future__ import annotations
import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from backend.app.api.auth import get_current_user
from backend.app.security.tokens import decode_access_token
from backend.app.database.user_repository import get_user_by_id

BACKEND = Path(__file__).resolve().parents[2]
MAIN_DB = BACKEND / 'data' / 'securevault.db'
SIDE_DB = BACKEND / 'data' / 'vault_organization.db'
router = APIRouter(prefix='/vault/organize', tags=['Vault Organization'])
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$')
EVENTS = {'document_created', 'encrypted_uploaded', 'encrypted_downloaded', 'document_deleted', 'document_renamed', 'organization_updated'}


def _connect(path: Path, *, readonly=False):
    path = Path(path).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('Vault database unavailable')
    if readonly:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)
    else:
        connection = sqlite3.connect(path, timeout=3)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_sidecar(path=SIDE_DB):
    """Explicit installer-only migration. Never run automatically on requests."""
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('Existing isolated organization database required')
    with closing(_connect(path)) as db, db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('''CREATE TABLE IF NOT EXISTS document_organization (
            document_id INTEGER PRIMARY KEY,
            folder TEXT NOT NULL DEFAULT 'Unfiled',
            tags TEXT NOT NULL DEFAULT '[]',
            favorite INTEGER NOT NULL DEFAULT 0 CHECK(favorite IN (0,1)),
            updated_at TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS vault_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            document_id INTEGER,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL)''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_vault_events_owner ON vault_events(owner_user_id,id DESC)')


def _owner(user):
    value = user.get('user_id') if isinstance(user, dict) else None
    if type(value) is not int or value < 1:
        raise HTTPException(401, 'Authentication required')
    return value


def _owned(document_id, owner_user_id):
    if type(document_id) is not int or document_id < 1:
        raise HTTPException(404, 'Document not found')
    with closing(_connect(MAIN_DB, readonly=True)) as db:
        record = db.execute('SELECT id,filename FROM owned_documents WHERE id=? AND owner_user_id=?', (document_id,owner_user_id)).fetchone()
    if record is None:
        raise HTTPException(404, 'Document not found')
    return dict(record)


def _insert_event(owner, event, document=None):
    if event not in EVENTS:
        raise ValueError('Invalid event type')
    with closing(_connect(SIDE_DB)) as db, db:
        db.execute('INSERT INTO vault_events(owner_user_id,document_id,event_type,created_at) VALUES (?,?,?,?)',
                   (owner,document,event,datetime.now(timezone.utc).isoformat(timespec='seconds')))
        if event == 'document_deleted' and document is not None:
            db.execute('DELETE FROM document_organization WHERE document_id=?',(document,))


def _validate_label(label):
    if not isinstance(label, str) or not NAME_RE.fullmatch(label) or '..' in label:
        raise HTTPException(422, 'Folder and tags must use 1–32 safe characters')
    return label


class OrganizationUpdate(BaseModel):
    folder: str = 'Unfiled'
    tags: list[str] = []
    favorite: bool = False


@router.get('/snapshot')
def snapshot(user=Depends(get_current_user)):
    owner = _owner(user)
    with closing(_connect(MAIN_DB, readonly=True)) as db:
        rows = db.execute('SELECT id FROM owned_documents WHERE owner_user_id=? ORDER BY id DESC LIMIT 500', (owner,)).fetchall()
        ids = [int(r['id']) for r in rows]
        has_keys = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='encrypted_document_keys'").fetchone() is not None
        encrypted = set()
        if has_keys and ids:
            for row in db.execute('''SELECT k.document_id FROM encrypted_document_keys k
                      JOIN owned_documents d ON d.id=k.document_id WHERE d.owner_user_id=?''',(owner,)):
                encrypted.add(row['document_id'])
    organized = {}
    if ids:
        with closing(_connect(SIDE_DB, readonly=True)) as db:
            for row in db.execute('SELECT document_id,folder,tags,favorite FROM document_organization WHERE document_id IN ('+','.join('?' for _ in ids)+')',ids):
                try: tags = json.loads(row['tags'])
                except (ValueError,TypeError): tags=[]
                organized[row['document_id']] = {'folder':row['folder'],'tags':tags,'favorite':bool(row['favorite'])}
    return {'items': {str(i): {**organized.get(i,{'folder':'Unfiled','tags':[],'favorite':False}), 'has_encrypted_key_record':i in encrypted} for i in ids},
            'scope':'First 500 owned records by ID; key-record presence does not prove ciphertext recoverability'}


@router.put('/documents/{document_id}')
def save_organization(document_id: int, payload: OrganizationUpdate, user=Depends(get_current_user)):
    owner = _owner(user)
    _owned(document_id,owner)
    folder = _validate_label(payload.folder)
    if len(payload.tags) > 8:
        raise HTTPException(422,'Maximum 8 tags')
    tags = list(dict.fromkeys(_validate_label(t) for t in payload.tags))
    with closing(_connect(SIDE_DB)) as db, db:
        db.execute('''INSERT INTO document_organization(document_id,folder,tags,favorite,updated_at)
            VALUES (?,?,?,?,?) ON CONFLICT(document_id) DO UPDATE SET folder=excluded.folder,tags=excluded.tags,
            favorite=excluded.favorite,updated_at=excluded.updated_at''',
            (document_id, folder, json.dumps(tags), int(payload.favorite),datetime.now(timezone.utc).isoformat(timespec='seconds')))
    _insert_event(owner,'organization_updated',document_id)
    return {'id':document_id,'folder':folder,'tags':tags,'favorite':payload.favorite}


@router.get('/activity')
def activity(limit:int=Query(30,ge=1,le=100), user=Depends(get_current_user)):
    owner = _owner(user)
    with closing(_connect(SIDE_DB,readonly=True)) as db:
        events = [dict(r) for r in db.execute('''SELECT id,document_id,event_type,created_at FROM vault_events
                   WHERE owner_user_id=? ORDER BY id DESC LIMIT ?''',(owner,limit))]
    return {'events':events, 'notice':'Best-effort local audit history; not tamper-resistant or compliance-grade'}


def observe_actions(app):
    """Observe successful API responses in this isolated runtime, never request bodies."""
    @app.middleware('http')
    async def vault_activity_observer(request:Request, call_next):
        response = await call_next(request)
        if response.status_code < 200 or response.status_code >= 300:
            return response
        path = request.url.path
        method = request.method.upper()
        event, document = None, None
        if path == '/documents/private' and method == 'POST': event='document_created'
        else:
            match = re.fullmatch(r'/documents/(\d+)/encrypted-content',path)
            if match and method in ('POST','GET'):
                event = 'encrypted_uploaded' if method=='POST' else 'encrypted_downloaded'
                document=int(match.group(1))
            else:
                match = re.fullmatch(r'/documents/private/(\d+)',path)
                if match and method in ('DELETE','PATCH'):
                    event='document_deleted' if method=='DELETE' else 'document_renamed'
                    document=int(match.group(1))
        if event is not None:
            try:
                authorization=request.headers.get('authorization','')
                if authorization.startswith('Bearer '):
                    owner=int(decode_access_token(authorization[7:]))
                    if get_user_by_id(owner) is not None:
                        _insert_event(owner,event,document)
            except Exception:
                # Operational audit errors never break an already successful file operation.
                pass
        return response
