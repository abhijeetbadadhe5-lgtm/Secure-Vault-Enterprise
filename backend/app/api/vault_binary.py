"""Isolated SecureVault binary-document API (PDF/OOXML/PNG/JPEG).

Demonstration only, single process; no change to original metadata or .txt APIs.
File length <= 5 MiB; image/OOXML checks are structural, not malware scanning.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from backend.app.api.auth import get_current_user
from backend.app.security.windows_kek_store import load_protected_kek

API = APIRouter(prefix='/vault/binary', tags=['Encrypted binary documents'])
ROOT = Path(__file__).resolve().parents[3]  # demo runtime
CORE_DB = ROOT / 'backend' / 'data' / 'securevault.db'
BINARY_DB = ROOT / 'backend' / 'data' / 'vault_binary.db'
BINARY_DIR = ROOT.parent / 'binary-files'
LIMIT = 5 * 1024 * 1024
FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.(?:pdf|docx|xlsx|png|jpg|jpeg)$', re.I)
MEDIA = {'.pdf':'application/pdf','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
         '.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
         '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg'}


def _open_database(path, *, readonly=False):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Required existing database unavailable')
    uri = path.resolve().as_uri() + '?mode=ro' if readonly else str(path)
    conn = sqlite3.connect(uri, uri=readonly, timeout=8)
    conn.row_factory = sqlite3.Row
    if not readonly: conn.execute('PRAGMA foreign_keys=ON')
    return conn


def _check_storage():
    if not BINARY_DIR.is_dir() or BINARY_DIR.is_symlink():
        raise RuntimeError('Protected binary storage unavailable')
    # Directory is created by guarded installer, never by HTTP requests.
    return BINARY_DIR


def _kek():
    key_dir = os.environ.get('SECUREVAULT_UPLOAD_KEK_DIR', '')
    key_id = os.environ.get('SECUREVAULT_UPLOAD_KEK_ID', '')
    key = load_protected_kek(Path(key_dir), key_id)['kek']
    if type(key) is not bytes or len(key) != 32:
        raise RuntimeError('Invalid protected demo key')
    return key


def _user(user):
    uid = user.get('user_id') if isinstance(user, dict) else None
    if type(uid) is not int or uid < 1:
        raise HTTPException(status_code=401,detail='Authentication required')
    return uid


def _is_safe_member(member):
    return (not member.startswith('/') and '\\' not in member and
            all(x not in ('', '..') for x in member.split('/')))


def validate(filename, data):
    """Limited structural checks; these do not establish that a file is harmless."""
    if type(filename) is not str or not FILENAME_RE.fullmatch(filename) or '..' in filename:
        raise ValueError('Unsupported or unsafe filename; PDF, DOCX, XLSX, PNG, JPG only')
    if type(data) is not bytes or not 1 <= len(data) <= LIMIT:
        raise ValueError('File must contain 1 byte to 5 MiB')
    ext = Path(filename).suffix.lower()
    if ext == '.pdf':
        if not data.startswith(b'%PDF-') or b'%%EOF' not in data[-2048:]:
            raise ValueError('PDF header/trailer validation failed')
    elif ext == '.png':
        if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data)<33 or data[12:16] != b'IHDR':
            raise ValueError('PNG structure validation failed')
    elif ext in ('.jpg','.jpeg'):
        if not (len(data)>=4 and data[:2]==b'\xff\xd8' and data[-2:]==b'\xff\xd9'):
            raise ValueError('JPEG structure validation failed')
    else:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if len(members)>512: raise ValueError('Too many archive entries')
                total = 0
                names = set()
                for member in members:
                    if not _is_safe_member(member.filename): raise ValueError('Unsafe archive path')
                    if member.flag_bits & 1: raise ValueError('Encrypted OOXML archive refused')
                    total += member.file_size
                    if total>24*1024*1024: raise ValueError('OOXML decompression budget exceeded')
                    if member.file_size>2*1024*1024 and member.file_size>max(member.compress_size,1)*100:
                        raise ValueError('Suspicious compressed entry')
                    names.add(member.filename)
                required = 'word/document.xml' if ext=='.docx' else 'xl/workbook.xml'
                if not {'[Content_Types].xml',required}.issubset(names):
                    raise ValueError('Missing expected DOCX/XLSX parts')
        except (zipfile.BadZipFile, EOFError, OSError) as err:
            raise ValueError('Invalid Office Open XML document') from err
    return MEDIA[ext]


def _aad(owner, file_id, storage, filename):
    return json.dumps(['SV-BINARY-1',owner,file_id,storage,filename],separators=(',',':')).encode()


def _cipher_path(storage):
    if not re.fullmatch('[0-9a-f]{32}',storage): raise RuntimeError('Invalid ciphertext reference')
    root=_check_storage()
    path=root/(storage+'.svbin')
    if path.is_symlink(): raise RuntimeError('Linked ciphertext refused')
    return path


def create_binary(*, owner, filename, body):
    media=validate(filename,body)
    root=_check_storage()
    kek=_kek()
    storage=secrets.token_hex(16)
    file_path=_cipher_path(storage)
    tmp=file_path.with_name(file_path.name+'.pending')
    digest=hashlib.sha256(body).hexdigest()
    with closing(_open_database(BINARY_DB)) as db:
        try:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''INSERT INTO binary_documents(owner_id,filename,media_type,size_bytes,sha256,storage_id,nonce,wrap_nonce,wrapped_dek,created_at,status)
                 VALUES(?,?,?,?,?,?,NULL,NULL,NULL,?, 'pending')''',
                 (owner,filename,media,len(body),digest,storage,datetime.now(timezone.utc).isoformat(timespec='seconds')))
            file_id=db.execute('SELECT last_insert_rowid()').fetchone()[0]
            dek=secrets.token_bytes(32); nonce=secrets.token_bytes(12); wrap_nonce=secrets.token_bytes(12)
            aad=_aad(owner,file_id,storage,filename)
            wrapped=AESGCM(kek).encrypt(wrap_nonce,dek,aad+b'|key')
            ciphertext=AESGCM(dek).encrypt(nonce,body,aad+b'|file')
            with tmp.open('xb') as stream:
                stream.write(ciphertext);stream.flush();os.fsync(stream.fileno())
            os.replace(tmp,file_path)
            db.execute("UPDATE binary_documents SET nonce=?,wrap_nonce=?,wrapped_dek=?,status='ready' WHERE id=?",
                       (nonce,wrap_nonce,wrapped,file_id))
            db.commit()
            return {'id':file_id,'filename':filename,'size_bytes':len(body),'media_type':media,'encrypted':True}
        except BaseException:
            db.rollback()
            for target in (tmp,file_path):
                try: target.unlink(missing_ok=True)
                except OSError: pass
            raise


def _find(owner, file_id):
    with closing(_open_database(BINARY_DB,readonly=True)) as db:
        row=db.execute('SELECT * FROM binary_documents WHERE id=? AND owner_id=? AND status=?',
                       (file_id,owner,'ready')).fetchone()
        return dict(row) if row else None


def read_binary(*,owner,file_id):
    row=_find(owner,file_id)
    if row is None: raise LookupError('Document not found')
    path=_cipher_path(row['storage_id'])
    if not path.is_file() or path.stat().st_size>LIMIT+16:
        raise RuntimeError('Ciphertext unavailable')
    aad=_aad(owner,file_id,row['storage_id'],row['filename'])
    dek=AESGCM(_kek()).decrypt(row['wrap_nonce'],row['wrapped_dek'],aad+b'|key')
    data=AESGCM(dek).decrypt(row['nonce'],path.read_bytes(),aad+b'|file')
    if len(data)!=row['size_bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:
        raise RuntimeError('Integrity verification failed')
    return row,data


def delete_binary(*,owner,file_id):
    root=_check_storage()
    with closing(_open_database(BINARY_DB)) as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute("SELECT storage_id FROM binary_documents WHERE id=? AND owner_id=? AND status='ready'",(file_id,owner)).fetchone()
        if row is None:
            db.rollback();return False
        path=_cipher_path(row['storage_id'])
        if not path.is_file():
            db.rollback(); raise RuntimeError('Ciphertext missing; metadata preserved')
        staged=path.with_name(path.name+'.deleting')
        if staged.exists():
            db.rollback(); raise RuntimeError('Staged deletion requires review')
        os.replace(path,staged)
        try:
            db.execute('DELETE FROM binary_documents WHERE id=? AND owner_id=?',(file_id,owner))
            db.commit()
        except BaseException:
            db.rollback(); os.replace(staged,path);raise
        # On unlink failure, staged ciphertext remains for explicit operator cleanup.
        staged.unlink(missing_ok=True)
        return True


@API.get('/files')
def list_files(user=Depends(get_current_user),limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0)):
    owner=_user(user)
    with closing(_open_database(BINARY_DB,readonly=True)) as db:
        count=db.execute("SELECT COUNT(*) FROM binary_documents WHERE owner_id=? AND status='ready'",(owner,)).fetchone()[0]
        rows=db.execute("SELECT id,filename,media_type,size_bytes,sha256,created_at FROM binary_documents WHERE owner_id=? AND status='ready' ORDER BY id DESC LIMIT ? OFFSET ?",(owner,limit,offset)).fetchall()
    return {'files':[dict(r) for r in rows],'total':count,'limit':limit,'offset':offset}


@API.post('/files',status_code=201)
async def upload_file(request:Request,filename:str=Query(...),user=Depends(get_current_user)):
    owner=_user(user)
    if request.headers.get('content-type','').split(';')[0].lower().strip()!='application/octet-stream':
        raise HTTPException(415,'Use application/octet-stream')
    chunks=[];total=0
    async for chunk in request.stream():
        total+=len(chunk)
        if total>LIMIT: raise HTTPException(413,'File exceeds 5 MiB limit')
        chunks.append(chunk)
    try: return create_binary(owner=owner,filename=filename,body=b''.join(chunks))
    except ValueError as exc: raise HTTPException(422,str(exc)) from None
    except Exception: raise HTTPException(503,'Encrypted storage temporarily unavailable') from None


@API.get('/files/{file_id}/download')
def download_file(file_id:int,user=Depends(get_current_user)):
    owner=_user(user)
    if file_id<=0: raise HTTPException(404,'Document not found')
    try: row,data=read_binary(owner=owner,file_id=file_id)
    except LookupError: raise HTTPException(404,'Document not found') from None
    except Exception: raise HTTPException(503,'Document recovery unavailable') from None
    name=quote(row['filename'],safe='')
    return Response(data,headers={'Content-Disposition':f"attachment; filename*=UTF-8''{name}", 'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'},media_type='application/octet-stream')


@API.delete('/files/{file_id}')
def delete_file(file_id:int,user=Depends(get_current_user)):
    owner=_user(user)
    if file_id<=0: raise HTTPException(404,'Document not found')
    try: removed=delete_binary(owner=owner,file_id=file_id)
    except Exception: raise HTTPException(503,'Deletion requires operator review') from None
    if not removed: raise HTTPException(404,'Document not found')
    return {'deleted':True,'id':file_id}
