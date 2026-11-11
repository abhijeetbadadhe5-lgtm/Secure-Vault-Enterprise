'use strict';
// SecureVault Batch 2 - isolated demo organization + audit; existing crypto APIs unchanged
(() => {
  const $ = id => document.getElementById(id);
  const MAX_DOCS = 500, FETCH_PAGE = 100, PAGE_SIZE = 15;
  let token = null, owner = null, enabled = false;
  let documents = [], serverTotal = 0, truncated = false, page = 0, selected = null, busyUpload = false;
  const activity = [];
  let organization = {}, auditEvents = [];
  const show = (message, error = false) => {
    $('message').textContent = message;
    $('message').className = `message${error ? ' error' : ''}`;
  };
  const stamp = value => { const d = new Date(value); return Number.isNaN(d.valueOf()) ? 'Unknown' : d.toLocaleDateString(); };
  const humanBytes = n => {
    if (!Number.isFinite(Number(n))) return '—';
    n = Number(n);
    return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;
  };
  function logAction(event) {
    activity.unshift({ event, when: new Date() });
    if (activity.length > 8) activity.length = 8;
    const list = $('activityList'); list.replaceChildren();
    for (const item of activity) {
      const li = document.createElement('li');
      const time = document.createElement('time'); time.textContent = item.when.toLocaleTimeString();
      const text = document.createElement('span'); text.textContent = item.event;
      li.append(time, text); list.append(li);
    }
  }
  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const result = await fetch(path, { ...options, headers, cache:'no-store', credentials:'same-origin' });
    if (result.status === 401 && token) { logout(true); throw new Error('Session expired. Sign in again.'); }
    if (!result.ok) {
      let detail = `Request failed (${result.status})`;
      try { const data = await result.json(); if (typeof data.detail === 'string') detail = data.detail; } catch (_) {}
      throw new Error(detail);
    }
    return result;
  }
  const json = async (path, opts = {}) => (await api(path, opts)).json();
  function logout(silent = false) {
    token = null; owner = null; documents = []; selected = null; page = 0;
    $('password').value = ''; $('loginPanel').hidden = false; $('workspace').hidden = true; $('logout').hidden = true;
    $('count').textContent = '—'; $('totalBytes').textContent = '—'; $('visibleCount').textContent = '—';
    $('documents').replaceChildren(); activity.length = 0; $('activityList').replaceChildren();
    organization = {}; auditEvents = []; $('auditList').replaceChildren(); $('securitySummary').textContent = 'Sign in to view security event history.';
    if (!silent) show('Signed out.');
  }
  async function status() {
    try {
      const data = await (await fetch('/vault/status', { cache: 'no-store' })).json();
      enabled = data.encrypted_upload_enabled === true;
    } catch (_) { enabled = false; }
    $('mode').textContent = enabled ? '● Encryption enabled' : '● Storage locked';
    $('mode').className = `statuspill${enabled ? ' ready' : ''}`;
    $('storageMetric').textContent = enabled ? 'Enabled' : 'Locked';
    $('disabledNotice').hidden = enabled;
    $('uploadPanel').hidden = !enabled;
    $('uploadLocked').hidden = enabled;
  }
  async function login(event) {
    event.preventDefault(); $('loginFormButton').disabled = true; show('Signing in…');
    try {
      const payload = JSON.stringify({ username: $('username').value, password: $('password').value });
      let response = await fetch('/auth/token', { method:'POST', headers:{'Content-Type':'application/json'}, body:payload, cache:'no-store' });
      if (response.status === 404) response = await fetch('/token', { method:'POST', headers:{'Content-Type':'application/json'}, body:payload, cache:'no-store' });
      if (!response.ok) throw new Error(response.status === 401 ? 'Invalid username or password' : `Login failed (${response.status})`);
      const data = await response.json();
      if (typeof data.access_token !== 'string' || !data.access_token) throw new Error('Token missing from response');
      token = data.access_token;
      owner = await json('/auth/me').catch(async error => {
        if (String(error.message).includes('404')) return json('/me');
        throw error;
      });
      $('password').value = ''; $('loginPanel').hidden = true; $('workspace').hidden = false; $('logout').hidden = false;
      $('welcome').textContent = owner.username ? `Signed in as ${owner.username}` : 'Authenticated workspace';
      await status(); await loadDocuments(); await loadActivity(); await loadBinaryFiles(); logAction('Signed in successfully'); show('Welcome to your vault.');
    } catch (error) { show(error.message, true); }
    finally { $('loginFormButton').disabled = false; }
  }
  async function loadDocuments() {
    const next = [];
    let expected = 0;
    $('docSummary').textContent = 'Loading document metadata…';
    try {
      for (let offset = 0; offset < MAX_DOCS; offset += FETCH_PAGE) {
        const data = await json(`/documents/private?limit=${FETCH_PAGE}&offset=${offset}`);
        const batch = Array.isArray(data.documents) ? data.documents : [];
        if (offset === 0) expected = Number.isFinite(Number(data.total)) ? Number(data.total) : batch.length;
        next.push(...batch);
        if (batch.length < FETCH_PAGE || data.has_more === false) break;
      }
      documents = next; serverTotal = expected; truncated = expected > next.length;
      await loadOrganization(); page = 0; render(); await loadActivity();
    } catch (error) { $('docSummary').textContent = 'Could not load'; show(error.message, true); }
  }
  function filteredDocuments() {
    const text = $('searchInput').value.trim().toLocaleLowerCase();
    const folder = $('folderFilter').value; const favorites = $('favoriteOnly').checked;
    const results = documents.filter(d => {
      const meta = organization[String(d.id)] || {};
      return (!text || String(d.filename||'').toLocaleLowerCase().includes(text) || String(d.id).includes(text) || (meta.tags||[]).some(t => t.toLocaleLowerCase().includes(text)))
        && (!folder || (meta.folder||'Unfiled') === folder) && (!favorites || meta.favorite === true);
    });
    const sort = $('sortSelect').value;
    results.sort((a,b) => {
      if (sort === 'name') return String(a.filename||'').localeCompare(String(b.filename||''));
      if (sort === 'size') return Number(b.size_bytes||0) - Number(a.size_bytes||0);
      if (sort === 'oldest') return (Date.parse(a.created_at) || Number(a.id||0)) - (Date.parse(b.created_at) || Number(b.id||0));
      return (Date.parse(b.created_at) || Number(b.id||0)) - (Date.parse(a.created_at) || Number(a.id||0));
    });
    return results;
  }
  function button(label, style, handler) {
    const element = document.createElement('button');
    element.type = 'button'; element.className = `button ${style}`; element.textContent = label;
    element.addEventListener('click', () => handler(element));
    return element;
  }
  function textCell(tr, value) { const td = document.createElement('td'); td.textContent = value; tr.append(td); return td; }
  function render() {
    const items = filteredDocuments();
    page = Math.min(page, Math.max(0, Math.ceil(items.length / PAGE_SIZE) - 1));
    $('count').textContent = String(serverTotal);
    $('totalBytes').textContent = humanBytes(documents.reduce((s,d) => s + (Number(d.size_bytes) || 0), 0));
    $('visibleCount').textContent = String(items.length);
    $('docSummary').textContent = `${items.length} matching · ${serverTotal} total owned records`;
    $('searchScope').textContent = truncated ? `Showing results from the first ${documents.length} document records (of ${serverTotal}); search is not exhaustive.` : 'Search and sorting use your loaded document metadata only. No document contents are searched.';
    $('prev').disabled = page === 0;
    $('next').disabled = (page + 1) * PAGE_SIZE >= items.length;
    $('pageLabel').textContent = `Page ${page + 1} of ${Math.max(1, Math.ceil(items.length / PAGE_SIZE))}`;
    const rows = $('documents'); rows.replaceChildren();
    const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    if (!slice.length) {
      const tr = document.createElement('tr'); textCell(tr, 'No matching documents.').colSpan = 4; rows.append(tr); return;
    }
    for (const doc of slice) {
      const tr = document.createElement('tr');
      const name = document.createElement('td');
      const icon = document.createElement('span'); icon.className = 'fileicon'; icon.textContent = '▤';
      const label = document.createElement('span'); label.className = 'filename'; label.textContent = String(doc.filename || 'Untitled');
      const info = document.createElement('span'); info.className = 'filemeta'; info.textContent = `Document ID ${doc.id}`;
      const meta = organization[String(doc.id)] || {folder:'Unfiled',tags:[],favorite:false,has_encrypted_key_record:false};
      if (meta.favorite) { const s=document.createElement('span');s.textContent='★';s.className='star';name.append(s); }
      name.append(icon,label,info);
      const folderBadge=document.createElement('span');folderBadge.className='folderbadge';folderBadge.textContent=meta.folder||'Unfiled';name.append(folderBadge);
      if ((meta.tags||[]).length) {const tags=document.createElement('span');tags.className='tagline';tags.textContent='Tags: '+meta.tags.join(', ');name.append(tags);}
      const state=document.createElement('span');state.className=meta.has_encrypted_key_record?'tagline':'recovernotice';
      state.textContent=meta.has_encrypted_key_record?'Encrypted key record present':'Metadata only — ciphertext not confirmed';name.append(state);tr.append(name);
      textCell(tr, humanBytes(doc.size_bytes)); textCell(tr, stamp(doc.created_at));
      const td = document.createElement('td'); const actions = document.createElement('div'); actions.className = 'actiongroup';
      const download = button('Download', 'subtle', b => downloadDoc(doc,b)); download.disabled = !enabled;
      const rename = button('Rename', 'subtle', () => renameDoc(doc));
      const del = button('Delete', 'danger', b => deleteDoc(doc,b));
      const organize = button('Organize', 'subtle', () => editOrganization(doc));
      const favorite = button(meta.favorite ? '★ Saved' : '☆ Favorite', 'subtle', () => toggleFavorite(doc));
      actions.append(download, rename, del, organize, favorite);
      if (enabled && !meta.has_encrypted_key_record) actions.append(button('Resume upload', 'subtle', b => resumeUpload(doc,b))); td.append(actions); tr.append(td); rows.append(tr);
    }
  }
  async function renameDoc(doc) {
    const name = prompt('New filename (.txt recommended):', String(doc.filename || ''));
    if (name === null) return;
    if (!name.trim() || name.length > 255) { show('Filename must contain 1–255 characters.', true); return; }
    try {
      await json(`/documents/private/${encodeURIComponent(doc.id)}`, { method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({filename:name}) });
      logAction(`Renamed metadata for document ${doc.id}`); await loadDocuments(); show('Metadata renamed.');
    } catch (error) { show(`Rename rejected: ${error.message}`,true); }
  }
  async function deleteDoc(doc, control) {
    if (!token || !owner) { show('Sign in before deleting.', true); return; }
    if (!confirm(`Permanently delete ${doc.filename} (ID ${doc.id})? This cannot be undone.`)) return;
    control.disabled = true;
    try {
      await api(`/documents/private/${encodeURIComponent(doc.id)}`, { method:'DELETE' });
      logAction(`Deleted document ${doc.id}`); await loadDocuments(); show('Document deleted.');
    } catch (error) { show(`Deletion failed: ${error.message}. No automatic retry was attempted.`, true); }
    finally { control.disabled = false; }
  }
  function saveBlob(bytes, name) {
    const safe = String(name || 'document.txt').replace(/[\\/:*?"<>|\x00-\x1F]/g, '_').slice(0,200) || 'document.txt';
    const url = URL.createObjectURL(new Blob([bytes], {type:'application/octet-stream'}));
    const link = document.createElement('a'); link.href = url; link.download = safe; document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  async function downloadDoc(doc, control) {
    control.disabled = true;
    try {
      const response = await api(`/documents/${encodeURIComponent(doc.id)}/encrypted-content`);
      const bytes = await response.arrayBuffer(); saveBlob(bytes, doc.filename);
      logAction(`Downloaded document ${doc.id}`); await loadActivity(); show('Decrypted download prepared.');
    } catch (error) { show(error.message,true); }
    finally { control.disabled = !enabled; }
  }
  function updateSelected(file) {
    selected = file;
    $('selectedFile').textContent = file ? `${file.name} · ${humanBytes(file.size)}` : 'No file selected';
  }
  function busy(working, text) {
    busyUpload = working; $('uploadButton').disabled = working;
    $('uploadProgress').hidden = !working;
    $('progressLabel').textContent = text || 'Working…';
  }
  async function upload(event) {
    event.preventDefault();
    if (busyUpload) return;
    if (!enabled) { show('Encrypted storage is disabled.',true); return; }
    const file = selected || $('file').files?.[0];
    if (!file) { show('Choose a text file.',true); return; }
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.txt$/.test(file.name) || file.name.includes('..')) { show('Choose a safe .txt filename (letters, digits, underscores, hyphens, periods).',true); return; }
    if (file.size < 1 || file.size > 1048576) { show('File size must be 1 byte to 1 MiB.',true); return; }
    let createdId = null;
    try {
      busy(true, 'Validating UTF-8 and preparing metadata…');
      const bytes = await file.arrayBuffer();
      const text = new TextDecoder('utf-8', { fatal:true }).decode(bytes);
      if (!text || text.length > 10000) throw new Error('Text must contain 1–10,000 characters.');
      busy(true, 'Creating owned document metadata…');
      const meta = await json('/documents/private', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({filename:file.name,content:text}) });
      createdId = meta.id;
      busy(true, 'Encrypting and saving file on the server…');
      await json(`/documents/${encodeURIComponent(meta.id)}/encrypted-content?filename=${encodeURIComponent(file.name)}`, { method:'POST', headers:{'Content-Type':'application/octet-stream'}, body:bytes });
      updateSelected(null); $('file').value = '';
      logAction(`Encrypted upload completed for document ${createdId}`); await loadDocuments(); show('Encrypted upload completed.');
    } catch (error) {
      show(`${createdId !== null ? `Metadata record ${createdId} may remain; encrypted upload failed. ` : ''}${error.message}`,true);
    } finally { busy(false); }
  }
  async function loadOrganization() {
    try {
      const data = await json('/vault/organize/snapshot');
      organization = data.items || {};
      const current = $('folderFilter').value;
      const folders = Array.from(new Set(Object.values(organization).map(v => v.folder||'Unfiled'))).sort();
      $('folderFilter').replaceChildren();
      const all = new Option('All folders',''); $('folderFilter').append(all);
      for (const folder of folders) $('folderFilter').append(new Option(folder,folder));
      $('folderFilter').value = folders.includes(current) ? current : '';
    } catch(error) { show('Organization API unavailable: '+error.message,true); }
  }
  async function loadActivity() {
    if (!token) return;
    try {
      const data=await json('/vault/organize/activity?limit=30');
      auditEvents=Array.isArray(data.events)?data.events:[];
      const list=$('auditList');list.replaceChildren();
      $('securitySummary').textContent=`${auditEvents.length} recent local events shown · Best-effort server log, not tamper resistant`;
      if (!auditEvents.length) { const li=document.createElement('li');li.textContent='No persistent events yet.';list.append(li); }
      for(const item of auditEvents){const li=document.createElement('li');const label=document.createElement('span');label.className='auditpill';label.textContent=String(item.event_type).replaceAll('_',' ');const time=document.createElement('time');time.textContent=new Date(item.created_at).toLocaleString();const ref=document.createElement('span');ref.textContent=item.document_id?` · Document ${item.document_id}`:'';li.append(time,label,ref);list.append(li);}
    }catch(error){$('securitySummary').textContent='Audit history could not load: '+error.message;}
  }
  async function saveOrganization(doc, value){
    const result=await json(`/vault/organize/documents/${encodeURIComponent(doc.id)}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});
    await loadOrganization();render();await loadActivity();return result;
  }
  async function editOrganization(doc){
    const meta=organization[String(doc.id)]||{folder:'Unfiled',tags:[],favorite:false};
    const folder=prompt('Folder (1–32 safe characters):',meta.folder||'Unfiled');if(folder===null)return;
    const tagsText=prompt('Tags (comma-separated, up to 8):',(meta.tags||[]).join(', '));if(tagsText===null)return;
    const tags=tagsText.split(',').map(v=>v.trim()).filter(Boolean);
    if(!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$/.test(folder)||folder.includes('..')||tags.length>8||tags.some(t=>!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$/.test(t)||t.includes('..'))){show('Folder/tags must use safe 1–32 character labels, maximum 8 tags.',true);return;}
    try{await saveOrganization(doc,{folder,tags,favorite:!!meta.favorite});show('Folder and tags saved to isolated demo database.');}catch(error){show(error.message,true);}
  }
  async function toggleFavorite(doc){
    const meta=organization[String(doc.id)]||{folder:'Unfiled',tags:[],favorite:false};
    try{await saveOrganization(doc,{folder:meta.folder||'Unfiled',tags:meta.tags||[],favorite:!meta.favorite});show('Favorite status saved.');}catch(error){show(error.message,true);}
  }
  async function resumeUpload(doc, control){
    if (!enabled || !token) return;
    const chooser=document.createElement('input');chooser.type='file';chooser.accept='.txt,text/plain';
    chooser.addEventListener('change',async()=>{
      const file=chooser.files?.[0];if(!file)return;
      if(file.name!==doc.filename || file.size!==Number(doc.size_bytes)){show('Resume blocked: filename or size does not match saved metadata.',true);return;}
      if(file.size<1||file.size>1048576){show('Resume file must be 1 byte–1 MiB.',true);return;}
      control.disabled=true;
      try{
        const bytes=await file.arrayBuffer();
        new TextDecoder('utf-8',{fatal:true}).decode(bytes);
        if(!crypto?.subtle)throw new Error('Browser SHA-256 support is required');
        const digest=await crypto.subtle.digest('SHA-256',bytes);
        const hash=Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,'0')).join('');
        if(hash.toLowerCase()!==String(doc.sha256||'').toLowerCase())throw new Error('Resume blocked: SHA-256 does not match metadata');
        if(!confirm(`Resume encrypted upload for existing document ID ${doc.id}?`))return;
        await json(`/documents/${encodeURIComponent(doc.id)}/encrypted-content?filename=${encodeURIComponent(doc.filename)}`,{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:bytes});
        await loadDocuments();show('Existing metadata record encrypted successfully.');
      }catch(error){show('Resume failed: '+error.message+'; review the record before retrying.',true);}
      finally{control.disabled=false;}
    },{once:true});chooser.click();
  }
  $('themeToggle').addEventListener('click', () => {
    document.body.classList.toggle('dark');
    $('themeToggle').setAttribute('aria-pressed', String(document.body.classList.contains('dark')));
  });
  $('loginForm').addEventListener('submit',login);
  $('logout').addEventListener('click',() => logout());
  $('refresh').addEventListener('click',loadDocuments);
  $('searchInput').addEventListener('input',() => {page=0;render();});
  $('sortSelect').addEventListener('change',() => {page=0;render();});
  $('folderFilter').addEventListener('change',() => {page=0;render();});
  $('favoriteOnly').addEventListener('change',() => {page=0;render();});
  $('uploadForm').addEventListener('submit',upload);
  $('file').addEventListener('change',e => updateSelected(e.target.files?.[0] || null));
  $('prev').addEventListener('click',() => {if (page > 0) {page--;render();}});
  $('next').addEventListener('click',() => { if ((page + 1)*PAGE_SIZE < filteredDocuments().length) {page++;render();} });
  const zone = $('dropzone');
  zone.addEventListener('dragover', e => {e.preventDefault();zone.classList.add('dragover');});
  zone.addEventListener('dragleave',() => zone.classList.remove('dragover'));
  zone.addEventListener('drop', e => {e.preventDefault();zone.classList.remove('dragover');const file=e.dataTransfer?.files?.[0];if(file){$('file').value='';updateSelected(file);}});
  zone.addEventListener('keydown',e => {if(e.target===zone && (e.key==='Enter'||e.key===' ')){e.preventDefault();$('file').click();}});
  // SECUREVAULT BATCH 3 — isolated binary-document interface; token remains closure-local.
  const binary = {files:[], total:0, selected:null, busy:false};
  function binaryStatus(text, error=false){
    const output=$('binaryMessage'); output.textContent=text; output.className='message'+(error?' error':'');
  }
  function selectBinary(file){
    binary.selected=file||null;
    $('binarySelected').textContent=file?`${file.name} · ${humanBytes(file.size)}`:'No binary document selected';
  }
  async function loadBinaryFiles(){
    if(!token) return;
    try{
      const data=await json('/vault/binary/files?limit=100&offset=0');
      binary.files=Array.isArray(data.files)?data.files:[]; binary.total=Number(data.total)||0;
      const list=$('binaryList');list.replaceChildren();
      $('binarySummary').textContent=`${binary.files.length} of ${binary.total} owned binary documents shown`;
      if(!binary.files.length){const li=document.createElement('li');li.textContent='No binary documents yet.';list.append(li);}
      for(const doc of binary.files){
        const li=document.createElement('li');li.className='binaryrow';
        const info=document.createElement('div');
        const name=document.createElement('strong');name.textContent=doc.filename;
        const sub=document.createElement('small');sub.textContent=` · ${humanBytes(doc.size_bytes)} · ID ${doc.id}`;
        info.append(name,sub);
        const actions=document.createElement('div');actions.className='actiongroup';
        actions.append(button('Download','subtle',async b=>{
          b.disabled=true;
          try {const response=await api(`/vault/binary/files/${encodeURIComponent(doc.id)}/download`);
               saveBlob(await response.arrayBuffer(),doc.filename);binaryStatus('Binary document downloaded.');}
          catch(error){binaryStatus(error.message,true);} finally{b.disabled=false;}
        }),button('Delete','danger',async b=>{
          if(!confirm(`Delete encrypted binary document ${doc.filename} (ID ${doc.id})?`))return;
          b.disabled=true;
          try{await api(`/vault/binary/files/${encodeURIComponent(doc.id)}`,{method:'DELETE'});
              binaryStatus('Binary document deleted.');await loadBinaryFiles();}
          catch(error){binaryStatus(error.message+'; do not retry blindly.',true);}finally{b.disabled=false;}
        }));
        li.append(info,actions);list.append(li);
      }
    }catch(error){binaryStatus(`Binary documents unavailable: ${error.message}`,true);}
  }
  async function uploadBinary(e){
    e.preventDefault();if(binary.busy)return;
    if(!token||!enabled){binaryStatus('Log in to the activated isolated vault.',true);return;}
    const file=binary.selected||$('binaryFile').files?.[0];
    if(!file){binaryStatus('Choose a PDF, DOCX, XLSX, PNG or JPEG.',true);return;}
    if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.(pdf|docx|xlsx|png|jpe?g)$/i.test(file.name)||file.name.includes('..')||file.size<1||file.size>5*1024*1024){
      binaryStatus('Use a safe supported filename and size 1 byte–5 MiB.',true);return;
    }
    binary.busy=true;$('binaryUpload').disabled=true;binaryStatus('Uploading and encrypting…');
    try {
      await json(`/vault/binary/files?filename=${encodeURIComponent(file.name)}`,{
        method:'POST',headers:{'Content-Type':'application/octet-stream'},body:await file.arrayBuffer()
      });
      binaryStatus('Binary document encrypted successfully.');
      binary.selected=null;$('binaryFile').value='';selectBinary(null);await loadBinaryFiles();
    } catch(error){binaryStatus('Upload rejected: '+error.message,true);}
    finally{binary.busy=false;$('binaryUpload').disabled=false;}
  }
  $('binaryForm').addEventListener('submit',uploadBinary);
  $('binaryFile').addEventListener('change',e=>selectBinary(e.target.files?.[0]||null));
  $('binaryRefresh').addEventListener('click',loadBinaryFiles);
  $('binaryDrop').addEventListener('dragover',e=>e.preventDefault());
  $('binaryDrop').addEventListener('drop',e=>{e.preventDefault();const f=e.dataTransfer?.files?.[0];if(f)selectBinary(f);});

  status();
})();
