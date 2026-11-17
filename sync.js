/* RCE Surface Tracker - GitHub-backed state sync
 *
 * The page stores state in localStorage (survives a browser restart).  This
 * module adds an optional second home for the state: a file in a GitHub
 * repository, pushed through the GitHub REST API directly from the browser.
 *
 * Why the browser can do this: api.github.com sends permissive CORS headers,
 * so a page served from *.github.io can PUT/GET the Contents API with a
 * token.  Verified live against the public tracker page.
 *
 * The token is entered by the operator, kept in localStorage, and is NEVER
 * written into the repository or into the page's own source.  The default
 * target is a PRIVATE repo so the notes are not published.
 */
'use strict';

const SYNC_STORE_KEY = 'rce-tracker-sync-v1';
const STATE_PATH_DEFAULT = 'tracker-state.json';

/* Normalise a state blob to the v2 shape:
 *   { checks: { key: {v: <bool>,   t: <ms>} },
 *     notes: { key: {v: <string>, t: <ms>} } }
 * The v1 shape ({key: true} / {key: "text"}) is accepted and migrated with a
 * zero timestamp, so an older store still loads and merges.
 * Shared by app.js and the merge below. */
function normalizeState(p) {
  const out = { checks: {}, notes: {} };
  if (!p || typeof p !== 'object') return out;
  for (const kind of ['checks', 'notes']) {
    const src = p[kind];
    if (!src || typeof src !== 'object') continue;
    for (const k of Object.keys(src)) {
      const entry = src[k];
      if (entry && typeof entry === 'object' && 'v' in entry) {
        out[kind][k] = { v: entry.v, t: entry.t || 0 };
      } else if (kind === 'checks') {
        out[kind][k] = { v: !!entry, t: 0 };
      } else if (typeof entry === 'string') {
        out[kind][k] = { v: entry, t: 0 };
      }
    }
  }
  return out;
}

let syncCfg = {
  enabled: false,
  token: '',
  owner: 'blackfriday-netizen',
  repo: 'rce-surface-tracker-state',
  branch: 'main',
  path: STATE_PATH_DEFAULT,
  auto: true,
  lastPush: null,
  lastPull: null,
  lastError: null
};

function loadSyncCfg() {
  try {
    const raw = localStorage.getItem(SYNC_STORE_KEY);
    if (raw) Object.assign(syncCfg, JSON.parse(raw));
  } catch (e) { /* ignore */ }
}

function saveSyncCfg() {
  try {
    localStorage.setItem(SYNC_STORE_KEY, JSON.stringify(syncCfg));
  } catch (e) { /* ignore */ }
}

/* ---------- base64 (UTF-8 safe) ---------- */

function toB64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function fromB64(b64) {
  const bin = atob(String(b64).replace(/\s+/g, ''));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/* ---------- GitHub Contents API ---------- */

function ghHeaders() {
  return {
    'Authorization': 'Bearer ' + syncCfg.token,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
}

function ghUrl(apiPath) {
  return `https://api.github.com/repos/${encodeURIComponent(syncCfg.owner)}/` +
         `${encodeURIComponent(syncCfg.repo)}${apiPath}`;
}

/** Fetch the remote state file. Returns {sha, json} or null when absent. */
async function ghFetch() {
  const url = ghUrl(`/contents/${encodeURIComponent(syncCfg.path)}`) +
              `?ref=${encodeURIComponent(syncCfg.branch)}`;
  const res = await fetch(url, { headers: ghHeaders() });
  if (res.status === 404) return null;
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`GET failed (${res.status}): ${body.slice(0, 160)}`);
  }
  const j = await res.json();
  if (!j.content) return null;
  let parsed = null;
  try {
    parsed = JSON.parse(fromB64(j.content));
  } catch (e) {
    throw new Error('remote file is not valid JSON: ' + e.message);
  }
  return { sha: j.sha, json: parsed };
}

/** Write the state file. Creates it on first push, updates it after that. */
async function ghPush(payload) {
  const url = ghUrl(`/contents/${encodeURIComponent(syncCfg.path)}`);
  const body = {
    message: 'tracker state: ' + new Date().toISOString(),
    content: toB64(JSON.stringify(payload, null, 2)),
    branch: syncCfg.branch
  };

  // The Contents API requires the blob's sha to UPDATE an existing file; it
  // must be omitted to CREATE one.  Read it first so we do not have to guess.
  const cur = await ghFetch();
  if (cur && cur.sha) body.sha = cur.sha;

  let res = await fetch(url, {
    method: 'PUT',
    headers: Object.assign(ghHeaders(), { 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  });

  // 409 = the file changed between our read and our write.  Re-read the sha
  // and retry once so a concurrent push from another tab does not wedge the
  // sync.
  if (res.status === 409) {
    const fresh = await ghFetch();
    if (fresh && fresh.sha) body.sha = fresh.sha;
    res = await fetch(url, {
      method: 'PUT',
      headers: Object.assign(ghHeaders(), { 'Content-Type': 'application/json' }),
      body: JSON.stringify(body)
    });
  }
  if (!res.ok) {
    const txt = await res.text();
    let msg = `PUT failed (${res.status})`;
    try { msg = JSON.parse(txt).message || msg; } catch (e) { msg += ': ' + txt.slice(0, 160); }
    throw new Error(msg);
  }
  const j = await res.json();
  return { sha: j.content && j.content.sha };
}

/** Verify the token can reach the configured repo. */
async function ghTest() {
  const res = await fetch(ghUrl(''), { headers: ghHeaders() });
  if (!res.ok) {
    const body = await res.text();
    let msg = `HTTP ${res.status}`;
    try { msg = JSON.parse(body).message || msg; } catch (e) {}
    throw new Error(msg);
  }
  const j = await res.json();
  return {
    ok: true,
    full_name: j.full_name,
    private: j.private,
    permission: j.permissions && j.permissions.push,
    default_branch: j.default_branch
  };
}

/* ---------- merge policy ---------- */

/* Both sides carry a per-key timestamp.  A key is taken from whichever side
 * has the newer timestamp; a key present on only one side is kept.  That way
 * two devices editing different products do not clobber each other, and a
 * note edited on one device is not reverted by another device's stale copy. */
function mergeState(local, remote) {
  // Normalise first: the remote may still be in the v1 shape ({key: true}
  // / {key: "text"}), and merging that raw would put entries the reader
  // cannot parse back into the state.
  const L = normalizeState(local);
  const R = normalizeState(remote);
  const out = { checks: {}, notes: {} };
  const conflicts = [];
  for (const kind of ['checks', 'notes']) {
    const lk = L[kind], rk = R[kind];
    const keys = new Set([...Object.keys(lk), ...Object.keys(rk)]);
    for (const k of keys) {
      const l = lk[k], r = rk[k];
      if (l === undefined) { out[kind][k] = r; continue; }
      if (r === undefined) { out[kind][k] = l; continue; }
      const lt = l.t || 0, rt = r.t || 0;
      if (rt > lt) { out[kind][k] = r; if (lt) conflicts.push(`${kind}:${k}`); }
      else if (lt > rt) { out[kind][k] = l; if (rt) conflicts.push(`${kind}:${k}`); }
      else {
        out[kind][k] = l;
        if (JSON.stringify(l.v) !== JSON.stringify(r.v)) conflicts.push(`${kind}:${k} (equal ts, kept local)`);
      }
    }
  }
  return { merged: out, conflicts };
}
