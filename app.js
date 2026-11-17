/* RCE Surface Tracker - app
 *
 * State (checkbox + notes) is stored in localStorage under one key.  Nothing
 * is transmitted.  Export/Import moves a snapshot between browsers.
 */
'use strict';

const STORE_KEY = 'rce-tracker-state-v1';
const DATA_URL = 'data.json';

let DATA = null;
let state = { checks: {}, notes: {} };
let view = { q: '', cls: '', tier: '', take: '', sort: 'priority', show: 'all', notes: 'inline' };

/* ---------------- state ---------------- */

function loadState() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return;
    const p = JSON.parse(raw);
    if (p && typeof p === 'object') {
      state.checks = (p.checks && typeof p.checks === 'object') ? p.checks : {};
      state.notes = (p.notes && typeof p.notes === 'object') ? p.notes : {};
    }
  } catch (e) {
    console.warn('could not read saved state', e);
  }
}

let saveTimer = null;
function saveState() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(state));
    } catch (e) {
      console.warn('could not save state', e);
    }
  }, 180);
}

/* ---------------- helpers ---------------- */

const nf = new Intl.NumberFormat('en-US');
function fmt(n) {
  if (n === null || n === undefined || n === '') return '&mdash;';
  return nf.format(n);
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
function cveLinks(s) {
  if (!s) return '';
  return s.split(/,\s*/).filter(Boolean).map(c => {
    const t = esc(c);
    if (/^CVE-\d{4}-\d{4,7}$/i.test(c)) {
      return `<a class="cve" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.toUpperCase())}" target="_blank" rel="noopener noreferrer">${t}</a>`;
    }
    return `<span class="cve">${t}</span>`;
  }).join('<br>');
}

const TIER_LABEL = { T1: 'T1', T2: 'T2', T3: 'T3', T4: 'T4' };
const TAKE_LABEL = { claim: 'claim', default: 'default', secret: 'secret', unknown: '&mdash;' };

/* ---------------- filtering / sorting ---------------- */

function rowText(r) {
  return [
    r.name, r.key, r.class, r.tier, r.rce_path, r.cves,
    (r.aliases || []).join(' '), (r.also_seen_as || []).join(' '),
    r.source_notes, r.takeover_note, r.confidence, r.measured_by
  ].filter(Boolean).join(' ').toLowerCase();
}

function isDone(r) { return !!state.checks[r.key]; }
function hasNote(r) { return !!(state.notes[r.key] || '').trim(); }

function matches(r) {
  if (view.q) {
    const q = view.q.toLowerCase();
    const terms = q.split(/\s+/).filter(Boolean);
    const hay = rowText(r);
    if (!terms.every(t => hay.includes(t))) return false;
  }
  if (view.cls && r.class !== view.cls) return false;
  if (view.tier && r.tier !== view.tier) return false;
  if (view.take && r.takeover !== view.take) return false;

  if (view.show === 'todo' && isDone(r)) return false;
  if (view.show === 'done' && !isDone(r)) return false;
  if (view.show === 'noted' && !hasNote(r)) return false;
  if (view.show === 'focus') {
    // actionable = T1 product surfaces with a takeover window or a known CVE
    const actionable = (r.tier === 'T1' || r.built_in_rce === true) &&
                       (r.takeover !== 'unknown' || !!r.cves);
    if (!actionable) return false;
  }
  return true;
}

function sortRows(rows) {
  const by = view.sort;
  const numOf = r => {
    if (by === 'netlas') return r.netlas || -1;
    if (by === 'zoomeye') return r.zoomeye || -1;
    if (by === 'pop') return r.population || 0;
    return 0;
  };
  rows.sort((a, b) => {
    if (by === 'name') return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    if (by === 'tier') return (a.tier || 'ZZ').localeCompare(b.tier || 'ZZ') ||
                                 a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    if (by === 'class') return (a.class || 'zz').localeCompare(b.class || 'zz') ||
                                  a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    if (by === 'reviewed') return (isDone(b) ? 1 : 0) - (isDone(a) ? 1 : 0) ||
                                   a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    if (by === 'priority') {
      // Default order for a working checklist: the actionable tier-1
      // products first (largest population first inside each tier), so the
      // generic T3/T4 web servers do not bury the panels worth working on.
      const ta = a.tier || 'ZZ', tb = b.tier || 'ZZ';
      if (ta !== tb) return ta.localeCompare(tb);
      const pa = a.population || 0, pb = b.population || 0;
      if (pa !== pb) return pb - pa;
      return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    }
    const d = numOf(b) - numOf(a);
    if (d) return d;
    return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
  });
  return rows;
}

/* ---------------- rendering ---------------- */

function renderRow(r) {
  const key = esc(r.key);
  const done = isDone(r);
  const note = state.notes[r.key] || '';

  const tier = r.tier
    ? `<span class="badge b-${esc(r.tier)}">${TIER_LABEL[r.tier] || esc(r.tier)}</span>`
    : '<span class="badge b-unknown">&mdash;</span>';

  const take = r.takeover !== 'unknown'
    ? `<span class="badge b-${esc(r.takeover)}">${TAKE_LABEL[r.takeover]}</span>`
    : '<span class="badge b-unknown">&mdash;</span>';

  const src = [];
  if (r.in_unified) src.push('curated list');
  if (r.in_census) src.push('census');
  const srcLine = src.length
    ? `<span class="srcline">${esc(src.join(' + '))}${r.measured_by ? ' &middot; via ' + esc(r.measured_by) : ''}</span>`
    : '';

  const alias = (r.aliases || []).filter(a => a !== r.name);
  const aliasLine = alias.length
    ? `<span class="aliases">${esc(alias.slice(0, 3).join(' · '))}</span>`
    : '';

  const pathExtra = r.takeover_note ? ` <span class="aliases">${esc(r.takeover_note)}</span>` : '';

  const notesCell = view.notes === 'hidden'
    ? (hasNote(r) ? '<span class="note-flag">has note</span>' : '')
    : `<textarea class="notes" data-key="${key}" placeholder="add a note&hellip;"
              rows="2" spellcheck="true">${esc(note)}</textarea>`;

  return `<tr class="${done ? 'done' : ''} ${r.noise ? 'noise-row' : ''}" data-key="${key}">
    <td class="c-check"><input type="checkbox" class="chk" data-key="${key}"${done ? ' checked' : ''}
        aria-label="Mark ${esc(r.name)} reviewed"></td>
    <td class="c-name">
      <span class="pname">${esc(r.name)}</span>
      ${aliasLine}
      ${srcLine}
      ${r.noise ? ' <span class="badge b-noise">noise</span>' : ''}
    </td>
    <td class="c-num">${fmt(r.netlas)}</td>
    <td class="c-num">${fmt(r.zoomeye)}</td>
    <td class="c-num"><b>${fmt(r.population)}</b></td>
    <td class="c-tier">${tier}</td>
    <td class="c-class"><span class="classcell">${esc(r.class || '—')}</span></td>
    <td class="c-take">${take}</td>
    <td class="c-path"><span class="path">${esc(r.rce_path || '—')}${pathExtra}</span></td>
    <td class="c-cve">${cveLinks(r.cves)}</td>
    <td class="c-notes">${notesCell}</td>
  </tr>`;
}

function render() {
  const rows = sortRows(DATA.rows.filter(matches));
  const tb = document.getElementById('tbody');

  // Preserve focus and caret across a re-render: render() rebuilds every
  // textarea, so without this a checkbox click while typing a note would
  // drop the caret.
  const active = document.activeElement;
  const activeKey = (active && active.classList && active.classList.contains('notes'))
    ? active.dataset.key : null;
  const caret = activeKey ? active.selectionStart : null;

  tb.innerHTML = rows.map(renderRow).join('');
  document.getElementById('empty').hidden = rows.length > 0;

  if (activeKey) {
    const again = tb.querySelector(`textarea.notes[data-key="${CSS.escape(activeKey)}"]`);
    if (again) {
      again.focus();
      if (caret !== null) { try { again.setSelectionRange(caret, caret); } catch (e) {} }
    }
  }

  const shown = rows.length;
  shownCount = shown;
  const total = DATA.rows.length;
  document.getElementById('resultCount').textContent =
    shown === total ? `${total} products` : `${shown} of ${total} products`;

  // header stats
  document.getElementById('statRows').textContent = total;
  document.getElementById('statT1').textContent =
    DATA.rows.filter(r => r.tier === 'T1').length;
  document.getElementById('statClaim').textContent =
    DATA.rows.filter(r => r.takeover === 'claim').length;

  refreshCounters();
}

/* ---------------- filters UI ---------------- */

function fillSelect(el, values, labelFn) {
  el.innerHTML = '<option value="">All</option>' +
    values.map(v => `<option value="${esc(v)}">${esc(labelFn ? labelFn(v) : v)}</option>`).join('');
}

function initControls() {
  const classes = [...new Set(DATA.rows.map(r => r.class).filter(Boolean))].sort();
  const tiers = [...new Set(DATA.rows.map(r => r.tier).filter(Boolean))].sort();
  const takes = [...new Set(DATA.rows.map(r => r.takeover).filter(Boolean))];

  fillSelect(document.getElementById('fClass'), classes);
  fillSelect(document.getElementById('fTier'), tiers);
  fillSelect(document.getElementById('fTake'), takes, v => TAKE_LABEL[v] || v);

  const q = document.getElementById('q');
  let qt = null;
  q.addEventListener('input', () => {
    clearTimeout(qt);
    qt = setTimeout(() => { view.q = q.value.trim(); render(); }, 120);
  });

  document.getElementById('fClass').addEventListener('change', e => { view.cls = e.target.value; render(); });
  document.getElementById('fTier').addEventListener('change', e => { view.tier = e.target.value; render(); });
  document.getElementById('fTake').addEventListener('change', e => { view.take = e.target.value; render(); });
  document.getElementById('fSort').addEventListener('change', e => { view.sort = e.target.value; render(); });

  document.querySelectorAll('[data-show]').forEach(b => {
    b.addEventListener('click', () => {
      document.querySelectorAll('[data-show]').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      view.show = b.dataset.show;
      render();
    });
  });

  document.querySelectorAll('[data-notes]').forEach(b => {
    b.addEventListener('click', () => {
      document.querySelectorAll('[data-notes]').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      view.notes = b.dataset.notes;
      render();
    });
  });
}

/* ---------------- row interactions ---------------- */

/* Update the counters without rebuilding the table. */
let shownCount = 0;

function refreshCounters() {
  const total = DATA.rows.length;
  const done = DATA.rows.filter(isDone).length;
  const noted = DATA.rows.filter(hasNote).length;
  document.getElementById('statDone').textContent = done;
  document.getElementById('progressBar').style.width =
    total ? ((done / total) * 100).toFixed(2) + '%' : '0';
  document.getElementById('resultCount').textContent =
    shownCount === total ? `${total} products` : `${shownCount} of ${total} products`;
  document.getElementById('resultNote').textContent =
    `${done} reviewed · ${noted} with notes · saved in this browser`;
}

document.addEventListener('change', e => {
  const el = e.target;
  if (el.classList && el.classList.contains('chk')) {
    const k = el.dataset.key;
    if (el.checked) state.checks[k] = true; else delete state.checks[k];
    saveState();
    // Update the row in place rather than rebuilding the table: a rebuild
    // would replace the clicked element and lose focus state, and it makes
    // rapid multi-select slow.
    const tr = el.closest('tr');
    if (tr) tr.classList.toggle('done', el.checked);
    refreshCounters();
    // A done/todo/focus filter depends on this flag, so the visible set has
    // to be recomputed - but only then.
    if (view.show === 'todo' || view.show === 'done' || view.show === 'focus') {
      render();
    }
  }
});

document.addEventListener('input', e => {
  const el = e.target;
  if (el.classList && el.classList.contains('notes')) {
    const k = el.dataset.key;
    const v = el.value;
    if (v.trim()) state.notes[k] = v; else delete state.notes[k];
    saveState();
    // update counters without re-rendering the textarea (would lose focus)
    refreshCounters();
  }
});

/* ---------------- export / import / reset ---------------- */

function exportState() {
  const payload = {
    kind: 'rce-tracker-state',
    version: 1,
    exported: new Date().toISOString(),
    checks: state.checks,
    notes: state.notes
  };
  const text = JSON.stringify(payload, null, 2);
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  const name = `rce-tracker-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}.json`;

  // Blob + object URL is the normal path.
  if (typeof Blob === 'function' && typeof URL.createObjectURL === 'function') {
    const blob = new Blob([text], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    return;
  }

  // Fallback for environments without object URLs (older browsers, some
  // embedded webviews): a data: URL.
  const a = document.createElement('a');
  a.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(text);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function importState(file) {
  const fr = new FileReader();
  fr.onload = () => {
    try {
      const p = JSON.parse(fr.result);
      if (!p || typeof p !== 'object') throw new Error('not an object');
      const c = p.checks && typeof p.checks === 'object' ? p.checks : {};
      const n = p.notes && typeof p.notes === 'object' ? p.notes : {};
      let ck = 0, nt = 0;
      for (const k of Object.keys(c)) {
        if (DATA.rows.some(r => r.key === k)) { state.checks[k] = c[k]; ck++; }
      }
      for (const k of Object.keys(n)) {
        if (DATA.rows.some(r => r.key === k)) { state.notes[k] = n[k]; nt++; }
      }
      saveState();
      render();
      alert(`Imported ${ck} checkboxes and ${nt} notes.`);
    } catch (e) {
      alert('Could not import: ' + e.message);
    }
  };
  fr.readAsText(file);
}

function resetAll() {
  if (!confirm('Clear every checkbox and note stored in this browser?\n\nThis cannot be undone. Export first if you want a backup.')) return;
  state = { checks: {}, notes: {} };
  saveState();
  render();
}

/* ---------------- boot ---------------- */

async function boot() {
  loadState();
  try {
    // data.js is a plain script that sets window.TRACKER_DATA.  Using it first
    // means the page also works when opened directly from disk (file://),
    // where fetch() of a local JSON file is blocked by the browser.
    if (window.TRACKER_DATA) {
      DATA = window.TRACKER_DATA;
    } else {
      const res = await fetch(DATA_URL, { cache: 'no-cache' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      DATA = await res.json();
    }
  } catch (e) {
    document.getElementById('tbody').innerHTML =
      `<tr><td colspan="11" style="padding:26px;text-align:center;color:var(--fg-dim)">
        Could not load the data file (${esc(e.message)}). Serve this directory
        over HTTP, or make sure <b>data.js</b> sits next to <b>index.html</b>.
       </td></tr>`;
    return;
  }
  initControls();
  document.getElementById('btnExport').addEventListener('click', exportState);
  document.getElementById('btnImport').addEventListener('click', () => document.getElementById('fileImport').click());
  document.getElementById('fileImport').addEventListener('change', e => {
    if (e.target.files && e.target.files[0]) importState(e.target.files[0]);
    e.target.value = '';
  });
  document.getElementById('btnReset').addEventListener('click', resetAll);

  document.getElementById('caveat').textContent = DATA.sources.caveat || '';
  document.getElementById('method').textContent = DATA.sources.method || '';
  document.getElementById('generated').textContent =
    'Data generated ' + (DATA.generated || '') + '. Sources: ' +
    (DATA.sources.unified || '') + ' and ' + (DATA.sources.census || '') + '.';

  render();
}

document.addEventListener('DOMContentLoaded', boot);
