'use strict';
// slopproxy traffic view. Everything shown comes from the proxy's own record of
// what passed through it; text is always inserted as text, never as HTML.

const $ = (sel) => document.querySelector(sel);

const state = {
  items: [], listKey: '',
  selected: null, follow: true,
  detail: null, detailKey: '',
  paused: false, tab: 'rewrites', showAll: false, rawRequest: false, rawResponse: false,
  reveal: false,
};
try { state.reveal = localStorage.getItem('slopproxy-reveal') === '1'; } catch { /* storage off */ }
const TABS = ['rewrites', 'request', 'response', 'headers'];
if (TABS.includes(location.hash.slice(1))) state.tab = location.hash.slice(1);

// ---------- DOM helpers ----------

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) e.append(k);
  return e;
}
const hint = (text) => el('p', { class: 'hint' }, text);
const code = (text) => el('code', null, text);
const chip = (text, cls) => el('span', { class: 'chip' + (cls ? ' ' + cls : '') }, text);

function table(head, rows) {
  return el('table', null,
    el('thead', null, el('tr', null, head.map((h) => el('th', null, h)))),
    el('tbody', null, rows.map((r) => el('tr', null, r.map((c) => (c instanceof Node && c.nodeName === 'TD') ? c : el('td', null, c))))));
}
const num = (n) => el('td', { class: 'num' }, String(n));

const fmtTime = (iso) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const fmtMs = (ms) => ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
const fmtBytes = (n) => n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`;
const shortModel = (m) => (m || '').replace(/^claude-/, '');

// ---------- highlighting ----------

const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// highlight returns text with every mark.find wrapped in a <mark>. Renamed
// words only count as whole words, as the proxy matches them.
function highlight(text, marks) {
  const frag = document.createDocumentFragment();
  const byFind = new Map();
  for (const m of [...marks].filter((m) => m.find).sort((a, b) => b.find.length - a.find.length)) {
    if (!byFind.has(m.find)) byFind.set(m.find, m);
  }
  if (!text || !byFind.size) { frag.append(text || ''); return frag; }
  const re = new RegExp([...byFind.values()].map((m) => {
    let p = escRe(m.find);
    if (m.word && /^\w/.test(m.find)) p = '\\b' + p;
    if (m.word && /\w$/.test(m.find)) p += '\\b';
    return p;
  }).join('|'), 'g');
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (!m[0]) continue;
    if (m.index > last) frag.append(text.slice(last, m.index));
    const mk = byFind.get(m[0]);
    frag.append(el('mark', { class: mk.cls, title: mk.title }, mk.display ?? m[0]));
    last = m.index + m[0].length;
  }
  frag.append(text.slice(last));
  return frag;
}

// What Anthropic saw: the stand-ins.
function outMarks(rewrites) {
  return (rewrites || []).map((r) => ({
    find: r.shown, word: r.kind === 'rename', cls: r.kind,
    title: (r.kind === 'secret' ? `Hidden secret ${r.name}` : r.kind === 'host' ? 'Cloaked host' : 'Renamed word') + (state.reveal ? `; the agent has: ${r.real}` : ''),
  }));
}

// What the agent got back: the real values, dotted out unless revealed.
function realMarks(rewrites) {
  return (rewrites || []).map((r) => ({
    find: r.real, word: r.kind === 'rename', cls: 'restore',
    display: state.reveal ? r.real : (r.kind === 'secret' ? `‹${r.name}›` : r.kind === 'host' ? '‹host›' : '‹renamed›'),
    title: `Restored from ${r.shown}`,
  }));
}

function realCell(r) {
  return state.reveal ? code(r.real) : el('span', { class: 'hidden-value', title: 'Turn on "Reveal real values" to see it' }, '••••••••');
}

const legend = () => el('div', { class: 'legend' },
  el('span', null, el('mark', { class: 'secret' }, 'hidden secret')),
  el('span', null, el('mark', { class: 'rename' }, 'renamed word')),
  el('span', null, el('mark', { class: 'host' }, 'cloaked host')),
  el('span', null, el('mark', { class: 'restore' }, 'restored for the agent')));

// ---------- data ----------

async function getJSON(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (r.status === 403) throw Object.assign(new Error('forbidden'), { forbidden: true });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(String(r.status));
  return r.json();
}

function setStatus(kind) {
  const s = $('#status');
  s.className = 'status' + (kind === 'live' ? '' : kind === 'paused' ? ' paused' : ' down');
  $('#status-text').textContent = {
    live: 'live', paused: 'paused', down: 'proxy not running',
    forbidden: 'open the link from your terminal again',
  }[kind];
}

async function poll() {
  if (!state.paused) {
    try {
      const items = await getJSON('api/list') || [];
      setStatus('live');
      const key = JSON.stringify(items);
      if (key !== state.listKey) {
        state.items = items;
        state.listKey = key;
        if (state.follow && items.length && items[0].id !== state.selected) {
          select(items[0].id, false);
        } else {
          renderList();
        }
      }
      const cur = items.find((i) => i.id === state.selected);
      if (cur && (!state.detail || state.detail.id !== cur.id || !state.detail.done)) await loadDetail(cur.id);
    } catch (e) {
      setStatus(e.forbidden ? 'forbidden' : 'down');
    }
  }
  setTimeout(poll, 1000);
}

async function loadDetail(id) {
  const d = await getJSON(`api/exchange/${id}`);
  if (!d || id !== state.selected) return;
  const key = [d.id, d.done, d.status, d.sent.length, d.response.length, (d.restores || []).length, d.error].join('|');
  if (key === state.detailKey) return;
  state.detail = d;
  state.detailKey = key;
  renderDetail();
}

function select(id, byUser) {
  if (byUser) state.follow = state.items.length > 0 && id === state.items[0].id;
  if (id !== state.selected) {
    state.selected = id;
    state.detail = null;
    state.detailKey = '';
    state.showAll = false;
    $('#detail').replaceChildren(el('div', { class: 'empty' }, 'Loading…'));
    $('#detail').scrollTop = 0;
    loadDetail(id).catch(() => {});
  }
  renderList();
}

// ---------- list ----------

function statusChip(it) {
  if (!it.done) return chip(it.status ? `${it.status} · streaming` : 'waiting', 'wait');
  return chip(String(it.status || 'failed'), it.status >= 200 && it.status < 400 ? 'ok' : 'bad');
}

function renderList() {
  const list = $('#list');
  const top = list.scrollTop;
  list.replaceChildren();
  if (!state.items.length) list.append(el('div', { class: 'empty' }, 'No requests yet'));
  for (const it of state.items) {
    list.append(el('button', {
      class: 'row' + (it.id === state.selected ? ' sel' : ''),
      'aria-current': it.id === state.selected ? 'true' : null,
      onclick: () => select(it.id, true),
    },
    el('div', { class: 'l1' },
      el('span', { class: 'id' }, `#${it.id}`),
      el('span', { class: 'uri', title: it.uri }, `${it.method} ${it.uri.split('?')[0]}`),
      el('span', { class: 'time' }, fmtTime(it.start))),
    el('div', { class: 'l2' },
      statusChip(it),
      it.model && chip(shortModel(it.model)),
      chip(fmtMs(it.ms)),
      it.hidden > 0 && chip(`${it.hidden} hidden`, 'secret'),
      it.restored > 0 && chip(`${it.restored} restored`, 'restore'))));
  }
  list.scrollTop = top;
}

// ---------- response parsing ----------

// parseResponse rebuilds the content blocks from an event stream or a JSON body.
function parseResponse(text) {
  const res = { blocks: [], usage: {}, stop: null, error: null };
  const t = (text || '').trimStart();
  if (t.startsWith('{')) {
    try {
      const j = JSON.parse(t);
      if (j.type === 'error') res.error = j.error;
      res.stop = j.stop_reason;
      res.usage = j.usage || {};
      (j.content || []).forEach((b, i) => { res.blocks[i] = { ...b, inputText: b.input !== undefined ? JSON.stringify(b.input) : '' }; });
    } catch { /* not JSON after all */ }
    return res;
  }
  for (const ev of t.split(/\r?\n\r?\n/)) {
    const data = ev.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
    if (!data) continue;
    let d;
    try { d = JSON.parse(data); } catch { continue; }
    if (d.type === 'message_start') {
      Object.assign(res.usage, d.message?.usage || {});
    } else if (d.type === 'content_block_start') {
      res.blocks[d.index] = { ...d.content_block, text: d.content_block.text || '', thinking: d.content_block.thinking || '', inputText: '' };
    } else if (d.type === 'content_block_delta') {
      const b = res.blocks[d.index] || (res.blocks[d.index] = { type: 'text', text: '', thinking: '', inputText: '' });
      if (d.delta.type === 'text_delta') b.text += d.delta.text;
      else if (d.delta.type === 'thinking_delta') b.thinking += d.delta.thinking;
      else if (d.delta.type === 'input_json_delta') b.inputText += d.delta.partial_json;
    } else if (d.type === 'message_delta') {
      res.stop = d.delta?.stop_reason;
      Object.assign(res.usage, d.usage || {});
    } else if (d.type === 'error') {
      res.error = d.error;
    }
  }
  return res;
}

const parseMaybe = (s) => { try { return JSON.parse(s); } catch { return s; } };

// ---------- detail ----------

function renderDetail() {
  const d = state.detail;
  const box = $('#detail');
  if (!d) return;
  const top = box.scrollTop;
  const parsed = parseResponse(d.response);
  const restored = (d.restores || []).filter((r) => r.rewrites && r.rewrites.length);
  const tabs = [
    ['rewrites', `Rewrites${d.hidden + restored.length ? ` (${d.rewrites.length + restored.length})` : ''}`],
    ['request', 'Request'],
    ['response', 'Response'],
    ['headers', 'Headers'],
  ];
  const content = {
    rewrites: () => rewritesTab(d, parsed),
    request: () => requestTab(d),
    response: () => responseTab(d, parsed),
    headers: () => headersTab(d),
  }[state.tab]();

  // Through el(), so nested arrays flatten and empty values (no error) are skipped.
  box.replaceChildren(el('div', null,
    el('h1', null, `${d.method} ${d.uri}`),
    el('div', { class: 'meta' },
      statusChip(d),
      d.model && chip(d.model),
      chip(fmtTime(d.start)),
      chip(fmtMs(d.ms)),
      chip(`sent ${fmtBytes(d.size)}`),
      d.response && chip(`received ${fmtBytes(d.response.length)}`)),
    d.error && el('div', { class: 'notice bad' }, d.error),
    el('div', { class: 'tabs', role: 'tablist' }, tabs.map(([id, label]) => el('button', {
      role: 'tab', 'aria-selected': state.tab === id ? 'true' : 'false',
      onclick: () => { state.tab = id; history.replaceState(null, '', '#' + id); renderDetail(); },
    }, label))),
    content));
  box.scrollTop = top;
}

function rewritesTab(d, parsed) {
  const hidden = [...(d.rewrites || [])].sort((a, b) => (a.kind === b.kind ? b.count - a.count : a.kind === 'secret' ? -1 : 1));
  const restored = (d.restores || []).filter((r) => r.rewrites && r.rewrites.length);
  const places = hidden.reduce((n, r) => n + r.count, 0);
  const out = [];

  out.push(el('p', { class: 'summary-line' },
    hidden.length
      ? `${hidden.length} ${hidden.length === 1 ? 'value' : 'values'} hidden in ${places} ${places === 1 ? 'place' : 'places'}`
      : 'Nothing hidden',
    ' · ',
    restored.length ? `${restored.length} ${restored.length === 1 ? 'block' : 'blocks'} of the reply restored` : 'nothing restored in the reply'));

  out.push(el('h2', null, 'Hidden from Anthropic'),
    hint('Replaced in the request before it left your machine. Every turn resends the whole conversation, so the counts include earlier messages.'));
  if (!d.size && !d.done) out.push(hint('Reading the request…'));
  else if (!hidden.length) out.push(hint('Nothing in this request needed hiding.'));
  else {
    out.push(table(['', 'Name', 'The agent has', 'Anthropic saw', 'Times'], hidden.map((r) => [
      el('span', { class: 'badge ' + r.kind }, r.kind),
      r.kind === 'secret'
        ? [code(r.name), r.source && el('div', { class: 'hint' }, r.source === 'request' ? 'detected in the request' : `found in ${r.source}`)]
        : el('span', { class: 'hint' }, r.kind === 'host' ? 'from [hosts]' : 'from [names]'),
      realCell(r),
      code(r.shown),
      num(r.count),
    ])));
  }

  out.push(el('h2', null, 'Restored for the agent'),
    hint('The model only ever writes stand-ins. In its tool calls and reply text they are swapped back to the real values, so the agent edits and runs the real thing and you read the real names. Cloaked hosts stay on localhost in commands and fetches, so those go through the cloak. Thinking is left as it came: it is signed.'));
  if (!restored.length) out.push(hint(d.done ? 'Nothing in this response needed restoring.' : 'Nothing restored yet.'));
  for (const r of restored) {
    const b = parsed.blocks[r.index];
    out.push(el('div', { class: 'block' },
      el('div', { class: 'block-label' }, b?.type === 'tool_use' ? `tool call: ${b.name}` : 'reply text'),
      table(['', 'Anthropic sent', 'The agent got', 'Times'], r.rewrites.map((x) => [
        el('span', { class: 'badge ' + x.kind }, x.kind), code(x.shown), realCell(x), num(x.count),
      ]))));
  }
  return out;
}

function segmented(options, current, onPick) {
  return options.map(([value, label]) => el('button', {
    'aria-pressed': current === value ? 'true' : 'false',
    onclick: () => { onPick(value); renderDetail(); },
  }, label));
}

function requestTab(d) {
  if (!d.sent) return [hint(d.done ? 'This request had no body.' : 'Reading the request…')];
  let body = null;
  try { body = JSON.parse(d.sent); } catch { /* shown raw */ }
  const marks = outMarks(d.rewrites);
  const out = [
    hint('Exactly what was sent to Anthropic, after hiding and renaming.'),
    el('div', { class: 'toolbar' },
      body && segmented([[false, 'Conversation'], [true, 'Raw JSON']], state.rawRequest, (v) => { state.rawRequest = v; }),
      legend()),
  ];
  if (d.sentCut) out.push(el('div', { class: 'notice' }, 'This body was larger than 8 MB; only the start was kept.'));
  if (!body || state.rawRequest) {
    out.push(el('pre', null, highlight(body ? JSON.stringify(body, null, 2) : d.sent, marks)));
    return out;
  }

  out.push(el('div', { class: 'meta' },
    body.max_tokens && chip(`max_tokens ${body.max_tokens}`),
    body.stream && chip('stream'),
    body.thinking && chip(`thinking ${body.thinking.type || ''}`.trim())));
  if (body.system) {
    const text = typeof body.system === 'string' ? body.system : body.system.map((b) => b.text || '').join('\n\n');
    out.push(el('details', null, el('summary', null, `System prompt · ${text.length.toLocaleString()} characters`), el('pre', null, highlight(text, marks))));
  }
  if (Array.isArray(body.tools) && body.tools.length) {
    out.push(el('details', null, el('summary', null, `${body.tools.length} tools`), el('pre', null, highlight(body.tools.map((t) => t.name).join('\n'), marks))));
  }
  const msgs = Array.isArray(body.messages) ? body.messages : [];
  const keep = state.showAll ? msgs.length : Math.min(2, msgs.length);
  const first = msgs.length - keep;
  if (msgs.length > 2) {
    out.push(el('div', { class: 'toolbar' },
      el('button', { onclick: () => { state.showAll = !state.showAll; renderDetail(); } },
        state.showAll ? 'Show only the latest 2' : `Show all ${msgs.length} messages`),
      el('span', { class: 'hint' }, state.showAll ? `${msgs.length} messages` : `messages ${first + 1}–${msgs.length} of ${msgs.length}`)));
  }
  msgs.slice(first).forEach((m, i) => {
    out.push(el('div', { class: 'msg' },
      el('div', { class: 'role' }, `${m.role} · #${first + i + 1}`),
      (typeof m.content === 'string' ? [{ type: 'text', text: m.content }] : m.content || []).map((b) => contentBlock(b, marks))));
  });
  return out;
}

function inputView(input, marks) {
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    return Object.entries(input).map(([k, v]) => el('div', { class: 'field' },
      el('div', { class: 'field-key' }, k),
      el('pre', null, highlight(typeof v === 'string' ? v : JSON.stringify(v, null, 2), marks))));
  }
  return el('pre', null, highlight(typeof input === 'string' ? input : JSON.stringify(input, null, 2), marks));
}

function contentBlock(b, marks) {
  switch (b.type) {
    case 'text':
      return el('div', { class: 'block' }, el('pre', null, highlight(b.text, marks)));
    case 'tool_use':
      return el('div', { class: 'block' }, el('div', { class: 'block-label' }, `→ tool call: ${b.name}`), inputView(b.input, marks));
    case 'tool_result': {
      const parts = typeof b.content === 'string' ? [{ type: 'text', text: b.content }] : b.content || [];
      return el('div', { class: 'block' },
        el('div', { class: 'block-label' }, `← tool result${b.is_error ? ' (error)' : ''}`),
        parts.map((p) => contentBlock(p, marks)));
    }
    case 'thinking':
      return el('details', { class: 'block' }, el('summary', null, 'thinking'), el('pre', null, highlight(b.thinking, marks)));
    case 'redacted_thinking':
      return hint('[redacted thinking]');
    case 'image':
    case 'document':
      return hint(`[${b.type}]`);
    default:
      return el('div', { class: 'block' }, el('div', { class: 'block-label' }, b.type || 'block'), el('pre', null, highlight(JSON.stringify(b, null, 2), marks)));
  }
}

function responseTab(d, parsed) {
  if (!d.response) return [hint(d.done ? 'No response body.' : 'Waiting for the response…')];
  const marks = outMarks(d.rewrites);
  const out = [
    hint('As Anthropic sent it. Where the reply text or a tool call had stand-ins, what you and the agent got is shown next to it.'),
    el('div', { class: 'toolbar' },
      segmented([[false, 'Readable'], [true, 'Raw']], state.rawResponse, (v) => { state.rawResponse = v; }),
      legend()),
  ];
  if (d.responseCut) out.push(el('div', { class: 'notice' }, 'This response was larger than 8 MB; only the start was kept.'));
  if (state.rawResponse) {
    out.push(el('pre', null, highlight(d.response, marks)));
    return out;
  }
  if (parsed.error) out.push(el('div', { class: 'notice bad' }, `${parsed.error.type || 'error'}: ${parsed.error.message || ''}`));
  parsed.blocks.forEach((b, i) => {
    if (!b) return;
    const r = (d.restores || []).find((x) => x.index === i);
    if (b.type === 'text' && r && r.rewrites && r.rewrites.length) {
      out.push(el('div', { class: 'block pair' },
        el('div', null, el('div', { class: 'col-label' }, 'Anthropic sent'), el('pre', null, highlight(r.model, outMarks(r.rewrites)))),
        el('div', null, el('div', { class: 'col-label' }, 'You got'), el('pre', null, highlight(r.agent, realMarks(r.rewrites))))));
      return;
    }
    if (b.type !== 'tool_use') {
      out.push(contentBlock(b, marks));
      return;
    }
    const label = el('div', { class: 'block-label' }, `→ tool call: ${b.name}`);
    if (r && r.rewrites && r.rewrites.length) {
      out.push(el('div', { class: 'block' }, label, el('div', { class: 'pair' },
        el('div', null, el('div', { class: 'col-label' }, 'Anthropic sent'), inputView(parseMaybe(r.model), outMarks(r.rewrites))),
        el('div', null, el('div', { class: 'col-label' }, 'The agent got'), inputView(parseMaybe(r.agent), realMarks(r.rewrites))))));
    } else {
      out.push(el('div', { class: 'block' }, label, inputView(parseMaybe(r ? r.model : b.inputText || '{}'), marks)));
    }
  });
  const u = parsed.usage;
  out.push(el('div', { class: 'meta' },
    parsed.stop && chip(`stop: ${parsed.stop}`),
    u.input_tokens != null && chip(`${u.input_tokens.toLocaleString()} in`),
    u.cache_read_input_tokens ? chip(`${u.cache_read_input_tokens.toLocaleString()} cached`) : null,
    u.output_tokens != null && chip(`${u.output_tokens.toLocaleString()} out`),
    !d.done && chip('streaming…', 'wait')));
  return out;
}

function headersTab(d) {
  const rows = (h) => Object.keys(h || {}).sort().map((k) => [code(k), code(h[k])]);
  return [
    hint('Credentials (authorization, x-api-key, cookies) are never recorded.'),
    el('h2', null, 'Request headers'),
    table(['Name', 'Value'], rows(d.reqHeaders)),
    el('h2', null, 'Response headers'),
    d.respHeaders ? table(['Name', 'Value'], rows(d.respHeaders)) : hint('No response yet.'),
  ];
}

// ---------- controls ----------

$('#reveal').checked = state.reveal;
$('#reveal').addEventListener('change', (e) => {
  state.reveal = e.target.checked;
  try { localStorage.setItem('slopproxy-reveal', state.reveal ? '1' : '0'); } catch { /* storage off */ }
  renderDetail();
});
$('#pause').addEventListener('click', (e) => {
  state.paused = !state.paused;
  e.target.setAttribute('aria-pressed', String(state.paused));
  e.target.textContent = state.paused ? 'Resume' : 'Pause';
  setStatus(state.paused ? 'paused' : 'live');
});
$('#clear').addEventListener('click', async () => {
  await fetch('api/clear', { method: 'POST' });
  Object.assign(state, { items: [], listKey: '', selected: null, detail: null, detailKey: '', follow: true });
  renderList();
  $('#detail').replaceChildren(el('div', { class: 'empty' }, 'Waiting for the agent\'s next request…'));
});
document.addEventListener('keydown', (e) => {
  if (e.target.closest('input, textarea') || !state.items.length) return;
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'j' && e.key !== 'k') return;
  const i = state.items.findIndex((x) => x.id === state.selected);
  const next = state.items[Math.max(0, Math.min(state.items.length - 1, i + (e.key === 'ArrowDown' || e.key === 'j' ? 1 : -1)))];
  if (next) { e.preventDefault(); select(next.id, true); }
});

renderList();
poll();
