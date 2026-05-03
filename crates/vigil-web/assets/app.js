'use strict';

// ── Auth token ─────────────────────────────────────────────────────────────
let VIGIL_TOKEN = '';
function authHeaders() {
  return VIGIL_TOKEN ? { 'Authorization': `Bearer ${VIGIL_TOKEN}` } : {};
}

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  sessions: {},
  selectedId: null,
  pendingApproval: null,
  sseConnected: false,
  sortCol: 'status',
  sortDir: 'desc',
  statusFilter: 'all',
};
let searchQuery = '';
let keyboardRow = null;

// ── Boot ───────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  VIGIL_TOKEN = params.get('token') || sessionStorage.getItem('vigil-token') || '';
  if (VIGIL_TOKEN) sessionStorage.setItem('vigil-token', VIGIL_TOKEN);

  state.sortCol = sessionStorage.getItem('vigil-sort-col') || 'status';
  state.sortDir = sessionStorage.getItem('vigil-sort-dir') || 'desc';
  state.statusFilter = sessionStorage.getItem('vigil-status-filter') || 'all';

  // Sync the active tab to the stored filter
  document.querySelectorAll('.filter-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === state.statusFilter);
  });

  attachFilterHandlers();

  // Close export dropdown when clicking outside
  document.addEventListener('click', () => {
    const dropdown = document.getElementById('export-dropdown');
    if (dropdown) dropdown.classList.remove('visible');
  });

  loadSessions();
  connectSSE();
  setInterval(loadSessions, 30000);
  setInterval(tickRelativeTimes, 30000);
  installKeyboardNav();
});

// ── Sessions API ───────────────────────────────────────────────────────────
async function loadSessions() {
  try {
    const res = await fetch('/api/sessions', { headers: authHeaders() });
    if (!res.ok) return;
    const sessions = await res.json();
    sessions.forEach(s => { state.sessions[s.id] = s; });
    renderSidebar();
    if (!state.selectedId) renderSessionsTable();
    updateSessionCount();
    updateFilterCounts();
  } catch (e) {
    console.warn('Failed to load sessions:', e);
  }
}

// ── SSE ────────────────────────────────────────────────────────────────────
function connectSSE() {
  const url = VIGIL_TOKEN
    ? `/api/events?token=${encodeURIComponent(VIGIL_TOKEN)}`
    : '/api/events';
  const es = new EventSource(url);

  const eventTypes = [
    'LlmRequest', 'LlmResponse', 'ToolCall', 'ToolCallResult',
    'FsWrite', 'FsRead', 'BurnRateAlert', 'LoopAlert', 'DriftAlert',
    'ExfilAlert', 'PromptInjectionAlert', 'WriteApprovalRequired',
    'WriteApprovalDecision', 'PiiAlert', 'ToolTimeout', 'CostAlert',
    'SessionDurationAlert', 'SubAgentSpawned', 'ProcessSpawn', 'McpCall',
    'vigil',
  ];
  eventTypes.forEach(type => {
    es.addEventListener(type, (ev) => {
      try { handleEvent(JSON.parse(ev.data)); } catch (e) { console.warn('SSE parse error:', e); }
    });
  });

  es.onopen = () => {
    state.sseConnected = true;
    document.getElementById('conn-status').textContent = 'live';
    document.getElementById('conn-status').style.color = 'var(--green)';
  };
  es.onerror = () => {
    state.sseConnected = false;
    document.getElementById('conn-status').textContent = 'reconnecting...';
    document.getElementById('conn-status').style.color = 'var(--amber)';
  };
}

// ── Event handler ──────────────────────────────────────────────────────────
function handleEvent(envelope) {
  const sid = envelope.session_id;
  if (!sid) return;

  if (!state.sessions[sid]) {
    state.sessions[sid] = {
      id: sid, name: null, agent: '', status: 'live',
      started_at: envelope.timestamp, cost_usd: 0,
      burn_rate_per_min: 0, last_event: '', tokens: 0,
      needs_attention: false, alerts: [],
    };
  }

  const s = state.sessions[sid];
  const ev = envelope.event;
  const etype = Object.keys(ev)[0];

  if (etype === 'LlmResponse') {
    const d = ev.LlmResponse;
    s.last_event = `LLM response (${d.output_tokens || 0} out)`;
    s.model = d.model;
  } else if (etype === 'LlmRequest') {
    const d = ev.LlmRequest;
    s.agent = s.agent || d.provider || 'agent';
    s.last_event = `LLM request (${d.input_tokens || 0} in)`;
    s.model = d.model;
  } else if (etype === 'ToolCall') {
    const d = ev.ToolCall;
    s.last_event = `Tool: ${d.tool_name}`;
    s.agent = s.agent || d.agent || 'agent';
  } else if (etype === 'FsWrite') {
    s.last_event = `Write: ${shortPath(ev.FsWrite.path)}`;
  } else if (etype === 'FsRead') {
    s.last_event = `Read: ${shortPath(ev.FsRead.path)}`;
  } else if (etype === 'BurnRateAlert') {
    const d = ev.BurnRateAlert;
    s.burn_rate_per_min = d.rate_per_min_usd || 0;
    s.needs_attention = true;
    addAlert(s, 'BURN');
    s.last_event = `BURN alert: $${s.burn_rate_per_min.toFixed(3)}/min`;
  } else if (etype === 'LoopAlert') {
    addAlert(s, 'LOOP'); s.needs_attention = true;
  } else if (etype === 'DriftAlert') {
    addAlert(s, 'DRFT'); s.needs_attention = true;
  } else if (etype === 'ExfilAlert') {
    addAlert(s, 'EXFL'); s.needs_attention = true;
  } else if (etype === 'PromptInjectionAlert') {
    addAlert(s, 'PINJ'); s.needs_attention = true;
  } else if (etype === 'WriteApprovalRequired') {
    addAlert(s, 'WAPPR');
    s.needs_attention = true;
    showApprovalBanner(ev.WriteApprovalRequired, sid);
  } else if (etype === 'WriteApprovalDecision') {
    hideApprovalBanner();
    s.needs_attention = false;
  }

  updateTableRow(sid);
  renderSidebar();
  updateFilterCounts();
  if (state.selectedId === sid) appendTimelineItem(envelope);
}

function addAlert(session, code) {
  if (!session.alerts) session.alerts = [];
  if (!session.alerts.includes(code)) session.alerts.push(code);
}

function shortPath(p) {
  if (!p) return '';
  const parts = p.replace(/\\/g, '/').split('/');
  return parts.length > 2 ? '…/' + parts.slice(-2).join('/') : p;
}

// ── Search ─────────────────────────────────────────────────────────────────
function onSearchInput(val) {
  searchQuery = val.trim().toLowerCase();
  keyboardRow = null;
  if (!state.selectedId) {
    renderSessionsTable();
    renderSidebar();
  }
}

function filteredSessions() {
  let sessions = Object.values(state.sessions);

  // Status filter
  if (state.statusFilter === 'live') {
    sessions = sessions.filter(s => s.status === 'live');
  } else if (state.statusFilter === 'completed') {
    sessions = sessions.filter(s => s.status !== 'live');
  }

  // Search filter
  if (!searchQuery) return sessions;
  return sessions.filter(s =>
    (s.name || '').toLowerCase().includes(searchQuery) ||
    (s.agent || '').toLowerCase().includes(searchQuery) ||
    s.id.toLowerCase().startsWith(searchQuery)
  );
}

// ── Sorting ────────────────────────────────────────────────────────────────
function sortedSessions(sessions) {
  const sorted = [...sessions];
  const col = state.sortCol;
  const dir = state.sortDir === 'asc' ? 1 : -1;

  sorted.sort((a, b) => {
    let aVal, bVal;
    if (col === 'name')       { aVal = (a.name || a.id).toLowerCase(); bVal = (b.name || b.id).toLowerCase(); }
    else if (col === 'agent') { aVal = (a.agent || '').toLowerCase(); bVal = (b.agent || '').toLowerCase(); }
    else if (col === 'cost')  { aVal = a.cost_usd || 0; bVal = b.cost_usd || 0; }
    else if (col === 'burn')  { aVal = a.burn_rate_per_min || 0; bVal = b.burn_rate_per_min || 0; }
    else if (col === 'last_event') { aVal = (a.last_event || '').toLowerCase(); bVal = (b.last_event || '').toLowerCase(); }
    else if (col === 'alerts') { aVal = (a.alerts || []).length; bVal = (b.alerts || []).length; }
    else if (col === 'started') { aVal = new Date(a.started_at).getTime(); bVal = new Date(b.started_at).getTime(); }
    else { // status: live first
      aVal = a.status === 'live' ? 0 : 1;
      bVal = b.status === 'live' ? 0 : 1;
    }

    if (aVal < bVal) return -1 * dir;
    if (aVal > bVal) return 1 * dir;
    // Secondary sort: newest first
    return new Date(b.started_at) - new Date(a.started_at);
  });
  return sorted;
}

function attachSortHandlers() {
  document.querySelectorAll('.sessions-table thead th.sortable').forEach(th => {
    th.addEventListener('click', (e) => {
      if (e.shiftKey) {
        state.sortCol = 'status';
        state.sortDir = 'desc';
      } else {
        const col = th.dataset.sortKey;
        if (state.sortCol === col) {
          state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
        } else {
          state.sortCol = col;
          // Default sort direction: numeric/date columns go desc, text goes asc
          state.sortDir = (col === 'cost' || col === 'burn' || col === 'started' || col === 'alerts') ? 'desc' : 'asc';
        }
      }
      sessionStorage.setItem('vigil-sort-col', state.sortCol);
      sessionStorage.setItem('vigil-sort-dir', state.sortDir);
      renderSessionsTable();
    });
  });
  updateSortIndicators();
}

function updateSortIndicators() {
  document.querySelectorAll('.sessions-table thead th.sortable').forEach(th => {
    const indicator = th.querySelector('.sort-indicator');
    const col = th.dataset.sortKey;
    if (col === state.sortCol) {
      th.classList.add('sort-active');
      indicator.className = `sort-indicator ${state.sortDir}`;
    } else {
      th.classList.remove('sort-active');
      indicator.className = 'sort-indicator';
    }
  });
}

// ── Status filter tabs ─────────────────────────────────────────────────────
function attachFilterHandlers() {
  document.querySelectorAll('.filter-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const filter = btn.dataset.filter;
      state.statusFilter = filter;
      sessionStorage.setItem('vigil-status-filter', filter);
      document.querySelectorAll('.filter-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      keyboardRow = null;
      renderSessionsTable();
    });
  });
}

function updateFilterCounts() {
  const all = Object.values(state.sessions).length;
  const live = Object.values(state.sessions).filter(s => s.status === 'live').length;
  const completed = Object.values(state.sessions).filter(s => s.status !== 'live').length;

  const allBtn = document.querySelector('[data-filter="all"] .tab-count');
  const liveBtn = document.querySelector('[data-filter="live"] .tab-count');
  const completedBtn = document.querySelector('[data-filter="completed"] .tab-count');
  if (allBtn) allBtn.textContent = `(${all})`;
  if (liveBtn) liveBtn.textContent = `(${live})`;
  if (completedBtn) completedBtn.textContent = `(${completed})`;
}

// ── Keyboard navigation ────────────────────────────────────────────────────
function installKeyboardNav() {
  document.addEventListener('keydown', (e) => {
    const tag = e.target.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'BUTTON') return;

    if (!state.selectedId) {
      const sessions = sortedSessions(filteredSessions());
      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault();
        keyboardRow = keyboardRow === null ? 0 : Math.min(keyboardRow + 1, sessions.length - 1);
        renderSessionsTable();
        scrollKeyboardRowIntoView();
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault();
        keyboardRow = keyboardRow === null ? sessions.length - 1 : Math.max(keyboardRow - 1, 0);
        renderSessionsTable();
        scrollKeyboardRowIntoView();
      } else if (e.key === 'Enter' && keyboardRow !== null && sessions[keyboardRow]) {
        selectSession(sessions[keyboardRow].id);
      } else if (e.key === '/') {
        e.preventDefault();
        const sb = document.getElementById('search-box');
        if (sb) sb.focus();
      }
    } else {
      if (e.key === 'Escape') showSessionsList();
    }
  });
}

function scrollKeyboardRowIntoView() {
  if (keyboardRow === null) return;
  const sessions = sortedSessions(filteredSessions());
  const s = sessions[keyboardRow];
  if (s) {
    const row = document.getElementById('row-' + s.id);
    if (row) row.scrollIntoView({ block: 'nearest' });
  }
}

// ── Relative time ticker ───────────────────────────────────────────────────
function tickRelativeTimes() {
  if (!state.selectedId) {
    renderSessionsTable();
    renderSidebar();
  }
}

// ── Sidebar ────────────────────────────────────────────────────────────────
function renderSidebar() {
  const list = document.getElementById('session-list');
  const sessions = sortedSessions(filteredSessions());
  if (sessions.length === 0) {
    list.innerHTML = `<div class="empty-state"><div class="empty-icon">◯</div><div>No sessions</div></div>`;
    return;
  }
  list.innerHTML = sessions.map(s => `
    <div class="session-card${state.selectedId === s.id ? ' active' : ''}" onclick="selectSession('${s.id}')">
      <div class="card-name">${escHtml(s.name || s.id.slice(0, 8))}</div>
      <div class="card-meta">
        <span class="badge badge-${s.status === 'live' ? 'live' : 'completed'}">${s.status === 'live' ? 'LIVE' : 'CMPL'}</span>
        <span>$${(s.cost_usd || 0).toFixed(3)}</span>
      </div>
    </div>
  `).join('');
}

// ── Sessions table ─────────────────────────────────────────────────────────
function renderSessionsTable() {
  const tbody = document.getElementById('sessions-tbody');
  const sessions = sortedSessions(filteredSessions());
  updateSessionCount();
  updateFilterCounts();

  if (sessions.length === 0) {
    const msg = searchQuery
      ? `No sessions match "${escHtml(searchQuery)}"`
      : state.statusFilter !== 'all'
        ? `No ${state.statusFilter} sessions`
        : 'No sessions yet — run <code>vigil run -- claude</code> to start';
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state"><div class="empty-icon">◯</div><div>${msg}</div></div></td></tr>`;
    attachSortHandlers();
    return;
  }

  tbody.innerHTML = sessions.map((s, idx) => buildTableRow(s, idx)).join('');
  attachSortHandlers();
}

function buildTableRow(s, idx) {
  const live = s.status === 'live';
  const alerts = (s.alerts || []).slice(0, 3).map(a =>
    `<span class="badge badge-${a.toLowerCase()}">${a}</span>`
  ).join(' ');
  const costColor = s.cost_usd > 5 ? 'color:var(--red)' : s.cost_usd > 1 ? 'color:var(--amber)' : '';
  const burnColor = s.burn_rate_per_min > 0.1 ? 'color:var(--red)' : '';
  const kbClass = keyboardRow === idx ? ' keyboard-selected' : '';

  return `<tr id="row-${s.id}" class="${kbClass}" onclick="selectSession('${s.id}')">
    <td><span style="font-weight:600">${escHtml(s.name || s.id.slice(0, 8))}</span></td>
    <td>${escHtml(s.agent || '—')}</td>
    <td class="num" style="${costColor}">$${(s.cost_usd || 0).toFixed(3)}</td>
    <td class="num" style="${burnColor}">${live ? '$' + (s.burn_rate_per_min || 0).toFixed(3) : '—'}</td>
    <td title="${escHtml(s.last_event || '')}">${escHtml(truncate(s.last_event || '', 50))}</td>
    <td>${alerts || '<span style="color:var(--text-muted)">—</span>'}</td>
    <td class="mono">${relativeTime(s.started_at)}</td>
    <td>
      ${live ? '<span class="live-dot"></span>' : ''}
      <span class="badge badge-${live ? 'live' : 'completed'}">${live ? 'LIVE' : 'CMPL'}</span>
    </td>
  </tr>`;
}

function updateTableRow(sid) {
  const s = state.sessions[sid];
  if (!s) return;
  const row = document.getElementById('row-' + sid);
  if (!row) {
    if (!state.selectedId) renderSessionsTable();
    return;
  }
  const sessions = sortedSessions(filteredSessions());
  const idx = sessions.findIndex(x => x.id === sid);
  row.outerHTML = buildTableRow(s, idx);
}

function updateSessionCount() {
  const sessions = Object.values(state.sessions);
  const live = sessions.filter(s => s.status === 'live').length;
  const completed = sessions.filter(s => s.status !== 'live').length;
  const el = document.getElementById('sessions-count');
  if (el) {
    const parts = [];
    if (live > 0) parts.push(`${live} live`);
    if (completed > 0) parts.push(`${completed} completed`);
    el.textContent = parts.length ? `(${parts.join(', ')})` : '';
  }
}

// ── Session detail ─────────────────────────────────────────────────────────
function selectSession(id) {
  state.selectedId = id;
  keyboardRow = null;
  renderSidebar();

  document.getElementById('sessions-view').style.display = 'none';
  document.getElementById('detail-view').style.display = 'flex';

  const s = state.sessions[id];
  if (!s) return;

  document.getElementById('detail-session-name').textContent =
    `${s.name || id.slice(0, 8)} · ${s.agent} · $${(s.cost_usd || 0).toFixed(4)}`;

  renderDetailInfo(s);
  loadSessionDetail(id);
}

function showSessionsList() {
  state.selectedId = null;
  document.getElementById('sessions-view').style.display = 'block';
  document.getElementById('detail-view').style.display = 'none';
  renderSidebar();
  renderSessionsTable();
}

async function loadSessionDetail(id, offset) {
  const timeline = document.getElementById('detail-timeline');
  timeline.innerHTML = '<div class="empty-state"><div>Loading events...</div></div>';

  const query = offset !== undefined ? `?limit=200&offset=${offset}` : '?limit=200';
  try {
    const res = await fetch(`/api/sessions/${id}${query}`, { headers: authHeaders() });
    if (!res.ok) {
      timeline.innerHTML = '<div class="empty-state"><div>No detailed events available</div></div>';
      return;
    }
    const data = await res.json();
    timeline.innerHTML = '';

    if (data.events_offset > 0) {
      const earlier = data.events_offset;
      const btn = document.createElement('button');
      btn.className = 'load-earlier-btn';
      btn.textContent = `Load ${earlier} earlier event${earlier === 1 ? '' : 's'}`;
      btn.onclick = () => loadAllSessionDetail(id, data.event_count);
      timeline.appendChild(btn);
    }

    (data.events || []).forEach(ev => appendTimelineItem(ev));
  } catch {
    timeline.innerHTML = '<div class="empty-state"><div>Session detail not yet available</div></div>';
  }
}

async function loadAllSessionDetail(id, total) {
  const timeline = document.getElementById('detail-timeline');
  timeline.innerHTML = '<div class="empty-state"><div>Loading all events...</div></div>';
  try {
    const res = await fetch(`/api/sessions/${id}?limit=${total}&offset=0`, { headers: authHeaders() });
    const data = await res.json();
    timeline.innerHTML = '';
    (data.events || []).forEach(ev => appendTimelineItem(ev));
  } catch {
    timeline.innerHTML = '<div class="empty-state"><div>Failed to load all events</div></div>';
  }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderDetailInfo(s) {
  const el = document.getElementById('detail-info');
  const duration = s.ended_at
    ? formatDuration(new Date(s.started_at), new Date(s.ended_at))
    : formatDuration(new Date(s.started_at), new Date());

  const sid = s.id;
  const modelSpan = s.model
    ? `<span>Model: <strong>${escHtml(s.model)}</strong></span>`
    : '';
  el.innerHTML = `
    <span>Started: <strong>${new Date(s.started_at).toLocaleString()}</strong></span>
    <span>Duration: <strong>${duration}</strong></span>
    <span>Cost: <strong>$${(s.cost_usd || 0).toFixed(4)}</strong></span>
    <span>Tokens: <strong>${(s.tokens || 0).toLocaleString()}</strong></span>
    <span>Status: <strong>${s.status === 'live' ? '🟢 LIVE' : '⚫ COMPLETED'}</strong></span>
    ${modelSpan}
    <div class="export-menu">
      <button class="btn btn-export" onclick="toggleExportMenu(event)">↓ Download</button>
      <div class="export-dropdown" id="export-dropdown">
        <button class="export-option" onclick="exportSessionJSON('${sid}')">JSON — raw events</button>
        <button class="export-option" onclick="exportSessionHTML('${sid}')">HTML — report</button>
      </div>
    </div>
  `;
}

function appendTimelineItem(envelope) {
  const timeline = document.getElementById('detail-timeline');
  if (!timeline) return;
  const emptyState = timeline.querySelector('.empty-state');
  if (emptyState) emptyState.remove();

  const ev = envelope.event;
  const etype = Object.keys(ev)[0];
  const data = ev[etype];
  const ts = new Date(envelope.timestamp).toLocaleTimeString();

  let title = etype;
  let meta = '';
  let itemClass = '';

  switch (etype) {
    case 'LlmRequest':
      title = `LLM Request (${data.input_tokens || 0} in)`;
      meta = data.model || '';
      break;
    case 'LlmResponse':
      title = `LLM Response (${data.output_tokens || 0} out)`;
      meta = `$${(data.cost_usd || 0).toFixed(4)} · ${data.model || ''}`;
      break;
    case 'ToolCall':
      title = `Tool: ${data.tool_name}`;
      meta = truncate(typeof data.input === 'string' ? data.input : JSON.stringify(data.input || {}), 80);
      break;
    case 'ToolCallResult':
      title = `Tool result: ${data.tool_name}${data.blocked ? ' (BLOCKED)' : ''}`;
      meta = data.duration_ms ? `${data.duration_ms}ms` : '';
      break;
    case 'FsWrite':
      title = `Write: ${shortPath(data.path)}`;
      meta = `+${data.lines_added || 0} -${data.lines_removed || 0} lines`;
      break;
    case 'FsRead':
      title = `Read: ${shortPath(data.path)}`;
      break;
    case 'BurnRateAlert':
      title = `BURN alert — $${(data.rate_per_min_usd || 0).toFixed(3)}/min`;
      itemClass = 'alert-item';
      break;
    case 'LoopAlert':
      title = `LOOP alert — ${data.tool_name} repeated ${data.repeat_count}x`;
      itemClass = 'warn-item';
      break;
    case 'DriftAlert':
      title = `DRFT alert — ${data.signal || ''}`;
      meta = data.details || '';
      itemClass = 'warn-item';
      break;
    case 'ExfilAlert':
      title = `EXFL alert — ${data.source}`;
      itemClass = 'alert-item';
      break;
    case 'PromptInjectionAlert':
      title = `PINJ alert — ${data.category}`;
      meta = truncate(data.snippet || '', 60);
      itemClass = 'alert-item';
      break;
    case 'WriteApprovalRequired':
      title = `Write approval required: ${shortPath(data.path)}`;
      meta = `Risk: ${data.risk_level || 'unknown'}${data.is_lockdown ? ' · LOCKDOWN' : ''}`;
      itemClass = data.is_lockdown ? 'alert-item' : 'warn-item';
      break;
    case 'WriteApprovalDecision':
      title = `Write ${data.approved ? 'approved' : 'rejected'}`;
      itemClass = data.approved ? '' : 'alert-item';
      break;
    case 'ToolTimeout':
      title = `TOUT alert — ${data.tool_name} silent for ${data.elapsed_secs}s`;
      itemClass = 'warn-item';
      break;
    case 'CostAlert':
      title = `COST alert — $${(data.session_cost_usd || 0).toFixed(4)} spent`;
      itemClass = 'warn-item';
      break;
    case 'SubAgentSpawned':
      title = `Sub-agent spawned (depth ${data.depth}) via ${data.tool_name}`;
      break;
    default:
      title = etype.replace(/([A-Z])/g, ' $1').trim();
  }

  const item = document.createElement('div');
  item.className = `timeline-item ${itemClass}`;
  item.innerHTML = `
    <div class="timeline-time">${ts}</div>
    <div class="timeline-body">
      <div class="timeline-title">${escHtml(title)}</div>
      ${meta ? `<div class="timeline-meta">${escHtml(meta)}</div>` : ''}
    </div>
  `;
  timeline.appendChild(item);
  if (timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 100) {
    timeline.scrollTop = timeline.scrollHeight;
  }
}

// ── Write approval banner ──────────────────────────────────────────────────
function showApprovalBanner(data, sessionId) {
  state.pendingApproval = {
    id: data.approval_id,
    path: data.path,
    risk: data.risk_level,
    session_id: sessionId,
    is_lockdown: data.is_lockdown || false,
  };
  document.getElementById('approval-path').textContent = data.path || '';
  const riskEl = document.getElementById('approval-risk');
  riskEl.textContent = (data.risk_level || 'Unknown').toUpperCase();
  riskEl.className = `badge badge-${(data.risk_level || '').toLowerCase()}`;

  const banner = document.getElementById('approval-banner');
  banner.classList.add('visible');
  if (data.is_lockdown) {
    banner.classList.add('lockdown');
  } else {
    banner.classList.remove('lockdown');
  }
}

function hideApprovalBanner() {
  state.pendingApproval = null;
  const banner = document.getElementById('approval-banner');
  banner.classList.remove('visible', 'lockdown');
}

async function submitApproval(approved) {
  if (!state.pendingApproval) return;
  const { id } = state.pendingApproval;
  try {
    await fetch(`/api/approvals/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ approved }),
    });
  } catch (e) {
    console.warn('Approval submit failed:', e);
  }
  hideApprovalBanner();
}

// ── Export ─────────────────────────────────────────────────────────────────
function toggleExportMenu(e) {
  e.stopPropagation();
  const dropdown = document.getElementById('export-dropdown');
  if (dropdown) dropdown.classList.toggle('visible');
}

async function exportSessionJSON(id) {
  if (!id) id = state.selectedId;
  if (!id) return;

  try {
    const res = await fetch(`/api/sessions/${id}?limit=10000&offset=0`, { headers: authHeaders() });
    const detail = await res.json();
    const payload = {
      session_id: detail.id,
      name: detail.name,
      agent: detail.agent,
      status: detail.status,
      started_at: detail.started_at,
      ended_at: detail.ended_at,
      cost_usd: detail.cost_usd,
      total_input_tokens: detail.total_input_tokens,
      total_output_tokens: detail.total_output_tokens,
      policy_violations: detail.policy_violations,
      event_count: detail.event_count,
      events: detail.events,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    downloadFile(blob, `vigil-session-${id.slice(0, 8)}-${Date.now()}.json`);
  } catch (e) {
    console.warn('Export JSON failed:', e);
  }
  const dd = document.getElementById('export-dropdown');
  if (dd) dd.classList.remove('visible');
}

async function exportSessionHTML(id) {
  if (!id) id = state.selectedId;
  if (!id) return;

  try {
    const res = await fetch(`/api/sessions/${id}?limit=10000&offset=0`, { headers: authHeaders() });
    const detail = await res.json();
    const s = state.sessions[id] || {};

    const duration = detail.ended_at
      ? formatDuration(new Date(detail.started_at), new Date(detail.ended_at))
      : formatDuration(new Date(detail.started_at), new Date());

    const eventRows = (detail.events || []).map(ev => {
      const etype = Object.keys(ev.event)[0];
      const data = ev.event[etype];
      const ts = new Date(ev.timestamp).toLocaleTimeString();
      let title = etype;
      if (etype === 'LlmRequest') title = `LLM Request (${data.input_tokens || 0} in)`;
      else if (etype === 'LlmResponse') title = `LLM Response (${data.output_tokens || 0} out) — $${(data.cost_usd || 0).toFixed(4)}`;
      else if (etype === 'FsWrite') title = `Write: ${shortPath(data.path)} +${data.lines_added || 0} -${data.lines_removed || 0}`;
      else if (etype === 'FsRead') title = `Read: ${shortPath(data.path)}`;
      else if (etype === 'ToolCall') title = `Tool: ${data.tool_name}`;
      else title = etype.replace(/([A-Z])/g, ' $1').trim();
      const isAlert = etype.includes('Alert') || etype === 'WriteApprovalRequired';
      return `<tr${isAlert ? ' style="color:#dc2626"' : ''}><td style="white-space:nowrap;padding:6px 8px;border-bottom:1px solid #eee">${ts}</td><td style="padding:6px 8px;border-bottom:1px solid #eee">${escHtml(title)}</td></tr>`;
    }).join('');

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>vigil — ${escHtml(detail.name || detail.id.slice(0, 8))}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f5f5f5; margin: 0; padding: 20px; color: #1f2937; }
    .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    h1 { margin: 0 0 4px 0; font-size: 22px; } h2 { font-size: 16px; margin: 28px 0 12px; }
    .subtitle { color: #6b7280; font-size: 13px; margin-bottom: 24px; font-family: monospace; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 28px; }
    .stat { padding: 12px 14px; background: #f9fafb; border-left: 3px solid #3b82f6; border-radius: 4px; }
    .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #9ca3af; margin-bottom: 4px; }
    .stat-value { font-size: 16px; font-weight: 600; font-family: monospace; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    thead th { background: #f3f4f6; padding: 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.4px; color: #6b7280; }
    tbody tr:hover { background: #fafafa; }
    .footer { margin-top: 24px; font-size: 11px; color: #9ca3af; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>vigil Session Report</h1>
    <div class="subtitle">${escHtml(detail.id)}</div>
    <div class="grid">
      <div class="stat"><div class="stat-label">Session</div><div class="stat-value">${escHtml(detail.name || detail.id.slice(0, 8))}</div></div>
      <div class="stat"><div class="stat-label">Agent</div><div class="stat-value">${escHtml(detail.agent)}</div></div>
      <div class="stat"><div class="stat-label">Status</div><div class="stat-value">${detail.status.toUpperCase()}</div></div>
      <div class="stat"><div class="stat-label">Started</div><div class="stat-value">${new Date(detail.started_at).toLocaleString()}</div></div>
      <div class="stat"><div class="stat-label">Duration</div><div class="stat-value">${duration}</div></div>
      <div class="stat"><div class="stat-label">Cost</div><div class="stat-value">$${(detail.cost_usd || 0).toFixed(4)}</div></div>
      <div class="stat"><div class="stat-label">Input Tokens</div><div class="stat-value">${(detail.total_input_tokens || 0).toLocaleString()}</div></div>
      <div class="stat"><div class="stat-label">Output Tokens</div><div class="stat-value">${(detail.total_output_tokens || 0).toLocaleString()}</div></div>
      <div class="stat"><div class="stat-label">Violations</div><div class="stat-value">${detail.policy_violations}</div></div>
      <div class="stat"><div class="stat-label">Events</div><div class="stat-value">${detail.event_count}</div></div>
    </div>
    <h2>Event Timeline (${(detail.events || []).length} shown)</h2>
    <table>
      <thead><tr><th>Time</th><th>Event</th></tr></thead>
      <tbody>${eventRows || '<tr><td colspan="2" style="text-align:center;color:#9ca3af;padding:20px">No events recorded</td></tr>'}</tbody>
    </table>
    <div class="footer">Generated by vigil v${escHtml(document.title.match(/vigil/) ? '0.7.5' : '')} &nbsp;·&nbsp; ${new Date().toLocaleString()}</div>
  </div>
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html' });
    downloadFile(blob, `vigil-session-${id.slice(0, 8)}-${Date.now()}.html`);
  } catch (e) {
    console.warn('Export HTML failed:', e);
  }
  const dd = document.getElementById('export-dropdown');
  if (dd) dd.classList.remove('visible');
}

function downloadFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Utilities ──────────────────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function truncate(str, n) {
  if (!str) return '';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

function relativeTime(iso) {
  if (!iso) return '—';
  const delta = (Date.now() - new Date(iso)) / 1000;
  if (delta < 60) return `${Math.round(delta)}s ago`;
  if (delta < 3600) return `${Math.round(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.round(delta / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

function formatDuration(start, end) {
  const delta = Math.max(0, Math.round((end - start) / 1000));
  const h = Math.floor(delta / 3600);
  const m = Math.floor((delta % 3600) / 60);
  const s = delta % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}
