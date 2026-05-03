'use strict';

// ── Auth token ─────────────────────────────────────────────────────────────
// Printed to stdout by vigil as: Dashboard: http://127.0.0.1:PORT/?token=...
// Stored in sessionStorage so the token survives navigations within the tab.
let VIGIL_TOKEN = '';

function authHeaders() {
  return VIGIL_TOKEN ? { 'Authorization': `Bearer ${VIGIL_TOKEN}` } : {};
}

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  sessions: {},       // id -> session object
  selectedId: null,   // currently viewed session id
  pendingApproval: null, // { id, path, risk, session_id }
  sseConnected: false,
};

// ── Boot ───────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  VIGIL_TOKEN = params.get('token') || sessionStorage.getItem('vigil-token') || '';
  if (VIGIL_TOKEN) sessionStorage.setItem('vigil-token', VIGIL_TOKEN);

  loadSessions();
  connectSSE();
  setInterval(loadSessions, 30000);
  setInterval(tickRelativeTimes, 30000);
});

// ── Sessions API ───────────────────────────────────────────────────────────
async function loadSessions() {
  try {
    const res = await fetch('/api/sessions', { headers: authHeaders() });
    if (!res.ok) return;
    const sessions = await res.json();
    sessions.forEach(s => { state.sessions[s.id] = s; });
    renderSidebar();
    if (!state.selectedId) {
      renderSessionsTable();
    }
    updateSessionCount();
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

  // Listen for all named event types the server emits
  const eventTypes = [
    'LlmRequest', 'LlmResponse', 'ToolCall', 'ToolCallResult',
    'FsWrite', 'FsRead', 'BurnRateAlert', 'LoopAlert', 'DriftAlert',
    'ExfilAlert', 'PromptInjectionAlert', 'WriteApprovalRequired',
    'WriteApprovalDecision', 'PiiAlert', 'ToolTimeout', 'CostAlert',
    'SessionDurationAlert', 'SubAgentSpawned', 'ProcessSpawn', 'McpCall',
    'vigil', // fallback for unknown types
  ];
  eventTypes.forEach(type => {
    es.addEventListener(type, (ev) => {
      try {
        handleEvent(JSON.parse(ev.data));
      } catch (e) {
        console.warn('SSE parse error:', e);
      }
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

  // Use server-authoritative values from LlmResponse; do NOT accumulate client-side
  if (etype === 'LlmResponse') {
    const d = ev.LlmResponse;
    // Server snapshot arrives on next loadSessions poll; update last_event only
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
    const d = ev.FsWrite;
    s.last_event = `Write: ${shortPath(d.path)}`;
  } else if (etype === 'FsRead') {
    const d = ev.FsRead;
    s.last_event = `Read: ${shortPath(d.path)}`;
  } else if (etype === 'BurnRateAlert') {
    const d = ev.BurnRateAlert;
    s.burn_rate_per_min = d.rate_per_min_usd || 0;
    s.needs_attention = true;
    addAlert(s, 'BURN');
    s.last_event = `BURN alert: $${s.burn_rate_per_min.toFixed(3)}/min`;
  } else if (etype === 'LoopAlert') {
    addAlert(s, 'LOOP');
    s.needs_attention = true;
  } else if (etype === 'DriftAlert') {
    addAlert(s, 'DRFT');
    s.needs_attention = true;
  } else if (etype === 'ExfilAlert') {
    addAlert(s, 'EXFL');
    s.needs_attention = true;
  } else if (etype === 'PromptInjectionAlert') {
    addAlert(s, 'PINJ');
    s.needs_attention = true;
  } else if (etype === 'WriteApprovalRequired') {
    const d = ev.WriteApprovalRequired;
    addAlert(s, 'WAPPR');
    s.needs_attention = true;
    showApprovalBanner(d, sid);
  } else if (etype === 'WriteApprovalDecision') {
    hideApprovalBanner();
    s.needs_attention = false;
  }

  updateTableRow(sid);
  renderSidebar();

  if (state.selectedId === sid) {
    appendTimelineItem(envelope);
  }
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
  const sessions = Object.values(state.sessions);
  if (sessions.length === 0) {
    list.innerHTML = `<div class="empty-state"><div class="empty-icon">◯</div><div>No sessions</div></div>`;
    return;
  }

  const sorted = [...sessions].sort((a, b) => {
    if (a.status === 'live' && b.status !== 'live') return -1;
    if (b.status === 'live' && a.status !== 'live') return 1;
    return new Date(b.started_at) - new Date(a.started_at);
  });

  list.innerHTML = sorted.map(s => `
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
  const sessions = Object.values(state.sessions);
  updateSessionCount();

  if (sessions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state"><div class="empty-icon">◯</div><div>No sessions yet — run <code>vigil run -- claude</code> to start</div></div></td></tr>`;
    return;
  }

  const sorted = [...sessions].sort((a, b) => {
    if (a.status === 'live' && b.status !== 'live') return -1;
    if (b.status === 'live' && a.status !== 'live') return 1;
    return new Date(b.started_at) - new Date(a.started_at);
  });

  tbody.innerHTML = sorted.map(s => buildTableRow(s)).join('');
}

function buildTableRow(s) {
  const live = s.status === 'live';
  const alerts = (s.alerts || []).slice(0, 3).map(a =>
    `<span class="badge badge-${a.toLowerCase()}">${a}</span>`
  ).join(' ');

  const costColor = s.cost_usd > 5 ? 'color:var(--red)' : s.cost_usd > 1 ? 'color:var(--amber)' : '';
  const burnColor = s.burn_rate_per_min > 0.1 ? 'color:var(--red)' : '';

  return `<tr id="row-${s.id}" onclick="selectSession('${s.id}')">
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
  row.outerHTML = buildTableRow(s);
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

async function loadSessionDetail(id) {
  const timeline = document.getElementById('detail-timeline');
  timeline.innerHTML = '<div class="empty-state"><div>Loading events...</div></div>';

  try {
    const res = await fetch(`/api/sessions/${id}`, { headers: authHeaders() });
    if (!res.ok) {
      timeline.innerHTML = '<div class="empty-state"><div>No detailed events available</div></div>';
      return;
    }
    const data = await res.json();
    timeline.innerHTML = '';
    (data.events || []).forEach(ev => appendTimelineItem(ev));
  } catch {
    timeline.innerHTML = '<div class="empty-state"><div>Session detail not yet available</div></div>';
  }
}

function renderDetailInfo(s) {
  const el = document.getElementById('detail-info');
  const duration = s.ended_at
    ? formatDuration(new Date(s.started_at), new Date(s.ended_at))
    : formatDuration(new Date(s.started_at), new Date());

  el.innerHTML = `
    <span>Started: <strong>${new Date(s.started_at).toLocaleString()}</strong></span>
    <span>Duration: <strong>${duration}</strong></span>
    <span>Cost: <strong>$${(s.cost_usd || 0).toFixed(4)}</strong></span>
    <span>Tokens: <strong>${(s.tokens || 0).toLocaleString()}</strong></span>
    <span>Status: <strong>${s.status === 'live' ? '🟢 LIVE' : '⚫ COMPLETED'}</strong></span>
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
      const inputStr = typeof data.input === 'string' ? data.input : JSON.stringify(data.input || {});
      meta = truncate(inputStr, 80);
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
      meta = `Risk: ${data.risk_level || 'unknown'}`;
      itemClass = 'warn-item';
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
  state.pendingApproval = { id: data.approval_id, path: data.path, risk: data.risk_level, session_id: sessionId };
  const banner = document.getElementById('approval-banner');
  document.getElementById('approval-path').textContent = data.path || '';
  const riskEl = document.getElementById('approval-risk');
  riskEl.textContent = (data.risk_level || 'Unknown').toUpperCase();
  riskEl.className = `badge badge-${(data.risk_level || '').toLowerCase()}`;
  banner.classList.add('visible');
}

function hideApprovalBanner() {
  state.pendingApproval = null;
  document.getElementById('approval-banner').classList.remove('visible');
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
