// Firewall4AI Admin UI
const API = '';
let pollInterval = null;
let lastLogID = 0;

// --- Navigation ---
function navigate(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.querySelector(`[data-page="${page}"]`).classList.add('active');
  if (page === 'dashboard') loadDashboard();
  if (page === 'approvals') loadApprovals();
  if (page === 'skills') loadSkills();
  if (page === 'credentials') loadCredentials();
  if (page === 'logs') loadLogs();
}

// --- API helpers ---
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(API + path, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text);
  }
  return res.json();
}

// --- Skill display helper ---
function formatSkillID(skillID) {
  if (!skillID) return '<span class="badge-status approved">global</span>';
  return esc(skillID);
}

// --- Source IP display helper ---
function formatSourceIP(sourceIP) {
  if (!sourceIP) return '<span class="badge-status approved">all VMs</span>';
  return esc(sourceIP);
}

// --- Dashboard ---
async function loadDashboard() {
  try {
    const [stats, pending, skills] = await Promise.all([
      api('GET', '/api/logs/stats'),
      api('GET', '/api/approvals/pending'),
      api('GET', '/api/skills'),
    ]);
    document.getElementById('stat-total').textContent = stats.total || 0;
    document.getElementById('stat-allowed').textContent = stats.allowed || 0;
    document.getElementById('stat-denied').textContent = stats.denied || 0;
    document.getElementById('stat-pending').textContent = stats.pending || 0;
    document.getElementById('pending-count').textContent = pending.length || 0;
    // Update sidebar badge
    const badge = document.getElementById('approval-badge');
    if (pending.length > 0) {
      badge.textContent = pending.length;
      badge.style.display = 'inline';
    } else {
      badge.style.display = 'none';
    }
    // Recent pending
    const tbody = document.getElementById('dash-pending-tbody');
    tbody.innerHTML = '';
    if (!pending || pending.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No pending approvals</td></tr>';
    } else {
      pending.slice(0, 5).forEach(a => {
        const skillDisplay = formatSkillID(a.skill_id);
        const sourceDisplay = formatSourceIP(a.source_ip);
        const approveBtn = `<button class="btn btn-success btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>`;
        const vmBtn = a.source_ip ? `<button class="btn btn-success btn-sm" onclick="decide('${esc(a.host)}','','${esc(a.source_ip)}','approved')" title="Approve for this VM">Approve VM</button>` : '';
        const globalBtn = (a.skill_id || a.source_ip) ? `<button class="btn btn-success btn-sm" onclick="decide('${esc(a.host)}','','','approved')" title="Approve for all agents">Approve Global</button>` : '';
        const denyBtn = `<button class="btn btn-danger btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>`;
        tbody.innerHTML += `<tr>
          <td><strong>${esc(a.host)}</strong></td>
          <td>${skillDisplay}</td>
          <td>${sourceDisplay}</td>
          <td>${timeAgo(a.created_at)}</td>
          <td>${approveBtn} ${vmBtn} ${globalBtn} ${denyBtn}</td>
        </tr>`;
      });
    }
  } catch (e) {
    console.error('Dashboard load error:', e);
  }
}

// --- Approvals ---
async function loadApprovals() {
  try {
    const approvals = await api('GET', '/api/approvals');
    const pending = (approvals || []).filter(a => a.status === 'pending');
    const badge = document.getElementById('approval-badge');
    if (pending.length > 0) {
      badge.textContent = pending.length;
      badge.style.display = 'inline';
    } else {
      badge.style.display = 'none';
    }
    const tbody = document.getElementById('approvals-tbody');
    tbody.innerHTML = '';
    if (!approvals || approvals.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No approval records</td></tr>';
      return;
    }
    approvals.sort((a, b) => {
      const order = { pending: 0, approved: 1, denied: 2 };
      return (order[a.status] || 9) - (order[b.status] || 9);
    });
    approvals.forEach(a => {
      const skillDisplay = formatSkillID(a.skill_id);
      const sourceDisplay = formatSourceIP(a.source_ip);
      const vmBtn = a.source_ip && a.status === 'pending'
        ? `<button class="btn btn-outline btn-sm" onclick="decide('${esc(a.host)}','','${esc(a.source_ip)}','approved')" title="Approve for this VM">VM</button>` : '';
      const globalBtn = (a.skill_id || a.source_ip) && a.status === 'pending'
        ? `<button class="btn btn-outline btn-sm" onclick="decide('${esc(a.host)}','','','approved')" title="Approve for all agents">Global</button>` : '';
      const actions = a.status === 'pending'
        ? `<button class="btn btn-success btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>
           ${vmBtn}
           ${globalBtn}
           <button class="btn btn-danger btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>`
        : `<button class="btn btn-outline btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>
           <button class="btn btn-outline btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>`;
      tbody.innerHTML += `<tr>
        <td><strong>${esc(a.host)}</strong></td>
        <td>${skillDisplay}</td>
        <td>${sourceDisplay}</td>
        <td><span class="badge-status ${a.status}">${a.status}</span></td>
        <td>${timeAgo(a.updated_at)}</td>
        <td>${actions}</td>
      </tr>`;
    });
  } catch (e) {
    console.error('Approvals load error:', e);
  }
}

async function decide(host, skillID, sourceIP, status) {
  try {
    await api('POST', '/api/approvals/decide', { host, skill_id: skillID, source_ip: sourceIP, status });
    // Refresh current page
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      const pageId = activePage.id.replace('page-', '');
      navigate(pageId);
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Add Rule (proactive approval) ---
function showAddRule() {
  document.getElementById('modal-rule').classList.add('active');
  updateRuleFields();
}
function hideAddRule() {
  document.getElementById('modal-rule').classList.remove('active');
  document.getElementById('rule-host').value = '';
  document.getElementById('rule-level').value = 'global';
  document.getElementById('rule-source-ip').value = '';
  document.getElementById('rule-status').value = 'approved';
  document.getElementById('rule-note').value = '';
  updateRuleFields();
}

function updateRuleFields() {
  const level = document.getElementById('rule-level').value;
  document.getElementById('rule-vm-fields').style.display = level === 'vm' ? 'block' : 'none';
}

async function addRule() {
  const host = document.getElementById('rule-host').value.trim();
  if (!host) { alert('Host pattern is required'); return; }
  const level = document.getElementById('rule-level').value;
  const status = document.getElementById('rule-status').value;
  const note = document.getElementById('rule-note').value.trim();
  let sourceIP = '';
  if (level === 'vm') {
    sourceIP = document.getElementById('rule-source-ip').value.trim();
    if (!sourceIP) { alert('Source IP is required for VM-specific rules'); return; }
  }
  try {
    await api('POST', '/api/approvals/decide', { host, skill_id: '', source_ip: sourceIP, status, note });
    hideAddRule();
    loadApprovals();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Skills ---
async function loadSkills() {
  try {
    const skills = await api('GET', '/api/skills');
    const tbody = document.getElementById('skills-tbody');
    tbody.innerHTML = '';
    if (!skills || skills.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No skills configured. Create one to get started.</td></tr>';
      return;
    }
    skills.forEach(s => {
      tbody.innerHTML += `<tr>
        <td><strong>${esc(s.id)}</strong></td>
        <td>${esc(s.name)}</td>
        <td><div class="token-display" onclick="copyToken(this)" title="Click to copy">${esc(s.token)}</div></td>
        <td>${(s.allowed_hosts || []).map(h => `<span class="badge-status approved">${esc(h)}</span>`).join(' ') || '<span class="badge-status denied">none</span>'}</td>
        <td>
          <span class="badge-status ${s.active ? 'approved' : 'denied'}">${s.active ? 'active' : 'inactive'}</span>
          <button class="btn btn-danger btn-sm" onclick="deleteSkill('${esc(s.id)}')" style="margin-left:8px">Delete</button>
        </td>
      </tr>`;
    });
  } catch (e) {
    console.error('Skills load error:', e);
  }
}

function showCreateSkill() {
  document.getElementById('modal-skill').classList.add('active');
}
function hideCreateSkill() {
  document.getElementById('modal-skill').classList.remove('active');
}

async function createSkill() {
  const id = document.getElementById('skill-id').value.trim();
  const name = document.getElementById('skill-name').value.trim();
  const hosts = document.getElementById('skill-hosts').value.trim().split(/[\n,]+/).map(h => h.trim()).filter(Boolean);
  if (!name) { alert('Name is required'); return; }
  try {
    const body = { name, allowed_hosts: hosts };
    if (id) body.id = id;
    const result = await api('POST', '/api/skills', body);
    hideCreateSkill();
    document.getElementById('skill-id').value = '';
    document.getElementById('skill-name').value = '';
    document.getElementById('skill-hosts').value = '';
    loadSkills();
    alert('Skill created!\n\nID: ' + result.id + '\nToken: ' + result.token);
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteSkill(id) {
  if (!confirm(`Delete skill "${id}"?`)) return;
  try {
    await api('DELETE', '/api/skills?id=' + encodeURIComponent(id));
    loadSkills();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

function copyToken(el) {
  navigator.clipboard.writeText(el.textContent);
  const orig = el.textContent;
  el.textContent = 'Copied!';
  setTimeout(() => { el.textContent = orig; }, 1000);
}

// --- Credentials ---
async function loadCredentials() {
  try {
    const creds = await api('GET', '/api/credentials');
    const tbody = document.getElementById('credentials-tbody');
    tbody.innerHTML = '';
    if (!creds || creds.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No credentials configured.</td></tr>';
      return;
    }
    creds.forEach(c => {
      tbody.innerHTML += `<tr>
        <td><strong>${esc(c.name)}</strong></td>
        <td>${esc(c.host_pattern)}</td>
        <td>${formatSkillID(c.skill_id)}</td>
        <td><span class="badge-status approved">${esc(c.injection_type)}</span></td>
        <td><span class="badge-status ${c.active ? 'approved' : 'denied'}">${c.active ? 'active' : 'inactive'}</span></td>
        <td><button class="btn btn-danger btn-sm" onclick="deleteCredential('${esc(c.id)}')">Delete</button></td>
      </tr>`;
    });
  } catch (e) {
    console.error('Credentials load error:', e);
  }
}

function showCreateCred() {
  document.getElementById('modal-cred').classList.add('active');
  updateCredFields();
}
function hideCreateCred() {
  document.getElementById('modal-cred').classList.remove('active');
}

function updateCredFields() {
  const type = document.getElementById('cred-type').value;
  document.getElementById('cred-header-fields').style.display = type === 'header' ? 'block' : 'none';
  document.getElementById('cred-basic-fields').style.display = type === 'basic_auth' ? 'block' : 'none';
  document.getElementById('cred-bearer-fields').style.display = type === 'bearer' ? 'block' : 'none';
  document.getElementById('cred-query-fields').style.display = type === 'query_param' ? 'block' : 'none';
}

async function createCredential() {
  const type = document.getElementById('cred-type').value;
  const cred = {
    name: document.getElementById('cred-name').value.trim(),
    host_pattern: document.getElementById('cred-host').value.trim(),
    skill_id: document.getElementById('cred-skill').value.trim(),
    injection_type: type,
    active: true,
  };
  if (!cred.name || !cred.host_pattern) { alert('Name and host pattern are required'); return; }
  if (type === 'header') {
    cred.header_name = document.getElementById('cred-header-name').value.trim();
    cred.header_value = document.getElementById('cred-header-value').value.trim();
  } else if (type === 'basic_auth') {
    cred.username = document.getElementById('cred-username').value.trim();
    cred.password = document.getElementById('cred-password').value.trim();
  } else if (type === 'bearer') {
    cred.token = document.getElementById('cred-bearer-token').value.trim();
  } else if (type === 'query_param') {
    cred.param_name = document.getElementById('cred-param-name').value.trim();
    cred.param_value = document.getElementById('cred-param-value').value.trim();
  }
  try {
    await api('POST', '/api/credentials', cred);
    hideCreateCred();
    loadCredentials();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteCredential(id) {
  if (!confirm('Delete this credential?')) return;
  try {
    await api('DELETE', '/api/credentials?id=' + encodeURIComponent(id));
    loadCredentials();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Logs ---
async function loadLogs() {
  try {
    const logs = await api('GET', '/api/logs?limit=200');
    renderLogs(logs || []);
  } catch (e) {
    console.error('Logs load error:', e);
  }
}

function renderLogs(logs) {
  const tbody = document.getElementById('logs-tbody');
  tbody.innerHTML = '';
  if (logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No log entries yet</td></tr>';
    return;
  }
  logs.forEach(l => {
    if (l.id > lastLogID) lastLogID = l.id;
    tbody.innerHTML += `<tr>
      <td style="color:var(--text-dim);font-size:11px">${formatTime(l.timestamp)}</td>
      <td>${formatSkillID(l.skill_id)}</td>
      <td><span class="method-badge">${esc(l.method)}</span></td>
      <td><strong>${esc(l.host)}</strong></td>
      <td>${esc(l.path || '-')}</td>
      <td><span class="badge-status ${l.status}">${l.status}</span></td>
      <td style="font-size:12px;color:var(--text-dim)">${esc(l.detail || '')}</td>
    </tr>`;
  });
}

// --- Polling ---
function startPolling() {
  pollInterval = setInterval(async () => {
    try {
      const pending = await api('GET', '/api/approvals/pending');
      const badge = document.getElementById('approval-badge');
      if (pending && pending.length > 0) {
        badge.textContent = pending.length;
        badge.style.display = 'inline';
      } else {
        badge.style.display = 'none';
      }
      // Poll new logs
      if (document.getElementById('page-logs').classList.contains('active')) {
        const newLogs = await api('GET', '/api/logs?after=' + lastLogID);
        if (newLogs && newLogs.length > 0) {
          const tbody = document.getElementById('logs-tbody');
          const empty = tbody.querySelector('.empty-state');
          if (empty) empty.parentElement.remove();
          newLogs.forEach(l => {
            if (l.id > lastLogID) lastLogID = l.id;
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td style="color:var(--text-dim);font-size:11px">${formatTime(l.timestamp)}</td>
              <td>${formatSkillID(l.skill_id)}</td>
              <td><span class="method-badge">${esc(l.method)}</span></td>
              <td><strong>${esc(l.host)}</strong></td>
              <td>${esc(l.path || '-')}</td>
              <td><span class="badge-status ${l.status}">${l.status}</span></td>
              <td style="font-size:12px;color:var(--text-dim)">${esc(l.detail || '')}</td>`;
            tbody.insertBefore(tr, tbody.firstChild);
          });
        }
      }
      // Refresh dashboard if active
      if (document.getElementById('page-dashboard').classList.contains('active')) {
        loadDashboard();
      }
    } catch (e) {
      // Silently ignore poll errors
    }
  }, 3000);
}

// --- Utilities ---
function esc(s) {
  if (!s) return '';
  const div = document.createElement('div');
  div.textContent = String(s);
  return div.innerHTML;
}

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  return d.toLocaleTimeString() + ' ' + d.toLocaleDateString();
}

function timeAgo(ts) {
  if (!ts) return '-';
  const seconds = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (seconds < 60) return seconds + 's ago';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
  return Math.floor(seconds / 86400) + 'd ago';
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.sidebar nav a').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      navigate(a.dataset.page);
    });
  });
  navigate('dashboard');
  startPolling();
});
