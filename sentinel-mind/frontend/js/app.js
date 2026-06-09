const STAGES = ['Recon','Weapon','Delivery','Exploit','Install','C2','Exfil'];
const DEMO_IPS = ['185.220.101.45','91.108.4.22','45.142.212.100','103.75.190.88','5.188.86.172','194.165.16.98','78.128.113.10','109.70.100.22'];
const DEMO_TYPES = ['SSH brute force','Port scan','HTTP probe','C2 beacon','Data exfiltration','Lateral movement'];
const DEMO_SEVS = ['Low','Medium','Medium','High','High','Critical'];
const DEMO_STAGES = ['Recon','Recon','Delivery','Exploit','C2','Exfil','Install'];

let smEvents = [];
let activeFilter = 'all';

function rnd(a, b) { return Math.floor(Math.random() * (b - a + 1) + a); }

function loadEvents() {
  try { const s = localStorage.getItem('sm_events'); if (s) smEvents = JSON.parse(s); } catch(e) { smEvents = []; }
}

function saveEvents() {
  try { localStorage.setItem('sm_events', JSON.stringify(smEvents)); } catch(e) {}
}

function getNow() {
  return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

function addManualEvent(ev) {
  if (!ev) {
    const ip = document.getElementById('f-ip').value.trim() || `${rnd(1,254)}.${rnd(1,254)}.${rnd(1,254)}.${rnd(1,254)}`;
    ev = {
      id: Date.now(),
      timestamp: getNow(),
      type: document.getElementById('f-type').value,
      ip,
      severity: document.getElementById('f-sev').value,
      stage: document.getElementById('f-stage').value,
    };
    document.getElementById('f-ip').value = '';
  }
  smEvents.unshift(ev);
  saveEvents();
  if (ev.severity === 'High' || ev.severity === 'Critical') showAlertBanner(ev);
  renderAll();
}

function showAlertBanner(ev) {
  const b = document.getElementById('alertBanner');
  b.style.display = 'block';
  b.innerHTML = `⚠ ${ev.severity} severity event from <strong>${ev.ip}</strong> — ${ev.type}`;
  clearTimeout(b._timer);
  b._timer = setTimeout(() => { b.style.display = 'none'; }, 5000);
}

function generateDemoEvents() {
  const n = rnd(6, 10);
  for (let i = 0; i < n; i++) {
    const si = rnd(0, DEMO_SEVS.length - 1);
    addManualEvent({
      id: Date.now() + i,
      timestamp: new Date(Date.now() - i * rnd(30000, 300000)).toISOString().replace('T', ' ').substring(0, 19),
      type: DEMO_TYPES[rnd(0, DEMO_TYPES.length - 1)],
      ip: DEMO_IPS[rnd(0, DEMO_IPS.length - 1)],
      severity: DEMO_SEVS[si],
      stage: DEMO_STAGES[rnd(0, DEMO_STAGES.length - 1)],
    });
  }
}

function clearAllEvents() {
  smEvents = [];
  saveEvents();
  activeFilter = 'all';
  renderAll();
}

function toggleFilter(f) {
  activeFilter = (activeFilter === f) ? 'all' : f;
  document.querySelectorAll('.kpi-clickable').forEach(k => k.classList.remove('kpi-active'));
  const map = { Critical: 'kpib-critical', High: 'kpib-high', unique: 'kpib-unique', all: 'kpib-all' };
  if (map[activeFilter]) document.getElementById(map[activeFilter])?.classList.add('kpi-active');
  renderAll();
}

function getFiltered() {
  if (activeFilter === 'all') return smEvents;
  if (activeFilter === 'unique') {
    const seen = new Set();
    return smEvents.filter(e => { if (seen.has(e.ip)) return false; seen.add(e.ip); return true; });
  }
  return smEvents.filter(e => e.severity === activeFilter);
}

function renderAll() {
  renderKPIs();
  renderKillChain();
  renderTable();
  renderFeed();
}

function renderKPIs() {
  const total = smEvents.length;
  const crit = smEvents.filter(e => e.severity === 'Critical').length;
  const high = smEvents.filter(e => e.severity === 'High').length;
  const unique = new Set(smEvents.map(e => e.ip)).size;
  const mttd = total ? rnd(180, 420) : 0;
  document.getElementById('kpi-events').textContent = total;
  document.getElementById('kpi-critical').textContent = crit;
  document.getElementById('kpi-attackers').textContent = high;
  document.getElementById('kpi-detect').textContent = unique;
  document.getElementById('kpi-mttd').textContent = mttd + 'ms';
}

function renderKillChain() {
  const el = document.getElementById('killChain');
  if (!el) return;
  const counts = {};
  STAGES.forEach(s => counts[s] = 0);
  smEvents.forEach(e => { if (counts[e.stage] !== undefined) counts[e.stage]++; });
  el.innerHTML = `<div class="kc-stages">${STAGES.map(s => {
    const c = counts[s];
    const crit = ['C2','Exfil'].includes(s);
    const cls = c === 0 ? 'kc-stage' : (crit ? 'kc-stage critical' : 'kc-stage active');
    return `<div class="${cls}"><div class="kc-num">${c}</div><div class="kc-name">${s}</div></div>`;
  }).join('')}</div>`;
}

function renderTable() {
  const filtered = getFiltered();
  const tbody = document.getElementById('eventTableBody');
  const empty = document.getElementById('eventTableEmpty');
  const label = document.getElementById('filterLabel');
  if (!tbody) return;
  label.textContent = activeFilter === 'all'
    ? `${filtered.length} event${filtered.length !== 1 ? 's' : ''}`
    : `Filter: ${activeFilter} — ${filtered.length} result${filtered.length !== 1 ? 's' : ''}`;
  if (!filtered.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  tbody.innerHTML = filtered.map(e => {
    const sc = { Critical:'sev-critical', High:'sev-high', Medium:'sev-medium', Low:'sev-low' }[e.severity] || 'sev-low';
    return `<tr>
      <td style="padding:.55rem 1rem;font-size:11px;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;color:var(--muted)">${e.timestamp}</td>
      <td style="padding:.55rem 1rem;font-size:11px;border-bottom:1px solid var(--border);color:var(--text)">${e.type}</td>
      <td style="padding:.55rem 1rem;font-size:11px;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;color:var(--accent)">${e.ip}</td>
      <td style="padding:.55rem 1rem;font-size:11px;border-bottom:1px solid var(--border)"><span class="${sc}">${e.severity}</span></td>
    </tr>`;
  }).join('');
}

function renderFeed() {
  const feed = document.getElementById('eventFeed');
  if (!feed) return;
  if (!smEvents.length) {
    feed.innerHTML = '<div style="padding:2rem;text-align:center;color:var(--muted);font-size:11px">No events yet.</div>';
    return;
  }
  feed.innerHTML = smEvents.slice(0, 40).map(ev => {
    const techName = ev.type || 'Unknown';
    const t = ev.timestamp || '';
    return `<div class="event-item">
      <span class="event-time">${t.substring(11, 19)}</span>
      <div class="event-body">
        <span class="event-ip">${ev.ip} [${ev.stage}]</span>
        <span class="event-tech">${techName}</span>
      </div>
      <span class="risk-badge risk-${ev.severity.toUpperCase()}">${ev.severity.toUpperCase()}</span>
    </div>`;
  }).join('');
}

// Tab navigation
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`view-${tab.dataset.view}`).classList.add('active');
    if (tab.dataset.view === 'honeypot') loadHoneypot();
    if (tab.dataset.view === 'threats') loadThreats();
    if (tab.dataset.view === 'intel') loadIntel();
    if (tab.dataset.view === 'mitre') renderMitre();
  });
});

const API = window.location.origin;

async function loadHoneypot() {
  try {
    const [ssh, http] = await Promise.all([
      fetch(`${API}/api/honeypot/sessions`).then(r => r.json()),
      fetch(`${API}/api/honeypot/http-probes`).then(r => r.json()),
    ]);
    renderSessions(ssh.sessions);
    renderProbes(http.probes);
  } catch { renderDemoHoneypot(); }
}

function renderSessions(sessions) {
  const el = document.getElementById('sshSessions');
  if (!el) return;
  el.innerHTML = `<div style="overflow-y:auto;max-height:380px">${sessions.map(s => `
    <div class="event-item">
      <span class="event-time">${new Date(s.timestamp).toLocaleTimeString()}</span>
      <div class="event-body">
        <span class="event-ip">${s.src_ip} user:${s.username}</span>
        <span class="event-tech">${s.commands_run?.join(' | ') || 'No commands'}</span>
      </div>
      <span class="risk-badge risk-HIGH">SSH</span>
    </div>`).join('')}</div>`;
}

function renderProbes(probes) {
  const el = document.getElementById('httpProbes');
  if (!el) return;
  el.innerHTML = `<div style="overflow-y:auto;max-height:380px">${probes.map(p => `
    <div class="event-item">
      <span class="event-time">${new Date(p.timestamp).toLocaleTimeString()}</span>
      <div class="event-body">
        <span class="event-ip">${p.src_ip} ${p.method} ${p.path}</span>
        <span class="event-tech">${p.payload || p.user_agent || ''}</span>
      </div>
      <span class="risk-badge risk-MEDIUM">HTTP</span>
    </div>`).join('')}</div>`;
}

function renderDemoHoneypot() {
  const el = document.getElementById('sshSessions');
  if (el) el.innerHTML = `<div style="padding:1rem;color:var(--muted);font-size:10px">Demo mode — start FastAPI server for live honeypot data.</div>`;
}

async function loadThreats() {
  try {
    const r = await fetch(`${API}/api/threats/active`);
    const d = await r.json();
    renderThreats(d.threats);
  } catch { renderDemoThreats(); }
}

function renderThreats(threats) {
  const el = document.getElementById('threatsList');
  if (!el) return;
  el.innerHTML = `<div style="display:flex;flex-direction:column;gap:1px">${threats.map(t => `
    <div style="padding:1.25rem;border-bottom:1px solid var(--border);display:grid;grid-template-columns:80px 1fr auto;gap:1rem;align-items:center">
      <span class="risk-badge risk-${t.severity}">${t.severity}</span>
      <div>
        <div style="font-size:12px;color:var(--text);font-weight:600;margin-bottom:.3rem">${t.name}</div>
        <div style="font-size:9px;color:var(--muted)">Stage: ${t.stage} · IOCs: ${t.iocs} · ${t.techniques.join(', ')}</div>
      </div>
      <div style="font-size:9px;color:var(--purple)">${t.id}</div>
    </div>`).join('')}</div>`;
}

function renderDemoThreats() {
  renderThreats([
    {id:'THR-001',name:'APT-29 Campaign',severity:'CRITICAL',stage:'Exfiltration',iocs:14,techniques:['T1041','T1071']},
    {id:'THR-002',name:'Cobalt Strike Beacon',severity:'HIGH',stage:'C2',iocs:7,techniques:['T1105','T1021']},
    {id:'THR-003',name:'SSH Brute Force Campaign',severity:'MEDIUM',stage:'Initial Access',iocs:31,techniques:['T1110','T1078']},
  ]);
}

async function loadIntel() {
  try {
    const r = await fetch(`${API}/api/intel/ioc-summary`);
    const d = await r.json();
    document.getElementById('feedSummary').innerHTML = `
      <div style="padding:1rem;display:flex;flex-direction:column;gap:.75rem">
        <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Total IOCs</span><strong style="color:var(--accent)">${d.total_iocs.toLocaleString()}</strong></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">IP Addresses</span><strong>${d.ips.toLocaleString()}</strong></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Domains</span><strong>${d.domains.toLocaleString()}</strong></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">File Hashes</span><strong>${d.hashes.toLocaleString()}</strong></div>
        <div style="font-size:9px;color:var(--green);margin-top:.5rem">Last sync: ${new Date(d.last_updated).toLocaleString()}</div>
      </div>`;
  } catch {
    const el = document.getElementById('feedSummary');
    if (el) el.innerHTML = `<div style="padding:1rem;color:var(--muted);font-size:10px">Start FastAPI server for live intel data.</div>`;
  }
}

async function checkIOC() {
  const val = document.getElementById('iocInput').value.trim();
  if (!val) return;
  try {
    const r = await fetch(`${API}/api/intel/check-ip/${val}`);
    const d = await r.json();
    document.getElementById('iocResult').innerHTML = `
      <div style="padding:1rem;margin:1rem;border:1px solid ${d.is_ioc ? 'var(--red)' : 'var(--green)'};border-radius:4px;background:${d.is_ioc ? 'rgba(248,81,73,.1)' : 'rgba(63,185,80,.1)'}">
        <div style="font-size:11px;font-weight:700;color:${d.is_ioc ? 'var(--red)' : 'var(--green)'};margin-bottom:.5rem">${d.is_ioc ? '⚠ KNOWN MALICIOUS' : '✓ NOT IN IOC DATABASE'}</div>
        ${d.threat_type ? `<div style="font-size:10px;color:var(--muted)">Type: ${d.threat_type}</div>` : ''}
      </div>`;
  } catch {
    document.getElementById('iocResult').innerHTML = `<div style="padding:1rem;color:var(--muted)">API not connected — start FastAPI server.</div>`;
  }
}

// Init
loadEvents();
renderAll();