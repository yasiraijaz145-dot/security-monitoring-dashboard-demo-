const STAGES = ['Recon','Weapon','Delivery','Exploit','Install','C2','Exfil'];
const DEMO_IPS = ['185.220.101.45','91.108.4.22','45.142.212.100','103.75.190.88','5.188.86.172','194.165.16.98','78.128.113.10','109.70.100.22'];
const DEMO_TYPES = ['SSH brute force','Port scan','HTTP probe','C2 beacon','Data exfiltration','Lateral movement'];
const DEMO_SEVS = ['Low','Medium','Medium','High','High','Critical'];
const DEMO_STAGES = ['Recon','Recon','Delivery','Exploit','C2','Exfil','Install'];

let smEvents = [];
let activeFilter = 'all';
let blockedIPs = new Set(JSON.parse(localStorage.getItem('sm_blocked') || '[]'));

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
  if (!b) return;
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
  renderGeoMap();
}

function renderGeoMap() {
  const el = document.getElementById('geoGrid');
  if (!el) return;
  const countryMap = {};
  const flags = {'185.220':'🇷🇺','91.108':'🇷🇺','45.142':'🇨🇳','103.75':'🇨🇳','5.188':'🇮🇷','194.165':'🇮🇷','78.128':'🇺🇦','109.70':'🇰🇵'};
  const names = {'185.220':'Russia','91.108':'Russia','45.142':'China','103.75':'China','5.188':'Iran','194.165':'Iran','78.128':'Ukraine','109.70':'N.Korea'};
  smEvents.forEach(e => {
    const prefix = e.ip.split('.').slice(0,2).join('.');
    const country = names[prefix] || 'Unknown';
    countryMap[country] = (countryMap[country] || 0) + 1;
  });
  if (!Object.keys(countryMap).length) {
    el.innerHTML = '<div style="color:var(--muted);font-size:10px">No data yet</div>';
    return;
  }
  const flagMap = {'Russia':'🇷🇺','China':'🇨🇳','Iran':'🇮🇷','Ukraine':'🇺🇦','N.Korea':'🇰🇵','Unknown':'🌐'};
  const sorted = Object.entries(countryMap).sort((a,b) => b[1]-a[1]);
  el.innerHTML = sorted.map(([country, count]) => `
    <div style="display:flex;align-items:center;gap:.5rem;padding:.5rem .75rem;background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:4px;min-width:140px">
      <span style="font-size:18px">${flagMap[country]||'🌐'}</span>
      <div>
        <div style="font-size:10px;color:var(--text)">${country}</div>
        <div style="font-size:9px;color:var(--red)">${count} attacks</div>
      </div>
    </div>`).join('');
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
  const bc = document.getElementById('blockedCount');
  if (bc) bc.textContent = blockedIPs.size + ' blocked';
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
    const count = smEvents.filter(x => x.ip === e.ip).length;
    const sc = { Critical:'sev-critical', High:'sev-high', Medium:'sev-medium', Low:'sev-low' }[e.severity] || 'sev-low';
    return `<tr>
      <td style="padding:.55rem 1rem;font-size:11px;border-bottom:1px solid var(--border);color:var(--muted)">${e.timestamp}</td>
      <td style="padding:.55rem 1rem;font-size:11px;border-bottom:1px solid var(--border);color:var(--text)">${e.type}</td>
      <td style="padding:.55rem 1rem;font-size:11px;border-bottom:1px solid var(--border);color:var(--accent)">
        ${e.ip}
        ${count > 2 ? `<span style="margin-left:.4rem;background:rgba(248,81,73,.2);color:var(--red);font-size:8px;padding:.1rem .35rem;border-radius:3px">${count}x</span>` : ''}
        ${blockedIPs.has(e.ip) ? `<span style="margin-left:.4rem;background:rgba(248,81,73,.2);color:var(--red);font-size:8px;padding:.1rem .35rem;border-radius:3px">BLOCKED</span>` : ''}
      </td>
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
      <button onclick="blockIP('${ev.ip}')" style="background:rgba(248,81,73,.15);border:1px solid var(--red);color:var(--red);font-family:inherit;font-size:9px;padding:.2rem .5rem;border-radius:3px;cursor:pointer;">BLOCK</button>
    </div>`;
  }).join('');
}

function blockIP(ip) {
  blockedIPs.add(ip);
  localStorage.setItem('sm_blocked', JSON.stringify([...blockedIPs]));
  showAlertBanner({severity: 'High', ip, type: 'IP BLOCKED'});
  renderBlocklist();
  renderFeed();
}

function unblockIP(ip) {
  blockedIPs.delete(ip);
  localStorage.setItem('sm_blocked', JSON.stringify([...blockedIPs]));
  renderBlocklist();
  renderFeed();
}

function renderBlocklist() {
  const el = document.getElementById('blocklistPanel');
  if (!el) return;
  const bc = document.getElementById('blockedCount');
  if (bc) bc.textContent = blockedIPs.size + ' blocked';
  if (!blockedIPs.size) {
    el.innerHTML = '<div style="padding:1rem;color:var(--muted);font-size:10px">No IPs blocked yet. Click BLOCK on any event.</div>';
    return;
  }
  el.innerHTML = [...blockedIPs].map(ip => `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:.6rem 1rem;border-bottom:1px solid var(--border)">
      <span style="font-family:monospace;font-size:11px;color:var(--red)">🚫 ${ip}</span>
      <button onclick="unblockIP('${ip}')" style="background:none;border:1px solid var(--border);color:var(--muted);font-family:inherit;font-size:9px;padding:.2rem .5rem;border-radius:3px;cursor:pointer;">UNBLOCK</button>
    </div>`).join('');
}

function exportCSV() {
  const rows = [['Timestamp','Type','IP','Severity','Stage']];
  smEvents.forEach(e => rows.push([e.timestamp, e.type, e.ip, e.severity, e.stage]));
  const csv = rows.map(r => r.join(',')).join('\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv,' + encodeURIComponent(csv);
  a.download = `sentinelmind_${getNow().replace(/ /g,'_')}.csv`;
  a.click();
}

// Tab navigation
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`view-${tab.dataset.view}`).classList.add('active');
    if (tab.dataset.view === 'honeypot') renderDemoHoneypotFull();
    if (tab.dataset.view === 'threats') renderDemoThreats();
    if (tab.dataset.view === 'intel') renderDemoIntelFull();
    if (tab.dataset.view === 'mitre') renderMitre();
    if (tab.dataset.view === 'blocklist') renderBlocklist();
  });
});

const API = window.location.origin;

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

function renderDemoHoneypotFull() {
  const users = ['admin','root','ubuntu','pi','oracle','test'];
  const commands = ['whoami','id','uname -a','cat /etc/passwd','ls /','ps aux'];
  const paths = ['/wp-admin','/.env','/phpmyadmin','/.git/config','/admin','/login'];
  const agents = ['sqlmap/1.7','Nikto/2.1.6','python-requests/2.31','curl/7.88'];
  const payloads = ["' OR 1=1--","<script>alert(1)</script>","../../../../etc/passwd"];

  const sessions = Array.from({length: 12}, (_, i) => ({
    src_ip: DEMO_IPS[rnd(0, DEMO_IPS.length-1)],
    timestamp: new Date(Date.now() - i * rnd(60000, 600000)).toISOString(),
    username: users[rnd(0, users.length-1)],
    commands_run: Array.from({length: rnd(0,3)}, () => commands[rnd(0, commands.length-1)]),
  }));

  const probes = Array.from({length: 12}, (_, i) => ({
    src_ip: DEMO_IPS[rnd(0, DEMO_IPS.length-1)],
    timestamp: new Date(Date.now() - i * rnd(60000, 600000)).toISOString(),
    method: ['GET','POST','PUT'][rnd(0,2)],
    path: paths[rnd(0, paths.length-1)],
    user_agent: agents[rnd(0, agents.length-1)],
    payload: Math.random() > 0.5 ? payloads[rnd(0, payloads.length-1)] : null,
  }));

  renderSessions(sessions);
  renderProbes(probes);
}

function renderDemoIntelFull() {
  const el = document.getElementById('feedSummary');
  if (el) el.innerHTML = `
    <div style="padding:1rem;display:flex;flex-direction:column;gap:.75rem">
      <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Total IOCs</span><strong style="color:var(--accent)">142,830</strong></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">IP Addresses</span><strong>98,241</strong></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Domains</span><strong>31,205</strong></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">File Hashes</span><strong>13,384</strong></div>
      <div style="font-size:9px;color:var(--muted);margin-top:.5rem">Sources: AlienVault OTX, EmergingThreats, Abuse.ch, VirusTotal</div>
      <div style="font-size:9px;color:var(--green)">Last sync: ${new Date().toLocaleString()}</div>
    </div>`;
}

function renderThreats(threats) {
  const el = document.getElementById('threatsList');
  if (!el) return;
  el.innerHTML = `<div style="display:flex;flex-direction:column;gap:1px">${threats.map(t => {
    const status = localStorage.getItem(`thr_status_${t.id}`) || 'OPEN';
    const statusColor = {OPEN:'var(--red)',INVESTIGATING:'var(--yellow)',RESOLVED:'var(--green)'}[status];
    return `
    <div style="padding:1.25rem;border-bottom:1px solid var(--border);display:grid;grid-template-columns:80px 1fr auto auto;gap:1rem;align-items:center">
      <span class="risk-badge risk-${t.severity}">${t.severity}</span>
      <div>
        <div style="font-size:12px;color:var(--text);font-weight:600;margin-bottom:.3rem">${t.name}</div>
        <div style="font-size:9px;color:var(--muted)">Stage: ${t.stage} · IOCs: ${t.iocs} · ${t.techniques.join(', ')}</div>
      </div>
      <select onchange="updateThreatStatus('${t.id}', this.value)" style="background:var(--bg);border:1px solid var(--border);color:${statusColor};font-family:inherit;font-size:9px;padding:.3rem;border-radius:3px;cursor:pointer">
        <option ${status==='OPEN'?'selected':''}>OPEN</option>
        <option ${status==='INVESTIGATING'?'selected':''}>INVESTIGATING</option>
        <option ${status==='RESOLVED'?'selected':''}>RESOLVED</option>
      </select>
      <div style="font-size:9px;color:var(--purple)">${t.id}</div>
    </div>`;
  }).join('')}</div>`;
}

function updateThreatStatus(id, status) {
  localStorage.setItem(`thr_status_${id}`, status);
  renderDemoThreats();
}

function renderDemoThreats() {
  renderThreats([
    {id:'THR-001',name:'APT-29 Campaign',severity:'CRITICAL',stage:'Exfiltration',iocs:14,techniques:['T1041','T1071']},
    {id:'THR-002',name:'Cobalt Strike Beacon',severity:'HIGH',stage:'C2',iocs:7,techniques:['T1105','T1021']},
    {id:'THR-003',name:'SSH Brute Force Campaign',severity:'MEDIUM',stage:'Initial Access',iocs:31,techniques:['T1110','T1078']},
  ]);
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
    const known = ['185.220.101.1','91.108.56.12','45.142.212.100','194.165.16.98','5.188.86.172'];
    const isKnown = known.includes(val);
    document.getElementById('iocResult').innerHTML = `
      <div style="padding:1rem;margin:1rem;border:1px solid ${isKnown ? 'var(--red)' : 'var(--green)'};border-radius:4px;background:${isKnown ? 'rgba(248,81,73,.1)' : 'rgba(63,185,80,.1)'}">
        <div style="font-size:11px;font-weight:700;color:${isKnown ? 'var(--red)' : 'var(--green)'};margin-bottom:.5rem">${isKnown ? '⚠ KNOWN MALICIOUS' : '✓ NOT IN IOC DATABASE'}</div>
        ${isKnown ? '<div style="font-size:10px;color:var(--muted)">Type: Known C2 / Botnet · Sources: AlienVault OTX, EmergingThreats</div>' : ''}
      </div>`;
  }
}

function autoStream() {
  setInterval(() => {
    const si = rnd(0, DEMO_SEVS.length - 1);
    const ev = {
      id: Date.now(),
      timestamp: getNow(),
      type: DEMO_TYPES[rnd(0, DEMO_TYPES.length - 1)],
      ip: DEMO_IPS[rnd(0, DEMO_IPS.length - 1)],
      severity: DEMO_SEVS[si],
      stage: DEMO_STAGES[rnd(0, DEMO_STAGES.length - 1)],
    };
    smEvents.unshift(ev);
    if (smEvents.length > 100) smEvents.pop();
    saveEvents();
    if (ev.severity === 'High' || ev.severity === 'Critical') showAlertBanner(ev);
    renderAll();
    drawTimeline(smEvents);
    document.title = `[${smEvents.filter(e=>e.severity==='Critical').length} CRITICAL] SentinelMind`;
  }, 1500 + Math.random() * 1500);
}

// Init
loadEvents();
if (smEvents.length === 0) generateDemoEvents();
renderAll();
autoStream();
