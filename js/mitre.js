const MITRE_DATA = {
  'Initial Access':      ['T1190 Exploit Public-Facing App','T1078 Valid Accounts','T1566 Phishing','T1133 External Remote Services'],
  'Execution':           ['T1059 Command Scripting','T1053 Scheduled Task','T1204 User Execution'],
  'Persistence':         ['T1547 Boot Autostart','T1543 System Service','T1136 Create Account'],
  'Credential Access':   ['T1110 Brute Force','T1003 OS Credential Dump','T1555 Credentials from Stores'],
  'Discovery':           ['T1046 Network Service Scan','T1018 Remote System Discovery','T1083 File Discovery'],
  'Lateral Movement':    ['T1021 Remote Services','T1563 Session Hijack','T1570 Lateral Tool Transfer'],
  'Command & Control':   ['T1071 App Layer Protocol','T1105 Ingress Tool Transfer','T1095 Non-App Layer'],
  'Exfiltration':        ['T1041 Exfil Over C2','T1048 Exfil Alt Protocol','T1567 Exfil Web Service'],
};

// Detected techniques (from live events)
const detectedTechniques = new Set(['T1110','T1046','T1041','T1071','T1021']);
const monitoredTechniques = new Set(['T1059','T1078','T1133','T1083','T1003']);

function renderMitre() {
  const el = document.getElementById('mitreMatrix');
  const cols = Object.entries(MITRE_DATA).map(([tactic, techs]) => `
    <div class="mitre-tactic-col">
      <div class="mitre-tactic-hdr">${tactic}</div>
      ${techs.map(t => {
        const id = t.split(' ')[0];
        const cls = detectedTechniques.has(id) ? 'detected' : monitoredTechniques.has(id) ? 'monitored' : '';
        return `<div class="mitre-cell ${cls}" title="${t}">${t}</div>`;
      }).join('')}
    </div>`).join('');
  
  el.innerHTML = `
    <div style="display:flex;gap:1rem;margin-bottom:.75rem;font-size:9px;padding:0 .5rem">
      <span style="display:flex;align-items:center;gap:.4rem"><span style="width:10px;height:10px;background:rgba(248,81,73,.3);border:1px solid rgba(248,81,73,.6);border-radius:2px;display:inline-block"></span> Detected</span>
      <span style="display:flex;align-items:center;gap:.4rem"><span style="width:10px;height:10px;background:rgba(210,153,34,.15);border:1px solid rgba(210,153,34,.4);border-radius:2px;display:inline-block"></span> Monitored</span>
      <span style="display:flex;align-items:center;gap:.4rem"><span style="width:10px;height:10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:2px;display:inline-block"></span> No Coverage</span>
    </div>
    <div class="mitre-tactics">${cols}</div>`;
}
