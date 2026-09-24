// detection.js — Detection rules that run over the generated log stream.
//
// Rules only ever inspect observable event fields — never the hidden `_truth`.
// That is what makes false positives *emergent*: an admin's 2am SSH, a marketer's
// big upload, a user's fumbled password and an internal vuln scan trip the exact
// same rules an intruder does. Each rule tags its alerts with a severity, an SLA,
// and a knowledge-base key so the teaching layer can explain it.

// Severity → SLA in sim-seconds. The player must triage by priority, not order.
const SLA = { critical: 300, high: 900, medium: 1800, low: 3600 };

const INJECTION_SIGNS = [
  "or '1'='1", 'union select', 'drop table', '../', 'etc/passwd', '.env',
  '/wp-login', '/wp-admin', 'phpmyadmin', '<script', '%27', ';select', ';drop',
  'admin-ajax.php', 'xmlrpc.php', 'cmd=', 'exec(', 'passwd',
];
const BAD_UA = ['sqlmap', 'nikto', 'nessus', 'python-requests', 'python-urllib', 'masscan', 'hydra'];
const WEB_PARENTS = ['w3wp.exe', 'apache2', 'nginx', 'php-fpm', 'httpd', 'tomcat'];
const SHELL_IMAGES = ['cmd.exe', '/bin/sh', '/bin/bash', 'powershell.exe', 'powershell'];
const MINING_PORTS = new Set([3333, 4444, 5555, 7777, 45560]);
const BUSINESS_START = 7;
const BUSINESS_END = 19;

function isExternal(ip) {
  return ip && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !/^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}
function hourOf(ts) {
  return Math.floor((ts % 86400) / 3600);
}
function has(hay, needles) {
  const s = (hay || '').toLowerCase();
  return needles.some((n) => s.includes(n));
}

export class DetectionEngine {
  constructor() {
    // Sliding windows keyed by entity.
    this.failByIp = new Map(); // ip -> [ts...]
    this.scanByHost = new Map(); // host -> [{ts,dst}]
    this.renameByHost = new Map(); // host -> [ts...]
    this.knownUserIps = new Map(); // user -> Set(ip) learned baseline
    this.cooldown = new Map(); // key -> ts (suppress duplicate alerts)
    this._id = 0;
  }

  _prune(arr, ts, win) {
    while (arr.length && arr[0] <= ts - win) arr.shift();
  }
  _pruneObj(arr, ts, win) {
    while (arr.length && arr[0].ts <= ts - win) arr.shift();
  }
  _cool(key, ts, seconds) {
    const last = this.cooldown.get(key);
    if (last !== undefined && ts - last < seconds) return false;
    this.cooldown.set(key, ts);
    return true;
  }
  _mk(ts, ruleId, severity, title, summary, entities, evidence, kbKey, extra = {}) {
    return {
      id: `alert-${++this._id}`,
      ts,
      ruleId,
      severity,
      title,
      summary,
      entities: { hosts: entities.hosts || [], users: entities.users || [], ips: entities.ips || [] },
      evidenceEventIds: evidence,
      status: 'new',
      sla: SLA[severity],
      slaDeadline: ts + SLA[severity],
      kbKey,
      ...extra,
    };
  }

  // Ingest one event; return an array of newly-fired alerts (usually empty).
  ingest(ev) {
    const alerts = [];
    const ts = ev.ts;
    const f = ev.fields;

    // ---- Rule: Brute force (failed auth burst from one source) ----
    if (ev.source === 'auth' && f.result === 'failure' && f.srcIp) {
      const arr = this.failByIp.get(f.srcIp) || [];
      arr.push(ts);
      this.failByIp.set(f.srcIp, arr);
      this._prune(arr, ts, 120);
      if (arr.length >= 5 && this._cool(`bf:${f.srcIp}`, ts, 180)) {
        const sev = arr.length >= 15 ? 'high' : 'medium';
        alerts.push(this._mk(ts, 'brute_force', sev,
          `Possible brute force from ${f.srcIp}`,
          `${arr.length} failed logons from ${f.srcIp} to ${ev.host} in under 2 minutes (user "${f.user}").`,
          { hosts: [ev.host], ips: [f.srcIp], users: f.user ? [f.user] : [] },
          [ev.id], 'brute_force', { count: arr.length }));
      }
    }
    // Learn baseline source IPs from successful logons.
    if (ev.source === 'auth' && f.result === 'success' && f.user && f.srcIp) {
      const set = this.knownUserIps.get(f.user) || new Set();
      // ---- Rule: Login from new/foreign source (impossible travel-ish) ----
      if (isExternal(f.srcIp) && !set.has(f.srcIp) && set.size > 0 && this._cool(`travel:${f.user}`, ts, 600)) {
        alerts.push(this._mk(ts, 'anomalous_login', 'medium',
          `Login for ${f.user} from new external IP`,
          `Successful ${f.service} logon for "${f.user}" from ${f.srcIp}, an external source not previously seen for this account.`,
          { hosts: [ev.host], ips: [f.srcIp], users: [f.user] },
          [ev.id], 'anomalous_login'));
      }
      set.add(f.srcIp);
      this.knownUserIps.set(f.user, set);

      // ---- Rule: Off-hours logon to a server ----
      const h = hourOf(ts);
      const offHours = h < BUSINESS_START || h >= BUSINESS_END;
      const toServer = /^(dc|fs|db|app|backup|jump|mail)/.test(ev.host);
      if (offHours && toServer && (f.logonType === 3 || f.logonType === 10 || f.service === 'ssh' || f.service === 'rdp') && this._cool(`offh:${ev.host}:${f.user}`, ts, 900)) {
        alerts.push(this._mk(ts, 'offhours_logon', 'low',
          `Off-hours logon to ${ev.host}`,
          `"${f.user}" logged on to ${ev.host} at ${String(h).padStart(2, '0')}:xx, outside business hours (${BUSINESS_START}:00–${BUSINESS_END}:00).`,
          { hosts: [ev.host], users: [f.user], ips: f.srcIp ? [f.srcIp] : [] },
          [ev.id], 'offhours_logon'));
      }
    }

    // ---- Rule: Web injection / attack signature ----
    if (ev.source === 'web') {
      const badPath = has(f.path, INJECTION_SIGNS);
      const badUa = has(f.ua, BAD_UA);
      if ((badPath || badUa) && this._cool(`inj:${f.srcIp}`, ts, 120)) {
        alerts.push(this._mk(ts, 'web_injection', 'medium',
          `Web attack signature from ${f.srcIp}`,
          `Request to ${ev.host}: "${f.httpMethod} ${f.path}"${badUa ? ` (tool UA: ${f.ua})` : ''}.`,
          { hosts: [ev.host], ips: [f.srcIp] },
          [ev.id], 'web_injection'));
      }
    }

    // ---- Process-based rules ----
    if (ev.source === 'process') {
      const parent = (f.parent || '').toLowerCase();
      const image = (f.image || '').toLowerCase();
      const cmd = (f.cmdline || '').toLowerCase();

      // Web/DB server process spawning a shell — classic RCE tell.
      if (WEB_PARENTS.some((p) => parent.includes(p)) && SHELL_IMAGES.some((s) => image.includes(s))) {
        if (this._cool(`rce:${ev.host}`, ts, 120)) {
          alerts.push(this._mk(ts, 'web_shell', 'high',
            `Web service spawned a shell on ${ev.host}`,
            `Parent "${f.parent}" spawned "${f.image}" (${f.cmdline || ''}). Web servers should not launch command shells.`,
            { hosts: [ev.host], users: f.user ? [f.user] : [] },
            [ev.id], 'web_shell'));
        }
      }
      // Credential dumping (LSASS access / known dumpers).
      if ((cmd.includes('lsass') && (cmd.includes('minidump') || cmd.includes('comsvcs') || cmd.includes('procdump'))) || image.includes('mimikatz') || cmd.includes('lazagne')) {
        if (this._cool(`creds:${ev.host}`, ts, 120)) {
          alerts.push(this._mk(ts, 'cred_dump', 'critical',
            `Credential dumping on ${ev.host}`,
            `Command "${f.cmdline}" indicates an attempt to extract credentials from memory.`,
            { hosts: [ev.host], users: f.user ? [f.user] : [] },
            [ev.id], 'cred_dump'));
        }
      }
      // Remote execution tool (PsExec/WMIExec).
      if (image.includes('psexesvc') || cmd.includes('psexec') || (image.includes('wmic') && cmd.includes('process call create'))) {
        if (this._cool(`psexec:${ev.host}`, ts, 120)) {
          alerts.push(this._mk(ts, 'remote_exec', 'high',
            `Remote execution tool on ${ev.host}`,
            `"${f.image}" ${f.cmdline || ''} — consistent with lateral movement via remote service execution.`,
            { hosts: [ev.host], users: f.user ? [f.user] : [] },
            [ev.id], 'remote_exec'));
        }
      }
      // Suspicious / obfuscated PowerShell.
      if (image.includes('powershell') && has(cmd, ['-enc', 'encodedcommand', 'hidden', 'downloadstring', 'frombase64', 'iex(', '-nop'])) {
        if (this._cool(`ps:${ev.host}`, ts, 180)) {
          alerts.push(this._mk(ts, 'suspicious_powershell', 'high',
            `Obfuscated PowerShell on ${ev.host}`,
            `"${f.cmdline}" uses encoding/hidden execution — common in malware loaders.`,
            { hosts: [ev.host], users: f.user ? [f.user] : [] },
            [ev.id], 'suspicious_powershell'));
        }
      }
      // Persistence mechanism creation (also fires on legit admin work → FP).
      if (has(cmd, ['schtasks', '/create /tn', 'sc.exe create', 'sc create', 'crontab', 'systemctl enable', 'new-service', 'reg.exe add', '\\run']) || image.includes('schtasks')) {
        if (this._cool(`persist:${ev.host}:${f.user}`, ts, 300)) {
          alerts.push(this._mk(ts, 'persistence', 'medium',
            `New autostart/task on ${ev.host}`,
            `"${f.cmdline}" created a persistence mechanism. Verify this is a sanctioned change.`,
            { hosts: [ev.host], users: f.user ? [f.user] : [] },
            [ev.id], 'persistence'));
        }
      }
      // Discovery commands (noisy; heavy FP from admins → low severity).
      if (has(cmd, ['net view', 'net group "domain admins"', 'nltest /dclist', 'nltest', 'whoami /all', 'ldapsearch', 'net group']) || image.includes('nmap')) {
        if (this._cool(`disco:${ev.host}`, ts, 300)) {
          alerts.push(this._mk(ts, 'discovery', 'low',
            `Reconnaissance commands on ${ev.host}`,
            `"${f.cmdline}" — enumeration of hosts/accounts. Common in both admin scripts and intrusions.`,
            { hosts: [ev.host], users: f.user ? [f.user] : [] },
            [ev.id], 'discovery'));
        }
      }
    }

    // ---- Rule: Data exfiltration (large outbound to external dest) ----
    if (ev.source === 'network' && f.direction === 'outbound' && isExternal(f.dstIp) && (f.bytes || 0) >= 50_000_000) {
      const sev = f.bytes >= 200_000_000 ? 'high' : 'medium';
      if (this._cool(`exfil:${ev.host}:${f.dstIp}`, ts, 300)) {
        alerts.push(this._mk(ts, 'exfiltration', sev,
          `Large outbound transfer from ${ev.host}`,
          `${(f.bytes / 1e6).toFixed(0)} MB sent from ${ev.host} to external ${f.dstIp}:${f.dstPort}. Possible data exfiltration.`,
          { hosts: [ev.host], ips: [f.dstIp] },
          [ev.id], 'exfiltration', { bytes: f.bytes }));
      }
    }
    // ---- Rule: Cryptomining (connection to mining pool port) ----
    if (ev.source === 'network' && (MINING_PORTS.has(f.dstPort) || (f.dstIp || '').includes('pool.'))) {
      if (this._cool(`mine:${ev.host}`, ts, 300)) {
        alerts.push(this._mk(ts, 'cryptomining', 'high',
          `Cryptomining traffic from ${ev.host}`,
          `${ev.host} connected to ${f.dstIp}:${f.dstPort} — a mining pool port.`,
          { hosts: [ev.host], ips: [f.dstIp] },
          [ev.id], 'cryptomining'));
      }
    }
    // ---- Rule: Internal port scan / sweep ----
    if (ev.source === 'network' && f.direction === 'internal') {
      const arr = this.scanByHost.get(ev.host) || [];
      arr.push({ ts, dst: f.dstIp });
      this.scanByHost.set(ev.host, arr);
      this._pruneObj(arr, ts, 90);
      const distinct = new Set(arr.map((x) => x.dst)).size;
      if (distinct >= 5 && this._cool(`scan:${ev.host}`, ts, 300)) {
        alerts.push(this._mk(ts, 'port_scan', 'medium',
          `Internal network scan from ${ev.host}`,
          `${ev.host} connected to ${distinct} distinct internal hosts in 90s — possible reconnaissance.`,
          { hosts: [ev.host] },
          arr.slice(-5).map(() => ev.id), 'port_scan'));
      }
    }

    // ---- Rule: Ransomware / mass file operation ----
    if (ev.source === 'file' && (f.op === 'rename' || f.op === 'delete' || f.op === 'write')) {
      if ((f.count || 0) >= 1000) {
        if (this._cool(`ransom:${ev.host}`, ts, 120)) {
          alerts.push(this._mk(ts, 'ransomware', 'critical',
            `Mass file modification on ${ev.host}`,
            `${f.count} files ${f.op}d on ${ev.host} (${f.path}). Consistent with ransomware encryption.`,
            { hosts: [ev.host], users: f.user ? [f.user] : [] },
            [ev.id], 'ransomware', { count: f.count }));
        }
      } else {
        const arr = this.renameByHost.get(ev.host) || [];
        arr.push(ts);
        this.renameByHost.set(ev.host, arr);
        this._prune(arr, ts, 60);
        if (arr.length >= 8 && this._cool(`ransom:${ev.host}`, ts, 120)) {
          alerts.push(this._mk(ts, 'ransomware', 'high',
            `Rapid file changes on ${ev.host}`,
            `${arr.length} file ${f.op} operations on ${ev.host} in 60s — possible encryption/wiper activity.`,
            { hosts: [ev.host], users: f.user ? [f.user] : [] },
            [ev.id], 'ransomware'));
        }
      }
    }
    // Ransom note dropped.
    if (ev.source === 'file' && f.op === 'create' && /readme|decrypt|recover|read_me|restore/i.test(f.path || '')) {
      if (this._cool(`note:${ev.host}`, ts, 120)) {
        alerts.push(this._mk(ts, 'ransom_note', 'critical',
          `Ransom note created on ${ev.host}`,
          `A ransom/recovery note "${f.path}" was written on ${ev.host}.`,
          { hosts: [ev.host] },
          [ev.id], 'ransomware'));
      }
    }

    // ---- Rule: Suspicious email (malicious-looking attachment/link) ----
    if (ev.source === 'email') {
      const att = (f.attachment || '').toLowerCase();
      const bad = /\.(exe|docm|xlsm|js|vbs|scr|jar|hta)$/.test(att) || /\.(pdf|docx|xlsx)\.exe$/.test(att);
      const lookalike = /(verify|secure-docs|account-|hr-portal|-verify)/.test(f.from || '');
      if ((bad || (lookalike && f.link)) && this._cool(`phish:${f.to}`, ts, 300)) {
        alerts.push(this._mk(ts, 'suspicious_email', 'low',
          `Suspicious email to ${f.to}`,
          `Mail from <${f.from}> with ${bad ? `attachment "${f.attachment}"` : 'a link'} and lookalike sender traits.`,
          { hosts: [ev.host], users: f.to ? [f.to.split('@')[0]] : [] },
          [ev.id], 'suspicious_email'));
      }
    }

    return alerts;
  }
}
