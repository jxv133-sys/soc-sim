// logsource.js — Canonical log event model + realistic message rendering.
//
// Both the behavior generator (benign) and the attack engine (malicious) emit
// events through here, so a real user fumbling a password and an attacker
// brute-forcing produce structurally identical auth-failure events. Detection
// rules only ever see the observable `fields` — never the hidden `_truth`, which
// exists solely for the after-action report.

import { fmtClock } from './time.js';

export const SOURCES = ['auth', 'web', 'process', 'network', 'dns', 'file', 'firewall', 'email'];

// Build an event. `_truth` records ground truth for scoring; strip it before
// sending to the client with sanitize().
export function makeEvent(id, ts, source, host, fields, truth) {
  const ev = {
    id,
    ts,
    source,
    host,
    srcIp: fields.srcIp || null,
    user: fields.user || null,
    fields,
    message: render(source, host, fields, ts),
    _truth: truth || { origin: 'benign' },
  };
  return ev;
}

// Remove ground-truth metadata for anything sent to the player.
export function sanitize(ev) {
  const { _truth, ...rest } = ev;
  return rest;
}

// Render a syslog-ish human-readable line per source. Kept realistic so that
// full-text search and pivoting feel like a real console.
function render(source, host, f, ts) {
  const t = fmtClock(ts);
  switch (source) {
    case 'auth': {
      const via = f.method || 'password';
      if (f.service === 'ssh') {
        return f.result === 'success'
          ? `${t} ${host} sshd[${f.pid || 0}]: Accepted ${via} for ${f.user} from ${f.srcIp} port ${f.srcPort || 0}`
          : `${t} ${host} sshd[${f.pid || 0}]: Failed ${via} for ${f.invalid ? 'invalid user ' : ''}${f.user} from ${f.srcIp} port ${f.srcPort || 0}`;
      }
      if (f.service === 'rdp' || f.service === 'winlogon') {
        const eid = f.result === 'success' ? 4624 : 4625;
        return `${t} ${host} Security-Auditing[${eid}]: ${f.result === 'success' ? 'Successful' : 'Failed'} logon user=${f.user} type=${f.logonType || 10} src=${f.srcIp || 'local'}`;
      }
      return `${t} ${host} auth: ${f.result} ${f.user} from ${f.srcIp}`;
    }
    case 'web': {
      return `${t} ${host} ${f.srcIp} - - "${f.httpMethod || 'GET'} ${f.path} HTTP/1.1" ${f.status} ${f.bytes || 0} "${f.ua || '-'}"`;
    }
    case 'process': {
      return `${t} ${host} Sysmon[1] ProcessCreate: user=${f.user || 'SYSTEM'} parent="${f.parent || '-'}" image="${f.image}" cmd="${f.cmdline || ''}"`;
    }
    case 'network': {
      const dir = f.direction || 'outbound';
      return `${t} ${host} netflow: ${dir} ${f.srcIp}:${f.srcPort || 0} -> ${f.dstIp}:${f.dstPort} ${f.proto || 'tcp'} bytes=${f.bytes || 0}`;
    }
    case 'dns': {
      return `${t} ${host} dns: query ${f.query} type=${f.qtype || 'A'} -> ${f.answer || 'NXDOMAIN'}`;
    }
    case 'file': {
      return `${t} ${host} file: user=${f.user || 'SYSTEM'} op=${f.op} path="${f.path}"${f.count ? ` count=${f.count}` : ''}`;
    }
    case 'firewall': {
      return `${t} FW ${f.action} ${f.srcIp}:${f.srcPort || 0} -> ${f.dstIp}:${f.dstPort} ${f.proto || 'tcp'}`;
    }
    case 'email': {
      return `${t} ${host} mail: from=<${f.from}> to=<${f.to}> subject="${f.subject}"${f.attachment ? ` attachment="${f.attachment}"` : ''}${f.link ? ' [contains-link]' : ''}`;
    }
    default:
      return `${t} ${host} ${source}: ${JSON.stringify(f)}`;
  }
}
