// behavior.js — Normal ("benign") activity generator.
//
// Each tick, personas generate activity consistent with their role and hours.
// Crucially, some of that perfectly legitimate activity looks suspicious and
// will trip the very same detection rules the attacker does — a fat-fingered
// password becomes a "brute force", an admin's 2am SSH becomes "off-hours
// lateral movement", a marketer's big upload becomes "exfiltration". False
// positives are never generated as a labeled category; they are a genuine
// consequence of realistic-but-benign behavior.

import { inHours, hourOf } from './time.js';

const NORMAL_DOMAINS = [
  'google.com', 'office365.com', 'salesforce.com', 'github.com', 'slack.com',
  'zoom.us', 'dropbox.com', 'atlassian.net', 'linkedin.com', 'cdn.jsdelivr.net',
  'aws.amazon.com', 'stackoverflow.com', 'notion.so', 'youtube.com', 'wikipedia.org',
];
const NORMAL_PATHS = ['/', '/login', '/dashboard', '/api/v1/status', '/assets/app.js', '/favicon.ico', '/health', '/reports', '/search?q=quarterly'];
const SCANNER_PATHS = [
  "/index.php?id=1' OR '1'='1", '/wp-login.php', '/admin/../../etc/passwd',
  '/.env', '/phpmyadmin/', '/api/users?id=1;SELECT', '/cgi-bin/test.sh', '/xmlrpc.php',
];
const UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/17.0',
  'Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0',
];
const ADMIN_TOOLS = [
  { image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmd: 'Get-Service | Where-Object {$_.Status -eq "Stopped"}' },
  { image: 'C:\\Windows\\System32\\wbem\\WMIC.exe', cmd: 'process list brief' },
  { image: 'C:\\Windows\\System32\\mmc.exe', cmd: 'compmgmt.msc' },
  { image: '/usr/bin/sudo', cmd: 'systemctl restart nginx' },
  { image: '/usr/bin/apt', cmd: 'apt upgrade -y' },
];

// Convert an events-per-hour rate into a per-tick probability given dt seconds.
function chance(ratePerHour, dt) {
  return 1 - Math.exp((-ratePerHour * dt) / 3600);
}

function effectiveHour(ts, tzShift) {
  return hourOf(ts + tzShift * 3600);
}

export function generateBackground(ctx) {
  const { rng, ts, dt, personas, network, emit } = ctx;

  for (const p of personas) {
    const atWork = inHours(ts + p.timezoneShift * 3600, p.workStart, p.workEnd);
    const prevAtWork = !!p._atWork;
    p._atWork = atWork;
    const host = network.hostById[p.primaryHost];
    if (!host) continue;

    // --- Session start: logon at the beginning of the workday ---
    if (atWork && !prevAtWork) {
      const fromVpn = p.habits.usesVpn && rng.bool(0.4);
      const srcIp = fromVpn && p.homeIp ? p.homeIp : host.ip;
      // Fat-finger: a burst of failed logons before success (benign brute-force).
      if (rng.bool(p.habits.fumbleRate * 6)) {
        const fails = rng.int(2, 5);
        for (let i = 0; i < fails; i++) {
          emit('auth', host.id, {
            service: host.os.startsWith('Windows') ? 'winlogon' : 'ssh',
            user: p.username, srcIp, result: 'failure', method: 'password', srcPort: rng.int(30000, 60000),
          });
        }
      }
      emit('auth', host.id, {
        service: host.os.startsWith('Windows') ? 'winlogon' : 'ssh',
        user: p.username, srcIp, result: 'success', method: p.habits.usesVpn && fromVpn ? 'publickey' : 'password',
        logonType: fromVpn ? 10 : 2, srcPort: rng.int(30000, 60000),
      });
    }

    if (!atWork && !(p.habits.oddHours && rng.bool(0.3))) {
      continue; // off the clock and not an odd-hours person right now
    }

    // --- Web browsing ---
    if (rng.bool(chance(p.habits.webHeavy ? 40 : 12, dt))) {
      const domain = rng.pick(NORMAL_DOMAINS);
      emit('dns', host.id, { query: domain, qtype: 'A', answer: `93.184.${rng.int(0, 255)}.${rng.int(1, 254)}` });
      emit('network', host.id, {
        srcIp: host.ip, dstIp: `93.184.${rng.int(0, 255)}.${rng.int(1, 254)}`,
        dstPort: 443, proto: 'tcp', direction: 'outbound', bytes: rng.int(500, 40000),
      });
    }

    // --- File server access (finance/hr/normal document work) ---
    if (rng.bool(chance(p.habits.accessDb ? 10 : 4, dt))) {
      const fs = network.hostById[network.landmarks.fileServer];
      if (fs) {
        emit('file', fs.id, { user: p.username, op: rng.pick(['read', 'write']), path: `\\\\${fs.hostname}\\${p.dept}\\${rng.pick(['Q3-budget.xlsx', 'contract.docx', 'payroll.csv', 'notes.txt'])}` });
      }
    }

    // --- Big legitimate transfers (marketing assets, dev artifacts, backups) ---
    if (p.habits.bigFiles && rng.bool(chance(2, dt))) {
      emit('network', host.id, {
        srcIp: host.ip, dstIp: rng.pick(['52.216.', '142.250.', '13.107.']) + rng.int(0, 255) + '.' + rng.int(1, 254),
        dstPort: 443, proto: 'tcp', direction: 'outbound', bytes: rng.int(50_000_000, 500_000_000),
      });
    }

    // --- Admins/devs SSH to servers (looks like lateral movement, esp. odd hours) ---
    if (p.habits.sshServers && p.managedHosts.length && rng.bool(chance(p.habits.admin ? 6 : 3, dt))) {
      const target = network.hostById[rng.pick(p.managedHosts)];
      if (target) {
        const srcIp = p.habits.usesVpn && rng.bool(0.3) && p.homeIp ? p.homeIp : host.ip;
        emit('auth', target.id, {
          service: target.os.startsWith('Windows') ? 'rdp' : 'ssh',
          user: p.username, srcIp, result: 'success', method: 'publickey', srcPort: rng.int(30000, 60000), logonType: 10,
        });
        // Admins legitimately run LOLBin-ish tools on servers.
        if (p.habits.admin && rng.bool(0.6)) {
          const tool = rng.pick(ADMIN_TOOLS);
          emit('process', target.id, { user: p.username, parent: target.os.startsWith('Windows') ? 'explorer.exe' : 'bash', image: tool.image, cmdline: tool.cmd });
        }
      }
    }

    // --- Developer midnight commits (off-hours activity that isn't malicious) ---
    if (p.habits.commitsAtNight) {
      const h = effectiveHour(ts, p.timezoneShift);
      if ((h >= 23 || h <= 2) && rng.bool(chance(8, dt))) {
        emit('process', host.id, { user: p.username, parent: 'bash', image: '/usr/bin/git', cmdline: `git push origin feature/${rng.pick(['auth', 'ui', 'api'])}-${rng.int(1, 99)}` });
        emit('network', host.id, { srcIp: host.ip, dstIp: '140.82.121.4', dstPort: 443, proto: 'tcp', direction: 'outbound', bytes: rng.int(10000, 2_000_000) });
      }
    }

    // --- Email (occasional external mail with links/attachments — benign) ---
    if (rng.bool(chance(3, dt))) {
      const external = rng.bool(0.4);
      emit('email', network.hostById[network.landmarks.mail]?.id || host.id, {
        from: external ? `${rng.pick(['newsletter', 'billing', 'noreply', 'jane.doe'])}@${rng.pick(['vendor.com', 'partner.io', 'news.co'])}` : `${p.username}@${network.domain}`,
        to: `${p.username}@${network.domain}`,
        subject: rng.pick(['Invoice #' + rng.int(1000, 9999), 'Re: meeting notes', 'Your weekly report', 'Action required: review doc']),
        attachment: rng.bool(0.3) ? rng.pick(['invoice.pdf', 'report.xlsx', 'contract.docx']) : null,
        link: rng.bool(0.5),
      });
    }
  }

  // --- Non-persona ambient noise on internet-facing services ---
  // Internal vulnerability scanner (runs periodically) + search crawlers + the
  // background internet hum against the DMZ. These create benign web alerts.
  for (const wsId of network.landmarks.webServers) {
    const web = network.hostById[wsId];
    if (!web) continue;
    // Normal traffic
    if (rng.bool(chance(60, dt))) {
      emit('web', web.id, {
        srcIp: `${rng.int(20, 220)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
        httpMethod: 'GET', path: rng.pick(NORMAL_PATHS), status: rng.pick([200, 200, 200, 301, 404]), bytes: rng.int(200, 8000), ua: rng.pick(UAS),
      });
    }
    // Internal authorized scanner or opportunistic internet scan — injection-ish
    // paths that trip the web-injection rule but are benign/expected.
    if (rng.bool(chance(6, dt))) {
      const internal = rng.bool(0.5);
      emit('web', web.id, {
        srcIp: internal ? `10.${network.baseOctet}.50.${rng.int(10, 40)}` : `${rng.int(20, 220)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
        httpMethod: rng.pick(['GET', 'POST']), path: rng.pick(SCANNER_PATHS), status: rng.pick([404, 403, 400, 200]), bytes: rng.int(0, 2000),
        ua: internal ? 'Nessus/10.6 (authorized-scan)' : rng.pick(['sqlmap/1.7', 'Nikto/2.5', 'python-requests/2.31']),
      });
    }
  }
}
