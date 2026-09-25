// network.js — Procedural network topology + firewall generator.
//
// From the seed we build a plausible small-org network: zones (DMZ, corporate
// workstations, internal servers, management), the hosts inside them, the
// services those hosts run, and the firewall rules governing what can reach
// what. Attack paths are NOT scripted — the attack engine pathfinds over the
// reachability graph produced here, so the topology genuinely constrains how an
// intrusion can unfold.

import { RNG } from './rng.js';

const ORG_PREFIXES = [
  'Meridian', 'Halcyon', 'Northwind', 'Brightpath', 'Cindermill', 'Vantage',
  'Blackstone', 'Riverbend', 'Ferrous', 'Ashgrove', 'Solstice', 'Kestrel',
];
const ORG_SUFFIXES = [
  'Logistics', 'Financial', 'Health', 'Manufacturing', 'Media', 'Retail',
  'Dynamics', 'Systems', 'Partners', 'Robotics', 'Analytics', 'Energy',
];

const ZONES = {
  internet: { label: 'Internet', cidrOctet: 0, kind: 'external' },
  dmz: { label: 'DMZ', kind: 'perimeter' },
  corp: { label: 'Corporate', kind: 'workstations' },
  servers: { label: 'Internal Servers', kind: 'servers' },
  mgmt: { label: 'Management', kind: 'admin' },
};

// Service templates keyed by host type. `weakChance` feeds vuln generation.
function serviceCatalog(rng, hostType) {
  switch (hostType) {
    case 'web-server': {
      const cms = rng.pick(['WordPress', 'Drupal', 'Joomla', 'custom-php-app', 'Tomcat']);
      return [
        { port: 443, proto: 'tcp', name: `https/${cms}`, exposure: 'internet', software: cms },
        { port: 80, proto: 'tcp', name: `http/${cms}`, exposure: 'internet', software: cms },
        { port: 22, proto: 'tcp', name: 'ssh', exposure: 'internal', software: 'OpenSSH' },
      ];
    }
    case 'vpn-gateway':
      return [{ port: 443, proto: 'tcp', name: 'ssl-vpn', exposure: 'internet', software: rng.pick(['FortiGate', 'PulseSecure', 'GlobalProtect']) }];
    case 'mail-server':
      return [
        { port: 25, proto: 'tcp', name: 'smtp', exposure: 'internet', software: 'Postfix' },
        { port: 993, proto: 'tcp', name: 'imaps', exposure: 'internal', software: 'Dovecot' },
        { port: 587, proto: 'tcp', name: 'submission', exposure: 'internet', software: 'Postfix' },
      ];
    case 'domain-controller':
      return [
        { port: 88, proto: 'tcp', name: 'kerberos', exposure: 'internal', software: 'ActiveDirectory' },
        { port: 389, proto: 'tcp', name: 'ldap', exposure: 'internal', software: 'ActiveDirectory' },
        { port: 445, proto: 'tcp', name: 'smb', exposure: 'internal', software: 'Windows' },
        { port: 53, proto: 'udp', name: 'dns', exposure: 'internal', software: 'Windows-DNS' },
      ];
    case 'file-server':
      return [
        { port: 445, proto: 'tcp', name: 'smb', exposure: 'internal', software: 'Windows' },
        { port: 2049, proto: 'tcp', name: 'nfs', exposure: 'internal', software: 'nfsd' },
      ];
    case 'db-server': {
      const db = rng.pick(['PostgreSQL', 'MySQL', 'MSSQL']);
      const port = db === 'PostgreSQL' ? 5432 : db === 'MySQL' ? 3306 : 1433;
      return [{ port, proto: 'tcp', name: db.toLowerCase(), exposure: 'internal', software: db }];
    }
    case 'app-server':
      return [
        { port: 8080, proto: 'tcp', name: 'http-app', exposure: 'internal', software: rng.pick(['Tomcat', 'Node', 'Jetty']) },
        { port: 22, proto: 'tcp', name: 'ssh', exposure: 'internal', software: 'OpenSSH' },
      ];
    case 'backup-server':
      return [
        { port: 445, proto: 'tcp', name: 'smb', exposure: 'internal', software: 'Windows' },
        { port: 9392, proto: 'tcp', name: 'backup-svc', exposure: 'internal', software: rng.pick(['Veeam', 'BackupExec']) },
      ];
    case 'jump-host':
      return [
        { port: 22, proto: 'tcp', name: 'ssh', exposure: 'internal', software: 'OpenSSH' },
        { port: 3389, proto: 'tcp', name: 'rdp', exposure: 'internal', software: 'Windows' },
      ];
    case 'workstation':
      return [{ port: 445, proto: 'tcp', name: 'smb', exposure: 'internal', software: 'Windows' }];
    default:
      return [];
  }
}

function pickOS(rng, hostType) {
  switch (hostType) {
    case 'workstation':
      return rng.pick(['Windows 10', 'Windows 11']);
    case 'domain-controller':
      return rng.pick(['Windows Server 2019', 'Windows Server 2022']);
    case 'file-server':
    case 'backup-server':
      return rng.pick(['Windows Server 2016', 'Windows Server 2019']);
    case 'web-server':
    case 'app-server':
    case 'db-server':
      return rng.pick(['Ubuntu 22.04', 'Debian 12', 'RHEL 9']);
    case 'jump-host':
      return rng.pick(['Windows Server 2019', 'Ubuntu 22.04']);
    case 'vpn-gateway':
      return 'appliance';
    case 'mail-server':
      return rng.pick(['Ubuntu 22.04', 'Debian 12']);
    default:
      return 'Linux';
  }
}

export function generateNetwork(seed) {
  const rng = new RNG(seed).fork('network');
  const base = rng.int(16, 199); // 10.<base>.<zone>.<host>
  const org = `${rng.pick(ORG_PREFIXES)} ${rng.pick(ORG_SUFFIXES)}`;
  const domain = `${org.split(' ')[0].toLowerCase()}.corp`;

  const zoneOctet = { dmz: 20, corp: 30, servers: 40, mgmt: 50 };
  const hosts = [];
  const counters = {};
  const ipCounters = { dmz: 10, corp: 10, servers: 10, mgmt: 10 };

  function nextName(prefix) {
    counters[prefix] = (counters[prefix] || 0) + 1;
    return `${prefix}${String(counters[prefix]).padStart(2, '0')}`;
  }
  function ipFor(zone) {
    return `10.${base}.${zoneOctet[zone]}.${ipCounters[zone]++}`;
  }
  function addHost(zone, type, hostnamePrefix, extra = {}) {
    const hostname = nextName(hostnamePrefix);
    const fqdn = `${hostname}.${domain}`;
    const host = {
      id: hostname,
      hostname,
      fqdn,
      ip: ipFor(zone),
      zone,
      type,
      os: pickOS(rng, type),
      services: serviceCatalog(rng, type),
      value: extra.value ?? 3,
      users: [],
      crownJewel: !!extra.crownJewel,
      ...extra,
    };
    hosts.push(host);
    return host;
  }

  // --- DMZ: internet-facing services ---
  const webCount = rng.int(1, 2);
  const webServers = [];
  for (let i = 0; i < webCount; i++) {
    webServers.push(addHost('dmz', 'web-server', 'web', { value: 4 }));
  }
  const hasVpn = rng.bool(0.7);
  const vpn = hasVpn ? addHost('dmz', 'vpn-gateway', 'vpn', { value: 5 }) : null;
  const mailInDmz = rng.bool(0.5);
  const mail = addHost(mailInDmz ? 'dmz' : 'servers', 'mail-server', 'mail', { value: 5 });

  // --- Internal servers: the crown jewels live here ---
  const dc = addHost('servers', 'domain-controller', 'dc', { value: 10, crownJewel: true });
  const fileServer = addHost('servers', 'file-server', 'fs', { value: 8, crownJewel: true });
  const db = addHost('servers', 'db-server', 'db', { value: 9, crownJewel: true });
  const extraServers = [];
  if (rng.bool(0.7)) extraServers.push(addHost('servers', 'app-server', 'app', { value: 6 }));
  if (rng.bool(0.6)) extraServers.push(addHost('servers', 'backup-server', 'backup', { value: 7 }));

  // --- Management: admin jump host ---
  const hasJump = rng.bool(0.7);
  const jump = hasJump ? addHost('mgmt', 'jump-host', 'jump', { value: 6 }) : null;

  // --- Corporate: workstations (populated with personas later) ---
  const wsCount = rng.int(6, 12);
  const workstations = [];
  for (let i = 0; i < wsCount; i++) {
    workstations.push(addHost('corp', 'workstation', 'ws', { value: 2 }));
  }

  // ---------- Firewall rules & reachability graph ----------
  // Rules are expressed zone-to-zone plus a few host-specific pinholes. The
  // reachability graph (edges with allowed ports) is what the attacker uses.
  const rules = [];
  const edges = []; // {from: hostId|'internet', to: hostId, ports:[...], note}

  const hostById = Object.fromEntries(hosts.map((h) => [h.id, h]));
  const inZone = (z) => hosts.filter((h) => h.zone === z);

  function allow(fromSel, toHost, ports, note) {
    edges.push({ from: fromSel, to: toHost.id, ports, note });
  }

  // Internet -> DMZ (only internet-exposed services).
  rules.push('Internet → DMZ: allow inbound to published services only');
  for (const h of inZone('dmz')) {
    const pub = h.services.filter((s) => s.exposure === 'internet').map((s) => s.port);
    if (pub.length) allow('internet', h, pub, 'published service');
  }

  // DMZ -> Internal servers: tight pinholes (this is the classic pivot).
  rules.push('DMZ → Servers: web app may reach its database only');
  for (const w of webServers) {
    // A web app typically talks to the database and sometimes an app server.
    allow(w.id, db, db.services.map((s) => s.port), 'app→db');
    for (const a of extraServers.filter((s) => s.type === 'app-server')) {
      allow(w.id, a, a.services.map((s) => s.port), 'app tier');
    }
  }
  if (mail.zone === 'dmz') {
    allow(mail.id, dc, [389, 88], 'mail→AD auth');
  }

  // Corporate -> Servers: workstations use core internal services.
  rules.push('Corporate → Servers: file shares, AD auth, mail, DNS');
  for (const w of workstations) {
    allow(w.id, dc, [88, 389, 445, 53], 'AD/SMB/DNS');
    allow(w.id, fileServer, fileServer.services.map((s) => s.port), 'file shares');
    allow(w.id, mail, [993, 587], 'mail');
    for (const s of extraServers) allow(w.id, s, s.services.map((x) => x.port), 'internal app');
  }

  // Servers -> Servers: internal trust, everything authenticates to the DC.
  rules.push('Servers → Servers: internal replication & AD auth');
  for (const s of inZone('servers')) {
    if (s.id !== dc.id) allow(s.id, dc, [88, 389, 445], 'AD auth');
  }

  // Management jump host -> everything internal (admin plane).
  if (jump) {
    rules.push('Management → All internal: administrative access (SSH/RDP/SMB)');
    for (const h of hosts) {
      if (h.zone === 'internet' || h.id === jump.id) continue;
      allow(jump.id, h, [22, 3389, 445], 'admin');
    }
    // Admins reach the jump host from their corp workstations.
    for (const w of workstations) allow(w.id, jump, [22, 3389], 'admin console');
  }

  // Corporate & servers -> Internet (egress for browsing/updates). Modeled as a
  // flag rather than per-host edges to keep the graph about lateral movement.
  rules.push('Corporate/Servers → Internet: egress allowed (web, DNS, updates)');

  // Build quick lookup: which hosts can a given host reach (and on which ports).
  const reachFrom = {};
  for (const e of edges) {
    (reachFrom[e.from] ||= []).push({ to: e.to, ports: e.ports, note: e.note });
  }

  // Seed-varied visual layout so every network *looks* distinct on the map, not
  // just structurally different. Deterministic per seed.
  const layout = generateLayout(rng.fork('layout'), hosts);

  return {
    seed,
    org,
    domain,
    baseOctet: base,
    zones: ZONES,
    hosts,
    hostById,
    edges,
    rules,
    reachFrom,
    layout,
    // Named references the rest of the sim uses.
    landmarks: {
      webServers: webServers.map((h) => h.id),
      vpn: vpn?.id || null,
      mail: mail.id,
      dc: dc.id,
      fileServer: fileServer.id,
      db: db.id,
      jump: jump?.id || null,
      workstations: workstations.map((h) => h.id),
      crownJewels: hosts.filter((h) => h.crownJewel).map((h) => h.id),
    },
    egressAllowed: true,
  };
}

// ---------------------------------------------------------------------------
// Layout generation — produce {hostId:{x,y}, internet:{x,y}, style} positions
// that vary by seed while keeping each zone visually grouped (so the map stays
// readable). Three distinct arrangement styles are chosen per seed.
// ---------------------------------------------------------------------------
function generateLayout(rng, hosts) {
  const zonesOrder = ['dmz', 'corp', 'servers', 'mgmt'];
  const byZone = {};
  for (const z of zonesOrder) byZone[z] = hosts.filter((h) => h.zone === z);
  const pos = {};
  const jit = (n) => rng.float(-n, n);

  // Arrange a list of nodes in a compact grid centred on (cx,cy).
  const gridAround = (list, cx, cy, cell = 96, maxCols = 4) => {
    const cols = Math.max(1, Math.min(maxCols, Math.ceil(Math.sqrt(list.length))));
    const rows = Math.ceil(list.length / cols);
    list.forEach((h, i) => {
      const c = i % cols, r = Math.floor(i / cols);
      pos[h.id] = { x: cx + (c - (cols - 1) / 2) * cell + jit(10), y: cy + (r - (rows - 1) / 2) * (cell * 0.78) + jit(8) };
    });
  };
  // Arrange nodes evenly on a ring centred on (cx,cy).
  const ringAround = (list, cx, cy, radius) => {
    const n = list.length;
    const a0 = rng.float(0, Math.PI * 2);
    list.forEach((h, i) => {
      const a = a0 + (i / Math.max(1, n)) * Math.PI * 2;
      const rr = radius * (n === 1 ? 0 : 1) + jit(6);
      pos[h.id] = { x: cx + Math.cos(a) * rr + jit(6), y: cy + Math.sin(a) * rr + jit(6) };
    });
  };

  const style = rng.pick(['hierarchy', 'columns', 'radial']);

  if (style === 'hierarchy') {
    pos.internet = { x: 500 + jit(40), y: 40 };
    gridAround(byZone.dmz, 500 + jit(60), 165, 120, 3);
    const swap = rng.bool();
    gridAround(byZone.corp, swap ? 300 : 720, 350, 96, 4);
    gridAround(byZone.servers, swap ? 760 : 280, 350, 110, 3);
    gridAround(byZone.mgmt, 500 + jit(120), 545, 110, 3);
  } else if (style === 'columns') {
    pos.internet = { x: 70, y: 350 + jit(30) };
    const mids = rng.shuffle(['corp', 'servers', 'mgmt']);
    const cols = ['dmz', ...mids];
    const xs = [230, 430, 640, 860];
    cols.forEach((z, i) => {
      const list = byZone[z]; const cx = xs[i];
      const rows = list.length; const spacing = Math.min(120, 620 / Math.max(1, rows));
      list.forEach((h, r) => { pos[h.id] = { x: cx + jit(20), y: 60 + r * spacing + jit(8) }; });
    });
  } else { // radial hub
    const cx = 520, cy = 360;
    pos.internet = { x: cx + jit(30), y: 70 };
    // Each zone becomes a cluster at a seeded angle/radius around the centre.
    const base = rng.float(0, Math.PI * 2);
    const zoneRing = { dmz: 190, corp: 300, servers: 300, mgmt: 210 };
    zonesOrder.forEach((z, i) => {
      const list = byZone[z]; if (!list.length) return;
      const ang = base + (i / zonesOrder.length) * Math.PI * 2 + jit(0.25);
      const R = zoneRing[z] + jit(30);
      const clx = cx + Math.cos(ang) * R, cly = cy + Math.sin(ang) * R;
      if (list.length <= 3) ringAround(list, clx, cly, 34);
      else ringAround(list, clx, cly, 30 + list.length * 6);
    });
  }
  pos.style = style;
  return pos;
}
