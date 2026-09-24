// personas.js — Procedural users with consistent behavior patterns.
//
// "Normal" is defined per-user, not globally. An admin who SSHes into servers at
// 02:00 is normal *for that admin*; the same event from an accountant is not.
// These persona traits are what the behavior generator reads to produce
// background noise — and that noise is what makes false positives believable,
// because a real user fumbling a password trips the very same brute-force rule
// an attacker would.

import { RNG } from './rng.js';

const FIRST = [
  'Aisha', 'Marco', 'Priya', 'Devon', 'Lena', 'Omar', 'Chen', 'Sofia', 'Raj',
  'Nadia', 'Tobias', 'Grace', 'Hiro', 'Elena', 'Kwame', 'Ivy', 'Sami', 'Rosa',
  'Yusuf', 'Maya', 'Diego', 'Anna', 'Leon', 'Farah', 'Noah', 'Zoe', 'Kofi', 'Mei',
];
const LAST = [
  'Okafor', 'Rossi', 'Patel', 'Brooks', 'Novak', 'Haddad', 'Wu', 'Reyes',
  'Sharma', 'Kaur', 'Berg', 'Lindqvist', 'Tanaka', 'Costa', 'Mensah', 'Cole',
  'Nasser', 'Diaz', 'Ahmed', 'Nguyen', 'Silva', 'Meyer', 'Park', 'Farrell',
];

// Role blueprints: how each role tends to behave.
const ROLES = {
  sysadmin: {
    dept: 'IT', count: [1, 2], webHeavy: false, sshServers: true,
    fumble: 0.05, adminly: true, oddHours: true, accessDb: false, bigFiles: false,
    workHours: [7, 19], vpnChance: 0.6,
  },
  developer: {
    dept: 'Engineering', count: [2, 4], webHeavy: true, sshServers: true,
    fumble: 0.06, adminly: false, oddHours: true, accessDb: true, bigFiles: true,
    workHours: [10, 22], vpnChance: 0.7,
  },
  accountant: {
    dept: 'Finance', count: [1, 3], webHeavy: false, sshServers: false,
    fumble: 0.10, adminly: false, oddHours: false, accessDb: true, bigFiles: false,
    workHours: [8, 17], vpnChance: 0.2,
  },
  hr: {
    dept: 'People', count: [1, 2], webHeavy: true, sshServers: false,
    fumble: 0.09, adminly: false, oddHours: false, accessDb: false, bigFiles: false,
    workHours: [9, 17], vpnChance: 0.2,
  },
  sales: {
    dept: 'Sales', count: [1, 3], webHeavy: true, sshServers: false,
    fumble: 0.08, adminly: false, oddHours: false, accessDb: false, bigFiles: false,
    workHours: [8, 18], vpnChance: 0.7, // travels
  },
  support: {
    dept: 'Support', count: [1, 2], webHeavy: true, sshServers: false,
    fumble: 0.07, adminly: false, oddHours: true, accessDb: true, bigFiles: false,
    workHours: [7, 23], vpnChance: 0.3, // shift work
  },
  executive: {
    dept: 'Leadership', count: [1, 1], webHeavy: true, sshServers: false,
    fumble: 0.12, adminly: false, oddHours: true, accessDb: false, bigFiles: false,
    workHours: [7, 20], vpnChance: 0.8, // travels a lot
  },
  marketing: {
    dept: 'Marketing', count: [1, 2], webHeavy: true, sshServers: false,
    fumble: 0.08, adminly: false, oddHours: false, accessDb: false, bigFiles: true,
    workHours: [9, 18], vpnChance: 0.3,
  },
};

// A pool of "home" / remote egress IPs for VPN and travelling users. These
// recur per-user so an experienced analyst can learn a user's normal source.
function homeIp(rng) {
  const blocks = [
    () => `73.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}`, // residential
    () => `98.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}`,
    () => `24.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}`,
    () => `188.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}`, // travel/EU
  ];
  return rng.pick(blocks)();
}

export function generatePersonas(seed, network) {
  const rng = new RNG(seed).fork('personas');
  const personas = [];
  const usedNames = new Set();

  function name() {
    for (let i = 0; i < 50; i++) {
      const f = rng.pick(FIRST);
      const l = rng.pick(LAST);
      const full = `${f} ${l}`;
      if (!usedNames.has(full)) {
        usedNames.add(full);
        return { f, l, full };
      }
    }
    return { f: rng.pick(FIRST), l: rng.pick(LAST) + rng.int(1, 9), full: 'anon' };
  }

  const workstations = network.hosts.filter((h) => h.type === 'workstation');
  const wsPool = rng.shuffle(workstations.slice());
  let wsIdx = 0;

  // Decide role counts, but never exceed available workstations for those who
  // need one. Admins can live on the jump host instead of a dedicated WS.
  const roleOrder = ['sysadmin', 'developer', 'accountant', 'hr', 'sales', 'support', 'executive', 'marketing'];
  for (const role of roleOrder) {
    const spec = ROLES[role];
    const n = rng.int(spec.count[0], spec.count[1]);
    for (let i = 0; i < n; i++) {
      const nm = name();
      const username = `${nm.f[0].toLowerCase()}${nm.l.toLowerCase().replace(/[^a-z]/g, '')}`;
      // Assign a primary workstation (admins may share the jump host).
      let primaryHost = null;
      if (wsIdx < wsPool.length) {
        primaryHost = wsPool[wsIdx++].id;
      } else {
        primaryHost = network.landmarks.jump || (wsPool.length ? wsPool[wsIdx % wsPool.length].id : null);
      }

      const usesVpn = rng.bool(spec.vpnChance);
      const p = {
        id: username,
        username,
        name: nm.full,
        role,
        dept: spec.dept,
        primaryHost,
        workStart: spec.workHours[0],
        workEnd: spec.workHours[1],
        timezoneShift: rng.bool(0.15) ? rng.int(-3, 3) : 0, // a few remote/off-tz people
        habits: {
          webHeavy: spec.webHeavy,
          sshServers: spec.sshServers,
          fumbleRate: +(spec.fumble * rng.float(0.7, 1.4)).toFixed(3),
          admin: spec.adminly,
          oddHours: spec.oddHours && rng.bool(0.7),
          accessDb: spec.accessDb,
          bigFiles: spec.bigFiles && rng.bool(0.6),
          usesVpn,
          commitsAtNight: role === 'developer' && rng.bool(0.5),
          travels: (role === 'sales' || role === 'executive') && rng.bool(0.7),
        },
        homeIp: usesVpn || spec.workHours[1] > 20 ? homeIp(rng) : null,
        // Servers this user legitimately administers or accesses.
        managedHosts: [],
        credWeight: spec.adminly ? 8 : role === 'developer' ? 5 : 2, // value if creds stolen
      };

      // Wire admins/devs to specific servers they touch.
      const servers = network.hosts.filter((h) => h.zone === 'servers');
      if (spec.adminly) {
        p.managedHosts = servers.map((h) => h.id); // admins touch everything
        if (network.landmarks.jump) p.managedHosts.push(network.landmarks.jump);
      } else if (spec.sshServers) {
        // developers touch app/db servers
        p.managedHosts = servers
          .filter((h) => h.type === 'app-server' || h.type === 'db-server')
          .map((h) => h.id);
      }

      personas.push(p);
      // Register the user on their primary host.
      const host = network.hostById[primaryHost];
      if (host && !host.users.includes(username)) host.users.push(username);
    }
  }

  // Make sure at least one sysadmin exists.
  if (!personas.some((p) => p.role === 'sysadmin')) {
    personas[0].role = 'sysadmin';
    personas[0].habits.admin = true;
    personas[0].habits.sshServers = true;
    personas[0].managedHosts = network.hosts.filter((h) => h.zone === 'servers').map((h) => h.id);
  }

  return personas;
}
