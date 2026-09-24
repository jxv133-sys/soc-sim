// actors.js — Threat actor profiles.
//
// An actor is a profile of *traits*, not flavour text. The attack engine reads
// these numbers to decide what actually happens in the logs: how fast stages
// complete, how much noise is generated, whether the actor only works during its
// own hours, how deep its persistence goes, and whether it adapts when a path is
// cut off. Each actor also has consistent habits (tooling, file-naming, reused
// infrastructure, timezone) — the calling cards a player learns to recognise, so
// attribution becomes a real skill.
//
// Not every known group is in play in a given game. A roster of groups is
// generated per seed; one (or more, later) is chosen as the active attacker.
// Some leave obvious calling cards; others must be deduced by matching TTPs to
// the knowledge-base dossiers.

import { RNG } from './rng.js';
import { generateFamily } from './malware.js';

// Archetype templates. Trait scales are 0..1 unless noted. `initialAccess` and
// `lateralStyle` constrain how the attack engine may move.
export const ARCHETYPES = {
  script_kiddie: {
    label: 'Script Kiddie',
    traits: { skill: [0.1, 0.35], noise: [0.7, 1.0], speed: [0.7, 1.0], patience: [0.05, 0.25], adaptability: [0.05, 0.25], persistenceDepth: [1, 1], stealth: [0.05, 0.25] },
    objectives: ['ransom', 'cryptomine'],
    initialAccess: ['brute_force', 'public_exploit'],
    lateralStyle: 'noisy_exploit',
    malware: ['ransomware', 'cryptominer'],
    reuseInfra: true,
    respectsActiveHours: false,
    givesUpEasily: true,
    leavesCallingCard: 0.5,
    tooling: 'off-the-shelf public tools (Hydra, Metasploit, leaked RaaS builder)',
  },
  crime_crew: {
    label: 'Criminal Organization',
    traits: { skill: [0.6, 0.85], noise: [0.15, 0.4], speed: [0.25, 0.5], patience: [0.6, 0.9], adaptability: [0.6, 0.9], persistenceDepth: [2, 3], stealth: [0.6, 0.85] },
    objectives: ['ransom', 'worm'],
    initialAccess: ['phishing', 'valid_accounts', 'public_exploit'],
    lateralStyle: 'lolbins',
    malware: ['ransomware', 'worm'],
    reuseInfra: false,
    respectsActiveHours: true,
    givesUpEasily: false,
    leavesCallingCard: 0.3,
    tooling: 'living off the land (PsExec, WMI, PowerShell), Cobalt-Strike-like beacons',
  },
  apt: {
    label: 'State-Sponsored (APT)',
    traits: { skill: [0.85, 1.0], noise: [0.02, 0.15], speed: [0.1, 0.3], patience: [0.85, 1.0], adaptability: [0.75, 0.95], persistenceDepth: [3, 4], stealth: [0.85, 1.0] },
    objectives: ['espionage'],
    initialAccess: ['phishing', 'valid_accounts'],
    lateralStyle: 'lolbins',
    malware: ['spyware', 'rat'],
    reuseInfra: false,
    respectsActiveHours: true,
    givesUpEasily: false,
    leavesCallingCard: 0.1,
    tooling: 'custom implants, signed binaries, WMI/scheduled-task persistence, minimal footprint',
  },
  hacktivist: {
    label: 'Hacktivist',
    traits: { skill: [0.35, 0.6], noise: [0.6, 0.9], speed: [0.6, 0.9], patience: [0.1, 0.35], adaptability: [0.2, 0.45], persistenceDepth: [1, 2], stealth: [0.2, 0.45] },
    objectives: ['disruption', 'leak'],
    initialAccess: ['public_exploit', 'brute_force'],
    lateralStyle: 'noisy_exploit',
    malware: ['wiper', 'spyware'],
    reuseInfra: true,
    respectsActiveHours: false,
    givesUpEasily: false,
    leavesCallingCard: 0.85, // hacktivists want credit
    tooling: 'public web exploits, SQLi/LFI tools, defacement kits',
  },
  insider: {
    label: 'Malicious Insider',
    traits: { skill: [0.2, 0.5], noise: [0.1, 0.3], speed: [0.3, 0.55], patience: [0.4, 0.7], adaptability: [0.15, 0.4], persistenceDepth: [1, 1], stealth: [0.5, 0.8] },
    objectives: ['data_theft', 'sabotage'],
    initialAccess: ['valid_accounts'], // already inside — no external breach
    lateralStyle: 'valid_accounts',
    malware: ['spyware', 'wiper'],
    reuseInfra: true,
    respectsActiveHours: false, // works whenever they're on shift
    givesUpEasily: false,
    leavesCallingCard: 0.05,
    tooling: 'legitimate access, USB/cloud exfil, no exploitation needed',
  },
};

// ---- Procedural naming per archetype ----
const APT_ADJ = ['Silk', 'Amber', 'Granite', 'Velvet', 'Charcoal', 'Nimbus', 'Cobalt', 'Umber'];
const APT_ANIMAL = ['Tempest', 'Panda', 'Bear', 'Kitten', 'Typhoon', 'Buffalo', 'Falcon', 'Serpent'];
const CREW_STEM = ['Wizard', 'Scattered', 'Indrik', 'Riddle', 'Grim', 'Cinder', 'Lunar', 'Hollow'];
const CREW_TAIL = ['Spider', 'Syndicate', 'Group', 'Collective', 'Cartel'];
const KIDDIE_HANDLE = ['xN1ght', 'z3r0Cool', 'pwnster', 'sk1dL0rd', 'gh0stByte', 'n00bslayer', 'r00tr', 'l33tw0lf'];
const HACK_STEM = ['Free', 'Red', 'Open', 'Ghost', 'Iron', 'People\'s'];
const HACK_TAIL = ['Front', 'Sec', 'Legion', 'Faction', 'Brigade'];
const INSIDER_TAG = ['disgruntled staff', 'departing employee', 'contractor', 'privileged user'];

function nameFor(rng, archetype) {
  switch (archetype) {
    case 'apt':
      return `${rng.pick(APT_ADJ)} ${rng.pick(APT_ANIMAL)}`;
    case 'crime_crew':
      return `${rng.pick(CREW_STEM)} ${rng.pick(CREW_TAIL)}`;
    case 'script_kiddie':
      return rng.pick(KIDDIE_HANDLE) + rng.int(10, 99);
    case 'hacktivist':
      return `${rng.pick(HACK_STEM)}${rng.pick(HACK_TAIL)}`;
    case 'insider':
      return `Insider (${rng.pick(INSIDER_TAG)})`;
    default:
      return 'Unknown';
  }
}

// Attacker infrastructure IPs. Reused infra returns a small fixed pool; rotating
// infra returns a larger pool the engine can switch through when it adapts.
function infraIps(rng, reuse) {
  const geo = rng.pick([
    { cc: 'RU', block: () => `185.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}` },
    { cc: 'CN', block: () => `223.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}` },
    { cc: 'NL', block: () => `45.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}` },
    { cc: 'BR', block: () => `177.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}` },
    { cc: 'US', block: () => `104.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}` },
    { cc: 'IR', block: () => `2.${rng.int(2, 254)}.${rng.int(2, 254)}.${rng.int(2, 254)}` },
  ]);
  const n = reuse ? rng.int(1, 2) : rng.int(3, 5);
  const ips = [];
  for (let i = 0; i < n; i++) ips.push(geo.block());
  return { cc: geo.cc, ips };
}

function scaleTrait(rng, range) {
  return +rng.float(range[0], range[1]).toFixed(3);
}

// Build one concrete actor from an archetype.
export function generateActor(seed, archetypeKey, idx = 0) {
  const rng = new RNG(seed).fork(`actor:${archetypeKey}:${idx}`);
  const arch = ARCHETYPES[archetypeKey];
  const traits = {};
  for (const [k, range] of Object.entries(arch.traits)) {
    traits[k] = k === 'persistenceDepth' ? rng.int(range[0], range[1]) : scaleTrait(rng, range);
  }
  const infra = infraIps(rng, arch.reuseInfra);
  const objective = rng.pick(arch.objectives);
  // Active hours are expressed directly in the target's (log) timezone — the
  // hours the player observes activity cluster in. The window opens in the
  // morning (so it overlaps the analyst's shift and the queue is never dead)
  // and its exact edges vary per actor, which is a real attribution signal:
  // an experienced player learns "this group goes quiet after ~16:00".
  const workStart = arch.respectsActiveHours ? rng.int(6, 8) : 0;
  const workEnd = arch.respectsActiveHours ? Math.min(23, workStart + rng.int(9, 11)) : 24;
  const tzShift = arch.respectsActiveHours ? 9 - workStart : 0; // nominal offset from a 09:00 norm, for dossier flavour

  // Mint malware families this actor prefers.
  const families = arch.malware.map((cat) => generateFamily(rng, cat));
  const primaryFamily = families.find((f) => {
    if (objective === 'ransom') return f.category === 'ransomware';
    if (objective === 'worm') return f.category === 'worm';
    if (objective === 'espionage' || objective === 'data_theft') return f.category === 'spyware' || f.category === 'rat';
    if (objective === 'cryptomine') return f.category === 'cryptominer';
    if (objective === 'disruption' || objective === 'sabotage') return f.category === 'wiper';
    return true;
  }) || families[0];

  return {
    id: `${archetypeKey}-${rng.id()}`,
    archetype: archetypeKey,
    archetypeLabel: arch.label,
    name: nameFor(rng, archetypeKey),
    traits,
    objective,
    initialAccess: arch.initialAccess.slice(),
    lateralStyle: arch.lateralStyle,
    tooling: arch.tooling,
    respectsActiveHours: arch.respectsActiveHours,
    givesUpEasily: arch.givesUpEasily,
    activeHours: { start: workStart, end: workEnd, tzShift },
    infra,
    families,
    primaryFamily,
    // Calling card: sometimes present, sometimes not (drives attribution).
    leavesCallingCard: rng.bool(arch.leavesCallingCard),
    callingCard: rng.bool(arch.leavesCallingCard)
      ? {
          text: rng.pick([
            `signed: ${nameFor(rng, archetypeKey)}`,
            `mutex ${primaryFamily.name}-${rng.int(1000, 9999)}`,
            `dropped ${primaryFamily.noteName || primaryFamily.dropFile}`,
          ]),
        }
      : null,
    fileNaming: primaryFamily.filePattern,
  };
}

// Generate the full roster of known groups for a seed (one per archetype). The
// KB shows all of these; only a subset is actually active in a game.
export function generateRoster(seed) {
  return Object.keys(ARCHETYPES).map((k, i) => generateActor(seed, k, i));
}

// Choose the active attacker(s) for a game given difficulty. Level tuning lives
// in the campaign; this just supports "which archetypes are eligible".
export function pickActiveActor(seed, { allow = null } = {}) {
  const rng = new RNG(seed).fork('active-actor');
  const keys = Object.keys(ARCHETYPES).filter((k) => (allow ? allow.includes(k) : true));
  const key = rng.pick(keys);
  const idx = rng.int(0, 99);
  return generateActor(seed, key, idx);
}
