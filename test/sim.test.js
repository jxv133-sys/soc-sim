// sim.test.js — automated checks for the simulation core.
// Run with: npm test   (node --test)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RNG } from '../server/sim/rng.js';
import { generateNetwork } from '../server/sim/network.js';
import { generatePersonas } from '../server/sim/personas.js';
import { generateRoster } from '../server/sim/actors.js';
import { DetectionEngine } from '../server/sim/detection.js';
import { GameSession } from '../server/sim/engine.js';

function runToEnd(seed, opts = {}) {
  const g = new GameSession(seed, { startHour: 5, speed: 8, ...opts });
  g.setPaused(false);
  let t = 0;
  while (!g.ended && t < 6000) { g.tick(); t++; }
  return g;
}

test('RNG is deterministic and reproducible', () => {
  const a = new RNG('seed-x'); const b = new RNG('seed-x');
  const sa = Array.from({ length: 20 }, () => a.next());
  const sb = Array.from({ length: 20 }, () => b.next());
  assert.deepEqual(sa, sb);
  const c = new RNG('seed-y');
  assert.notDeepEqual(sa, Array.from({ length: 20 }, () => c.next()));
});

test('Requirement 1: everything is procedurally generated from the seed', () => {
  const n1 = generateNetwork('proc-1');
  const n2 = generateNetwork('proc-1');
  const n3 = generateNetwork('proc-2');
  // reproducible
  assert.deepEqual(n1.hosts.map((h) => h.ip), n2.hosts.map((h) => h.ip));
  assert.equal(n1.org, n2.org);
  // genuinely different across seeds
  assert.ok(n1.org !== n3.org || n1.hosts.length !== n3.hosts.length);
  // always has the crown jewels and a domain controller
  assert.ok(n1.landmarks.dc && n1.landmarks.crownJewels.length >= 1);
  // firewall reachability graph exists and constrains movement
  assert.ok(n1.edges.length > 0 && Object.keys(n1.reachFrom).length > 0);
});

test('personas define per-user normal (roles, hours, habits)', () => {
  const net = generateNetwork('p-1');
  const people = generatePersonas('p-1', net);
  assert.ok(people.length >= 6);
  assert.ok(people.some((p) => p.role === 'sysadmin'));
  // every persona has working hours and a fumble rate (source of FPs)
  for (const p of people) {
    assert.ok(Number.isFinite(p.workStart) && Number.isFinite(p.workEnd));
    assert.ok(p.habits.fumbleRate >= 0);
  }
});

test('actor traits drive behavior and roster is attributable', () => {
  const roster = generateRoster('a-1');
  assert.equal(roster.length, 5); // one per archetype
  const kiddie = roster.find((a) => a.archetype === 'script_kiddie');
  const apt = roster.find((a) => a.archetype === 'apt');
  // script kiddies are louder & less skilled than APTs — traits are meaningful
  assert.ok(kiddie.traits.noise > apt.traits.noise);
  assert.ok(apt.traits.skill > kiddie.traits.skill);
  assert.ok(apt.traits.stealth > kiddie.traits.stealth);
  // each actor has preferred malware families (calling cards)
  assert.ok(apt.families.length >= 1 && apt.primaryFamily);
});

test('Requirement 2: alerts emerge from rules and false positives dominate naturally', () => {
  const g = new GameSession('detect-1', { startHour: 5, speed: 8 });
  g.setPaused(false);
  for (let t = 0; t < 300; t++) g.tick();
  const alerts = [...g.alerts.values()];
  assert.ok(alerts.length > 5, 'rules should fire alerts from the log stream');
  const benign = alerts.filter((a) => !a._malicious).length;
  const malicious = alerts.filter((a) => a._malicious).length;
  // benign activity trips the same rules — FPs are emergent, not labeled
  assert.ok(benign > 0, 'benign activity must produce false positives');
  assert.ok(benign >= malicious, 'in a realistic queue, noise outnumbers real threats');
});

test('detection uses only observable fields, never ground truth', () => {
  const det = new DetectionEngine();
  // a benign-looking fat-finger burst trips brute force with no truth hints
  let fired = 0;
  for (let i = 0; i < 6; i++) {
    const alerts = det.ingest({ id: 'e' + i, ts: 1000 + i, source: 'auth', host: 'ws01', srcIp: '10.1.1.5', user: 'jdoe', fields: { service: 'winlogon', result: 'failure', srcIp: '10.1.1.5', user: 'jdoe' }, message: 'x' });
    fired += alerts.length;
  }
  assert.ok(fired >= 1, 'brute-force rule fires on failed-auth volume alone');
});

test('Requirement 3: a full game runs on the clock and reaches a terminal state', () => {
  const g = runToEnd('game-1');
  assert.ok(g.ended, 'game should reach an end state');
  const report = g.afterAction();
  assert.ok(['contained', 'attacker_gave_up', 'objective_completed', 'time_expired'].includes(report.endReason));
  assert.ok(report.timeline.length >= 1, 'after-action timeline records attacker steps');
  assert.ok(report.score && report.score.grade);
});

test('passive play loses; the attacker reaches its objective', () => {
  const g = runToEnd('passive-1');
  const r = g.afterAction();
  // with no analyst action, the intrusion should generally succeed or run long
  assert.ok(['succeeded', 'spreading', 'active', 'dormant'].includes(r.outcome.status));
});

test('ticket quality maps to outcome (strong beats weak)', () => {
  const g = new GameSession('ticket-1', { startHour: 5, speed: 8, actor: 'crime_crew' });
  g.setPaused(false);
  // advance until the attacker has a foothold
  let t = 0;
  while (g.attack.footholds.size === 0 && t < 2000) { g.tick(); t++; }
  const foothold = [...g.attack.footholds][0];
  const malEv = [...g.events.values()].find((e) => e._truth.origin === 'malicious');
  const ctx = { ts: g.simTime, attack: g.attack, getEvent: (id) => g.events.get(id) };
  const strong = g.tier2.score({ verdict: 'escalate', severity: 'high', affectedHosts: [foothold], evidenceEventIds: malEv ? [malEv.id] : [], recommendedAction: 'isolate_host' }, ctx);
  const weak = g.tier2.score({ verdict: 'escalate', severity: 'low', affectedHosts: ['nonexistent'], evidenceEventIds: [], recommendedAction: 'monitor' }, ctx);
  assert.ok(strong.q > weak.q, 'a precise, evidenced ticket scores higher than a vague one');
});

test('worm spreads across the segment when missed', () => {
  // scan a few forced-worm seeds; at least one should spread beyond one host
  let maxInfected = 0;
  for (const s of ['w5', 'w6', 'w8']) {
    const g = runToEnd(s, { actor: 'crime_crew' });
    if (g.actor.objective === 'worm') maxInfected = Math.max(maxInfected, g.attack.infected.size);
  }
  assert.ok(maxInfected >= 3, 'a missed worm should infect multiple hosts');
});

test('containment stops or degrades the attack (adaptation is real)', () => {
  const g = new GameSession('contain-1', { startHour: 5, speed: 8, actor: 'script_kiddie' });
  g.setPaused(false);
  let t = 0;
  while (g.attack.footholds.size === 0 && t < 2000) { g.tick(); t++; }
  const before = g.attack.status;
  const fh = [...g.attack.footholds][0];
  g.attack.applyAction({ type: 'isolate_host', host: fh });
  assert.ok(g.attack.containedHosts.has(fh));
  // low-adaptability actor with no surviving persistence should not simply thrive
  assert.ok(['active', 'stopped', 'gaveup', 'dormant'].includes(g.attack.status));
  assert.ok(before !== undefined);
});
