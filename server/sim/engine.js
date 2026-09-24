// engine.js — Orchestrates one game session on an accelerated, controllable
// clock. Each tick: personas generate normal activity, the attacker advances if
// ready, detection rules evaluate the new events, alerts/logs/map-updates are
// collected for streaming to the client, and Tier 2 acts on due tickets. Holds
// full ground truth server-side (never streamed live) for the after-action
// report and scoring.

import { RNG } from './rng.js';
import { generateNetwork } from './network.js';
import { generatePersonas } from './personas.js';
import { generateRoster } from './actors.js';
import { AttackEngine } from './attack.js';
import { DetectionEngine } from './detection.js';
import { Tier2 } from './tier2.js';
import { makeEvent, sanitize } from './logsource.js';
import { fmtClock, hourOf } from './time.js';
import { ALERT_KB, actorDossier } from './knowledge.js';
import { generateBackground } from './behavior.js';

// Clock calibration. At 1x the simulation runs in real time — one sim-second per
// real second (two 500ms ticks, each advancing 0.5 sim-seconds) — so a 5-minute
// critical SLA is genuinely five minutes and packets animate at a lifelike rate.
// The analyst can accelerate (2x/4x/8x) to fast-forward quiet stretches to the
// next activity; there is no pause (the feed is always live).
const REAL_TICK_MS = 500;         // wall-clock interval between ticks
const SIM_STEP_AT_1X = 0.5;       // sim-seconds advanced per tick (2 ticks/sec = real time at 1x)
const SPEEDS = [1, 2, 4, 8];      // real-time and fast-forward multipliers
const MAX_EVENTS = 60000;         // safety cap on stored events

export class GameSession {
  constructor(seed, options = {}) {
    this.seed = seed;
    this.options = options;
    this.rng = new RNG(seed);

    // --- Build the world from the seed ---
    this.network = generateNetwork(seed);
    this.personas = generatePersonas(seed, this.network);
    // Build the roster of known groups for this seed; the active attacker IS one
    // of them, so a player who reads the dossiers can attribute the intrusion.
    this.roster = generateRoster(seed);
    const activeRng = this.rng.fork('active-actor');
    if (options.actor) {
      this.actor = this.roster.find((a) => a.archetype === options.actor) || this.roster[0];
    } else if (options.allowArchetypes) {
      const pool = this.roster.filter((a) => options.allowArchetypes.includes(a.archetype));
      this.actor = activeRng.pick(pool.length ? pool : this.roster);
    } else {
      this.actor = activeRng.pick(this.roster);
    }
    this.attack = new AttackEngine(seed, this.actor, this.network, this.personas, { startHour: options.startHour ?? 8 });
    this.detection = new DetectionEngine();
    this.tier2 = new Tier2();

    // --- Clock / control ---
    this.simTime = (options.startHour ?? 8) * 3600; // begin mid-morning, office busy
    // 1x = real time; the analyst can accelerate to fast-forward to activity.
    this.speed = options.speed ?? 1;
    this.paused = false; // the feed is always live — no pause control
    this.ended = false;
    this.startedRealTs = Date.now();
    this.postImpactUntil = null;
    this.simDurationCap = options.durationHours ? options.durationHours * 3600 : 22 * 3600; // end by 22:00-ish window

    // --- Event/alert stores ---
    this._eventId = 0;
    this.events = new Map();      // id -> full event (with _truth)
    this.eventOrder = [];         // ids in order
    this.alerts = [];             // full alert objects (status mutated)
    this.alertById = new Map();
    this.firstMaliciousTs = null;
    this.containedTs = null;

    // --- Player state ---
    this.player = {
      hostTags: {},               // hostId -> 'suspected'|'confirmed'|'contained'|'clear'
      hintsUsed: [],
      points: 1000,
      tickets: [],
    };

    // --- Outbound delta buffer (drained by the server each tick) ---
    this._delta = this._freshDelta();
  }

  _freshDelta() {
    return { events: [], alerts: [], alertUpdates: [], messages: [], map: [], meta: null };
  }

  // Factory used by both behavior and attack: builds+stores an event, buffers it.
  _emit = (source, host, fields, truth) => {
    const ev = makeEvent(`ev-${++this._eventId}`, this.simTime, source, host, fields, truth);
    this.events.set(ev.id, ev);
    this.eventOrder.push(ev.id);
    if (this.eventOrder.length > MAX_EVENTS) {
      const drop = this.eventOrder.shift();
      // keep evidence events referenced by the attack timeline
      this.events.delete(drop);
    }
    if (ev._truth.origin === 'malicious' && this.firstMaliciousTs === null) {
      this.firstMaliciousTs = this.simTime;
    }
    this._delta.events.push(sanitize(ev));

    // Run detection immediately over the new event.
    const newAlerts = this.detection.ingest(ev);
    for (const a of newAlerts) this._registerAlert(a);
    return ev;
  };

  _registerAlert(a) {
    // Enrich with KB + malicious flag (server-side truth for scoring).
    a.kb = ALERT_KB[a.kbKey] ? { title: ALERT_KB[a.kbKey].title, mitre: ALERT_KB[a.kbKey].mitre } : null;
    a._malicious = (a.evidenceEventIds || []).some((id) => this.events.get(id)?._truth?.origin === 'malicious');
    this.alerts.push(a);
    this.alertById.set(a.id, a);
    this._delta.alerts.push(this._clientAlert(a));
  }

  _clientAlert(a) {
    return {
      id: a.id, ts: a.ts, ruleId: a.ruleId, severity: a.severity, title: a.title,
      summary: a.summary, entities: a.entities, status: a.status, sla: a.sla,
      slaDeadline: a.slaDeadline, kbKey: a.kbKey, kb: a.kb, count: a.count || null,
      evidenceEventIds: a.evidenceEventIds,
    };
  }

  // ---- Clock control ---- (fast-forward only; the UI has no pause)
  setSpeed(s) { if (SPEEDS.includes(s)) this.speed = s; this._delta.meta = this.metaSnapshot(); }
  // Retained for headless/testing control; the live UI never pauses.
  setPaused(p) { this.paused = !!p; this._delta.meta = this.metaSnapshot(); }

  // ---- The main tick ----
  tick() {
    if (this.ended) return this.drainDelta();
    if (this.paused) { this._checkSla(); return this.drainDelta(); }

    const dt = SIM_STEP_AT_1X * this.speed;
    this.simTime += dt;
    const tickRng = this.rng.fork(`tick:${this.simTime}`);

    // 1) Normal activity.
    generateBackground({ rng: tickRng, ts: this.simTime, dt, personas: this.personas, network: this.network, emit: this._emit });

    // 2) Attacker advances.
    const prevInfected = new Set(this.attack.infected.keys());
    this.attack.tick({ ts: this.simTime, dt, emit: this._emit });

    // 3) Tier 2 executes due actions.
    const prevStatus = this.attack.status;
    this.tier2.tick({ ts: this.simTime, attack: this.attack, getEvent: (id) => this.events.get(id) });
    if ((this.attack.status === 'stopped' || this.attack.status === 'gaveup') && this.containedTs === null) {
      this.containedTs = this.simTime;
    }

    // 4) Map updates from newly-visible impact / infection.
    this._emitMapUpdates(prevInfected);

    // 5) SLA sweep + Tier2 messages.
    this._checkSla();
    this._drainTier2Messages();

    // 6) End conditions.
    this._checkEnd();

    this._delta.meta = this.metaSnapshot();
    return this.drainDelta();
  }

  _emitMapUpdates(prevInfected) {
    // Reveal a host's status on the map only once its impact is observable
    // (fog of war: footholds stay hidden; detonation/spread/exfil/mining show).
    for (const [host, info] of this.attack.infected.entries()) {
      const status = info.effect; // dark|spread|exfil|mine
      const key = `${host}:${status}:${info.contained ? 'c' : 'a'}`;
      if (this._lastMap?.[host] === key) continue;
      (this._lastMap ||= {})[host] = key;
      this._delta.map.push({ host, status, contained: !!info.contained, sinceTs: info.sinceTs });
    }
    // Containment visibility.
    for (const host of this.attack.containedHosts) {
      const key = `${host}:contained`;
      if (this._lastMap?.[host] === key) continue;
      (this._lastMap ||= {})[host] = key;
      this._delta.map.push({ host, status: 'contained', contained: true, sinceTs: this.simTime });
    }
  }

  _checkSla() {
    for (const a of this.alerts) {
      if (a.status === 'new' && this.simTime > a.slaDeadline) {
        a.status = 'breached';
        if (a._malicious) this.player.points -= 40;
        this._delta.alertUpdates.push({ id: a.id, status: a.status });
      }
    }
  }

  _drainTier2Messages() {
    if (this._t2msgIdx === undefined) this._t2msgIdx = 0;
    const msgs = this.tier2.messages;
    while (this._t2msgIdx < msgs.length) {
      this._delta.messages.push(msgs[this._t2msgIdx++]);
    }
  }

  _checkEnd() {
    const st = this.attack.status;
    if (st === 'stopped' || st === 'gaveup') {
      this._finish(st === 'stopped' ? 'contained' : 'attacker_gave_up');
    } else if (st === 'succeeded') {
      if (this.postImpactUntil === null) this.postImpactUntil = this.simTime + 240; // show impact briefly
      else if (this.simTime >= this.postImpactUntil) this._finish('objective_completed');
    } else if (this.simTime >= this.simDurationCap) {
      this._finish('time_expired');
    }
  }

  _finish(reason) {
    if (this.ended) return;
    this.ended = true;
    this.endReason = reason;
    this._delta.meta = this.metaSnapshot();
    this._delta.report = this.afterAction();
  }

  // ---- Player actions ----
  tagHost(hostId, tag) {
    if (!this.network.hostById[hostId]) return { error: 'unknown host' };
    if (tag === 'clear') delete this.player.hostTags[hostId];
    else this.player.hostTags[hostId] = tag;
    return { ok: true, hostTags: this.player.hostTags };
  }

  buyHint(alertId) {
    const a = this.alertById.get(alertId);
    if (!a) return { error: 'unknown alert' };
    const kb = ALERT_KB[a.kbKey];
    // Point toward where to look — not the answer.
    const nudges = [];
    if (a.entities.ips?.length) nudges.push(`Pivot on source IP ${a.entities.ips[0]} across all hosts and time — does it recur?`);
    if (a.entities.hosts?.length) nudges.push(`Build a timeline on ${a.entities.hosts[0]}: what happened in the 2 minutes around ${fmtClock(a.ts)}?`);
    if (a.entities.users?.length) nudges.push(`Is "${a.entities.users[0]}" behaving normally for their role and hours? Check their persona.`);
    const kbCheck = kb ? kb.check[Math.floor(this.rng.next() * kb.check.length)] : null;
    const hint = { alertId, ts: this.simTime, lines: [kbCheck, ...nudges].filter(Boolean).slice(0, 2), cost: 25 };
    this.player.points -= hint.cost;
    this.player.hintsUsed.push(hint);
    return { ok: true, hint, points: this.player.points };
  }

  submitTicket(ticket) {
    const alert = ticket.alertId ? this.alertById.get(ticket.alertId) : null;
    if (ticket.alertId && !alert) return { error: 'unknown alert' };
    // Enrich ticket with server-side truth flags for grading.
    const enriched = {
      ...ticket,
      alertTitle: alert?.title || ticket.alertTitle || 'manual ticket',
      affectedIps: ticket.affectedIps || alert?.entities?.ips || [],
      _alertMalicious: alert ? alert._malicious : (ticket.evidenceEventIds || []).some((id) => this.events.get(id)?._truth?.origin === 'malicious'),
    };
    const result = this.tier2.submit(enriched, { ts: this.simTime, attack: this.attack, getEvent: (id) => this.events.get(id) });

    // Update alert status + running score.
    if (alert) {
      alert.status = ticket.verdict === 'false_positive' ? 'dismissed' : 'escalated';
      this._delta.alertUpdates.push({ id: alert.id, status: alert.status });
    }
    this.player.tickets.push({ ...enriched, ts: this.simTime, result: { q: result.q, kind: result.kind } });
    // Running points.
    if (result.kind === 'escalation') this.player.points += Math.round((result.q || 0) * 100);
    else if (result.kind === 'false_escalation') this.player.points -= 50;
    else if (result.kind === 'dismissal') this.player.points += result.correct ? 10 : -30;

    this._drainTier2Messages();
    this._delta.meta = this.metaSnapshot();
    return { ok: true, result: { q: result.q, kind: result.kind, followUp: result.followUp, eta: result.executeTs ? result.executeTs - this.simTime : null } };
  }

  // ---- Server-side log search (full history) ----
  search(query = {}) {
    const { q, source, host, user, ip, sinceTs, untilTs, limit = 300 } = query;
    const ql = (q || '').toLowerCase();
    const out = [];
    for (let i = this.eventOrder.length - 1; i >= 0 && out.length < limit; i--) {
      const ev = this.events.get(this.eventOrder[i]);
      if (!ev) continue;
      if (source && ev.source !== source) continue;
      if (host && ev.host !== host) continue;
      if (user && ev.user !== user) continue;
      if (ip && ev.srcIp !== ip && ev.fields.dstIp !== ip) continue;
      if (sinceTs != null && ev.ts < sinceTs) continue;
      if (untilTs != null && ev.ts > untilTs) continue;
      if (ql && !ev.message.toLowerCase().includes(ql) && !JSON.stringify(ev.fields).toLowerCase().includes(ql)) continue;
      out.push(sanitize(ev));
    }
    return out.reverse();
  }

  getEventsByIds(ids) {
    return ids.map((id) => this.events.get(id)).filter(Boolean).map(sanitize);
  }

  // Readable dossiers for every known group (the active one is not flagged —
  // the player must attribute by matching tooling, timing and calling cards).
  dossiers() {
    return this.roster.map((a) => actorDossier(a));
  }

  // ---- Snapshots ----
  metaSnapshot() {
    return {
      seed: this.seed, org: this.network.org, domain: this.network.domain,
      simTime: this.simTime, clock: fmtClock(this.simTime), hour: hourOf(this.simTime),
      speed: this.speed, paused: this.paused, ended: this.ended, endReason: this.endReason || null,
      trust: +this.tier2.trust.toFixed(2), points: this.player.points,
      pending: this.tier2.pending.map((e) => ({ title: e.ticket.alertTitle, eta: Math.max(0, e.executeTs - this.simTime) })),
      attackStatus: this.attack.status,
    };
  }

  fullSnapshot() {
    return {
      meta: this.metaSnapshot(),
      network: {
        org: this.network.org, domain: this.network.domain, zones: this.network.zones,
        hosts: this.network.hosts.map((h) => ({ id: h.id, hostname: h.hostname, ip: h.ip, zone: h.zone, type: h.type, os: h.os, crownJewel: h.crownJewel, services: h.services })),
        edges: this.network.edges.map((e) => ({ from: e.from, to: e.to })),
        rules: this.network.rules,
      },
      users: this.personas.map((p) => ({ username: p.username, name: p.name, role: p.role, dept: p.dept, primaryHost: p.primaryHost, workHours: [p.workStart, p.workEnd], usesVpn: p.habits.usesVpn, admin: p.habits.admin })),
      alerts: this.alerts.map((a) => this._clientAlert(a)),
      hostTags: this.player.hostTags,
      messages: this.tier2.messages,
      kb: ALERT_KB,
      map: this.attack ? [...this.attack.infected.entries()].map(([host, info]) => ({ host, status: info.effect, contained: !!info.contained, sinceTs: info.sinceTs })) : [],
    };
  }

  drainDelta() {
    const d = this._delta;
    this._delta = this._freshDelta();
    return d;
  }

  // ---- After-action report (the key teaching artifact) ----
  afterAction() {
    const gt = this.attack.groundTruth();
    // Which malicious steps did the player have a chance to catch, and did they?
    const escalatedEventIds = new Set();
    for (const t of this.player.tickets) {
      if (t.verdict !== 'false_positive') for (const id of t.evidenceEventIds || []) escalatedEventIds.add(id);
    }
    const alertedEventIds = new Set();
    for (const a of this.alerts) for (const id of a.evidenceEventIds || []) alertedEventIds.add(id);

    const timeline = gt.timeline.filter((s) => !s.meta).map((s) => {
      const detectedByRule = (s.evidence || []).some((id) => alertedEventIds.has(id));
      const escalated = (s.evidence || []).some((id) => escalatedEventIds.has(id));
      const sampleEv = (s.evidence || []).map((id) => this.events.get(id)).find(Boolean);
      return {
        ts: s.ts, clock: fmtClock(s.ts ?? 0), stage: s.stage, mitre: s.mitre, technique: s.technique,
        host: s.host, note: s.note,
        detectedByRule, escalated,
        revealingLogLine: sampleEv ? sampleEv.message : null,
        evidenceCount: (s.evidence || []).length,
      };
    });

    // Earliest stage the player could have stopped it (first detected step).
    const firstDetected = timeline.find((s) => s.detectedByRule);
    const firstEscalated = timeline.find((s) => s.escalated);

    // Damage accounting.
    const infected = gt.infected;
    const crownJewelsHit = infected.filter((i) => this.network.hostById[i.host]?.crownJewel).length;
    // Business disruption: impacted asset value as a share of the whole estate,
    // weighted so downing the DC/DB/file server hurts far more than a workstation.
    const totalValue = this.network.hosts.reduce((s, h) => s + (h.value || 1), 0);
    const impactedValue = infected.reduce((s, i) => s + (this.network.hostById[i.host]?.value || 1), 0);
    const businessDisruptionPct = Math.min(100, Math.round((impactedValue / Math.max(1, totalValue)) * 100));
    const disruptionLabel = businessDisruptionPct === 0 ? 'None' : businessDisruptionPct < 15 ? 'Limited' : businessDisruptionPct < 40 ? 'Serious' : 'Severe';
    const dwell = this.firstMaliciousTs != null
      ? (this.containedTs != null ? this.containedTs : this.simTime) - this.firstMaliciousTs
      : 0;

    // Scoring.
    const falseEsc = this.tier2.falseEscalations;
    const goodEsc = this.tier2.goodEscalations;
    const breachedMal = this.alerts.filter((a) => a.status === 'breached' && a._malicious).length;
    const avgQ = this.player.tickets.filter((t) => t.result?.q != null).reduce((s, t, _, arr) => s + t.result.q / arr.length, 0) || 0;

    const outcomeScore = this._scoreOutcome(gt, { crownJewelsHit, dwell, falseEsc, breachedMal, avgQ, goodEsc, businessDisruptionPct });

    return {
      seed: this.seed,
      org: this.network.org,
      endReason: this.endReason,
      attacker: {
        name: gt.actor.name, archetype: gt.actor.archetypeLabel, objective: gt.actor.objective,
        family: gt.actor.family?.name, familyType: gt.actor.family?.label, callingCard: gt.actor.callingCard?.text || null,
        infra: gt.actor.infra, activeHours: gt.actor.activeHours, traits: gt.actor.traits,
      },
      outcome: {
        status: gt.status,
        reason: gt.outcome?.reason || this.endReason,
        stagesReached: gt.stagesReached,
        infectedHosts: infected.map((i) => ({ host: i.host, effect: i.effect, contained: !!i.contained })),
        crownJewelsHit,
        dwellSeconds: dwell,
        couldHaveStoppedAt: firstDetected ? { stage: firstDetected.stage, clock: firstDetected.clock, technique: firstDetected.technique } : null,
        firstEscalatedStage: firstEscalated ? firstEscalated.stage : null,
      },
      timeline,
      playerActions: this.player.tickets.map((t) => ({ ts: t.ts, clock: fmtClock(t.ts), alertTitle: t.alertTitle, verdict: t.verdict, action: t.recommendedAction, q: t.result?.q, kind: t.result?.kind })),
      metrics: {
        dwellSeconds: dwell, crownJewelsHit, infectedCount: infected.length,
        businessDisruptionPct, disruptionLabel,
        falseEscalations: falseEsc, goodEscalations: goodEsc, breachedMaliciousAlerts: breachedMal,
        avgTicketQuality: +avgQ.toFixed(2), hintsUsed: this.player.hintsUsed.length, trust: +this.tier2.trust.toFixed(2),
        detectionCoverage: this._detectionCoverage(timeline),
      },
      score: outcomeScore,
    };
  }

  _detectionCoverage(timeline) {
    const total = timeline.length || 1;
    const detected = timeline.filter((s) => s.detectedByRule).length;
    const escalated = timeline.filter((s) => s.escalated).length;
    return { steps: total, detectedByRule: detected, escalated, detectedPct: Math.round((detected / total) * 100), escalatedPct: Math.round((escalated / total) * 100) };
  }

  _scoreOutcome(gt, m) {
    // Grade A–F from outcome + hygiene.
    let pts = 1000;
    if (gt.status === 'stopped') pts += 400;
    else if (gt.status === 'gaveup') pts += 200;
    else if (gt.status === 'succeeded') pts -= 300;
    else if (gt.status === 'spreading') pts -= 200;
    else if ((gt.status === 'active' || gt.status === 'dormant') && m.crownJewelsHit === 0) pts += 120; // held the line to time-out
    pts -= m.crownJewelsHit * 150;
    pts -= Math.round((m.businessDisruptionPct || 0) * 2);
    pts -= m.breachedMal * 40;
    pts -= m.falseEsc * 50;
    pts -= this.player.hintsUsed.length * 25;
    pts += Math.round(m.avgQ * 200);
    pts -= Math.min(300, Math.round(m.dwell / 60) * 5);
    pts = Math.max(0, pts);
    const grade = pts >= 1400 ? 'A' : pts >= 1150 ? 'B' : pts >= 900 ? 'C' : pts >= 650 ? 'D' : 'F';
    let verdict;
    if (gt.status === 'stopped' && m.crownJewelsHit === 0) verdict = gt.stagesReached.length <= 2 ? 'Excellent — caught during initial access, nothing was compromised.' : 'Good — attacker was stopped mid-chain with limited damage.';
    else if (gt.status === 'gaveup') verdict = 'The attacker gave up after being disrupted — solid pressure.';
    else if (gt.status === 'succeeded' || gt.status === 'spreading') verdict = 'Missed — the attacker achieved its objective. Study the timeline below.';
    else if (m.crownJewelsHit === 0 && (gt.status === 'active' || gt.status === 'dormant')) verdict = 'Held the line — you disrupted the intrusion enough that it never reached its objective before the day ended, though it was never fully eradicated.';
    else verdict = 'Time expired with the intrusion unresolved.';
    return { points: pts, grade, verdict };
  }
}

export { REAL_TICK_MS, SPEEDS };
