// tier2.js — The simulated Tier 2 analyst who acts on escalated tickets.
//
// Ticket quality maps directly to outcome. A strong ticket (right host, solid
// evidence, correct recommended action) makes Tier 2 act fast, so the attack is
// stopped at an earlier stage. A vague ticket makes Tier 2 investigate slowly or
// ask a follow-up, burning time. A wrong recommendation (reset a password when a
// backdoor exists) fires but doesn't fully work — the attacker falls back.
// Over-escalating noise erodes Tier 2's trust, and low trust slows every future
// ticket (alert fatigue, modeled from the receiving end).

// Base time (sim-seconds) Tier 2 takes to act on a *perfect* ticket, by severity.
const BASE_DELAY = { critical: 90, high: 150, medium: 240, low: 360 };

// Which stage implies which "true" severity, used to grade the player's call.
const STAGE_SEVERITY = {
  initial_access: 'medium', persistence: 'medium', discovery: 'medium',
  credential_access: 'high', lateral_movement: 'high', objective: 'critical',
};
const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

export class Tier2 {
  constructor() {
    this.trust = 1.0;
    this.pending = []; // [{ticket, executeTs, q, actions, followUp}]
    this.history = []; // resolved tickets with grades
    this.messages = []; // feedback lines shown to the player
    this.falseEscalations = 0;
    this.goodEscalations = 0;
    this._msgId = 0;
  }

  _msg(ts, kind, text) {
    const m = { id: `t2-${++this._msgId}`, ts, kind, text };
    this.messages.push(m);
    return m;
  }

  // Compute the set of hosts genuinely involved in the intrusion right now.
  _compromised(attack) {
    const s = new Set([...attack.footholds]);
    for (const p of attack.persistence) s.add(p.host);
    for (const h of attack.infected.keys()) s.add(h);
    return s;
  }

  // Score a ticket 0..1 against ground truth. Also returns component detail for
  // the after-action report and immediate feedback.
  score(ticket, ctx) {
    const attack = ctx.attack;
    const compromised = this._compromised(attack);
    const stolen = new Set(attack.creds);
    const infra = new Set(attack.actor.infra.ips);

    // Host accuracy.
    const th = ticket.affectedHosts || [];
    const hitHosts = th.filter((h) => compromised.has(h)).length;
    const hostScore = th.length ? hitHosts / th.length : 0;
    const coversPrimary = th.some((h) => compromised.has(h));

    // Evidence quality: fraction of attached evidence that is genuinely malicious.
    const ev = ticket.evidenceEventIds || [];
    const malEv = ev.filter((id) => {
      const e = ctx.getEvent(id);
      return e && e._truth && e._truth.origin === 'malicious';
    }).length;
    const evidenceScore = ev.length ? malEv / ev.length : 0;
    const hasEvidence = malEv >= 1;

    // Account accuracy (matters for credential actions).
    const ta = ticket.affectedAccounts || [];
    const hitAcct = ta.filter((u) => stolen.has(u)).length;
    const acctScore = ta.length ? hitAcct / ta.length : (stolen.size ? 0 : 1);

    // Severity accuracy vs. the current stage.
    const trueSev = STAGE_SEVERITY[attack.currentStage] || (attack.status === 'succeeded' ? 'critical' : 'medium');
    const sevDelta = Math.abs((SEV_RANK[ticket.severity] ?? 1) - SEV_RANK[trueSev]);
    const sevScore = 1 - sevDelta / 3;

    // Action appropriateness.
    const action = ticket.recommendedAction;
    const needsCredReset = stolen.size > 0;
    const hasPersistence = attack.persistence.length > 0;
    const external = infra.size > 0;
    let actionScore = 0.5;
    const actionTargetsCompromised = ticket.affectedHosts?.some((h) => compromised.has(h));
    switch (action) {
      case 'isolate_host':
      case 'contain_host':
        actionScore = actionTargetsCompromised ? 0.9 : 0.2;
        break;
      case 'full_remediation':
        actionScore = hasEvidence && coversPrimary ? 1.0 : 0.4;
        break;
      case 'reset_credentials':
      case 'disable_account':
        actionScore = needsCredReset ? 0.75 : 0.3;
        break;
      case 'block_ip':
        actionScore = external ? 0.65 : 0.3;
        break;
      case 'remediate_vector':
      case 'patch':
        actionScore = attack.currentStage === 'initial_access' ? 0.8 : 0.5;
        break;
      case 'monitor':
        actionScore = 0.2;
        break;
      default:
        actionScore = 0.3;
    }

    const q = +(
      hostScore * 0.3 +
      evidenceScore * 0.25 +
      actionScore * 0.25 +
      sevScore * 0.1 +
      acctScore * 0.1
    ).toFixed(3);

    return { q, hostScore, evidenceScore, actionScore, sevScore, acctScore, coversPrimary, hasEvidence, trueSev, actionTargetsCompromised, hasPersistence };
  }

  // Player submits a ticket. Returns immediate feedback; the action (if any) is
  // scheduled and executed later in tick().
  submit(ticket, ctx) {
    const ts = ctx.ts;
    const attack = ctx.attack;
    const alertMalicious = ticket._alertMalicious; // set by engine from the alert's evidence truth

    // False-positive verdict: player dismisses the alert (no escalation).
    if (ticket.verdict === 'false_positive') {
      const wasActuallyMalicious = alertMalicious;
      const rec = { ...ticket, submittedTs: ts, resolvedTs: ts, q: null, kind: 'dismissal', correct: !wasActuallyMalicious };
      if (wasActuallyMalicious) {
        this._msg(ts, 'warning', `You marked "${ticket.alertTitle}" as a false positive — but it was part of a real intrusion. That thread is now unwatched.`);
      } else {
        this.goodEscalations += 0; // dismissals don't build trust, but don't hurt
        this._msg(ts, 'ok', `Dismissed "${ticket.alertTitle}" as benign. Good triage — that was normal activity.`);
        this.trust = Math.min(1, this.trust + 0.02);
      }
      this.history.push(rec);
      return rec;
    }

    // Escalation. Grade it.
    const s = this.score(ticket, ctx);

    // Over-escalation of noise erodes trust (alert fatigue).
    if (!alertMalicious) {
      this.falseEscalations++;
      this.trust = Math.max(0.3, this.trust - 0.12);
      this._msg(ts, 'warning', `Tier 2: "${ticket.alertTitle}" looks like benign activity. Escalating noise slows our real work — trust ${(this.trust * 100) | 0}%.`);
      const rec = { ...ticket, submittedTs: ts, resolvedTs: ts, q: s.q, kind: 'false_escalation', correct: false, score: s };
      this.history.push(rec);
      return rec;
    }

    this.goodEscalations++;
    this.trust = Math.min(1, this.trust + 0.05);

    // Compute response delay from quality, trust, and severity.
    const base = BASE_DELAY[ticket.severity] || 240;
    const qualityMult = 0.7 + (1 - s.q) * 2.3;
    const trustMult = 1 / Math.max(0.3, this.trust);
    let delay = Math.round(base * qualityMult * trustMult);

    // Vague ticket → Tier 2 asks a follow-up first (extra time).
    let followUp = null;
    if (!s.hasEvidence || !s.coversPrimary || s.q < 0.4) {
      followUp = !s.hasEvidence
        ? 'Tier 2 needs supporting log lines — attach the specific events.'
        : !s.coversPrimary
        ? 'Tier 2 asks: which host is actually affected? The named host does not appear compromised.'
        : 'Tier 2 asks for clarification before acting.';
      delay += Math.round(base * 0.8);
      this._msg(ts, 'question', `Tier 2: ${followUp}`);
    }

    // Translate the recommendation into concrete actions on the attack.
    const actions = this._planActions(ticket, s, attack);

    const entry = {
      ticket: { ...ticket, submittedTs: ts },
      executeTs: ts + delay,
      q: s.q,
      score: s,
      actions,
      followUp,
      kind: 'escalation',
    };
    this.pending.push(entry);
    this._msg(ts, 'ok', `Tier 2 accepted escalation "${ticket.alertTitle}" (quality ${(s.q * 100) | 0}%). Acting in ~${delay}s.`);
    return entry;
  }

  _planActions(ticket, s, attack) {
    const action = ticket.recommendedAction;
    const targets = ticket.affectedHosts || [];
    const accts = ticket.affectedAccounts || [];
    const out = [];
    switch (action) {
      case 'isolate_host':
      case 'contain_host':
        for (const h of targets) out.push({ type: 'isolate_host', host: h });
        break;
      case 'reset_credentials':
      case 'disable_account':
        for (const u of accts) out.push({ type: 'reset_credentials', user: u });
        // A good analyst also isolates; if they named a host, use it.
        for (const h of targets) out.push({ type: 'contain_host', host: h });
        break;
      case 'block_ip':
        for (const ip of ticket.affectedIps || []) out.push({ type: 'block_ip', ip });
        break;
      case 'remediate_vector':
      case 'patch':
        out.push({ type: 'remediate_vector' });
        for (const h of targets) out.push({ type: 'contain_host', host: h });
        break;
      case 'full_remediation':
        // Only honored as full remediation if the ticket is strong; otherwise it
        // degrades to isolating what was named.
        if (s.hasEvidence && s.coversPrimary && s.q >= 0.6) {
          out.push({ type: 'full_remediation' });
        } else {
          for (const h of targets) out.push({ type: 'isolate_host', host: h });
        }
        break;
      case 'monitor':
      default:
        // No containment — attacker keeps going.
        break;
    }
    return out;
  }

  // Execute due actions each tick.
  tick(ctx) {
    const ts = ctx.ts;
    const due = this.pending.filter((e) => ts >= e.executeTs);
    this.pending = this.pending.filter((e) => ts < e.executeTs);
    for (const e of due) {
      const applied = [];
      for (const a of e.actions) {
        const notes = ctx.attack.applyAction(a);
        applied.push(...notes);
      }
      e.resolvedTs = ts;
      e.applied = applied;
      this.history.push(e);
      const stopped = ctx.attack.status === 'stopped' || ctx.attack.status === 'gaveup';
      if (applied.length === 0) {
        this._msg(ts, 'warning', `Tier 2 acted on "${e.ticket.alertTitle}" but the recommendation ("${e.ticket.recommendedAction}") had no effect. Re-evaluate.`);
      } else if (stopped) {
        this._msg(ts, 'success', `Tier 2 executed your ticket "${e.ticket.alertTitle}": ${applied.join('; ')}. The intrusion is contained.`);
      } else {
        this._msg(ts, 'ok', `Tier 2 executed: ${applied.join('; ')}. Effect may be partial — verify the attacker hasn't fallen back.`);
      }
    }
  }
}
