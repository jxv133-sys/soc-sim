// tier2.js — The simulated Tier 2 analyst who acts on escalated tickets.
//
// Ticket quality maps directly to outcome. A strong ticket (right host, solid
// evidence, correct recommended action) makes Tier 2 act fast, so the attack is
// stopped at an earlier stage. A vague ticket makes Tier 2 investigate slowly or
// ask a follow-up, burning time. A wrong recommendation (reset a password when a
// backdoor exists) fires but doesn't fully work — the attacker falls back.
// Over-escalating noise erodes Tier 2's trust, and low trust slows every future
// ticket (alert fatigue, modeled from the receiving end).

// Base time (sim-seconds ≈ real seconds) Tier 2 takes to act on a *perfect*
// ticket, by severity. Critical/high are treated as urgent: a confirmed webshell
// or credential-dumping escalation gets a near-immediate response — not an hour.
const BASE_DELAY = { critical: 20, high: 40, medium: 150, low: 300 };
// Hard ceiling on response time by severity, so an urgent ticket is always acted
// on fast even if it's imperfect or trust is low. Slower tiers stay quality- and
// trust-sensitive (that's where triage discipline is taught).
const MAX_DELAY = { critical: 75, high: 150, medium: 320, low: 460 };
const URGENT = new Set(['critical', 'high']);

// Which stage implies which "true" severity, used to grade the player's call.
const STAGE_SEVERITY = {
  initial_access: 'medium', persistence: 'medium', discovery: 'medium',
  credential_access: 'high', lateral_movement: 'high', objective: 'critical',
};
const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

export class Tier2 {
  constructor() {
    this.trust = 1.0;
    this.pending = []; // cases under review [{caseId, ticket, reviewTs, s, q, alertMalicious, actions, kind}]
    this.history = []; // reviewed cases with disposition
    this.messages = []; // feedback lines shown to the player
    this.falseEscalations = 0;
    this.goodEscalations = 0;
    this.caseSeq = 0;
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

  // Player submits a case. The analyst gets NO immediate assessment — Tier 2
  // takes time to review, then reports back (in tick()) the disposition it
  // determined (true / false positive) and the actions it took. Quality is graded
  // silently now and only surfaces as the review's speed and outcome.
  submit(ticket, ctx) {
    const ts = ctx.ts;
    const attack = ctx.attack;
    const alertMalicious = !!ticket._alertMalicious; // ground truth (server-side only)
    const sev = ticket.severity;
    const isEsc = ticket.verdict !== 'false_positive';
    const s = this.score(ticket, ctx); // graded silently, revealed later via the outcome
    const caseId = 'CASE-' + String(++this.caseSeq).padStart(3, '0');

    let reviewDelay, actions = [];
    if (!isEsc) {
      // Analyst closed it as a false positive → Tier 2 does a quick QA pass.
      reviewDelay = Math.round((BASE_DELAY[sev] || 150) * 0.4) + 20;
    } else {
      // Escalation → review time scales with quality, trust and severity. Urgent
      // (critical/high) reviews are fast with a hard ceiling; the action itself
      // only lands if the review confirms a true positive.
      const urgent = URGENT.has(sev);
      const base = BASE_DELAY[sev] || 150;
      const qualityMult = 0.7 + (1 - s.q) * (urgent ? 0.6 : 2.3);
      const trustMult = 1 / Math.max(urgent ? 0.7 : 0.3, this.trust);
      reviewDelay = Math.round(base * qualityMult * trustMult);
      if (!s.hasEvidence || !s.coversPrimary || s.q < 0.4) reviewDelay += Math.round(base * (urgent ? 0.25 : 0.8));
      reviewDelay = Math.min(reviewDelay, MAX_DELAY[sev] || 700);
      if (alertMalicious) actions = this._planActions(ticket, s, attack); // acted on only if truly a TP
    }

    const entry = {
      caseId, kind: isEsc ? 'escalation' : 'dismissal',
      ticket: { ...ticket, submittedTs: ts }, submittedTs: ts, reviewTs: ts + reviewDelay,
      s, q: s.q, alertMalicious, actions, resolved: false,
    };
    this.pending.push(entry);

    // Neutral acknowledgement only — no verdict, no score.
    if (isEsc) this._msg(ts, 'received', `${caseId} raised — Tier 2 is reviewing your escalation of "${ticket.alertTitle}".`);
    else this._msg(ts, 'received', `${caseId} — you closed "${ticket.alertTitle}" as a false positive; sent to Tier 2 for QA.`);
    return { caseId, kind: entry.kind };
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

  // Complete reviews whose time has come and report back to the analyst. This is
  // the ONLY place a disposition (true / false positive) or an action is
  // revealed. `ctx.addPoints(n)` applies the (previously hidden) score impact.
  tick(ctx) {
    const ts = ctx.ts;
    const due = this.pending.filter((e) => ts >= e.reviewTs);
    this.pending = this.pending.filter((e) => ts < e.reviewTs);
    const add = ctx.addPoints || (() => {});
    for (const e of due) {
      e.resolved = true;
      e.resolvedTs = ts;
      e.disposition = e.alertMalicious ? 'true_positive' : 'false_positive';
      const title = e.ticket.alertTitle;

      if (e.kind === 'escalation') {
        if (e.alertMalicious) {
          // Confirmed true positive → Tier 2 carries out the recommended action.
          const applied = [];
          for (const a of e.actions) applied.push(...ctx.attack.applyAction(a));
          e.applied = applied;
          this.goodEscalations++;
          this.trust = Math.min(1, this.trust + 0.05);
          add(Math.round((e.q || 0) * 100));
          const stopped = ctx.attack.status === 'stopped' || ctx.attack.status === 'gaveup';
          const weak = !e.s.hasEvidence || !e.s.coversPrimary;
          if (!applied.length) {
            this._msg(ts, 'warning', `${e.caseId} — Tier 2 confirms TRUE POSITIVE on "${title}", but your recommended action ("${e.ticket.recommendedAction}") had no usable effect. Re-escalate with the right action.`);
          } else if (stopped) {
            this._msg(ts, 'success', `${e.caseId} — TRUE POSITIVE confirmed on "${title}". Tier 2 actioned: ${applied.join('; ')}. The intrusion is contained.`);
          } else {
            this._msg(ts, 'ok', `${e.caseId} — TRUE POSITIVE on "${title}". Tier 2 actioned: ${applied.join('; ')}. Effect may be partial — watch for a fallback.${weak ? ' (Review was slowed by thin evidence.)' : ''}`);
          }
        } else {
          // Over-escalated benign activity → assessed false positive, trust drops.
          this.falseEscalations++;
          this.trust = Math.max(0.3, this.trust - 0.12);
          add(-50);
          this._msg(ts, 'warning', `${e.caseId} — Tier 2 assessed "${title}" as a FALSE POSITIVE (benign activity); no action taken. Over-escalating noise erodes trust (now ${(this.trust * 100) | 0}%).`);
        }
      } else {
        // Dismissal QA: was the analyst right to close it?
        if (!e.alertMalicious) {
          this.trust = Math.min(1, this.trust + 0.02);
          add(10);
          this._msg(ts, 'ok', `${e.caseId} — Tier 2 QA concurs: "${title}" was a FALSE POSITIVE. Closed. Good triage.`);
        } else {
          add(-30);
          this._msg(ts, 'warning', `${e.caseId} — Tier 2 QA: "${title}" was a MISSED TRUE POSITIVE — real malicious activity you closed as benign. It was not actioned; logged for the after-action.`);
        }
      }
      this.history.push(e);
    }
  }
}
