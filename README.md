# SENTINEL SOC — Tier 1 Analyst Training Simulator

A browser-based game that trains the core skills of a Tier 1 Security Operations Center (SOC)
analyst: **triaging alerts**, **investigating logs to separate real threats from false alarms**,
and **escalating well-written tickets** to a (simulated) Tier 2 analyst who acts on the network.

You are a Tier 1 analyst. You never touch the network directly. You watch a live alert queue,
investigate by searching and pivoting through logs, decide each alert's verdict, and — for real
threats — write a ticket (verdict, severity, affected hosts/accounts, supporting log evidence,
recommended action) and escalate it. **The quality of your ticket determines how fast and how
effectively Tier 2 stops the attack.**

---

## The three hard requirements (and how they're met)

### 1. Everything is procedurally generated. No hardcoded attacks.
Each game starts from a **seed** (reproducible and shareable). From that seed the simulator builds
the network topology, the users and their behavior patterns, the day's normal activity, and the
attack itself. Two seeds produce genuinely different games — different network layout, different
attacker, different attack path, different noise. See `server/sim/rng.js` (seeded PRNG with
labeled sub-streams) and every `generate*` function that derives from it.

### 2. Alerts emerge from detection rules running over generated logs — never placed by hand.
Detection rules (`server/sim/detection.js`) run over the generated log stream. Alerts fire wherever
rules match. **False positives arise naturally**: a real user who fat-fingers their password trips
the same brute-force rule as an attacker; an admin's 2 a.m. SSH trips the same off-hours rule as
lateral movement; a marketer's big upload trips the same exfiltration rule. Rules only ever see
observable log fields — never the hidden ground-truth tag — so the false alarms are real, not a
separate labeled category. In a typical queue, benign alerts outnumber malicious ones.

### 3. The simulation is live and dynamic.
The game runs on an **accelerated clock with pause and speed controls** (pausing is essential for
learning). Logs and alerts stream to the client over **WebSocket** as the simulation ticks. Each
tick: users generate normal activity, the attacker advances if ready, detection rules evaluate new
events, and new logs/alerts/map-updates push to the client. You work against time and SLA timers.

---

## Core systems

| System | File | What it does |
|---|---|---|
| Seeded RNG | `server/sim/rng.js` | Deterministic generation; labeled sub-streams; shareable seeds. |
| Network + firewall | `server/sim/network.js` | Zones (DMZ, corp, servers, mgmt), hosts, services, and firewall rules. **Attack paths derive from the reachability graph.** |
| Personas | `server/sim/personas.js` | Users with consistent roles, hours, and habits. "Normal" is defined *per user* — the basis for believable false positives. |
| Threat actors | `server/sim/actors.js` | Profiles of **traits** (skill, noise, speed, patience, persistence depth, adaptability, objective, tooling, active hours). Traits drive behavior; each actor has calling cards for attribution. |
| Malware catalog | `server/sim/malware.js` | Ransomware, worm, spyware/infostealer, RAT, cryptominer, wiper — each with observable IOCs and a procedurally-named family per actor. |
| Attack engine | `server/sim/attack.js` | A **live state machine**: initial access → persistence → discovery → credential access → lateral movement → objective. MITRE ATT&CK-tagged, pathfinds over the topology, and **adapts** (falls back to persistence / rotates infra) when disrupted. |
| Log model | `server/sim/logsource.js` | Canonical event shape + realistic syslog-style rendering. Ground truth rides along server-side only. |
| Behavior | `server/sim/behavior.js` | Per-persona normal activity each tick — the source of emergent false positives. |
| Detection | `server/sim/detection.js` | Windowed, stateful rules over the observable stream. |
| Tier 2 NPC | `server/sim/tier2.js` | Ticket-quality → response speed & effectiveness; **trust model** for alert fatigue from over-escalation. |
| Knowledge base | `server/sim/knowledge.js` | Alert explainers + generated actor dossiers for attribution. |
| Campaign | `server/sim/campaign.js` | Progressive levels; free play. |
| Engine | `server/sim/engine.js` | Orchestrates the clock, wiring, deltas, scoring, and the after-action report. |
| Server | `server/index.js` | Express static host + WebSocket game channel. |
| GUI | `public/` | The SOC console (alert queue, investigation, network map, ticket editor, clock). |

### Threat actor groups
Five archetypes ship, each easy to extend (add to `ARCHETYPES` in `actors.js`):
- **Script Kiddie** — low skill, loud, fast, impatient; public exploits & brute force; reused IPs; often gives up if blocked. Prefers off-the-shelf ransomware / cryptominers.
- **Criminal Organization** — skilled, quiet, patient; lives off the land (PsExec/WMI/PowerShell); multiple persistence mechanisms; adapts when blocked. Ransomware / worm.
- **State-Sponsored (APT)** — very high skill, very quiet, patient; minimal footprint; espionage/exfiltration; fixed working timezone. Custom implants / RATs.
- **Hacktivist** — medium skill, loud, wants credit (leaves calling cards); web exploits; disruption/leak. Wipers.
- **Malicious Insider** — no break-in; abuses legitimate credentials; abnormal data access; sabotage/theft.

A roster of named groups is generated per seed; **the active attacker is one of them**. Read the
dossiers (🎭 Actors) and match tooling, timezone, infrastructure, and calling cards to attribute
the intrusion — some groups announce themselves, others must be deduced.

### Stopping vs. infection (the stakes)
The race is between the attacker completing stages and your escalation being acted on by Tier 2:
- **Caught during initial access** → attack dies, nothing infected (best outcome).
- **Caught mid-chain** → attacker stopped, some hosts already compromised and flagged for cleanup (partial win).
- **Missed** → the payload lands. Ransomware: the host goes **dark** on the map. Worm: infection
  **spreads** host-to-host across the segment over subsequent ticks. Exfil/mining/wiper show their
  own effects. Consequences are visible on the map, because watching a missed alert become a
  spreading outbreak is a primary teaching moment.

---

## Running it

```bash
npm install
npm start
# open http://localhost:3000
```

Node 18+ (developed on Node 22). No external network needed at runtime — Cytoscape.js is vendored
under `public/js/vendor/`.

Run the test suite (covers the three requirements and key mechanics):
```bash
npm test
```

Dev mode with auto-restart:
```bash
npm run dev
```

`PORT` env var overrides the default port 3000.

---

## How to play

1. **Pick a shift.** Choose a campaign level (guided, one attack type at a time) or Free Play
   (random or a specific seed). Read the briefing, then Begin.
2. **Triage the queue (left).** Alerts show severity, source entities, and an **SLA countdown**.
   Sort by SLA/severity/time and filter by status. Don't work in order — prioritize.
3. **Investigate (bottom).** Full-text search the logs, filter by source, and **pivot** with one
   click (same IP / user / host / adjacent time). Pivoting is the main investigative motion.
   Clicking an alert loads its evidence and pivots there.
4. **Use the map (center).** Hosts light up when alerts implicate them. Click a host to investigate
   it or tag it *suspected / confirmed / contained*. **Fog of war:** the map shows what you know —
   only observed impact (dark host, spreading worm) is revealed; true state comes in the report.
5. **Escalate (right).** Attach evidence by ticking real log lines, fill the ticket (verdict,
   severity, affected hosts/accounts, source IPs, recommended action), and submit to Tier 2.
   - A **strong** ticket (right host, solid evidence, correct action) → Tier 2 acts fast.
   - A **vague** ticket → Tier 2 asks a follow-up and burns time.
   - A **wrong** recommendation (reset a password when a backdoor exists) → acts but doesn't fully work; the attacker falls back.
   - **Over-escalating noise** drops Tier 2's trust, slowing every future ticket (alert fatigue).
6. **Learn.** 📖 KB explains each alert type (what it means, benign look-alikes, what to check).
   💡 Hints (cost points) point toward *where to look*, not the answer.
7. **After-action report.** On game end (or on demand), a side-by-side timeline shows **what the
   attacker actually did vs. what you saw and did**, highlighting missed steps with the exact log
   line that would have revealed each one, plus the moment the attack could have been stopped.
   You're scored on dwell time, damage, business disruption, false escalations, and ticket quality.

Keyboard: **Space** pauses/resumes.

**Pacing.** The shift starts paused at 08:00 (a busy office, so there's benign
activity to triage immediately). The default **1×** speed advances ~4 sim-seconds
per real second — a critical alert's 5-minute SLA gives you about 75 real seconds
to react, and logs arrive as a readable trickle. Drop to **0.5×** during a hectic
incident, or jump to **4× / 8×** to fast-forward quiet stretches. When in doubt,
pause and investigate.

---

## Extending the simulator

- **New threat actor** (hacktivist variant, ransomware affiliate, etc.): add an entry to
  `ARCHETYPES` in `server/sim/actors.js` — traits, initial-access options, lateral style, preferred
  malware, calling-card probability. The attack engine and dossier generator pick it up automatically.
- **New malware type:** add a category to `CATEGORIES` in `server/sim/malware.js` with an
  `objective` and `mapEffect`, and (if new) handle that objective in `attack.js` `_executeObjective`.
- **New detection rule:** add a rule to `DetectionEngine.ingest` in `server/sim/detection.js` and a
  matching explainer in `ALERT_KB` (`server/sim/knowledge.js`). Because rules run over the shared
  stream, any benign behavior that matches will naturally generate false positives.
- **New level:** add to `LEVELS` in `server/sim/campaign.js`.

---

## Design notes

- **Ground truth never leaks to the client.** Every event carries a server-only `_truth` tag used
  purely for the after-action report and Tier 2 grading; the sanitized event sent to the browser has
  it stripped, and detection rules never read it.
- **Determinism.** The same seed reproduces the same network, users, actor, and — for identical
  player input — the same timeline. Seeds are shareable scenario IDs.
- **Reactivity is real.** When you contain a foothold or block an IP, the attacker responds
  according to its traits: a high-adaptability crew falls back to a surviving persistence mechanism
  or rotates infrastructure; a low-adaptability script kiddie may simply give up.
