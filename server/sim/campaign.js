// campaign.js — Progressive teaching campaign.
//
// Early levels introduce one attack type at a time with a briefing and learning
// goals; later levels widen the field; free play unlocks fully random seeds and
// any actor. Levels only *scope* the procedural generator (which archetypes are
// eligible, the start hour) — everything is still generated from the seed, so no
// two runs of a level are the same.

export const LEVELS = [
  {
    id: 1,
    title: 'First Shift: Failed Logins',
    focus: 'Brute force vs. fumbled passwords',
    allowArchetypes: ['script_kiddie'],
    startHour: 8,
    brief:
      'Welcome to your first shift. Watch the alert queue. Today you will mostly see authentication alerts. Some are real password-guessing from the internet; many are just staff mistyping their passwords. Learn to tell them apart before you escalate.',
    goals: [
      'Open an alert and read the source IP: internal (a user\'s own host) or external?',
      'Pivot on a source IP to see if it is hitting many accounts/hosts (attacker) or one (fumble).',
      'Escalate the real brute force with the source IP and a recommended action; dismiss the fumbles.',
    ],
    hintsFree: true,
  },
  {
    id: 2,
    title: 'Web Exposure',
    focus: 'Web exploitation and the web-shell tell',
    allowArchetypes: ['hacktivist', 'script_kiddie'],
    startHour: 8,
    brief:
      'Your DMZ web server faces the internet, so it is scanned constantly. Most injection-looking requests are harmless scanners and crawlers. The one that matters is the request that makes the web server spawn a shell — web servers serve pages, they do not run cmd or /bin/sh.',
    goals: [
      'Distinguish authorized-scanner / crawler web alerts from a real exploitation attempt.',
      'Find the high-fidelity "web service spawned a shell" alert and pivot on that host.',
      'Escalate with the host, the source IP, and the supporting process log line.',
    ],
    hintsFree: true,
  },
  {
    id: 3,
    title: 'Phishing to Foothold',
    focus: 'Email lure → Office spawns PowerShell',
    allowArchetypes: ['crime_crew'],
    startHour: 8,
    brief:
      'A criminal crew is phishing your staff. A suspicious email alone is low-signal, but when a user opens the attachment you will see Office spawn an obfuscated PowerShell — that is the foothold. Move before they establish persistence and move laterally.',
    goals: [
      'Correlate a suspicious email with a following process alert on the recipient\'s host.',
      'Recognize obfuscated/encoded PowerShell as a loader.',
      'Escalate early — the sooner Tier 2 isolates the host, the less the crew accomplishes.',
    ],
    hintsFree: false,
  },
  {
    id: 4,
    title: 'Living Off the Land',
    focus: 'Discovery, credential dumping, lateral movement',
    allowArchetypes: ['crime_crew'],
    startHour: 8,
    brief:
      'This crew avoids malware where it can, using built-in tools (PsExec, WMI, PowerShell). The hard part: admins use those same tools legitimately. Build timelines on hosts and follow the chain — credential dumping (LSASS) and remote execution are your high-fidelity anchors.',
    goals: [
      'Separate legitimate admin tool use from malicious living-off-the-land activity.',
      'Anchor on credential-dumping and remote-execution alerts, then trace the lateral path.',
      'Escalate with affected accounts (for credential reset) as well as hosts.',
    ],
    hintsFree: false,
  },
  {
    id: 5,
    title: 'The Quiet Ones',
    focus: 'Stealthy espionage and attribution',
    allowArchetypes: ['apt'],
    startHour: 8,
    brief:
      'A patient, skilled group is after your data, not your money. They are quiet and operate on a consistent schedule. Signals will be sparse — an off-hours login here, a large outbound transfer there. Read the group dossiers and match tooling, timezone and infrastructure to attribute the intrusion.',
    goals: [
      'Detect a low-and-slow intrusion from sparse, low-severity signals.',
      'Identify the large-exfiltration objective before it completes.',
      'Use the dossiers to attribute the actor by TTPs, active hours and infrastructure.',
    ],
    hintsFree: false,
  },
  {
    id: 6,
    title: 'Insider Threat',
    focus: 'Malicious use of legitimate access',
    allowArchetypes: ['insider'],
    startHour: 9,
    brief:
      'There is no break-in this time. Someone who already has valid credentials is abusing them — accessing data or hosts outside their normal pattern. No exploits, no malware droppers; just legitimate logons doing illegitimate things. Compare behavior against each user\'s persona.',
    goals: [
      'Spot access that is abnormal for a specific user\'s role and history.',
      'Recognize that "valid account" does not mean "authorized action".',
      'Escalate with account-focused actions (disable/monitor) rather than host isolation alone.',
    ],
    hintsFree: false,
  },
  {
    id: 7,
    title: 'Free Play',
    focus: 'Any actor, any objective, random seed',
    allowArchetypes: null,
    startHour: 8,
    brief:
      'No training wheels. A random seed generates a fresh network, a fresh set of users, and one of any known group with any objective. Triage the queue, investigate, attribute, and escalate well-written tickets. Good luck, analyst.',
    goals: [
      'Handle a full, unscoped shift end to end.',
      'Prioritize by SLA and severity — do not work the queue in order.',
      'Attribute the actor and keep Tier 2\'s trust high by not over-escalating.',
    ],
    hintsFree: false,
  },
];

export function getLevel(id) {
  return LEVELS.find((l) => l.id === id) || null;
}
