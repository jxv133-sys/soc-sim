// knowledge.js — The teaching layer's content: alert explainers and actor
// dossiers. Each detection rule links to a short explainer (what it means, what
// benign activity looks similar, what to check next). Dossiers are generated
// from actor traits so players can "read up" on groups and match tooling /
// timezone / calling cards to what they see in the logs — real attribution.

export const ALERT_KB = {
  brute_force: {
    title: 'Brute Force / Password Guessing',
    mitre: 'T1110',
    means: 'Many failed authentication attempts against an account or host in a short window — someone (or something) is trying many passwords.',
    benign: 'A user who fat-fingers their password several times, a misconfigured service with stale credentials, or a mail client retrying a bad saved password. Volume and source matter: 5 fails from the user\'s own workstation is likely a fumble; 200 from a foreign IP is not.',
    check: ['Is the source IP internal (the user\'s host) or external/unfamiliar?', 'Did a SUCCESS follow the failures? (successful brute force)', 'Pivot on the source IP: is it hitting multiple accounts/hosts?', 'Pivot on the user: is this their normal machine and hours?'],
  },
  anomalous_login: {
    title: 'Anomalous / New-Source Login',
    mitre: 'T1078',
    means: 'A successful logon for an account from a source (IP/geo) not previously seen for that user.',
    benign: 'Travelling sales staff, a new home IP, VPN, or an executive logging in from a hotel. Compare against the user\'s persona and normal source.',
    check: ['Does this user normally travel or use VPN?', 'Is the geo plausible vs. their last login (impossible travel)?', 'What did the account do right after login — normal work or discovery/lateral movement?', 'Pivot on the user across all hosts.'],
  },
  offhours_logon: {
    title: 'Off-Hours Logon to a Server',
    mitre: 'T1078 / T1021',
    means: 'An interactive or remote logon to a server outside business hours.',
    benign: 'Admins and developers legitimately work odd hours; batch jobs and on-call responders too. This is a low-fidelity signal on its own — corroborate it.',
    check: ['Is this user an admin/dev who normally works late?', 'Is the source their usual host?', 'Are there discovery or credential-access events on the same host shortly after?', 'Pivot on host + adjacent time.'],
  },
  web_injection: {
    title: 'Web Attack Signature (SQLi / LFI / RCE probe)',
    mitre: 'T1190',
    means: 'An HTTP request whose path or tool signature matches known web-exploitation patterns.',
    benign: 'Authorized vulnerability scanners (Nessus, internal security testing), search-engine crawlers hitting odd URLs, and the constant background hum of opportunistic internet scanning that never succeeds.',
    check: ['Was the source an authorized internal scanner (check UA and source subnet)?', 'Did the server RESPOND abnormally (500s, then a shell)? A 200 to an injection is worse than a 404.', 'Follow the source IP: did a web process spawn a shell afterwards?', 'Pivot on the target host process tree.'],
  },
  web_shell: {
    title: 'Web Service Spawned a Shell (likely RCE)',
    mitre: 'T1190 / T1505',
    means: 'A web-server process (w3wp, apache, nginx, php-fpm) launched a command shell. Web servers serve pages; they do not run cmd/sh.',
    benign: 'Very rarely a legitimate CGI script or admin webhook. This is a high-fidelity signal — treat as real until proven otherwise.',
    check: ['What command did the shell run (id, whoami, download)?', 'Pivot on the host: new files, persistence, outbound connections?', 'Which external IP triggered the preceding web requests?', 'This is likely a confirmed foothold — consider escalation.'],
  },
  cred_dump: {
    title: 'Credential Dumping',
    mitre: 'T1003',
    means: 'An attempt to extract credentials from memory or local stores (LSASS MiniDump, mimikatz, LaZagne).',
    benign: 'Almost none. Some EDR/AV or crash-dump tooling touches LSASS, but explicit MiniDump of lsass is a strong indicator of compromise.',
    check: ['Which account ran it, and how did they get admin?', 'Assume stolen credentials — which accounts are now suspect?', 'Pivot to where those accounts log in next (lateral movement).', 'Escalate: recommend credential resets for exposed accounts.'],
  },
  remote_exec: {
    title: 'Remote Execution / Lateral Movement Tool',
    mitre: 'T1021 / T1570',
    means: 'A remote service-execution tool (PsExec, WMIExec) ran — code executed on a host pushed from another.',
    benign: 'IT sometimes uses PsExec for administration. Check whether it came from a sanctioned admin host and account.',
    check: ['Source host and account — is it an admin jump host?', 'What binary did it drop/run on the target?', 'Trace the chain backward: where did this foothold come from?', 'Map every host touched — build the lateral path.'],
  },
  suspicious_powershell: {
    title: 'Obfuscated / Encoded PowerShell',
    mitre: 'T1059 / T1027',
    means: 'PowerShell run with encoded commands, hidden windows, or in-memory download/execute — hallmarks of loaders.',
    benign: 'Some legitimate management scripts use -EncodedCommand. Hidden + download-cradle together is rarely benign.',
    check: ['Decode the command if possible — what does it fetch/run?', 'Parent process — did Office spawn PowerShell (phishing)?', 'Outbound connection right after?', 'Pivot on host and user.'],
  },
  persistence: {
    title: 'Persistence Mechanism Created',
    mitre: 'T1053 / T1547 / T1543',
    means: 'A scheduled task, service, run key, or cron job was created that survives reboot.',
    benign: 'Admins and installers create tasks/services constantly. Look at WHAT it runs and WHERE the binary lives.',
    check: ['Does the task run a binary from Temp/ProgramData/public dirs?', 'Was it created by an admin change window or out of nowhere?', 'Name mimicry (e.g. "MicrosoftUpdate")?', 'Pivot to the referenced file and its origin.'],
  },
  discovery: {
    title: 'Reconnaissance / Discovery',
    mitre: 'T1018 / T1087 / T1046',
    means: 'Enumeration of hosts, domain accounts, or services (net view, nltest, ldapsearch, nmap).',
    benign: 'Admin scripts and monitoring tools enumerate constantly. Very low fidelity alone; valuable as corroboration next to a foothold.',
    check: ['Same host as any higher-fidelity alert?', 'Is the running account an admin or a workstation user?', 'Followed by credential access or lateral movement?', 'Build the timeline on this host.'],
  },
  exfiltration: {
    title: 'Data Exfiltration (large outbound transfer)',
    mitre: 'T1041 / T1567',
    means: 'A large volume of data left a host to an external destination.',
    benign: 'Backups to cloud, marketing/media uploads, developer artifact pushes, video calls. Destination reputation and host role matter.',
    check: ['Is the destination a known service (AWS/Google) or a rare/foreign IP?', 'Does this host/user normally move big files?', 'Was data staged (archive created) beforehand?', 'Pivot on destination IP and host.'],
  },
  cryptomining: {
    title: 'Cryptomining',
    mitre: 'T1496',
    means: 'A host connected to a mining-pool port / sustained mining traffic.',
    benign: 'Almost none on a corporate host. A build server pegging CPU is not the same as stratum traffic.',
    check: ['Which process opened the connection?', 'How did it get there (initial access)?', 'Usually opportunistic — but confirm no further objectives.'],
  },
  port_scan: {
    title: 'Internal Network Scan',
    mitre: 'T1046',
    means: 'A host connected to many internal hosts/ports quickly — sweeping the network.',
    benign: 'Authorized internal vulnerability scanners and asset-discovery tools do exactly this on a schedule.',
    check: ['Is the source an authorized scanner host?', 'Is it scanning from a workstation that has no business scanning?', 'Corroborate with discovery/credential events.'],
  },
  ransomware: {
    title: 'Ransomware / Mass File Modification',
    mitre: 'T1486 / T1485',
    means: 'A large number of files renamed/encrypted/deleted rapidly, often with shadow-copy deletion.',
    benign: 'Backup software and bulk archive operations touch many files — but not usually with new random extensions and a ransom note.',
    check: ['New file extension appended en masse?', 'Ransom note created?', 'Shadow copies deleted (vssadmin)?', 'THIS IS AN ACTIVE IMPACT EVENT — isolate immediately.'],
  },
  ransom_note: {
    title: 'Ransom Note Dropped',
    mitre: 'T1486',
    means: 'A recovery/decrypt instruction file was written — the attacker is announcing impact.',
    benign: 'None.',
    check: ['Isolate the host now.', 'Identify the family from the note/extension.', 'Determine spread — check neighbours.'],
  },
  suspicious_email: {
    title: 'Suspicious Email (phishing lure)',
    mitre: 'T1566',
    means: 'An inbound email with a malicious-looking attachment or a link from a lookalike sender.',
    benign: 'Lots of legitimate mail has macro-docs and links; newsletters and vendors use odd domains. Low fidelity — but the start of many intrusions.',
    check: ['Did the recipient open it? (Office spawning PowerShell soon after)', 'Attachment type — macro/executable/double-extension?', 'Sender domain age/lookalike?', 'Pivot to the recipient\'s host.'],
  },
};

// Human-readable dossier generated from an actor's traits.
export function actorDossier(actor) {
  const t = actor.traits;
  const lvl = (v) => (v >= 0.75 ? 'very high' : v >= 0.5 ? 'high' : v >= 0.3 ? 'moderate' : 'low');
  const tzGuess = actor.respectsActiveHours
    ? `operates on a consistent schedule (~${String(actor.activeHours.start).padStart(2, '0')}:00–${String(actor.activeHours.end).padStart(2, '0')}:00 local to the target), suggesting a fixed working timezone`
    : 'operates at random hours with no consistent schedule';
  return {
    id: actor.id,
    name: actor.name,
    archetype: actor.archetypeLabel,
    summary: `${actor.name} is a ${actor.archetypeLabel.toLowerCase()} group. Skill ${lvl(t.skill)}, stealth ${lvl(t.stealth)}, speed ${lvl(t.speed)}, patience ${lvl(t.patience)}.`,
    objective: actor.objective,
    tooling: actor.tooling,
    lateralStyle: actor.lateralStyle === 'lolbins' ? 'living off the land (built-in tools like PsExec/WMI/PowerShell)' : actor.lateralStyle === 'valid_accounts' ? 'legitimate credentials only' : 'noisy public exploits and remote tools',
    schedule: tzGuess,
    infraHint: actor.infra.ips.length <= 2 ? `reuses a small set of source addresses (observed origin: ${actor.infra.cc})` : `rotates through several source addresses (observed origin: ${actor.infra.cc})`,
    malware: actor.families.map((f) => ({ name: f.name, category: f.label, ext: f.extension, note: f.noteName, proc: f.procName, drop: f.dropFile })),
    callingCard: actor.callingCard ? actor.callingCard.text : 'Known to avoid leaving obvious calling cards — attribute by tooling and timing.',
    initialAccess: actor.initialAccess,
    persistenceDepth: t.persistenceDepth,
    adaptability: lvl(t.adaptability),
    attributionHints: [
      `Preferred initial access: ${actor.initialAccess.join(', ')}.`,
      `Lateral style: ${actor.lateralStyle}.`,
      actor.respectsActiveHours ? 'Activity clusters in a fixed daily window — match log timestamps to their working hours.' : 'Activity is bursty and at all hours — a hallmark of low-discipline actors.',
      actor.infra.ips.length <= 2 ? 'Reuses infrastructure — the same source IP recurs across stages.' : 'Rotates infrastructure — expect the source IP to change, especially after you block one.',
    ],
  };
}
