// app.js — SOC console UI: state, rendering, and interaction wiring.
(function () {
  'use strict';
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const EV_CAP = 6000;

  const S = {
    meta: {}, network: null, level: null, users: [], usersByName: {}, hostsById: {},
    alerts: new Map(), events: [], eventsById: new Map(),
    messages: [], msgSeen: new Set(),
    kb: {}, dossiers: [], hostTags: {}, levels: [], ipToHost: {},
    selectedAlertId: null, evidence: new Map(),
    live: true, pivots: [], searchSource: '', searchText: '', viewEvents: null,
    ended: false, epsBuf: [], expanded: new Set(),
  };

  // ---------------- boot ----------------
  Net.connect();
  Net.on('hello', (m) => populateLevels(m.levels));
  Net.on('game_started', onGameStarted);
  Net.on('delta', (m) => applyDelta(m.delta));
  Net.on('ticket_result', onTicketResult);
  Net.on('tag_result', (m) => { if (m.hostTags) { S.hostTags = m.hostTags; } });
  Net.on('hint_result', onHintResult);
  Net.on('search_result', (m) => { S.viewEvents = m.events; renderLogs(); });
  Net.on('events_result', (m) => { S.viewEvents = m.events; S.live = false; setLiveBtn(); renderLogs(); });
  Net.on('report', (m) => openReport(m.report));
  Net.on('dossiers', (m) => { S.dossiers = m.dossiers; });

  fetch('/api/levels').then((r) => r.json()).then((d) => populateLevels(d.levels)).catch(() => {});

  const GRADE_RANK = { F: 0, D: 1, C: 2, B: 3, A: 4 };
  function getProgress() { try { return JSON.parse(localStorage.getItem('socsim.progress') || '{}'); } catch { return {}; } }
  function saveProgress(levelId, grade) {
    if (!levelId || !grade) return;
    try {
      const p = getProgress();
      if (!(p[levelId] in GRADE_RANK) || GRADE_RANK[grade] > GRADE_RANK[p[levelId]]) { p[levelId] = grade; localStorage.setItem('socsim.progress', JSON.stringify(p)); }
    } catch { /* private mode: progress simply isn't remembered */ }
  }

  function populateLevels(levels) { if (levels) S.levels = levels; renderLevels(); }
  function renderLevels() {
    const list = $('#level-list'); if (!list || !S.levels.length) return;
    const prog = getProgress();
    const firstIncomplete = S.levels.find((lv) => !prog[lv.id]);
    list.innerHTML = '';
    S.levels.forEach((lv) => {
      const item = el('div', 'level-item');
      const done = prog[lv.id];
      if (firstIncomplete && lv.id === firstIncomplete.id) item.classList.add('lv-next');
      item.innerHTML =
        `<div class="lv-title"><span class="lv-num">${lv.id}</span>${esc(lv.title)}` +
        (done ? `<span class="lv-grade grade-${done}">✓ ${done}</span>` : '') +
        (firstIncomplete && lv.id === firstIncomplete.id ? `<span class="lv-tag">next</span>` : '') +
        `</div><div class="lv-focus">${esc(lv.focus)}</div>`;
      item.onclick = () => startGame({ level: lv.id });
      list.appendChild(item);
    });
  }

  $('#btn-freeplay').onclick = () => startGame({ seed: $('#seed-input').value });
  function startGame({ seed, level }) {
    // reset state
    S.alerts.clear(); S.events = []; S.eventsById.clear(); S.messages = []; S.msgSeen.clear();
    S.evidence.clear(); S.selectedAlertId = null; S.hostTags = {}; S.viewEvents = null; S.pivots = []; S.live = true; S.ended = false;
    Net.send('new_game', { seed, level });
  }

  // ---------------- game start ----------------
  function onGameStarted(m) {
    $('#start-screen').classList.add('hidden');
    $('#console').classList.remove('hidden');
    S.level = m.level; S.dossiers = m.dossiers || [];
    const snap = m.snapshot;
    S.network = snap.network;
    S.hostsById = Object.fromEntries(snap.network.hosts.map((h) => [h.id, h]));
    S.users = snap.users; S.usersByName = Object.fromEntries(snap.users.map((u) => [u.username, u]));
    S.kb = snap.kb || {};
    S.meta = snap.meta;
    S.hostTags = snap.hostTags || {};
    (snap.alerts || []).forEach((a) => S.alerts.set(a.id, a));
    (snap.messages || []).forEach(addMessage);
    $('#scenario-name').textContent = m.level ? m.level.title : 'Free Play';
    $('#seed-name').textContent = m.seed;
    $('#map-org').textContent = `${snap.network.org} · ${snap.network.domain}`;
    S.ipToHost = Object.fromEntries(snap.network.hosts.map((h) => [h.ip, h.id]));
    S.epsBuf = [];
    buildSpeeds(m.speeds || [1, 2, 4, 8]);

    // Briefing
    if (m.level) {
      $('#briefing').classList.remove('hidden');
      $('#briefing-name').textContent = m.level.title;
      $('#briefing-body').textContent = m.level.brief;
      const goals = $('#briefing-goals'); goals.innerHTML = '';
      (m.level.goals || []).forEach((g) => { const li = el('li'); li.textContent = g; goals.appendChild(li); });
    } else {
      $('#briefing').classList.add('hidden');
    }

    SOCMap.init($('#cy'), snap.network, { onHostClick: onHostClick });
    Object.entries(S.hostTags).forEach(([h, t]) => SOCMap.setTag(h, t));
    renderAll();
  }

  // ---------------- deltas ----------------
  function applyDelta(d) {
    if (!d) return;
    if (d.events && d.events.length) {
      for (const ev of d.events) { S.events.push(ev); S.eventsById.set(ev.id, ev); }
      if (S.events.length > EV_CAP) S.events.splice(0, S.events.length - EV_CAP);
      S.epsBuf.push({ t: Date.now(), n: d.events.length });
      if (S.live) renderLogs();
      animateFlows(d.events);
    }
    if (d.alerts && d.alerts.length) {
      for (const a of d.alerts) {
        S.alerts.set(a.id, a);
        if (a.severity === 'critical' || a.severity === 'high') toast(`⚠ ${a.severity.toUpperCase()}: ${a.title}`);
        SOCMap.pulse((a.entities.hosts || [])[0]);
      }
      recomputeImplicated();
      renderAlerts();
    }
    if (d.alertUpdates && d.alertUpdates.length) {
      for (const u of d.alertUpdates) { const a = S.alerts.get(u.id); if (a) a.status = u.status; }
      renderAlerts();
    }
    if (d.messages && d.messages.length) { d.messages.forEach(addMessage); renderTier2(); }
    if (d.map && d.map.length) {
      for (const mu of d.map) {
        SOCMap.setImpact(mu.host, mu.status, mu.contained);
        if (mu.status === 'dark') toast(`💀 ${mu.host} is DARK — ransomware/wiper impact`);
        else if (mu.status === 'spread') toast(`🦠 Worm spreading to ${mu.host}`);
        else if (mu.status === 'exfil') toast(`📤 Data exfiltration from ${mu.host}`);
      }
    }
    if (d.meta) { S.meta = d.meta; renderMeta(); renderAlerts(); }
    if (d.report) { S.ended = true; openReport(d.report); }
  }

  function addMessage(m) { if (m && !S.msgSeen.has(m.id)) { S.msgSeen.add(m.id); S.messages.push(m); } }

  // ---------------- live packet flow on the map ----------------
  const INTERNAL_RE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
  function ipNode(ip) {
    if (!ip) return null;
    if (S.ipToHost[ip]) return S.ipToHost[ip];   // a known internal asset
    if (INTERNAL_RE.test(ip)) return null;        // internal but not a mapped host
    return 'internet';                            // external address → the internet cloud
  }
  // Resolve an event to a directed edge (from → to) on the map, if it represents
  // traffic between two nodes we can place.
  function flowEndpoints(ev) {
    const f = ev.fields || {};
    switch (ev.source) {
      case 'network': return [ipNode(ev.srcIp) || ipNode(f.srcIp), ipNode(f.dstIp)];
      case 'auth':    return [ipNode(ev.srcIp), ev.host];            // login flows to the host
      case 'web':     return [ipNode(ev.srcIp), ev.host];            // request flows to the server
      case 'dns':     return [ev.host, 'internet'];                  // resolver query out
      default:        return [null, null];
    }
  }
  function animateFlows(events) {
    if (!window.SOCMap || !SOCMap.flowPacket) return;
    let budget = 14; // cap packets spawned per delta to keep the map calm
    for (const ev of events) {
      if (budget <= 0) break;
      const [from, to] = flowEndpoints(ev);
      if (from && to && from !== to) { SOCMap.flowPacket(from, to, ev.source); budget--; }
    }
  }

  // Ambient background traffic: a steady, cosmetic trickle of packets along real
  // firewall-permitted links so the network map always looks alive (these are
  // not log events — just the constant hum of a working network).
  setInterval(() => {
    if (!S.network || !window.SOCMap || !SOCMap.flowPacket) return;
    if (S.meta.paused || S.meta.ended) return;
    const edges = S.network.edges;
    if (!edges || !edges.length) return;
    const n = 1 + Math.floor(Math.random() * 2);
    for (let i = 0; i < n; i++) {
      const e = edges[Math.floor(Math.random() * edges.length)];
      // mostly ride internal links; occasionally show internet egress
      SOCMap.flowPacket(e.from, e.to, 'ambient');
    }
  }, 600);

  // ---------------- meta / topbar / KPIs ----------------
  function buildSpeeds(speeds) {
    const c = $('#speed-controls'); if (!c) return; c.innerHTML = '';
    speeds.forEach((sp) => {
      const b = el('button', 'speed-btn', `${sp}×`);
      b.dataset.speed = sp;
      b.onclick = () => Net.send('set_speed', { speed: sp });
      c.appendChild(b);
    });
  }
  function renderMeta() {
    const mt = S.meta;
    $('#clock').textContent = mt.clock || '--:--:--';
    const dp = $('#dp-label'); if (dp && S.live && mt.clock) dp.textContent = 'Live · ' + mt.clock.slice(0, 5);
    $$('#speed-controls .speed-btn').forEach((b) => b.classList.toggle('active', +b.dataset.speed === mt.speed));
    $('#t2-count').textContent = S.messages.length;
    renderKPIs();
  }
  const THREAT_LABEL = { dormant: 'Quiet', active: 'Active intrusion', spreading: 'SPREADING', stopped: 'Contained', gaveup: 'Withdrawn', succeeded: 'BREACHED' };
  function renderKPIs() {
    const mt = S.meta;
    const open = [...S.alerts.values()].filter((a) => a.status === 'new' || a.status === 'breached');
    const crit = open.filter((a) => a.severity === 'critical').length;
    const high = open.filter((a) => a.severity === 'high').length;
    const breach = [...S.alerts.values()].filter((a) => a.status === 'breached').length;
    // events/sec over the last 5 real seconds
    const now = Date.now(); S.epsBuf = (S.epsBuf || []).filter((x) => now - x.t < 5000);
    const eps = S.epsBuf.reduce((s, x) => s + x.n, 0) / 5;
    set('#kpi-open', open.length); set('#kpi-crit', crit); set('#kpi-high', high); set('#kpi-breach', breach);
    const epsEl = $('#kpi-eps'); if (epsEl) epsEl.innerHTML = `${eps.toFixed(1)}<span class="kpi-unit">/s</span>`;
    const trust = Math.round((mt.trust ?? 1) * 100);
    const tEl = $('#kpi-trust'); if (tEl) tEl.innerHTML = `${trust}<span class="kpi-unit">%</span>`;
    const tf = $('#trust-fill'); if (tf) tf.style.width = trust + '%';
    set('#kpi-score', mt.points ?? 0);
    const st = $('#kpi-status'); if (st) { st.textContent = THREAT_LABEL[mt.attackStatus] || '—'; st.style.color = (mt.attackStatus === 'succeeded' || mt.attackStatus === 'spreading') ? 'var(--crit)' : (mt.attackStatus === 'stopped' || mt.attackStatus === 'gaveup') ? 'var(--ok)' : (mt.attackStatus === 'active') ? 'var(--high)' : 'var(--text2)'; }
    function set(sel, v) { const e = $(sel); if (e) e.textContent = v; }
  }

  // ---------------- alerts ----------------
  function recomputeImplicated() {
    const set = new Set();
    for (const a of S.alerts.values()) {
      if (a.status === 'dismissed') continue;
      (a.entities.hosts || []).forEach((h) => set.add(h));
    }
    SOCMap.setImplicated([...set]);
  }

  function slaInfo(a) {
    const rem = (a.slaDeadline ?? 0) - (S.meta.simTime ?? 0);
    if (a.status === 'breached') return { txt: 'BREACHED', cls: 'danger' };
    if (a.status === 'escalated') return { txt: 'sent', cls: 'done' };
    if (a.status === 'dismissed') return { txt: 'dismissed', cls: 'done' };
    const pct = rem / (a.sla || 1);
    const cls = rem <= 0 ? 'danger' : pct < 0.15 ? 'danger' : pct < 0.35 ? 'warn' : '';
    const m = Math.max(0, Math.floor(rem / 60)), s = Math.max(0, Math.floor(rem % 60));
    return { txt: `${m}:${String(s).padStart(2, '0')}`, cls };
  }

  function renderAlerts() {
    const list = $('#alert-list'); if (!list) return;
    const filter = $('#alert-filter').value, sort = $('#alert-sort').value;
    let arr = [...S.alerts.values()];
    arr = arr.filter((a) => {
      if (filter === 'all') return true;
      if (filter === 'open') return a.status === 'new' || a.status === 'breached';
      return a.status === filter;
    });
    arr.sort((a, b) => {
      if (sort === 'severity') return (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || (a.slaDeadline - b.slaDeadline);
      if (sort === 'time') return b.ts - a.ts;
      // sla
      const ra = (a.slaDeadline ?? 0), rb = (b.slaDeadline ?? 0);
      const openA = a.status === 'new' ? 0 : 1, openB = b.status === 'new' ? 0 : 1;
      return (openA - openB) || (ra - rb);
    });
    $('#alert-count').textContent = arr.filter((a) => a.status === 'new' || a.status === 'breached').length;
    list.innerHTML = '';
    for (const a of arr) {
      const sla = slaInfo(a);
      const tr = el('tr', `incident-row sev-${a.severity} st-${a.status}`);
      if (a.id === S.selectedAlertId) tr.classList.add('selected');
      const ent = [...(a.entities.hosts || []), ...(a.entities.ips || []), ...(a.entities.users || [])].slice(0, 3).join(' · ');
      const mitre = (a.kb && a.kb.mitre) ? a.kb.mitre : '';
      const sub = [mitre, ent].filter(Boolean).join('  ·  ');
      tr.innerHTML =
        `<td class="c-sev"><span class="sev-cell sev-${a.severity}"><span class="sev-dot"></span><span class="sev-txt">${a.severity}</span></span></td>` +
        `<td class="c-time it-time">${fmtClock(a.ts)}</td>` +
        `<td class="c-rule"><div class="it-rule" title="${esc(a.title)}">${esc(a.title)}</div><div class="it-ent" title="${esc(sub)}">${esc(sub)}</div></td>` +
        `<td class="c-sla"><span class="sla-pill ${sla.cls}">${sla.txt}</span></td>` +
        `<td class="c-st"><span class="st-pill ${a.status}">${esc(a.status)}</span></td>`;
      tr.onclick = () => selectAlert(a.id);
      list.appendChild(tr);
    }
    renderKPIs();
  }
  $('#alert-filter').onchange = renderAlerts;
  $('#alert-sort').onchange = renderAlerts;

  function selectAlert(id) {
    S.selectedAlertId = id;
    const a = S.alerts.get(id);
    renderAlerts();
    renderAlertDetail(a);
    prefillTicket(a);
    switchTab('ticket');
    // Load the alert's evidence into the investigation view.
    if (a && a.evidenceEventIds && a.evidenceEventIds.length) {
      Net.send('get_events', { ids: a.evidenceEventIds, forAlert: id });
      setPivotCrumbs([{ kind: 'alert', value: a.title }]);
    }
  }

  // ---------------- alert detail + KB ----------------
  function renderAlertDetail(a) {
    const box = $('#alert-detail');
    if (!a) { box.innerHTML = '<div class="muted small pad">Select an alert.</div>'; return; }
    const kb = S.kb[a.kbKey];
    box.innerHTML =
      `<h3 class="pill-${a.severity}" style="display:inline-block;padding:2px 10px;border-radius:5px">${esc(a.title)}</h3>` +
      `<div class="ad-row"><div class="ad-label">Summary</div>${esc(a.summary)}</div>` +
      `<div class="ad-row"><div class="ad-label">Entities</div>${renderEntityChips(a.entities)}</div>` +
      (a.kb ? `<div class="ad-row"><div class="ad-label">MITRE ATT&CK</div><span class="mitre-tag">${esc(a.kb.mitre || '')}</span></div>` : '') +
      (kb ? renderKb(kb) : '');
    $$('.chip[data-pivot]', box).forEach((c) => c.onclick = () => pivotFromChip(c.dataset.pivkind, c.dataset.pivot));
  }
  function renderEntityChips(ent) {
    let h = '';
    (ent.hosts || []).forEach((x) => h += `<span class="chip" data-pivkind="host" data-pivot="${esc(x)}">🖥 ${esc(x)}</span>`);
    (ent.ips || []).forEach((x) => h += `<span class="chip" data-pivkind="ip" data-pivot="${esc(x)}">🌐 ${esc(x)}</span>`);
    (ent.users || []).forEach((x) => h += `<span class="chip" data-pivkind="user" data-pivot="${esc(x)}">👤 ${esc(x)}</span>`);
    return h || '<span class="muted small">none</span>';
  }
  function renderKb(kb) {
    return `<div class="ad-kb">` +
      `<h4>What it means</h4><div class="muted">${esc(kb.means)}</div>` +
      `<h4>Benign look-alike</h4><div class="muted">${esc(kb.benign)}</div>` +
      `<h4>What to check next</h4><ul>${(kb.check || []).map((c) => `<li>${esc(c)}</li>`).join('')}</ul>` +
      `</div>`;
  }

  // ---------------- ticket ----------------
  function prefillTicket(a) {
    $('#ticket-empty').classList.add('hidden');
    $('#ticket-form').classList.remove('hidden');
    if (!a) return;
    $('#tf-alert').innerHTML = `<b>${esc(a.title)}</b><br><span class="muted small">${esc(a.summary)}</span>`;
    $('#tf-severity').value = a.severity;
    $('#tf-hosts').value = (a.entities.hosts || []).join(', ');
    $('#tf-accounts').value = (a.entities.users || []).join(', ');
    $('#tf-ips').value = (a.entities.ips || []).join(', ');
    // suggest an action
    const suggest = { web_shell: 'isolate_host', ransomware: 'isolate_host', ransom_note: 'isolate_host', cred_dump: 'reset_credentials', remote_exec: 'isolate_host', brute_force: 'block_ip', web_injection: 'monitor', exfiltration: 'isolate_host', cryptomining: 'isolate_host', anomalous_login: 'disable_account', suspicious_email: 'monitor', discovery: 'monitor', persistence: 'isolate_host', offhours_logon: 'monitor', port_scan: 'monitor' }[a.kbKey];
    if (suggest) $('#tf-action').value = suggest;
  }

  $('#ticket-form').onsubmit = (e) => {
    e.preventDefault();
    const f = e.target;
    const verdict = f.verdict.value;
    const ticket = {
      alertId: S.selectedAlertId,
      verdict,
      severity: $('#tf-severity').value,
      recommendedAction: $('#tf-action').value,
      affectedHosts: splitList($('#tf-hosts').value),
      affectedAccounts: splitList($('#tf-accounts').value),
      affectedIps: splitList($('#tf-ips').value),
      evidenceEventIds: [...S.evidence.keys()],
      narrative: $('#tf-notes').value,
    };
    Net.send('submit_ticket', { ticket });
  };
  function splitList(s) { return (s || '').split(',').map((x) => x.trim()).filter(Boolean); }

  function onTicketResult(m) {
    const r = m.result && m.result.result;
    if (!r) return;
    // No verdict or quality is revealed here — Tier 2 reviews and reports back.
    const label = r.caseId || 'Case';
    toast(r.kind === 'dismissal'
      ? `${label} sent to Tier 2 QA — awaiting review.`
      : `${label} submitted to Tier 2 — under review. They'll report back with the disposition and actions.`);
    if (m.meta) { S.meta = m.meta; renderMeta(); }
    // clear evidence tray + notes after submit
    S.evidence.clear(); renderEvidence(); $('#tf-notes').value = '';
    renderTier2(); switchTab('tier2');
  }

  $('#btn-hint').onclick = () => { if (S.selectedAlertId) Net.send('buy_hint', { alertId: S.selectedAlertId }); else toast('Select an alert first.'); };
  function onHintResult(m) {
    if (m.error) return toast(m.error);
    const lines = (m.hint && m.hint.lines) || [];
    toast('💡 ' + lines.join('  ·  '));
    if (m.points != null) { S.meta.points = m.points; renderMeta(); }
  }

  // ---------------- Tier 2 feed ----------------
  function renderTier2() {
    const feed = $('#t2-feed');
    if (!S.messages.length) { feed.innerHTML = '<div class="muted small pad">Tier 2 messages will appear here.</div>'; return; }
    feed.innerHTML = '';
    S.messages.slice(-60).forEach((m) => {
      const div = el('div', `t2-msg ${m.kind || 'ok'}`);
      div.innerHTML = `<span class="t2-time">${fmtClock(m.ts)}</span>${esc(m.text)}`;
      feed.appendChild(div);
    });
    feed.scrollTop = feed.scrollHeight;
    $('#t2-count').textContent = S.messages.length;
  }

  // ---------------- investigation / logs ----------------
  function currentLogEvents() {
    if (!S.live && S.viewEvents) return S.viewEvents;
    let arr = S.events;
    if (S.searchSource) arr = arr.filter((e) => e.source === S.searchSource);
    return arr.slice(-400);
  }
  function renderLogs() {
    const body = $('#log-body'); if (!body) return;
    const evs = currentLogEvents();
    renderHistogram(evs);
    body.innerHTML = '';
    for (const ev of evs) {
      const isExp = S.expanded.has(ev.id);
      const tr = el('tr', 'log-row'); tr.dataset.id = ev.id;
      if (S.evidence.has(ev.id)) tr.classList.add('selected');
      tr.innerHTML =
        `<td class="c-sel"><input type="checkbox" class="log-check" ${S.evidence.has(ev.id) ? 'checked' : ''}></td>` +
        `<td class="c-exp"><span class="exp-caret">${isExp ? '▾' : '▸'}</span></td>` +
        `<td class="c-time">${fmtClock(ev.ts)}</td>` +
        `<td class="c-src"><span class="src-tag src-${ev.source}">${ev.source}</span></td>` +
        `<td class="c-host">${esc(ev.host)}</td>` +
        `<td class="c-msg"><span class="log-msg">${esc(ev.message)}</span></td>` +
        `<td class="c-piv"><div class="piv-btns">${pivBtns(ev)}</div></td>`;
      tr.querySelector('.log-check').onchange = (e) => toggleEvidence(ev, e.target.checked);
      tr.querySelector('.exp-caret').onclick = () => { if (S.expanded.has(ev.id)) S.expanded.delete(ev.id); else S.expanded.add(ev.id); renderLogs(); };
      $$('.piv', tr).forEach((b) => b.onclick = () => pivotFromChip(b.dataset.k, b.dataset.v));
      body.appendChild(tr);
      if (isExp) {
        const dr = el('tr', 'log-detail');
        dr.innerHTML = `<td></td><td></td><td colspan="5">${fieldGrid(ev)}</td>`;
        body.appendChild(dr);
        $$('.fpiv', dr).forEach((b) => b.onclick = () => pivotFromChip(b.dataset.k, b.dataset.v));
      }
    }
    if (S.live) { const w = $('.panel-logs .table-scroll'); if (w) w.scrollTop = w.scrollHeight; }
  }
  // Splunk-style field extraction shown when a result row is expanded.
  function fieldGrid(ev) {
    const rows = [];
    const add = (k, v, piv) => { if (v == null || v === '') return; rows.push(`<div class="field-kv"><span class="field-k">${esc(k)}</span><span class="field-v">${esc(v)}${piv ? ` <span class="fpiv" data-k="${piv.k}" data-v="${esc(piv.v)}" title="pivot">⧉</span>` : ''}</span></div>`); };
    add('_time', fmtClock(ev.ts));
    add('source', ev.source);
    add('host', ev.host, { k: 'host', v: ev.host });
    const f = ev.fields || {};
    for (const [k, v] of Object.entries(f)) {
      if (v == null || v === '') continue;
      let piv = null;
      if (k === 'srcIp' || k === 'dstIp') piv = { k: 'ip', v };
      else if (k === 'user') piv = { k: 'user', v };
      add(k, typeof v === 'object' ? JSON.stringify(v) : v, piv);
    }
    return `<div class="field-grid">${rows.join('')}</div>`;
  }
  // Event-volume histogram over the currently displayed results.
  function renderHistogram(evs) {
    const host = $('#log-histogram'); if (!host) return;
    if (!evs || !evs.length) { host.innerHTML = ''; const l = $('#hist-label'); if (l) l.textContent = ''; return; }
    const N = 44;
    const tmin = evs[0].ts, tmax = evs[evs.length - 1].ts;
    const span = Math.max(1, tmax - tmin);
    const buckets = new Array(N).fill(0);
    for (const e of evs) { const i = Math.min(N - 1, Math.floor((e.ts - tmin) / span * N)); buckets[i]++; }
    const max = Math.max(1, ...buckets);
    host.innerHTML = buckets.map((c) => `<div class="hbar${c / max > 0.75 ? ' hot' : ''}" style="height:${Math.max(4, Math.round((c / max) * 100))}%"></div>`).join('');
    const l = $('#hist-label'); if (l) l.textContent = `${evs.length} events · ${fmtClock(tmin)}–${fmtClock(tmax)}`;
  }
  function pivBtns(ev) {
    let h = '';
    if (ev.srcIp) h += `<span class="piv" data-k="ip" data-v="${esc(ev.srcIp)}">IP</span>`;
    if (ev.user) h += `<span class="piv" data-k="user" data-v="${esc(ev.user)}">user</span>`;
    if (ev.host) h += `<span class="piv" data-k="host" data-v="${esc(ev.host)}">host</span>`;
    h += `<span class="piv" data-k="time" data-v="${ev.ts}">±time</span>`;
    return h;
  }

  function pivotFromChip(kind, value) {
    S.live = false; setLiveBtn();
    const q = { limit: 400 };
    if (kind === 'ip') q.ip = value;
    else if (kind === 'user') q.user = value;
    else if (kind === 'host') q.host = value;
    else if (kind === 'time') { q.sinceTs = +value - 120; q.untilTs = +value + 120; }
    if (S.searchSource) q.source = S.searchSource;
    if (S.searchText) q.q = S.searchText;
    S.lastQuery = q;
    setPivotCrumbs([{ kind, value: kind === 'time' ? `±120s @ ${fmtClock(+value)}` : value }]);
    Net.send('search', { query: q });
  }

  function setPivotCrumbs(crumbs) {
    const c = $('#pivot-crumbs'); c.innerHTML = '';
    crumbs.forEach((cr) => {
      const span = el('span', 'crumb', `${esc(cr.kind)}: ${esc(cr.value)} <span class="x">✕</span>`);
      span.querySelector('.x').onclick = goLive;
      c.appendChild(span);
    });
  }

  const searchInput = $('#log-search');
  let searchTimer = null;
  searchInput.oninput = () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      S.searchText = searchInput.value.trim();
      if (!S.searchText && !S.pivots.length) { goLive(); return; }
      S.live = false; setLiveBtn();
      const q = { q: S.searchText, limit: 400 };
      if (S.searchSource) q.source = S.searchSource;
      S.lastQuery = q;
      setPivotCrumbs(S.searchText ? [{ kind: 'search', value: S.searchText }] : []);
      Net.send('search', { query: q });
    }, 250);
  };
  $('#log-source').onchange = (e) => {
    S.searchSource = e.target.value;
    if (S.live) renderLogs();
    else searchInput.oninput();
  };
  $('#log-live').onclick = goLive;
  function goLive() { S.live = true; S.viewEvents = null; S.searchText = ''; searchInput.value = ''; setPivotCrumbs([]); setLiveBtn(); renderLogs(); }
  function setLiveBtn() {
    $('#log-live').classList.toggle('active', S.live);
    const dp = $('#dp-label'); if (dp) dp.textContent = S.live ? 'Live' : 'Filtered';
  }

  // ---------------- evidence tray ----------------
  function toggleEvidence(ev, on) {
    if (on) S.evidence.set(ev.id, ev); else S.evidence.delete(ev.id);
    renderEvidence();
    // reflect in row
    const tr = $(`.log-row[data-id="${ev.id}"]`); if (tr) tr.classList.toggle('selected', on);
  }
  function renderEvidence() {
    const tray = $('#evidence-tray');
    if (!S.evidence.size) { tray.innerHTML = '<span class="muted small">No evidence attached. Tick log lines in the investigation view.</span>'; return; }
    tray.innerHTML = '';
    for (const ev of S.evidence.values()) {
      const chip = el('div', 'ev-chip');
      chip.innerHTML = `<span title="${esc(ev.message)}">${fmtClock(ev.ts)} ${esc(ev.source)} · ${esc(ev.host)}</span><span class="rm">✕</span>`;
      chip.querySelector('.rm').onclick = () => toggleEvidence(ev, false);
      tray.appendChild(chip);
    }
  }

  // ---------------- host click (map) ----------------
  let hostMenu = null;
  function onHostClick(hostId, oe) {
    closeHostMenu();
    const h = S.hostsById[hostId];
    hostMenu = el('div', 'modal-card');
    hostMenu.style.cssText = 'position:fixed;z-index:70;width:230px;padding:0;';
    const x = Math.min((oe?.clientX || 200), window.innerWidth - 250);
    const y = Math.min((oe?.clientY || 200), window.innerHeight - 260);
    hostMenu.style.left = x + 'px'; hostMenu.style.top = y + 'px';
    hostMenu.innerHTML =
      `<div class="modal-head" style="padding:10px 12px"><h2 style="font-size:13px">${esc(h.hostname)}</h2><button class="btn btn-ghost btn-sm" id="hm-x">✕</button></div>` +
      `<div style="padding:10px 12px;font-size:11px" class="muted">${esc(h.type)} · ${esc(h.ip)} · ${esc(h.os)}${h.crownJewel ? ' · ⭐ crown jewel' : ''}</div>` +
      `<div style="padding:0 12px 12px;display:flex;flex-direction:column;gap:6px">` +
      `<button class="btn btn-sm" data-a="investigate">🔎 Investigate logs</button>` +
      `<button class="btn btn-sm" data-a="add">➕ Add to ticket hosts</button>` +
      `<div style="display:flex;gap:5px;flex-wrap:wrap">` +
      `<button class="btn btn-sm" data-a="suspected">Suspected</button>` +
      `<button class="btn btn-sm" data-a="confirmed">Confirmed</button>` +
      `<button class="btn btn-sm" data-a="contained">Contained</button>` +
      `<button class="btn btn-sm" data-a="clear">Clear</button>` +
      `</div></div>`;
    document.body.appendChild(hostMenu);
    $('#hm-x', hostMenu).onclick = closeHostMenu;
    $$('[data-a]', hostMenu).forEach((b) => b.onclick = () => {
      const a = b.dataset.a;
      if (a === 'investigate') pivotFromChip('host', hostId);
      else if (a === 'add') { const inp = $('#tf-hosts'); const cur = splitList(inp.value); if (!cur.includes(hostId)) cur.push(hostId); inp.value = cur.join(', '); toast(`Added ${hostId} to ticket.`); }
      else { Net.send('tag_host', { hostId, tag: a }); SOCMap.setTag(hostId, a === 'clear' ? null : a); }
      closeHostMenu();
    });
  }
  function closeHostMenu() { if (hostMenu) { hostMenu.remove(); hostMenu = null; } }
  document.addEventListener('click', (e) => { if (hostMenu && !hostMenu.contains(e.target) && !e.target.closest('#cy')) closeHostMenu(); });

  // ---------------- tabs ----------------
  $$('#right-tabs .tab').forEach((t) => t.onclick = () => switchTab(t.dataset.tab));
  function switchTab(name) {
    $$('#right-tabs .tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $$('.tab-body').forEach((b) => b.classList.toggle('hidden', b.dataset.body !== name));
    if (name === 'detail') renderAlertDetail(S.alerts.get(S.selectedAlertId));
  }

  // ---------------- speed controls (keyboard shortcut) ----------------
  document.addEventListener('keydown', (e) => {
    if (/input|textarea|select/i.test(document.activeElement.tagName)) return;
    const map = { Digit1: 1, Digit2: 2, Digit4: 4, Digit8: 8 };
    if (map[e.code]) { e.preventDefault(); Net.send('set_speed', { speed: map[e.code] }); }
  });
  $('#briefing-dismiss').onclick = () => { $('#briefing').classList.add('hidden'); };

  // ---------------- Kibana left nav ----------------
  $$('.knav-item').forEach((b) => b.onclick = () => {
    const nav = b.dataset.nav;
    if (nav === 'kb') return openKb();
    if (nav === 'actors') return openDossiers();
    if (nav === 'report') return Net.send('get_report');
    if (nav === 'new') return toStartScreen();
    $$('.knav-item').forEach((x) => x.classList.toggle('active', x === b));
    const panelSel = { overview: '.panel-alerts', incidents: '.panel-alerts', investigate: '.panel-logs', network: '.panel-map', cases: '.panel-ticket' }[nav];
    if (panelSel) { const p = $(panelSel); if (p) { p.classList.add('flash'); setTimeout(() => p.classList.remove('flash'), 600); if (nav === 'investigate') $('#log-search').focus(); } }
  });

  // ---------------- Discover refresh (KQL bar) ----------------
  $('#log-refresh').onclick = () => {
    if (S.live) { renderLogs(); return; }
    // re-run the current query/pivot
    if (S.lastQuery) Net.send('search', { query: S.lastQuery });
    else renderLogs();
  };

  // ---------------- modals ----------------
  $('#modal-close').onclick = () => $('#modal').classList.add('hidden');
  function openModal(title, html) { $('#modal-title').textContent = title; $('#modal-body').innerHTML = html; $('#modal').classList.remove('hidden'); return $('#modal-body'); }

  function openKb() {
    const html = Object.entries(S.kb).map(([k, v]) =>
      `<div class="kb-entry"><h3>${esc(v.title)} <span class="mitre-tag">${esc(v.mitre)}</span></h3>` +
      `<h4>What it means</h4><div class="muted">${esc(v.means)}</div>` +
      `<h4>Benign look-alike</h4><div class="muted">${esc(v.benign)}</div>` +
      `<h4>What to check</h4><ul>${(v.check || []).map((c) => `<li>${esc(c)}</li>`).join('')}</ul></div>`
    ).join('');
    openModal('📖 Knowledge Base — Detection Explainers', html);
  }

  function openDossiers() { if (!S.dossiers.length) Net.send('get_dossiers'); setTimeout(renderDossiers, 60); }
  function renderDossiers() {
    const html = S.dossiers.map((d) =>
      `<div class="dossier"><div class="arch">${esc(d.archetype)}</div><h3>${esc(d.name)}</h3><div class="muted">${esc(d.summary)}</div>` +
      `<dl>` +
      `<dt>Objective</dt><dd>${esc(d.objective)}</dd>` +
      `<dt>Tooling</dt><dd>${esc(d.tooling)}</dd>` +
      `<dt>Lateral style</dt><dd>${esc(d.lateralStyle)}</dd>` +
      `<dt>Schedule</dt><dd>${esc(d.schedule)}</dd>` +
      `<dt>Infrastructure</dt><dd>${esc(d.infraHint)}</dd>` +
      `<dt>Initial access</dt><dd>${esc((d.initialAccess || []).join(', '))}</dd>` +
      `<dt>Persistence depth</dt><dd>${esc(d.persistenceDepth)} mechanism(s)</dd>` +
      `<dt>Adaptability</dt><dd>${esc(d.adaptability)}</dd>` +
      `<dt>Preferred malware</dt><dd>${(d.malware || []).map((mm) => `${esc(mm.name)} <span class="muted">(${esc(mm.category)}${mm.ext ? ', ext ' + esc(mm.ext) : ''})</span>`).join(', ')}</dd>` +
      `<dt>Calling card</dt><dd class="cc">${esc(d.callingCard)}</dd>` +
      `</dl>` +
      `<h4 style="margin-top:10px;font-size:11px;color:var(--accent)">Attribution hints</h4><ul class="muted" style="margin:4px 0;padding-left:18px">${(d.attributionHints || []).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` +
      `</div>`
    ).join('');
    openModal('🎭 Threat Actor Dossiers — Read up and attribute', html || '<div class="muted">No dossiers.</div>');
  }

  function toStartScreen() { $('#modal').classList.add('hidden'); $('#console').classList.add('hidden'); $('#start-screen').classList.remove('hidden'); renderLevels(); }

  function openReport(r) {
    if (!r) return;
    const m = r.metrics, o = r.outcome, sc = r.score;
    if (S.level && sc && sc.grade) { saveProgress(S.level.id, sc.grade); renderLevels(); }
    const metric = (v, l) => `<div class="metric"><div class="m-val">${v}</div><div class="m-lbl">${l}</div></div>`;
    let html = `<div class="report-score"><div class="grade-badge grade-${sc.grade}">${sc.grade}</div>` +
      `<div><div style="font-size:18px;font-weight:700">${sc.points} pts — ${esc(sc.verdict)}</div>` +
      `<div class="muted" style="margin-top:6px">Attacker: <b>${esc(r.attacker.name)}</b> (${esc(r.attacker.archetype)}) · objective: ${esc(r.attacker.objective)} · malware: ${esc(r.attacker.family || '—')} (${esc(r.attacker.familyType || '')})</div>` +
      `<div class="muted">Outcome: <b>${esc(o.status)}</b> — ${esc(o.reason || r.endReason)}${o.couldHaveStoppedAt ? ` · earliest stop: <b>${esc(o.couldHaveStoppedAt.stage)}</b> @ ${esc(o.couldHaveStoppedAt.clock)}` : ''}</div>` +
      (r.attacker.callingCard ? `<div class="muted cc" style="color:var(--warn)">Calling card left: ${esc(r.attacker.callingCard)}</div>` : '') +
      `</div></div>`;

    html += `<div class="metrics-grid">` +
      metric(fmtDur(m.dwellSeconds), 'Dwell time') +
      metric(m.crownJewelsHit, 'Crown jewels hit') +
      metric(m.infectedCount, 'Hosts impacted') +
      metric(`${m.businessDisruptionPct ?? 0}%`, `Business disruption${m.disruptionLabel ? ' — ' + m.disruptionLabel : ''}`) +
      metric(m.detectionCoverage.detectedPct + '%', 'Steps rule-detected') +
      metric(m.detectionCoverage.escalatedPct + '%', 'Steps you escalated') +
      metric(Math.round(m.avgTicketQuality * 100) + '%', 'Avg ticket quality') +
      metric(m.falseEscalations, 'False escalations') +
      metric(m.breachedMaliciousAlerts, 'Missed (SLA breach)') +
      metric(m.hintsUsed, 'Hints used') +
      metric(Math.round(m.trust * 100) + '%', 'Final Tier 2 trust') +
      `</div>`;

    html += `<h3 style="margin:18px 0 6px">Attacker actions vs. what you saw</h3>` +
      `<div class="muted small" style="margin-bottom:8px">Red rows are steps that produced an observable log line you could have caught. The exact revealing log line is shown.</div>` +
      `<table class="timeline-tbl"><thead><tr><th>Time</th><th>Stage / Technique</th><th>Host</th><th>Detection</th><th>Revealing evidence</th></tr></thead><tbody>`;
    for (const s of r.timeline) {
      const tag = s.escalated ? '<span class="tag-dot tag-caught">escalated</span>' : s.detectedByRule ? '<span class="tag-dot tag-seen">alerted, not escalated</span>' : '<span class="tag-dot tag-missed">no detection</span>';
      const rowcls = s.escalated ? 'tl-caught' : (!s.detectedByRule ? 'tl-missed' : '');
      html += `<tr class="${rowcls}"><td>${esc(s.clock)}</td>` +
        `<td><b>${esc(s.stage)}</b><br><span class="mitre-tag">${esc(s.mitre || '')}</span> ${esc(s.technique || '')}</td>` +
        `<td>${esc(s.host || '—')}</td><td>${tag}</td>` +
        `<td>${s.revealingLogLine ? `<span class="tl-logline">${esc(s.revealingLogLine)}</span>` : '<span class="muted small">—</span>'}</td></tr>`;
    }
    html += `</tbody></table>`;

    if (r.playerActions && r.playerActions.length) {
      html += `<h3 style="margin:18px 0 6px">Your cases</h3><table class="timeline-tbl"><thead><tr><th>Case</th><th>Time</th><th>Detection</th><th>Your call</th><th>Action</th><th>Tier 2 disposition</th><th>Quality</th></tr></thead><tbody>`;
      const DISP = { true_positive: '<span class="tag-dot tag-caught">true positive</span>', false_positive: '<span class="tag-dot tag-seen">false positive</span>', under_review: '<span class="muted small">under review</span>' };
      for (const p of r.playerActions) html += `<tr><td class="mono">${esc(p.caseId || '')}</td><td>${esc(p.clock)}</td><td>${esc(p.alertTitle)}</td><td>${esc(p.verdict === 'false_positive' ? 'false positive' : 'escalate')}</td><td>${esc(p.action || '—')}</td><td>${DISP[p.disposition] || '—'}</td><td>${p.q != null ? Math.round(p.q * 100) + '%' : '—'}</td></tr>`;
      html += `</tbody></table>`;
    }

    html += `<div style="margin-top:20px;display:flex;gap:10px"><button class="btn btn-primary" id="rp-again">▶ New Shift</button><button class="btn btn-ghost" id="rp-close">Close</button></div>`;
    const body = openModal('📊 After-Action Report', html);
    $('#rp-again', body).onclick = toStartScreen;
    $('#rp-close', body).onclick = () => $('#modal').classList.add('hidden');
  }

  // ---------------- utils ----------------
  function fmtClock(sec) {
    sec = Math.max(0, Math.floor(sec || 0)) % 86400;
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = Math.floor(sec % 60);
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }
  function fmtDur(sec) { sec = Math.max(0, Math.round(sec || 0)); if (sec < 60) return sec + 's'; const m = Math.floor(sec / 60), s = sec % 60; if (m < 60) return s ? `${m}m ${s}s` : `${m}m`; const h = Math.floor(m / 60); return `${h}h ${m % 60}m`; }

  let toastTimer = null;
  function toast(msg) {
    const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.add('hidden'), 3200);
  }

  function renderAll() { renderMeta(); renderAlerts(); renderLogs(); renderTier2(); renderEvidence(); recomputeImplicated(); }
})();
