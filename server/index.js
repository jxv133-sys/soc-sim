// index.js — HTTP + WebSocket server.
//
// Serves the SOC console (public/) and runs one live GameSession per WebSocket
// connection. The simulation ticks on an accelerated wall-clock and streams
// deltas (new logs, alerts, map changes, Tier 2 messages) to the client; the
// client sends player actions (tickets, tags, hints, search, clock control).

import express from 'express';
import { WebSocketServer } from 'ws';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GameSession, REAL_TICK_MS, SPEEDS } from './sim/engine.js';
import { LEVELS, getLevel } from './sim/campaign.js';
import { randomSeed } from './sim/rng.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// Lightweight REST helpers (the live game runs over WebSocket).
app.get('/api/seed', (_req, res) => res.json({ seed: randomSeed() }));
app.get('/api/levels', (_req, res) => res.json({ levels: LEVELS }));
app.get('/api/health', (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

function send(ws, type, payload) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ type, ...payload }));
}

wss.on('connection', (ws) => {
  const conn = { session: null, timer: null };

  function stopLoop() {
    if (conn.timer) { clearInterval(conn.timer); conn.timer = null; }
  }

  function startGame({ seed, level }) {
    stopLoop();
    const finalSeed = seed && String(seed).trim() ? String(seed).trim() : randomSeed();
    const lvl = level ? getLevel(level) : null;
    const opts = lvl
      ? { allowArchetypes: lvl.allowArchetypes || undefined, actor: lvl.allowArchetypes && lvl.allowArchetypes.length === 1 ? lvl.allowArchetypes[0] : undefined, startHour: lvl.startHour }
      : { startHour: 8 };
    const session = new GameSession(finalSeed, opts);
    conn.session = session;

    send(ws, 'game_started', {
      seed: finalSeed,
      level: lvl ? { id: lvl.id, title: lvl.title, focus: lvl.focus, brief: lvl.brief, goals: lvl.goals } : null,
      snapshot: session.fullSnapshot(),
      dossiers: session.dossiers(),
      speeds: SPEEDS,
    });

    // Drive the simulation.
    conn.timer = setInterval(() => {
      if (ws.readyState !== ws.OPEN) { stopLoop(); return; }
      const delta = session.tick();
      const hasContent = delta.events.length || delta.alerts.length || delta.alertUpdates.length || delta.messages.length || delta.map.length || delta.meta || delta.report;
      if (hasContent) send(ws, 'delta', { delta });
      if (session.ended) stopLoop();
    }, REAL_TICK_MS);
  }

  send(ws, 'hello', { levels: LEVELS });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    const s = conn.session;
    switch (msg.type) {
      case 'new_game':
        startGame({ seed: msg.seed, level: msg.level });
        break;
      case 'set_speed':
        if (s) { s.setSpeed(msg.speed); send(ws, 'delta', { delta: { events: [], alerts: [], alertUpdates: [], messages: [], map: [], meta: s.metaSnapshot() } }); }
        break;
      case 'submit_ticket':
        if (s) send(ws, 'ticket_result', { result: s.submitTicket(msg.ticket || {}), meta: s.metaSnapshot() });
        break;
      case 'tag_host':
        if (s) send(ws, 'tag_result', s.tagHost(msg.hostId, msg.tag));
        break;
      case 'buy_hint':
        if (s) send(ws, 'hint_result', s.buyHint(msg.alertId));
        break;
      case 'search':
        if (s) send(ws, 'search_result', { query: msg.query, events: s.search(msg.query || {}) });
        break;
      case 'get_events':
        if (s) send(ws, 'events_result', { forAlert: msg.forAlert || null, events: s.getEventsByIds(msg.ids || []) });
        break;
      case 'get_report':
        if (s) send(ws, 'report', { report: s.afterAction() });
        break;
      case 'get_dossiers':
        if (s) send(ws, 'dossiers', { dossiers: s.dossiers() });
        break;
      default:
        break;
    }
  });

  ws.on('close', () => stopLoop());
  ws.on('error', () => stopLoop());
});

server.listen(PORT, () => {
  console.log(`SOC Analyst Training Simulator running at http://localhost:${PORT}`);
});
