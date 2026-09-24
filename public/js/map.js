// map.js — Interactive network map with fog of war (Cytoscape.js).
//
// Shows the known asset inventory (the analyst's CMDB) laid out by zone. Hosts
// light up when alerts implicate them and can be tagged suspected/confirmed/
// contained. Observed impact (ransomware "dark", worm "spread", exfil, mining) is
// revealed and animated as it happens; footholds the player hasn't detected stay
// hidden — the map reflects what the player knows, not ground truth.
(function () {
  let cy = null;
  let adj = {}; // undirected adjacency (nodeId -> Set of neighbours) for packet routing
  const ZONE_Y = { internet: 40, dmz: 150, corp: 300, servers: 300, mgmt: 470 };
  const ZONE_X = { corp: [40, 480], servers: [560, 980] };

  // Elastic (EUI) palette to match the console theme.
  const ZONE_COLOR = { internet: '#535966', dmz: '#da8b45', corp: '#36a2ef', servers: '#54b399', mgmt: '#f68fbe' };

  function laneNodes(hosts) {
    const byZone = {};
    for (const h of hosts) (byZone[h.zone] ||= []).push(h);
    const positions = {};
    // internet pseudo-node
    positions['internet'] = { x: 510, y: ZONE_Y.internet };
    for (const zone of Object.keys(byZone)) {
      const list = byZone[zone];
      if (zone === 'corp' || zone === 'servers') {
        const [x0, x1] = ZONE_X[zone];
        list.forEach((h, i) => {
          const cols = Math.ceil(Math.sqrt(list.length)) || 1;
          const row = Math.floor(i / cols), col = i % cols;
          const span = (x1 - x0);
          positions[h.id] = { x: x0 + (col + 0.5) * (span / cols), y: ZONE_Y[zone] + row * 70 };
        });
      } else {
        const total = list.length;
        list.forEach((h, i) => { positions[h.id] = { x: 250 + (i - (total - 1) / 2) * 150, y: ZONE_Y[zone] || 300 }; });
      }
    }
    return positions;
  }

  function icon(type) {
    return ({
      'web-server': '🌐', 'vpn-gateway': '🔐', 'mail-server': '✉', 'domain-controller': '🏛',
      'file-server': '📁', 'db-server': '🗄', 'app-server': '⚙', 'backup-server': '💾',
      'jump-host': '🧭', 'workstation': '💻',
    })[type] || '▪';
  }

  function init(el, network, handlers) {
    if (typeof cytoscape === 'undefined') { setTimeout(() => init(el, network, handlers), 200); return; }
    if (cy) { cy.destroy(); cy = null; }
    const positions = laneNodes(network.hosts);

    const nodes = [{ data: { id: 'internet', label: '☁ Internet', zone: 'internet', type: 'internet' }, position: positions['internet'] }];
    for (const h of network.hosts) {
      nodes.push({ data: { id: h.id, label: `${icon(h.type)} ${h.hostname}`, zone: h.zone, type: h.type, crown: h.crownJewel }, position: positions[h.id] || { x: 500, y: 300 } });
    }
    const seen = new Set();
    const edges = [];
    adj = {};
    const link = (a, b) => { (adj[a] ||= new Set()).add(b); (adj[b] ||= new Set()).add(a); };
    for (const e of network.edges) {
      const key = [e.from, e.to].sort().join('|');
      if (seen.has(key)) continue; seen.add(key);
      if (!positions[e.from] && e.from !== 'internet') continue;
      edges.push({ data: { id: `e-${e.from}-${e.to}`, source: e.from, target: e.to } });
      link(e.from, e.to);
    }

    cy = cytoscape({
      container: el,
      elements: { nodes, edges },
      minZoom: 0.3, maxZoom: 2.5, wheelSensitivity: 0.2,
      style: [
        { selector: 'node', style: {
          'background-color': (n) => ZONE_COLOR[n.data('zone')] || '#39424f',
          'background-opacity': 0.18, 'border-width': 2,
          'border-color': (n) => ZONE_COLOR[n.data('zone')] || '#39424f',
          label: 'data(label)', color: '#dfe5ef', 'font-size': 11, 'font-family': 'Roboto Mono, monospace',
          'text-valign': 'bottom', 'text-margin-y': 4, 'text-outline-color': '#141519', 'text-outline-width': 2,
          width: 34, height: 34, shape: 'round-rectangle',
        }},
        { selector: 'node[type="internet"]', style: { shape: 'ellipse', 'background-opacity': 0.25, width: 46, height: 46, 'border-color': '#5f7183', 'background-color': '#39424f' } },
        { selector: 'node[?crown]', style: { 'border-width': 3, 'border-style': 'double' } },
        { selector: 'edge', style: { width: 1.2, 'line-color': '#343741', 'curve-style': 'straight', 'target-arrow-shape': 'none', opacity: 0.7 } },
        // Implicated by an alert
        { selector: 'node.implicated', style: { 'background-opacity': 0.4, 'border-color': '#fec514', 'border-width': 3 } },
        // Player tags
        { selector: 'node.tag-suspected', style: { 'border-color': '#fec514', 'border-style': 'dashed', 'border-width': 3 } },
        { selector: 'node.tag-confirmed', style: { 'border-color': '#da8b45', 'border-width': 4 } },
        { selector: 'node.tag-contained', style: { 'border-color': '#36a2ef', 'border-width': 4, 'border-style': 'dotted' } },
        { selector: 'node.tag-clear', style: {} },
        // Observed impact
        { selector: 'node.impact-dark', style: { 'background-color': '#e7664c', 'background-opacity': 0.55, 'border-color': '#e7664c', color: '#fff', 'border-width': 3 } },
        { selector: 'node.impact-spread', style: { 'background-color': '#da8b45', 'background-opacity': 0.6, 'border-color': '#e7664c', 'border-width': 3 } },
        { selector: 'node.impact-exfil', style: { 'background-color': '#f68fbe', 'background-opacity': 0.5, 'border-color': '#f68fbe', 'border-width': 3 } },
        { selector: 'node.impact-mine', style: { 'background-color': '#d6bf57', 'background-opacity': 0.5, 'border-color': '#d6bf57', 'border-width': 3 } },
        { selector: 'node.contained', style: { 'border-style': 'dotted', 'border-color': '#36a2ef', opacity: 0.6 } },
        { selector: 'edge.hot', style: { 'line-color': '#e7664c', width: 2.4, opacity: 1 } },
        // Animated traffic packets travelling along edges.
        { selector: 'node.pkt', style: { label: '', 'text-opacity': 0, events: 'no', 'border-width': 0, width: 7, height: 7, 'background-opacity': 1, 'z-index': 999, shape: 'ellipse' } },
        { selector: 'edge.flowing', style: { 'line-color': '#2c5a57', width: 1.8, opacity: 1 } },
      ],
      layout: { name: 'preset' },
    });

    cy.on('tap', 'node', (evt) => {
      const id = evt.target.id();
      if (id === 'internet') return;
      handlers.onHostClick && handlers.onHostClick(id, evt.originalEvent);
    });
    setTimeout(() => cy.fit(undefined, 40), 60);
  }

  function setImplicated(ids) {
    if (!cy) return;
    cy.nodes().removeClass('implicated');
    ids.forEach((id) => cy.$id(id).addClass('implicated'));
  }
  function setTag(host, tag) {
    if (!cy) return;
    const n = cy.$id(host);
    n.removeClass('tag-suspected tag-confirmed tag-contained tag-clear');
    if (tag) n.addClass('tag-' + tag);
  }
  function setImpact(host, status, contained) {
    if (!cy) return;
    const n = cy.$id(host);
    n.removeClass('impact-dark impact-spread impact-exfil impact-mine');
    const cls = { dark: 'impact-dark', spread: 'impact-spread', exfil: 'impact-exfil', mine: 'impact-mine' }[status];
    if (cls) {
      n.addClass(cls);
      // pulse
      n.animate({ style: { 'border-width': 6 } }, { duration: 220, complete: () => n.animate({ style: { 'border-width': 3 } }, { duration: 400 }) });
      // heat adjacent edges for worm spread
      if (status === 'spread') n.connectedEdges().addClass('hot');
    }
    if (contained) n.addClass('contained');
  }
  function pulse(host) {
    if (!cy) return; const n = cy.$id(host); if (!n) return;
    n.animate({ style: { 'background-opacity': 0.6 } }, { duration: 200, complete: () => n.animate({ style: { 'background-opacity': 0.18 } }, { duration: 500 }) });
  }

  // Shortest path (undirected) between two nodes over the real links, so a packet
  // rides the actual edges instead of cutting across empty space.
  function pathBetween(from, to) {
    if (from === to) return [from];
    if (!adj[from] || !adj[to]) return null;
    const prev = { [from]: null };
    const queue = [from];
    while (queue.length) {
      const cur = queue.shift();
      if (cur === to) break;
      for (const nb of adj[cur] || []) {
        if (!(nb in prev)) { prev[nb] = cur; queue.push(nb); }
      }
    }
    if (!(to in prev)) return null;
    const path = [];
    for (let n = to; n != null; n = prev[n]) path.push(n);
    path.reverse();
    return path.length <= 7 ? path : null; // ignore implausibly long routes
  }

  // Send a packet travelling hop-by-hop along the links from → to. Colour encodes
  // the log source, so the analyst literally watches traffic move across the
  // network along the real firewall-permitted paths.
  const PKT_COLOR = { auth: '#36a2ef', web: '#da8b45', network: '#54b399', dns: '#98a2b3', ambient: '#2c5a57' };
  let pktSeq = 0;
  let pktCount = 0;
  function flowPacket(fromId, toId, kind) {
    if (!cy || pktCount > 70) return;
    const path = pathBetween(fromId, toId);
    if (!path || path.length < 2) return; // no link path → don't float a packet
    const start = cy.$id(path[0]);
    if (!start || start.empty()) return;
    const p0 = start.position();
    const ambient = kind === 'ambient';
    const id = 'pkt-' + (pktSeq++);
    const color = PKT_COLOR[kind] || '#00bfb3';
    const sz = ambient ? 4 : 7;
    let node;
    try {
      node = cy.add({ group: 'nodes', data: { id, pkt: true }, position: { x: p0.x, y: p0.y }, classes: 'pkt', selectable: false, grabbable: false });
      node.style({ 'background-color': color, width: sz, height: sz, 'background-opacity': ambient ? 0.65 : 1 });
    } catch (e) { return; }
    pktCount++;
    const litEdges = [];
    const cleanup = () => { try { node.remove(); } catch (e) {} pktCount--; litEdges.forEach((ed) => { try { ed.removeClass('flowing'); } catch (e) {} }); };

    // Walk each segment of the path in turn.
    const step = (i) => {
      if (i >= path.length - 1) { cleanup(); return; }
      const a = cy.$id(path[i]), b = cy.$id(path[i + 1]);
      if (!a || !b || a.empty() || b.empty()) { cleanup(); return; }
      const pa = a.position(), pb = b.position();
      const dist = Math.hypot(pb.x - pa.x, pb.y - pa.y);
      const dur = Math.max(160, Math.min(520, dist * 1.6));
      if (!ambient) { const ed = a.edgesWith(b); if (ed && ed.length) { ed.addClass('flowing'); litEdges.push(ed); } }
      node.animate({ position: { x: pb.x, y: pb.y } }, { duration: dur, easing: 'linear', complete: () => step(i + 1) });
    };
    step(0);
  }

  // Cytoscape needs a resize + refit when its container becomes visible (e.g. the
  // Network tab is shown after being display:none).
  function resize() { if (!cy) return; try { cy.resize(); cy.fit(undefined, 40); } catch (e) {} }

  window.SOCMap = { init, setImplicated, setTag, setImpact, pulse, flowPacket, resize };
})();
