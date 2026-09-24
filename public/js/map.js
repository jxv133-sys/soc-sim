// map.js — Interactive network map with fog of war (Cytoscape.js).
//
// Shows the known asset inventory (the analyst's CMDB) laid out by zone. Hosts
// light up when alerts implicate them and can be tagged suspected/confirmed/
// contained. Observed impact (ransomware "dark", worm "spread", exfil, mining) is
// revealed and animated as it happens; footholds the player hasn't detected stay
// hidden — the map reflects what the player knows, not ground truth.
(function () {
  let cy = null;
  const ZONE_Y = { internet: 40, dmz: 150, corp: 300, servers: 300, mgmt: 470 };
  const ZONE_X = { corp: [40, 480], servers: [560, 980] };

  const ZONE_COLOR = { internet: '#39424f', dmz: '#e0803a', corp: '#4a90d9', servers: '#37d67a', mgmt: '#b57ce0' };

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
    for (const e of network.edges) {
      const key = [e.from, e.to].sort().join('|');
      if (seen.has(key)) continue; seen.add(key);
      if (!positions[e.from] && e.from !== 'internet') continue;
      edges.push({ data: { id: `e-${e.from}-${e.to}`, source: e.from, target: e.to } });
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
          label: 'data(label)', color: '#cdd7e1', 'font-size': 11, 'font-family': 'JetBrains Mono, monospace',
          'text-valign': 'bottom', 'text-margin-y': 4, 'text-outline-color': '#0a0e13', 'text-outline-width': 2,
          width: 34, height: 34, shape: 'round-rectangle',
        }},
        { selector: 'node[type="internet"]', style: { shape: 'ellipse', 'background-opacity': 0.25, width: 46, height: 46, 'border-color': '#5f7183', 'background-color': '#39424f' } },
        { selector: 'node[?crown]', style: { 'border-width': 3, 'border-style': 'double' } },
        { selector: 'edge', style: { width: 1.2, 'line-color': '#22303f', 'curve-style': 'bezier', 'target-arrow-shape': 'none', opacity: 0.7 } },
        // Implicated by an alert
        { selector: 'node.implicated', style: { 'background-opacity': 0.4, 'border-color': '#ffd43b', 'border-width': 3 } },
        // Player tags
        { selector: 'node.tag-suspected', style: { 'border-color': '#ffb84d', 'border-style': 'dashed', 'border-width': 3 } },
        { selector: 'node.tag-confirmed', style: { 'border-color': '#ff9f43', 'border-width': 4 } },
        { selector: 'node.tag-contained', style: { 'border-color': '#6fb1fc', 'border-width': 4, 'border-style': 'dotted' } },
        { selector: 'node.tag-clear', style: {} },
        // Observed impact
        { selector: 'node.impact-dark', style: { 'background-color': '#ff4d5e', 'background-opacity': 0.55, 'border-color': '#ff4d5e', color: '#fff', 'border-width': 3 } },
        { selector: 'node.impact-spread', style: { 'background-color': '#ff7043', 'background-opacity': 0.6, 'border-color': '#ff4d5e', 'border-width': 3 } },
        { selector: 'node.impact-exfil', style: { 'background-color': '#b57ce0', 'background-opacity': 0.5, 'border-color': '#b57ce0', 'border-width': 3 } },
        { selector: 'node.impact-mine', style: { 'background-color': '#ffd43b', 'background-opacity': 0.5, 'border-color': '#ffd43b', 'border-width': 3 } },
        { selector: 'node.contained', style: { 'border-style': 'dotted', 'border-color': '#6fb1fc', opacity: 0.6 } },
        { selector: 'edge.hot', style: { 'line-color': '#ff4d5e', width: 2.4, opacity: 1 } },
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

  window.SOCMap = { init, setImplicated, setTag, setImpact, pulse };
})();
