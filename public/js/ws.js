// ws.js — thin WebSocket client with auto-reconnect and a message dispatcher.
(function () {
  const listeners = {};
  let ws = null;
  let queue = [];
  let connected = false;

  function url() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    return `${proto}://${location.host}/ws`;
  }

  function connect() {
    ws = new WebSocket(url());
    ws.onopen = () => {
      connected = true;
      emit('__open__', {});
      queue.forEach((m) => ws.send(m));
      queue = [];
    };
    ws.onclose = () => {
      connected = false;
      emit('__close__', {});
      setTimeout(connect, 1200);
    };
    ws.onerror = () => { try { ws.close(); } catch (e) {} };
    ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      emit(msg.type, msg);
    };
  }

  function emit(type, msg) {
    (listeners[type] || []).forEach((fn) => fn(msg));
    (listeners['*'] || []).forEach((fn) => fn(type, msg));
  }

  window.Net = {
    on(type, fn) { (listeners[type] ||= []).push(fn); return this; },
    send(type, payload = {}) {
      const data = JSON.stringify({ type, ...payload });
      if (connected && ws.readyState === WebSocket.OPEN) ws.send(data);
      else queue.push(data);
    },
    get connected() { return connected; },
    connect,
  };
})();
