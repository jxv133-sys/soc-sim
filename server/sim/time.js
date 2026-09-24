// time.js — Virtual simulation clock helpers.
//
// Sim time is tracked as an integer number of seconds since the start of the
// simulated day (00:00:00). The engine advances this by a fixed amount each
// tick, scaled by the current speed multiplier. All durations, detection
// windows and SLA timers are expressed in sim-seconds so they scale together.

export const SECONDS_PER_DAY = 24 * 3600;

// Format sim-seconds as HH:MM:SS on a 24h clock (wraps past a day).
export function fmtClock(simSeconds) {
  const s = ((simSeconds % SECONDS_PER_DAY) + SECONDS_PER_DAY) % SECONDS_PER_DAY;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = Math.floor(s % 60);
  return (
    String(h).padStart(2, '0') +
    ':' +
    String(m).padStart(2, '0') +
    ':' +
    String(sec).padStart(2, '0')
  );
}

// Hour of day (0-23) for a given sim-second.
export function hourOf(simSeconds) {
  return Math.floor((simSeconds % SECONDS_PER_DAY) / 3600);
}

// Is `sec` within [start,end) working hours? Handles overnight windows.
export function inHours(simSeconds, startHour, endHour) {
  const h = hourOf(simSeconds);
  if (startHour <= endHour) return h >= startHour && h < endHour;
  // overnight (e.g. 22 -> 6)
  return h >= startHour || h < endHour;
}

// Format a compact duration like "3m 20s" or "45s".
export function fmtDuration(seconds) {
  seconds = Math.max(0, Math.round(seconds));
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return mm ? `${h}h ${mm}m` : `${h}h`;
}
