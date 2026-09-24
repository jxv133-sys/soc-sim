// rng.js — Deterministic, seedable pseudo-random number generator.
//
// Everything procedural in the simulator derives from one of these. Given the
// same seed string, every generator (network, personas, attacker, noise) is
// perfectly reproducible, which is what makes a seed shareable.
//
// We use mulberry32 (a small, fast, well-distributed 32-bit PRNG) seeded from a
// string hash. `fork(label)` derives an independent sub-stream so that, say,
// consuming extra randomness in the persona generator never shifts the sequence
// the attacker generator sees. Keep sub-streams labeled and stable.

function xmur3(str) {
  // Hash a string into a 32-bit seed value.
  let h = 1779033703 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  return function () {
    h = Math.imul(h ^ (h >>> 16), 2246822507);
    h = Math.imul(h ^ (h >>> 13), 3266489909);
    h ^= h >>> 16;
    return h >>> 0;
  };
}

function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export class RNG {
  constructor(seed) {
    this.seed = String(seed);
    const seedFn = xmur3(this.seed);
    this._next = mulberry32(seedFn());
  }

  // Float in [0, 1).
  next() {
    return this._next();
  }

  // Integer in [min, max] inclusive.
  int(min, max) {
    if (max === undefined) {
      max = min;
      min = 0;
    }
    return Math.floor(this.next() * (max - min + 1)) + min;
  }

  // Float in [min, max).
  float(min, max) {
    if (max === undefined) {
      max = min;
      min = 0;
    }
    return this.next() * (max - min) + min;
  }

  // True with probability p.
  bool(p = 0.5) {
    return this.next() < p;
  }

  // Uniformly pick one element.
  pick(arr) {
    return arr[Math.floor(this.next() * arr.length)];
  }

  // Pick n distinct elements (no repeats). Returns fewer if n > arr.length.
  sample(arr, n) {
    const copy = arr.slice();
    this.shuffle(copy);
    return copy.slice(0, Math.min(n, copy.length));
  }

  // Weighted pick. `items` is [{value, weight}, ...] or pass parallel arrays.
  weighted(items) {
    const total = items.reduce((s, it) => s + (it.weight ?? 1), 0);
    let r = this.next() * total;
    for (const it of items) {
      r -= it.weight ?? 1;
      if (r <= 0) return it.value;
    }
    return items[items.length - 1].value;
  }

  // Fisher–Yates in place.
  shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(this.next() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  // Approximate normal distribution (Box–Muller), clamped to be finite.
  gaussian(mean = 0, stddev = 1) {
    let u = 0;
    let v = 0;
    while (u === 0) u = this.next();
    while (v === 0) v = this.next();
    const z = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    return z * stddev + mean;
  }

  // A value in [min,max] biased by a normal curve around the midpoint.
  gaussianRange(min, max, tightness = 4) {
    const mean = (min + max) / 2;
    const stddev = (max - min) / tightness;
    let x = this.gaussian(mean, stddev);
    if (x < min) x = min;
    if (x > max) x = max;
    return x;
  }

  // Derive an independent, deterministic sub-stream.
  fork(label) {
    return new RNG(`${this.seed}::${label}`);
  }

  // Short hex id derived from the stream (stable within a stream position).
  id(prefix = '') {
    const n = Math.floor(this.next() * 0xffffffff).toString(16).padStart(8, '0');
    return prefix ? `${prefix}-${n}` : n;
  }
}

// Generate a fresh, human-typeable seed (adjective-noun-number style).
const SEED_WORDS_A = [
  'amber', 'cobalt', 'silent', 'crimson', 'hollow', 'iron', 'quiet', 'lunar',
  'onyx', 'rapid', 'still', 'vivid', 'north', 'ember', 'frost', 'gilded',
];
const SEED_WORDS_B = [
  'falcon', 'harbor', 'cipher', 'meadow', 'signal', 'anchor', 'summit', 'raven',
  'circuit', 'delta', 'quartz', 'willow', 'beacon', 'canyon', 'orbit', 'thorn',
];

export function randomSeed() {
  const r = new RNG(String(Date.now()) + ':' + Math.random());
  return `${r.pick(SEED_WORDS_A)}-${r.pick(SEED_WORDS_B)}-${r.int(1000, 9999)}`;
}
