import { AppError } from '../shared/errors';
/** JSON scanner rejects duplicate (including escaped) keys, deep inputs and unsafe integers. */
export function strictJson(input: string, maxBytes = 262144): unknown {
  if (Buffer.byteLength(input) > maxBytes) throw new AppError('INVALID_INPUT');
  let p = 0;
  const fail = (): never => { throw new AppError('INVALID_INPUT'); };
  const ws = () => { while (/\s/.test(input[p] ?? '') && p < input.length) p++; };
  const string = (): string => {
    const start = p++;
    while (p < input.length) {
      const c = input[p++];
      if (c === '\\') { p++; continue; }
      if (c === '"') { try { return JSON.parse(input.slice(start, p)) as string; } catch { return fail(); } }
    }
    return fail();
  };
  const value = (depth: number): void => {
    if (depth > 32) fail();
    ws(); const c = input[p];
    if (c === '"') { string(); return; }
    if (c === '{' || c === '[') {
      const object = c === '{', end = object ? '}' : ']'; const keys = new Set<string>(); p++; ws();
      if (input[p] === end) { p++; return; }
      while (p < input.length) {
        if (object) {
          if (input[p] !== '"') fail();
          const key = string(); if (keys.has(key) || ['__proto__', 'prototype', 'constructor'].includes(key)) fail(); keys.add(key);
          ws(); if (input[p++] !== ':') fail();
        }
        value(depth + 1); ws();
        if (input[p] === end) { p++; return; }
        if (input[p++] !== ',') fail(); ws();
      }
      fail();
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(input.slice(p));
    if (!match) fail();
    const token = match![0];
    if (/^[-\d]/.test(token)) {
      const n = Number(token); if (!Number.isFinite(n) || (Number.isInteger(n) && !Number.isSafeInteger(n))) fail();
    }
    p += token.length;
  };
  value(0); ws(); if (p !== input.length) fail();
  try { return JSON.parse(input); } catch { return fail(); }
}
