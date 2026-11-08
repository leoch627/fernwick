/** Schema acceptance oracle for the Go migration; never contains live secrets. */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { AccountSchema, BuildSchema, CommandSchema, PolicySchema, PreferencesSchema, RefreshSchema, defaultPreferences } from '../src/shared/schema';
import { strictJson } from '../src/domain/json';
import { account, policy } from '../tests/fixtures';
import development from '../config/development.json';

const schemas = { account: AccountSchema, build: BuildSchema, command: CommandSchema, policy: PolicySchema, preferences: PreferencesSchema, refresh: RefreshSchema };
type SchemaName = keyof typeof schemas;
const cases: { name: string; schema: SchemaName; raw: string; valid: boolean }[] = [];
function add(name: string, schema: SchemaName, input: unknown, raw = false) {
  const text = raw ? input as string : JSON.stringify(input);
  let valid = false;
  try { valid = schemas[schema].safeParse(strictJson(text)).success; } catch { /* Invalid before schema validation. */ }
  cases.push({ name, schema, raw: text, valid });
}
function absent(value: object, key: string) { const result = { ...value } as Record<string, unknown>; delete result[key]; return result; }

add('development defaults', 'build', absent(absent(development, 'healthTargets'), 'allowUnverifiedNodeTrials'));
add('development config', 'build', development);
add('default is not nullable', 'build', { ...development, healthTargets: null });
add('unknown build field', 'build', { ...development, exec: 'program' });
add('account valid', 'account', account);
add('account nullable expiry', 'account', { ...account, expiryKind: 'unknown', expiresAt: null });
add('account required nullable expiry', 'account', absent(account, 'expiresAt'));
add('account inconsistent expiry', 'account', { ...account, expiresAt: null });
add('account decimal max', 'account', { ...account, usedBytes: '9'.repeat(30) });
add('account decimal overflow', 'account', { ...account, usedBytes: '9'.repeat(31) });
add('account numeric bytes', 'account', { ...account, usedBytes: 1024 });
add('account leading zero bytes', 'account', { ...account, usedBytes: '01' });
add('account no evidence', 'account', { ...account, authorizationEvidence: '' });
for (const value of ['2026-10-31T00:00:00Z', '2026-10-31T00:00:00.123456789123Z', '2026-10-31T08:00:00+08:00', '2026-10-31T00:00Z', '2026-10-31T0:00:00Z', '2026-10-31T00:00:00,123Z', '2026-10-31T00:00:00+24:00', '2026-10-31T00:00:00+00:60', '2026-02-29T00:00:00Z']) {
  add(`date ${value}`, 'account', { ...account, observedAt: value });
}
for (const email of ['alice@example.invalid', "o'hara@example.com", 'a+b@example.com', '.alice@example.com', 'alice..bob@example.com', 'alice@localhost', 'alice@例子.中国', 'a@example.c', 'a@example.c0m', 'a@example.com\n']) {
  add(`email ${JSON.stringify(email)}`, 'command', { type: 'login', email, password: 'password' });
}
for (const password of ['', 'x', 'x'.repeat(1024), 'x'.repeat(1025), '🚄'.repeat(512), '🚄'.repeat(513), '🚄'.repeat(1024), '🚄'.repeat(1025), '\ud800'.repeat(1024), '\ud800'.repeat(1025)]) {
  add(`password ${password.length} code units ${JSON.stringify(password.slice(0, 2))}`, 'command', { type: 'login', email: account.email, password });
}
for (const type of ['state', 'sync', 'connect', 'disconnect', 'logout', 'repair', 'check-update', 'download-update', 'pause-update', 'cancel-update', 'install-update', 'diagnostics', 'renewal-return', 'open-download-page']) {
  add(`command ${type}`, 'command', { type });
}
add('command unknown type', 'command', { type: 'execute' });
add('command unknown property', 'command', { type: 'state', token: 'fixture-only' });
add('command missing discriminant', 'command', {});
add('command null', 'command', null);
add('command array', 'command', []);
add('command escaped duplicate', 'command', '{"type":"state","\\u0074ype":"connect"}', true);
add('command constructor key', 'command', '{"type":"state","constructor":{}}', true);
add('command trailing', 'command', '{"type":"state"}false', true);
for (const count of [0, 1, 64, 65]) add(`probe count ${count}`, 'command', { type: 'probe-nodes', nodeIds: Array.from({ length: count }, (_, i) => `node-${i}`) });
add('probe empty ID', 'command', { type: 'probe-nodes', nodeIds: [''] });
add('probe long ID', 'command', { type: 'probe-nodes', nodeIds: ['x'.repeat(257)] });
add('open allowed link', 'command', { type: 'open-link', link: 'renew' });
add('open arbitrary URL', 'command', { type: 'open-link', link: 'https://example.com/' });
add('signup config', 'command', { type: 'signup-config' });
add('signup config extra field', 'command', { type: 'signup-config', email: account.email });
for (const purpose of ['register', 'reset', 'login']) add(`email code purpose ${purpose}`, 'command', { type: 'send-email-code', email: account.email, purpose });
add('email code invalid email', 'command', { type: 'send-email-code', email: 'not-an-email', purpose: 'register' });
const register = { type: 'register', email: account.email, password: 'password1', emailCode: '123456', inviteCode: 'abcd' };
add('register valid', 'command', register);
for (const emailCode of ['', '12345', '1234567', '12345a', '１２３４５６', ' 123456']) add(`register code ${JSON.stringify(emailCode)}`, 'command', { ...register, emailCode });
for (const password of ['1234567', '12345678', 'x'.repeat(64), 'x'.repeat(65), '🚄'.repeat(8), '🚄'.repeat(65)]) add(`register password ${password.length} code units`, 'command', { ...register, password });
add('register empty invitation', 'command', { ...register, inviteCode: '' });
add('register long invitation', 'command', { ...register, inviteCode: 'x'.repeat(65) });
add('register missing invitation', 'command', absent(register, 'inviteCode'));
add('register unknown field', 'command', { ...register, recaptcha: 'token' });
const reset = { type: 'reset-password', email: account.email, password: 'password1', emailCode: '123456' };
add('reset valid', 'command', reset);
add('reset empty code', 'command', { ...reset, emailCode: '' });
add('reset short password', 'command', { ...reset, password: 'short' });
add('reset invitation field', 'command', { ...reset, inviteCode: '' });
add('preferences default', 'preferences', defaultPreferences);
add('preferences command', 'command', { type: 'preferences', preferences: defaultPreferences });
add('preferences missing nullable', 'preferences', absent(defaultPreferences, 'nodeId'));
add('preferences unknown nested', 'command', { type: 'preferences', preferences: { ...defaultPreferences, token: 'fixture-only' } });
add('preferences before tunnel and ad blocking', 'preferences', absent(absent(defaultPreferences, 'tunnel'), 'adBlock'));
add('preferences TUN tunnel', 'preferences', { ...defaultPreferences, tunnel: 'tun', adBlock: false });
add('preferences unknown tunnel', 'preferences', { ...defaultPreferences, tunnel: 'vpn' });
add('preferences null tunnel', 'preferences', { ...defaultPreferences, tunnel: null });
add('preferences ad blocking as text', 'preferences', { ...defaultPreferences, adBlock: 'yes' });
add('preferences before node lists', 'preferences', absent(absent(defaultPreferences, 'favoriteNodeIds'), 'recentNodeIds'));
for (const [key, limit] of [['favoriteNodeIds', 256], ['recentNodeIds', 8]] as const) {
  for (const count of [0, limit, limit + 1]) add(`${key} count ${count}`, 'preferences', { ...defaultPreferences, [key]: Array.from({ length: count }, (_, i) => `node-${i}`) });
  for (const ids of [null, [''], ['x'.repeat(257)], ['node', 'node']]) add(`${key} rejects ${JSON.stringify(ids)}`, 'preferences', { ...defaultPreferences, [key]: ids });
}
add('favorite also recently connected', 'preferences', { ...defaultPreferences, favoriteNodeIds: ['node'], recentNodeIds: ['node'] });
add('favorite command', 'command', { type: 'favorite-node', nodeId: 'node', favorite: true });
add('unfavorite command', 'command', { type: 'favorite-node', nodeId: 'node', favorite: false });
for (const data of [{ nodeId: '' }, { nodeId: 'x'.repeat(257) }, { favorite: null }, { favorite: 'yes' }, { extra: true }]) add(`invalid favorite ${JSON.stringify(data)}`, 'command', { type: 'favorite-node', nodeId: 'node', favorite: true, ...data });
add('refresh valid', 'refresh', policy.refresh);
add('refresh interval beyond window', 'refresh', { ...policy.refresh, maxSnapshotAgeSec: 600 });
add('refresh polling too slow', 'refresh', { ...policy.refresh, accountIntervalSec: 3000 });
add('refresh decimal integer notation', 'refresh', JSON.stringify(policy.refresh).replace(':1800', ':1800.0'), true);
add('refresh fractional integer', 'refresh', { ...policy.refresh, subscriptionIntervalSec: 1800.5 });
add('policy valid', 'policy', policy);
add('policy optional order and group', 'policy', { ...policy, nodeOperations: [{ nodeId: 'node', hiddenFromList: false, eligibleForAuto: true, disabledForConnection: false }] });
add('policy optional order is not nullable', 'policy', { ...policy, nodeOperations: [{ nodeId: 'node', hiddenFromList: false, eligibleForAuto: true, disabledForConnection: false, order: null }] });
add('policy missing nullable maintenance', 'policy', absent(policy, 'maintenance'));
add('policy unsafe numeric version', 'policy', JSON.stringify(policy).replace('"policyVersion":1', '"policyVersion":9007199254740993'), true);

const target = resolve('desktop/core/testdata/schema.json');
const output = JSON.stringify({ generatedBy: 'tools/wails-schema-fixtures.ts (TypeScript reference validators)', cases }, null, 2) + '\n';
if (process.argv.includes('--check')) {
  if (readFileSync(target, 'utf8') !== output) throw new Error('Schema fixtures differ from the TypeScript reference; run npm run fixtures:wails');
  console.log(`Verified ${cases.length} schema compatibility cases`);
} else {
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, output);
  console.log(`Wrote ${cases.length} schema compatibility cases to ${target}`);
}
