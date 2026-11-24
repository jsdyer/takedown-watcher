import test from 'node:test';
import assert from 'node:assert/strict';
import { summarize, firstTakedown, formatDuration, parseTarget, registeredDomain, parseDoh, parseRdap, quickState, stateInfo } from '../web/model.mjs';

const record = (target, changes, extra = {}) => ({ target, changes, current: changes.at(-1) ?? {}, watched: true, ...extra });

test('takedown time is measured from the report date', () => {
  const r = record('a.example', [
    { at: '2026-11-19T00:00:00Z', state: 'live' },
    { at: '2026-11-22T00:00:00Z', state: 'suspended', actor: 'host' },
  ], { reported: '2026-11-20' });
  assert.deepEqual(firstTakedown(r), { at: '2026-11-22T00:00:00Z', state: 'suspended', actor: 'host', observedLiveBefore: true, afterReport: '2 days' });
});

test('a takedown before the report date is ignored', () => {
  const r = record('a.example', [{ at: '2026-11-10T00:00:00Z', state: 'nxdomain' }], { reported: '2026-11-20' });
  assert.equal(firstTakedown(r), null);
});

test('summary sorts live sites first and hides removed targets by default', () => {
  const history = { last_run: '2026-11-23T00:00:00Z', targets: {
    'b.example': record('b.example', [{ at: 'x', state: 'hold' }]),
    'a.example': record('a.example', [{ at: 'x', state: 'live' }]),
    'gone.example': record('gone.example', [{ at: 'x', state: 'live' }], { watched: false }),
  } };
  const { rows, unwatched, counts } = summarize(history);
  assert.deepEqual(rows.map(r => r.target), ['a.example', 'b.example']);
  assert.equal(unwatched, 1);
  assert.deepEqual(counts, { live: 1, hold: 1 });
  assert.equal(summarize(history, { includeUnwatched: true }).rows.length, 3);
});

test('summary handles any number of targets', () => {
  const targets = Object.fromEntries(Array.from({ length: 75 }, (_, i) => [`s${i}.example`, record(`s${i}.example`, [])]));
  assert.equal(summarize({ targets }).rows.length, 75);
});

test('rejects malformed history', () => { assert.throws(() => summarize(null), TypeError); });

test('durations', () => {
  assert.equal(formatDuration(5 * 60_000), '5 min');
  assert.equal(formatDuration(30 * 3_600_000), '30 h');
  assert.equal(formatDuration(-1), '');
});

test('parses domains and URLs for the instant check', () => {
  assert.equal(parseTarget(' https://Shop.Example.ORG/login?x=1 '), 'shop.example.org');
  assert.equal(parseTarget('example.com.'), 'example.com');
  assert.throws(() => parseTarget(''), /Enter/);
  assert.throws(() => parseTarget('not a domain'), /valid/);
  assert.throws(() => parseTarget('localhost'), /valid/);
  assert.equal(registeredDomain('a.b.example.co.uk'), 'example.co.uk');
});

test('DNS and RDAP parsing feed the quick state', () => {
  const dns = parseDoh({ Status: 0, Answer: [{ type: 5, data: 'x.' }, { type: 1, data: '192.0.2.1' }] }, 'A');
  assert.deepEqual(dns, { rcode: 'NOERROR', addresses: ['192.0.2.1'] });
  const rdap = parseRdap({ status: ['Client Hold'], entities: [{ roles: ['registrar'],
    vcardArray: ['vcard', [['fn', {}, 'text', 'Reg Inc']]],
    entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['email', {}, 'text', 'abuse@reg.example']]] }] }] });
  assert.equal(rdap.registrar, 'Reg Inc');
  assert.equal(rdap.registrarAbuse, 'abuse@reg.example');
  assert.equal(quickState(dns, rdap), 'hold');
  assert.equal(quickState({ rcode: 'NXDOMAIN', addresses: [] }, null), 'nxdomain');
  assert.equal(quickState(dns, { found: false }), 'resolves');
  assert.equal(quickState(dns, { found: true, statuses: [] }), 'resolves');
  assert.throws(() => parseDoh({}, 'A'));
});

test('unknown states still render', () => { assert.equal(stateInfo('weird').label, 'weird'); });

test('ordinary errors and first-seen holds are not timed as takedowns', () => {
  for (const state of ['http-error', 'nxdomain', 'unreachable', 'tls-error']) {
    assert.equal(firstTakedown(record('a.example', [{at:'2026-11-19T00:00:00Z',state:'live'}, {at:'2026-11-22T00:00:00Z',state}], {reported:'2026-11-20'})), null);
  }
  assert.equal(firstTakedown(record('a.example', [{at:'2026-11-22T00:00:00Z',state:'hold'}], {reported:'2026-11-20'})), null);
  assert.equal(quickState({rcode:'SERVFAIL',addresses:[]}, null), 'dns-error');
});
