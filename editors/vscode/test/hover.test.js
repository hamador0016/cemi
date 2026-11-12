'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { hoverText, daysUntil } = require('../src/hover');

const variable = {
  name: 'STRIPE_SECRET_KEY',
  reference: 'stripe#secret',
  resolved: 'local:stripe#secret',
  purpose: null,
  file: false,
};

// What `cemi show stripe --json` returns (non-secret values are included by
// cemi; the hover must still never print them).
const record = {
  path: 'stripe',
  vault: 'local',
  archived: false,
  environments: ['dev', 'prod'],
  memory: {
    purpose: 'Charges cards',
    expires: '2027-01-15',
    rotate: 'Roll it in the Stripe dashboard',
    if_leaked: 'Roll it now',
    owner: 'billing team',
  },
  fields: [
    {
      name: 'secret',
      kind: 'text',
      secret: true,
      values: [{ env: 'dev', set: true, versions: 1, updated: '2026-11-11T10:00:00Z', external: null }],
      origins: [{ env: 'prod', origin: 'command `stripe-roll`' }],
      destinations: [{ id: 'a1', env: 'prod', destination: 'GitHub acme/shop: secret STRIPE_KEY', last_sent: null }],
      verify: [],
    },
    {
      name: 'publishable',
      kind: 'text',
      secret: false,
      values: [{ env: 'all', set: true, versions: 1, updated: '2026-11-11T10:00:00Z', value: 'pk_test_not_shown_123' }],
      origins: [],
      destinations: [],
      verify: [],
    },
  ],
};

const today = new Date(Date.UTC(2026, 10, 11));

test('a record: purpose, expiry, rotation and where it is set', () => {
  const md = hoverText(variable, { kind: 'record', record, recordRef: 'local:stripe', field: 'secret' }, today);
  assert.match(md, /\*\*STRIPE\\_SECRET\\_KEY\*\* → `local:stripe#secret`/);
  assert.match(md, /Charges cards/);
  assert.match(md, /\*\*Expires:\*\* 2027\\-01\\-15 \(in 65 days\)/);
  assert.match(md, /\*\*Rotate:\*\* Roll it in the Stripe dashboard/);
  assert.match(md, /\*\*If leaked:\*\* Roll it now/);
  assert.match(md, /\*\*owner:\*\* billing team/);
  assert.match(md, /\*\*Set for:\*\* dev \(2026\\-11\\-11\)/);
  assert.match(md, /\*\*No value for:\*\* prod/);
  assert.match(md, /\*\*New values \(prod\):\*\* command `stripe\\-roll`|New values \(prod\)/);
  assert.match(md, /\*\*Copied to:\*\* GitHub acme\/shop: secret STRIPE\\_KEY \(prod\)/);
  assert.match(md, /`cemi show local:stripe`/);
});

test('values are never shown, not even non-secret ones', () => {
  for (const field of ['secret', 'publishable']) {
    const md = hoverText(variable, { kind: 'record', record, recordRef: 'local:stripe', field }, today);
    assert.ok(!md.includes('pk_test_not_shown_123'), md);
    assert.ok(!md.includes('pk\\_test'), md);
  }
});

test('expiry soon or past is marked', () => {
  const soon = { ...record, memory: { expires: '2026-11-20' } };
  assert.match(hoverText(variable, { kind: 'record', record: soon, recordRef: 'stripe', field: 'secret' }, today), /⚠ 2026\\-11\\-20 \(in 9 days\)/);
  const past = { ...record, memory: { expires: '2026-11-01' } };
  assert.match(hoverText(variable, { kind: 'record', record: past, recordRef: 'stripe', field: 'secret' }, today), /⚠ expired 2026\\-11\\-01 \(10 days ago\)/);
  assert.equal(daysUntil('2026-11-11', today), 0);
  assert.equal(daysUntil('soon', today), undefined);
});

test('a secret with no way to rotate it says how to add one', () => {
  const bare = { ...record, memory: {}, fields: [{ ...record.fields[0], origins: [] }] };
  const md = hoverText(variable, { kind: 'record', record: bare, recordRef: 'local:stripe', field: 'secret' }, today);
  assert.match(md, /no recipe yet/);
  assert.match(md, /`cemi note local:stripe --rotate "\.\.\."`/);
});

test('locked vault and errors', () => {
  const locked = hoverText({ ...variable, purpose: 'Payments' }, { kind: 'locked' }, today);
  assert.match(locked, /Payments/);
  assert.match(locked, /\[Unlock it\]\(command:cemi\.unlock\)/);
  const failed = hoverText(variable, { kind: 'error', message: 'record not found: stripe' }, today);
  assert.match(failed, /Cemí could not read it: record not found: stripe/);
});

test('user text cannot inject links or commands', () => {
  const evil = { ...record, memory: { purpose: '[click](command:workbench.action.terminal.new)' } };
  const md = hoverText(variable, { kind: 'record', record: evil, recordRef: 'stripe', field: 'secret' }, today);
  assert.ok(!md.includes('](command:workbench'), md);
});
