'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseOutput, resolveProgram } = require('../src/cli');
const { projectDir, splitRef, variablesByName } = require('../src/project');
const { findings, toUtf16 } = require('../src/scan');

test('reads the JSON object of cemi --json', () => {
  const ok = parseOutput('{"ok":true,"exit_code":0,"data":{"x":1},"text":""}\n', 0);
  assert.deepEqual(ok, { ok: true, exitCode: 0, data: { x: 1 }, kind: undefined, message: undefined });
  const locked = parseOutput(
    '{"data":null,"error":{"kind":"locked","message":"the vault is locked"},"exit_code":3,"ok":false,"text":""}',
    3,
  );
  assert.equal(locked.kind, 'locked');
  assert.equal(locked.exitCode, 3);
  assert.equal(parseOutput('not json', 9).kind, 'error');
});

test('cemi is found in PATH, never in the project folder', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cemi-vscode-'));
  const bin = path.join(tmp, 'bin');
  fs.mkdirSync(bin);
  const name = process.platform === 'win32' ? 'cemi.exe' : 'cemi';
  fs.writeFileSync(path.join(bin, name), '');
  fs.writeFileSync(path.join(tmp, name), '');
  const sep = process.platform === 'win32' ? ';' : ':';
  const env = { PATH: ['.', '', 'relative/dir', bin].join(sep) };
  assert.equal(resolveProgram('cemi', env, process.platform), path.join(bin, name));
  assert.equal(resolveProgram('', env, process.platform), path.join(bin, name));
  assert.equal(resolveProgram('cemi', { PATH: '.' }, process.platform), undefined);
  assert.equal(resolveProgram(path.join(bin, name), {}, process.platform), path.join(bin, name));
  assert.equal(resolveProgram(`.${path.sep}${name}`, env, process.platform), undefined);
  if (process.platform === 'win32') {
    fs.writeFileSync(path.join(bin, 'other.cmd'), '');
    assert.equal(resolveProgram('other', env, 'win32'), undefined);
    assert.equal(resolveProgram('other.cmd', env, 'win32'), undefined);
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('the project is the nearest cemi.toml', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cemi-vscode-'));
  fs.mkdirSync(path.join(tmp, 'app', 'src'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'app', 'cemi.toml'), '');
  assert.equal(projectDir(path.join(tmp, 'app', 'src', 'main.js')), path.join(tmp, 'app'));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('references and variables', () => {
  assert.deepEqual(splitRef('global:acme/shop/stripe#secret'), { record: 'global:acme/shop/stripe', field: 'secret' });
  assert.deepEqual(splitRef('stripe'), { record: 'stripe', field: undefined });
  const vars = variablesByName({
    variables: [
      { name: 'A', reference: 'db#url', resolved: 'local:db#url', purpose: null, file: false },
      { name: 'B', reference: 'bad ref', resolved: null, purpose: 'x', file: true },
    ],
  });
  assert.equal(vars.get('A').resolved, 'local:db#url');
  assert.equal(vars.get('B').resolved, null);
  assert.equal(vars.get('B').file, true);
  assert.equal(variablesByName(null).size, 0);
});

test('scan findings become ranges', () => {
  const lines = ['first', 'const k = "sk_test_value_123";', '😀 = "sk_test_value_123"'];
  const out = findings(
    {
      findings: [
        { place: 'a.js', line: 2, column: 12, length: 17, secret: 'local:stripe#secret [dev]' },
        { place: 'a.js', line: 3, column: 6, length: 17, secret: 'local:stripe#secret [dev]' },
        { place: 'a.js', line: 1, secret: 'x' },
      ],
    },
    (n) => lines[n],
  );
  assert.deepEqual([out[0].line, out[0].start, out[0].end], [1, 11, 28]);
  assert.equal(lines[1].slice(out[0].start, out[0].end), 'sk_test_value_123');
  // The emoji is one character for cemi and two UTF-16 units for VS Code.
  assert.equal(lines[2].slice(out[1].start, out[1].end), 'sk_test_value_123');
  assert.deepEqual([out[2].start, out[2].end], [0, 5]);
  assert.match(out[0].message, /local:stripe#secret \[dev\]/);
  assert.ok(!out[0].message.includes('sk_test'));
  assert.equal(toUtf16('😀a', 1), 2);
});
