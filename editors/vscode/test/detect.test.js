'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { variableAt } = require('../src/detect');

/** The name found when the cursor is on `marker` inside `line`. */
function at(line, marker, languageId, fileName = 'file') {
  const i = line.indexOf(marker);
  assert.ok(i >= 0, `marker ${marker} not in ${line}`);
  const found = variableAt(line, i, languageId, fileName);
  return found && found.name;
}

test('JavaScript and TypeScript', () => {
  assert.equal(at('const k = process.env.STRIPE_KEY;', 'STRIPE', 'javascript'), 'STRIPE_KEY');
  assert.equal(at('const k = process.env.STRIPE_KEY;', 'process', 'typescript'), 'STRIPE_KEY');
  assert.equal(at('process.env["DB_URL"]', 'DB', 'typescript'), 'DB_URL');
  assert.equal(at("process.env['DB_URL']", 'DB', 'javascriptreact'), 'DB_URL');
  assert.equal(at('import.meta.env.VITE_KEY', 'VITE', 'typescriptreact'), 'VITE_KEY');
  assert.equal(at('Deno.env.get("TOKEN")', 'TOKEN', 'typescript'), 'TOKEN');
  assert.equal(at('const k = process.env.STRIPE_KEY;', 'const', 'javascript'), undefined);
});

test('Python, Rust and Go', () => {
  assert.equal(at('os.environ["API_KEY"]', 'API', 'python'), 'API_KEY');
  assert.equal(at("os.environ.get('API_KEY', '')", 'API', 'python'), 'API_KEY');
  assert.equal(at('os.getenv("API_KEY")', 'getenv', 'python'), 'API_KEY');
  assert.equal(at('std::env::var("DATABASE_URL")?', 'DATABASE', 'rust'), 'DATABASE_URL');
  assert.equal(at('env::var_os("HOME")', 'HOME', 'rust'), 'HOME');
  assert.equal(at('env!("BUILD_KEY")', 'BUILD', 'rust'), 'BUILD_KEY');
  assert.equal(at('key := os.Getenv("STRIPE")', 'STRIPE', 'go'), 'STRIPE');
});

test('shell, PowerShell, .env and cemi.toml', () => {
  assert.equal(at('curl -H "Bearer $TOKEN" x', 'TOKEN', 'shellscript'), 'TOKEN');
  assert.equal(at('echo ${DB_URL:-none}', 'DB_URL', 'shellscript'), 'DB_URL');
  assert.equal(at('echo ${DB_URL}', 'DB_URL', 'shellscript'), 'DB_URL');
  assert.equal(at('$env:API_KEY', 'API', 'powershell'), 'API_KEY');
  assert.equal(at('export STRIPE_KEY=abc', 'STRIPE', 'plaintext', '/p/.env.local'), 'STRIPE_KEY');
  assert.equal(at('STRIPE_KEY=abc', 'STRIPE', 'dotenv', '/p/.env'), 'STRIPE_KEY');
  assert.equal(at('STRIPE_KEY=abc', 'abc', 'dotenv', '/p/.env'), undefined);
  assert.equal(at('DATABASE_URL = "db#url"', 'DATABASE', 'toml', 'C:\\p\\cemi.toml'), 'DATABASE_URL');
});

test('the range covers the name only', () => {
  const line = 'x = process.env.KEY_1 + 1';
  const found = variableAt(line, line.indexOf('KEY'), 'javascript', 'a.js');
  assert.deepEqual(found, { name: 'KEY_1', start: 16, end: 21 });
  assert.equal(variableAt(line, 0, 'markdown', 'a.md'), undefined);
});
