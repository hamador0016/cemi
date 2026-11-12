'use strict';
// Finds the environment variable under the cursor. Only names are read here;
// the extension shows a hover only for names the project's cemi.toml declares.

const NAME = '[A-Za-z_][A-Za-z0-9_]*';
const QUOTED = `["'\`](${NAME})["'\`]`;

/** @type {Record<string, RegExp[]>} */
const BY_LANGUAGE = {
  js: [
    new RegExp(`\\bprocess\\.env\\.(${NAME})`, 'dg'),
    new RegExp(`\\bprocess\\.env\\[\\s*${QUOTED}\\s*\\]`, 'dg'),
    new RegExp(`\\bimport\\.meta\\.env\\.(${NAME})`, 'dg'),
    new RegExp(`\\bimport\\.meta\\.env\\[\\s*${QUOTED}\\s*\\]`, 'dg'),
    new RegExp(`\\bDeno\\.env\\.get\\(\\s*${QUOTED}`, 'dg'),
    new RegExp(`\\bBun\\.env\\.(${NAME})`, 'dg'),
  ],
  python: [
    new RegExp(`\\benviron\\[\\s*${QUOTED}\\s*\\]`, 'dg'),
    new RegExp(`\\benviron\\.get\\(\\s*${QUOTED}`, 'dg'),
    new RegExp(`\\bgetenv\\(\\s*${QUOTED}`, 'dg'),
  ],
  rust: [
    new RegExp(`\\benv::var(?:_os)?\\(\\s*"(${NAME})"`, 'dg'),
    new RegExp(`\\b(?:option_)?env!\\(\\s*"(${NAME})"`, 'dg'),
  ],
  go: [new RegExp(`\\bos\\.(?:Getenv|LookupEnv)\\(\\s*"(${NAME})"`, 'dg')],
  shell: [new RegExp(`\\$\\{(${NAME})(?:[:}?=+-])`, 'dg'), new RegExp(`\\$(${NAME})`, 'dg')],
  powershell: [new RegExp(`\\$env:(${NAME})`, 'dgi')],
  dotenv: [new RegExp(`^\\s*(?:export\\s+)?(${NAME})\\s*=`, 'dg')],
  toml: [new RegExp(`^\\s*(${NAME})\\s*=`, 'dg')],
};

const LANGUAGES = {
  javascript: 'js',
  javascriptreact: 'js',
  typescript: 'js',
  typescriptreact: 'js',
  vue: 'js',
  svelte: 'js',
  astro: 'js',
  python: 'python',
  rust: 'rust',
  go: 'go',
  shellscript: 'shell',
  dockerfile: 'shell',
  makefile: 'shell',
  yaml: 'shell',
  powershell: 'powershell',
  dotenv: 'dotenv',
  properties: 'dotenv',
  toml: 'toml',
};

/**
 * Which set of patterns applies to a file.
 * @param {string} languageId
 * @param {string} fileName
 * @returns {string | undefined}
 */
function kindOf(languageId, fileName) {
  const base = fileName.replace(/\\/g, '/').split('/').pop() || '';
  if (base === '.env' || base.startsWith('.env.') || base.endsWith('.env')) return 'dotenv';
  if (base === 'cemi.toml') return 'toml';
  return LANGUAGES[languageId];
}

/**
 * The variable name at a position of one line, if any.
 * @param {string} line
 * @param {number} character 0-based UTF-16 offset, as VS Code gives it
 * @param {string} languageId
 * @param {string} fileName
 * @returns {{ name: string, start: number, end: number } | undefined}
 */
function variableAt(line, character, languageId, fileName) {
  const kind = kindOf(languageId, fileName);
  if (!kind) return undefined;
  for (const pattern of BY_LANGUAGE[kind]) {
    pattern.lastIndex = 0;
    for (const m of line.matchAll(pattern)) {
      const whole = /** @type {[number, number]} */ (m.indices && m.indices[0]);
      const name = /** @type {[number, number]} */ (m.indices && m.indices[1]);
      if (!whole || !name) continue;
      if (character >= whole[0] && (character < whole[1] || character === name[1])) {
        return { name: m[1], start: name[0], end: name[1] };
      }
    }
  }
  return undefined;
}

module.exports = { variableAt, kindOf };
