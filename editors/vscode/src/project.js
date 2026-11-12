'use strict';

const fs = require('fs');
const path = require('path');

/**
 * The folder of the nearest cemi.toml above a file, as cemi itself finds it.
 * @param {string} file
 * @returns {string | undefined}
 */
function projectDir(file) {
  let dir = path.dirname(path.resolve(file));
  for (;;) {
    if (fs.existsSync(path.join(dir, 'cemi.toml'))) return dir;
    const up = path.dirname(dir);
    if (up === dir) return undefined;
    dir = up;
  }
}

/**
 * Splits a reference like `global:acme/shop/stripe#secret` into the record
 * part (what `cemi show` takes) and the field.
 * @param {string} ref
 * @returns {{ record: string, field: string | undefined }}
 */
function splitRef(ref) {
  const i = ref.lastIndexOf('#');
  return i < 0 ? { record: ref, field: undefined } : { record: ref.slice(0, i), field: ref.slice(i + 1) };
}

/**
 * The variables of `cemi var ls --json`, by name.
 * @param {any} data
 * @returns {Map<string, { name: string, reference: string, resolved: string | null, purpose: string | null, file: boolean }>}
 */
function variablesByName(data) {
  const out = new Map();
  for (const v of (data && Array.isArray(data.variables) ? data.variables : [])) {
    if (v && typeof v.name === 'string') {
      out.set(v.name, {
        name: v.name,
        reference: String(v.reference || ''),
        resolved: typeof v.resolved === 'string' ? v.resolved : null,
        purpose: typeof v.purpose === 'string' ? v.purpose : null,
        file: v.file === true,
      });
    }
  }
  return out;
}

module.exports = { projectDir, splitRef, variablesByName };
