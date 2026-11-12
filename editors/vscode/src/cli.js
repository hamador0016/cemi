'use strict';
// Runs the cemi CLI. Every call uses --json (one object on stdout) and
// --no-input (never a password prompt: a locked vault answers "locked").
// The commands used never print secret values.

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

/**
 * @typedef {{ ok: boolean, exitCode: number, data: any, kind?: string, message?: string }} Result
 */

/**
 * Finds the cemi program. A bare name is looked up in PATH only, never in the
 * project folder: a repository could ship its own "cemi.exe", and Windows
 * would otherwise run it from the working directory first.
 * @param {string} setting the `cemi.path` setting
 * @param {NodeJS.ProcessEnv} env
 * @param {string} platform
 * @returns {string | undefined} an absolute path
 */
function resolveProgram(setting, env, platform) {
  const name = (setting || 'cemi').trim();
  const isWin = platform === 'win32';
  const p = isWin ? path.win32 : path.posix;
  if (name.includes('/') || name.includes('\\')) {
    return p.isAbsolute(name) && isFile(name) ? name : undefined;
  }
  if (isWin && /\.(bat|cmd)$/i.test(name)) return undefined;
  // Only real programs: .bat and .cmd files need a shell, and arguments
  // (file paths, references from cemi.toml) must never pass through one.
  const exts = isWin ? ['.exe', '.com'] : [''];
  const dirs = (env.PATH || env.Path || '').split(isWin ? ';' : ':');
  for (const dir of dirs) {
    if (!dir || !p.isAbsolute(dir)) continue;
    for (const ext of exts) {
      if (isWin && name.toLowerCase().endsWith(ext)) {
        const exact = p.join(dir, name);
        if (isFile(exact)) return exact;
      }
      const candidate = p.join(dir, name + ext);
      if (isFile(candidate)) return candidate;
    }
  }
  return undefined;
}

/** @param {string} f */
function isFile(f) {
  try {
    return fs.statSync(f).isFile();
  } catch {
    return false;
  }
}

/**
 * Reads what `cemi --json` printed.
 * @param {string} stdout
 * @param {number} code
 * @returns {Result}
 */
function parseOutput(stdout, code) {
  let v;
  try {
    v = JSON.parse(stdout.trim());
  } catch {
    return { ok: false, exitCode: code, data: null, kind: 'error', message: 'cemi gave no JSON' };
  }
  return {
    ok: v.ok === true,
    exitCode: typeof v.exit_code === 'number' ? v.exit_code : code,
    data: v.data === undefined ? null : v.data,
    kind: v.error ? v.error.kind : undefined,
    message: v.error ? v.error.message : undefined,
  };
}

/**
 * Runs `cemi --json --no-input ARGS` in a folder.
 * @param {string} program absolute path from resolveProgram
 * @param {string[]} args
 * @param {string} cwd
 * @param {number} timeoutMs
 * @returns {Promise<Result>}
 */
function run(program, args, cwd, timeoutMs) {
  return new Promise((resolve) => {
    execFile(
      program,
      ['--json', '--no-input', ...args],
      { cwd, timeout: timeoutMs, windowsHide: true, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout) => {
        const e = /** @type {any} */ (err);
        if (e && e.killed) {
          resolve({ ok: false, exitCode: -1, data: null, kind: 'timeout', message: `cemi took more than ${timeoutMs} ms` });
          return;
        }
        if (e && typeof e.code === 'string') {
          resolve({ ok: false, exitCode: -1, data: null, kind: 'missing', message: `cannot run cemi (${e.code})` });
          return;
        }
        resolve(parseOutput(String(stdout), e && typeof e.code === 'number' ? e.code : 0));
      },
    );
  });
}

module.exports = { resolveProgram, parseOutput, run };
