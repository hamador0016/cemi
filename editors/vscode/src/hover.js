'use strict';
// Builds the hover text for a variable from `cemi var ls` and `cemi show`.
// Values are never part of it, not even the non-secret ones `show` returns.

const KNOWN = [
  ['purpose', 'For'],
  ['used_in', 'Used in'],
  ['rotate', 'Rotate'],
  ['if_leaked', 'If leaked'],
  ['if_lost', 'If lost'],
  ['backup', 'Backup'],
  ['delicate', 'Delicate'],
  ['links', 'Links'],
];
const SKIP = new Set(['expires', ...KNOWN.map(([k]) => k)]);
const MAX_DESTINATIONS = 5;

/** Escapes text for Markdown. @param {unknown} s */
function esc(s) {
  return String(s).replace(/[\\`*_{}[\]()#+\-.!|<>~]/g, '\\$&').replace(/\r?\n/g, '  \n');
}

/** Inline code; backticks inside are dropped. @param {unknown} s */
function code(s) {
  return '`' + String(s).replace(/`/g, '') + '`';
}

/**
 * Days from `today` to a date like 2027-11-09 (negative when past).
 * @param {string} date
 * @param {Date} today
 * @returns {number | undefined}
 */
function daysUntil(date, today) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(date).trim());
  if (!m) return undefined;
  const target = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const now = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  return Math.round((target - now) / 86400000);
}

/**
 * @param {string} date
 * @param {Date} today
 */
function expiryText(date, today) {
  const d = daysUntil(date, today);
  if (d === undefined) return esc(date);
  if (d < 0) return `⚠ expired ${esc(date)} (${-d} day${d === -1 ? '' : 's'} ago)`;
  if (d === 0) return `⚠ expires today (${esc(date)})`;
  const when = `${esc(date)} (in ${d} day${d === 1 ? '' : 's'})`;
  return d <= 30 ? `⚠ ${when}` : when;
}

/** @param {string} e */
function envLabel(e) {
  return e === 'all' ? 'all environments' : e;
}

/**
 * The header shared by every state.
 * @param {{ name: string, reference: string, resolved: string | null, file: boolean }} variable
 */
function header(variable) {
  const ref = variable.resolved || variable.reference;
  return `**${esc(variable.name)}** → ${code(ref)}${variable.file ? ' (as a file)' : ''}`;
}

/**
 * @param {{ name: string, reference: string, resolved: string | null, purpose: string | null, file: boolean }} variable
 * @param {{ kind: 'record', record: any, recordRef: string, field: string | undefined } | { kind: 'locked' } | { kind: 'error', message: string }} state
 * @param {Date} today
 * @returns {string} Markdown
 */
function hoverText(variable, state, today) {
  const lines = [header(variable)];
  if (variable.purpose) lines.push('', esc(variable.purpose));

  if (state.kind === 'locked') {
    lines.push(
      '',
      'The vault is locked. [Unlock it](command:cemi.unlock) (or run `cemi unlock` in a terminal) to see what this key is for, when it expires and how to rotate it.',
    );
    return lines.join('\n');
  }
  if (state.kind === 'error') {
    lines.push('', `Cemí could not read it: ${esc(state.message)}`);
    return lines.join('\n');
  }

  const rec = state.record || {};
  const memory = rec.memory && typeof rec.memory === 'object' ? rec.memory : {};
  const fields = Array.isArray(rec.fields) ? rec.fields : [];
  const shownRef = state.recordRef || rec.path || '';
  const field = fields.find((f) => f && f.name === state.field);
  const facts = [];

  if (rec.archived) facts.push('⚠ This record is archived.');
  if (state.field && !field) facts.push(`⚠ ${code(shownRef)} has no field ${code(state.field)}.`);
  if (field) {
    const kind = field.secret ? `secret ${field.kind}` : field.kind;
    facts.push(`**Kind:** ${esc(kind)}${field.kind === 'template' ? ' (built from other values)' : ''}`);
  }
  if (memory.purpose && memory.purpose !== variable.purpose) facts.push(`**For:** ${esc(memory.purpose)}`);
  if (memory.expires) facts.push(`**Expires:** ${expiryText(memory.expires, today)}`);
  for (const [key, label] of KNOWN) {
    if (key !== 'purpose' && memory[key]) facts.push(`**${label}:** ${esc(memory[key])}`);
  }
  for (const [key, value] of Object.entries(memory)) {
    if (!SKIP.has(key)) facts.push(`**${esc(key)}:** ${esc(value)}`);
  }

  if (field) {
    const values = Array.isArray(field.values) ? field.values : [];
    const set = values.filter((v) => v.set).map((v) => {
      const day = typeof v.updated === 'string' ? v.updated.slice(0, 10) : '';
      return day ? `${esc(envLabel(v.env))} (${esc(day)})` : esc(envLabel(v.env));
    });
    const outside = values.filter((v) => v.external).map((v) => `${esc(envLabel(v.env))}: ${esc(v.external)}`);
    const envs = Array.isArray(rec.environments) ? rec.environments : [];
    const covered = values.some((v) => v.env === 'all' && (v.set || v.external));
    const missing = covered ? [] : envs.filter((e) => !values.some((v) => v.env === e && (v.set || v.external)));
    if (set.length) facts.push(`**Set for:** ${set.join(', ')}`);
    if (outside.length) facts.push(`**Not stored here:** ${outside.join('; ')}`);
    if (missing.length) facts.push(`**No value for:** ${missing.map(esc).join(', ')}`);

    const origins = Array.isArray(field.origins) ? field.origins : [];
    for (const o of origins) facts.push(`**New values (${esc(envLabel(o.env))}):** ${esc(o.origin)}`);
    if (!origins.length && !memory.rotate && field.secret) {
      facts.push(`**Rotate:** no recipe yet. Add one with ${code(`cemi note ${shownRef} --rotate "..."`)}`);
    }
    const dests = Array.isArray(field.destinations) ? field.destinations : [];
    if (dests.length) {
      const shown = dests.slice(0, MAX_DESTINATIONS).map((d) => `${esc(d.destination)} (${esc(envLabel(d.env))})`);
      if (dests.length > MAX_DESTINATIONS) shown.push(`and ${dests.length - MAX_DESTINATIONS} more`);
      facts.push(`**Copied to:** ${shown.join('; ')}`);
    }
  }

  if (facts.length) lines.push('', facts.join('  \n'));
  lines.push('', `_Values are never shown here. More: ${code(`cemi show ${shownRef}`)}_`);
  return lines.join('\n');
}

module.exports = { hoverText, daysUntil, esc };
