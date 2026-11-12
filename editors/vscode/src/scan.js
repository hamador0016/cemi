'use strict';
// Turns `cemi scan FILE --json` into editor warnings. cemi reports where a
// vault value starts and how long it is, plus the record it belongs to; the
// value itself never leaves cemi.

/**
 * Converts a column counted in characters (code points) to VS Code's UTF-16
 * offset on the same line.
 * @param {string} lineText
 * @param {number} chars
 */
function toUtf16(lineText, chars) {
  let units = 0;
  let seen = 0;
  for (const ch of lineText) {
    if (seen >= chars) break;
    units += ch.length;
    seen += 1;
  }
  return units;
}

/**
 * @param {any} data the `data` of `cemi scan --json`
 * @param {(line: number) => string} lineText 0-based line → its text
 * @returns {{ line: number, start: number, end: number, message: string }[]}
 */
function findings(data, lineText) {
  const out = [];
  const list = data && Array.isArray(data.findings) ? data.findings : [];
  for (const f of list) {
    if (typeof f.line !== 'number' || f.line < 1) continue;
    const line = f.line - 1;
    const text = lineText(line);
    let start = 0;
    let end = text.length;
    if (typeof f.column === 'number' && f.column >= 1) {
      start = toUtf16(text, f.column - 1);
      end = typeof f.length === 'number' ? toUtf16(text, f.column - 1 + f.length) : text.length;
    }
    out.push({
      line,
      start,
      end: Math.max(end, start + 1),
      message:
        `The value of ${f.secret} is written here. Read it from the environment ` +
        '(`cemi run`) instead. If this was ever committed or shared, rotate it.',
    });
  }
  return out;
}

module.exports = { findings, toUtf16 };
