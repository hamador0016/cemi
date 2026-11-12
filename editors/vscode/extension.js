'use strict';
// Cemí for VS Code: hover an environment variable to see what it is for,
// when it expires and how it is rotated; get a warning when a vault value is
// written in a file. The extension only runs cemi commands that never print
// secret values, and never asks for the password itself.

const path = require('path');
const vscode = require('vscode');
const cli = require('./src/cli');
const { variableAt } = require('./src/detect');
const { hoverText } = require('./src/hover');
const { projectDir, splitRef, variablesByName } = require('./src/project');
const scan = require('./src/scan');

const VARIABLES_TTL = 30_000;
const RECORD_TTL = 60_000;
const MAX_SCAN_BYTES = 5 * 1024 * 1024;

/** @param {vscode.ExtensionContext} context */
function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection('cemi');
  const log = vscode.window.createOutputChannel('Cemí');
  const lockItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  lockItem.text = '$(lock) Cemí locked';
  lockItem.tooltip = 'The vault is locked. Click to unlock it in a terminal.';
  lockItem.command = 'cemi.unlock';

  /** @type {Map<string, { at: number, value: Promise<Map<string, any>> }>} */
  const variables = new Map();
  /** @type {Map<string, { at: number, value: cli.Result }>} */
  const records = new Map();
  let warnedMissing = false;

  function settings() {
    const c = vscode.workspace.getConfiguration('cemi');
    return {
      path: c.get('path', 'cemi'),
      hover: c.get('hover.enabled', true),
      scanOnSave: c.get('scan.onSave', true),
      exclude: c.get('scan.exclude', []),
      timeoutMs: c.get('timeoutMs', 5000),
    };
  }

  function program() {
    const p = cli.resolveProgram(settings().path, process.env, process.platform);
    if (!p && !warnedMissing) {
      warnedMissing = true;
      vscode.window.showWarningMessage(
        'Cemí: the cemi program was not found in PATH. Install it, or set "cemi.path" to the full path of the program.',
      );
    }
    return p;
  }

  /**
   * @param {string[]} args
   * @param {string} cwd
   * @param {boolean} opensVault whether the answer tells if the vault is locked
   */
  async function call(args, cwd, opensVault) {
    const p = program();
    if (!p) return { ok: false, exitCode: -1, data: null, kind: 'missing', message: 'cemi was not found' };
    const r = await cli.run(p, args, cwd, settings().timeoutMs);
    if (opensVault) {
      if (r.kind === 'locked') lockItem.show();
      else if (r.data) lockItem.hide();
    }
    if (!r.ok && r.kind && r.kind !== 'locked' && r.exitCode !== 1) {
      log.appendLine(`cemi ${args[0]} in ${cwd}: ${r.kind}: ${r.message || ''}`);
    }
    return r;
  }

  /** @param {string} dir */
  function projectVariables(dir) {
    const hit = variables.get(dir);
    if (hit && Date.now() - hit.at < VARIABLES_TTL) return hit.value;
    const value = call(['var', 'ls'], dir, false).then((r) => (r.ok ? variablesByName(r.data) : new Map()));
    variables.set(dir, { at: Date.now(), value });
    return value;
  }

  /**
   * @param {string} dir
   * @param {string} recordRef
   */
  async function record(dir, recordRef) {
    const key = `${dir}\n${recordRef}`;
    const hit = records.get(key);
    if (hit && Date.now() - hit.at < RECORD_TTL) return hit.value;
    const value = await call(['show', recordRef], dir, true);
    if (value.ok) records.set(key, { at: Date.now(), value });
    return value;
  }

  const hovers = vscode.languages.registerHoverProvider(
    { scheme: 'file' },
    {
      async provideHover(document, position) {
        if (!settings().hover) return undefined;
        const line = document.lineAt(position.line).text;
        const found = variableAt(line, position.character, document.languageId, document.fileName);
        if (!found) return undefined;
        const dir = projectDir(document.fileName);
        if (!dir) return undefined;
        const variable = (await projectVariables(dir)).get(found.name);
        if (!variable) return undefined;

        let state;
        if (!variable.resolved) {
          state = { kind: 'error', message: `the reference ${variable.reference} in cemi.toml is not valid` };
        } else {
          const { record: recordRef, field } = splitRef(variable.resolved);
          const r = await record(dir, recordRef);
          if (r.ok) state = { kind: 'record', record: r.data, recordRef, field };
          else if (r.kind === 'locked') state = { kind: 'locked' };
          else state = { kind: 'error', message: r.message || 'unknown error' };
        }
        const md = new vscode.MarkdownString(hoverText(variable, /** @type {any} */ (state), new Date()));
        md.isTrusted = { enabledCommands: ['cemi.unlock'] };
        const range = new vscode.Range(position.line, found.start, position.line, found.end);
        return new vscode.Hover(md, range);
      },
    },
  );

  /** @param {vscode.TextDocument} document */
  function excluded(document) {
    return settings().exclude.some(
      (/** @type {string} */ pattern) => vscode.languages.match({ pattern }, document) > 0,
    );
  }

  /**
   * @param {vscode.TextDocument} document
   * @param {boolean} manual
   */
  async function scanDocument(document, manual) {
    if (document.uri.scheme !== 'file') return;
    if (!manual && (!settings().scanOnSave || excluded(document))) return;
    if (!manual && document.getText().length > MAX_SCAN_BYTES) return;
    const cwd = projectDir(document.fileName) || path.dirname(document.fileName);
    const r = await call(['scan', document.fileName], cwd, true);
    if (!r.data) {
      diagnostics.delete(document.uri);
      if (manual && r.kind === 'locked') {
        const pick = await vscode.window.showWarningMessage('Cemí: the vault is locked.', 'Unlock');
        if (pick) vscode.commands.executeCommand('cemi.unlock');
      } else if (manual) {
        vscode.window.showWarningMessage(`Cemí: cannot scan this file: ${r.message || r.kind}`);
      }
      return;
    }
    const found = scan.findings(r.data, (n) => (n < document.lineCount ? document.lineAt(n).text : ''));
    diagnostics.set(
      document.uri,
      found.map((f) => {
        const d = new vscode.Diagnostic(
          new vscode.Range(f.line, f.start, f.line, f.end),
          f.message,
          vscode.DiagnosticSeverity.Warning,
        );
        d.source = 'cemi';
        return d;
      }),
    );
    if (manual && found.length === 0) {
      vscode.window.showInformationMessage('Cemí: no value from your vaults is written in this file.');
    }
  }

  function forget() {
    variables.clear();
    records.clear();
  }

  const watcher = vscode.workspace.createFileSystemWatcher('**/cemi.toml');
  watcher.onDidChange(forget);
  watcher.onDidCreate(forget);
  watcher.onDidDelete(forget);

  context.subscriptions.push(
    diagnostics,
    log,
    lockItem,
    hovers,
    watcher,
    vscode.workspace.onDidSaveTextDocument((d) => scanDocument(d, false)),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('cemi')) {
        warnedMissing = false;
        forget();
      }
    }),
    vscode.commands.registerCommand('cemi.unlock', () => {
      const p = program();
      if (!p) return;
      // The password is typed in the terminal, straight into cemi. It runs
      // where the current file's project is, so its local vault opens too.
      const editor = vscode.window.activeTextEditor;
      const file = editor && editor.document.uri.scheme === 'file' ? editor.document.fileName : undefined;
      const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
      const cwd = (file && (projectDir(file) || path.dirname(file))) || (folder && folder.uri.fsPath);
      const terminal = vscode.window.createTerminal({
        name: 'Cemí unlock',
        shellPath: p,
        shellArgs: ['unlock'],
        cwd,
      });
      terminal.show();
    }),
    vscode.window.onDidCloseTerminal((t) => {
      if (t.name === 'Cemí unlock') {
        forget();
        lockItem.hide();
      }
    }),
    vscode.commands.registerCommand('cemi.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) scanDocument(editor.document, true);
    }),
    vscode.commands.registerCommand('cemi.refresh', forget),
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
