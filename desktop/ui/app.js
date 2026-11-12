// Cemí Desktop interface. Talks to the Rust backend through Tauri's invoke;
// opened in a plain browser, it loads mock.js (fake data) instead.
'use strict';

// ---------- Strings ----------

const STRINGS = {
  es: {
    search: 'Buscar',
    searchPlaceholder: 'Buscar claves o notas',
    minimize: 'Minimizar',
    maximize: 'Maximizar',
    close: 'Cerrar',
    lockedTitle: 'La bóveda está cerrada',
    password: 'Contraseña',
    open: 'Abrir',
    keepOpen: (m) => `Mantenerla abierta ${m} minutos`,
    useRecovery: 'Usar el código de recuperación',
    recoveryHelp: 'Por ahora el código se usa en una terminal: ',
    wrongPassword: 'Contraseña incorrecta.',
    waitSeconds: (s) => `Demasiados intentos. Espera ${s} s.`,
    opening: 'Abriendo…',
    closedByTime: 'La bóveda se cerró por tiempo. Ábrela otra vez.',
    closedElsewhere: 'La bóveda se cerró.',
    noVaultTitle: 'Todavía no hay bóveda',
    noVaultText: 'Cemí usa la bóveda global de esta computadora. Créala en una terminal:',
    noVaultThen: 'Después vuelve aquí.',
    lookAgain: 'Buscar de nuevo',
    sections: 'Secciones',
    navVault: 'Bóveda',
    navAttention: 'Atención',
    navApprovals: 'Aprobaciones',
    navImport: 'Importar',
    navConnect: 'Conectar IA',
    soon: 'pronto',
    vaults: 'Bóvedas',
    closeVault: 'Cerrar la bóveda',
    environment: 'Ambiente',
    keys: (n) => (n === 1 ? '1 clave' : `${n} claves`),
    results: 'Resultados',
    noNotes: 'sin notas',
    noRecords: 'No hay claves en esta entidad.',
    noResults: 'Nada coincide con la búsqueda.',
    pickRecord: 'Elige una clave de la lista.',
    rotate: 'Rotar',
    history: 'Historial',
    edit: 'Editar',
    more: 'Más',
    comingSoon: 'Pronto',
    field: 'Campo',
    valueIn: (env) => (env ? `Valor (${env})` : 'Valor'),
    secret: 'secreto',
    kinds: { text: 'texto', multiline: 'varias líneas', file: 'archivo', url: 'URL', date: 'fecha', number: 'número', template: 'plantilla' },
    noValue: 'sin valor',
    livesIn: (p) => `vive en: ${p}`,
    fileValue: (n) => `archivo ${n}`,
    view: 'Ver',
    copy: 'Copiar',
    noFields: 'Esta clave no tiene campos.',
    memory: 'Memoria',
    noMemory: 'Sin notas todavía.',
    memoryLabels: {
      purpose: 'Para qué', used_in: 'Dónde se usa', rotate: 'Cómo rotar', if_lost: 'Si se pierde',
      if_leaked: 'Si se filtra', expires: 'Vence', backup: 'Respaldo', links: 'Enlaces', delicate: 'Delicado',
    },
    copiedTo: 'Copiada en',
    noDestinations: 'No se copia a ningún sitio.',
    allEnvs: 'todas',
    sentOn: (d) => `enviada ${d}`,
    notSent: 'sin enviar',
    statusOpen: (t) => `Abierta · se cierra en ${t}`,
    statusOpenHere: (t) => `Abierta en esta ventana · se cierra en ${t}`,
    revealTitle: 'Mostrar valor',
    envVersion: (env, v) => [env || 'todos los ambientes', v ? `versión ${v}` : ''].filter(Boolean).join(' · '),
    hidesIn: (s) => `se oculta en ${s} s`,
    confirmedWith: (how, time) => `Confirmado con ${how} a las ${time} · queda en el registro`,
    thePassword: 'la contraseña',
    hide: 'Ocultar',
    copyClears: 'Copiar · se borra en 30 s',
    copied: 'Copiado. El portapapeles se borra en 30 s.',
    confirmTitle: 'Confirma que eres tú',
    whyReveal: 'Para mostrar este valor, escribe la contraseña de la bóveda.',
    whyCopy: 'Para copiar este valor, escribe la contraseña de la bóveda.',
    vaultPassword: 'Contraseña de la bóveda',
    deviceUnavailable: (d, why) => `${d} no está disponible: ${why}`,
    cancel: 'Cancelar',
    confirm: 'Confirmar',
    refused: (d) => `No se confirmó con ${d}.`,
    unreadable: (n) => `${n} objeto(s) de la bóveda no se pudieron abrir. Ejecuta \`cemi doctor\`.`,
    error: 'Algo salió mal: ',
  },
  en: {
    search: 'Search',
    searchPlaceholder: 'Search keys or notes',
    minimize: 'Minimize',
    maximize: 'Maximize',
    close: 'Close',
    lockedTitle: 'The vault is closed',
    password: 'Password',
    open: 'Open',
    keepOpen: (m) => `Keep it open ${m} minutes`,
    useRecovery: 'Use the recovery code',
    recoveryHelp: 'For now the code is used in a terminal: ',
    wrongPassword: 'Wrong password.',
    waitSeconds: (s) => `Too many tries. Wait ${s} s.`,
    opening: 'Opening…',
    closedByTime: 'The vault closed after a while. Open it again.',
    closedElsewhere: 'The vault was closed.',
    noVaultTitle: 'No vault yet',
    noVaultText: 'Cemí uses the global vault of this computer. Create it in a terminal:',
    noVaultThen: 'Then come back here.',
    lookAgain: 'Look again',
    sections: 'Sections',
    navVault: 'Vault',
    navAttention: 'Attention',
    navApprovals: 'Approvals',
    navImport: 'Import',
    navConnect: 'Connect AI',
    soon: 'soon',
    vaults: 'Vaults',
    closeVault: 'Close the vault',
    environment: 'Environment',
    keys: (n) => (n === 1 ? '1 key' : `${n} keys`),
    results: 'Results',
    noNotes: 'no notes',
    noRecords: 'There are no keys in this entity.',
    noResults: 'Nothing matches the search.',
    pickRecord: 'Pick a key from the list.',
    rotate: 'Rotate',
    history: 'History',
    edit: 'Edit',
    more: 'More',
    comingSoon: 'Soon',
    field: 'Field',
    valueIn: (env) => (env ? `Value (${env})` : 'Value'),
    secret: 'secret',
    kinds: { text: 'text', multiline: 'multiline', file: 'file', url: 'URL', date: 'date', number: 'number', template: 'template' },
    noValue: 'no value',
    livesIn: (p) => `lives in: ${p}`,
    fileValue: (n) => `file ${n}`,
    view: 'View',
    copy: 'Copy',
    noFields: 'This key has no fields.',
    memory: 'Memory',
    noMemory: 'No notes yet.',
    memoryLabels: {
      purpose: 'Purpose', used_in: 'Used in', rotate: 'How to rotate', if_lost: 'If lost',
      if_leaked: 'If leaked', expires: 'Expires', backup: 'Backup', links: 'Links', delicate: 'Delicate',
    },
    copiedTo: 'Copied to',
    noDestinations: 'Not copied anywhere.',
    allEnvs: 'all',
    sentOn: (d) => `sent ${d}`,
    notSent: 'not sent',
    statusOpen: (t) => `Open · closes in ${t}`,
    statusOpenHere: (t) => `Open in this window · closes in ${t}`,
    revealTitle: 'Show value',
    envVersion: (env, v) => [env || 'all environments', v ? `version ${v}` : ''].filter(Boolean).join(' · '),
    hidesIn: (s) => `hides in ${s} s`,
    confirmedWith: (how, time) => `Confirmed with ${how} at ${time} · noted in the log`,
    thePassword: 'the password',
    hide: 'Hide',
    copyClears: 'Copy · clears in 30 s',
    copied: 'Copied. The clipboard clears in 30 s.',
    confirmTitle: 'Confirm it is you',
    whyReveal: 'To show this value, type the vault password.',
    whyCopy: 'To copy this value, type the vault password.',
    vaultPassword: 'Vault password',
    deviceUnavailable: (d, why) => `${d} is not available: ${why}`,
    cancel: 'Cancel',
    confirm: 'Confirm',
    refused: (d) => `Not confirmed with ${d}.`,
    unreadable: (n) => `${n} object(s) in the vault could not be opened. Run \`cemi doctor\`.`,
    error: 'Something went wrong: ',
  },
};

const LANG = (navigator.language || 'en').toLowerCase().startsWith('es') ? 'es' : 'en';
const T = STRINGS[LANG];
document.documentElement.lang = LANG;

// ---------- Small helpers ----------

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  vault: 'M7 14a4 4 0 1 1 3.9-5H21v4h-2v2h-3v-2h-5.1A4 4 0 0 1 7 14z',
  alert: 'M12 3 2 20h20L12 3zM12 10v4M12 17v.5',
  check: 'M9 12l2 2 4-4M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z',
  import: 'M12 3v12M7 10l5 5 5-5M4 19h16',
  plug: 'M9 7V3M15 7V3M7 7h10v4a5 5 0 0 1-10 0V7zM12 16v5',
  rotate: 'M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7',
  history: 'M12 7v5l3 2M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5',
  edit: 'M4 20h4L19 9l-4-4L4 16v4z',
  more: 'M5 12h.01M12 12h.01M19 12h.01',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  copy: 'M11 9h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2zM5 15V5a2 2 0 0 1 2-2h10',
};

function icon(name, size) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', `icon-${size || 16}`);
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', ICONS[name]);
  svg.appendChild(path);
  return svg;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function applyStrings() {
  document.querySelectorAll('[data-i18n]').forEach((n) => { n.textContent = T[n.dataset.i18n]; });
  document.querySelectorAll('[data-i18n-label]').forEach((n) => {
    n.setAttribute('aria-label', T[n.dataset.i18nLabel]);
    if (n.tagName === 'BUTTON') n.title = T[n.dataset.i18nLabel];
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((n) => { n.placeholder = T[n.dataset.i18nPlaceholder]; });
}

function formatClock(secs) {
  const s = Math.max(0, Math.floor(secs));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

function formatDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(LANG, { day: 'numeric', month: 'short', year: 'numeric' });
}

function nowTime() {
  return new Date().toLocaleTimeString(LANG, { hour: '2-digit', minute: '2-digit' });
}

let toastTimer = null;
function toast(text, bad) {
  const t = $('toast');
  t.textContent = text;
  t.classList.toggle('bad', !!bad);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 4000);
}

// ---------- Backend ----------

let backend = null;

function invoke(cmd, args) {
  return backend.invoke(cmd, args || {});
}

/** Runs a command; a closed vault sends the person back to the unlock screen. */
async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    const message = String(e && e.message ? e.message : e);
    if (message === 'locked') {
      showUnlock(T.closedByTime);
      return null;
    }
    toast(T.error + message, true);
    return null;
  }
}

// ---------- Window ----------

function setupWindow() {
  const win = backend.window;
  $('win-min').addEventListener('click', () => win.minimize());
  $('win-max').addEventListener('click', () => win.toggleMaximize());
  $('win-close').addEventListener('click', () => win.close());
  const sync = async () => {
    try {
      document.body.classList.toggle('maximized', await win.isMaximized());
    } catch (_) { /* not available in the browser preview */ }
  };
  window.addEventListener('resize', sync);
  sync();
}

// ---------- State ----------

const state = {
  info: null,
  view: null,
  entity: null,
  expanded: new Set(),
  record: null,
  detail: null,
  env: null,
  query: '',
  remaining: 0,
  shared: true,
  wasOpen: false,
};

let tick = null;
let poll = null;

function showScreen(id) {
  for (const s of ['screen-unlock', 'screen-novault', 'screen-vault']) $(s).hidden = s !== id;
  $('search-box').hidden = id !== 'screen-vault';
}

// ---------- Unlock ----------

function showUnlock(notice) {
  stopTimers();
  closeDialogs();
  state.view = null;
  state.detail = null;
  state.record = null;
  state.wasOpen = false;
  showScreen('screen-unlock');
  $('unlock-where').textContent = `global · ${state.info.vault.dir}`;
  $('unlock-keep-label').textContent = T.keepOpen(state.info.vault.ttlMinutes);
  $('unlock-version').textContent = `v${state.info.version}`;
  $('unlock-notice').hidden = !notice;
  $('unlock-notice').textContent = notice || '';
  $('unlock-error').textContent = '';
  $('unlock-password').value = '';
  $('unlock-password').focus();
}

let waitTimer = null;
function blockUnlockFor(secs) {
  const button = $('unlock-submit');
  let left = secs;
  button.disabled = true;
  $('unlock-error').textContent = T.waitSeconds(left);
  clearInterval(waitTimer);
  waitTimer = setInterval(() => {
    left -= 1;
    if (left <= 0) {
      clearInterval(waitTimer);
      button.disabled = false;
      $('unlock-error').textContent = '';
    } else {
      $('unlock-error').textContent = T.waitSeconds(left);
    }
  }, 1000);
}

async function submitUnlock(event) {
  event.preventDefault();
  const input = $('unlock-password');
  const button = $('unlock-submit');
  if (!input.value || button.disabled) return;
  button.disabled = true;
  button.textContent = T.opening;
  $('unlock-error').textContent = '';
  let result;
  try {
    result = await invoke('unlock', { password: input.value, keep: $('unlock-keep').checked });
  } catch (e) {
    result = { status: 'error', message: String(e) };
  }
  input.value = '';
  button.textContent = T.open;
  button.disabled = false;
  switch (result.status) {
    case 'open':
      await enterVault();
      break;
    case 'wrong_password':
      if (result.wait) blockUnlockFor(result.wait);
      else $('unlock-error').textContent = T.wrongPassword;
      input.focus();
      break;
    case 'wait':
      blockUnlockFor(result.wait);
      break;
    case 'no_vault':
      showScreen('screen-novault');
      break;
    default:
      $('unlock-error').textContent = T.error + (result.message || '');
  }
}

// ---------- Session countdown ----------

function stopTimers() {
  clearInterval(tick);
  clearInterval(poll);
  tick = null;
  poll = null;
}

function renderStatus() {
  const clock = formatClock(state.remaining);
  $('status-time').textContent = state.shared ? T.statusOpen(clock) : T.statusOpenHere(clock);
}

async function refreshSession() {
  let s;
  try {
    s = await invoke('session_state');
  } catch (_) {
    return;
  }
  if (!s.open) {
    if (state.wasOpen) showUnlock(T.closedByTime);
    return;
  }
  state.remaining = s.remainingSecs;
  state.shared = s.shared;
  renderStatus();
}

function startTimers() {
  stopTimers();
  tick = setInterval(() => {
    state.remaining = Math.max(0, state.remaining - 1);
    renderStatus();
    if (state.remaining === 0) refreshSession();
  }, 1000);
  poll = setInterval(refreshSession, 5000);
}

// ---------- Vault ----------

async function enterVault() {
  const view = await call('vault_view');
  if (!view) return;
  state.view = view;
  state.wasOpen = true;
  if (!state.entity || !view.entities.some((e) => e.id === state.entity)) {
    state.entity = view.root;
    state.expanded = new Set(view.entities.filter((e) => e.depth < 1).map((e) => e.id));
  }
  showScreen('screen-vault');
  $('status-where').textContent = `global · ${state.info.vault.dir}`;
  $('status-version').textContent = `v${state.info.version}`;
  if (view.unreadable) toast(T.unreadable(view.unreadable), true);
  renderNav();
  renderTree();
  renderList();
  await refreshSession();
  startTimers();
  const first = visibleRecords()[0];
  if (state.record && view.records.some((r) => r.id === state.record)) await selectRecord(state.record);
  else if (first) await selectRecord(first.id);
  else renderDetail();
}

function renderNav() {
  const nav = $('nav');
  clear(nav);
  const items = [
    ['navVault', 'vault', true],
    ['navAttention', 'alert', false],
    ['navApprovals', 'check', false],
    ['navImport', 'import', false],
    ['navConnect', 'plug', false],
  ];
  for (const [key, ic, active] of items) {
    const b = el('button', 'nav-item' + (active ? ' active' : ''));
    b.type = 'button';
    b.appendChild(icon(ic, 16));
    b.appendChild(el('span', 'label', T[key]));
    if (active) b.setAttribute('aria-current', 'page');
    else {
      b.disabled = true;
      b.title = T.comingSoon;
      b.appendChild(el('span', 'soon', T.soon));
    }
    nav.appendChild(b);
  }
}

function entityById(id) {
  return state.view.entities.find((e) => e.id === id);
}

function entityLabel(e) {
  return e.parent ? e.name : 'global';
}

function isVisible(e) {
  let p = e.parent;
  while (p) {
    if (!state.expanded.has(p)) return false;
    p = entityById(p).parent;
  }
  return true;
}

function renderTree() {
  const tree = $('tree');
  clear(tree);
  for (const e of state.view.entities) {
    if (!isVisible(e)) continue;
    const row = el('div', 'tree-item' + (e.id === state.entity ? ' selected' : ''));
    row.setAttribute('role', 'treeitem');
    row.tabIndex = 0;
    row.style.paddingLeft = `${6 + e.depth * 14}px`;
    const chev = el('button', 'tree-chev', e.hasChildren ? (state.expanded.has(e.id) ? '▾' : '▸') : '');
    chev.type = 'button';
    chev.tabIndex = -1;
    if (e.hasChildren) {
      row.setAttribute('aria-expanded', String(state.expanded.has(e.id)));
      chev.addEventListener('click', (ev) => {
        ev.stopPropagation();
        toggleEntity(e.id);
      });
    }
    row.appendChild(chev);
    row.appendChild(el('span', 'tree-label', entityLabel(e)));
    if (e.records) row.appendChild(el('span', 'tree-count', String(e.records)));
    row.addEventListener('click', () => selectEntity(e.id));
    row.addEventListener('dblclick', () => e.hasChildren && toggleEntity(e.id));
    row.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectEntity(e.id); }
      if (ev.key === 'ArrowRight' && e.hasChildren && !state.expanded.has(e.id)) toggleEntity(e.id);
      if (ev.key === 'ArrowLeft' && state.expanded.has(e.id)) toggleEntity(e.id);
    });
    tree.appendChild(row);
  }
}

function toggleEntity(id) {
  if (state.expanded.has(id)) state.expanded.delete(id);
  else state.expanded.add(id);
  renderTree();
}

async function selectEntity(id) {
  state.entity = id;
  if (state.query) {
    state.query = '';
    $('search').value = '';
  }
  renderTree();
  renderList();
  const first = visibleRecords()[0];
  if (first) await selectRecord(first.id);
  else {
    state.record = null;
    state.detail = null;
    renderDetail();
  }
}

function visibleRecords() {
  if (!state.view) return [];
  const q = state.query.trim().toLowerCase();
  if (q) {
    return state.view.records.filter((r) =>
      r.name.toLowerCase().includes(q) || r.path.toLowerCase().includes(q) || r.notes.toLowerCase().includes(q));
  }
  return state.view.records.filter((r) => r.entity === state.entity);
}

function renderEnvSwitch() {
  const box = $('env-switch');
  clear(box);
  const envs = state.detail ? state.detail.envs : [];
  box.hidden = envs.length === 0 || !!state.query;
  for (const env of envs) {
    const b = el('button', env === state.env ? 'on' : '', env);
    b.type = 'button';
    b.setAttribute('aria-pressed', String(env === state.env));
    b.addEventListener('click', () => {
      state.env = env;
      selectRecord(state.record);
    });
    box.appendChild(b);
  }
}

function renderList() {
  const list = $('record-list');
  clear(list);
  const records = visibleRecords();
  const title = $('list-title');
  clear(title);
  if (state.query) {
    title.appendChild(document.createTextNode(T.results + ' '));
  } else {
    const e = entityById(state.entity);
    title.appendChild(document.createTextNode(entityLabel(e) + ' '));
  }
  title.appendChild(el('span', 'count', `· ${T.keys(records.length)}`));
  renderEnvSwitch();
  if (!records.length) {
    list.appendChild(el('div', 'empty', state.query ? T.noResults : T.noRecords));
    return;
  }
  for (const r of records) {
    const row = el('button', 'record' + (r.id === state.record ? ' selected' : ''));
    row.type = 'button';
    const top = el('div', 'record-top');
    top.appendChild(el('span', 'record-name', state.query ? r.path : r.name));
    const dot = el('span', `dot dot-${r.status}`);
    if (r.attention.length) row.title = r.attention.join('\n');
    top.appendChild(dot);
    row.appendChild(top);
    row.appendChild(el('span', 'record-sub', r.purpose || T.noNotes));
    row.addEventListener('click', () => selectRecord(r.id));
    list.appendChild(row);
  }
}

async function selectRecord(id) {
  const detail = await call('record_view', { recordId: id, env: state.env });
  if (!detail) return;
  state.record = id;
  state.detail = detail;
  state.env = detail.env;
  renderList();
  renderDetail();
}

function fieldKindLabel(f) {
  const kind = T.kinds[f.kind] || f.kind;
  if (f.secret) return [T.secret, f.version ? `v${f.version}` : ''].filter(Boolean).join(' · ');
  return kind;
}

function renderDetail() {
  const body = $('detail-body');
  const tools = $('tools');
  clear(body);
  clear(tools);
  const d = state.detail;
  $('detail-title').textContent = d ? d.name : '';
  if (!d) {
    body.appendChild(el('div', 'empty', T.pickRecord));
    return;
  }

  for (const [key, ic] of [['rotate', 'rotate'], ['history', 'history'], ['edit', 'edit'], ['more', 'more']]) {
    const b = el('button', 'tool');
    b.type = 'button';
    b.disabled = true;
    b.title = `${T[key]} · ${T.comingSoon}`;
    b.setAttribute('aria-label', b.title);
    b.appendChild(icon(ic, 14));
    if (key !== 'more') b.appendChild(document.createTextNode(T[key]));
    tools.appendChild(b);
  }

  if (d.purpose) body.appendChild(el('span', 'purpose', d.purpose));
  const item = state.view.records.find((r) => r.id === d.id);
  if (item && item.attention.length) {
    const box = el('div', 'attention' + (item.status === 'bad' ? ' bad' : ''));
    for (const a of item.attention) box.appendChild(el('span', '', a));
    body.appendChild(box);
  }

  // Fields
  const table = el('div', 'table');
  const head = el('div', 'table-row head');
  head.appendChild(el('span', '', T.field));
  head.appendChild(el('span', '', T.valueIn(d.env)));
  head.appendChild(el('span', ''));
  table.appendChild(head);
  if (!d.fields.length) table.appendChild(el('div', 'empty', T.noFields));
  for (const f of d.fields) {
    const row = el('div', 'table-row');
    const name = el('span', 'field-name');
    name.appendChild(el('span', 'strong', f.name));
    name.appendChild(el('span', 'field-kind', fieldKindLabel(f)));
    row.appendChild(name);

    let value;
    if (f.state === 'external') value = el('code', 'field-value none', T.livesIn(f.external));
    else if (f.state === 'empty') value = el('code', 'field-value none', T.noValue);
    else if (f.fileName) value = el('code', 'field-value', T.fileValue(f.fileName));
    else if (f.confirm) value = el('code', 'field-value', '••••••••••••••••••••••••');
    else value = el('code', 'field-value plain', f.value);
    row.appendChild(value);

    const actions = el('span', 'field-actions');
    if (f.state === 'value' && !f.fileName) {
      if (f.confirm) {
        const view = el('button', 'small-btn');
        view.type = 'button';
        view.appendChild(icon('eye', 13));
        view.appendChild(document.createTextNode(T.view));
        view.addEventListener('click', () => requestValue('reveal', f.name, null, view));
        actions.appendChild(view);
      }
      const copy = el('button', 'small-btn');
      copy.type = 'button';
      copy.appendChild(icon('copy', 13));
      copy.appendChild(document.createTextNode(T.copy));
      copy.addEventListener('click', () => requestValue('copy', f.name, null, copy));
      actions.appendChild(copy);
    }
    row.appendChild(actions);
    table.appendChild(row);
  }
  body.appendChild(table);

  // Memory and destinations
  const cards = el('div', 'cards');
  const memory = el('div', 'box');
  memory.appendChild(el('span', 'box-title', T.memory));
  if (!d.memory.length) memory.appendChild(el('span', 'muted', T.noMemory));
  for (const m of d.memory) {
    const row = el('div', 'memory-row');
    row.appendChild(el('span', 'muted', T.memoryLabels[m.key] || m.key));
    row.appendChild(el('span', 'memory-text', m.text));
    memory.appendChild(row);
  }
  cards.appendChild(memory);

  const dests = el('div', 'box');
  dests.appendChild(el('span', 'box-title', T.copiedTo));
  if (!d.destinations.length) dests.appendChild(el('span', 'muted', T.noDestinations));
  for (const x of d.destinations) {
    const row = el('div', 'dest-row');
    row.appendChild(el('span', `dot ${x.lastSent ? 'dot-ok' : 'dot-bare'}`));
    const text = el('span', 'dest-text');
    text.appendChild(el('b', 'strong', x.kind));
    text.appendChild(document.createTextNode(' '));
    text.appendChild(el('span', 'muted', `${x.description} · #${x.field} · ${x.env || T.allEnvs}`));
    row.appendChild(text);
    row.appendChild(el('span', 'pill' + (x.lastSent ? ' sent' : ''), x.lastSent ? T.sentOn(formatDate(x.lastSent)) : T.notSent));
    dests.appendChild(row);
  }
  cards.appendChild(dests);
  body.appendChild(cards);
}

// ---------- Show and copy a value ----------

/**
 * Asks the backend to show (`reveal`) or copy a value. The backend decides
 * how the person confirms; the value itself only comes back for `reveal`.
 */
async function requestValue(kind, field, password, button) {
  const recordId = state.record;
  const env = state.env;
  if (button) button.disabled = true;
  let res;
  try {
    res = await invoke(kind === 'reveal' ? 'reveal' : 'copy_value', { recordId, field, env, password, lang: LANG });
  } catch (e) {
    const message = String(e && e.message ? e.message : e);
    if (button) button.disabled = false;
    if (message === 'locked') showUnlock(T.closedByTime);
    else if (password !== null) $('password-error').textContent = T.error + message;
    else toast(T.error + message, true);
    return;
  }
  if (button) button.disabled = false;
  switch (res.status) {
    case 'granted':
      closePasswordDialog();
      if (kind === 'reveal') openReveal(res, field);
      else toast(T.copied);
      break;
    case 'need_password':
      openPasswordDialog(kind, field, res.reason ? T.deviceUnavailable(res.device, res.reason) : null);
      break;
    case 'wrong_password':
      $('password-error').textContent = res.wait ? T.waitSeconds(res.wait) : T.wrongPassword;
      $('password-input').value = '';
      $('password-input').focus();
      break;
    case 'wait':
      $('password-error').textContent = T.waitSeconds(res.wait);
      break;
    case 'refused':
      toast(T.refused(res.device), true);
      break;
    default:
      toast(T.error + res.status, true);
  }
}

let passwordRequest = null;

function openPasswordDialog(kind, field, reason) {
  passwordRequest = { kind, field };
  $('password-why').textContent = kind === 'reveal' ? T.whyReveal : T.whyCopy;
  $('password-reason').hidden = !reason;
  $('password-reason').textContent = reason || '';
  $('password-error').textContent = '';
  $('password-input').value = '';
  $('overlay').hidden = false;
  $('password-dialog').hidden = false;
  $('password-input').focus();
}

function closePasswordDialog() {
  passwordRequest = null;
  $('password-input').value = '';
  $('password-dialog').hidden = true;
  if ($('reveal-dialog').hidden) $('overlay').hidden = true;
}

async function submitPassword(event) {
  event.preventDefault();
  if (!passwordRequest) return;
  const input = $('password-input');
  const button = $('password-submit');
  if (!input.value || button.disabled) return;
  const { kind, field } = passwordRequest;
  const pw = input.value;
  input.value = '';
  $('password-error').textContent = '';
  button.disabled = true;
  try {
    await requestValue(kind, field, pw, null);
  } finally {
    button.disabled = false;
  }
}

const REVEAL_SECONDS = 20;
let reveal = null;

function openReveal(res, field) {
  closeReveal();
  const how = res.by === 'device' ? res.device : T.thePassword;
  $('reveal-ref').textContent = res.reference;
  $('reveal-env').textContent = T.envVersion(res.env, res.version);
  $('reveal-value').textContent = res.value;
  res.value = null;
  $('reveal-confirmed').textContent = T.confirmedWith(how, nowTime());
  const bar = $('reveal-bar');
  bar.style.transition = 'none';
  bar.style.width = '100%';
  reveal = { left: REVEAL_SECONDS, field, timer: null };
  $('reveal-left').textContent = T.hidesIn(reveal.left);
  $('overlay').hidden = false;
  $('reveal-dialog').hidden = false;
  requestAnimationFrame(() => {
    bar.style.transition = '';
    bar.style.width = `${((reveal.left - 1) / REVEAL_SECONDS) * 100}%`;
  });
  reveal.timer = setInterval(() => {
    reveal.left -= 1;
    if (reveal.left <= 0) {
      closeReveal();
      return;
    }
    $('reveal-left').textContent = T.hidesIn(reveal.left);
    bar.style.width = `${((reveal.left - 1) / REVEAL_SECONDS) * 100}%`;
  }, 1000);
  $('reveal-hide').focus();
}

/** Takes the value out of the page. */
function closeReveal() {
  if (reveal) {
    clearInterval(reveal.timer);
    // The copy button of this dialog no longer works without confirming.
    invoke('end_reveal').catch(() => {});
  }
  reveal = null;
  const v = $('reveal-value');
  v.textContent = '';
  clear(v);
  $('reveal-ref').textContent = '';
  $('reveal-dialog').hidden = true;
  if ($('password-dialog').hidden) $('overlay').hidden = true;
  const sel = window.getSelection && window.getSelection();
  if (sel) sel.removeAllRanges();
}

function closeDialogs() {
  closeReveal();
  closePasswordDialog();
}

// ---------- Search and keys ----------

function setupSearch() {
  const input = $('search');
  input.addEventListener('input', () => {
    state.query = input.value;
    renderList();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      input.value = '';
      state.query = '';
      renderList();
      input.blur();
    }
    if (e.key === 'Enter') {
      const first = visibleRecords()[0];
      if (first) selectRecord(first.id);
    }
  });
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k' && !$('screen-vault').hidden) {
      e.preventDefault();
      input.focus();
      input.select();
    }
    if (e.key === 'Escape') {
      if (!$('password-dialog').hidden) closePasswordDialog();
      else if (!$('reveal-dialog').hidden) closeReveal();
    }
  });
}

// ---------- Start ----------

async function lockVault() {
  closeDialogs();
  try {
    await invoke('lock');
  } catch (_) { /* closing anyway */ }
  showUnlock(T.closedElsewhere);
}

async function start() {
  applyStrings();
  setupWindow();
  setupSearch();
  $('unlock-form').addEventListener('submit', submitUnlock);
  $('recovery-link').addEventListener('click', () => {
    const help = $('recovery-help');
    clear(help);
    help.appendChild(document.createTextNode(T.recoveryHelp));
    help.appendChild(el('code', '', 'cemi recovery'));
    help.hidden = !help.hidden;
  });
  $('novault-retry').addEventListener('click', findVault);
  $('lock-button').addEventListener('click', lockVault);
  $('reveal-hide').addEventListener('click', closeReveal);
  $('reveal-close').addEventListener('click', closeReveal);
  $('reveal-copy').addEventListener('click', (e) => reveal && requestValue('copy', reveal.field, null, e.currentTarget));
  $('password-dialog').addEventListener('submit', submitPassword);
  $('password-cancel').addEventListener('click', closePasswordDialog);
  $('password-close').addEventListener('click', closePasswordDialog);
  document.addEventListener('contextmenu', (e) => e.preventDefault());
  await findVault();
}

async function findVault() {
  state.info = await invoke('app_info');
  if (!state.info.vault.exists) {
    showScreen('screen-novault');
    return;
  }
  if (await invoke('resume')) await enterVault();
  else showUnlock();
}

let started = false;
function boot() {
  if (started) return;
  started = true;
  start();
}

if (window.__TAURI__) {
  backend = {
    invoke: (cmd, args) => window.__TAURI__.core.invoke(cmd, args),
    window: window.__TAURI__.window.getCurrentWindow(),
  };
  boot();
} else {
  // A normal browser: fake data, for looking at the interface.
  const script = document.createElement('script');
  script.src = 'mock.js';
  script.addEventListener('load', () => {
    backend = window.CemiMock;
    boot();
  });
  document.head.appendChild(script);
}
