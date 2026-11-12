// A fake backend for looking at the interface in a normal browser (no
// Tauri). Loaded by app.js only when window.__TAURI__ is missing. All the
// data is made up, and the "values" are placeholders, not real key formats.
// The password of this fake vault is "demo".
'use strict';

(function () {
  const now = Date.now();
  const days = (n) => new Date(now + n * 86400000).toISOString().slice(0, 10);

  const entities = [
    { id: 'e-root', name: '', parent: null, depth: 0, path: '', hasChildren: true, envs: ['dev', 'staging', 'prod'] },
    { id: 'e-acme', name: 'acme', parent: 'e-root', depth: 1, path: 'acme', hasChildren: true },
    { id: 'e-tienda', name: 'tienda', parent: 'e-acme', depth: 2, path: 'acme/tienda', hasChildren: false },
    { id: 'e-blog', name: 'blog', parent: 'e-acme', depth: 2, path: 'acme/blog', hasChildren: false },
    { id: 'e-cuentas', name: 'cuentas', parent: 'e-root', depth: 1, path: 'cuentas', hasChildren: true },
    { id: 'e-bancos', name: 'bancos', parent: 'e-cuentas', depth: 2, path: 'cuentas/bancos', hasChildren: false },
  ];

  const text = (value, version) => ({ value, version });
  const records = [
    {
      id: 'r-stripe', entity: 'e-tienda', name: 'stripe',
      memory: {
        purpose: 'Cobros con tarjeta de la tienda en línea',
        rotate: 'Panel del proveedor → Developers → API keys → Roll key.',
        if_leaked: 'Rotarla ya y revisar los cobros de las últimas 24 h.',
        expires: days(9),
      },
      attention: ['expires on ' + days(9) + ' (in 9 days)'], status: 'warn',
      fields: [
        { name: 'key', kind: 'text', secret: true, values: { dev: text('DEMO-NOT-A-REAL-KEY-dev-0001', 3), prod: text('DEMO-NOT-A-REAL-KEY-prod-0001', 5) } },
        { name: 'publishable', kind: 'text', secret: false, values: { '*': text('demo-public-value-abc', 1) } },
        { name: 'account', kind: 'text', secret: false, values: { '*': text('demo-account-tienda', 1) } },
      ],
      destinations: [
        { field: 'key', env: 'prod', kind: 'GitHub', description: 'GitHub acme/shop: secret STRIPE_KEY', lastSent: new Date(now - 3 * 86400000).toISOString() },
        { field: 'key', env: 'prod', kind: 'Vercel', description: 'Vercel project shop: STRIPE_KEY (production)', lastSent: new Date(now - 3 * 86400000).toISOString() },
        { field: 'key', env: 'dev', kind: '.env', description: 'C:\\proyectos\\tienda\\.env (STRIPE_KEY)', lastSent: null },
      ],
    },
    {
      id: 'r-supabase', entity: 'e-tienda', name: 'supabase',
      memory: { purpose: 'Base de datos y login', used_in: 'API de la tienda y el panel', backup: 'Copia en papel en la caja fuerte' },
      attention: [], status: 'ok',
      fields: [
        { name: 'service_key', kind: 'text', secret: true, values: { '*': text('DEMO-PLACEHOLDER-service-role', 2) } },
        { name: 'url', kind: 'url', secret: false, values: { '*': text('https://demo-project.example.test', 1) } },
        { name: 'db_url', kind: 'template', secret: false, values: { '*': text('postgres://app:DEMO-PASSWORD@db.example.test/app', 1) } },
      ],
      destinations: [],
    },
    {
      id: 'r-resend', entity: 'e-tienda', name: 'resend',
      memory: { purpose: 'Correos · rotación a medias' },
      attention: ['api_key: rotation started but not finished'], status: 'bad',
      fields: [{ name: 'api_key', kind: 'text', secret: true, values: { '*': text('DEMO-PLACEHOLDER-mail-key', 4) } }],
      destinations: [],
    },
    {
      id: 'r-webhook', entity: 'e-tienda', name: 'webhook',
      memory: { purpose: 'Firma de avisos de pagos' },
      attention: [], status: 'ok',
      fields: [{ name: 'signing_secret', kind: 'text', secret: true, values: { '*': { external: 'GitHub environment production' } } }],
      destinations: [],
    },
    {
      id: 'r-cloudflare', entity: 'e-tienda', name: 'cloudflare',
      memory: {},
      attention: ['no purpose noted (cemi note --purpose)'], status: 'bare',
      fields: [{ name: 'token', kind: 'text', secret: true, values: {} }],
      destinations: [],
    },
    {
      id: 'r-ghost', entity: 'e-blog', name: 'ghost',
      memory: { purpose: 'Panel del blog' },
      attention: [], status: 'ok',
      fields: [
        { name: 'admin_key', kind: 'text', secret: true, values: { '*': text('DEMO-PLACEHOLDER-blog-admin', 1) } },
        { name: 'cert', kind: 'file', secret: true, values: { '*': { file: 'demo-cert.pem', version: 1 } } },
      ],
      destinations: [],
    },
    {
      id: 'r-correo', entity: 'e-root', name: 'correo',
      memory: { purpose: 'Cuenta de correo principal', delicate: 'Tiene la recuperación de todo lo demás' },
      attention: [], status: 'ok',
      fields: [
        { name: 'user', kind: 'text', secret: false, values: { '*': text('persona@example.test', 1) } },
        { name: 'password', kind: 'text', secret: true, values: { '*': text('demo password with spaces', 2) } },
      ],
      destinations: [],
    },
    {
      id: 'r-banco', entity: 'e-bancos', name: 'banco',
      memory: { purpose: 'Banca en línea' },
      attention: [], status: 'ok',
      fields: [{ name: 'pin', kind: 'number', secret: true, values: { '*': text('0000', 1) } }],
      destinations: [],
    },
  ];

  const PASSWORD = 'demo';
  const TTL = 15 * 60;
  const MEMORY_ORDER = ['purpose', 'used_in', 'rotate', 'if_lost', 'if_leaked', 'expires', 'backup', 'links', 'delicate'];
  let open = false;
  let expires = 0;
  let failures = 0;
  let blockedUntil = 0;
  let grace = null;

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const entity = (id) => entities.find((e) => e.id === id);
  const record = (id) => {
    const r = records.find((x) => x.id === id);
    if (!r) throw new Error('that record is no longer in the vault');
    return r;
  };
  // Every entity inherits the environments of the root, as in a new vault.
  const envsOf = () => entity('e-root').envs.slice();
  const pathOf = (r) => (entity(r.entity).path ? entity(r.entity).path + '/' : '') + r.name;
  const slot = (f, env) => (env && f.values[env]) || f.values['*'];
  const touch = () => { expires = Date.now() + TTL * 1000; };
  const requireOpen = () => {
    if (!open || Date.now() > expires) {
      open = false;
      throw 'locked';
    }
    touch();
  };
  const remaining = () => Math.max(0, Math.round((expires - Date.now()) / 1000));

  function checkPassword(pw) {
    if (Date.now() < blockedUntil) return { status: 'wait', wait: Math.ceil((blockedUntil - Date.now()) / 1000) };
    if (pw === PASSWORD) {
      failures = 0;
      return null;
    }
    failures += 1;
    if (failures >= 3) {
      failures = 0;
      blockedUntil = Date.now() + 30000;
      return { status: 'wrong_password', wait: 30 };
    }
    return { status: 'wrong_password', wait: null };
  }

  async function value(args, reveal) {
    requireOpen();
    const r = record(args.recordId);
    const f = r.fields.find((x) => x.name === args.field);
    const confirm = f.secret || f.kind === 'template';
    const out = { status: 'granted', device: 'Windows Hello', reference: `global:${pathOf(r)}#${f.name}`, env: args.env, by: 'none' };
    const covered = !reveal && grace && grace.recordId === args.recordId && grace.field === args.field && grace.env === args.env && Date.now() < grace.until;
    if (confirm && covered) out.by = grace.by;
    else if (confirm) {
      if (!args.password) return { status: 'need_password', device: 'Windows Hello', reason: 'not available in the browser preview' };
      await sleep(400);
      const bad = checkPassword(args.password);
      if (bad) {
        if (bad.status === 'wrong_password') await sleep(1000);
        return { ...bad, device: 'Windows Hello' };
      }
      out.by = 'password';
    }
    const s = slot(f, args.env);
    out.version = s && s.version;
    if (reveal) {
      out.value = s.value;
      grace = { recordId: args.recordId, field: args.field, env: args.env, by: out.by, until: Date.now() + 20000 };
    }
    return out;
  }

  const commands = {
    app_info: () => ({ version: '0.6.0', platform: 'browser', vault: { exists: true, dir: 'C:\\Users\\demo\\.cemi', ttlMinutes: 15 } }),
    session_state: () => {
      if (open && Date.now() > expires) open = false;
      return { open, remainingSecs: open ? remaining() : 0, shared: true };
    },
    resume: () => open,
    unlock: async ({ password, keep }) => {
      await sleep(500);
      const bad = checkPassword(password);
      if (bad) {
        if (bad.status === 'wrong_password') await sleep(1000);
        return bad;
      }
      open = true;
      touch();
      void keep;
      return { status: 'open' };
    },
    lock: () => { open = false; grace = null; },
    end_reveal: () => { grace = null; },
    vault_view: () => {
      requireOpen();
      return {
        root: 'e-root',
        unreadable: 0,
        entities: entities.map(({ envs, ...e }) => ({ ...e, records: records.filter((r) => r.entity === e.id).length })),
        records: records.map((r) => ({
          id: r.id, entity: r.entity, name: r.name, path: pathOf(r),
          purpose: r.memory.purpose || null, notes: Object.values(r.memory).join('\n'),
          status: r.status, attention: r.attention,
        })),
      };
    },
    record_view: ({ recordId, env }) => {
      requireOpen();
      const r = record(recordId);
      const envs = envsOf(r.entity);
      const chosen = envs.includes(env) ? env : envs[0] || null;
      return {
        id: r.id, name: r.name, path: pathOf(r), entityPath: entity(r.entity).path,
        envs, env: chosen, protected: chosen === 'prod', purpose: r.memory.purpose || null,
        fields: r.fields.map((f) => {
          const s = slot(f, chosen);
          const confirm = f.secret || f.kind === 'template';
          const state = !s ? 'empty' : s.external ? 'external' : 'value';
          return {
            name: f.name, kind: f.kind, secret: f.secret, confirm, state,
            value: state === 'value' && !confirm && !s.file ? s.value : null,
            fileName: s && s.file ? s.file : null,
            version: s && s.version ? s.version : null,
            external: s && s.external ? s.external : null,
            shared: !!(s && s === f.values['*']),
          };
        }),
        memory: MEMORY_ORDER.filter((k) => r.memory[k]).map((k) => ({ key: k, text: r.memory[k] })),
        destinations: r.destinations,
      };
    },
    reveal: (args) => value(args, true),
    copy_value: (args) => value(args, false),
  };

  window.CemiMock = {
    async invoke(cmd, args) {
      const run = commands[cmd];
      if (!run) throw new Error(`unknown command ${cmd}`);
      return run(args || {});
    },
    window: {
      minimize: () => {},
      toggleMaximize: () => {},
      close: () => {},
      isMaximized: async () => false,
    },
  };
})();
