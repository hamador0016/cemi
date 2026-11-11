# Hoja de ruta

[English](roadmap.md)

Cada versión está lista cuando la frase de *Lista cuando* es cierta. Todas compilan y pasan sus
pruebas en Windows, macOS y Linux.

## v0.1 — Bóveda, memoria e IA sin valores (lista)

Bóvedas, estructura libre, ambientes, memoria, `status`, `run`, `cemi.toml`,
`import`/`export`, servidor MCP con tokens limitados, `mcp launch`, auditoría, `scan` y el
pre-commit.

## v0.2 — Rotación (lista)

- **Orígenes y destinos.** Cemí sabe dónde nace cada llave y cada lugar donde se copia, por
  ambiente.
- **Conectores**: secretos de GitHub Actions, Supabase (secretos de funciones y llaves de API),
  archivos `.env` locales y cualquier comando tuyo. Los conectores externos
  (`cemi-connector-<nombre>`) hablan JSON por stdin, así cualquiera agrega un proveedor.
- **Huellas**: cada destino recuerda un hash del último valor enviado, así `cemi check` ve qué
  está desactualizado o se cambió por fuera de Cemí.
- `cemi push`, `cemi check`, `cemi rotate` (plan → aprobar → crear → propagar → verificar →
  confirmar → revocar, con vuelta atrás automática) y `cemi incident` para llaves filtradas.
- **Aprobación** que una IA no puede dar: los cambios en producción piden la contraseña de la
  bóveda escrita por una persona; lo que pida una IA espera a `cemi approve`.
- Herramientas MCP `check`, `push` y `rotate`: la IA recibe planes y resultados, nunca valores.

*Lista cuando:* una llave filtrada se reemplaza en todos los lugares donde se usa con un
comando.

## v0.3 — Uso diario (en curso)

Hecho:

- `cemi import --discover`: encuentra los `.env` de tus proyectos, los trae a la bóveda y avisa
  de `.env` subidos a git o fuera de `.gitignore`, valores repetidos entre proyectos y archivos
  que no cambian hace un año.
- Autocompletado (PowerShell, bash, zsh, fish, elvish) que también completa nombres de
  registros, entidades y ambientes mientras la bóveda está abierta.
- Buscador interactivo: `cemi copy` sin argumentos.
- `cemi types`: tipos de TypeScript o un esquema zod generados desde `cemi.toml`, con `--check`
  para CI.
- Presets: `cemi init --preset next-supabase` (también `supabase`, `stripe`, `resend`,
  `postgres`) crea la estructura típica con sus notas de memoria; `cemi preset add` para
  proyectos que ya existen.
- Salida `--json` y códigos de salida estables en todos los comandos
  ([docs/scripting.md](scripting.md)).
- Secretos en CI sin copiarlos a mano: `cemi ci export` cifra solo lo que el CI necesita para
  una llave hecha para el CI, y la acción `cemi` de GitHub (o `cemi ci load` en cualquier CI)
  lo abre al correr.
- `cemi prompt` para el prompt de la terminal (Starship) con lo que hay que hacer pronto, como
  llaves que vencen esta semana.
- `cemi deps` entre proyectos: cada bóveda recuerda los proyectos que la usan, así un comando
  muestra todos los proyectos, plantillas, conectores, servidores MCP, destinos y archivos de CI
  que usan un valor. `cemi status` avisa de archivos de CI con valores viejos; `cemi rotate` los
  menciona.

Falta:

- Extensión de VS Code: al pasar el mouse sobre una variable muestra para qué sirve, cuándo
  vence y cómo se rota (nunca el valor); avisa de secretos escritos en el código.

*Lista cuando:* quien instala Cemí pasa sus `.env` a la bóveda el primer día y sigue usándola.

## v0.4 — Producción

- App de escritorio (bandeja) con aprobación por Windows Hello o Touch ID.
- Proxy de credenciales: la IA llama a las API HTTP y el proxy agrega la llave, así el comando
  nunca la recibe. Con esto la IA puede usar `run` en producción.
- Más conectores: Cloudflare, Netlify, Vercel, Resend, servidores por SSH.

*Lista cuando:* una IA prueba API de producción sin tener nunca una llave de producción.

## v0.5 — Equipos y varias máquinas

- `cemi share acme/tienda --with <llave pública>`: da una entidad a otro desarrollador. Cada
  objeto ya se cifra para una lista de destinatarios, así que no hace falta servidor.
- `cemi sync`: la bóveda es un archivo cifrado por objeto, así que se sincroniza con un repo git
  privado y los conflictos se resuelven objeto por objeto.

*Lista cuando:* un segundo desarrollador recibe solo `acme/tienda` de `dev`.

## Antes de la primera versión pública

En una herramienta de secretos, la confianza pesa más que las funciones. Todo esto es gratis y
va antes de anunciar Cemí:

- **Pruebas de compatibilidad**: una bóveda creada con la v0.1 vive en el repo y cada versión
  nueva tiene que abrirla.
- **Fuzzing** (`cargo-fuzz`) de todo lo que lee datos de afuera: referencias, `.env`,
  `cemi.toml` y archivos de la bóveda.
- **Instaladores verificables** con cargo-dist: checksums SHA-256, atestación de origen
  (`actions/attest-build-provenance`) y firmas minisign que verifica `cemi self update`.
- **Cadena de dependencias**: acciones fijadas por hash, Dependabot, OpenSSF Scorecard.
- **Repo**: `main` protegida, CHANGELOG (git-cliff), versionado semántico, plantillas de issues.
- **Reservar el nombre** en crates.io (y npm para el instalador).
- **Auditoría externa** cuando haya usuarios (OSTIF apoya proyectos open source de seguridad).

## Difusión

- Una grabación de 20 segundos en el README (asciinema): `import` → `run` → una IA usando una
  llave que nunca ve.
- Sitio de documentación con mdBook en GitHub Pages.
- Una comparación justa con dotenvx, SOPS, Infisical y el CLI de 1Password.
- Instaladores: Scoop y winget (Windows), Homebrew (macOS), `cargo binstall`.
- Anunciarlo en Show HN y r/rust cuando salga la v0.2.
