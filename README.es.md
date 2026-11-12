# Cemí

**Secretos con memoria que tu IA puede usar sin ver.**

[English](README.md)

Cemí guarda tus API keys, tokens y contraseñas cifrados en tu computadora, junto con para qué
sirve cada uno, dónde se usa y cómo reemplazarlo. Tus proyectos corren con ellos inyectados, y
los asistentes de IA (Claude, ChatGPT, Cursor… por MCP) pueden usarlos sin recibir nunca los
valores.

*El nombre viene del cemí taíno, una figura tallada que protegía lo que su dueño valoraba.*

> **Estado: v0.2, temprana.** El formato y los comandos todavía pueden cambiar. Lee
> [docs/threat-model.md](docs/threat-model.md) antes de confiarle secretos de producción.

## Por qué

- **Los secretos están regados**: secretos de CI, archivos `.env`, servidores, secretos de
  funciones, un gestor de contraseñas. Algunos no se guardan en ningún lado ("si se pierde, se
  regenera"), pero igual hay que saber que existen.
- **Lo importante no es el valor**: para qué sirve, dónde está copiado, cómo se rota, cuándo
  vence, si tiene respaldo. Todos terminan anotándolo a mano.
- **Las IAs necesitan llaves** para correr pruebas o desplegar, y la forma habitual de dárselas
  (pegarlas en el chat, o un `.env` que la IA lee) las filtra.

## Qué lo hace distinto

- **Tu estructura, no un esquema fijo.** Entidades dentro de entidades (`acme/tienda`),
  registros dentro, y campos con el nombre que tú quieras.
- **Memoria junto a cada secreto**: para qué sirve, dónde se usa, cómo rotarlo, qué hacer si se
  pierde o se filtra, vencimiento, respaldo. `cemi status` dice qué necesita atención.
- **Ambientes** (`dev`, `prod`…) que se heredan hacia abajo.
- **La IA usa, nunca ve.** Ninguna herramienta MCP devuelve un valor secreto. La IA puede listar,
  leer notas, generar secretos y correr comandos permitidos con los secretos inyectados y
  ocultos en la salida. Una persona desbloquea la bóveda; los tokens tienen alcance, vencen y se
  pueden revocar.
- **Formato abierto.** Cada registro es un archivo [age](https://age-encryption.org). Si Cemí
  desaparece, tus datos se abren con herramientas estándar.
- **Local primero.** Sin cuenta, sin servidor, sin red.

## Instalar

```bash
cargo install --git https://github.com/hamador0016/cemi --locked
```

Con la primera versión publicada: `cargo install cemi`, `npm install -g cemi`, Homebrew y un
script de instalación, y también `npm install --save-dev cemi` o `mise use cemi` para fijarlo
por proyecto.

Autocompletado con Tab, incluidos los nombres de tus registros y ambientes mientras la bóveda
está abierta: `cemi completion powershell` (o `bash`, `zsh`, `fish`, `elvish`) imprime la línea
para el perfil de tu terminal.

En tu prompt, `cemi prompt` imprime `cemi !2` cuando hay dos cosas que hacer pronto (una llave
que vence esta semana, una rotación que no terminó, una aprobación esperando, un destino
desactualizado), `cemi locked` en un proyecto cuya bóveda está cerrada, y nada en otro caso.
Con [Starship](https://starship.rs):

```toml
[custom.cemi]
command = "cemi prompt"
when = true
style = "bold yellow"
```

## Primeros pasos

```bash
# Una vez por computadora: la bóveda global (llaves compartidas)
cemi init --global

# En un proyecto, como `git init`
cd mi-proyecto
cemi init                         # crea .cemi/ (ignorada por git) y cemi.toml
cemi add db
cemi field add db password --secret
cemi set db#password -e dev       # se escribe oculto; nunca como argumento
cemi field add db url --type template
cemi set db#url --stdin <<< 'postgres://app:{{db#password}}@localhost/app'
cemi var add DATABASE_URL db#url  # cemi.toml guarda una referencia, no el valor
cemi run -e dev -- npm run dev    # DATABASE_URL llega inyectada
cemi note db --purpose "base de la app" --rotate "ALTER ROLE app PASSWORD …" --backup "gestor de contraseñas"
cemi status
```

La bóveda del proyecto se abre con tu contraseña global. Las llaves compartidas pueden vivir en
la global y usarse desde cualquier proyecto: `cemi var add CF_TOKEN global:cuentas/cloudflare#token`.

Para un stack común, empieza con un preset en vez de una bóveda vacía:

```bash
cemi init --preset next-supabase --preset stripe
```

Crea los registros con sus campos, notas sobre cómo rotar cada llave y qué hacer si se filtra,
y las variables en `cemi.toml`; después lista los `cemi set` para los valores. `cemi preset ls`
los muestra todos (Supabase, Next.js + Supabase, Stripe, Resend, Postgres); `cemi preset add`
agrega uno a un proyecto que ya existe.

## ¿Ya tienes archivos .env?

```bash
cemi import --discover ~/code
```

Cemí busca los `.env` de cada proyecto dentro de esa carpeta (sin entrar a `node_modules`, a
las carpetas de compilación ni a los `.env.example`) y muestra lo que encontró antes de cambiar
nada:

```text
  shop  →  global:shop
    .env                       all        2 variables
    .env.local                 dev        1 variable
    .env.production            prod       1 variable

! shop/.env.production is committed to git: anyone with the repository has these keys. …
! web/.env is not in .gitignore: one `git add .` away from being committed
! The same value is in PAYMENTS in web/.env, STRIPE_KEY in shop/.env.local: …
! api/.env.staging has not changed since 2024-01-01: its keys may be due for rotation
```

Avisa de los `.env` subidos a git, de los que no están en `.gitignore`, de valores repetidos
entre proyectos y de archivos que no cambian hace más de un año. Si dices que sí, cada proyecto
recibe una entidad en la bóveda global y un `cemi.toml` que apunta a ella. El ambiente sale del
nombre del archivo: `.env` vale para todos, y `.env.<ambiente>` y `.env.local` lo
sobrescriben, igual que los leen la mayoría de las herramientas. Después, `cemi run -e dev --
<tu comando>` en cada carpeta, y los `.env` se pueden borrar.

## Tipos para tus variables

```bash
cemi types -o env.d.ts                       # process.env.DATABASE_URL es string, no string | undefined
cemi types --format zod -o src/env.ts        # un esquema zod que al arrancar nombra cada variable que falte
cemi types -o env.d.ts --check               # en CI: falla si cemi.toml cambió y el archivo no
```

Salen solo de `cemi.toml`, así que son iguales en cualquier computadora y en CI.

## Con un asistente de IA

```bash
cemi token create claude --allow read --allow run --env dev --expires 7d
cemi mcp setup claude-code --token-name claude
```

Y en `cemi.toml`, lo que la IA puede correr:

```toml
[ai.commands]
test = { cmd = ["npm", "test"], envs = ["dev"] }
```

Para otros servidores MCP que piden un token en su configuración:

```bash
cemi mcp add supabase --env SUPABASE_ACCESS_TOKEN=global:cuentas/supabase#token -- npx -y @supabase/mcp-server-supabase
# En el cliente de IA, el comando pasa a ser: cemi mcp launch supabase
```

**Lo que el ocultamiento no cubre.** Un comando que recibe un secreto en sus variables
igual puede mandarlo a otro lado o imprimirlo con una codificación que Cemí no reconoce. Cemí lo
acota: los clientes de IA solo corren los comandos que listas y en los ambientes que listas. En
los ambientes protegidos (`prod` por defecto) una IA solo puede correr un comando si todos sus
secretos pasan por el proxy de credenciales, así el comando nunca recibe una llave. Detalles en
[docs/threat-model.md](docs/threat-model.md).

## APIs de producción sin la llave

Dile a Cemí a qué API entra una llave y qué llamadas puede hacer una IA con ella:

```bash
cemi api add acme/shop/stripe#secret -e prod --base https://api.stripe.com \
  --auth basic --allow "GET /v1/**" --allow "POST /v1/refunds"
cemi token create claude --allow read --allow api --env prod --expires 1d
```

La IA usa la herramienta MCP `call_api` (`GET /v1/balance` con `acme/shop/stripe#secret`,
`prod`). Cemí agrega la llave, manda la solicitud solo a `https://api.stripe.com`, rechaza
cualquier método o ruta fuera de las reglas, no sigue redirecciones y oculta la llave si la
respuesta la trae. Puedes probar la misma llamada con
`cemi api call stripe#secret -e prod GET /v1/balance`.

Con programas funciona igual. En `cemi.toml`, la variable que lleva la dirección de la API:

```toml
[env]
STRIPE_SECRET_KEY = "stripe#secret"

[proxy]
STRIPE_API_BASE = "stripe#secret"
```

`cemi run --proxy -e prod -- npm test` arranca un proxy en `127.0.0.1` para esa corrida.
`STRIPE_SECRET_KEY` recibe un marcador y `STRIPE_API_BASE` la dirección del proxy, que cambia el
marcador por la llave. El `run` de una IA en un ambiente protegido siempre funciona así, y falla
si algún secreto del comando no tiene API. El programa tiene que leer la dirección de la API de
una variable; la mayoría de los SDK aceptan una URL base.

## Rotar una llave en todos lados

Le dices a Cemí, una vez, dónde nace cada llave y adónde se copia:

```bash
cemi origin set tienda/supabase#key -e prod supabase-key --project abcdefghijklmnopqrst --token global:cuentas/supabase#token
cemi dest add tienda/supabase#key -e prod github --repo acme/tienda --name SUPABASE_KEY --environment production
cemi dest add tienda/supabase#key -e prod dotenv --file .env.production --key SUPABASE_KEY
cemi verify tienda/supabase#key -e prod -- npm run check:supabase
```

Desde ahí:

```bash
cemi check                                     # desactualizados, cambiados por fuera, faltantes
cemi push                                      # envía los valores actuales donde falten
cemi rotate tienda/supabase#key -e prod        # llave nueva → cada destino → verificar → revocar la vieja
cemi incident tienda/supabase#key -e prod      # se filtró: dónde está, quién la usó; --rotate la reemplaza
```

Si un destino o la verificación falla, la llave vieja vuelve a todos lados. Incluidos: secretos
de GitHub Actions, llaves de API y secretos de funciones de Supabase, archivos `.env` y
cualquier comando; cualquiera puede agregar un proveedor con un programa pequeño. Ver
[docs/connectors.md](docs/connectors.md).

`prod` está protegido: los cambios ahí piden tu contraseña, y si una IA los pide por MCP solo
crea una solicitud que tú apruebas con `cemi approve`.

## Secretos en CI

El CI recibe una sola llave; los valores viajan cifrados dentro del repositorio.

```bash
cemi ci setup --repo acme/shop        # una llave solo para el CI; GitHub la recibe como el secreto CEMI_CI_KEY
cemi ci export -e prod                # cemi.ci.age: las variables de este proyecto para prod, cifradas
git add cemi.ci.age cemi.toml && git commit -m "Secretos de CI"
```

```yaml
# .github/workflows/deploy.yml
- uses: hamador0016/cemi@main
  with:
    key: ${{ secrets.CEMI_CI_KEY }}
- run: npm run deploy                 # las variables están puestas, y ocultas en el log
```

En otros CI, define `CEMI_CI_KEY` y corre `cemi ci load -- <comando>`. `--only` (o `vars` en
`cemi.toml [ci]`) limita lo que va al CI. Después de cambiar un valor, exporta otra vez
(`cemi status` te lo recuerda). Si la
llave del CI se filtra, reemplázala (`cemi ci setup --new-key`) y también los valores del
archivo: las copias viejas del archivo quedan en el historial de git.

## Qué usa una llave

Cada bóveda recuerda los proyectos cuyo `cemi.toml` la usa (cifrado, como todo lo demás en la
bóveda). Un proyecto queda anotado la primera vez que `cemi` abre la bóveda desde su carpeta, o
con `cemi project add <carpeta>`. Así, una sola pregunta cubre todos los proyectos:

```bash
cemi deps global:accounts/cloudflare#token
```

```text
global:accounts/cloudflare#token is used by:
Projects:
  blog: CF_TOKEN (/home/me/code/blog)
  shop: CLOUDFLARE_API_TOKEN (/home/me/code/shop)
    copied to cemi.ci.age (prod): out of date; run `cemi ci export -e prod` in that folder and commit it
Connectors that sign in with it:
  connector cloudflare-dns (destination of acme/shop/api#token)
Copied to:
  GitHub acme/shop: secret CLOUDFLARE_API_TOKEN (prod)
```

También muestra las plantillas armadas con el valor y los servidores MCP que arrancan con él.
Los proyectos que Cemí no ha anotado no se revisan; `cemi project ls` muestra los que conoce.
`cemi status` avisa cuando un `cemi.ci.age` tiene un valor viejo, y `cemi rotate` dice cuáles
hay que exportar de nuevo. Los asistentes de IA reciben la misma lista con la herramienta MCP
`show`, sin valores.

## Nunca subir un secreto

```bash
cemi hook install        # pre-commit: bloquea commits con cualquier valor de tus bóvedas
cemi scan --history      # busca tus valores en todo el historial de git
```

## Comandos

| Área | Comandos |
|---|---|
| Bóveda | `init [-g]`, `unlock`, `lock`, `status`, `prompt`, `recovery verify/reset/new`, `passwd`, `doctor`, `log` |
| Estructura | `ls`, `add`, `mv`, `rm`, `field add/rm/edit`, `find`, `show` |
| Valores | `set`, `generate`, `copy` (sin argumento: buscar y elegir), `reveal`, `history`, `revert` |
| Memoria | `note`, `task`, `deps` (todos los proyectos que usan un valor), `doc` |
| Ambientes | `env ls/add/rm/diff/protect/unprotect` |
| Rotación | `origin set/rm`, `dest add/ls/rm`, `verify`, `push`, `check`, `rotate`, `revoke`, `incident`, `approve` |
| Proyecto | `preset ls/add`, `link`, `var add/rm/ls`, `project ls/add/rm`, `run`, `types`, `ci setup/export/load`, `export`, `import` (`--discover` para todos tus proyectos) |
| IA | `token create/ls/revoke`, `mcp serve/setup/add/launch/ls/rm`, `api add/ls/rm/call`, `run --proxy` |
| Git | `scan`, `hook install` |

Las referencias tienen la forma `[global:|local:]entidad/registro#campo`.

Para scripts y CI, todos los comandos aceptan `--json`, y los códigos de salida no cambian entre
versiones: ver [docs/scripting.md](docs/scripting.md).

## Próximas versiones

- **v0.2**: rotación, con orígenes, destinos y aprobaciones.
- **v0.3** (en curso, casi lista): uso diario: encontrar los `.env` que ya tienes,
  autocompletado, presets, tipos para tu código, `--json`, secretos en CI, módulo para el
  prompt. Falta: la extensión de VS Code.
- **v0.4**: app de escritorio y proxy de credenciales (la IA llama a las API sin recibir la
  llave).
- **v0.5**: sincronizar entre tus máquinas y compartir una entidad con otra persona.

Plan completo: [docs/roadmap.es.md](docs/roadmap.es.md). Diseño: [docs/design.es.md](docs/design.es.md).

## Licencia

Apache-2.0. Cemí no trae garantía: cada quien responde por sus llaves y su código de recuperación.
