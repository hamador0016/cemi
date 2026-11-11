# Cemí

**Secretos con memoria que tu IA puede usar sin ver.**

[English](README.md)

Cemí guarda tus API keys, tokens y contraseñas cifrados en tu computadora, junto con para qué
sirve cada uno, dónde se usa y cómo reemplazarlo. Tus proyectos corren con ellos inyectados, y
los asistentes de IA (Claude, ChatGPT, Cursor… por MCP) pueden usarlos sin recibir nunca los
valores.

*El nombre viene del cemí taíno, una figura tallada que protegía lo que su dueño valoraba.*

> **Estado: v0.1, temprana.** El formato y los comandos todavía pueden cambiar. Lee
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

**Lo que ocultar la salida no cubre.** Un comando que recibe un secreto en su entorno todavía
puede enviarlo a otro lado o imprimirlo en una codificación que Cemí no reconoce. Cemí lo
reduce: la IA solo corre los comandos que tú listas, en los ambientes que tú listas. El proxy
de credenciales previsto para la v0.4 lo cierra para las API HTTP, porque el comando nunca
recibe la llave. Mientras tanto, no dejes que una IA corra comandos con secretos de
producción. Detalles en [docs/threat-model.md](docs/threat-model.md).

## Nunca subir un secreto

```bash
cemi hook install        # pre-commit: bloquea commits con cualquier valor de tus bóvedas
cemi scan --history      # busca tus valores en todo el historial de git
```

## Comandos

| Área | Comandos |
|---|---|
| Bóveda | `init [-g]`, `unlock`, `lock`, `status`, `recovery verify/reset/new`, `passwd`, `doctor`, `log` |
| Estructura | `ls`, `add`, `mv`, `rm`, `field add/rm/edit`, `find`, `show` |
| Valores | `set`, `generate`, `copy`, `reveal`, `history`, `revert` |
| Memoria | `note`, `task`, `deps`, `doc` |
| Ambientes | `env ls/add/rm/diff` |
| Proyecto | `link`, `var add/rm/ls`, `run`, `export`, `import` |
| IA | `token create/ls/revoke`, `mcp serve/setup/add/launch/ls/rm` |
| Git | `scan`, `hook install` |

Las referencias tienen la forma `[global:|local:]entidad/registro#campo`.

## Próximas versiones

- **v0.2**: rotación. Cemí sabe dónde nace cada llave y adónde se copia (secretos de GitHub,
  Supabase, archivos `.env`…), así `cemi rotate` crea una llave nueva, actualiza cada destino,
  verifica y revoca la vieja, con tu aprobación.
- **v0.3**: uso diario: encontrar los `.env` que ya tienes, autocompletado, tipos para tu código,
  secretos en CI.
- **v0.4**: app de escritorio y proxy de credenciales (la IA llama a las API sin recibir la
  llave).
- **v0.5**: sincronizar entre tus máquinas y compartir una entidad con otra persona.

Plan completo: [docs/roadmap.es.md](docs/roadmap.es.md). Diseño: [docs/design.es.md](docs/design.es.md).

## Licencia

Apache-2.0. Cemí no trae garantía: cada quien responde por sus llaves y su código de recuperación.
