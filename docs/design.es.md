# Cemí — secretos con memoria que tu IA puede usar sin ver

> **Documento de diseño.** La v0.1 ya está programada (ver "Estado de la implementación" abajo); las secciones de orígenes, destinos y rotación describen la v0.2.
> **Decidido (11 nov 2026):** nombre **Cemí** (comando `cemi`), código abierto en un GitHub personal, sin dominio ni venta, para cualquier desarrollador. Se usa como git: se instala en la PC o en un proyecto y todo se hace con comandos en inglés. Hay una bóveda global por máquina y, si se quiere, una local por proyecto. La IA puede rotar y propagar en producción solo con aprobación. Los primeros conectores son GitHub, Supabase, `.env` local y scripts propios. Sin firma de código.
> El caso real que motivó el proyecto está en `privado/` (excluido de git). Este documento usa la organización ficticia **Acme** en los ejemplos para poder publicarse tal cual.

*Cemí: espíritu protector taíno que se guardaba en objetos tallados. Como "git", el nombre no describe lo que hace.*

---

## Estado de la implementación (v0.1, 11 nov 2026)

**Hecho y probado** (25 pruebas unitarias + 11 de punta a punta con el ejecutable real, en Windows; la CI corre también Linux y macOS):

- Bóvedas global (`cemi init --global`) y local (`cemi init`), con la local abierta por la global. Contraseña con Argon2id (256 MiB) y **código de recuperación** de 52 caracteres (base32, 256 bits) en lugar de 24 palabras: no necesita una lista de palabras y da la misma seguridad.
- Formato: `vault.json` (encabezado) + un archivo age por objeto en `objects/`, nombres cifrados, llave por entidad, verificación de que el id interno coincide con el archivo.
- Sesión en el llavero del sistema por 15 min de inactividad (`unlock`/`lock`), probada con el Administrador de credenciales de Windows real.
- Entidades, registros, campos (`text`, `multiline`, `file`, `url`, `date`, `number`, `template`), ambientes heredados, valores por ambiente o compartidos, valor "externo" (no guardado aquí), historial con `revert`.
- Memoria (`note`), tareas recurrentes (`task`), `status`, `doc`, `deps`, `find`, `env diff`.
- `cemi.toml` con `[env]`, `[files]` y `[ai.commands]`; `var`, `link`, `run` (con `--redact`), `export`, `import` de `.env`.
- `copy` (portapapeles fuera del historial de Windows, se borra a los 30 s), `reveal` (pide la contraseña otra vez), `generate`.
- Auditoría cifrada y encadenada (`log --verify`).
- Tokens para IA guardados en el llavero (`token create/ls/revoke`) y servidor MCP (`mcp serve`) con `list`, `show`, `search`, `status`, `project`, `generate` y `run`; ninguna herramienta devuelve valores, y si la bóveda está cerrada pide `cemi unlock` en vez de preguntar la contraseña.
- `mcp add/launch`: otros servidores MCP arrancan con su token inyectado.
- `scan` (archivos, `--staged`, `--history`) y `hook install`.

**Cambios respecto al diseño:**

- Las variables del proyecto se manejan con `cemi var add/rm/ls` (no `cemi env add`, que es para ambientes).
- `cemi env clone` no hace falta: los campos son de la estructura, así que `cemi env add staging` ya crea el ambiente vacío.
- `self update` queda para cuando existan los instaladores; mientras tanto se actualiza con el mismo gestor con que se instaló.
- `ask_value` (ventana para que el humano pegue un valor) queda para la app (v0.4); hoy el humano usa `cemi set` en su terminal.

**Pendiente para publicar:** cuenta de crates.io para reservar `cemi`, y `cargo-dist` para los instaladores (npm, Homebrew, scripts). Ambos requieren instalar herramientas o crear cuentas, así que se deciden aparte.

---

## Resumen

1. **Lo que ya existe guarda bien los valores, pero olvida el contexto.** Doppler, Infisical, Vault, 1Password, Bitwarden, SOPS o dotenvx resuelven "dónde pongo la llave y cómo llega al programa". Ninguno trata como parte central *para qué sirve, dónde está copiada, cómo se regenera y qué pasa si se pierde*. Casi todos los equipos terminan anotándolo a mano en un documento aparte.
2. **El hueco más grande es rotar y propagar.** Cuando una llave se filtra hay que crear otra en el proveedor, copiarla a cada lugar donde se usa, redesplegar, verificar y revocar la vieja. Cemí sabe de dónde nace cada llave y adónde va, así que lo hace con un comando, o lo hace una IA **sin que el valor pase por el chat** y con tu aprobación.
3. **La IA usa, no ve.** Hay varias herramientas nuevas (2025–2026) con esa idea, pero ninguna la junta con una estructura que define el usuario, con memoria ni con rotación de punta a punta. Tampoco con Windows bien soportado.
4. **Límite:** si una IA ejecuta código arbitrario con la llave en su entorno, puede filtrarla. La protección real es que el valor nunca entre en un proceso que la IA controla, más tu aprobación por un canal que la IA no puede tocar.
5. **Cómo:** Rust, un solo ejecutable, local primero, formato abierto **age** (si Cemí desaparece, tus datos se abren con `age` estándar). Se instala con un comando, como git.

---

## 1. El problema

Un desarrollador con unos pocos proyectos ya maneja decenas de llaves. Por ejemplo, la tienda de Acme:

- Están **repartidas**: secretos de GitHub Actions, `.env` del servidor, archivos locales (`.pem`, llaves SSH), secretos de funciones en Supabase, variables de Netlify o Vercel, y una copia en un gestor de contraseñas.
- **Algunas no se guardan en ningún lado** a propósito ("se creó directo en GitHub; si se pierde, se regenera"). Igual hay que saber que existen.
- **Hay variables no secretas** mezcladas con las secretas (host, orígenes permitidos, llaves públicas).
- **La información importante no es el valor**: para qué sirve, dónde se usa, cómo se regenera, qué se rompe si se pierde, cuándo vence, si tiene copia de respaldo.
- **Hay llaves que no se pueden rotar a la ligera**: una llave que cifra datos (rotarla exige migrarlos) o una llave privada que abre respaldos viejos (al cambiarla, la vieja se conserva).
- **Hay valores compuestos** (`DATABASE_URL` contiene la contraseña de la base) y **pares que cambian juntos** (id + secreto de un token).
- **Y ahora hay IAs** que necesitan esas llaves para correr pruebas, desplegar o arreglar una filtración, y la manera habitual de dárselas (pegarlas en el chat o dejarlas en un `.env` que la IA lee) las expone.

---

## 2. Estado del arte

### 2.1 Tabla comparativa

| Herramienta | Qué es | Licencia | Qué hace bien | Dónde falla para un dev solo / equipo chico |
|---|---|---|---|---|
| **Doppler** | Servicio en la nube | Cerrado | Proyectos × ambientes claros; `doppler run`; sincroniza con muchos destinos | Tus secretos en su nube; plan gratis limitado (según comparativas: 3 usuarios, ~10 proyectos, 4 ambientes; confirmar); sin memoria |
| **Infisical** | Plataforma, nube o auto-alojada | Núcleo MIT; carpeta `ee/` comercial | Abierto, ambientes, **rotación automática** de algunos proveedores (incluye Supabase), MCP oficial, **Agent Vault** (proxy, vista previa) | Auto-alojarlo es servidor + Postgres + Redis; funciones detrás de licencia; su MCP **sí devuelve valores** |
| **HashiCorp Vault** | Servidor empresarial | BSL 1.1 desde 2023 | Secretos dinámicos, políticas, auditoría | Sobredimensionado; no es código abierto |
| **OpenBao** | Fork de Vault | MPL-2.0 | Igual que Vault, abierto | Igual de pesado |
| **1Password CLI** | Gestor + CLI | Cerrado | Referencias `op://…`; `op run` **enmascara** la salida; MCP de Environments que **nunca devuelve valores** | De pago; el MCP y los montajes **solo en Mac y Linux**; plantillas fijas |
| **Bitwarden Secrets Manager** | Secretos para máquinas | Cliente abierto; servidor con licencia propia | Plan gratis; `bws run`; cifrado de extremo a extremo | Modelo plano; sin ambientes de primera clase; sin MCP oficial para este producto |
| **SOPS + age** | Cifra valores en archivos del repo | MPL-2.0 / BSD-3, MIT-Apache | Sin servidor; age moderno y auditado | Solo formato: sin ambientes, memoria, auditoría ni rotación |
| **dotenvx** | `.env` cifrado | BSD-3 | Cero fricción | Rotación, revocación y auditoría son de pago |
| **git-crypt** | Cifrado transparente en git | GPL-3 | Simple | Licencia copyleft; revocar acceso es casi imposible |
| **direnv / mise** | Cargan variables por carpeta | MIT | Cómodos | No cifran por sí solos |
| **fnox** | CLI con proveedores (age, 1Password, nubes) | MIT | Mezcla valores cifrados y referencias; **modo proxy** | Clave/valor; sin memoria ni destinos |
| **AWS / GCP Secrets Manager** | Nube | Cerrados | Rotación con funciones, IAM, auditoría | Costo por secreto (AWS ~US$0.40/mes; GCP US$0.06 por versión activa, 6 gratis); te ata al proveedor |

### 2.2 Herramientas pensadas para agentes de IA

| Herramienta | Idea central | Lección |
|---|---|---|
| **secretctl** (Go, Apache-2.0) | Local, SQLite cifrado, CLI + app, MCP que ejecuta y redacta, lista blanca de comandos | La más parecida. Plantillas fijas, sin ambientes ni rotación, y su ejemplo **guarda la contraseña maestra en texto plano en `~/.claude.json`** |
| **llm-secret-manager** (macOS) | MCP **sin verbo "leer"** | "Escribir y usar, nunca leer" |
| **varlock** (MIT) | Esquema con `@sensitive`; redacción; **proxy** con valores falsos | El valor falso + proxy es elegante |
| **Infisical Agent Vault** | Proxy HTTP que inyecta la credencial según el dominio | El patrón más seguro hoy |
| **1Password Environments MCP** | El MCP solo ve nombres; el programa recibe el valor por un `.env` en memoria | Separar lo que ve la IA de lo que recibe el programa |
| **secretspec** (Apache-2.0) | Declarar qué necesita un proyecto, aparte de dónde está | El archivo del repo declara necesidades, no valores |

### 2.3 Conclusiones

- Cifrar y entregar al proceso está resuelto: no hay que inventar criptografía.
- Nadie trata la memoria operativa como dato principal, ni deja que el usuario defina la estructura, ni documenta secretos que no guarda.
- La rotación de punta a punta solo existe en productos de nube, con tus secretos en *su* servidor. Localmente y con IA no existe.
- Windows está desatendido en las herramientas para IA.

---

## 3. Cómo darle secretos a una IA sin filtrarlos

### 3.1 Patrones, de menos a más seguro

| # | Patrón | Cómo funciona | Qué protege | Qué NO protege |
|---|---|---|---|---|
| 0 | **Pegar la llave en el chat** | — | Nada | Queda en el historial del proveedor de IA |
| 1 | **Referencias** | Se maneja `cemi://acme/tienda/stripe#secret`, nunca el valor | Archivos, commits, chat | Nada en tiempo de ejecución |
| 2 | **Inyección en variables de entorno** | El valor solo existe en el proceso hijo | Disco y chat | El proceso hijo puede imprimirlo |
| 3 | **Redacción de salidas** | Se reemplaza el valor por `[OCULTO:nombre]` | Fugas accidentales | Cualquier transformación (base64, hex…) |
| 4 | **Ejecutor con lista blanca** | La IA elige de comandos aprobados, sin shell | Comandos inventados | Que la IA edite el script que luego corre → aviso de archivos cambiados |
| 5 | **Tokens acotados** | La IA entra con un token: entidades, ambientes, acciones, vencimiento. Revocable | Alcance y tiempo | Mal uso dentro del alcance |
| 6 | **Aprobación humana** | Diálogo nativo fuera del chat con el plan exacto | Inyección de instrucciones contra producción | Fatiga; IA con control del escritorio → PIN, Windows Hello o Touch ID |
| 7 | **Proxy de credenciales** | La IA llama a `127.0.0.1/stripe/...`; el proxy pone la autorización y reenvía solo al dominio permitido | **El valor nunca entra en un proceso de la IA** | Daño *con* el permiso → reglas por método y ruta |
| 8 | **"Escribir sin leer"** | La IA pide: rota, guarda y empuja; o "pide el valor al humano" en una ventana propia | El valor va del proveedor al destino sin pasar por el chat | Depende de conectores confiables |
| 9 | **Auditoría** | Cada uso registrado sin valores, encadenado con hash | Saber qué pasó | Detecta, no previene |

### 3.2 Límites (van en la documentación pública)

1. Una IA que ejecuta código arbitrario con la llave en su entorno puede filtrarla. Los patrones 2–3 solo valen para desarrollo o con lista blanca y aprobación.
2. **"Tríada letal"** (Simon Willison, 2025): datos privados + contenido no confiable + comunicación hacia afuera = fuga posible. Para producción hay que quitar un lado: que la IA no tenga el valor (proxy, conectores) o que no pueda actuar sin un humano.
3. El token de la IA también es un secreto: solo da lo que da, y lo peligroso exige además aprobación.
4. Una IA con control del escritorio hace clic como el humano: producción con PIN o biometría.
5. **Agregar un destino es enviar un secreto a algún lado.** Crear o cambiar destinos siempre exige aprobación, y solo se aceptan tipos conocidos.
6. Si una llave se expuso, la única cura es rotarla.

---

## 4. Diseño

### 4.1 Principios

1. **Formato abierto y aburrido.** Cada registro es un archivo cifrado con age.
2. **Local primero y con dos alcances, como git.** Sin internet ni cuenta. Igual que `git config --global` y `git config` local, hay dos bóvedas:
   - **Global** (`~/.cemi/`, se crea con `cemi init --global`): llaves que comparten varios proyectos (cuentas de Cloudflare, GitHub, Supabase) y su memoria.
   - **Local del proyecto** (`<proyecto>/.cemi/`, se crea con `cemi init` dentro del repo): llaves que solo usa ese proyecto. `cemi init` la agrega solo al `.gitignore`, y `cemi scan` avisa si alguna vez se va a subir.
   - Al buscar una referencia, Cemí mira primero la local y después la global. Un proyecto también puede no tener bóveda local y solo apuntar a una entidad de la global (`cemi link acme/tienda`).
   - En el repo solo va `cemi.toml`, con referencias y sin secretos.
3. **Nada fijo.** El usuario define la estructura; Cemí solo distingue si un campo es secreto o no.
4. **La IA usa, no ve.** Ninguna herramienta del MCP devuelve un valor secreto.
5. **El secreto sin su memoria está incompleto.**
6. **Fácil como git:** un ejecutable, un comando para instalar, comandos cortos y predecibles.
7. **Solo dependencias MIT/Apache/BSD.** Cemí se publica con Apache-2.0.

### 4.2 Modelo de datos

```
Bóveda (global ~/.cemi/ o local <proyecto>/.cemi/; mismo formato)
└── Entidad  "acme"                          (árbol de profundidad libre)
    ├── Ambientes: dev, prod                 (se heredan hacia abajo)
    ├── Registro "cuentas/supabase"          (las credenciales de los conectores también son registros)
    └── Entidad  "tienda"
        ├── Ambientes: + "staging" (solo aquí)
        └── Registro "stripe"
            ├── Campo "publishable"   texto     · no secreto
            ├── Campo "secret"        secreto   · valor por ambiente
            ├── Origen   (por ambiente)   de dónde nace y cómo se regenera       → §4.4
            ├── Destinos (por ambiente)   adónde se copia y qué hacer después    → §4.4
            ├── Memoria (campos con rol, todos opcionales)
            │   para qué sirve · si se pierde · si se filtra · vence · respaldo · enlaces
            │   rotación delicada: no / "requiere migración" / "conservar versiones"
            └── Historial (cifrado; estados: pendiente, activa, retirada, archivada)
```

- **Entidad**: carpeta lógica con nombre libre, anidable sin límite.
- **Registro**: un "archivo" dentro de la entidad.
- **Campo**: nombre libre + un tipo que solo dice cómo tratarlo: `text`, `secret`, `multiline`, `file`, `url`, `date`, `number`, `template`.
- **Valor por ambiente**: único o uno por ambiente; un registro puede existir solo en `prod`.
- **Valor compuesto** (`template`): `postgres://app:{{db#password}}@{{db#host}}:5432/postgres`. Si se rota la contraseña, la URL se recalcula y se propaga.
- **Grupo de rotación**: campos que cambian juntos (id + secreto).
- **Valor ausente a propósito**: "no guardado aquí, vive en GitHub `production`".
- **Referencia**: un campo puede apuntar a otro registro (`cemi://acme/cuentas/cloudflare#token`); un secreto compartido existe una sola vez.
- **Plantillas del usuario**: cada quien guarda las suyas; Cemí no trae ninguna.
- **Historial con estados**: `pending`, `active`, `retired` (revocada en el proveedor), `archived` (ya no se usa, pero **se conserva**, p. ej. la llave privada que abre respaldos viejos).
- **Tareas recurrentes** por entidad ("cada mes: prueba de restauración").

### 4.3 Archivo de proyecto (va al repo, no tiene secretos)

```toml
# cemi.toml
entity = "acme/tienda"

[env]
DATABASE_URL      = { ref = "db#url" }
STRIPE_SECRET_KEY = { ref = "stripe#secret" }

[files]  # se escribe a un temporal con permisos solo del usuario y se borra al terminar
GOOGLE_APPLICATION_CREDENTIALS = { ref = "gcp#service-account" }

[ai.commands]  # lista blanca para la IA
test = { cmd = ["npm", "test"],      envs = ["dev"] }
dev  = { cmd = ["npm", "run", "dev"], envs = ["dev"] }
```

### 4.4 Orígenes, destinos y conectores

- **Origen**: dónde nace la llave y con qué cuenta. Permite **generar**, **revocar**, **consultar** (existe, vence) y **descubrir** llaves existentes.
- **Destinos**: cada lugar donde se copia, por ambiente, con la acción posterior (redesplegar, reiniciar). Cada destino guarda la **huella** (hash) del último valor enviado, para detectar cambios.
- **Conectores**, en tres clases para no fijar nada:
  1. **Incluidos**: los más usados.
  2. **De comando**: cualquier script del usuario que imprima la llave nueva. Cemí la lee sin mostrarla.
  3. **Externos**: programas `cemi-connector-<nombre>` que hablan JSON por stdin/stdout, igual que los *credential helpers* de git y los plugins de age. Cualquiera agrega un proveedor sin tocar el núcleo. Los valores viajan solo por stdin, nunca como argumentos.
- **Recetas manuales**: si no hay API, el origen es una lista de pasos. Cemí la muestra, abre la ventana para pegar el valor nuevo y sigue sola con los destinos.

**Qué permiten los proveedores más comunes** (según su documentación; confirmar cada endpoint al programar el conector):

| Proveedor | Generar / rotar | Escribir como destino | Detectar cambios sin leer el valor |
|---|---|---|---|
| **GitHub** | — | Secretos de Actions y de entornos por API, cifrados con la llave pública del repo (sellado libsodium) | Parcial: fecha de última actualización |
| **Supabase** | Crear llaves secretas `sb_secret_…` por API (`POST /v1/projects/{ref}/api-keys`). Las `anon`/`service_role` antiguas se retiran a fines de 2026. Contraseñas de roles por SQL | Secretos de funciones | **Sí**: la API devuelve la huella SHA-256 de cada secreto, nunca el valor |
| **Cloudflare** | Renovar tokens (`PUT /user/tokens/{id}/value`); crear y borrar otros tokens | Variables de Pages/Workers | Estado y vencimiento del token |
| **Resend** | Crear llaves (`POST /api-keys`, limitables a un dominio) | — | — |
| **Netlify / Vercel** | — | Variables del sitio por API | Fecha de actualización |
| **Servidor propio** | — | `.env` por SSH + reiniciar servicio | Hash calculado en el servidor |
| **Archivo `.env` local** | — | Sí | Hash |

### 4.5 Rotar una llave (normal o por filtración)

`cemi rotate acme/tienda/stripe -e prod`, o la IA vía MCP:

```
1. PLAN       origen, destinos, valores compuestos que cambian, acciones, verificación.
              Si la llave es "rotación delicada", se detiene y muestra la receta.
2. APROBAR    en prod: PIN o biometría, en una ventana propia (no en el chat).
3. GENERAR    llave nueva en el origen → "pending". La vieja sigue viva.
4. GUARDAR    en la bóveda.
5. PROPAGAR   a cada destino; recalcula y empuja los valores compuestos.
6. APLICAR    redespliegue / reinicio.
7. VERIFICAR  comando de salud o llamada de prueba.
8. CONFIRMAR  la nueva pasa a "active".
9. REVOCAR    la vieja: de inmediato si se filtró, o tras un periodo de gracia.
10. ANOTAR    auditoría + historial.
Si falla entre 5 y 7: devuelve la vieja a los destinos ya tocados y deja la nueva en "pending".
```

- **`cemi incident`**: marca las llaves expuestas y calcula el **radio de daño** (qué compuestos y destinos las contienen). Ofrece **cortar primero** (revocar ya, con una caída corta) o **rotar sin caída**. También muestra en la auditoría quién las usó.
- **Llaves delicadas**: nunca se rotan solas; se muestra la receta y la versión vieja se archiva, no se borra.

### 4.6 Detectar cambios

`cemi check` (a mano, por la IA, o con una tarea programada) compara la bóveda con el mundo:

| Situación | Cómo se detecta | Qué propone |
|---|---|---|
| Cambiaste un valor en la bóveda | Huella nueva ≠ huella del último envío | "3 destinos desactualizados: ¿`cemi push`?" |
| Alguien cambió un destino por fuera | Fecha posterior al último envío, o huella distinta | Importarlo (si se puede leer) o rotar para volver a un valor conocido |
| El proveedor cambió la llave solo | Huella o consulta del origen | Actualizar bóveda y destinos |
| La llave fue revocada en el proveedor | Consulta del origen | Marcarla `retired` y avisar qué se rompe |
| Vence pronto | Origen + memoria | Recordatorio o rotar |
| Memoria incompleta, sin respaldo, tarea atrasada | Bóveda | Aparece en `cemi status` |

### 4.7 Ambientes

- Se definen en una entidad y se heredan; una sub-entidad puede agregar los suyos.
- **Cada ambiente tiene su propio origen y sus destinos** (dev → proyecto de pruebas y `.env` local; prod → proyecto real y GitHub `production`).
- `cemi env diff dev prod`: qué falta en uno y qué valores se repiten (alarma: la misma llave en dev y prod).
- `cemi env clone prod staging`: copia la estructura, los destinos y la memoria **sin valores**.
- Los tokens de la IA se limitan por ambiente: dev libre, prod con aprobación.

### 4.8 Cifrado

**No se inventa criptografía**: solo se componen piezas estándar y auditadas.

```
Contraseña maestra ──Argon2id──► llave de la contraseña ──┐
                                                           ├─► identidad de la bóveda (X25519, formato age)
Kit de recuperación (24 palabras) ────────────────────────┘
                                                                │
                      identidad age por entidad (permite compartir solo una entidad en el futuro)
                                                                │
                      cada registro = un archivo age cifrado para la identidad de su entidad
```

- Formato age v1 (X25519 + ChaCha20-Poly1305), crate `age`.
- Argon2id con parámetros altos (~256 MiB, ~1 s), guardados en el archivo.
- Cambiar la contraseña no re-cifra todo; el kit de recuperación abre la misma llave intermedia.
- En disco solo hay IDs al azar: los nombres también van cifrados.
- `secrecy`/`zeroize`, memoria bloqueada, sin volcados de memoria del servicio.
- Portapapeles: en Windows se excluye del historial y de la nube (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory`); en todas las plataformas se borra a los 30 s.
- Desbloqueo cómodo: llave de sesión en el llavero del sistema (Windows Credential Manager, Keychain de macOS, Secret Service en Linux, vía `keyring`) con Windows Hello o Touch ID; bloqueo por inactividad. Producción siempre pide confirmación aparte.

### 4.9 Componentes

Todo vive en **un solo ejecutable** `cemi`:

| Pieza | Qué hace | Cuándo |
|---|---|---|
| CLI | Todos los comandos (§5) | v0.1 |
| Servicio en segundo plano | Arranca solo con el primer comando que lo necesite (como `ssh-agent`). Tiene la bóveda abierta y atiende a la CLI, al MCP y a la app por un canal local que solo el usuario puede abrir (*named pipe* en Windows, socket Unix en Mac/Linux) | v0.1 |
| Servidor MCP | `cemi mcp serve` para Claude Code, Claude Desktop, ChatGPT, Cursor… | v0.1 |
| Lanzador de MCP | `cemi mcp launch <nombre>` arranca **otros** servidores MCP con su token inyectado, para que no quede en texto plano en la configuración del cliente | v0.1 |
| Conectores | §4.4 | v0.2 |
| App visual (Tauri) | Árbol, editor, aprobaciones, avisos, auditoría | v0.4 |
| Proxy de credenciales | APIs HTTP sin que el valor llegue a la IA | v0.4 |
| Sincronizar entre máquinas propias / compartir una entidad | Carpeta cifrada en git privado, nube o S3/R2; destinatarios age | v0.4 |

### 4.10 Integración con IAs

**Tokens para IAs.** `cemi token create claude-tienda --entity acme/tienda --envs dev,prod --allow show,run,rotate --expires 7d`. En la bóveda solo se guarda su hash. `cemi token revoke claude-tienda` lo corta al instante.

**Configurarlo en un cliente:** `cemi mcp setup claude-code` (o `claude-desktop`, `cursor`) agrega la entrada al archivo de configuración del cliente. El token va al llavero del sistema y la configuración solo guarda una referencia, nunca el token en texto plano.

**Herramientas del MCP** (ninguna devuelve valores secretos):

| Herramienta | Qué hace | Control |
|---|---|---|
| `list`, `search`, `show` | Estructura y memoria ("¿cómo roto el token de R2?") | Libre |
| `status`, `check` | Vencimientos, sin respaldo, destinos desactualizados o cambiados por fuera | Libre |
| `env_diff` | Diferencias entre ambientes | Libre |
| `ask_value` | Abre una ventana para que **el humano** pegue un valor; la IA solo recibe "guardado" | Libre |
| `generate` | Valor aleatorio guardado sin mostrarse | Libre |
| `run` | Comando de la lista blanca con variables inyectadas; salida redactada | dev libre; prod hasta que exista el proxy (v0.4), con aprobación |
| `push` | Empuja el valor actual a destinos desactualizados | dev libre; prod con aprobación |
| `rotate` | Flujo completo de §4.5; la IA recibe el plan y el resultado, nunca el valor | prod **siempre** con aprobación |
| `propose_destination`, `propose_origin` | La IA *redacta* configuración no secreta | **Siempre** con aprobación |
| `call_api` (v0.4) | Vía proxy, a un dominio permitido | Reglas por método/ruta |

Resumen: **la IA configura y pide, Cemí ejecuta y tú apruebas.** Ejemplo: "se filtró la llave de Supabase de la tienda" → la IA llama a `rotate` → aparece el plan (Supabase crea una llave nueva; destinos: Netlify prod y `.env` local; verificación: `npm test`) → apruebas con Windows Hello → Cemí lo hace todo → la IA recibe "rotada, 2 destinos actualizados, la vieja revocada".

Opcional para Claude Code: `cemi mcp setup claude-code --guard` instala un *hook* `PreToolUse` que bloquea `printenv`, `cat ~/.cemi/**` o `cemi reveal` cuando los ejecuta la IA (respaldo, no garantía).

### 4.11 Catálogo de casos de uso

| Caso | Cómo se cubre |
|---|---|
| Guardar una llave sin que pase por el chat | `cemi set` (entrada oculta o portapapeles), `ask_value` |
| Generar una contraseña o llave | `cemi generate` |
| Proveedor → bóveda → destinos sin copiar y pegar | Origen + destinos + `cemi rotate` |
| Llave filtrada | `cemi incident` |
| Rotación periódica | Recordatorio en la memoria + `cemi rotate` |
| Rotación que exige migrar datos | Marca "requiere migración": solo receta manual |
| Conservar llaves viejas que abren datos viejos | Estado `archived` |
| Volver atrás si la nueva falla | Reversión automática antes de revocar; `cemi history` |
| Valor armado con otros | Campo `template` |
| Id + secreto que cambian juntos | Grupo de rotación |
| Un secreto usado por varios proyectos | Referencia |
| Secreto que vive solo en el destino | "Valor ausente a propósito" |
| Variables no secretas | Campos `text` |
| Archivos (`.pem`, llaves SSH, JSON de cuentas de servicio) | Campo `file`; `run` los escribe a un temporal |
| Llave pública + privada | Dos campos; la pública no es secreta |
| Ambientes con cuentas o proyectos distintos | Origen y destinos por ambiente |
| Comparar o crear ambientes | `cemi env diff`, `cemi env clone` |
| Alguien cambió una llave por fuera / el proveedor la cambió | `cemi check` |
| Tokens con vencimiento, dominios, tokens temporales | Memoria `expires` + consulta del origen |
| Tareas periódicas | Tareas recurrentes por entidad |
| Qué se rompe si borro o roto algo | `cemi deps` (grafo de compuestos, destinos y acciones) |
| Empezar con lo que ya hay | `cemi import` desde `.env`, desde una tabla de inventario, o descubriendo en proveedores |
| Inventario sin valores para el repo | `cemi doc` |
| `.env.example` | `cemi export --example` |
| Correr un proyecto con sus llaves | `cemi run -e dev -- …` |
| Tokens de otros MCP sin texto plano | `cemi mcp launch` |
| Que una IA use, rote y propague sin ver | MCP + tokens + aprobación |
| Que no se cuele un secreto en un commit | `cemi scan` (§6) |
| Cambiar de PC | Copiar la carpeta cifrada + contraseña o kit |
| Perder la contraseña maestra | Kit de recuperación; `cemi recovery verify` |
| Compartir una entidad con otra persona (más adelante) | Identidad age por entidad + destinatarios |

---

## 5. Instalación y comandos

### 5.1 Instalar (como git: un comando y listo)

Cemí es una herramienta de terminal: no tiene instalador con ventanas ni nada que hacer clic. Se instala con un comando y después todo se hace con `cemi …`, igual que `git …`. Por dentro, en Windows es un `cemi.exe`, igual que git es `git.exe`, pero el usuario nunca lo descarga a mano. Lo baja su gestor de paquetes o el script de instalación desde la terminal. Por eso **no hace falta firmarlo**: el aviso de SmartScreen solo sale con archivos bajados desde el navegador, y esa vía no se documenta.

GitHub Actions compila cada versión con **cargo-dist** (MIT/Apache), que genera los binarios para Windows, macOS y Linux, el paquete de npm, la fórmula de Homebrew y los scripts de instalación.

**En la PC (global), elegir uno:**

```bash
cargo install cemi --locked
```

```bash
npm install -g cemi
```

```bash
brew install TU_USUARIO/tap/cemi
```

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/TU_USUARIO/cemi/releases/latest/download/cemi-installer.sh | sh
```

```bash
powershell -c "irm https://github.com/TU_USUARIO/cemi/releases/latest/download/cemi-installer.ps1 | iex"
```

**Solo en un proyecto** (la versión queda fijada en el repo, y quien clone el proyecto recibe la misma):

```bash
npm install --save-dev cemi        # proyectos JavaScript; se usa con: npx cemi …
```

```bash
mise use cemi@0.1                  # cualquier proyecto que use mise; queda en mise.toml
```

- **Verificación**: cada versión publica sumas SHA-256 y **atestaciones de origen de GitHub** (gratis en repos públicos), que se comprueban con `gh attestation verify`.
- **Actualizar**: con el mismo gestor (`cargo install`, `npm update`, `brew upgrade`) o `cemi self update` si se instaló con el script. **Desinstalar** no toca las bóvedas.
- `cemi.toml` puede declarar `cemi_version = ">=0.2"`, y Cemí avisa si la versión instalada es más vieja.

### 5.2 Primeros pasos

```bash
# Una sola vez en la PC: bóveda global para llaves compartidas
cemi init --global                 # pide la contraseña y muestra el kit de recuperación una vez

# En un proyecto, como git init
cd mi-proyecto
cemi init                          # crea .cemi/ local, la agrega al .gitignore y crea cemi.toml
cemi add stripe                    # registro en la bóveda local
cemi field add stripe secret --secret
cemi set stripe#secret -e dev      # entrada oculta; nunca como argumento
cemi env add DATABASE_URL --ref global:acme/tienda/db#url   # o apuntar a la global
cemi run -e dev -- npm run dev     # corre con las llaves inyectadas
cemi status                        # qué falta, qué vence, qué está desactualizado
cemi mcp setup claude-code         # conecta Claude Code a Cemí
```

### 5.3 Referencia de comandos

Los comandos van en inglés, como git, para que cualquier desarrollador los adivine. La documentación va en inglés y en español.

| Grupo | Comando | Qué hace |
|---|---|---|
| **Bóveda** | `cemi init [--global]` | Crea la bóveda local del proyecto (la agrega al `.gitignore` y crea `cemi.toml`) o la global de la PC, con su kit de recuperación |
| | `cemi unlock` / `cemi lock` | Abre o cierra la sesión del servicio |
| | `cemi status` | Lo pendiente: vencimientos, destinos desactualizados, sin respaldo, memoria incompleta, tareas atrasadas (como `git status`) |
| | `cemi recovery verify` | Comprueba que el kit de recuperación abre la bóveda |
| | `cemi passwd` | Cambia la contraseña maestra |
| | `cemi doctor` | Revisa instalación, permisos y servicio |
| **Estructura** | `cemi ls [ruta]` | Lista entidades y registros (sin valores) |
| | `cemi add <ruta>` | Crea un registro (y sus entidades) |
| | `cemi mv`, `cemi rm` | Renombra o borra (borrar archiva; no destruye el historial) |
| | `cemi field add/rm/edit <ref> <campo> [--secret] [--type file]` | Define campos |
| | `cemi template save/use` | Plantillas propias |
| | `cemi find <texto>` | Busca en nombres y memoria |
| **Valores** | `cemi set <ref#campo> [-e amb]` | Pone un valor (entrada oculta, `--from-clipboard`, `--from-file`) |
| | `cemi generate <ref#campo> [--length 48]` | Genera y guarda sin mostrar |
| | `cemi copy <ref#campo>` | Al portapapeles por 30 s |
| | `cemi reveal <ref#campo>` | Lo muestra en pantalla (pide confirmación; bloqueado para la IA) |
| | `cemi show <ref>` | La ficha: campos (valores ocultos), memoria, origen, destinos |
| | `cemi history <ref>` / `cemi revert <ref> <versión>` | Versiones y vuelta atrás |
| **Memoria** | `cemi note <ref> --purpose … --if-lost … --expires 2027-11-09` | Edita la memoria |
| | `cemi task add <entidad> "prueba de restauración" --every month` | Tareas recurrentes |
| | `cemi deps <ref>` | Qué depende de esta llave |
| | `cemi doc [entidad]` | Inventario en Markdown sin valores |
| **Ambientes** | `cemi env ls/add/rm` | Administra ambientes |
| | `cemi env diff dev prod` | Compara |
| | `cemi env clone prod staging` | Copia la estructura sin valores |
| **Proyecto** | `cemi link <entidad>` | Conecta el proyecto a una entidad de la bóveda global (sin bóveda local) |
| | `cemi env add <VARIABLE> --ref <ref>` | Agrega una variable a `cemi.toml` |
| | `cemi run -e <amb> -- <comando>` | Corre con las variables y archivos inyectados |
| | `cemi export --example` | Genera `.env.example` |
| | `cemi import <.env \| inventario.md>` | Importa lo existente |
| **Destinos y rotación** | `cemi origin set <ref> -e <amb> <conector> …` | Define de dónde nace |
| | `cemi dest add <ref> -e <amb> <conector> …` | Agrega un destino |
| | `cemi push [ref] [-e amb]` | Envía los valores actuales a los destinos desactualizados |
| | `cemi check` | Detecta cambios por fuera, revocaciones y vencimientos |
| | `cemi rotate <ref> -e <amb>` | Rotación completa con plan y aprobación |
| | `cemi incident <ref…>` | Modo filtración |
| | `cemi connector ls/add` | Conectores instalados (incluidos y `cemi-connector-*`) |
| **IA** | `cemi mcp serve` | Servidor MCP |
| | `cemi mcp setup <cliente> [--guard]` | Configura Claude Code, Claude Desktop, Cursor… |
| | `cemi mcp launch <nombre>` / `cemi mcp add <nombre> -- <comando>` | Lanza otros MCP con su token inyectado |
| | `cemi token create/ls/revoke` | Tokens para IAs |
| | `cemi approve` | Aprobaciones pendientes (si no hay ventana disponible) |
| **Seguridad** | `cemi log [--ref …]` | Auditoría |
| | `cemi scan [ruta] [--staged] [--history]` | Busca en archivos o en git **los valores exactos de tu bóveda** (§6) |
| | `cemi hook install` | Instala `cemi scan --staged` como pre-commit en el repo |
| **Instalación** | `cemi self update` / `cemi self uninstall` | Actualiza o desinstala (si se instaló con el script) |
| | `cemi --version`, `cemi help <comando>` | Versión y ayuda |

---

## 6. Publicar sin filtrar secretos

**Regla: el repositorio de Cemí nunca contiene datos reales.**

1. **Ejemplos ficticios**: la organización `acme` y valores como `cemi_test_no_es_real_…`. Las pruebas generan sus llaves al correr; no hay llaves reales en fixtures.
2. **Lo privado no se sube**: las notas con infraestructura real viven en `privado/`, que está en `.gitignore` junto a `.cemi/`, `.env*` (salvo `.env.example`), `*.pem`, `*.key` y `*.age`. Lo mismo vale para los usuarios: `cemi init` agrega `.cemi/` al `.gitignore` de cada proyecto, y `cemi scan --staged` bloquea el commit si la bóveda local o un valor conocido se va a subir.
3. **Escaneo en dos capas antes de cada commit**:
   - **gitleaks** (MIT): detecta formatos conocidos (tokens de GitHub, Stripe, Supabase, llaves privadas…).
   - **`cemi scan --staged`**: busca **los valores exactos de tu propia bóveda** en lo que vas a subir. Detecta cualquier secreto tuyo aunque no tenga un formato reconocible. Es el uso de Cemí para proteger el propio repo de Cemí.
4. **En GitHub**: gitleaks en CI en cada PR, y *secret scanning* con *push protection* activados (gratis en repos públicos).
5. **Primera publicación**: crear el repo privado, correr `gitleaks detect` y `cemi scan --history` sobre todo el historial, y recién entonces hacerlo público. Si algo se coló, se rota la llave (borrarla del historial no basta).
6. **Archivos públicos del repo**: `README` (inglés y español), `LICENSE` (Apache-2.0), `SECURITY.md` (cómo reportar vulnerabilidades en privado), `docs/threat-model.md` con los límites de §3.2, y `CONTRIBUTING.md` con la regla de cero datos reales.

---

## 7. Plan de versiones

| Versión | Contenido | Listo cuando |
|---|---|---|
| **v0.1** | Bóveda, estructura, ambientes, memoria, `status`, `run`, `cemi.toml`, `doc`, `import`/`export`, MCP de solo memoria + `ask_value` + `generate` + `run` en dev, `mcp launch`, tokens, auditoría, `scan`, instaladores | El autor deja de copiar llaves a mano para desarrollar y ninguna IA vuelve a ver un valor |
| **v0.2** | Orígenes, destinos, huellas. Conectores **GitHub, Supabase, `.env` local y de comando** (más externos `cemi-connector-*`). `push`, `check`, `rotate`, `incident`; aprobación con la contraseña de la bóveda escrita por una persona; MCP `check`, `push`, `rotate` | Una llave filtrada se rota y se actualiza en todos sus destinos con un comando |
| **v0.3** | Uso diario: `import --discover`, autocompletado, buscador, `cemi types`, presets, `--json`, secretos en CI, extensión de VS Code | Quien instala Cemí pasa sus `.env` el primer día y sigue usándola |
| **v0.4** | App de escritorio con Windows Hello / Touch ID, proxy de credenciales, `run` en prod, conectores Cloudflare, SSH, Resend, Netlify, Vercel | Probar APIs de producción sin que la IA tenga el valor |
| **v0.5** | Sincronizar entre máquinas propias; compartir una entidad | Un segundo desarrollador recibe solo `acme/tienda` dev |

El detalle vive en [roadmap.es.md](roadmap.es.md).

Todas las versiones compilan y pasan pruebas en Windows, macOS y Linux desde el día uno. Windows es la plataforma donde más se prueba al inicio.

### 7.1 Lenguaje: Rust

- Un solo ejecutable sin dependencias, con arranque instantáneo (importa para `run` y el MCP) e instaladores simples en las tres plataformas.
- Seguridad de memoria y control de cuándo se borra un secreto de la RAM.
- Todo lo necesario existe con licencia permisiva:

| Necesidad | Crate | Versión vista | Licencia |
|---|---|---|---|
| Formato y cifrado | `age` | 0.12 | MIT o Apache-2.0 |
| Contraseña → llave | `argon2` | 0.6 | MIT o Apache-2.0 |
| Cifrado simétrico (si hace falta) | `chacha20poly1305` | 0.11 | MIT o Apache-2.0 |
| Sellado para secretos de GitHub | `crypto_box` (`seal`) | 0.9 | MIT o Apache-2.0 |
| HTTP para conectores | `reqwest` | 0.13 | MIT o Apache-2.0 |
| SSH (v0.4) | `russh` | 0.65 | Apache-2.0 |
| Borrar secretos de la RAM | `zeroize`, `secrecy` | 1.9 / 0.10 | MIT o Apache-2.0 |
| Llavero del sistema | `keyring` | 4.2 | MIT o Apache-2.0 |
| Servidor MCP | `rmcp` (SDK oficial) | 3.9 | Apache-2.0 |
| CLI | `clap` | 4.6 | MIT o Apache-2.0 |
| Serialización | `serde`, `serde_json`, `toml` | 1.0 | MIT o Apache-2.0 |
| Instaladores y versiones | `cargo-dist` | 0.34 | MIT o Apache-2.0 |
| App visual (v0.4) | `tauri` | 2.12 | MIT o Apache-2.0 |

Herramientas de CI: gitleaks (MIT), `cargo deny`, `cargo vet`. TruffleHog queda fuera por ser AGPL-3.0.

---

## 8. Riesgos

### 8.1 Seguridad

- **Error de composición**: usar age tal cual, publicar el modelo de amenazas, *fuzzing* del lector de archivos, y pedir revisión externa antes de recomendarlo como estable.
- **Los conectores tienen credenciales con poder**: documentar el permiso mínimo para cada proveedor; destinos solo de tipos conocidos; aprobación para crearlos.
- **Rotación a medias**: no revocar la vieja hasta verificar; reversión automática; `check` lo detecta.
- **Punto único de fallo**: kit de recuperación obligatorio y `recovery verify` periódico.
- **Malware en la PC**: bloqueo por inactividad, prod con PIN o biometría, canal local solo del usuario.
- **Cadena de suministro**: pocas dependencias, `cargo deny`/`cargo vet`, versiones fijas, atestaciones de origen.
- **Falsa sensación de seguridad**: publicar los límites de §3.2 en el README, no en letra pequeña.

### 8.2 Responsabilidad legal

Cemí es local y de código abierto: el autor nunca tiene acceso a secretos ajenos. La licencia Apache-2.0 excluye garantías y responsabilidad, y el README debe decir claramente que cada usuario responde por sus llaves y su kit de recuperación. Un servicio en línea que guardara bóvedas cambiaría esto (leyes de protección de datos, abogado), pero no está en los planes.

### 8.3 Competencia

1Password, Infisical y Doppler se mueven hacia "secretos para agentes" y rotación, pero con tus datos en su nube o con un servidor que mantener. Las herramientas pequeñas (secretctl, fnox, varlock, llm-secret-manager) se parecen en partes, pero ninguna tiene estructura libre, memoria, ni origen → destinos. Para un proyecto abierto lo que importa es la lección de git: resolver de verdad el problema propio, y que sea fácil de instalar y de entender.

### 8.4 Nombre

**Cemí** está libre en crates.io y npm (revisado el 11 nov 2026). En GitHub no hay proyectos con ese nombre exacto (solo nombres parecidos como "Cemiuiler" o "CEMiTool").

Nada de esto se compra. En crates.io y npm el nombre es del primero que publica algo con él: se entra con la cuenta de GitHub (crates.io) o con una cuenta gratis (npm), y la primera versión publicada reserva el nombre. Conviene publicar una v0.0.1 temprano para asegurarlo. Git tampoco compró su nombre. Años después, su organización (Software Freedom Conservancy) registró la marca para protegerla, y eso es opcional.

---

## 9. Decisiones tomadas

| Tema | Decisión |
|---|---|
| Nombre | **Cemí**, comando `cemi` |
| Licencia y publicación | Código abierto (Apache-2.0) en el GitHub personal del autor; sin dominio ni venta |
| Forma de uso | Como git: se instala con un comando, en la PC o en un proyecto, y todo se hace con comandos |
| Bóvedas | Global por PC (`~/.cemi/`) + local opcional por proyecto (`.cemi/`, nunca se sube) |
| Idioma | Comandos en inglés; documentación en inglés y español |
| Firma de código | No; se instala por gestores de paquetes o script, sin descarga manual |
| IA en producción | Puede pedir `rotate` y `push` con plan visible y aprobación con PIN o biometría; nunca ve valores. `run` en prod llega con el proxy (v0.4) |
| Primeros conectores | GitHub, Supabase, `.env` local y de comando |

**Siguiente paso:** crear el repo `cemi` (privado al inicio) y programar la v0.1 (§7).

---

## Fuentes

Consultadas el 11 nov 2026. Precios y endpoints cambian seguido: confirmar al programar.

**Herramientas existentes**
- Infisical: https://infisical.com/docs/self-hosting/ee · MCP: https://npmjs.com/package/@infisical/mcp · Agent Vault: https://infisical.com/ai-agents.md · rotación de Supabase: https://infisical.com/docs/api-reference/endpoints/secret-rotations/supabase-api-key/get-by-id.md
- 1Password: https://www.1password.dev/cli/reference/commands/run · https://www.1password.dev/get-started/secure-ai-access · https://www.1password.dev/environments/mcp-server
- Vault y OpenBao: https://www.openlogic.com/blog/hashicorp-vault-alternatives-openbao-vs-vault · https://thenewstack.io/meet-openbao-an-open-source-fork-of-hashicorp-vault/
- Bitwarden Secrets Manager: https://bitwarden.com/go/secrets-manager/ · https://bitwarden.com/help/secrets-manager-cli/ · https://community.bitwarden.com/t/bitwarden-mcp-server/86665
- SOPS: https://getsops.io/docs/ · dotenvx: https://dotenvx.com/ · git-crypt: https://formulae.brew.sh/formula/git-crypt
- mise: https://mise.jdx.dev/environments/secrets/ · fnox: https://fnox.jdx.dev/guide/what-is-fnox · https://fnox.jdx.dev/guide/proxy · direnv: https://direnv.net/
- Doppler: https://www.doppler.com/pricing · AWS: https://aws.amazon.com/secrets-manager/pricing/ · GCP: https://cloud.google.com/secret-manager/pricing

**Herramientas para agentes**
- secretctl: https://github.com/forest6511/secretctl · llm-secret-manager: https://github.com/NG-Bullseye/llm-secret-manager
- varlock: https://varlock.dev/ · https://varlock.dev/guides/proxy/ · secretspec: https://secretspec.dev/ · agent-redact: https://github.com/TonyDuongg/agent-redact
- 1Password con agentes de programación: https://kovyrin.net/2026/06/04/agent-secret/

**Seguridad de agentes**
- Simon Willison, "The lethal trifecta": https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- WorkOS: https://workos.com/blog/credentials-out-of-agent-context · agentgateway: https://agentgateway.dev/blog/2026-07-27-credential-injection-ai-agent-egress-cb4a/ · Composio: https://composio.dev/content/credential-isolation-ai-agents

**APIs de proveedores**
- Supabase: https://supabase.com/docs/guides/api/api-keys · https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys · https://supabase.com/docs/guides/integrations/supabase-for-platforms · https://supabase.com/docs/reference/api/v1-get-project-api-keys · https://supabase.com/docs/guides/functions/secrets · huellas SHA-256: https://www.pulumi.com/registry/packages/supabase/api-docs/edgefunctionsecrets/
- Cloudflare: https://developers.cloudflare.com/api/operations/user-api-tokens-roll-token
- GitHub: https://docs.github.com/en/rest/guides/encrypting-secrets-for-the-rest-api
- Resend: https://resend.com/docs/api-reference/api-keys/create-api-key

**Distribución y escaneo**
- cargo-dist: https://github.com/axodotdev/cargo-dist · gitleaks: https://github.com/gitleaks/gitleaks · mise (versiones por proyecto): https://mise.jdx.dev/
- Atestaciones de GitHub: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations

**Formato y librerías**
- age v1: https://age-encryption.org/v1 · crates: https://crates.io/crates/age · https://crates.io/crates/argon2 · https://crates.io/crates/crypto_box · https://crates.io/crates/keyring · https://crates.io/crates/rmcp · https://crates.io/crates/cargo-dist · https://crates.io/crates/tauri
