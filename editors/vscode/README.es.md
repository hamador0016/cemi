# Cemí para VS Code

*[Read in English](README.md)*

Pasa el mouse sobre una variable de entorno para ver para qué sirve la llave, cuándo vence y cómo
se rota. El valor nunca se muestra. Al guardar un archivo, la extensión avisa si tiene escrito un
valor de tus bóvedas.

```text
STRIPE_SECRET_KEY → local:stripe#secret

Kind: secret text
For: Charges cards
Expires: 2027-01-15 (in 65 days)
Rotate: Roll it in the Stripe dashboard
Set for: dev (2026-11-11)
No value for: prod
Copied to: GitHub acme/shop: secret STRIPE_KEY (prod)
```

## Qué reconoce

Solo las variables declaradas en el `cemi.toml` del proyecto muestran información. Las encuentra
en:

| Lenguaje | Formas |
|---|---|
| JavaScript, TypeScript (también Vue, Svelte, Astro) | `process.env.X`, `process.env["X"]`, `import.meta.env.X`, `Deno.env.get("X")`, `Bun.env.X` |
| Python | `os.environ["X"]`, `os.environ.get("X")`, `os.getenv("X")` |
| Rust | `env::var("X")`, `env::var_os("X")`, `env!("X")`, `option_env!("X")` |
| Go | `os.Getenv("X")`, `os.LookupEnv("X")` |
| Shell, Dockerfile, Makefile, YAML | `$X`, `${X}` |
| PowerShell | `$env:X` |
| Archivos `.env` y `cemi.toml` | `X=…`, `export X=…`, `X = "…"` |

## Secretos escritos en archivos

Al guardar, la extensión corre `cemi scan` sobre el archivo. Cemí lo compara con los valores
exactos de tus bóvedas (los actuales y los anteriores), así encuentra cualquiera de tus secretos
sin importar su formato. El aviso dice el registro y subraya dónde empieza y termina el valor.
Los archivos `.env` y `.cemi/` no se revisan (ajuste `cemi.scan.exclude`). **Cemí: Look for vault
values in this file** lo corre cuando quieras.

## Bóveda cerrada

La extensión nunca pide tu contraseña. Si la bóveda está cerrada, el texto y la barra de estado lo
dicen; **Cemí: Unlock the vault** abre una terminal con `cemi unlock` y escribes la contraseña ahí.

## Cómo habla con Cemí

Corre el programa `cemi` con `--json --no-input` y solo estos comandos: `var ls`, que lee
`cemi.toml`; `show`, que da la memoria de cada secreto y si tiene valor, nunca el valor; y `scan`,
que da el registro y la posición de un valor que encuentra, nunca el valor.

`cemi` se busca solo en el `PATH`, nunca en la carpeta abierta, así un repositorio no puede traer
su propio programa para que la extensión lo corra. El ajuste `cemi.path` solo se puede poner en
tus ajustes de usuario, no en los de un proyecto.

## Instalar

Primero instala `cemi` (ver el [README principal](../../README.es.md)). La extensión todavía no
está en el Marketplace. Córrela desde esta carpeta:

```bash
code --extensionDevelopmentPath=/ruta/a/cemi/editors/vscode /ruta/a/tu/proyecto
```

O copia la carpeta a tu carpeta de extensiones y reinicia VS Code:

```bash
cp -r editors/vscode ~/.vscode/extensions/cemi.cemi-0.1.0
```

```powershell
Copy-Item -Recurse editors\vscode "$env:USERPROFILE\.vscode\extensions\cemi.cemi-0.1.0"
```

No tiene dependencias. Se activa en carpetas que tienen un `cemi.toml` o una bóveda `.cemi/`.

## Ajustes

| Ajuste | Por defecto | Qué hace |
|---|---|---|
| `cemi.path` | `cemi` | El programa: un nombre en el `PATH` o una ruta completa (`cemi.exe` en Windows) |
| `cemi.hover.enabled` | `true` | Mostrar la información al pasar el mouse |
| `cemi.scan.onSave` | `true` | Buscar valores de la bóveda al guardar |
| `cemi.scan.exclude` | `.env`, `.env.*`, `.cemi/` | Archivos que no se revisan al guardar |
| `cemi.timeoutMs` | `5000` | Cuánto esperar a `cemi` |

## Pruebas

```bash
node --test editors/vscode/test/*.test.js
```
