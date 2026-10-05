**English** | [Español](#español)

# TinyIRC

A single-file C IRC client, maintained as two editions in one repository.
It is a rework of Nathan I. Laredo's [TinyIRC 1.1.1](https://github.com/nlaredo/tinyirc):
modern C11/POSIX, no `termcap`, `ncurses`, `utmp` or `-m486`, plus a test suite
for each edition.

```text
Copyright (C) 1991-2007 Nathan I. Laredo
Modified 2026 by @mmoroca & Arena.ai
```

Licensed **GPL-2.0-only**; the unmodified license text is in [`COPYING`](COPYING).

## Origin

The initial commit of this repository is Laredo's `tinyirc.c` and `COPYING`
verbatim, taken from [nlaredo/tinyirc](https://github.com/nlaredo/tinyirc). The
commits above it are the rewrite, so `git log` and `git blame` show which lines
are original and which are not.

## Editions

| Directory | Edition | Notes |
|---|---|---|
| [`full/`](full) | TinyIRC 1.2.0 | Optional verified TLS (OpenSSL >= 1.1.1), color rendering, credential protection, server-console context, `/ping` RTT. 44 tests. |
| [`compact/`](compact) | TinyIRC 1.1.2 | Plain TCP, no external libraries, no password masking. 15 tests. Includes the 1.1.1 -> 1.1.2 patch. |

Both are single-file clients whose source is called `tinyirc.c`, which is why
they live in separate directories.

## Build and test

Build each edition from its own directory:

```sh
cd full && make && make test          # add TLS=1 to build with OpenSSL
cd compact && make && make test       # C11, -Wall -Wextra -Wpedantic -Werror
```

The tests need Python 3 (standard library only) and use loopback sockets and
pseudo-terminals, so no public IRC server is required. `make TLS=1 test` in
`full/` additionally needs the OpenSSL development files and `pkg-config`.
Run `make clean` afterwards; `make clean` removes the binary, and the
`.gitignore` at the repository root keeps build output and `__pycache__` out of
git.

## Layout

```text
COPYING                GPL-2.0 license text (unchanged from upstream)
README.md              this file, in English and Spanish
.gitignore
full/                  TinyIRC 1.2.0
compact/               TinyIRC 1.1.2
tinyirc.c              TinyIRC 1.1.1 as published upstream (seed commit only)
```

The root `tinyirc.c` exists only in the seed commit; both editions keep their
own copy under `full/` and `compact/`.

---

[English](#tinyirc) | **Español**

# TinyIRC

Un cliente de IRC en C de un solo fichero, mantenido como dos ediciones en un
mismo repositorio. Es una reelaboración del [TinyIRC 1.1.1](https://github.com/nlaredo/tinyirc)
de Nathan I. Laredo: C11/POSIX moderno, sin `termcap`, `ncurses`, `utmp` ni
`-m486`, y con una batería de pruebas para cada edición.

```text
Copyright (C) 1991-2007 Nathan I. Laredo
Modified 2026 by @mmoroca & Arena.ai
```

Licencia **GPL-2.0-only**; el texto original de la licencia está en
[`COPYING`](COPYING), sin cambios.

## Origen

El commit inicial de este repositorio contiene el `tinyirc.c` y el `COPYING` de
Laredo tal cual, tomados de [nlaredo/tinyirc](https://github.com/nlaredo/tinyirc).
Los commits posteriores son la reelaboración, de modo que `git log` y
`git blame` muestran qué líneas son originales y cuáles no.

## Ediciones

| Directorio | Edición | Notas |
|---|---|---|
| [`full/`](full) | TinyIRC 1.2.0 | TLS verificado opcional (OpenSSL >= 1.1.1), colores, protección de credenciales, contexto de consola de servidor, RTT con `/ping`. 44 pruebas. |
| [`compact/`](compact) | TinyIRC 1.1.2 | TCP sin cifrar, sin bibliotecas externas, sin enmascarar la contraseña. 15 pruebas. Incluye el parche 1.1.1 -> 1.1.2. |

Ambas son clientes de un solo fichero cuyo fuente se llama `tinyirc.c`, y por
eso viven en directorios separados.

## Compilación y pruebas

Compila cada edición desde su propio directorio:

```sh
cd full && make && make test          # añade TLS=1 para compilar con OpenSSL
cd compact && make && make test       # C11, -Wall -Wextra -Wpedantic -Werror
```

Las pruebas necesitan Python 3 (solo la biblioteca estándar) y usan sockets de
*bucle local* y pseudoterminales, así que no hace falta ningún servidor de IRC
público. `make TLS=1 test` en `full/` necesita además los ficheros de
desarrollo de OpenSSL y `pkg-config`. Ejecuta `make clean` al terminar:
`make clean` borra el binario, y el `.gitignore` de la raíz del repositorio
mantiene fuera de git los resultados de la compilación y `__pycache__`.

## Estructura

```text
COPYING                texto de la licencia GPL-2.0 (sin cambios respecto a upstream)
README.md              este fichero, en inglés y español
.gitignore
full/                  TinyIRC 1.2.0
compact/               TinyIRC 1.1.2
tinyirc.c              TinyIRC 1.1.1 tal como se publicó (solo en el commit semilla)
```

El `tinyirc.c` de la raíz solo existe en el commit semilla; cada edición guarda
su propia copia en `full/` y `compact/`.
