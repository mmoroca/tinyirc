**English** | [Español](#español)

# TinyIRC 1.1.2

A small, single-file IRC client based on Nathan I. Laredo's TinyIRC 1.1.1. This is the compact release; the more feature-rich edition is **TinyIRC 1.2.0**, maintained in this same repository under [`../full/`](../full). Both editions use the filename `tinyirc.c`, so each lives in its own directory: `compact/` and `full/`.

```text
Copyright (C) 1991-2007 Nathan I. Laredo
Modified 2026 by @mmoroca & Arena.ai
```

The source is **GPL-2.0-only**; see `COPYING`. The startup banner and CTCP `VERSION` identify this edition as `TinyIRC 1.1.2`.

## Build

No third-party libraries are required. On macOS or another POSIX system with a C11 compiler:

```sh
make
# Equivalent direct build:
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror tinyirc.c -o tinyirc
make clean
```

`make` compiles only this directory's `tinyirc.c` into `tinyirc`; it never touches `../full/`.

## Run

```sh
./tinyirc YourNick irc.example.net 6667
./tinyirc YourNick irc.example.net 6667 -dumb
```

The optional positional arguments are `[nick] [server] [port]`; `-dumb` may appear anywhere. Without arguments, the nick comes from `IRCNICK` or your account, the default server is `irc.libera.chat`, and the port is `6667`; `IRCSERVER=host[:port]` is also supported. Connections use IPv4 and **unencrypted TCP**.

**Security warning: this edition has no TLS or password masking.** The IRC-Hispano-specific `/nick NICK:PASSWORD` is accepted, but the password is sent **verbatim over unencrypted TCP**, appears while you type in the interactive prompt, and can remain in its eight-entry in-memory history (pressing Up/Ctrl-P can reveal it again). In `-dumb` mode, your terminal may also echo what you type. The client's own status message shows only the nickname and a warning, but that does **not** protect the password or prevent a server from echoing it. A password is not saved or retried if you issue the command while disconnected. `/msg NickServ IDENTIFY ...`, `/PASS ...` and `/join #channel key` are likewise unprotected. **Use TinyIRC 1.2.0 with verified TLS for real credentials.**

## Contexts and commands

- `/join #channel [key]` joins a channel; `/join nick` opens/selects a private conversation without sending JOIN. `/part [target] [reason]` leaves a channel (or closes a private conversation). A server-confirmed channel JOIN selects that channel.
- **Esc** cycles through open channels, private conversations **and the server context** (`*` in the prompt). `/switch *` selects the server explicitly; `/switch name` selects an open target, and `/switch` cycles. None of these actions parts a channel or closes a private conversation. `/switch *` also works in `-dumb` mode.
- At the server context you can issue commands such as `/whois nick`, `/nick newnick` and `/join #channel`. Plain text is **not** sent as a raw server command: select a conversation first. `/part` without a target there reports its usage instead of leaving a channel.
- `/nick NICK[:PASSWORD]` sends a plain nickname change or, with a password suffix, the network-specific `NICK NICK:PASSWORD` command used by IRC-Hispano. The local nick changes only on server confirmation. The password suffix is rejected if empty or if you are disconnected; it is never stored for reconnect. This minimal command does **not** mask input or encrypt the connection; see the warning above.
- `/msg target text`, `/notice target text`, `/topic`, `/kick`, `/away` and `/quit` work alongside the original command list. Full command names are required; ambiguous abbreviations from the original client are not used.
- The historical `@text` notation sends hexadecimal text, and `#hex` displays decoded text. The client answers CTCP `PING` and `VERSION`. The prompt provides eight-command history (`Ctrl-P/N` or Up/Down) and basic line editing.
- `/ping` or `/ping server` measures an IRC `PING`/`PONG` round trip to the **connected server**; `/ping Alice` sends a `PRIVMSG` with CTCP `PING` and measures only Alice's matching CTCP `NOTICE` reply. A dotted server name such as `/ping molybdenum.libera.chat` selects the server variant, **not** a CTCP request to a nickname; it still measures the server of this connection, not an arbitrary remote host. Replies show elapsed milliseconds from a monotonic clock. If no matching reply arrives in 30 seconds, the client reports that RTT is unavailable. Up to eight probes can be pending, including multiple probes to the same target; pending probes are discarded on disconnect. A server `PONG` cannot establish a user's latency.
- Incoming JOIN, PART, QUIT, NICK and KICK events display the nickname from the IRC prefix (for example, `*** Alice joined #linux` and `*** Max quit: Max SendQ exceeded`).

The terminal interface uses ANSI sequences **only to edit/redraw the prompt**, not to color messages. Received IRC formatting codes are removed and server-supplied escape sequences are neutralized. With `-dumb` (also selected automatically if input or output is not a TTY), input is line-oriented and there is no interactive prompt or Esc navigation; use `/switch` instead.

Server numeric `470` is displayed like other numerics, without special forwarding logic. If a network redirects a JOIN from `#trivia` to `##Trivia`, a subsequent JOIN notification for `##Trivia` selects that confirmed channel.

## Modernization and tests

The original K&R declarations and obsolete `sgtty`, `termcap`, `utmp` and `gethostbyname` usage were replaced with C11/POSIX code, `termios`, `poll`, `getaddrinfo`, bounded IRC lines and safer terminal output. Reconnection rejoins confirmed channels; a JOIN key is **not retained** for reconnecting. This edition does not provide the TLS, credential protection or color rendering of TinyIRC 1.2.0.

```sh
make test   # Requires Python 3; local fake-server and pseudo-terminal tests
make clean
```

Tests use loopback networking, not a public IRC server. They exercise IRC-Hispano `NICK NICK:PASSWORD` transmission, invalid/offline passwords, deliberate visibility in the terminal prompt/history, nickname attribution in JOIN/QUIT and other channel events, concurrent server/CTCP ping probes, mismatched replies and pending-probe cleanup on reconnection. The preceding compact study was built and used successfully by the user on macOS 27. Build and behavior of this renamed release, including the new nick/password and ping behavior, should be verified again on macOS.

## Provenance

`tinyirc-1.1.1-to-1.1.2.patch` reproduces this edition's `tinyirc.c` from the
unmodified TinyIRC 1.1.1 source, which is the initial commit of this repository:

```sh
# From the repository root:
TMP=$(mktemp -d)
git show "$(git rev-list --max-parents=0 HEAD)":tinyirc.c > "$TMP/tinyirc.c"
patch --fuzz=0 -p1 -d "$TMP" < compact/tinyirc-1.1.1-to-1.1.2.patch
cmp "$TMP/tinyirc.c" compact/tinyirc.c && echo identical
rm -rf "$TMP"
```

---

[English](#tinyirc-112) | **Español**

# TinyIRC 1.1.2

Un cliente de IRC pequeño, de un solo fichero, basado en el TinyIRC 1.1.1 de Nathan I. Laredo. Esta es la edición compacta; la edición más completa es **TinyIRC 1.2.0**, mantenida en este mismo repositorio en [`../full/`](../full). Ambas ediciones usan el nombre de fichero `tinyirc.c`, así que cada una vive en su propio directorio: `compact/` y `full/`.

```text
Copyright (C) 1991-2007 Nathan I. Laredo
Modified 2026 by @mmoroca & Arena.ai
```

El fuente es **GPL-2.0-only**; consulta `COPYING`. El mensaje de arranque y el CTCP `VERSION` identifican esta edición como `TinyIRC 1.1.2`.

## Compilación

No se necesita ninguna biblioteca de terceros. En macOS u otro sistema POSIX con un compilador C11:

```sh
make
# Compilación directa equivalente:
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror tinyirc.c -o tinyirc
make clean
```

`make` compila únicamente el `tinyirc.c` de este directorio en `tinyirc`; nunca toca `../full/`.

## Ejecución

```sh
./tinyirc TuNick irc.example.net 6667
./tinyirc TuNick irc.example.net 6667 -dumb
```

Los argumentos posicionales opcionales son `[nick] [servidor] [puerto]`; `-dumb` puede ir en cualquier posición. Sin argumentos, el nick se toma de `IRCNICK` o de tu cuenta, el servidor predeterminado es `irc.libera.chat` y el puerto es `6667`; también se admite `IRCSERVER=equipo[:puerto]`. Las conexiones usan IPv4 y **TCP sin cifrar**.

**Aviso de seguridad: esta edición no tiene TLS ni enmascaramiento de contraseña.** Se acepta el `/nick NICK:CONTRASEÑA` específico de IRC-Hispano, pero la contraseña se envía **literalmente por TCP sin cifrar**, aparece mientras la escribes en el *prompt* interactivo y puede quedar en su historial en memoria de ocho entradas (pulsar Arriba/Ctrl-P puede volver a mostrarla). En modo `-dumb`, tu terminal también puede repetir lo que escribes. El mensaje de estado del propio cliente muestra solo el nick y un aviso, pero eso **no** protege la contraseña ni impide que un servidor la repita. La contraseña no se guarda ni se reintenta si lanzas la orden estando desconectado. `/msg NickServ IDENTIFY ...`, `/PASS ...` y `/join #canal clave` tampoco están protegidos. **Usa TinyIRC 1.2.0 con TLS verificado para credenciales reales.**

## Contextos y comandos

- `/join #canal [clave]` entra en un canal; `/join nick` abre o selecciona una conversación privada sin enviar JOIN. `/part [destino] [motivo]` abandona un canal (o cierra una conversación privada). Un JOIN de canal confirmado por el servidor selecciona ese canal.
- **Esc** rota por los canales abiertos, las conversaciones privadas **y el contexto del servidor** (`*` en el *prompt*). `/switch *` selecciona el servidor explícitamente; `/switch nombre` selecciona un destino abierto, y `/switch` rota. Ninguna de estas acciones abandona un canal ni cierra una conversación privada. `/switch *` también funciona en modo `-dumb`.
- En el contexto del servidor puedes lanzar órdenes como `/whois nick`, `/nick nuevonick` y `/join #canal`. El texto sin barra **no** se envía como orden cruda al servidor: selecciona antes una conversación. Allí, `/part` sin destino muestra su uso en lugar de abandonar un canal.
- `/nick NICK[:CONTRASEÑA]` envía un cambio de nick normal o, con el sufijo de contraseña, la orden `NICK NICK:CONTRASEÑA` específica de la red que usa IRC-Hispano. El nick local cambia solo cuando el servidor lo confirma. El sufijo de contraseña se rechaza si está vacío o si estás desconectado; nunca se guarda para reconectar. Esta orden mínima **no** enmascara la entrada ni cifra la conexión; mira el aviso de arriba.
- `/msg destino texto`, `/notice destino texto`, `/topic`, `/kick`, `/away` y `/quit` funcionan junto a la lista de órdenes original. Se requieren los nombres de orden completos; no se usan las abreviaturas ambiguas del cliente original.
- La notación histórica `@texto` envía texto hexadecimal, y `#hex` muestra el texto decodificado. El cliente responde a CTCP `PING` y `VERSION`. El *prompt* ofrece un historial de ocho órdenes (`Ctrl-P/N` o Arriba/Abajo) y edición de línea básica.
- `/ping` o `/ping server` mide un viaje de ida y vuelta `PING`/`PONG` de IRC con el **servidor conectado**; `/ping Alicia` envía un `PRIVMSG` con CTCP `PING` y mide únicamente el `NOTICE` CTCP de respuesta de Alicia. Un nombre de servidor con puntos, como `/ping molybdenum.libera.chat`, selecciona la variante de servidor, **no** una petición CTCP a un nick; sigue midiendo el servidor de esta conexión, no un equipo remoto cualquiera. Las respuestas muestran los milisegundos transcurridos según un reloj monotónico. Si no llega ninguna respuesta coincidente en 30 segundos, el cliente informa de que el RTT no está disponible. Puede haber hasta ocho sondas pendientes, incluidas varias al mismo destino; las sondas pendientes se descartan al desconectar. Un `PONG` del servidor no puede establecer la latencia de un usuario.
- Los eventos entrantes JOIN, PART, QUIT, NICK y KICK muestran el nick del prefijo de IRC (por ejemplo, `*** Alice joined #linux` y `*** Max quit: Max SendQ exceeded`).

La interfaz de terminal usa secuencias ANSI **solo para editar y redibujar el *prompt***, no para colorear mensajes. Los códigos de formato de IRC recibidos se eliminan y las secuencias de escape que envíe el servidor se neutralizan. Con `-dumb` (que también se selecciona automáticamente si la entrada o la salida no son una TTY), la entrada está orientada a líneas y no hay *prompt* interactivo ni navegación con Esc; usa `/switch` en su lugar.

El numérico de servidor `470` se muestra como los demás numéricos, sin lógica especial de redirección. Si una red redirige un JOIN de `#trivia` a `##Trivia`, una notificación JOIN posterior de `##Trivia` selecciona ese canal ya confirmado.

## Modernización y pruebas

Las declaraciones K&R originales y el uso obsoleto de `sgtty`, `termcap`, `utmp` y `gethostbyname` se sustituyeron por código C11/POSIX, `termios`, `poll`, `getaddrinfo`, líneas de IRC acotadas y una salida a terminal más segura. La reconexión vuelve a entrar en los canales confirmados; la clave de JOIN **no** se conserva para reconectar. Esta edición no ofrece el TLS, la protección de credenciales ni el coloreado de TinyIRC 1.2.0.

```sh
make test   # Requiere Python 3; pruebas locales con servidor simulado y pseudoterminal
make clean
```

Las pruebas usan red de bucle local, no un servidor de IRC público. Ejercitan la transmisión de `NICK NICK:CONTRASEÑA` de IRC-Hispano, contraseñas inválidas o sin conexión, la visibilidad deliberada en el *prompt* y el historial del terminal, la atribución del nick en JOIN/QUIT y otros eventos de canal, sondas *ping* concurrentes de servidor/CTCP, respuestas no coincidentes y la limpieza de sondas pendientes al reconectar. El estudio compacto previo fue compilado y usado con éxito por el usuario en macOS 27. La compilación y el comportamiento de esta versión renombrada, incluido el nuevo manejo de nick/contraseña y de *ping*, deberían verificarse de nuevo en macOS.

## Procedencia

`tinyirc-1.1.1-to-1.1.2.patch` reproduce el `tinyirc.c` de esta edición a partir
del fuente de TinyIRC 1.1.1 sin modificar, que es el commit inicial de este
repositorio:

```sh
# Desde la raíz del repositorio:
TMP=$(mktemp -d)
git show "$(git rev-list --max-parents=0 HEAD)":tinyirc.c > "$TMP/tinyirc.c"
patch --fuzz=0 -p1 -d "$TMP" < compact/tinyirc-1.1.1-to-1.1.2.patch
cmp "$TMP/tinyirc.c" compact/tinyirc.c && echo identical
rm -rf "$TMP"
```
