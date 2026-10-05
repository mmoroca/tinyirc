**English** | [Español](#español)

# TinyIRC 1.2.0

A single-file IRC client based on [Nathan I. Laredo's TinyIRC 1.1.1](https://github.com/penny64/tinyirc/tree/master). This is the feature-rich edition; the compact edition is **TinyIRC 1.1.2**, maintained in this same repository under [`../compact/`](../compact). Each edition keeps its own `tinyirc.c`, `Makefile` and `README.md`, so they live in separate directories. `tinyircd`, the toy server from the original project, is **not** carried into this repository. The code remains **GPL-2.0-only**; the original license text is in [`../COPYING`](../COPYING).

```text
Copyright (C) 1991-2007 Nathan I. Laredo
Modified 2026 by @mmoroca & Arena.ai
```

These credits appear in the same order on startup. CTCP `VERSION` reports `TinyIRC 1.2.0`.

## Building

Without extra libraries (TCP **without encryption**):

```sh
make
# Or, if you only have the source file:
cc -std=c11 -O2 -Wall -Wextra -Wpedantic tinyirc.c -o tinyirc
```

With optional TLS, including CA and hostname/IP certificate verification, using OpenSSL 1.1.1 or newer:

```sh
# Debian/Ubuntu: install libssl-dev and pkg-config
# macOS with Homebrew: brew install openssl@3 pkgconf
PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig" make TLS=1  # macOS
# On Linux, if pkg-config already finds OpenSSL: make TLS=1
```

If you use another OpenSSL installation on macOS, supply its include and library paths to the compiler. The basic build does not require `termcap`, `ncurses`, `utmp`, obsolete headers, or platform-specific `-m486` flags. `SIGWINCH` is optional: if the macOS headers do not expose it, the client checks the terminal width periodically.

> **Verification:** GCC 14 on Linux 6.1, plain TCP and OpenSSL builds, with local tests and AddressSanitizer/UndefinedBehaviorSanitizer. The user previously confirmed operation on macOS 27, including colors, protected editing and server-console selection; the new ping behavior has been tested on Linux but not yet rechecked on that Mac. Optional TLS requires the OpenSSL development files on either platform.

## Examples

```sh
./tinyirc --nick YourNick --server irc.libera.chat --port 6697 --tls
./tinyirc YourNick irc.libera.chat 6667 -dumb
IRCSERVER='[::1]:6667' IRCNICK=YourNick ./tinyirc -dumb
```

`--tls` selects port **6697** unless you specify another port. Without `--tls`, the default is **6667**, unencrypted, and the client prints a warning. Certificate verification failures **never fall back to unencrypted TCP**. The default server is `irc.libera.chat`; other networks may require account registration or SASL, which this client does **not** implement.

The interactive interface requires an ANSI-compatible terminal with both input and output attached to a TTY. Otherwise, the client switches to line-oriented `-dumb` mode. IRC formatting controls (including `0x03` for colors, bold, italic, underline, reverse video, strikethrough, and hexadecimal `RRGGBB` colors) are interpreted: the terminal displays the **16 standard mIRC colors** and hex colors using ANSI; `-dumb` removes formatting codes without leaving question marks. Set `NO_COLOR=1` to suppress colors and styles while keeping the text readable. Extended mIRC color indices above 15 use the terminal's default color. Server-supplied ANSI escapes are never passed through to the terminal. Tabs in messages become four spaces to help preserve text artwork. If a bot sends text in a legacy encoding such as CP437 rather than UTF-8, some characters may still appear as `?`; its encoding would need to be identified before conversion.

In line-oriented mode, **EOF on stdin ends the session** after the output queue has been drained. `--help` shows the command-line syntax. `IRCSERVER` and `IRCNICK` environment variables remain supported.

## Commands

- `/join #channel [key]`, `/part [#channel] [reason]`; `/join nick` selects a private conversation and `/part nick` closes it locally. Channel keys are retained **in memory only** for rejoining after disconnection.
- `/msg target text`, `/notice target text`, `/me action`, `/nick nick[:password]`, `/topic #channel [topic]`, `/kick #channel nick [reason]`, `/away [reason]`, `/quit [reason]`.
- `/targets` lists the server console (`*`), channels, and private conversations; `/switch *` selects the server console, and `/switch [target]` selects a named conversation or cycles when omitted. `Ctrl-W` or `Esc` cycles through **all** of them, including the server console, without closing anything. Server commands such as `/whois nick` work there; text without a slash needs a channel or private target. `Ctrl-P/N` or ↑/↓ navigates command history. `Ctrl-A/E/B/F/D/H`, ←/→, `Ctrl-L`, and `Ctrl-Z` work in terminal mode.
- `/ping` or `/ping server` sends an IRC `PING` with a unique identifier and measures the matching server `PONG` in milliseconds. `/ping Alice` sends a CTCP `PING` in a `PRIVMSG` and measures only Alice's matching CTCP `NOTICE` reply; a server `PONG` does **not** measure a user's latency. A dotted server name such as `/ping molybdenum.libera.chat` selects the server form, not a nickname; the probe still measures the **connected server**, not an arbitrary remote host. Up to eight probes can be pending at once. Missing replies yield an “RTT unavailable” notice after 30 seconds, and pending probes are discarded on disconnect. A user or network that blocks CTCP cannot return a measured user RTT.
- Other IRC commands (`/whois`, `/mode`, `/names`, and so on) are sent with their arguments unchanged. `/raw COMMAND ...` sends one protocol line; it rejects line breaks and dangerous control characters. Raw `PING` is not tracked for RTT. Ambiguous legacy command abbreviations are not supported.
- The historical `@text` notation sends a hex-encoded message, and `#hex` displays decoded text. The client responds to CTCP `PING` and `VERSION` requests and displays CTCP actions.

Some servers forward a JOIN to another channel with numeric `470`. For example, `/join #trivia` may lead to `##Trivia`: the second `#` is part of the destination's real name, not a display error. The client replaces its pending `#trivia` target with `##Trivia`; after the server confirms the JOIN, one `/part` leaves it. On reconnection the client requests the destination instead of the old alias. A key supplied for the original channel is **not** reused for the forwarded channel.

On networks that support it, such as **IRC-Hispano**, `/nick name:password` identifies a registered nickname by sending `NICK name:password`. The part before the colon must be a valid IRC nick; the nonempty password is sent only with that command. The client masks it with asterisks in the interactive prompt, omits the command from history, and never stores the password for reconnection. Erasing the entire password and then the colon leaves `/nick name` visible and editable. Editing the command or colon while a credential could still be present instead keeps the whole line masked and rejects it on Enter; clear and retype it. The status line shows only the name, and the local nick changes only when the server confirms it. This is a **network-specific extension**, not standard IRC authentication; other networks may require SASL or a NickServ command instead.

For **NickServ** networks such as Libera.Chat, use `/msg NickServ IDENTIFY nick password` when that is the form instructed by the network (some services accept just `IDENTIFY password`). TinyIRC recognizes case-insensitive `/msg` or `/privmsg` directed to `NickServ`. **Once NickServ is the selected private target, typing `IDENTIFY [nick] password` directly is protected too**: a failed attempt does not make a second attempt reveal its password. In both forms, TinyIRC masks **all arguments after `IDENTIFY`** because the first argument may be a nickname or the password, sends the original message, but neither echoes its arguments in its own status output nor saves the line in history. After you erase **all** identification arguments, you can also erase the separator and edit or delete the `IDENTIFY` keyword without the rest of the line turning into asterisks. Editing its command syntax while arguments could still contain a credential instead keeps the entire line masked and rejects it on Enter; clear it and retype. If you switch conversations while a credential is **currently masked**, TinyIRC silently erases the **entire draft**, whether it is an explicit `/msg`, `/nick name:password`, or direct `IDENTIFY`. You can switch again or type a new message immediately, without an extra Enter. An `IDENTIFY` or `/nick` prefix with no masked argument, and ordinary drafts, are left alone. Input typed **after** a switch is new input: check the selected target before retyping a password. `/notice NickServ IDENTIFY ...` receives the same local protection, although services usually expect `/msg`. Very long identification messages are rejected rather than split. The password is **not** retained or automatically resent after reconnecting.

An IRC `433` means the nickname is unavailable or in use; the server's explanation is displayed without assuming that this network accepts `NICK nick:password`. If you are not yet registered (no `001` welcome), select an available nick with `/nick another_nick` and wait for the welcome before attempting NickServ identification; the client does not send `IDENTIFY` before registration.

Use a verified TLS connection before sending **either** kind of password. Without TLS, the password travels **unencrypted** and the client warns you; for Libera.Chat use `--tls` (port 6697 by default) rather than plaintext port 6667. Only the recognized forms above are protected: `/raw`, `/quote`, and network-specific aliases are **not masked or excluded from history**; do not use those forms with a password. In `-dumb` mode attached to a terminal, your terminal/shell may echo what you type; for secret entry, prefer the interactive TTY mode. Server-supplied text is outside the client's control and may itself repeat information you sent.

Bracketed paste helps prevent pasted multiple commands from being executed in terminals that support it. SASL, DCC, proxies, and a `curses` interface are not implemented. The current terminal UI uses an **editable prompt** rather than the original `termcap` scrolling region.

## Technical changes

`getaddrinfo` (IPv4/IPv6), `poll`, `termios`, `sigaction`, nonblocking connections, an outgoing queue that handles partial writes, exponential reconnection backoff, IRC lines limited to **512 bytes including CRLF**, long-message splitting at UTF-8 boundaries, a bounded parser, and protection from terminal control sequences in server messages. Obsolete APIs such as `gethostbyname`, `sgtty`, `utmp`, and `psignal` are no longer used. The optional TLS mode verifies both the certificate chain and the DNS name or IP address.

## Tests

```sh
make test
make clean && make TLS=1 && make TLS=1 test
```

Tests use local loopback IRC servers (including IPv6/TLS), without Internet access. They cover concurrent server/CTCP RTT probes, out-of-order and mismatched replies, no fabricated user latency from a server PONG, pending-probe cleanup on reconnect, TLS RTT, fragmented PING, reconnects, JOIN and numeric `470` channel forwards (including `/part`, multiple forwards, existing targets and rejoin), line limits, UTF-8, oversized input, PTY editing, password-protected `/nick` and NickServ `IDENTIFY` (explicit `/msg` and direct in its target) over TCP and TLS, masked editing, history exclusion, early `433`, target changes while typing credentials (silently discarding masked drafts without locking the keyboard), cycling to and selecting the server console while channels and private conversations remain open, erasing passwords and continuing to edit `IDENTIFY` or `/nick` prefixes, changes to protected command syntax, IRC formatting in terminal and `-dumb` modes, `NO_COLOR`, valid TLS, and rejection of incorrect certificate names.

---

[English](#tinyirc-120) | **Español**

# TinyIRC 1.2.0

Un cliente de IRC de un solo fichero basado en el [TinyIRC 1.1.1 de Nathan I. Laredo](https://github.com/penny64/tinyirc/tree/master). Esta es la edición completa; la edición compacta es **TinyIRC 1.1.2**, mantenida en este mismo repositorio en [`../compact/`](../compact). Cada edición conserva su propio `tinyirc.c`, `Makefile` y `README.md`, por eso viven en directorios separados. `tinyircd`, el servidor de juguete del proyecto original, **no** se incluye en este repositorio. El código sigue siendo **GPL-2.0-only**; el texto original de la licencia está en [`../COPYING`](../COPYING).

```text
Copyright (C) 1991-2007 Nathan I. Laredo
Modified 2026 by @mmoroca & Arena.ai
```

Estos créditos aparecen en ese mismo orden al arrancar. El CTCP `VERSION` informa `TinyIRC 1.2.0`.

## Compilación

Sin bibliotecas adicionales (TCP **sin cifrar**):

```sh
make
# O, si solo tienes el fichero fuente:
cc -std=c11 -O2 -Wall -Wextra -Wpedantic tinyirc.c -o tinyirc
```

Con TLS opcional, incluida la verificación de la CA y del nombre de *host*/IP del certificado, usando OpenSSL 1.1.1 o superior:

```sh
# Debian/Ubuntu: instala libssl-dev y pkg-config
# macOS con Homebrew: brew install openssl@3 pkgconf
PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig" make TLS=1  # macOS
# En Linux, si pkg-config ya encuentra OpenSSL: make TLS=1
```

Si en macOS usas otra instalación de OpenSSL, pasa al compilador sus rutas de cabeceras y bibliotecas. La compilación básica no necesita `termcap`, `ncurses`, `utmp`, cabeceras obsoletas ni opciones `-m486` específicas de plataforma. `SIGWINCH` es opcional: si las cabeceras de macOS no lo exponen, el cliente comprueba el ancho del terminal periódicamente.

> **Verificación:** GCC 14 en Linux 6.1, compilaciones en TCP plano y con OpenSSL, con pruebas locales y AddressSanitizer/UndefinedBehaviorSanitizer. El usuario confirmó previamente el funcionamiento en macOS 27, incluidos los colores, la edición protegida y la selección de la consola de servidor; el nuevo comportamiento de `/ping` se ha probado en Linux pero aún no se ha reconfirmado en ese Mac. El TLS opcional requiere los ficheros de desarrollo de OpenSSL en cualquiera de las dos plataformas.

## Ejemplos

```sh
./tinyirc --nick YourNick --server irc.libera.chat --port 6697 --tls
./tinyirc YourNick irc.libera.chat 6667 -dumb
IRCSERVER='[::1]:6667' IRCNICK=YourNick ./tinyirc -dumb
```

`--tls` selecciona el puerto **6697** salvo que indiques otro. Sin `--tls` el valor predeterminado es **6667**, sin cifrar, y el cliente muestra un aviso. Un fallo de verificación del certificado **nunca** provoca una vuelta a TCP sin cifrar. El servidor predeterminado es `irc.libera.chat`; otras redes pueden exigir registro de cuenta o SASL, que este cliente **no** implementa.

La interfaz interactiva requiere un terminal compatible con ANSI con la entrada y la salida conectadas a una TTY. En caso contrario, el cliente pasa al modo `-dumb`, orientado a líneas. Los códigos de formato de IRC (incluido `0x03` para colores, negrita, cursiva, subrayado, vídeo inverso, tachado y colores hexadecimales `RRGGBB`) se interpretan: el terminal muestra los **16 colores estándar de mIRC** y los colores hexadecimales mediante ANSI; `-dumb` elimina los códigos de formato sin dejar signos de interrogación. Con `NO_COLOR=1` se suprimen colores y estilos manteniendo el texto legible. Los índices de color de mIRC superiores a 15 usan el color predeterminado del terminal. Las secuencias de escape ANSI que envíe el servidor nunca se transmiten al terminal. Las tabulaciones de los mensajes se convierten en cuatro espacios para ayudar a conservar el arte ASCII. Si un *bot* envía texto en una codificación antigua como CP437 en lugar de UTF-8, algunos caracteres pueden seguir apareciendo como `?`; habría que identificar su codificación antes de convertirla.

En el modo orientado a líneas, **EOF en la entrada estándar termina la sesión** una vez vaciada la cola de salida. `--help` muestra la sintaxis de la línea de órdenes. Las variables de entorno `IRCSERVER` e `IRCNICK` siguen siendo compatibles.

## Comandos

- `/join #canal [clave]`, `/part [#canal] [motivo]`; `/join nick` selecciona una conversación privada y `/part nick` la cierra localmente. Las claves de canal se conservan **solo en memoria** para volver a entrar tras una desconexión.
- `/msg destino texto`, `/notice destino texto`, `/me acción`, `/nick nick[:contraseña]`, `/topic #canal [tema]`, `/kick #canal nick [motivo]`, `/away [motivo]`, `/quit [motivo]`.
- `/targets` lista la consola del servidor (`*`), los canales y las conversaciones privadas; `/switch *` selecciona la consola del servidor y `/switch [destino]` selecciona una conversación concreta o va rotando si se omite. `Ctrl-W` o `Esc` rota por **todos** ellos, incluida la consola del servidor, sin cerrar nada. Allí funcionan órdenes de servidor como `/whois nick`; el texto sin barra necesita un canal o un destino privado. `Ctrl-P/N` o ↑/↓ recorre el historial de órdenes. `Ctrl-A/E/B/F/D/H`, ←/→, `Ctrl-L` y `Ctrl-Z` funcionan en modo terminal.
- `/ping` o `/ping server` envía un `PING` de IRC con un identificador único y mide en milisegundos el `PONG` del servidor que le corresponde. `/ping Alicia` envía un CTCP `PING` en un `PRIVMSG` y mide únicamente el `NOTICE` CTCP de respuesta de Alicia; un `PONG` del servidor **no** mide la latencia de un usuario. Un nombre de servidor con puntos, como `/ping molybdenum.libera.chat`, selecciona la forma de servidor, no un nick; la sonda sigue midiendo el **servidor conectado**, no un equipo remoto cualquiera. Puede haber hasta ocho sondas pendientes a la vez. Si falta la respuesta, a los 30 segundos se informa de que el RTT no está disponible, y las sondas pendientes se descartan al desconectar. Un usuario o una red que bloquee CTCP no puede devolver un RTT de usuario medido.
- Las demás órdenes de IRC (`/whois`, `/mode`, `/names`, etcétera) se envían con sus argumentos sin cambios. `/raw ORDEN ...` envía una línea de protocolo; rechaza saltos de línea y caracteres de control peligrosos. Un `PING` en crudo no se registra para el RTT. No se admiten las abreviaturas ambiguas de órdenes heredadas.
- La notación histórica `@texto` envía un mensaje codificado en hexadecimal, y `#hex` muestra el texto decodificado. El cliente responde a las peticiones CTCP `PING` y `VERSION` y muestra las acciones CTCP.

Algunos servidores redirigen un JOIN a otro canal con el numérico `470`. Por ejemplo, `/join #trivia` puede acabar en `##Trivia`: el segundo `#` forma parte del nombre real del destino, no es un error de visualización. El cliente sustituye su destino pendiente `#trivia` por `##Trivia`; una vez que el servidor confirma el JOIN, un solo `/part` lo abandona. Al reconectar, el cliente pide el destino en lugar del alias antiguo. Una clave indicada para el canal original **no** se reutiliza para el canal de destino.

En las redes que lo admiten, como **IRC-Hispano**, `/nick nombre:contraseña` identifica un nick registrado enviando `NICK nombre:contraseña`. La parte anterior a los dos puntos debe ser un nick de IRC válido; la contraseña, que no puede estar vacía, solo se envía con esa orden. El cliente la enmascara con asteriscos en el *prompt* interactivo, omite la orden del historial y nunca guarda la contraseña para reconectar. Si borras toda la contraseña y después los dos puntos, `/nick nombre` queda visible y editable. En cambio, si editas la orden o los dos puntos mientras podría quedar una credencial, toda la línea sigue enmascarada y se rechaza al pulsar Intro; bórrala y vuelve a escribirla. La línea de estado muestra solo el nombre, y el nick local cambia únicamente cuando el servidor lo confirma. Se trata de una **extensión específica de esa red**, no de autenticación estándar de IRC; otras redes pueden requerir SASL o una orden de NickServ.

En redes con **NickServ**, como Libera.Chat, usa `/msg NickServ IDENTIFY nick contraseña` cuando esa sea la forma que indique la red (algunos servicios aceptan solo `IDENTIFY contraseña`). TinyIRC reconoce `/msg` o `/privmsg` dirigidos a `NickServ`, sin distinguir mayúsculas. **Una vez que NickServ es el destino privado seleccionado, escribir `IDENTIFY [nick] contraseña` directamente también está protegido**: un intento fallido no hace que un segundo intento revele su contraseña. En ambas formas, TinyIRC enmascara **todos los argumentos posteriores a `IDENTIFY`**, porque el primero puede ser un nick o la contraseña, envía el mensaje original, pero ni repite sus argumentos en su propia salida de estado ni guarda la línea en el historial. Después de borrar **todos** los argumentos de identificación, también puedes borrar el separador y editar o eliminar la palabra `IDENTIFY` sin que el resto de la línea se convierta en asteriscos. En cambio, si editas su sintaxis mientras los argumentos podrían contener aún una credencial, la línea entera sigue enmascarada y se rechaza al pulsar Intro; bórrala y vuelve a escribirla. Si cambias de conversación mientras hay una credencial **actualmente enmascarada**, TinyIRC borra en silencio el **borrador completo**, sea un `/msg` explícito, un `/nick nombre:contraseña` o un `IDENTIFY` directo. Puedes cambiar de nuevo o escribir un mensaje nuevo de inmediato, sin pulsar Intro otra vez. Un prefijo `IDENTIFY` o `/nick` sin argumentos enmascarados, y los borradores normales, se dejan intactos. Lo que escribas **después** de cambiar es entrada nueva: comprueba el destino seleccionado antes de volver a escribir una contraseña. `/notice NickServ IDENTIFY ...` recibe la misma protección local, aunque los servicios suelen esperar `/msg`. Los mensajes de identificación muy largos se rechazan en lugar de dividirse. La contraseña **no** se conserva ni se reenvía automáticamente tras reconectar.

Un `433` de IRC significa que el nick no está disponible o está en uso; se muestra la explicación del servidor sin dar por hecho que esa red acepte `NICK nick:contraseña`. Si aún no estás registrado (sin bienvenida `001`), elige un nick libre con `/nick otro_nick` y espera la bienvenida antes de intentar la identificación con NickServ; el cliente no envía `IDENTIFY` antes del registro.

Usa una conexión TLS verificada antes de enviar **cualquiera** de los dos tipos de contraseña. Sin TLS, la contraseña viaja **sin cifrar** y el cliente te avisa; en Libera.Chat usa `--tls` (puerto 6697 por defecto) en lugar del puerto 6667 en claro. Solo están protegidas las formas reconocidas descritas arriba: `/raw`, `/quote` y los alias específicos de cada red **no se enmascaran ni se excluyen del historial**; no los uses con una contraseña. En modo `-dumb` conectado a un terminal, tu terminal o *shell* puede repetir lo que escribes; para introducir secretos, usa mejor el modo interactivo con TTY. El texto que envía el servidor escapa al control del cliente y puede repetir por sí mismo información que tú hayas enviado.

El pegado entre corchetes (*bracketed paste*) ayuda a evitar que se ejecuten varias órdenes pegadas en los terminales que lo admiten. No están implementados SASL, DCC, los *proxies* ni una interfaz `curses`. La interfaz de terminal actual usa un ***prompt* editable** en lugar de la región de desplazamiento `termcap` original.

## Cambios técnicos

`getaddrinfo` (IPv4/IPv6), `poll`, `termios`, `sigaction`, conexiones no bloqueantes, una cola de salida que gestiona escrituras parciales, reintento de reconexión con espera exponencial, líneas de IRC limitadas a **512 bytes incluido el CRLF**, división de mensajes largos en fronteras UTF-8, un analizador acotado y protección frente a secuencias de control de terminal en los mensajes del servidor. Ya no se usan API obsoletas como `gethostbyname`, `sgtty`, `utmp` y `psignal`. El modo TLS opcional verifica tanto la cadena de certificados como el nombre DNS o la dirección IP.

## Pruebas

```sh
make test
make clean && make TLS=1 && make TLS=1 test
```

Las pruebas usan servidores de IRC locales en bucle (incluido IPv6/TLS), sin acceso a Internet. Cubren sondas RTT concurrentes de servidor/CTCP, respuestas desordenadas y no coincidentes, que no se invente latencia de usuario a partir de un PONG del servidor, limpieza de sondas pendientes al reconectar, RTT con TLS, PING fragmentado, reconexiones, JOIN y redirecciones de canal con el numérico `470` (incluidos `/part`, varias redirecciones, destinos ya existentes y reentrada), límites de línea, UTF-8, entradas sobredimensionadas, edición con PTY, `/nick` con contraseña y `IDENTIFY` de NickServ (tanto `/msg` explícito como directo en su destino) sobre TCP y TLS, edición enmascarada, exclusión del historial, `433` temprano, cambios de destino mientras se escriben credenciales (descartando en silencio los borradores enmascarados sin bloquear el teclado), rotación y selección de la consola del servidor mientras siguen abiertos canales y conversaciones privadas, borrado de contraseñas y edición continua de prefijos `IDENTIFY` o `/nick`, cambios en la sintaxis de órdenes protegidas, formato de IRC en modo terminal y `-dumb`, `NO_COLOR`, TLS válido y rechazo de nombres de certificado incorrectos.
