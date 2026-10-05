/*
 * TinyIRC 1.2.0 - portable IRC client (POSIX/macOS/Linux)
 *
 * Copyright (C) 1991-2007 Nathan I. Laredo
 * Modified 2026 by @mmoroca & Arena.ai
 * Based on TinyIRC 1.1.1.  SPDX-License-Identifier: GPL-2.0-only
 * See COPYING for the complete license.  This is the CLIENT, not tinyircd.
 *
 * Build without dependencies: cc -std=c11 -O2 -Wall -Wextra -Wpedantic \
 *                             tinyirc.c -o tinyirc
 * Optional verified TLS (OpenSSL >= 1.1.1): add -DTINYIRC_USE_OPENSSL and
 *                             the compiler/linker flags from pkg-config openssl.
 */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#ifdef TINYIRC_USE_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#endif

#define RELEASE             "TinyIRC 1.2.0"
#define ORIGINAL_COPYRIGHT  "Copyright (C) 1991-2007 Nathan I. Laredo"
#define MODIFICATION_CREDIT "Modified 2026 by @mmoroca & Arena.ai"
#define DEFAULT_SERVER      "irc.libera.chat"
#define DEFAULT_PORT        6667
#define TLS_PORT            6697
#define IRC_PAYLOAD_MAX     510u       /* RFC 1459/2812: 512 including CRLF */
#define RX_CAP              8192u      /* also tolerates IRCv3 message tags */
#define TX_CAP              65536u
#define INPUT_CAP           4096u
#define HISTORY_CAP         8u
#define TARGET_CAP          64u
#define TARGET_NAME_CAP     128u
#define CONNECT_TIMEOUT_MS 6000u
#define PING_LIMIT          8u
#define PING_WAIT_MS        30000u

static volatile sig_atomic_t stop_signal;
static volatile sig_atomic_t resize_signal;
static volatile sig_atomic_t suspend_signal;

typedef enum { CASE_ASCII, CASE_RFC1459, CASE_STRICT_RFC1459 } CaseMap;
typedef enum {
    SECRET_NONE, SECRET_NICK_PASSWORD, SECRET_NICKSERV_MESSAGE, SECRET_BARE_IDENTIFY
} SecretEdit;

typedef struct Target {
    char name[TARGET_NAME_CAP];
    char key[TARGET_NAME_CAP];          /* optional JOIN key, only in memory */
    char modes[64];
    bool wanted;                        /* rejoin after a reconnect */
    bool joined;
    struct Target *next;
} Target;

typedef struct {
    char token[64], target[256];
    uint64_t started;
    bool active, peer;
} PingProbe;

typedef struct {
    int fd;
    char host[256], port[6], nick[64], username[64], realname[128];
    bool dumb, tty_active, stdin_eof, quitting, registered, tls_requested;
    bool rx_drop, input_drop, paste, defer_redraw, prompt_dirty;
    SecretEdit secret_edit;           /* protect recognized identification drafts */
    bool secret_had_arguments;        /* unlock prefix only after erasing them */
    struct termios old_tty;
    CaseMap casemap;
    Target *targets, *current;         /* NULL current = server console */
    bool server_console_selected;      /* do not auto-select an incoming target */
    size_t target_count;
    char rx[RX_CAP + 1];
    size_t rx_len;
    char tx[TX_CAP];
    size_t tx_off, tx_len;
    char edit[INPUT_CAP], history[HISTORY_CAP][INPUT_CAP], draft[INPUT_CAP];
    size_t edit_len, cursor;
    unsigned hist_count, hist_next;
    int hist_nav;                       /* -1 = current unsaved input */
    int escape;                         /* 0=normal, 1=ESC, 2=CSI, 3=SS3 */
    char escape_seq[16];
    size_t escape_len;
    uint64_t escape_at, next_retry, backoff, quit_deadline;
    PingProbe pings[PING_LIMIT];
    uint64_t ping_serial;
    time_t last_prompt_minute;
    int last_columns;                  /* resize fallback when SIGWINCH is hidden */
#ifdef TINYIRC_USE_OPENSSL
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    bool tls_ready;
    short handshake_want, read_want, write_want;
    size_t ssl_retry_len;               /* keep SSL_write's pointer/size stable */
#endif
} Client;

typedef struct {
    char *prefix, *command, *param[15];
    size_t count;
} IrcMessage;

static void draw_prompt(Client *c);
static void ui_printf(Client *c, const char *fmt, ...);
static void process_input(Client *c, char *line);
static bool irc_send(Client *c, const char *fmt, ...);
static void socket_lost(Client *c, const char *why);

static uint64_t clock_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    return (uint64_t)time(NULL) * 1000u;
}

static void on_signal(int signum)
{
#ifdef SIGWINCH
    if (signum == SIGWINCH) {
        resize_signal = 1;
        return;
    }
#endif
    if (signum == SIGCONT)
        resize_signal = 1;
    else if (signum == SIGTSTP)
        suspend_signal = 1;
    else
        stop_signal = signum;
}

static bool set_handler(int signum, void (*handler)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    return sigaction(signum, &sa, NULL) == 0;
}

static bool copy_string(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap)
        return false;
    memcpy(dst, src, n + 1);
    return true;
}

static unsigned char ascii_lower(unsigned char ch)
{
    return ch >= 'A' && ch <= 'Z' ? (unsigned char)(ch + ('a' - 'A')) : ch;
}

/* Detect the password field of the server-specific /nick NAME:PASSWORD syntax.
 * The returned offset also works for a password that is still being typed. */
static size_t nick_password_start(const char *line, size_t len)
{
    static const char command[] = "nick";
    size_t i, j;
    if (len < 6 || line[0] != '/') return SIZE_MAX;
    for (j = 0; j < sizeof(command) - 1; j++)
        if (ascii_lower((unsigned char)line[j + 1]) != (unsigned char)command[j])
            return SIZE_MAX;
    i = 5;
    if (line[i] == ':') return i + 1; /* also mask an incomplete command */
    if (line[i] != ' ' && line[i] != '\t') return SIZE_MAX;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    while (i < len && line[i] != ' ' && line[i] != '\t') {
        if (line[i] == ':') return i + 1;
        i++;
    }
    return SIZE_MAX;
}

static bool ascii_segment_equal(const char *text, size_t len, const char *word)
{
    size_t i;
    if (strlen(word) != len) return false;
    for (i = 0; i < len; i++)
        if (ascii_lower((unsigned char)text[i]) !=
            ascii_lower((unsigned char)word[i])) return false;
    return true;
}

/* For /msg NickServ IDENTIFY [nick] password, mask every argument: the
 * first one may itself be the password. Also accept /privmsg and /notice. */
static size_t nickserv_identify_start(const char *line, size_t len)
{
    size_t i = 1, start;
    if (len < 2 || line[0] != '/') return SIZE_MAX;
    while (i < len && line[i] != ' ' && line[i] != '\t') i++;
    if (!ascii_segment_equal(line + 1, i - 1, "msg") &&
        !ascii_segment_equal(line + 1, i - 1, "privmsg") &&
        !ascii_segment_equal(line + 1, i - 1, "notice")) return SIZE_MAX;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    start = i;
    while (i < len && line[i] != ' ' && line[i] != '\t') i++;
    if (!ascii_segment_equal(line + start, i - start, "NickServ")) return SIZE_MAX;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    if (i < len && line[i] == ':') i++; /* be cautious even with an extra colon */
    start = i;
    while (i < len && line[i] != ' ' && line[i] != '\t') i++;
    if (!ascii_segment_equal(line + start, i - start, "IDENTIFY")) return SIZE_MAX;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    return i;
}

static bool current_is_nickserv(const Client *c)
{
    return c->current && ascii_segment_equal(c->current->name,
                                               strlen(c->current->name), "NickServ");
}

/* A bare IDENTIFY is a message to the selected NickServ target. Recognize
 * the complete keyword even after its arguments and separator are erased. */
static size_t bare_identify_start(const char *line, size_t len)
{
    size_t i = 0;
    if (!len || line[0] == '/') return SIZE_MAX;
    while (i < len && line[i] != ' ' && line[i] != '\t') i++;
    if (!ascii_segment_equal(line, i, "IDENTIFY")) return SIZE_MAX;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    return i;
}

static size_t secret_start_for_kind(SecretEdit kind, const char *line, size_t len)
{
    if (kind == SECRET_NICK_PASSWORD) return nick_password_start(line, len);
    if (kind == SECRET_NICKSERV_MESSAGE) return nickserv_identify_start(line, len);
    if (kind == SECRET_BARE_IDENTIFY) return bare_identify_start(line, len);
    return SIZE_MAX;
}

static size_t input_secret_start(const Client *c, const char *line, size_t len)
{
    size_t i;
    if (c->secret_edit != SECRET_NONE) {
        i = secret_start_for_kind(c->secret_edit, line, len);
        return i != SIZE_MAX ? i : 0; /* edited command: mask everything */
    }
    i = nick_password_start(line, len);
    if (i != SIZE_MAX) return i;
    i = nickserv_identify_start(line, len);
    if (i != SIZE_MAX) return i;
    return current_is_nickserv(c) ? bare_identify_start(line, len) : SIZE_MAX;
}

static void reset_secret_edit(Client *c)
{
    c->secret_edit = SECRET_NONE;
    c->secret_had_arguments = false;
}

static void wipe_secret(void *data, size_t len)
{
    volatile unsigned char *p = data;
    while (len--) *p++ = 0;
}

static bool ascii_equal(const char *a, const char *b)
{
    while (*a && *b) {
        if (ascii_lower((unsigned char)*a++) != ascii_lower((unsigned char)*b++))
            return false;
    }
    return *a == *b;
}

static unsigned char irc_lower(CaseMap map, unsigned char ch)
{
    ch = ascii_lower(ch);
    if (map != CASE_ASCII) {
        if (ch == '[') return '{';
        if (ch == ']') return '}';
        if (ch == '\\') return '|';
        if (ch == '^' && map == CASE_RFC1459) return '~';
    }
    return ch;
}

static bool irc_equal(const Client *c, const char *a, const char *b)
{
    while (*a && *b) {
        if (irc_lower(c->casemap, (unsigned char)*a++) !=
            irc_lower(c->casemap, (unsigned char)*b++))
            return false;
    }
    return *a == *b;
}

static bool channel_name(const char *name)
{
    return name && (name[0] == '#' || name[0] == '&' ||
                    name[0] == '+' || name[0] == '!');
}

/* UTF-8 validation is used for safe terminal output, never as an IRC parser. */
static size_t utf8_one(const char *s, size_t left, uint32_t *cp)
{
    unsigned char a, b;
    size_t i, need;
    uint32_t value, min;
    if (!left) return 0;
    a = (unsigned char)s[0];
    if (a < 0x80) { *cp = a; return 1; }
    if (a >= 0xc2 && a <= 0xdf) { need = 2; value = a & 0x1f; min = 0x80; }
    else if (a >= 0xe0 && a <= 0xef) { need = 3; value = a & 0x0f; min = 0x800; }
    else if (a >= 0xf0 && a <= 0xf4) { need = 4; value = a & 7; min = 0x10000; }
    else return 0;
    if (left < need) return 0;
    for (i = 1; i < need; i++) {
        b = (unsigned char)s[i];
        if ((b & 0xc0) != 0x80) return 0;
        value = (value << 6) | (b & 0x3f);
    }
    if (value < min || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
        return 0;
    *cp = value;
    return need;
}

static bool safe_codepoint(uint32_t cp)
{
    /* Do not let the server move the cursor, erase text or reorder nicknames. */
    return cp >= 0x20 && !(cp >= 0x7f && cp <= 0x9f) &&
           cp != 0x2028 && cp != 0x2029 &&
           !(cp >= 0x202a && cp <= 0x202e) &&
           !(cp >= 0x2066 && cp <= 0x2069);
}

static void safe_write(const char *s, size_t len)
{
    size_t i = 0, n;
    uint32_t cp;
    while (i < len) {
        n = utf8_one(s + i, len - i, &cp);
        if (!n) { putchar('?'); i++; }
        else {
            if (safe_codepoint(cp)) (void)fwrite(s + i, 1, n, stdout);
            else putchar('?');
            i += n;
        }
    }
}

/* IRC formatting is NOT ANSI: never forward terminal escapes from the server.
 * Interpret only the IRC controls we understand, then generate our own SGR.
 * The formatting state is local to each displayed line and always reset. */
typedef struct {
    bool bold, italic, underline, reverse, strike;
    int fg, bg;                         /* -1 = terminal default; 0..15 = mIRC */
    bool fg_rgb, bg_rgb;
    unsigned rgb_fg, rgb_bg;           /* 24-bit hexadecimal mIRC colours */
} IrcStyle;

static int hex_value(unsigned char ch);

static bool hex_rgb(const char *text, size_t available, unsigned *out)
{
    size_t j;
    unsigned rgb = 0;
    if (available < 6) return false;
    for (j = 0; j < 6; j++) {
        int nibble = hex_value((unsigned char)text[j]);
        if (nibble < 0) return false;
        rgb = (rgb << 4) | (unsigned)nibble;
    }
    *out = rgb;
    return true;
}

static size_t decimal_color(const char *text, size_t available, int *value)
{
    size_t n = 0;
    *value = 0;
    while (n < available && n < 2 && text[n] >= '0' && text[n] <= '9') {
        *value = *value * 10 + text[n] - '0';
        n++;
    }
    return n;
}

static void clear_irc_colors(IrcStyle *style)
{
    style->fg = style->bg = -1;
    style->fg_rgb = style->bg_rgb = false;
}

static void emit_irc_style(const IrcStyle *style)
{
    /* Basic palette: approximation of the sixteen traditional mIRC colours.
     * For colour 0/1 without a background use the terminal's foreground;
     * this keeps text readable on both dark and light terminal themes. */
    static const int foreground[16] = {
        97, 30, 34, 32, 31, 31, 35, 33,
        93, 92, 36, 96, 94, 95, 90, 37
    };
    static const int background[16] = {
        107, 40, 44, 42, 41, 41, 45, 43,
        103, 102, 46, 106, 104, 105, 100, 47
    };
    bool has_bg = style->bg_rgb || (style->bg >= 0 && style->bg < 16);
    bool has_fg = style->fg_rgb || (style->fg >= 0 && style->fg < 16);
    if (!has_bg && !style->fg_rgb && (style->fg == 0 || style->fg == 1))
        has_fg = false;
    if (has_fg && has_bg &&
        ((style->fg_rgb && style->bg_rgb && style->rgb_fg == style->rgb_bg) ||
         (!style->fg_rgb && !style->bg_rgb && style->fg == style->bg)))
        has_fg = false;
    fputs("\033[0", stdout);
    if (style->bold) fputs(";1", stdout);
    if (style->italic) fputs(";3", stdout);
    if (style->underline) fputs(";4", stdout);
    if (style->reverse) fputs(";7", stdout);
    if (style->strike) fputs(";9", stdout);
    if (has_fg) {
        if (style->fg_rgb)
            (void)printf(";38;2;%u;%u;%u", (style->rgb_fg >> 16) & 255u,
                         (style->rgb_fg >> 8) & 255u, style->rgb_fg & 255u);
        else (void)printf(";%d", foreground[style->fg]);
    }
    if (has_bg) {
        if (style->bg_rgb)
            (void)printf(";48;2;%u;%u;%u", (style->rgb_bg >> 16) & 255u,
                         (style->rgb_bg >> 8) & 255u, style->rgb_bg & 255u);
        else (void)printf(";%d", background[style->bg]);
    }
    putchar('m');
}

static void render_irc_text(const Client *c, const char *s, size_t len)
{
    const char *no_color = getenv("NO_COLOR");
    bool ansi = !c->dumb && c->tty_active && !(no_color && *no_color);
    bool formatted = false;
    IrcStyle style = {.fg = -1, .bg = -1};
    size_t i = 0, plain = 0;
    while (i < len) {
        unsigned char ch = (unsigned char)s[i];
        if (ch != 0x02 && ch != 0x03 && ch != 0x04 && ch != 0x0f &&
            ch != 0x11 && ch != 0x16 && ch != 0x1d && ch != 0x1e &&
            ch != 0x1f && ch != '\t') {
            i++;
            continue;
        }
        safe_write(s + plain, i - plain);
        if (ch == '\t') {
            /* Avoid terminal-dependent tab stops breaking ASCII artwork. */
            fputs("    ", stdout);
            i++;
        } else if (ch == 0x03) {
            int colour;
            size_t digits;
            clear_irc_colors(&style);
            i++;
            digits = decimal_color(s + i, len - i, &colour);
            if (digits) {
                if (colour < 16) style.fg = colour;
                i += digits;
                if (i < len && s[i] == ',' && i + 1 < len &&
                    s[i + 1] >= '0' && s[i + 1] <= '9') {
                    i++;
                    digits = decimal_color(s + i, len - i, &colour);
                    if (colour < 16) style.bg = colour;
                    i += digits;
                }
            }
            if (ansi) emit_irc_style(&style);
            formatted = true;
        } else if (ch == 0x04) {
            unsigned rgb;
            clear_irc_colors(&style);
            i++;
            if (hex_rgb(s + i, len - i, &rgb)) {
                style.fg_rgb = true;
                style.rgb_fg = rgb;
                i += 6;
                if (i < len && s[i] == ',' && hex_rgb(s + i + 1, len - i - 1, &rgb)) {
                    style.bg_rgb = true;
                    style.rgb_bg = rgb;
                    i += 7;
                }
            }
            if (ansi) emit_irc_style(&style);
            formatted = true;
        } else {
            i++;
            if (ch == 0x0f) style = (IrcStyle){.fg = -1, .bg = -1};
            else if (ch == 0x02) style.bold = !style.bold;
            else if (ch == 0x16) style.reverse = !style.reverse;
            else if (ch == 0x1d) style.italic = !style.italic;
            else if (ch == 0x1e) style.strike = !style.strike;
            else if (ch == 0x1f) style.underline = !style.underline;
            /* 0x11 requests monospace; no portable ANSI equivalent. */
            if (ch != 0x11 && ansi) emit_irc_style(&style);
            formatted = true;
        }
        plain = i;
    }
    safe_write(s + plain, len - plain);
    if (ansi && formatted) fputs("\033[0m", stdout);
}

static size_t char_width(const char *s, size_t left, size_t *bytes)
{
    uint32_t cp;
    int w;
    *bytes = utf8_one(s, left, &cp);
    if (!*bytes) { *bytes = 1; return 1; }
    if (!safe_codepoint(cp)) return 1;
    w = wcwidth((wchar_t)cp);
    return w < 0 ? 1u : (size_t)w;
}

static size_t text_width(const char *s, size_t len)
{
    size_t pos = 0, bytes, width = 0;
    while (pos < len) {
        width += char_width(s + pos, len - pos, &bytes);
        pos += bytes;
    }
    return width;
}

static size_t previous_char(const char *s, size_t pos)
{
    size_t start, n;
    uint32_t cp;
    if (pos == 0) return 0;
    start = pos - 1;
    while (start && ((unsigned char)s[start] & 0xc0) == 0x80)
        start--;
    n = utf8_one(s + start, pos - start, &cp);
    return n == pos - start ? start : pos - 1;
}

static size_t next_char(const char *s, size_t len, size_t pos)
{
    size_t n;
    uint32_t cp;
    if (pos == len) return len;
    n = utf8_one(s + pos, len - pos, &cp);
    return pos + (n ? n : 1);
}

static int terminal_columns(void)
{
    struct winsize ws;
    const char *env;
    char *end;
    long n;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col >= 20)
        return ws.ws_col;
    env = getenv("COLUMNS");
    if (env) {
        errno = 0;
        n = strtol(env, &end, 10);
        if (!errno && *env && !*end && n >= 20 && n <= 1000) return (int)n;
    }
    return 80;
}

static void draw_prompt(Client *c)
{
    char prompt[320], timebuf[16], shown[INPUT_CAP];
    time_t now;
    struct tm tm_now;
    size_t prefix, budget, start = 0, end = 0, bytes, width = 0, back;
    size_t password_at;
    int columns;
    if (c->dumb || !c->tty_active) return;
    if (c->secret_edit == SECRET_NONE && c->edit_len) {
        /* Latch as soon as a credential-bearing command is recognizable,
         * even before the first password byte or a target switch. */
        password_at = nick_password_start(c->edit, c->edit_len);
        if (password_at != SIZE_MAX)
            c->secret_edit = SECRET_NICK_PASSWORD;
        else if (nickserv_identify_start(c->edit, c->edit_len) != SIZE_MAX)
            c->secret_edit = SECRET_NICKSERV_MESSAGE;
        else if (current_is_nickserv(c) &&
                 bare_identify_start(c->edit, c->edit_len) != SIZE_MAX)
            c->secret_edit = SECRET_BARE_IDENTIFY;
    }
    if (c->secret_edit != SECRET_NONE) {
        password_at = secret_start_for_kind(c->secret_edit, c->edit, c->edit_len);
        if (password_at != SIZE_MAX && password_at < c->edit_len)
            c->secret_had_arguments = true;
    }
    if (c->defer_redraw) { c->prompt_dirty = true; return; }
    c->prompt_dirty = false;
    memcpy(shown, c->edit, c->edit_len + 1);
    password_at = input_secret_start(c, shown, c->edit_len);
    if (password_at != SIZE_MAX)
        memset(shown + password_at, '*', c->edit_len - password_at);
    columns = terminal_columns();
    c->last_columns = columns;
    now = time(NULL);
    c->last_prompt_minute = now / 60;
    if (localtime_r(&now, &tm_now))
        (void)snprintf(timebuf, sizeof(timebuf), "%02d:%02d", tm_now.tm_hour, tm_now.tm_min);
    else (void)copy_string(timebuf, sizeof(timebuf), "--:--");
    if (c->current && c->current->modes[0])
        (void)snprintf(prompt, sizeof(prompt), "[%s %s | %s (%s)] > ", timebuf,
                       c->nick, c->current->name, c->current->modes);
    else
        (void)snprintf(prompt, sizeof(prompt), "[%s %s | %s] > ", timebuf,
                       c->nick, c->current ? c->current->name : "*");
    prefix = text_width(prompt, strlen(prompt));
    if (prefix + 4 >= (size_t)columns) {
        (void)copy_string(prompt, sizeof(prompt), "> ");
        prefix = 2;
    }
    budget = (size_t)columns - prefix - 1; /* avoid right-margin wrap */
    while (start < c->cursor && text_width(shown + start, c->cursor - start) >= budget)
        start = next_char(shown, c->edit_len, start);
    end = start;
    while (end < c->edit_len) {
        size_t w = char_width(shown + end, c->edit_len - end, &bytes);
        if (width + w > budget) break;
        width += w;
        end += bytes;
    }
    back = end > c->cursor ? text_width(shown + c->cursor, end - c->cursor) : 0;
    fputs("\r\033[2K", stdout);
    safe_write(prompt, strlen(prompt));
    safe_write(shown + start, end - start);
    if (back) (void)printf("\033[%zuD", back);
    (void)fflush(stdout);
}

static void ui_bytes(Client *c, const char *head, const char *body, size_t len)
{
    if (!c->dumb && c->tty_active) fputs("\r\033[2K", stdout);
    safe_write(head, strlen(head));
    render_irc_text(c, body, len);
    putchar('\n');
    draw_prompt(c);
    (void)fflush(stdout);
}

static void ui_printf(Client *c, const char *fmt, ...)
{
    char line[RX_CAP + 512];
    va_list args;
    int n;
    va_start(args, fmt);
    n = vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);
    if (n < 0) return;
    if ((size_t)n >= sizeof(line)) n = (int)sizeof(line) - 1;
    ui_bytes(c, "", line, (size_t)n);
}

static bool enable_tty(Client *c)
{
    struct termios raw;
    if (tcgetattr(STDIN_FILENO, &c->old_tty) != 0) return false;
    raw = c->old_tty;
    raw.c_iflag &= (tcflag_t)~(ICRNL | IXON);
    raw.c_lflag &= (tcflag_t)~(ICANON | ECHO | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return false;
    c->tty_active = true;
    fputs("\033[?2004h", stdout);           /* bracketed paste */
    draw_prompt(c);
    return true;
}

static void disable_tty(Client *c)
{
    if (!c->tty_active) return;
    fputs("\r\033[2K\033[?2004l", stdout);
    (void)fflush(stdout);
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &c->old_tty);
    c->tty_active = false;
}

static void suspend_tty(Client *c)
{
    suspend_signal = 0;
    disable_tty(c);
    (void)set_handler(SIGTSTP, SIG_DFL);
    (void)raise(SIGTSTP);
    (void)set_handler(SIGTSTP, on_signal);
    if (!c->dumb && !enable_tty(c)) c->dumb = true;
    resize_signal = 1;
}

static bool valid_text(const char *s);

static bool valid_atom(const char *s, size_t cap)
{
    size_t i, n = strlen(s);
    if (!n || n >= cap) return false;
    for (i = 0; i < n; i++) {
        unsigned char b = (unsigned char)s[i];
        if (b <= ' ' || b == 0x7f || b == ',' || b == ':' || b == 0x1b)
            return false;
    }
    return valid_text(s);
}

static bool valid_nick(const char *s)
{
    size_t i;
    if (!valid_atom(s, 64)) return false;
    for (i = 0; s[i]; i++)
        if (s[i] == '!' || s[i] == '@' || s[i] == '#' || s[i] == '&')
            return false;
    return true;
}

static bool valid_text(const char *s)
{
    size_t i = 0, n = strlen(s), bytes;
    uint32_t cp;
    while (i < n) {
        bytes = utf8_one(s + i, n - i, &cp);
        if (!bytes || !safe_codepoint(cp)) return false;
        i += bytes;
    }
    return true;
}

/* An edit with masked credential bytes must not follow a target switch.
 * Erase it silently; an unmasked prefix or ordinary draft may remain. */
static void discard_masked_edit(Client *c)
{
    if (c->secret_edit == SECRET_NONE || !c->edit_len ||
        input_secret_start(c, c->edit, c->edit_len) >= c->edit_len) return;
    wipe_secret(c->edit, sizeof(c->edit));
    wipe_secret(c->draft, sizeof(c->draft));
    c->edit_len = c->cursor = 0;
    c->hist_nav = -1;
    reset_secret_edit(c);
    draw_prompt(c);
}

static void set_current_target(Client *c, Target *target)
{
    if (c->current == target) {
        if (!target) c->server_console_selected = true;
        return;
    }
    c->current = target;
    c->server_console_selected = target == NULL;
    discard_masked_edit(c);
}

static Target *find_target(Client *c, const char *name)
{
    Target *t;
    for (t = c->targets; t; t = t->next)
        if (irc_equal(c, t->name, name)) return t;
    return NULL;
}

static Target *add_target(Client *c, const char *name, bool select)
{
    Target *t;
    bool first_target = !c->targets && !c->current && !c->server_console_selected;
    if (!valid_atom(name, TARGET_NAME_CAP)) {
        ui_printf(c, "*** Invalid or overlong target name.");
        return NULL;
    }
    t = find_target(c, name);
    if (t) { if (select) set_current_target(c, t); return t; }
    if (c->target_count >= TARGET_CAP) {
        ui_printf(c, "*** Target limit (%u) reached.", TARGET_CAP);
        return NULL;
    }
    t = calloc(1, sizeof(*t));
    if (!t) { ui_printf(c, "*** Out of memory for another target."); return NULL; }
    (void)copy_string(t->name, sizeof(t->name), name);
    t->next = c->targets;
    c->targets = t;
    c->target_count++;
    if (select || first_target) set_current_target(c, t);
    return t;
}

static void remove_target(Client *c, const char *name)
{
    Target **p = &c->targets, *t;
    while (*p && !irc_equal(c, (*p)->name, name)) p = &(*p)->next;
    if (!*p) return;
    t = *p;
    *p = t->next;
    if (c->current == t) set_current_target(c, t->next ? t->next : c->targets);
    memset(t->key, 0, sizeof(t->key));
    free(t);
    c->target_count--;
    draw_prompt(c);
}

static void cycle_target(Client *c)
{
    if (!c->targets) { set_current_target(c, NULL); return; }
    set_current_target(c, c->current ? c->current->next : c->targets);
    ui_printf(c, "*** Current target: %s", c->current ? c->current->name : "server");
}

/* A bounded queue prevents partial writes, EINTR and EAGAIN from losing IRC lines. */
static size_t queue_free(const Client *c)
{
    size_t reusable = c->tx_off;
#ifdef TINYIRC_USE_OPENSSL
    if (c->ssl_retry_len) reusable = 0;
#endif
    return TX_CAP - (c->tx_len - reusable);
}

static bool queue_payload(Client *c, const char *payload, size_t n)
{
    size_t i;
    if (c->fd < 0) { ui_printf(c, "*** Not connected."); return false; }
#ifdef TINYIRC_USE_OPENSSL
    if (c->tls_requested && !c->tls_ready) {
        ui_printf(c, "*** TLS handshake in progress; please wait.");
        return false;
    }
#endif
    if (n > IRC_PAYLOAD_MAX) {
        ui_printf(c, "*** IRC line too long (%zu > %u bytes).", n, IRC_PAYLOAD_MAX);
        return false;
    }
    for (i = 0; i < n; i++) {
        unsigned char b = (unsigned char)payload[i];
        if (!b || b == '\r' || b == '\n' || b == 0x1b || b == 0x7f ||
            (b < 0x20 && b != 0x01)) {
            ui_printf(c, "*** Line rejected: contains control characters.");
            return false;
        }
    }
    /* Do not relocate a buffer while OpenSSL is retrying SSL_write. */
#ifdef TINYIRC_USE_OPENSSL
    if (c->tx_off && !c->ssl_retry_len)
#else
    if (c->tx_off)
#endif
    {
        size_t unsent = c->tx_len - c->tx_off;
        memmove(c->tx, c->tx + c->tx_off, unsent);
        wipe_secret(c->tx + unsent, c->tx_off);
        c->tx_len = unsent;
        c->tx_off = 0;
    }
    if (n + 2 > TX_CAP - c->tx_len) {
        ui_printf(c, "*** Outgoing queue full; command not sent.");
        return false;
    }
    memcpy(c->tx + c->tx_len, payload, n);
    c->tx_len += n;
    c->tx[c->tx_len++] = '\r';
    c->tx[c->tx_len++] = '\n';
    return true;
}

static bool irc_send(Client *c, const char *fmt, ...)
{
    char buf[IRC_PAYLOAD_MAX + 1];
    va_list args;
    int n;
    bool queued;
    va_start(args, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n < 0 || (size_t)n > IRC_PAYLOAD_MAX) {
        wipe_secret(buf, sizeof(buf));
        ui_printf(c, "*** Command too long; nothing sent.");
        return false;
    }
    queued = queue_payload(c, buf, (size_t)n);
    wipe_secret(buf, sizeof(buf));
    return queued;
}

static size_t utf8_chunk(const char *s, size_t length, size_t maximum)
{
    size_t n = length < maximum ? length : maximum;
    if (n < length)
        while (n && ((unsigned char)s[n] & 0xc0) == 0x80) n--;
    return n;
}

static bool send_text(Client *c, const char *verb, const char *target,
                      const char *text, bool action)
{
    char prefix[TARGET_NAME_CAP + 32], wire[IRC_PAYLOAD_MAX + 1];
    size_t p, suffix = action ? 1u : 0u, left, n, needed = 0, remaining;
    const char *scan;
    bool sent = false;
    int result;
    if (!valid_atom(target, TARGET_NAME_CAP) || !valid_text(text)) {
        ui_printf(c, "*** Invalid target or text (control characters/invalid UTF-8).");
        return false;
    }
    result = snprintf(prefix, sizeof(prefix), "%s %s :%s", verb, target,
                      action ? "\001ACTION " : "");
    if (result < 0 || (size_t)result >= sizeof(prefix)) return false;
    p = (size_t)result;
    if (p + suffix >= IRC_PAYLOAD_MAX) {
        ui_printf(c, "*** Target too long for a message.");
        return false;
    }
    left = strlen(text);
    scan = text;
    remaining = left;
    do {
        n = utf8_chunk(scan, remaining, IRC_PAYLOAD_MAX - p - suffix);
        if (remaining && !n) { ui_printf(c, "*** UTF-8 character does not fit in an IRC line."); return false; }
        needed += p + n + suffix + 2;
        scan += n;
        remaining -= n;
    } while (remaining);
    if (needed > queue_free(c)) {
        ui_printf(c, "*** Outgoing queue full; message not sent."); return false;
    }
    do {
        n = utf8_chunk(text, left, IRC_PAYLOAD_MAX - p - suffix);
        memcpy(wire, prefix, p);
        memcpy(wire + p, text, n);
        if (suffix) wire[p + n] = '\001';
        if (!queue_payload(c, wire, p + n + suffix)) {
            wipe_secret(wire, sizeof(wire));
            return false;
        }
        text += n;
        left -= n;
        sent = true;
    } while (left);
    wipe_secret(wire, sizeof(wire));
    return sent;
}

static bool send_hex(Client *c, const char *target, const char *text)
{
    char prefix[TARGET_NAME_CAP + 32], wire[IRC_PAYLOAD_MAX + 1];
    static const char hex[] = "0123456789abcdef";
    size_t p, left, n, i, needed = 0, remaining;
    const char *scan;
    int result;
    if (!valid_atom(target, TARGET_NAME_CAP) || !valid_text(text)) {
        ui_printf(c, "*** Invalid hexadecimal message."); return false;
    }
    result = snprintf(prefix, sizeof(prefix), "PRIVMSG %s :@", target);
    if (result < 0 || (size_t)result >= sizeof(prefix)) return false;
    p = (size_t)result;
    left = strlen(text);
    if (p + 2 > IRC_PAYLOAD_MAX) return false;
    scan = text;
    remaining = left;
    do {
        n = utf8_chunk(scan, remaining, (IRC_PAYLOAD_MAX - p) / 2);
        if (remaining && !n) { ui_printf(c, "*** UTF-8 character does not fit in hex encoding."); return false; }
        needed += p + 2 * n + 2;
        scan += n;
        remaining -= n;
    } while (remaining);
    if (needed > queue_free(c)) {
        ui_printf(c, "*** Outgoing queue full; hex message not sent."); return false;
    }
    do {
        n = utf8_chunk(text, left, (IRC_PAYLOAD_MAX - p) / 2);
        if (left && !n) { ui_printf(c, "*** UTF-8 character does not fit in hex encoding."); return false; }
        memcpy(wire, prefix, p);
        for (i = 0; i < n; i++) {
            unsigned char b = (unsigned char)text[i];
            wire[p + 2 * i] = hex[b >> 4];
            wire[p + 2 * i + 1] = hex[b & 15];
        }
        if (!queue_payload(c, wire, p + 2 * n)) return false;
        text += n;
        left -= n;
    } while (left);
    return true;
}

static int hex_value(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    ch = ascii_lower(ch);
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

/* Only complete @hex pairs are decoded; binary bytes are escaped by safe_write. */
static bool decode_hex(const char *s, char *out, size_t cap, size_t *out_len)
{
    size_t i, n = strlen(s);
    int a, b;
    if (n % 2 || n / 2 > cap) return false;
    for (i = 0; i < n; i += 2) {
        a = hex_value((unsigned char)s[i]);
        b = hex_value((unsigned char)s[i + 1]);
        if (a < 0 || b < 0) return false;
        out[i / 2] = (char)(a * 16 + b);
    }
    *out_len = n / 2;
    return true;
}

static bool parse_irc(char *line, IrcMessage *m)
{
    char *p = line, *space;
    memset(m, 0, sizeof(*m));
    if (*p == '@') {                    /* IRCv3 tags: ignored, not displayed */
        space = strchr(p, ' ');
        if (!space) return false;
        p = space + 1;
    }
    while (*p == ' ') p++;
    if (*p == ':') {
        m->prefix = ++p;
        space = strchr(p, ' ');
        if (!space) return false;
        *space = '\0';
        p = space + 1;
    }
    while (*p == ' ') p++;
    if (!*p) return false;
    m->command = p;
    while (*p && *p != ' ') p++;
    if (*p) *p++ = '\0';
    while (*p && m->count < 15) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == ':') { m->param[m->count++] = p + 1; break; }
        m->param[m->count++] = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
    }
    return true;
}

static const char *param(const IrcMessage *m, size_t i)
{
    return i < m->count ? m->param[i] : "";
}

static void actor_name(const IrcMessage *m, char *out, size_t cap)
{
    const char *p = m->prefix ? m->prefix : "server";
    size_t n = strcspn(p, "!@");
    if (n >= cap) n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
}

/* Match a reply only to a probe on this connection; a PONG is not a user's RTT. */
static PingProbe *free_ping(Client *c)
{
    for (size_t i = 0; i < PING_LIMIT; i++)
        if (!c->pings[i].active) return &c->pings[i];
    return NULL;
}

static void finish_ping(Client *c, PingProbe *p)
{
    uint64_t now = clock_ms();
    uint64_t elapsed = now >= p->started ? now - p->started : 0;
    ui_printf(c, "*** %s PING %s: %llu ms", p->peer ? "CTCP" : "Server",
              p->target, (unsigned long long)elapsed);
    memset(p, 0, sizeof(*p));
}

static bool ping_pong(Client *c, const IrcMessage *m)
{
    if (m->prefix && strchr(m->prefix, '!')) return false; /* not a server */
    for (size_t i = 0; i < PING_LIMIT; i++) {
        PingProbe *p = &c->pings[i];
        if (!p->active || p->peer) continue;
        for (size_t j = 0; j < m->count; j++)
            if (strcmp(param(m, j), p->token) == 0) {
                finish_ping(c, p);
                return true;
            }
    }
    return false;
}

static bool ping_notice(Client *c, const char *actor, const char *to,
                        const char *ctcp)
{
    if (!irc_equal(c, to, c->nick) || strncmp(ctcp, "PING ", 5) != 0)
        return false;
    for (size_t i = 0; i < PING_LIMIT; i++) {
        PingProbe *p = &c->pings[i];
        if (p->active && p->peer && irc_equal(c, actor, p->target) &&
            strcmp(ctcp + 5, p->token) == 0) {
            finish_ping(c, p);
            return true;
        }
    }
    return false;
}

static void expire_pings(Client *c, uint64_t now)
{
    for (size_t i = 0; i < PING_LIMIT; i++) {
        PingProbe *p = &c->pings[i];
        if (p->active && now >= p->started && now - p->started >= PING_WAIT_MS) {
            ui_printf(c, "*** %s PING %s: no reply (30 s); RTT unavailable.",
                      p->peer ? "CTCP" : "Server", p->target);
            memset(p, 0, sizeof(*p));
        }
    }
}

static void show_generic(Client *c, const IrcMessage *m)
{
    char line[RX_CAP + 256];
    size_t i, used = 0;
    int n = snprintf(line, sizeof(line), "*** %s", m->command);
    if (n < 0) return;
    used = (size_t)n;
    for (i = 0; i < m->count && used < sizeof(line) - 1; i++) {
        n = snprintf(line + used, sizeof(line) - used, " %s", param(m, i));
        if (n < 0) break;
        if ((size_t)n >= sizeof(line) - used) { used = sizeof(line) - 1; break; }
        used += (size_t)n;
    }
    if (m->prefix && used < sizeof(line) - 1) {
        n = snprintf(line + used, sizeof(line) - used, " [%s]", m->prefix);
        if (n > 0 && (size_t)n < sizeof(line) - used) used += (size_t)n;
    }
    ui_bytes(c, "", line, used);
}

static void show_chat(Client *c, const char *head, const char *text)
{
    char decoded[RX_CAP];
    size_t length;
    if (text[0] == '@' && decode_hex(text + 1, decoded, sizeof(decoded), &length))
        ui_bytes(c, head, decoded, length);
    else
        ui_bytes(c, head, text, strlen(text));
}

static void handle_chat(Client *c, const IrcMessage *m, bool notice)
{
    char actor[256], head[512];
    const char *to = param(m, 0), *text = param(m, 1);
    size_t n = strlen(text);
    actor_name(m, actor, sizeof(actor));
    if (!notice && !channel_name(to) && !irc_equal(c, actor, c->nick) &&
        valid_atom(actor, TARGET_NAME_CAP))
        (void)add_target(c, actor, false);
    if (n >= 2 && text[0] == '\001' && text[n - 1] == '\001') {
        char ctcp[RX_CAP];
        size_t inner = n - 2;
        memcpy(ctcp, text + 1, inner);
        ctcp[inner] = '\0';
        if (notice && ping_notice(c, actor, to, ctcp)) return;
        if (!notice && inner >= 7 && strncmp(ctcp, "ACTION ", 7) == 0) {
            (void)snprintf(head, sizeof(head), "* %s ", actor);
            show_chat(c, head, ctcp + 7);
            return;
        }
        if (!notice && valid_nick(actor) && !irc_equal(c, actor, c->nick)) {
            if (strcmp(ctcp, "VERSION") == 0) {
                (void)irc_send(c, "NOTICE %s :\001VERSION %s\001", actor, RELEASE);
            } else if ((strcmp(ctcp, "PING") == 0 ||
                        (strncmp(ctcp, "PING ", 5) == 0 && valid_text(ctcp + 5))) &&
                       inner + strlen(actor) + 10 <= IRC_PAYLOAD_MAX) {
                (void)irc_send(c, "NOTICE %s :\001%s\001", actor, ctcp);
            }
        }
        (void)snprintf(head, sizeof(head), "*** CTCP %s from %s: ",
                       notice ? "reply" : "request", actor);
        show_chat(c, head, ctcp);
        return;
    }
    if (notice && channel_name(to))
        (void)snprintf(head, sizeof(head), "-%s:%s- ", actor, to);
    else if (notice)
        (void)snprintf(head, sizeof(head), "-%s- ", actor);
    else if (channel_name(to) && c->current && irc_equal(c, c->current->name, to))
        (void)snprintf(head, sizeof(head), "<%s> ", actor);
    else if (channel_name(to))
        (void)snprintf(head, sizeof(head), "<%s:%s> ", actor, to);
    else
        (void)snprintf(head, sizeof(head), "*%s* ", actor);
    show_chat(c, head, text);
}

/* 470 means the server is joining a different channel than the one we asked
 * for. Move the pending target instead of leaving a phantom JOIN behind. */
static void track_channel_forward(Client *c, const IrcMessage *m)
{
    const char *from = param(m, 1), *to = param(m, 2);
    Target *source, *destination;
    if (m->count < 3 || !channel_name(from) || !channel_name(to) ||
        !valid_atom(to, TARGET_NAME_CAP)) return;
    source = find_target(c, from);
    if (!source || !source->wanted || source->joined) return;
    destination = find_target(c, to);
    if (destination && destination != source) {
        destination->wanted = true;
        if (c->current == source) set_current_target(c, destination);
        remove_target(c, source->name);
    } else {
        /* A key for the old channel must not be reused on the destination. */
        if (!irc_equal(c, from, to)) wipe_secret(source->key, sizeof(source->key));
        if (c->current == source) discard_masked_edit(c);
        (void)copy_string(source->name, sizeof(source->name), to);
        source->modes[0] = '\0';
        draw_prompt(c);
    }
    ui_printf(c, "*** Following channel forward: %s -> %s", from, to);
}

static void handle_numeric(Client *c, const IrcMessage *m)
{
    if (strcmp(m->command, "001") == 0) {
        Target *t;
        if (valid_nick(param(m, 0)))
            (void)copy_string(c->nick, sizeof(c->nick), param(m, 0));
        c->registered = true;
        c->backoff = 1000;
        for (t = c->targets; t; t = t->next)
            if (channel_name(t->name) && t->wanted)
                (void)irc_send(c, "JOIN %s%s%s", t->name,
                               t->key[0] ? " " : "", t->key);
    } else if (strcmp(m->command, "005") == 0) {
        size_t i;
        for (i = 1; i < m->count; i++) {
            const char *p = param(m, i);
            if (strncmp(p, "CASEMAPPING=", 12) == 0) {
                p += 12;
                if (ascii_equal(p, "ascii")) c->casemap = CASE_ASCII;
                else if (ascii_equal(p, "strict-rfc1459")) c->casemap = CASE_STRICT_RFC1459;
                else if (ascii_equal(p, "rfc1459")) c->casemap = CASE_RFC1459;
            }
        }
    } else if (strcmp(m->command, "324") == 0 && m->count >= 3) {
        Target *t = find_target(c, param(m, 1));
        if (t) (void)snprintf(t->modes, sizeof(t->modes), "%s", param(m, 2));
    } else if (strcmp(m->command, "470") == 0) {
        track_channel_forward(c, m);
    } else if (strcmp(m->command, "432") == 0) {
        ui_printf(c, "*** Invalid nickname. Use /nick NEW_NICK.");
    }
    /* For 433, show the server's actual explanation without assuming that
     * this network supports the IRC-Hispano nick:password extension. */
    show_generic(c, m);
}

static void handle_server_line(Client *c, char *raw)
{
    IrcMessage m;
    char actor[256];
    const char *chan, *victim;
    Target *t;
    if (!parse_irc(raw, &m)) return;
    actor_name(&m, actor, sizeof(actor));
    if (strlen(m.command) == 3 &&
        isdigit((unsigned char)m.command[0]) &&
        isdigit((unsigned char)m.command[1]) &&
        isdigit((unsigned char)m.command[2])) {
        handle_numeric(c, &m);
        return;
    }
    if (ascii_equal(m.command, "PING")) {
        if (m.count >= 2)
            (void)irc_send(c, "PONG %s :%s", param(&m, 0), param(&m, 1));
        else if (m.count) (void)irc_send(c, "PONG :%s", param(&m, 0));
        return;
    }
    if (ascii_equal(m.command, "PONG") && ping_pong(c, &m)) return;
    if (ascii_equal(m.command, "PRIVMSG") || ascii_equal(m.command, "NOTICE")) {
        if (m.count >= 2)
            handle_chat(c, &m, ascii_equal(m.command, "NOTICE"));
        return;
    }
    if (ascii_equal(m.command, "JOIN") && m.count >= 1) {
        chan = param(&m, 0);
        if (irc_equal(c, actor, c->nick) && channel_name(chan)) {
            t = add_target(c, chan, true);
            if (t) { t->wanted = t->joined = true; (void)irc_send(c, "MODE %s", chan); }
            ui_printf(c, "*** Now talking in %s", chan);
        } else ui_printf(c, "*** %s joined %s", actor, chan);
        return;
    }
    if (ascii_equal(m.command, "PART") && m.count >= 1) {
        chan = param(&m, 0);
        ui_printf(c, "*** %s left %s %s", actor, chan, param(&m, 1));
        if (irc_equal(c, actor, c->nick)) remove_target(c, chan);
        return;
    }
    if (ascii_equal(m.command, "KICK") && m.count >= 2) {
        chan = param(&m, 0);
        victim = param(&m, 1);
        ui_printf(c, "*** %s kicked %s from %s: %s", actor, victim,
                  chan, param(&m, 2));
        if (irc_equal(c, victim, c->nick)) remove_target(c, chan);
        return;
    }
    if (ascii_equal(m.command, "NICK") && m.count >= 1) {
        ui_printf(c, "*** %s is now known as %s", actor, param(&m, 0));
        if (irc_equal(c, actor, c->nick) && valid_nick(param(&m, 0))) {
            (void)copy_string(c->nick, sizeof(c->nick), param(&m, 0));
            draw_prompt(c);
        }
        return;
    }
    if (ascii_equal(m.command, "MODE") && m.count >= 2) {
        if ((t = find_target(c, param(&m, 0))) != NULL)
            (void)snprintf(t->modes, sizeof(t->modes), "%s", param(&m, 1));
        ui_printf(c, "*** %s changed mode of %s: %s %s", actor,
                  param(&m, 0), param(&m, 1), param(&m, 2));
        return;
    }
    if (ascii_equal(m.command, "TOPIC") && m.count >= 2) {
        ui_printf(c, "*** %s set the topic of %s: %s", actor,
                  param(&m, 0), param(&m, 1));
        return;
    }
    if (ascii_equal(m.command, "QUIT")) {
        ui_printf(c, "*** %s quit: %s", actor, param(&m, 0));
        return;
    }
    if (ascii_equal(m.command, "INVITE") && m.count >= 2) {
        ui_printf(c, "*** %s invites you to %s", actor, param(&m, 1));
        return;
    }
    if (ascii_equal(m.command, "KILL") && m.count >= 1) {
        ui_printf(c, "*** KILL from %s for %s: %s", actor,
                  param(&m, 0), param(&m, 1));
        if (irc_equal(c, param(&m, 0), c->nick)) {
            c->quitting = true;      /* do not hammer a network after a KILL */
            socket_lost(c, "KILL");
        }
        return;
    }
    if (ascii_equal(m.command, "ERROR")) {
        ui_printf(c, "*** ERROR: %s", param(&m, 0));
        socket_lost(c, "server closed the connection");
        return;
    }
    show_generic(c, &m);
}

static void feed_socket(Client *c, const char *bytes, size_t n)
{
    size_t i, length;
    for (i = 0; i < n && c->fd >= 0; i++) {
        unsigned char b = (unsigned char)bytes[i];
        if (b == '\n') {
            if (c->rx_drop) {
                ui_printf(c, "*** Incoming line too long or contains NUL; discarded.");
            } else {
                length = c->rx_len;
                if (length && c->rx[length - 1] == '\r') length--;
                c->rx[length] = '\0';
                if (length) handle_server_line(c, c->rx);
            }
            c->rx_len = 0;
            c->rx_drop = false;
        } else if (!b) {
            c->rx_drop = true;
        } else if (!c->rx_drop) {
            if (c->rx_len < RX_CAP)
                c->rx[c->rx_len++] = (char)b;
            else c->rx_drop = true;
        }
    }
}

static void socket_lost(Client *c, const char *why)
{
    Target *t;
    if (c->fd < 0) return;
#ifdef TINYIRC_USE_OPENSSL
    if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
    c->tls_ready = false;
    c->ssl_retry_len = 0;
#endif
    (void)close(c->fd);
    c->fd = -1;
    c->registered = false;
    memset(c->pings, 0, sizeof(c->pings));
    if (c->tx_len) wipe_secret(c->tx, c->tx_len);
    c->rx_len = c->tx_len = c->tx_off = 0;
    c->rx_drop = false;
    for (t = c->targets; t; t = t->next) {
        t->joined = false;
        t->modes[0] = '\0';
    }
    if (!c->quitting) {
        c->next_retry = clock_ms() + c->backoff;
        ui_printf(c, "*** Disconnected (%s). Retrying in %" PRIu64 " s.",
                  why, (uint64_t)(c->backoff / 1000));
        if (c->backoff < 30000) {
            c->backoff *= 2;
            if (c->backoff > 30000) c->backoff = 30000;
        }
    }
}

static bool set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static void register_client(Client *c)
{
    (void)irc_send(c, "NICK %s", c->nick);
    (void)irc_send(c, "USER %s 0 * :%s", c->username, c->realname);
}

#ifdef TINYIRC_USE_OPENSSL
static void tls_failure(Client *c, const char *operation)
{
    char message[256];
    unsigned long code = ERR_get_error();
    long verification = c->ssl ? SSL_get_verify_result(c->ssl) : X509_V_OK;
    if (verification != X509_V_OK)
        (void)snprintf(message, sizeof(message), "TLS %s: %s", operation,
                       X509_verify_cert_error_string(verification));
    else if (code) {
        char detail[160];
        ERR_error_string_n(code, detail, sizeof(detail));
        (void)snprintf(message, sizeof(message), "TLS %s: %s", operation, detail);
    } else (void)snprintf(message, sizeof(message), "TLS %s: connection closed", operation);
    socket_lost(c, message);
}

static bool tls_start(Client *c)
{
    struct in_addr v4;
    struct in6_addr v6;
    bool ip = inet_pton(AF_INET, c->host, &v4) == 1 ||
              inet_pton(AF_INET6, c->host, &v6) == 1;
    X509_VERIFY_PARAM *verify;
    c->ssl = SSL_new(c->ssl_ctx);
    if (!c->ssl) return false;
    verify = SSL_get0_param(c->ssl);
    if (SSL_set_fd(c->ssl, c->fd) != 1 ||
        (ip ? X509_VERIFY_PARAM_set1_ip_asc(verify, c->host) != 1 :
              (SSL_set_tlsext_host_name(c->ssl, c->host) != 1 ||
               SSL_set1_host(c->ssl, c->host) != 1)))
        return false;
    c->handshake_want = POLLIN | POLLOUT;
    c->read_want = POLLIN;
    c->write_want = POLLOUT;
    return true;
}

static void tls_handshake(Client *c)
{
    int result = SSL_connect(c->ssl), error;
    if (result == 1) {
        X509 *peer = SSL_get_peer_certificate(c->ssl);
        if (!peer || SSL_get_verify_result(c->ssl) != X509_V_OK) {
            if (peer) X509_free(peer);
            tls_failure(c, "certificate verification");
            return;
        }
        X509_free(peer);
        c->tls_ready = true;
        c->handshake_want = 0;
        ui_printf(c, "*** TLS certificate verified for %s", c->host);
        register_client(c);
        return;
    }
    error = SSL_get_error(c->ssl, result);
    if (error == SSL_ERROR_WANT_READ) c->handshake_want = POLLIN;
    else if (error == SSL_ERROR_WANT_WRITE) c->handshake_want = POLLOUT;
    else tls_failure(c, "handshake");
}
#endif

static bool connect_host(Client *c)
{
    struct addrinfo hints, *list = NULL, *a;
    int gai, fd = -1, err, last_error = 0;
    socklen_t errlen;
    uint64_t deadline, now;
    struct pollfd pfd;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    ui_printf(c, "*** Connecting to %s:%s%s ...", c->host, c->port,
              c->tls_requested ? " (TLS)" : "");
    gai = getaddrinfo(c->host, c->port, &hints, &list);
    if (gai != 0) { ui_printf(c, "*** DNS: %s", gai_strerror(gai)); return false; }
    for (a = list; a && !stop_signal; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) { last_error = errno; continue; }
        if (!set_nonblocking(fd)) { last_error = errno; (void)close(fd); fd = -1; continue; }
#ifdef SO_NOSIGPIPE
        {
            int yes = 1;
            (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
        }
#endif
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        if (errno == EINPROGRESS) {
            deadline = clock_ms() + CONNECT_TIMEOUT_MS;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            while (!stop_signal) {
                now = clock_ms();
                if (now >= deadline) { last_error = ETIMEDOUT; break; }
                pfd.revents = 0;
                err = poll(&pfd, 1, (int)(deadline - now));
                if (err < 0 && errno == EINTR) continue;
                if (err <= 0) { last_error = err == 0 ? ETIMEDOUT : errno; break; }
                errlen = (socklen_t)sizeof(last_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &last_error, &errlen) == 0 &&
                    last_error == 0) goto connected;
                if (!last_error) last_error = errno;
                break;
            }
        } else last_error = errno;
        (void)close(fd);
        fd = -1;
    }
connected:
    freeaddrinfo(list);
    if (fd < 0 || stop_signal) {
        if (fd >= 0) (void)close(fd);
        ui_printf(c, "*** Connection failed: %s", strerror(last_error ? last_error : EINTR));
        return false;
    }
    c->fd = fd;
    c->rx_len = c->tx_len = c->tx_off = 0;
    c->rx_drop = false;
#ifdef TINYIRC_USE_OPENSSL
    if (c->tls_requested) {
        if (!tls_start(c)) {
            tls_failure(c, "initialization");
            return false;
        }
        tls_handshake(c);
        return c->fd >= 0;
    }
#endif
    register_client(c);
    return true;
}

static void plain_read(Client *c)
{
    char data[4096];
    ssize_t n;
    do {
        n = recv(c->fd, data, sizeof(data), 0);
        if (n > 0) feed_socket(c, data, (size_t)n);
        else if (n == 0) { socket_lost(c, "connection closed"); return; }
        else if (errno == EINTR) continue;
        else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            socket_lost(c, strerror(errno)); return;
        }
    } while (n > 0 && c->fd >= 0);
}

static void flush_output(Client *c)
{
    ssize_t n;
    while (c->fd >= 0 && c->tx_off < c->tx_len) {
#ifdef TINYIRC_USE_OPENSSL
        if (c->tls_requested) {
            size_t len = c->ssl_retry_len ? c->ssl_retry_len : c->tx_len - c->tx_off;
            int result = SSL_write(c->ssl, c->tx + c->tx_off, (int)len);
            int err;
            if (result > 0) {
                c->tx_off += (size_t)result;
                c->ssl_retry_len = 0;
                c->write_want = POLLOUT;
                continue;
            }
            err = SSL_get_error(c->ssl, result);
            if (err == SSL_ERROR_WANT_READ) c->write_want = POLLIN;
            else if (err == SSL_ERROR_WANT_WRITE) c->write_want = POLLOUT;
            else tls_failure(c, "write");
            return;
        }
#endif
        n = send(c->fd, c->tx + c->tx_off, c->tx_len - c->tx_off, 0);
        if (n > 0) c->tx_off += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        else { socket_lost(c, n < 0 ? strerror(errno) : "send returned zero"); return; }
    }
    if (c->tx_off == c->tx_len) {
        if (c->tx_len) wipe_secret(c->tx, c->tx_len);
        c->tx_off = c->tx_len = 0;
    }
}

#ifdef TINYIRC_USE_OPENSSL
static void tls_read(Client *c)
{
    char data[4096];
    int n, error;
    while (c->fd >= 0) {
        n = SSL_read(c->ssl, data, (int)sizeof(data));
        if (n > 0) {
            c->read_want = POLLIN;
            feed_socket(c, data, (size_t)n);
            continue;
        }
        error = SSL_get_error(c->ssl, n);
        if (error == SSL_ERROR_WANT_READ) c->read_want = POLLIN;
        else if (error == SSL_ERROR_WANT_WRITE) c->read_want = POLLOUT;
        else if (error == SSL_ERROR_ZERO_RETURN) socket_lost(c, "TLS connection closed");
        else tls_failure(c, "read");
        return;
    }
}
#endif

static void socket_event(Client *c, short events)
{
#ifdef TINYIRC_USE_OPENSSL
    if (c->tls_requested && !c->tls_ready) {
        if (events & c->handshake_want) tls_handshake(c);
        if (c->fd < 0 || !c->tls_ready) return;
    }
    if (c->tls_requested) {
        if ((events & c->read_want) || SSL_pending(c->ssl)) tls_read(c);
        if (c->fd >= 0 && c->tx_off < c->tx_len && (events & c->write_want))
            flush_output(c);
    } else
#endif
    {
        if (events & (POLLIN | POLLHUP)) plain_read(c);
        if (c->fd >= 0 && (events & POLLOUT)) flush_output(c);
    }
    if (c->fd >= 0 && (events & (POLLERR | POLLHUP | POLLNVAL)))
        socket_lost(c, "socket error");
}

static char *skip_spaces(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

static char *take_word(char **rest)
{
    char *word = skip_spaces(*rest), *end = word;
    while (*end && *end != ' ' && *end != '\t') end++;
    if (*end) *end++ = '\0';
    *rest = skip_spaces(end);
    return word;
}

static void command_ping(Client *c, char *args)
{
    char *name = take_word(&args);
    /* A hostname selects the server probe; only the connected server is timed. */
    bool server = !*name || ascii_equal(name, "server") ||
                  irc_equal(c, name, c->host) || strchr(name, '.') != NULL;
    PingProbe *p;
    uint64_t now;
    int n;
    if (*args || (server && *name && !valid_atom(name, sizeof(c->host))) ||
        (!server && !valid_nick(name))) {
        ui_printf(c, "*** Usage: /ping [server|server.hostname|nick]");
        return;
    }
    if (c->fd < 0) { ui_printf(c, "*** Not connected."); return; }
    p = free_ping(c);
    if (!p) { ui_printf(c, "*** Too many pending pings (maximum 8)."); return; }
    now = clock_ms();
    n = snprintf(p->token, sizeof(p->token), "tinyirc-%llu-%llu",
                 (unsigned long long)now, (unsigned long long)++c->ping_serial);
    if (n < 0 || (size_t)n >= sizeof(p->token)) return;
    if (!(server ? irc_send(c, "PING :%s", p->token) :
                   irc_send(c, "PRIVMSG %s :\001PING %s\001", name, p->token)))
        return;
    (void)copy_string(p->target, sizeof(p->target), server ? c->host : name);
    p->started = now;
    p->peer = !server;
    p->active = true;
    ui_printf(c, "*** %s PING sent to %s; waiting for reply.",
              server ? "Server" : "CTCP", p->target);
}

static void request_quit(Client *c, const char *reason)
{
    if (c->quitting) return;
    if (!valid_text(reason)) { ui_printf(c, "*** Invalid quit reason."); return; }
#ifdef TINYIRC_USE_OPENSSL
    if (c->fd >= 0 && (!c->tls_requested || c->tls_ready) &&
        !irc_send(c, "QUIT :%s", *reason ? reason : RELEASE)) return;
#else
    if (c->fd >= 0 && !irc_send(c, "QUIT :%s", *reason ? reason : RELEASE)) return;
#endif
    c->quitting = true;
    c->quit_deadline = clock_ms() + 3000;
    ui_printf(c, "*** Quitting...");
}

static void command_join(Client *c, char *args)
{
    Target *t;
    char *name = take_word(&args), *key = take_word(&args);
    if (!*name || *args || (channel_name(name) && *key &&
        !valid_atom(key, TARGET_NAME_CAP))) {
        ui_printf(c, "*** Usage: /join #channel [key]  or  /join nick");
        return;
    }
    if (!channel_name(name) && *key) {
        ui_printf(c, "*** /join nick does not accept a key."); return;
    }
    t = add_target(c, name, true);
    if (!t) return;
    if (channel_name(name)) {
        if (*key) {
            memset(t->key, 0, sizeof(t->key));
            (void)copy_string(t->key, sizeof(t->key), key);
        }
        t->wanted = true;
        if (c->registered && !t->joined)
            (void)irc_send(c, "JOIN %s%s%s", t->name, t->key[0] ? " " : "", t->key);
        ui_printf(c, "*** %s%s", t->name,
                  c->registered ? " (JOIN requested)" : " (JOIN after connecting)");
    } else ui_printf(c, "*** Now talking to %s", t->name);
}

static void command_part(Client *c, char *args)
{
    Target *t;
    char current_name[TARGET_NAME_CAP];
    char *name = take_word(&args);
    if (!*name) {
        if (!c->current) { ui_printf(c, "*** Usage: /part [#channel] [reason]"); return; }
        (void)copy_string(current_name, sizeof(current_name), c->current->name);
        name = current_name;
    }
    if (!valid_atom(name, TARGET_NAME_CAP) || !valid_text(args)) {
        ui_printf(c, "*** Invalid target or reason."); return;
    }
    t = find_target(c, name);
    if (!channel_name(name)) {
        if (t) { remove_target(c, name); ui_printf(c, "*** Closed: %s", name); }
        else ui_printf(c, "*** No such private target.");
        return;
    }
    if (!c->registered || (t && !t->joined)) {
        if (t) remove_target(c, name);
        ui_printf(c, "*** Pending JOIN cancelled for %s", name);
        return;
    }
    if (*args ? irc_send(c, "PART %s :%s", name, args) :
                irc_send(c, "PART %s", name)) {
        if (t) t->wanted = false;
        ui_printf(c, "*** Leaving %s...", name);
    }
}

static bool send_nickserv_identify(Client *c, const char *verb,
                                   const char *target, const char *text)
{
    if (!c->registered) {
        ui_printf(c, "*** Wait for server registration before identifying with NickServ.");
        return false;
    }
    /* Never split a credential into multiple IRC messages. */
    if (strlen(verb) + 1 + strlen(target) + 2 + strlen(text) > IRC_PAYLOAD_MAX) {
        ui_printf(c, "*** NickServ IDENTIFY too long; nothing sent.");
        return false;
    }
    if (!send_text(c, verb, target, text, false)) return false;
    if (!channel_name(target)) (void)add_target(c, target, false);
    if (!c->tls_requested)
        ui_printf(c, "*** Warning: NickServ identification queued over unencrypted IRC.");
    ui_printf(c, "*** NickServ identification message sent (arguments hidden).");
    return true;
}

static void command_message(Client *c, char *args, const char *verb, bool identify)
{
    char *target = take_word(&args);
    if (!*target || !*args) {
        ui_printf(c, "*** Usage: /%s target message", ascii_equal(verb, "NOTICE") ? "notice" : "msg");
        return;
    }
    if (identify) { (void)send_nickserv_identify(c, verb, target, args); return; }
    if (send_text(c, verb, target, args, false)) {
        if (!channel_name(target)) (void)add_target(c, target, false);
        ui_printf(c, "-> %s: %s", target, args);
    }
}

static void command_topic(Client *c, char *args)
{
    char *channel = take_word(&args);
    if (!*channel && c->current && channel_name(c->current->name))
        channel = c->current->name;
    if (!channel_name(channel) || !valid_atom(channel, TARGET_NAME_CAP) ||
        !valid_text(args)) {
        ui_printf(c, "*** Usage: /topic #channel [new topic]"); return;
    }
    if (*args) (void)irc_send(c, "TOPIC %s :%s", channel, args);
    else (void)irc_send(c, "TOPIC %s", channel);
}

static void command_kick(Client *c, char *args)
{
    char *channel = take_word(&args), *nick = take_word(&args);
    if (!channel_name(channel) || !valid_atom(channel, TARGET_NAME_CAP) ||
        !valid_nick(nick) || !valid_text(args)) {
        ui_printf(c, "*** Usage: /kick #channel nick [reason]"); return;
    }
    if (*args) (void)irc_send(c, "KICK %s %s :%s", channel, nick, args);
    else (void)irc_send(c, "KICK %s %s", channel, nick);
}

static void print_help(Client *c)
{
    ui_printf(c, "*** /join #channel [key] | /join nick | /part [target] [reason]");
    ui_printf(c, "*** /msg nick text | /notice nick text | /me action | /nick nick[:password]");
    ui_printf(c, "*** NickServ: /msg NickServ IDENTIFY [nick] password; in its target: IDENTIFY ...");
    ui_printf(c, "*** Identification arguments are masked and skipped in history; use TLS.");
    ui_printf(c, "*** /nick nick:password is network-specific; use TLS for passwords.");
    ui_printf(c, "*** /topic #channel [topic] | /kick #channel nick [reason]");
    ui_printf(c, "*** /switch [target|*] | /targets | /away [reason] | /quit [reason]");
    ui_printf(c, "*** /ping [server|server.hostname|nick]: server PONG or user CTCP RTT (ms)");
    ui_printf(c, "*** /raw COMMAND ...; other /COMMAND ... are sent as-is.");
    ui_printf(c, "*** @text sends hex; #hex displays decoded text.");
    ui_printf(c, "*** Ctrl-A/E/B/F/D/H, arrows, Ctrl-P/N, Ctrl-W/ESC, Ctrl-L/Z.");
}

static void process_input(Client *c, char *line)
{
    char *p, *args, *word;
    char cmd[32], decoded[INPUT_CAP];
    size_t n, i, length;
    if (!*line) return;
    if (c->secret_edit != SECRET_NONE &&
        secret_start_for_kind(c->secret_edit, line, strlen(line)) == SIZE_MAX) {
        ui_printf(c, "*** Protected identification input changed; nothing sent. Retype the command.");
        return;
    }
    if (line[0] == '#') {
        if (decode_hex(line + 1, decoded, sizeof(decoded), &length))
            ui_bytes(c, "*** Hex: ", decoded, length);
        else ui_printf(c, "*** Invalid hexadecimal string.");
        return;
    }
    if (line[0] == '@') {
        if (!c->current) { ui_printf(c, "*** No current target."); return; }
        if (send_hex(c, c->current->name, line + 1))
            ui_printf(c, "> %s (@hex)", line + 1);
        return;
    }
    if (line[0] != '/') {
        if (bare_identify_start(line, strlen(line)) != SIZE_MAX &&
            (c->secret_edit == SECRET_BARE_IDENTIFY || current_is_nickserv(c))) {
            if (!current_is_nickserv(c))
                ui_printf(c, "*** NickServ target changed; identification not sent.");
            else (void)send_nickserv_identify(c, "PRIVMSG", c->current->name, line);
            return;
        }
        if (!c->current) { ui_printf(c, "*** No current target; use /join or /msg."); return; }
        if (send_text(c, "PRIVMSG", c->current->name, line, false))
            ui_printf(c, "> %s", line);
        return;
    }
    p = line + 1;
    n = 0;
    while (p[n] && p[n] != ' ' && p[n] != '\t' && n < sizeof(cmd) - 1) {
        unsigned char b = (unsigned char)p[n];
        if (!((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
              (b >= '0' && b <= '9'))) {
            ui_printf(c, "*** Invalid command."); return;
        }
        cmd[n] = (char)(b >= 'a' && b <= 'z' ? b - ('a' - 'A') : b);
        n++;
    }
    if (!n || (p[n] && p[n] != ' ' && p[n] != '\t')) {
        ui_printf(c, "*** Empty or overlong command."); return;
    }
    cmd[n] = '\0';
    args = skip_spaces(p + n);
    if (strcmp(cmd, "HELP") == 0) print_help(c);
    else if (strcmp(cmd, "PING") == 0) command_ping(c, args);
    else if (strcmp(cmd, "JOIN") == 0) command_join(c, args);
    else if (strcmp(cmd, "PART") == 0) command_part(c, args);
    else if (strcmp(cmd, "MSG") == 0 || strcmp(cmd, "PRIVMSG") == 0)
        command_message(c, args, "PRIVMSG",
                        nickserv_identify_start(line, strlen(line)) != SIZE_MAX);
    else if (strcmp(cmd, "NOTICE") == 0)
        command_message(c, args, "NOTICE",
                        nickserv_identify_start(line, strlen(line)) != SIZE_MAX);
    else if (strcmp(cmd, "ME") == 0) {
        if (!c->current || !*args) ui_printf(c, "*** Usage: /me action (with an open target)");
        else if (send_text(c, "PRIVMSG", c->current->name, args, true))
            ui_printf(c, "* %s %s", c->nick, args);
    } else if (strcmp(cmd, "QUIT") == 0) request_quit(c, args);
    else if (strcmp(cmd, "NICK") == 0) {
        char *separator;
        bool with_password, sent;
        word = take_word(&args);
        separator = strchr(word, ':');
        with_password = separator != NULL;
        if (with_password) *separator = '\0';
        if (!valid_nick(word) || *args ||
            (with_password && (!separator[1] || !valid_text(separator + 1)))) {
            ui_printf(c, "*** Usage: /nick NICK[:PASSWORD]");
        } else if (c->fd < 0) {
            if (with_password)
                ui_printf(c, "*** Not connected; password not stored. Retry /nick after connecting.");
            else {
                (void)copy_string(c->nick, sizeof(c->nick), word);
                ui_printf(c, "*** Nick saved for the next connection: %s", word);
            }
        } else {
            if (with_password) *separator = ':'; /* only on the outgoing wire */
            sent = irc_send(c, "NICK %s", word);
            if (with_password) *separator = '\0';
            if (sent) {
                if (with_password && !c->tls_requested)
                    ui_printf(c, "*** Warning: nickname password queued over unencrypted IRC.");
                /* Wait for the server to confirm a password-protected nick. */
                if (!with_password && !c->registered)
                    (void)copy_string(c->nick, sizeof(c->nick), word);
                ui_printf(c, "*** Nick change requested: %s", word);
            }
        }
    } else if (strcmp(cmd, "TOPIC") == 0) command_topic(c, args);
    else if (strcmp(cmd, "KICK") == 0) command_kick(c, args);
    else if (strcmp(cmd, "SWITCH") == 0 || strcmp(cmd, "TARGET") == 0) {
        word = take_word(&args);
        if (*args) ui_printf(c, "*** Usage: /switch [target|*]");
        else if (!*word) cycle_target(c);
        else if (strcmp(word, "*") == 0) {
            set_current_target(c, NULL);
            ui_printf(c, "*** Current target: server");
        } else {
            Target *t = find_target(c, word);
            if (t) { set_current_target(c, t); ui_printf(c, "*** Current target: %s", t->name); }
            else ui_printf(c, "*** Unknown target.");
        }
    } else if (strcmp(cmd, "TARGETS") == 0) {
        Target *t;
        ui_printf(c, "*** %s * (server)", c->current ? " " : ">");
        for (t = c->targets; t; t = t->next)
            ui_printf(c, "*** %s %s%s", t == c->current ? ">" : " ", t->name,
                      t->wanted && !t->joined ? " (pending)" : "");
        if (!c->targets) ui_printf(c, "*** No open targets.");
    } else if (strcmp(cmd, "AWAY") == 0) {
        if (!valid_text(args)) ui_printf(c, "*** Invalid reason.");
        else if (*args) (void)irc_send(c, "AWAY :%s", args);
        else (void)irc_send(c, "AWAY");
    } else if (strcmp(cmd, "RAW") == 0 || strcmp(cmd, "QUOTE") == 0) {
        if (!*args) ui_printf(c, "*** Usage: /raw COMMAND parameters...");
        else if (queue_payload(c, args, strlen(args)))
            ui_printf(c, "*** Raw command sent (parameters hidden).");
    } else {
        /* IRC extensions remain usable, but no ambiguous legacy abbreviation. */
        if (!valid_text(args)) { ui_printf(c, "*** Invalid parameters."); return; }
        i = strlen(args);
        if (irc_send(c, "%s%s%s", cmd, i ? " " : "", args))
            ui_printf(c, "*** /%s sent (parameters hidden).", cmd);
    }
}

static void editor_set(Client *c, const char *text)
{
    reset_secret_edit(c);
    (void)copy_string(c->edit, sizeof(c->edit), text);
    c->edit_len = c->cursor = strlen(c->edit);
    draw_prompt(c);
}

static void history_up(Client *c)
{
    unsigned i;
    if (!c->hist_count) return;
    if (c->hist_nav < 0) {
        if (input_secret_start(c, c->edit, c->edit_len) != SIZE_MAX) {
            wipe_secret(c->draft, sizeof(c->draft));
            wipe_secret(c->edit, sizeof(c->edit));
        } else (void)copy_string(c->draft, sizeof(c->draft), c->edit);
    }
    if (c->hist_nav + 1 < (int)c->hist_count) c->hist_nav++;
    i = (c->hist_next + HISTORY_CAP - 1u - (unsigned)c->hist_nav) % HISTORY_CAP;
    editor_set(c, c->history[i]);
}

static void history_down(Client *c)
{
    unsigned i;
    if (c->hist_nav < 0) return;
    if (c->hist_nav == 0) { c->hist_nav = -1; editor_set(c, c->draft); return; }
    c->hist_nav--;
    i = (c->hist_next + HISTORY_CAP - 1u - (unsigned)c->hist_nav) % HISTORY_CAP;
    editor_set(c, c->history[i]);
}

static bool secret_suffix_empty_after_erasure(const Client *c)
{
    return c->secret_edit != SECRET_NONE && c->secret_had_arguments &&
           secret_start_for_kind(c->secret_edit, c->edit, c->edit_len) == c->edit_len;
}

static void editor_release_secret_if_safe(Client *c, bool empty_before)
{
    /* Only an edit made after *all* previously entered arguments were erased
     * may unlock an unrecognized prefix. Otherwise keep it masked/blocked. */
    if (!c->edit_len || (empty_before &&
        secret_start_for_kind(c->secret_edit, c->edit, c->edit_len) == SIZE_MAX))
        reset_secret_edit(c);
}

static void editor_insert(Client *c, char ch)
{
    bool empty_suffix = secret_suffix_empty_after_erasure(c);
    if (c->edit_len >= INPUT_CAP - 1) {
        c->input_drop = true;
        ui_printf(c, "*** Input too long; discarding until Enter is pressed.");
        return;
    }
    memmove(c->edit + c->cursor + 1, c->edit + c->cursor,
            c->edit_len - c->cursor + 1);
    c->edit[c->cursor++] = ch;
    c->edit_len++;
    editor_release_secret_if_safe(c, empty_suffix);
    c->hist_nav = -1;
    draw_prompt(c);
}

static void editor_backspace(Client *c)
{
    size_t start = previous_char(c->edit, c->cursor), old_len = c->edit_len;
    bool empty_suffix = secret_suffix_empty_after_erasure(c);
    if (start == c->cursor) return;
    memmove(c->edit + start, c->edit + c->cursor,
            c->edit_len - c->cursor + 1);
    c->edit_len -= c->cursor - start;
    c->cursor = start;
    wipe_secret(c->edit + c->edit_len + 1, old_len - c->edit_len);
    editor_release_secret_if_safe(c, empty_suffix);
    c->hist_nav = -1;
    draw_prompt(c);
}

static void editor_delete(Client *c)
{
    size_t end = next_char(c->edit, c->edit_len, c->cursor), old_len = c->edit_len;
    bool empty_suffix = secret_suffix_empty_after_erasure(c);
    if (end == c->cursor) return;
    memmove(c->edit + c->cursor, c->edit + end, c->edit_len - end + 1);
    c->edit_len -= end - c->cursor;
    wipe_secret(c->edit + c->edit_len + 1, old_len - c->edit_len);
    editor_release_secret_if_safe(c, empty_suffix);
    c->hist_nav = -1;
    draw_prompt(c);
}

static void editor_submit(Client *c)
{
    char line[INPUT_CAP];
    bool sensitive;
    if (!c->edit_len) return;
    sensitive = input_secret_start(c, c->edit, c->edit_len) != SIZE_MAX;
    (void)copy_string(line, sizeof(line), c->edit);
    if (!sensitive && (!c->hist_count ||
        strcmp(line, c->history[(c->hist_next + HISTORY_CAP - 1) % HISTORY_CAP]) != 0)) {
        (void)copy_string(c->history[c->hist_next], INPUT_CAP, line);
        c->hist_next = (c->hist_next + 1) % HISTORY_CAP;
        if (c->hist_count < HISTORY_CAP) c->hist_count++;
    }
    if (sensitive) {
        wipe_secret(c->edit, sizeof(c->edit));
        wipe_secret(c->draft, sizeof(c->draft));
    }
    c->edit[0] = '\0';
    c->edit_len = c->cursor = 0;
    c->hist_nav = -1;
    process_input(c, line);
    if (sensitive) wipe_secret(line, sizeof(line));
    reset_secret_edit(c);
    draw_prompt(c);
}

static void escape_key(Client *c, unsigned char b)
{
    if (c->escape == 1) {
        c->escape = 0;
        if (b == '[') { c->escape = 2; c->escape_len = 0; return; }
        if (b == 'O') { c->escape = 3; c->escape_len = 0; return; }
        if (!c->paste && !c->input_drop) cycle_target(c);
        /* A non-sequence character after ESC is intentionally consumed. */
        return;
    }
    if (c->escape == 3) {
        c->escape = 0;
        if (c->paste || c->input_drop) return;
        if (b == 'H') c->cursor = 0;
        if (b == 'F') c->cursor = c->edit_len;
        if (b == 'C') c->cursor = next_char(c->edit, c->edit_len, c->cursor);
        if (b == 'D') c->cursor = previous_char(c->edit, c->cursor);
        draw_prompt(c);
        return;
    }
    if (c->escape_len >= sizeof(c->escape_seq) - 1) { c->escape = 0; return; }
    c->escape_seq[c->escape_len++] = (char)b;
    c->escape_seq[c->escape_len] = '\0';
    if (b < '@' || b > '~') return;      /* CSI parameter, not final byte */
    c->escape = 0;
    if (strcmp(c->escape_seq, "200~") == 0) c->paste = true;
    else if (strcmp(c->escape_seq, "201~") == 0) c->paste = false;
    else if (c->paste || c->input_drop) return;
    else if (strcmp(c->escape_seq, "A") == 0) history_up(c);
    else if (strcmp(c->escape_seq, "B") == 0) history_down(c);
    else if (strcmp(c->escape_seq, "C") == 0)
        c->cursor = next_char(c->edit, c->edit_len, c->cursor);
    else if (strcmp(c->escape_seq, "D") == 0)
        c->cursor = previous_char(c->edit, c->cursor);
    else if (strcmp(c->escape_seq, "H") == 0 || strcmp(c->escape_seq, "1~") == 0)
        c->cursor = 0;
    else if (strcmp(c->escape_seq, "F") == 0 || strcmp(c->escape_seq, "4~") == 0)
        c->cursor = c->edit_len;
    else if (strcmp(c->escape_seq, "3~") == 0) { editor_delete(c); return; }
    draw_prompt(c);
}

static void tty_byte(Client *c, unsigned char b)
{
    if (c->escape) { escape_key(c, b); return; }
    if (b == 0x1b) { c->escape = 1; c->escape_at = clock_ms(); return; }
    if (c->input_drop) {
        if (b == 0x03 && !c->paste) stop_signal = SIGINT;
        if ((b == '\r' || b == '\n') && !c->paste) {
            c->input_drop = false;
            wipe_secret(c->edit, sizeof(c->edit));
            c->edit[0] = '\0';
            c->edit_len = c->cursor = 0;
            reset_secret_edit(c);
            ui_printf(c, "*** Input discarded.");
        }
        return;
    }
    if (c->paste) {
        if (b == '\r' || b == '\n' || b == '\t') b = ' ';
        if (b >= ' ') editor_insert(c, (char)b);
        return;
    }
    switch (b) {
    case '\r': case '\n': editor_submit(c); return;
    case 0x03: stop_signal = SIGINT; return;
    case 0x1a: suspend_signal = 1; return;
    case 0x01: c->cursor = 0; break;                /* Ctrl-A */
    case 0x05: c->cursor = c->edit_len; break;      /* Ctrl-E */
    case 0x02: c->cursor = previous_char(c->edit, c->cursor); break;
    case 0x06: c->cursor = next_char(c->edit, c->edit_len, c->cursor); break;
    case 0x08: case 0x7f: editor_backspace(c); return;
    case 0x04:
        if (!c->edit_len) { request_quit(c, "EOF"); return; }
        editor_delete(c); return;
    case 0x10: history_up(c); return;
    case 0x0e: history_down(c); return;
    case 0x17: cycle_target(c); return;
    case 0x0c: fputs("\033[2J\033[H", stdout); break;
    default:
        if (b >= ' ' && b != 0x7f) { editor_insert(c, (char)b); return; }
        return;
    }
    draw_prompt(c);
}

static void stdin_event(Client *c)
{
    unsigned char buf[512];
    ssize_t n;
    size_t i;
    bool sensitive;
    n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return;
        ui_printf(c, "*** Error reading stdin: %s", strerror(errno));
        n = 0;
    }
    if (n == 0) {
        c->stdin_eof = true;
        if (c->input_drop) ui_printf(c, "*** Oversized or binary input; line discarded.");
        else if (c->edit_len) {
            c->edit[c->edit_len] = '\0';
            sensitive = input_secret_start(c, c->edit, c->edit_len) != SIZE_MAX;
            process_input(c, c->edit);
            if (sensitive) wipe_secret(c->edit, sizeof(c->edit));
        }
        c->edit_len = 0;
        if (!c->quitting) request_quit(c, "stdin closed");
        if (!c->quitting) {
            c->quitting = true;
            c->quit_deadline = clock_ms() + 3000;
        }
        return;
    }
    c->defer_redraw = !c->dumb;
    for (i = 0; i < (size_t)n && !c->quitting && !stop_signal; i++) {
        unsigned char b = buf[i];
        if (!c->dumb) { tty_byte(c, b); continue; }
        if (b == '\n') {
            if (c->input_drop) ui_printf(c, "*** Oversized or binary input; line discarded.");
            else {
                if (c->edit_len && c->edit[c->edit_len - 1] == '\r') c->edit_len--;
                c->edit[c->edit_len] = '\0';
                sensitive = input_secret_start(c, c->edit, c->edit_len) != SIZE_MAX;
                process_input(c, c->edit);
                if (sensitive) wipe_secret(c->edit, sizeof(c->edit));
            }
            c->input_drop = false;
            c->edit_len = 0;
            c->edit[0] = '\0';
        } else if (!c->input_drop) {
            if (b == 0 || c->edit_len >= INPUT_CAP - 1) {
                wipe_secret(c->edit, sizeof(c->edit));
                c->input_drop = true;
                c->edit_len = 0;
                c->edit[0] = '\0';
            } else c->edit[c->edit_len++] = (char)b;
        }
    }
    c->defer_redraw = false;
    if (c->prompt_dirty) draw_prompt(c);
    wipe_secret(buf, (size_t)n);
}

static bool parse_port(const char *s, char out[6])
{
    char *end;
    unsigned long port;
    if (!*s) return false;
    errno = 0;
    port = strtoul(s, &end, 10);
    if (errno || *end || port < 1 || port > 65535) return false;
    (void)snprintf(out, 6, "%lu", port);
    return true;
}

static bool parse_server(Client *c, const char *spec, bool *explicit_port)
{
    char host[sizeof(c->host)], port[sizeof(c->port)];
    const char *colon = NULL, *end;
    size_t len, i, colons = 0;
    (void)copy_string(port, sizeof(port), c->port);
    if (*spec == '[') {                 /* [2001:db8::1]:6697 */
        end = strchr(spec + 1, ']');
        if (!end || (end[1] && end[1] != ':')) return false;
        len = (size_t)(end - (spec + 1));
        if (end[1]) colon = end + 1;
        spec++;
    } else {
        for (i = 0; spec[i]; i++) if (spec[i] == ':') { colons++; colon = spec + i; }
        if (colons == 1) len = (size_t)(colon - spec);
        else { len = strlen(spec); colon = NULL; } /* unbracketed IPv6 */
    }
    if (!len || len >= sizeof(host)) return false;
    memcpy(host, spec, len);
    host[len] = '\0';
    for (i = 0; i < len; i++)
        if ((unsigned char)host[i] <= ' ' || (unsigned char)host[i] >= 0x7f ||
            host[i] == '/' || host[i] == ',') return false;
    if (colon) {
        if (!parse_port(colon + 1, port)) return false;
        *explicit_port = true;
    }
    (void)copy_string(c->host, sizeof(c->host), host);
    (void)copy_string(c->port, sizeof(c->port), port);
    return true;
}

static void init_identity(Client *c)
{
    struct passwd *pw = getpwuid(getuid());
    const char *login = pw && pw->pw_name && *pw->pw_name ? pw->pw_name : "tinyirc";
    const char *gecos = pw && pw->pw_gecos && *pw->pw_gecos ? pw->pw_gecos : login;
    size_t i, n;
    n = strlen(login);
    if (n >= sizeof(c->username)) n = sizeof(c->username) - 1;
    for (i = 0; i < n; i++) {
        unsigned char b = (unsigned char)login[i];
        c->username[i] = ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
                          (b >= '0' && b <= '9') || b == '-' || b == '_') ? (char)b : '_';
    }
    c->username[n] = '\0';
    if (!n) (void)copy_string(c->username, sizeof(c->username), "tinyirc");
    n = strcspn(gecos, ",");
    if (n >= sizeof(c->realname)) n = sizeof(c->realname) - 1;
    memcpy(c->realname, gecos, n);
    c->realname[n] = '\0';
    if (!n || !valid_text(c->realname))
        (void)copy_string(c->realname, sizeof(c->realname), "tinyirc user");
    if (valid_nick(login)) (void)copy_string(c->nick, sizeof(c->nick), login);
    else (void)copy_string(c->nick, sizeof(c->nick), "tinyirc");
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [nick] [server] [port] [-dumb] [--tls]\n"
            "       %s [--nick N] [--server HOST] [--port N] [-dumb] [--tls]\n"
            "       --tls requires an OpenSSL-enabled build (make TLS=1).\n"
            "       IRCSERVER=host[:port], IRCNICK=nick; IPv6: [::1]:6697.\n",
            program, program);
}

static bool looks_like_server(const char *s)
{
    return strchr(s, '.') || strchr(s, ':') || *s == '[' || strcmp(s, "localhost") == 0;
}

static bool parse_options(Client *c, int argc, char **argv)
{
    const char *value, *env;
    bool port_explicit = false;
    int i, position = 0;
    env = getenv("IRCSERVER");
    if (env && *env && !parse_server(c, env, &port_explicit)) return false;
    env = getenv("IRCNICK");
    if (env && *env) {
        if (!valid_nick(env)) return false;
        (void)copy_string(c->nick, sizeof(c->nick), env);
    }
    for (i = 1; i < argc; i++) {
        value = argv[i];
        if (strcmp(value, "-d") == 0 || strcmp(value, "-dumb") == 0 ||
            strcmp(value, "--dumb") == 0) c->dumb = true;
        else if (strcmp(value, "-t") == 0 || strcmp(value, "--tls") == 0)
            c->tls_requested = true;
        else if (strcmp(value, "--nick") == 0 || strcmp(value, "--server") == 0 ||
                 strcmp(value, "--port") == 0) {
            const char *flag = value;
            if (++i == argc) return false;
            value = argv[i];
            if (strcmp(flag, "--nick") == 0) {
                if (!valid_nick(value)) return false;
                (void)copy_string(c->nick, sizeof(c->nick), value);
            } else if (strcmp(flag, "--server") == 0) {
                if (!parse_server(c, value, &port_explicit)) return false;
            } else {
                if (!parse_port(value, c->port)) return false;
                port_explicit = true;
            }
        } else if (value[0] == '-') return false;
        else if (position == 0) {
            if (looks_like_server(value)) {
                if (!parse_server(c, value, &port_explicit)) return false;
            } else if (parse_port(value, c->port)) port_explicit = true;
            else {
                if (!valid_nick(value)) return false;
                (void)copy_string(c->nick, sizeof(c->nick), value);
            }
            position++;
        } else if (position == 1) {
            if (parse_port(value, c->port)) port_explicit = true;
            else if (!parse_server(c, value, &port_explicit)) return false;
            position++;
        } else if (position == 2) {
            if (!parse_port(value, c->port)) return false;
            port_explicit = true;
            position++;
        } else return false;
    }
    if (c->tls_requested && !port_explicit)
        (void)snprintf(c->port, sizeof(c->port), "%u", TLS_PORT);
    return true;
}

static void free_targets(Client *c)
{
    Target *t = c->targets, *next;
    while (t) {
        next = t->next;
        memset(t->key, 0, sizeof(t->key));
        free(t);
        t = next;
    }
}

static int event_loop(Client *c)
{
    struct pollfd pfd[2];
    nfds_t count;
    int socket_index, input_index, result, wait_ms;
    short events;
    uint64_t now, remaining;
    for (;;) {
        if (stop_signal) break;
        if (suspend_signal) suspend_tty(c);
        if (resize_signal) { resize_signal = 0; draw_prompt(c); }
        now = clock_ms();
        expire_pings(c, now);
        if (c->escape == 1 && now - c->escape_at >= 120) {
            c->escape = 0;
            if (!c->paste && !c->input_drop) cycle_target(c);
        } else if (c->escape > 1 && now - c->escape_at >= 2000) {
            c->escape = 0;
        }
        if (c->fd < 0 && !c->quitting && now >= c->next_retry) {
            if (!connect_host(c) && c->fd < 0 && c->next_retry <= now) {
                c->next_retry = clock_ms() + c->backoff;
                ui_printf(c, "*** Retrying in %" PRIu64 " s.",
                          (uint64_t)(c->backoff / 1000));
                if (c->backoff < 30000) {
                    c->backoff *= 2;
                    if (c->backoff > 30000) c->backoff = 30000;
                }
            }
        }
        now = clock_ms();
        if (c->quitting && (c->fd < 0 || c->tx_off == c->tx_len ||
                            now >= c->quit_deadline)) break;
        count = 0;
        socket_index = input_index = -1;
        if (c->fd >= 0) {
            socket_index = (int)count;
            events = POLLIN;
#ifdef TINYIRC_USE_OPENSSL
            if (c->tls_requested) {
                events = c->tls_ready ? c->read_want : c->handshake_want;
                if (c->tls_ready && c->tx_off < c->tx_len) events |= c->write_want;
            } else
#endif
            if (c->tx_off < c->tx_len) events |= POLLOUT;
            pfd[count].fd = c->fd;
            pfd[count].events = events;
            pfd[count++].revents = 0;
        }
        if (!c->stdin_eof && !c->quitting) {
            input_index = (int)count;
            pfd[count].fd = STDIN_FILENO;
            pfd[count].events = POLLIN;
            pfd[count++].revents = 0;
        }
        wait_ms = 1000;                 /* redraw clock, respond to signals */
        if (c->fd < 0 && !c->quitting) {
            remaining = c->next_retry > now ? c->next_retry - now : 0;
            if (remaining < (uint64_t)wait_ms) wait_ms = (int)remaining;
        }
        if (c->escape == 1) {
            remaining = now - c->escape_at < 120 ? 120 - (now - c->escape_at) : 0;
            if (remaining < (uint64_t)wait_ms) wait_ms = (int)remaining;
        }
        if (c->quitting) {
            remaining = c->quit_deadline > now ? c->quit_deadline - now : 0;
            if (remaining < (uint64_t)wait_ms) wait_ms = (int)remaining;
        }
        result = poll(pfd, count, wait_ms);
        if (result < 0) {
            if (errno == EINTR) continue;
            ui_printf(c, "*** poll error: %s", strerror(errno));
            return 1;
        }
        if (socket_index >= 0 && pfd[socket_index].revents)
            socket_event(c, pfd[socket_index].revents);
        if (input_index >= 0 && pfd[input_index].revents)
            stdin_event(c);
        if (!c->dumb && !c->quitting &&
            (c->prompt_dirty || c->last_prompt_minute != time(NULL) / 60 ||
             c->last_columns != terminal_columns()))
            draw_prompt(c);
    }
    return stop_signal ? 128 + stop_signal : 0;
}

int main(int argc, char **argv)
{
    Client c;
    int status;
    const char *term;
    memset(&c, 0, sizeof(c));
    c.fd = -1;
    c.hist_nav = -1;
    c.backoff = 1000;
    c.casemap = CASE_RFC1459;
    (void)copy_string(c.host, sizeof(c.host), DEFAULT_SERVER);
    (void)snprintf(c.port, sizeof(c.port), "%u", DEFAULT_PORT);
    (void)setlocale(LC_CTYPE, "");
    init_identity(&c);
    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(argv[0]);
        return 0;
    }
    if (!parse_options(&c, argc, argv)) { usage(argv[0]); return 2; }
#ifndef TINYIRC_USE_OPENSSL
    if (c.tls_requested) {
        fprintf(stderr, "tinyirc: --tls requires an OpenSSL-enabled build (make TLS=1).\n");
        return 2;
    }
#else
    if (c.tls_requested) {
        c.ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!c.ssl_ctx || SSL_CTX_set_min_proto_version(c.ssl_ctx, TLS1_2_VERSION) != 1 ||
            SSL_CTX_set_default_verify_paths(c.ssl_ctx) != 1) {
            fprintf(stderr, "tinyirc: unable to initialize TLS or load trusted CAs.\n");
            SSL_CTX_free(c.ssl_ctx);
            return 1;
        }
        SSL_CTX_set_verify(c.ssl_ctx, SSL_VERIFY_PEER, NULL);
    }
#endif
    term = getenv("TERM");
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO) || !term ||
        strcmp(term, "dumb") == 0) c.dumb = true;
    (void)set_handler(SIGINT, on_signal);
    (void)set_handler(SIGHUP, on_signal);
    (void)set_handler(SIGTERM, on_signal);
#ifdef SIGWINCH
    (void)set_handler(SIGWINCH, on_signal);
#endif
    (void)set_handler(SIGCONT, on_signal);
    (void)set_handler(SIGTSTP, on_signal);
    (void)set_handler(SIGPIPE, SIG_IGN);
    if (!c.dumb && !enable_tty(&c)) c.dumb = true;
    ui_printf(&c, "*** %s", RELEASE);
    ui_printf(&c, "*** %s", ORIGINAL_COPYRIGHT);
    ui_printf(&c, "*** %s", MODIFICATION_CREDIT);
    ui_printf(&c, "*** GPL-2.0-only | /help for commands");
    if (!c.tls_requested)
        ui_printf(&c, "*** Warning: unencrypted TCP connection. Use --tls (OpenSSL build) when possible.");
    status = event_loop(&c);
    disable_tty(&c);
#ifdef TINYIRC_USE_OPENSSL
    if (c.ssl) SSL_free(c.ssl);
    if (c.ssl_ctx) SSL_CTX_free(c.ssl_ctx);
#endif
    if (c.fd >= 0) (void)close(c.fd);
    free_targets(&c);
    return status;
}
