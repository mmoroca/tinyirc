/*
 * TinyIRC 1.1.2 - portable IRC client (C11/POSIX)
 *
 * Copyright (C) 1991-2007 Nathan I. Laredo
 * Modified 2026 by @mmoroca & Arena.ai
 * Based on TinyIRC 1.1.1. SPDX-License-Identifier: GPL-2.0-only
 * See COPYING for the complete license.
 *
 * Bounded IRC I/O, termios line editing, eight-entry history, server/channel/
 * private contexts, reconnection, CTCP PING/VERSION and @text/#hex notation.
 *
 * Build: cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror tinyirc.c -o tinyirc
 */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define RELEASE       "TinyIRC 1.1.2"
#define IRC_MAX       510u            /* maximum payload before CRLF */
#define INPUT_CAP     512u
#define RX_CAP        512u
#define HISTORY_CAP   8u
#define TARGET_CAP    32u
#define TARGET_LEN    128u
#define CONNECT_MS    5000
#define PING_LIMIT    8u
#define PING_WAIT_MS  30000u

static volatile sig_atomic_t stop_signal;
static volatile sig_atomic_t suspend_signal;
static volatile sig_atomic_t refresh_signal;

typedef struct Target {
    char name[TARGET_LEN];
    char mode[64];
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
    char host[256], port[6], nick[32], user[32], real[96];
    bool dumb, tty, quit, rx_drop, input_drop;
    struct termios saved_tty;
    Target *targets, *current;
    size_t target_count, rx_len, edit_len, cursor;
    char rx[RX_CAP], edit[INPUT_CAP];
    char history[HISTORY_CAP][INPUT_CAP], draft[INPUT_CAP];
    unsigned hist_next, hist_size;
    int hist_pos, esc;
    char esc_seq[12];
    size_t esc_len;
    uint64_t esc_time, next_retry, backoff;
    PingProbe pings[PING_LIMIT];
    uint64_t ping_serial;
} Client;

typedef struct {
    char *prefix, *command, *param[15];
    size_t count;
} Message;

static void prompt(Client *c);
static void print_line(Client *c, const char *fmt, ...);

static uint64_t milliseconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    return (uint64_t)time(NULL) * 1000u;
}

static void on_signal(int sig)
{
    if (sig == SIGTSTP) suspend_signal = 1;
    else if (sig == SIGCONT) refresh_signal = 1;
    else stop_signal = sig;
}

static void install_signal(int sig, void (*fn)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fn;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(sig, &sa, NULL);
}

static bool copy_text(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap) return false;
    memcpy(dst, src, n + 1);
    return true;
}

static unsigned char irc_lower(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') ch = (unsigned char)(ch + ('a' - 'A'));
    if (ch == '[') return '{';
    if (ch == ']') return '}';
    if (ch == '\\') return '|';
    if (ch == '^') return '~';
    return ch;
}

static bool irc_equal(const char *a, const char *b)
{
    while (*a && *b)
        if (irc_lower((unsigned char)*a++) != irc_lower((unsigned char)*b++))
            return false;
    return !*a && !*b;
}

static bool channel_name(const char *s)
{
    return *s == '#' || *s == '&' || *s == '+';
}

static bool valid_name(const char *s, size_t cap)
{
    size_t n = strlen(s), i;
    if (!n || n >= cap) return false;
    for (i = 0; i < n; i++)
        if ((unsigned char)s[i] <= ' ' || (unsigned char)s[i] == 127 ||
            s[i] == ':' || s[i] == ',') return false;
    return true;
}

static bool valid_nick(const char *s)
{
    size_t i;
    if (!valid_name(s, 32) || isdigit((unsigned char)*s) || *s == '-')
        return false;
    for (i = 0; s[i]; i++)
        if (s[i] == '!' || s[i] == '@' || s[i] == '#' || s[i] == '&' ||
            s[i] == '*') return false;
    return true;
}

static bool valid_message(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 32 || (unsigned char)*s == 127)
            return false;
    return true;
}

/* Plain text only: strip mIRC formatting and prevent terminal escape injection. */
static void safe_print(const char *s, size_t n)
{
    size_t i = 0, j;
    while (i < n) {
        unsigned char ch = (unsigned char)s[i++];
        if (ch == 3) {
            for (j = 0; j < 2 && i < n && isdigit((unsigned char)s[i]); j++, i++) {}
            if (i < n && s[i] == ',') {
                i++;
                for (j = 0; j < 2 && i < n && isdigit((unsigned char)s[i]); j++, i++) {}
            }
        } else if (ch == 4) {
            for (j = 0; j < 6 && i < n && isxdigit((unsigned char)s[i]); j++, i++) {}
            if (i < n && s[i] == ',') {
                i++;
                for (j = 0; j < 6 && i < n && isxdigit((unsigned char)s[i]); j++, i++) {}
            }
        } else if (ch == '\t') fputs("    ", stdout);
        else if (ch == 27 || ch == 127) putchar('?');
        else if (ch >= 0x80) {
            /* Never emit a bare 8-bit terminal control (e.g. CSI = 0x9b). */
            size_t extra = ch <= 0xdf && ch >= 0xc2 ? 1 :
                           ch >= 0xe0 && ch <= 0xef ? 2 :
                           ch >= 0xf0 && ch <= 0xf4 ? 3 : 0;
            bool valid = extra && i + extra <= n;
            if (valid) {
                for (j = 0; j < extra; j++)
                    if (((unsigned char)s[i + j] & 0xc0) != 0x80) valid = false;
                if ((ch == 0xc2 && (unsigned char)s[i] <= 0x9f) ||
                    (ch == 0xe0 && (unsigned char)s[i] < 0xa0) ||
                    (ch == 0xed && (unsigned char)s[i] >= 0xa0) ||
                    (ch == 0xf0 && (unsigned char)s[i] < 0x90) ||
                    (ch == 0xf4 && (unsigned char)s[i] >= 0x90)) valid = false;
            }
            if (valid) {
                putchar(ch);
                (void)fwrite(s + i, 1, extra, stdout);
                i += extra;
            } else putchar('?');
        } else if (ch >= 32) putchar(ch);
        /* Drop other formatting and control characters (including CTCP). */
    }
}

static int columns(void)
{
    struct winsize w;
    const char *p = getenv("COLUMNS");
    char *end;
    long value;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col >= 20)
        return (int)w.ws_col;
    if (p && *p) {
        errno = 0;
        value = strtol(p, &end, 10);
        if (!errno && !*end && value >= 20 && value <= 1000) return (int)value;
    }
    return 80;
}

static void prompt(Client *c)
{
    char head[256];
    time_t now;
    struct tm tm_now;
    size_t prefix, room, start, end, back;
    if (!c->tty) return;
    now = time(NULL);
    if (localtime_r(&now, &tm_now))
        (void)snprintf(head, sizeof(head), "[%02d:%02d %s | %s (%s)] > ",
                       tm_now.tm_hour, tm_now.tm_min, c->nick,
                       c->current ? c->current->name : "*",
                       c->current && *c->current->mode ? c->current->mode : "*");
    else (void)snprintf(head, sizeof(head), "[%s | %s (%s)] > ", c->nick,
                        c->current ? c->current->name : "*",
                        c->current && *c->current->mode ? c->current->mode : "*");
    prefix = strlen(head);
    if (prefix + 4 >= (size_t)columns()) { (void)copy_text(head, sizeof(head), "> "); prefix = 2; }
    room = (size_t)columns() - prefix - 1;
    start = c->cursor > room ? c->cursor - room : 0;
    while (start && ((unsigned char)c->edit[start] & 0xc0) == 0x80) start--;
    end = c->edit_len < start + room ? c->edit_len : start + room;
    while (end > start && ((unsigned char)c->edit[end] & 0xc0) == 0x80) end--;
    back = end > c->cursor ? end - c->cursor : 0;
    fputs("\r\033[2K", stdout);
    fputs(head, stdout);
    safe_print(c->edit + start, end - start);
    if (back) (void)printf("\033[%zuD", back);
    (void)fflush(stdout);
}

static void print_line(Client *c, const char *fmt, ...)
{
    char text[RX_CAP + 512];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (c->tty) fputs("\r\033[2K", stdout);
    safe_print(text, (size_t)n < sizeof(text) ? (size_t)n : sizeof(text) - 1);
    putchar('\n');
    prompt(c);
    (void)fflush(stdout);
}

static bool enable_tty(Client *c)
{
    struct termios raw;
    if (tcgetattr(STDIN_FILENO, &c->saved_tty) != 0) return false;
    raw = c->saved_tty;
    raw.c_iflag &= (tcflag_t)~(ICRNL | IXON);
    raw.c_lflag &= (tcflag_t)~(ICANON | ECHO | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return false;
    c->tty = true;
    prompt(c);
    return true;
}

static void disable_tty(Client *c)
{
    if (!c->tty) return;
    fputs("\r\033[2K", stdout);
    (void)fflush(stdout);
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &c->saved_tty);
    c->tty = false;
}

static void suspend_tty(Client *c)
{
    suspend_signal = 0;
    disable_tty(c);
    install_signal(SIGTSTP, SIG_DFL);
    (void)raise(SIGTSTP);
    install_signal(SIGTSTP, on_signal);
    if (!c->dumb && !enable_tty(c)) c->dumb = true;
    prompt(c);
}

static Target *find_target(Client *c, const char *name)
{
    Target *t;
    for (t = c->targets; t; t = t->next)
        if (irc_equal(t->name, name)) return t;
    return NULL;
}

static Target *add_target(Client *c, const char *name, bool select)
{
    Target *t;
    if (!valid_name(name, TARGET_LEN)) { print_line(c, "*** Invalid target."); return NULL; }
    t = find_target(c, name);
    if (t) { if (select) c->current = t; return t; }
    if (c->target_count == TARGET_CAP) { print_line(c, "*** Too many targets."); return NULL; }
    t = calloc(1, sizeof(*t));
    if (!t) { print_line(c, "*** Out of memory."); return NULL; }
    (void)copy_text(t->name, sizeof(t->name), name);
    t->next = c->targets;
    c->targets = t;
    c->target_count++;
    if (select || !c->current) c->current = t;
    return t;
}

static void remove_target(Client *c, const char *name)
{
    Target **p = &c->targets, *t;
    while (*p && !irc_equal((*p)->name, name)) p = &(*p)->next;
    if (!*p) return;
    t = *p;
    *p = t->next;
    if (c->current == t) c->current = t->next ? t->next : c->targets;
    free(t);
    c->target_count--;
    prompt(c);
}

static void cycle_target(Client *c)
{
    c->current = c->current ? c->current->next : c->targets;
    print_line(c, "*** Current target: %s",
               c->current ? c->current->name : "server");
}

static void drop_connection(Client *c)
{
    Target *t;
    if (c->fd >= 0) (void)close(c->fd);
    c->fd = -1;
    memset(c->pings, 0, sizeof(c->pings));
    c->rx_len = 0;
    c->rx_drop = false;
    c->next_retry = milliseconds() + 1000;
    for (t = c->targets; t; t = t->next) {
        t->joined = false;
        t->mode[0] = '\0';
    }
}

static bool send_line(Client *c, const char *fmt, ...)
{
    char line[IRC_MAX + 3];
    va_list ap;
    int n;
    size_t at = 0, total;
    uint64_t end = milliseconds() + 3000;
    if (c->fd < 0) { print_line(c, "*** Not connected."); return false; }
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 1 || (size_t)n > IRC_MAX) {
        print_line(c, "*** IRC line too long; not sent."); return false;
    }
    for (int i = 0; i < n; i++)
        if (((unsigned char)line[i] < 32 && line[i] != 1) ||
            (unsigned char)line[i] == 127) {
            print_line(c, "*** Invalid control character; not sent."); return false;
        }
    line[n] = '\r'; line[n + 1] = '\n';
    total = (size_t)n + 2;
    while (at < total && !stop_signal && milliseconds() < end) {
        ssize_t wrote = send(c->fd, line + at, total - at, 0);
        if (wrote > 0) { at += (size_t)wrote; continue; }
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { c->fd, POLLOUT, 0 };
            uint64_t now = milliseconds();
            if (now >= end || poll(&pfd, 1, (int)(end - now)) <= 0) break;
            continue;
        }
        break;
    }
    if (at == total) return true;
    drop_connection(c); /* A partial IRC line must not pollute the next send. */
    print_line(c, "*** Connection lost while sending.");
    return false;
}

static bool connect_host(Client *c)
{
    struct addrinfo hints, *list = NULL, *a;
    int s = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* preserve the original IPv4-only transport */
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(c->host, c->port, &hints, &list) != 0) {
        print_line(c, "*** Unable to resolve %s.", c->host); return false;
    }
    for (a = list; a; a = a->ai_next) {
        int flags, error = 0, ready;
        socklen_t size = (socklen_t)sizeof(error);
        struct pollfd pfd;
        s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s < 0) continue;
        flags = fcntl(s, F_GETFL, 0);
        if (flags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) != 0) {
            (void)close(s); s = -1; continue;
        }
        ready = connect(s, a->ai_addr, a->ai_addrlen);
        if (ready != 0 && errno == EINPROGRESS) {
            pfd.fd = s; pfd.events = POLLOUT; pfd.revents = 0;
            ready = poll(&pfd, 1, CONNECT_MS);
            if (ready > 0 && getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &size) == 0)
                ready = error ? -1 : 0;
            else ready = -1;
        }
        if (ready == 0) break;
        (void)close(s); s = -1;
    }
    freeaddrinfo(list);
    if (s < 0) return false;
    c->fd = s;
    c->rx_len = 0;
    c->rx_drop = false;
    print_line(c, "*** Connected to %s:%s (unencrypted).", c->host, c->port);
    if (!send_line(c, "NICK %s", c->nick) ||
        !send_line(c, "USER %s 0 * :%s", c->user, c->real)) {
        drop_connection(c); return false;
    }
    return true;
}

static bool parse_message(char *line, Message *m)
{
    char *p = line, *space;
    memset(m, 0, sizeof(*m));
    if (*p == '@') {
        space = strchr(p, ' ');
        if (!space) return false;
        p = space + 1; /* ignore IRCv3 tags without interpreting them */
    }
    while (*p == ' ') p++;
    if (*p == ':') {
        m->prefix = ++p;
        space = strchr(p, ' ');
        if (!space) return false;
        *space = '\0'; p = space + 1;
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

static const char *param(const Message *m, size_t i)
{
    return i < m->count ? m->param[i] : "";
}

static void actor_name(const Message *m, char name[64])
{
    const char *p = m->prefix ? m->prefix : "server";
    size_t n = strcspn(p, "!@");
    if (n > 63) n = 63;
    memcpy(name, p, n);
    name[n] = '\0';
}

/* Each measurement belongs to one connection and one independently matched reply. */
static PingProbe *free_ping(Client *c)
{
    for (size_t i = 0; i < PING_LIMIT; i++)
        if (!c->pings[i].active) return &c->pings[i];
    return NULL;
}

static void finish_ping(Client *c, PingProbe *p)
{
    uint64_t now = milliseconds();
    uint64_t elapsed = now >= p->started ? now - p->started : 0;
    print_line(c, "*** %s PING %s: %llu ms", p->peer ? "CTCP" : "Server",
               p->target, (unsigned long long)elapsed);
    memset(p, 0, sizeof(*p));
}

static bool ping_pong(Client *c, const Message *m)
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
                        const char *text)
{
    size_t n = strlen(text);
    if (!irc_equal(to, c->nick) || n < 8 || text[0] != 1 ||
        text[n - 1] != 1 || strncmp(text + 1, "PING ", 5) != 0)
        return false;
    for (size_t i = 0; i < PING_LIMIT; i++) {
        PingProbe *p = &c->pings[i];
        if (p->active && p->peer && irc_equal(actor, p->target) &&
            strlen(p->token) == n - 7 &&
            memcmp(text + 6, p->token, n - 7) == 0) {
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
            print_line(c, "*** %s PING %s: no reply (30 s); RTT unavailable.",
                       p->peer ? "CTCP" : "Server", p->target);
            memset(p, 0, sizeof(*p));
        }
    }
}

static void show_generic(Client *c, const Message *m)
{
    char text[RX_CAP + 128];
    size_t used = 0, i;
    int n = snprintf(text, sizeof(text), "*** %s", m->command);
    if (n < 0) return;
    used = (size_t)n < sizeof(text) ? (size_t)n : sizeof(text) - 1;
    for (i = 0; i < m->count && used < sizeof(text) - 1; i++) {
        n = snprintf(text + used, sizeof(text) - used, " %s", param(m, i));
        if (n < 0) break;
        used += (size_t)n < sizeof(text) - used ? (size_t)n : sizeof(text) - used - 1;
    }
    print_line(c, "%s", text);
}

static bool decode_hex(const char *s, char out[INPUT_CAP]);

static void update_modes(Target *t, const char *flags)
{
    bool adding = true;
    for (; *flags; flags++) {
        char *at;
        size_t len;
        if (*flags == '+') { adding = true; continue; }
        if (*flags == '-') { adding = false; continue; }
        if (!strchr("psitnml", *flags)) continue;
        at = strchr(t->mode, *flags);
        if (!adding && at)
            memmove(at, at + 1, strlen(at));
        else if (adding && !at) {
            len = strlen(t->mode);
            if (len < sizeof(t->mode) - 1) {
                t->mode[len] = *flags;
                t->mode[len + 1] = '\0';
            }
        }
    }
}

/* These two replies existed in the original build; never reflect raw CR/LF. */
static bool answer_ctcp(Client *c, const char *actor, const char *text)
{
    size_t n = strlen(text);
    if (n < 2 || text[0] != 1 || text[n - 1] != 1 || !valid_nick(actor))
        return false;
    for (size_t i = 1; i + 1 < n; i++)
        if ((unsigned char)text[i] < 32 || (unsigned char)text[i] == 127)
            return false;
    if (n >= 6 && !strncmp(text, "\001PING", 5) &&
        (text[5] == ' ' || text[5] == 1)) {
        if (send_line(c, "NOTICE %s :%s", actor, text))
            print_line(c, "*** CTCP PING from %s", actor);
        return true;
    }
    if (strcmp(text, "\001VERSION\001") == 0) {
        if (send_line(c, "NOTICE %s :\001VERSION %s :*ix\001", actor, RELEASE))
            print_line(c, "*** CTCP VERSION from %s", actor);
        return true;
    }
    return false;
}

static void handle_server(Client *c, char *line)
{
    Message m;
    Target *t;
    char actor[64], decoded[INPUT_CAP];
    const char *a, *b;
    if (!parse_message(line, &m)) return;
    actor_name(&m, actor);
    a = param(&m, 0); b = param(&m, 1);
    if (irc_equal(m.command, "PING")) {
        if (m.count >= 2) (void)send_line(c, "PONG %s :%s", a, b);
        else if (*a) (void)send_line(c, "PONG :%s", a);
        return;
    }
    if (irc_equal(m.command, "PONG") && ping_pong(c, &m)) return;
    if (irc_equal(m.command, "PRIVMSG") || irc_equal(m.command, "NOTICE")) {
        if (m.count < 2) return;
        if (irc_equal(m.command, "NOTICE") && ping_notice(c, actor, a, b)) return;
        if (irc_equal(m.command, "PRIVMSG") && answer_ctcp(c, actor, b)) return;
        if (*b == '@' && decode_hex(b + 1, decoded)) b = decoded;
        if (irc_equal(m.command, "NOTICE")) print_line(c, "-%s- %s", actor, b);
        else if (channel_name(a)) print_line(c, "<%s%s%s> %s", actor,
                    c->current && !irc_equal(c->current->name, a) ? ":" : "",
                    c->current && !irc_equal(c->current->name, a) ? a : "", b);
        else print_line(c, "*%s* %s", actor, b);
        return;
    }
    if (irc_equal(m.command, "JOIN") && *a && irc_equal(actor, c->nick)) {
        t = add_target(c, a, true);
        if (t) { t->joined = true; (void)send_line(c, "MODE %s", a); }
    } else if (irc_equal(m.command, "PART") && *a && irc_equal(actor, c->nick))
        remove_target(c, a);
    else if (irc_equal(m.command, "KICK") && m.count >= 2 &&
             irc_equal(b, c->nick)) remove_target(c, a);
    else if (irc_equal(m.command, "NICK") && *a && irc_equal(actor, c->nick))
        (void)copy_text(c->nick, sizeof(c->nick), a);
    else if (irc_equal(m.command, "MODE") && m.count >= 2) {
        t = find_target(c, a);
        if (t) update_modes(t, b);
    } else if (irc_equal(m.command, "324") && m.count >= 3) {
        t = find_target(c, b);
        if (t) { t->mode[0] = '\0'; update_modes(t, param(&m, 2)); }
    } else if (irc_equal(m.command, "001")) {
        if (valid_nick(a)) (void)copy_text(c->nick, sizeof(c->nick), a);
        for (t = c->targets; t; t = t->next)
            if (channel_name(t->name)) (void)send_line(c, "JOIN %s", t->name);
    }
    if (irc_equal(m.command, "JOIN") && *a)
        print_line(c, "*** %s joined %s", actor, a);
    else if (irc_equal(m.command, "PART") && *a)
        print_line(c, "*** %s left %s%s%s", actor, a, *b ? ": " : "", b);
    else if (irc_equal(m.command, "QUIT"))
        print_line(c, "*** %s quit%s%s", actor, *a ? ": " : "", a);
    else if (irc_equal(m.command, "NICK") && *a)
        print_line(c, "*** %s is now known as %s", actor, a);
    else if (irc_equal(m.command, "KICK") && m.count >= 2)
        print_line(c, "*** %s kicked %s from %s%s%s", actor, b, a,
                   *param(&m, 2) ? ": " : "", param(&m, 2));
    else show_generic(c, &m); /* Includes the server's actual 432/433 explanation. */
    if (irc_equal(m.command, "ERROR") ||
        (irc_equal(m.command, "KILL") && irc_equal(a, c->nick))) c->quit = true;
}

static bool read_server(Client *c)
{
    char buf[2048];
    ssize_t n;
    n = recv(c->fd, buf, sizeof(buf), 0);
    if (n <= 0) return n < 0 && (errno == EAGAIN || errno == EINTR);
    for (size_t i = 0; i < (size_t)n; i++) {
        unsigned char ch = (unsigned char)buf[i];
        if (ch == '\n') {
            if (!c->rx_drop) {
                if (c->rx_len && c->rx[c->rx_len - 1] == '\r') c->rx_len--;
                c->rx[c->rx_len] = '\0';
                if (c->rx_len > IRC_MAX)
                    print_line(c, "*** Server line too long; discarded.");
                else if (c->rx_len) handle_server(c, c->rx);
                if (c->fd < 0) return false;
            }
            c->rx_len = 0;
            c->rx_drop = false;
        } else if (!c->rx_drop) {
            if (c->rx_len < RX_CAP - 1) c->rx[c->rx_len++] = (char)ch;
            else { c->rx_drop = true; print_line(c, "*** Server line too long; discarded."); }
        }
    }
    return true;
}

static char *spaces(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

static char *word(char **tail)
{
    char *w = spaces(*tail), *end = w;
    while (*end && *end != ' ' && *end != '\t') end++;
    if (*end) *end++ = '\0';
    *tail = spaces(end);
    return w;
}

static void command_ping(Client *c, char *args)
{
    char *name = word(&args);
    /* A hostname selects the server probe; only the connected server is timed. */
    bool server = !*name || irc_equal(name, "server") ||
                  irc_equal(name, c->host) || strchr(name, '.') != NULL;
    PingProbe *p;
    uint64_t now;
    int n;
    if (*args || (server && *name && !valid_name(name, sizeof(c->host))) ||
        (!server && !valid_nick(name))) {
        print_line(c, "*** Usage: /ping [server|server.hostname|nick].");
        return;
    }
    if (c->fd < 0) { print_line(c, "*** Not connected."); return; }
    p = free_ping(c);
    if (!p) { print_line(c, "*** Too many pending pings (maximum 8)."); return; }
    now = milliseconds();
    n = snprintf(p->token, sizeof(p->token), "tinyirc-%llu-%llu",
                 (unsigned long long)now, (unsigned long long)++c->ping_serial);
    if (n < 0 || (size_t)n >= sizeof(p->token)) return;
    if (!(server ? send_line(c, "PING :%s", p->token) :
                   send_line(c, "PRIVMSG %s :\001PING %s\001", name, p->token)))
        return;
    (void)copy_text(p->target, sizeof(p->target), server ? c->host : name);
    p->started = now;
    p->peer = !server;
    p->active = true;
    print_line(c, "*** %s PING sent to %s; waiting for reply.",
               server ? "Server" : "CTCP", p->target);
}

static bool original_command(const char *s)
{
    static const char *const commands[] = {
        "ADMIN", "AWAY", "CLOSE", "CONNECT", "DIE", "DNS", "ERROR", "HASH",
        "HELP", "INFO", "INVITE", "ISON", "JOIN", "KICK", "KILL", "LINKS",
        "LIST", "LUSERS", "MODE", "MOTD", "MSG", "NAMES", "NICK", "NOTE",
        "NOTICE", "OPER", "PART", "PASS", "PING", "PONG", "PRIVMSG", "QUIT",
        "REHASH", "RESTART", "SERVER", "SQUIT", "STATS", "SUMMON", "TIME",
        "TOPIC", "TRACE", "USER", "USERHOST", "USERS", "VERSION", "WALLOPS",
        "WHO", "WHOIS", "WHOWAS"
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        if (strcmp(s, commands[i]) == 0) return true;
    return false;
}

static int hex_digit(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool decode_hex(const char *s, char out[INPUT_CAP])
{
    size_t n = strlen(s);
    if (n % 2 || n / 2 >= INPUT_CAP) return false;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_digit((unsigned char)s[i]), lo = hex_digit((unsigned char)s[i + 1]);
        if (hi < 0 || lo < 0 || hi * 16 + lo == 0) return false;
        out[i / 2] = (char)(hi * 16 + lo);
    }
    out[n / 2] = '\0';
    return true;
}

static void process_input(Client *c, char *line)
{
    char cmd[32], *p = line + 1, *arg, *name;
    size_t i = 0;
    if (!*line) return;
    if (*line == '#') {
        char decoded[INPUT_CAP];
        if (decode_hex(line + 1, decoded)) print_line(c, "*** Hex: %s", decoded);
        else print_line(c, "*** Invalid hexadecimal input.");
        return;
    }
    if (*line != '/') {
        if (!c->current) { print_line(c, "*** No current target; use /join."); return; }
        if (*line == '@') {
            char encoded[2 * INPUT_CAP];
            static const char hex[] = "0123456789abcdef";
            size_t n = strlen(line + 1);
            for (i = 0; i < n; i++) {
                unsigned char ch = (unsigned char)line[i + 1];
                encoded[2 * i] = hex[ch >> 4]; encoded[2 * i + 1] = hex[ch & 15];
            }
            encoded[2 * n] = '\0';
            if (send_line(c, "PRIVMSG %s :@%s", c->current->name, encoded))
                print_line(c, "> %s", line);
        } else if (send_line(c, "PRIVMSG %s :%s", c->current->name, line))
            print_line(c, "> %s", line);
        return;
    }
    while (*p && *p != ' ' && *p != '\t' && i < sizeof(cmd) - 1) {
        if (!isalnum((unsigned char)*p)) { print_line(c, "*** Invalid command."); return; }
        cmd[i++] = (char)toupper((unsigned char)*p++);
    }
    if (!i || (*p && *p != ' ' && *p != '\t')) {
        print_line(c, "*** Empty or overlong command."); return;
    }
    cmd[i] = '\0';
    arg = spaces(p);
    if (strcmp(cmd, "PING") == 0) { command_ping(c, arg); return; }
    if (strcmp(cmd, "SWITCH") == 0) {
        Target *t;
        name = word(&arg);
        if (*arg) print_line(c, "*** Usage: /switch [*|target].");
        else if (!*name) cycle_target(c);
        else if (strcmp(name, "*") == 0) {
            c->current = NULL;
            print_line(c, "*** Current target: server");
        } else if ((t = find_target(c, name)) != NULL) {
            c->current = t;
            print_line(c, "*** Current target: %s", t->name);
        } else print_line(c, "*** Unknown target.");
        return;
    }
    if (!original_command(cmd)) { print_line(c, "*** Unknown command."); return; }
    if (strcmp(cmd, "JOIN") == 0) {
        char *key;
        name = word(&arg); key = word(&arg);
        if (!valid_name(name, TARGET_LEN) || *arg || (channel_name(name) &&
            *key && !valid_message(key))) {
            print_line(c, "*** Usage: /join #channel [key] or /join nick."); return;
        }
        if (!channel_name(name)) {
            if (*key) { print_line(c, "*** Private target cannot have a key."); return; }
            if (add_target(c, name, true)) print_line(c, "*** Now talking to %s.", name);
        } else if (find_target(c, name) && find_target(c, name)->joined) {
            c->current = find_target(c, name);
            print_line(c, "*** Now talking in %s.", name);
        } else if (*key ? send_line(c, "JOIN %s %s", name, key) :
                           send_line(c, "JOIN %s", name))
            print_line(c, "*** JOIN requested: %s", name);
    } else if (strcmp(cmd, "PART") == 0) {
        name = word(&arg);
        if (!*name) {
            if (!c->current) { print_line(c, "*** Usage: /part [target]."); return; }
            name = c->current->name;
        }
        if (!valid_name(name, TARGET_LEN) || !valid_message(arg)) {
            print_line(c, "*** Invalid target/reason."); return;
        }
        if (!channel_name(name)) {
            if (find_target(c, name)) {
                print_line(c, "*** Closed: %s", name);
                remove_target(c, name);
            } else print_line(c, "*** No such private target.");
        } else if (*arg ? send_line(c, "PART %s :%s", name, arg) :
                           send_line(c, "PART %s", name))
            print_line(c, "*** Leaving %s...", name);
    } else if (strcmp(cmd, "MSG") == 0 || strcmp(cmd, "PRIVMSG") == 0 ||
               strcmp(cmd, "NOTICE") == 0) {
        const char *verb = strcmp(cmd, "NOTICE") == 0 ? "NOTICE" : "PRIVMSG";
        name = word(&arg);
        if (!valid_name(name, TARGET_LEN) || !*arg || !valid_message(arg)) {
            print_line(c, "*** Usage: /msg target text."); return;
        }
        if (send_line(c, "%s %s :%s", verb, name, arg))
            print_line(c, "-> %s: %s", name, arg);
    } else if (strcmp(cmd, "NICK") == 0) {
        /* Compact edition: send IRC-Hispano's suffix verbatim, without masking. */
        char *separator;
        name = word(&arg);
        separator = strchr(name, ':');
        if (separator) *separator = '\0';
        if (!valid_nick(name) || *arg ||
            (separator && (!separator[1] || !valid_message(separator + 1)))) {
            print_line(c, "*** Usage: /nick NICK[:PASSWORD]."); return;
        }
        if (c->fd < 0) {
            if (separator)
                print_line(c, "*** Not connected; nickname password not stored. Retry after connecting.");
            else {
                (void)copy_text(c->nick, sizeof(c->nick), name);
                print_line(c, "*** Nick saved for reconnect: %s", name);
            }
        } else if (send_line(c, "NICK %s%s%s", name, separator ? ":" : "",
                             separator ? separator + 1 : "")) {
            if (separator)
                print_line(c, "*** Warning: nickname password sent unencrypted; terminal input/history are not masked.");
            print_line(c, "*** Nick change requested: %s", name);
        }
    } else if (strcmp(cmd, "QUIT") == 0) {
        if (!valid_message(arg)) { print_line(c, "*** Invalid quit reason."); return; }
        (void)send_line(c, "QUIT :%s", *arg ? arg : RELEASE);
        c->quit = true;
    } else if (strcmp(cmd, "AWAY") == 0 && *arg) {
        if (send_line(c, "AWAY :%s", arg)) print_line(c, "= AWAY %s", arg);
    } else if (strcmp(cmd, "TOPIC") == 0 && *arg) {
        name = word(&arg);
        if (send_line(c, "TOPIC %s%s%s", name, *arg ? " :" : "", arg))
            print_line(c, "= TOPIC %s %s", name, arg);
    } else if (strcmp(cmd, "KICK") == 0 && *arg) {
        char *victim;
        name = word(&arg); victim = word(&arg);
        if (!*name || !*victim || !valid_message(arg)) {
            print_line(c, "*** Usage: /kick channel nick [reason]."); return;
        }
        if (send_line(c, "KICK %s %s%s%s", name, victim, *arg ? " :" : "", arg))
            print_line(c, "= KICK %s %s %s", name, victim, arg);
    } else {
        if (!valid_message(arg)) { print_line(c, "*** Invalid arguments."); return; }
        if (send_line(c, "%s%s%s", cmd, *arg ? " " : "", arg))
            print_line(c, "= %s %s", cmd, arg);
    }
}

static size_t prev_char(const char *s, size_t pos)
{
    if (!pos) return 0;
    pos--;
    while (pos && ((unsigned char)s[pos] & 0xc0) == 0x80) pos--;
    return pos;
}

static size_t next_char(const char *s, size_t len, size_t pos)
{
    if (pos >= len) return len;
    pos++;
    while (pos < len && ((unsigned char)s[pos] & 0xc0) == 0x80) pos++;
    return pos;
}

static void editor_set(Client *c, const char *text)
{
    (void)copy_text(c->edit, sizeof(c->edit), text);
    c->cursor = c->edit_len = strlen(c->edit);
    prompt(c);
}

static void history_up(Client *c)
{
    unsigned index;
    if (!c->hist_size) return;
    if (c->hist_pos < 0) (void)copy_text(c->draft, sizeof(c->draft), c->edit);
    if (c->hist_pos + 1 < (int)c->hist_size) c->hist_pos++;
    index = (c->hist_next + HISTORY_CAP - 1u - (unsigned)c->hist_pos) % HISTORY_CAP;
    editor_set(c, c->history[index]);
}

static void history_down(Client *c)
{
    unsigned index;
    if (c->hist_pos < 0) return;
    if (c->hist_pos == 0) { c->hist_pos = -1; editor_set(c, c->draft); return; }
    c->hist_pos--;
    index = (c->hist_next + HISTORY_CAP - 1u - (unsigned)c->hist_pos) % HISTORY_CAP;
    editor_set(c, c->history[index]);
}

static void submit(Client *c)
{
    char line[INPUT_CAP];
    if (!c->edit_len) return;
    (void)copy_text(line, sizeof(line), c->edit);
    if (!c->hist_size || strcmp(c->history[(c->hist_next + HISTORY_CAP - 1) % HISTORY_CAP], line)) {
        (void)copy_text(c->history[c->hist_next], INPUT_CAP, line);
        c->hist_next = (c->hist_next + 1u) % HISTORY_CAP;
        if (c->hist_size < HISTORY_CAP) c->hist_size++;
    }
    c->edit[0] = '\0';
    c->edit_len = c->cursor = 0;
    c->hist_pos = -1;
    process_input(c, line);
    prompt(c);
}

static void insert(Client *c, unsigned char ch)
{
    if (c->edit_len >= INPUT_CAP - 1) {
        c->input_drop = true;
        print_line(c, "*** Input too long; discarding to newline.");
        return;
    }
    memmove(c->edit + c->cursor + 1, c->edit + c->cursor,
            c->edit_len - c->cursor + 1);
    c->edit[c->cursor++] = (char)ch;
    c->edit_len++;
    prompt(c);
}

static void erase(Client *c, bool forward)
{
    size_t start = c->cursor, end;
    if (forward) end = next_char(c->edit, c->edit_len, start);
    else { start = prev_char(c->edit, start); end = c->cursor; }
    if (start == end) return;
    memmove(c->edit + start, c->edit + end, c->edit_len - end + 1);
    c->edit_len -= end - start;
    c->cursor = start;
    c->hist_pos = -1;
    prompt(c);
}

static void terminal_byte(Client *c, unsigned char ch);

static void escape_byte(Client *c, unsigned char ch)
{
    if (c->esc == 1) {
        c->esc = 0;
        if (ch == '[') { c->esc = 2; c->esc_len = 0; return; }
        if (ch == 'O') { c->esc = 3; c->esc_len = 0; return; }
        cycle_target(c);
        terminal_byte(c, ch);
        return;
    }
    if (c->esc == 3) {
        c->esc = 0;
        if (ch == 'H') c->cursor = 0;
        if (ch == 'F') c->cursor = c->edit_len;
        prompt(c);
        return;
    }
    if (c->esc_len >= sizeof(c->esc_seq) - 1) { c->esc = 0; return; }
    c->esc_seq[c->esc_len++] = (char)ch;
    c->esc_seq[c->esc_len] = '\0';
    if (ch < '@' || ch > '~') return;
    c->esc = 0;
    if (strcmp(c->esc_seq, "A") == 0) history_up(c);
    else if (strcmp(c->esc_seq, "B") == 0) history_down(c);
    else if (strcmp(c->esc_seq, "C") == 0) c->cursor = next_char(c->edit, c->edit_len, c->cursor);
    else if (strcmp(c->esc_seq, "D") == 0) c->cursor = prev_char(c->edit, c->cursor);
    else if (strcmp(c->esc_seq, "H") == 0 || strcmp(c->esc_seq, "1~") == 0) c->cursor = 0;
    else if (strcmp(c->esc_seq, "F") == 0 || strcmp(c->esc_seq, "4~") == 0) c->cursor = c->edit_len;
    else if (strcmp(c->esc_seq, "3~") == 0) { erase(c, true); return; }
    prompt(c);
}

static void terminal_byte(Client *c, unsigned char ch)
{
    if (c->esc) { escape_byte(c, ch); return; }
    if (ch == 27) { c->esc = 1; c->esc_time = milliseconds(); return; }
    if (c->input_drop) {
        if (ch == 3) stop_signal = SIGINT;
        if (ch == '\r' || ch == '\n') {
            c->input_drop = false;
            c->edit_len = c->cursor = 0;
            c->edit[0] = '\0';
            print_line(c, "*** Input discarded.");
        }
        return;
    }
    switch (ch) {
    case 3: stop_signal = SIGINT; return;
    case 26: suspend_signal = 1; return;
    case '\r': case '\n': submit(c); return;
    case 1: c->cursor = 0; break; /* Ctrl-A */
    case 5: c->cursor = c->edit_len; break; /* Ctrl-E */
    case 2: c->cursor = prev_char(c->edit, c->cursor); break;
    case 6: c->cursor = next_char(c->edit, c->edit_len, c->cursor); break;
    case 16: history_up(c); return; /* Ctrl-P */
    case 14: history_down(c); return; /* Ctrl-N */
    case 8: case 127: erase(c, false); return;
    case 4: erase(c, true); return;
    case 12: break; /* redraw */
    default:
        if (ch >= ' ' && ch != 127) { insert(c, ch); return; }
        return;
    }
    prompt(c);
}

static void stdin_ready(Client *c)
{
    unsigned char buf[256];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) return;
        n = 0;
    }
    if (n == 0) {
        if (!c->dumb && c->edit_len) submit(c);
        else if (c->dumb && c->edit_len && !c->input_drop) {
            c->edit[c->edit_len] = '\0'; process_input(c, c->edit);
        }
        if (c->fd >= 0) (void)send_line(c, "QUIT :stdin closed");
        c->quit = true;
        return;
    }
    for (ssize_t i = 0; i < n && !stop_signal && !c->quit; i++) {
        unsigned char ch = buf[i];
        if (!c->dumb) { terminal_byte(c, ch); continue; }
        if (ch == '\n') {
            if (c->input_drop) print_line(c, "*** Oversized/binary input discarded.");
            else {
                if (c->edit_len && c->edit[c->edit_len - 1] == '\r') c->edit_len--;
                c->edit[c->edit_len] = '\0';
                process_input(c, c->edit);
            }
            c->edit_len = 0; c->edit[0] = '\0'; c->input_drop = false;
        } else if (!c->input_drop) {
            if (!ch || c->edit_len >= INPUT_CAP - 1) {
                c->edit_len = 0; c->edit[0] = '\0'; c->input_drop = true;
            } else c->edit[c->edit_len++] = (char)ch;
        }
    }
}

static bool parse_port(const char *p, char out[6])
{
    char *end;
    unsigned long n;
    if (!*p) return false;
    for (const char *q = p; *q; q++)
        if (!isdigit((unsigned char)*q)) return false;
    errno = 0;
    n = strtoul(p, &end, 10);
    if (errno || *end || n < 1 || n > 65535) return false;
    (void)snprintf(out, 6, "%lu", n);
    return true;
}

static void identity(Client *c)
{
    struct passwd *pw = getpwuid(getuid());
    const char *nick = getenv("IRCNICK");
    const char *user = pw && pw->pw_name && *pw->pw_name ? pw->pw_name : "tinyirc";
    const char *real = pw && pw->pw_gecos && *pw->pw_gecos ? pw->pw_gecos : user;
    size_t n;
    if (!nick || !*nick) nick = user;
    if (!copy_text(c->nick, sizeof(c->nick), nick))
        (void)copy_text(c->nick, sizeof(c->nick), "tinyirc");
    n = strcspn(user, " \t\r\n:@");
    if (n >= sizeof(c->user)) n = sizeof(c->user) - 1;
    memcpy(c->user, user, n); c->user[n] = '\0';
    if (!n) (void)copy_text(c->user, sizeof(c->user), "tinyirc");
    n = strcspn(real, ",\r\n");
    if (n >= sizeof(c->real)) n = sizeof(c->real) - 1;
    memcpy(c->real, real, n); c->real[n] = '\0';
    if (!valid_message(c->real)) (void)copy_text(c->real, sizeof(c->real), c->user);
}

static bool options(Client *c, int argc, char **argv)
{
    int positional = 0;
    const char *env = getenv("IRCSERVER");
    if (env && *env) {
        const char *colon = strchr(env, ':');
        size_t len = colon ? (size_t)(colon - env) : strlen(env);
        if (!len || len >= sizeof(c->host) || (colon && strchr(colon + 1, ':')))
            return false;
        memcpy(c->host, env, len); c->host[len] = '\0';
        if (colon && !parse_port(colon + 1, c->port)) return false;
    }
    for (int i = 1; i < argc; i++) {
        const char *value = argv[i];
        if (strcmp(value, "-dumb") == 0) c->dumb = true;
        else if (strcmp(value, "--help") == 0 || strcmp(value, "-h") == 0) return false;
        else if (value[0] == '-') return false;
        else if (positional == 0) {
            if (!copy_text(c->nick, sizeof(c->nick), value)) return false;
            positional++;
        } else if (positional == 1) {
            if (!copy_text(c->host, sizeof(c->host), value)) return false;
            positional++;
        } else if (positional == 2) {
            if (!parse_port(value, c->port)) return false;
            positional++;
        } else return false;
    }
    return valid_nick(c->nick) && *c->host;
}

static void free_targets(Client *c)
{
    Target *t = c->targets, *next;
    while (t) { next = t->next; free(t); t = next; }
}

int main(int argc, char **argv)
{
    Client c = { 0 };
    c.fd = -1;
    c.hist_pos = -1;
    c.backoff = 1000;
    (void)copy_text(c.host, sizeof(c.host), "irc.libera.chat");
    (void)copy_text(c.port, sizeof(c.port), "6667");
    identity(&c);
    if (!options(&c, argc, argv)) {
        fprintf(stderr, "Usage: %s [nick] [server] [port] [-dumb]\n", argv[0]);
        return argc > 1 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) ? 0 : 2;
    }
    install_signal(SIGPIPE, SIG_IGN);
    install_signal(SIGINT, on_signal);
    install_signal(SIGTERM, on_signal);
    install_signal(SIGHUP, on_signal);
    install_signal(SIGTSTP, on_signal);
    install_signal(SIGCONT, on_signal);
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) c.dumb = true;
    print_line(&c, "*** %s", RELEASE);
    print_line(&c, "*** Copyright (C) 1991-2007 Nathan I. Laredo");
    print_line(&c, "*** Modified 2026 by @mmoroca & Arena.ai");
    print_line(&c, "*** WARNING: unencrypted TCP; no password masking or history protection.");
    if (!c.dumb && !enable_tty(&c)) c.dumb = true;
    while (!c.quit && !stop_signal) {
        struct pollfd pfd[2];
        nfds_t count = 0;
        int socket_index = -1, input_index = -1, wait = 1000, result;
        uint64_t now = milliseconds();
        expire_pings(&c, now);
        if (suspend_signal) suspend_tty(&c);
        if (refresh_signal) { refresh_signal = 0; prompt(&c); }
        if (c.esc == 1 && now - c.esc_time >= 120) { c.esc = 0; cycle_target(&c); }
        if (c.fd < 0 && now >= c.next_retry) {
            if (connect_host(&c)) c.backoff = 1000;
            else {
                print_line(&c, "*** Connection failed; retrying in %llu seconds.",
                           (unsigned long long)(c.backoff / 1000));
                c.next_retry = milliseconds() + c.backoff;
                if (c.backoff < 30000)
                    c.backoff = c.backoff < 15000 ? c.backoff * 2 : 30000;
            }
        }
        now = milliseconds();
        if (c.fd >= 0) {
            socket_index = (int)count;
            pfd[count].fd = c.fd; pfd[count].events = POLLIN; pfd[count++].revents = 0;
        } else {
            uint64_t remaining = c.next_retry > now ? c.next_retry - now : 0;
            if (remaining < (uint64_t)wait) wait = (int)remaining;
        }
        input_index = (int)count;
        pfd[count].fd = STDIN_FILENO; pfd[count].events = POLLIN; pfd[count++].revents = 0;
        if (c.esc == 1) {
            uint64_t remaining = now - c.esc_time < 120 ? 120 - (now - c.esc_time) : 0;
            if (remaining < (uint64_t)wait) wait = (int)remaining;
        }
        result = poll(pfd, count, wait);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) { print_line(&c, "*** poll failed."); break; }
        if (socket_index >= 0 && pfd[socket_index].revents && !read_server(&c)) {
            drop_connection(&c);
            print_line(&c, "*** Disconnected; reconnecting...");
        }
        if (input_index >= 0 && pfd[input_index].revents && !c.quit) stdin_ready(&c);
    }
    disable_tty(&c);
    if (c.fd >= 0) (void)close(c.fd);
    free_targets(&c);
    return stop_signal ? 128 + stop_signal : 0;
}
