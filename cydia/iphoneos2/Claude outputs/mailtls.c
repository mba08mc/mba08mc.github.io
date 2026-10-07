/* mailtls - lets iPhone OS 2's Mail talk to today's mail servers.
 *
 * Mail on iPhone OS 2 only knows SSL 3 / TLS 1.0, which Gmail, iCloud, Yahoo etc. now refuse.
 * mailtls sits on 127.0.0.1: Mail connects to it in plain text (never leaves the phone), and
 * mailtls opens a modern TLS 1.2 connection (Mbed TLS) to the real server and relays bytes.
 *
 * The package runs one listener per server from launchd (-l); each connection Mail opens
 * gets its own forked process. Idle listeners just sit in accept() and use no battery.
 * (launchd's inetd-style sockets didn't work reliably on iPhone OS 2.1.)
 *
 *   mailtls -l localport [options] host port  listen on 127.0.0.1:localport (what the package uses)
 *   mailtls [options] host port               relay stdin/stdout <-> TLS to host:port (testing)
 *
 * options:
 *   -s        SMTP STARTTLS: connect in plain text, upgrade with STARTTLS (e.g. iCloud :587)
 *   -c file   CA bundle (default /usr/share/mailtls/cacert.pem)
 *   -k        ignore certificate dates (for a phone whose clock is wrong); names and
 *             signatures are still checked
 *
 * Errors go to syslog (never stderr: under launchd stderr is the client socket).
 *
 * Debugging: while /tmp/mailtls-debug exists, every connection appends a transcript to
 * /tmp/mailtls.log (timings, TLS result, and the conversation with passwords blanked out).
 *   touch /tmp/mailtls-debug     ...try in Mail...     cat /tmp/mailtls.log
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#define DEFAULT_CA "/usr/share/mailtls/cacert.pem"
#define IDLE_SECONDS (35 * 60)   /* IMAP IDLE re-issues every 29 minutes */

static const char *g_host, *g_port, *g_ca = DEFAULT_CA;
static int g_starttls, g_nodates, g_imap;
static int g_in = 0, g_out = 1;

/* ---- debug transcript ---------------------------------------------------- */

static int g_dbg = -1;              /* log fd, or -1 */
static struct timeval g_t0;
static int g_hide_next;             /* next client data is a SASL reply: blank it */

static void dbg_open(void)
{
    if (access("/tmp/mailtls-debug", F_OK) != 0) return;
    g_dbg = open("/tmp/mailtls.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    gettimeofday(&g_t0, NULL);
}

static void dbg(const char *fmt, ...)
{
    char line[600];
    struct timeval now;
    va_list ap;
    int n;
    long ms;
    if (g_dbg < 0) return;
    gettimeofday(&now, NULL);
    ms = (now.tv_sec - g_t0.tv_sec) * 1000L + (now.tv_usec - g_t0.tv_usec) / 1000L;
    n = snprintf(line, sizeof(line), "[%d %s:%s +%ldms] ", (int)getpid(), g_host, g_port, ms);
    va_start(ap, fmt);
    n += vsnprintf(line + n, sizeof(line) - n - 2, fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(line) - 2) n = sizeof(line) - 2;
    line[n++] = '\n';
    if (write(g_dbg, line, n) < 0) { /* nothing to do */ }
}

static int starts_ci(const unsigned char *p, size_t n, const char *word)
{
    size_t i, w = strlen(word);
    if (n < w) return 0;
    for (i = 0; i < w; i++) if (toupper(p[i]) != word[i]) return 0;
    return 1;
}

/* Logs one chunk of the conversation (dir "C>" = from Mail, "S>" = from the server). */
static void dbg_data(const char *dir, const unsigned char *p, size_t n)
{
    char out[400];
    size_t i, o = 0, show = n;
    int client = dir[0] == 'C';
    if (g_dbg < 0) return;
    if (client && g_hide_next) { g_hide_next = 0; dbg("%s [%u bytes, password data hidden]", dir, (unsigned)n); return; }
    if (client) {
        /* IMAP "tag LOGIN user pass" / SMTP "AUTH PLAIN xxx": keep only the start */
        size_t sp = 0;
        while (sp < n && p[sp] != ' ') sp++;
        if (starts_ci(p, n, "AUTH ")) {
            size_t e = 5;
            while (e < n && p[e] != ' ' && p[e] != '\r') e++;
            show = e;
        } else if (sp + 1 < n && (starts_ci(p + sp + 1, n - sp - 1, "LOGIN ") || starts_ci(p + sp + 1, n - sp - 1, "AUTHENTICATE "))) {
            show = sp + 7;
        }
    } else if (n >= 3 && p[0] == '3' && p[1] == '3' && p[2] == '4') {
        g_hide_next = 1;            /* SMTP 334: server asks for a login step */
    } else if (n >= 1 && p[0] == '+') {
        g_hide_next = 1;            /* IMAP continuation during AUTHENTICATE */
    }
    for (i = 0; i < show && i < 300 && o < sizeof(out) - 5; i++) {
        unsigned char c = p[i];
        if (c == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c < 32 || c > 126) out[o++] = '.';
        else out[o++] = (char)c;
    }
    out[o] = 0;
    dbg("%s %s%s (%u bytes)", dir, out, (show < n) ? " [rest hidden]" : (n > 300 ? "..." : ""), (unsigned)n);
}

static void fail_to_client(const char *why)
{
    char line[300];
    if (g_imap) snprintf(line, sizeof(line), "* BYE mailtls: %s\r\n", why);
    else snprintf(line, sizeof(line), "421 mailtls: %s\r\n", why);
    if (write(g_out, line, strlen(line)) < 0) { /* client already gone */ }
    syslog(LOG_ERR, "%s:%s: %s", g_host, g_port, why);
    dbg("ERROR %s", why);
}

static void tls_error(const char *what, int r)
{
    char buf[200], msg[300];
    mbedtls_strerror(r, buf, sizeof(buf));
    snprintf(msg, sizeof(msg), "%s failed: %s (-0x%04x)", what, buf, (unsigned)-r);
    fail_to_client(msg);
}

/* Connecting + TLS setup must finish within a minute, or Mail gets told why instead of
 * waiting forever. */
static void on_alarm(int sig)
{
    (void)sig;
    fail_to_client("timed out reaching the server (see /tmp/mailtls.log with debugging on)");
    _exit(1);
}

/* ---- plain-text SMTP before STARTTLS ---------------------------------- */

/* Reads one SMTP reply (possibly multi-line). Returns the code, copies the first line. */
static int smtp_reply(int fd, char *first, size_t firstlen)
{
    char line[1024];
    size_t n = 0;
    int code = -1, firstdone = 0;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return -1;
        if (n < sizeof(line) - 1) line[n++] = c;
        if (c != '\n') continue;
        line[n] = 0;
        if (!firstdone && first) {
            snprintf(first, firstlen, "%s", line);
            firstdone = 1;
        }
        if (n >= 4) {
            code = atoi(line);
            if (line[3] == ' ') return code;    /* last line of the reply */
        } else return -1;
        n = 0;
    }
}

static int smtp_send(int fd, const char *s)
{
    size_t len = strlen(s);
    return write(fd, s, len) == (ssize_t)len ? 0 : -1;
}

/* ---- certificate checks ------------------------------------------------ */

static int verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    (void)ctx; (void)crt; (void)depth;
    if (g_nodates) *flags &= ~(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
    return 0;
}

/* ---- connecting to the server ---------------------------------------- */

/* Like mbedtls_net_connect, but tries IPv4 addresses before IPv6 and gives each address
 * 10 seconds. iPhone OS 2 will happily pick an IPv6 address on a network where IPv6
 * doesn't actually get anywhere, and then sit in connect() for over a minute. */
static int connect_one(const struct addrinfo *ai)
{
    int fd, fl, err = 0;
    fd_set wr;
    struct timeval tv;
    socklen_t len = sizeof(err);
    char addr[64] = "?";

    if (ai->ai_family == AF_INET)
        inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, addr, sizeof(addr));
    else if (ai->ai_family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, addr, sizeof(addr));

    fd = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { dbg("socket(%s) failed: %s", addr, strerror(errno)); return -1; }
    fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
        if (errno != EINPROGRESS) { dbg("connect %s: %s", addr, strerror(errno)); close(fd); return -1; }
        FD_ZERO(&wr);
        FD_SET(fd, &wr);
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        if (select(fd + 1, NULL, &wr, NULL, &tv) <= 0) { dbg("connect %s: timed out", addr); close(fd); return -1; }
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err) {
            dbg("connect %s: %s", addr, strerror(err ? err : errno)); close(fd); return -1;
        }
    }
    fcntl(fd, F_SETFL, fl);
    dbg("TCP connected to %s", addr);
    return fd;
}

static int connect_server(mbedtls_net_context *ctx)
{
    struct addrinfo hints, *res = NULL, *ai;
    int pass, fd, r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    r = getaddrinfo(g_host, g_port, &hints, &res);
    if (r != 0 || !res) { dbg("DNS lookup failed: %s", gai_strerror(r)); return MBEDTLS_ERR_NET_UNKNOWN_HOST; }
    dbg("DNS lookup done");
    for (pass = 0; pass < 2; pass++) {             /* pass 0: IPv4, pass 1: everything else */
        for (ai = res; ai; ai = ai->ai_next) {
            if ((ai->ai_family == AF_INET) != (pass == 0)) continue;
            if ((fd = connect_one(ai)) >= 0) { freeaddrinfo(res); ctx->fd = fd; return 0; }
        }
    }
    freeaddrinfo(res);
    return MBEDTLS_ERR_NET_CONNECT_FAILED;
}

/* ---- relay ------------------------------------------------------------- */

static int write_all(int fd, const unsigned char *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int ssl_write_all(mbedtls_ssl_context *ssl, const unsigned char *p, size_t n)
{
    while (n) {
        int w = mbedtls_ssl_write(ssl, p, n);
        if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (w < 0) return w;
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int relay(void)
{
    mbedtls_net_context srv;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    unsigned char buf[16384];
    char greeting[512] = "";
    int r, rc = 1, client_done = 0;

    mbedtls_net_init(&srv);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&ca);
    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);
    dbg_open();
    dbg("Mail connected%s", g_starttls ? " (STARTTLS mode)" : "");
    signal(SIGALRM, on_alarm);
    alarm(60);

    if ((r = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char *)"mailtls", 7)) != 0) {
        tls_error("random seed", r); goto out;
    }
    if ((r = mbedtls_x509_crt_parse_file(&ca, g_ca)) < 0) {
        tls_error("loading the certificate list", r); goto out;
    }
    dbg("certificates loaded");
    if ((r = connect_server(&srv)) != 0) {
        tls_error("connecting", r); goto out;
    }

    if (g_starttls) {
        if (smtp_reply(srv.fd, greeting, sizeof(greeting)) != 220) { fail_to_client("no SMTP greeting"); goto out; }
        if (smtp_send(srv.fd, "EHLO mailtls.local\r\n") || smtp_reply(srv.fd, NULL, 0) != 250) { fail_to_client("EHLO refused"); goto out; }
        if (smtp_send(srv.fd, "STARTTLS\r\n") || smtp_reply(srv.fd, NULL, 0) != 220) { fail_to_client("STARTTLS refused"); goto out; }
    }

    if ((r = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        tls_error("TLS setup", r); goto out;
    }
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
    mbedtls_ssl_conf_verify(&conf, verify_cb, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    if ((r = mbedtls_ssl_setup(&ssl, &conf)) != 0 || (r = mbedtls_ssl_set_hostname(&ssl, g_host)) != 0) {
        tls_error("TLS setup", r); goto out;
    }
    mbedtls_ssl_set_bio(&ssl, &srv, mbedtls_net_send, mbedtls_net_recv, NULL);
    while ((r = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) {
            uint32_t v = mbedtls_ssl_get_verify_result(&ssl);
            if (v != 0 && v != (uint32_t)-1) {
                char vb[256], msg[320];
                mbedtls_x509_crt_verify_info(vb, sizeof(vb), "", v);
                vb[strcspn(vb, "\n")] = 0;
                snprintf(msg, sizeof(msg), "certificate rejected: %s%s", vb,
                         (v & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE)) ? " (is the phone's date right?)" : "");
                fail_to_client(msg);
            } else tls_error("TLS handshake", r);
            goto out;
        }
    }
    syslog(LOG_INFO, "%s:%s connected (%s, %s)", g_host, g_port, mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl));
    alarm(0);
    dbg("TLS up: %s %s", mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl));

    /* STARTTLS: the client never saw the server, so give it the original greeting now. */
    if (g_starttls) dbg_data("S>", (const unsigned char *)greeting, strlen(greeting));
    if (g_starttls && write_all(g_out, (const unsigned char *)greeting, strlen(greeting))) goto out;

    for (;;) {
        fd_set rd;
        struct timeval tv;
        int maxfd = (!client_done && g_in > srv.fd) ? g_in : srv.fd;

        /* data Mbed TLS already decrypted doesn't show up in select() */
        while (mbedtls_ssl_get_bytes_avail(&ssl) > 0) {
            r = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
            if (r <= 0) break;
            dbg_data("S>", buf, (size_t)r);
            if (write_all(g_out, buf, (size_t)r)) { dbg("write to Mail failed (errno %d)", errno); goto out; }
        }
        FD_ZERO(&rd);
        if (!client_done) FD_SET(g_in, &rd);
        FD_SET(srv.fd, &rd);
        /* after Mail hangs up, pass on whatever the server still sends (e.g. "BYE"), briefly */
        tv.tv_sec = client_done ? 10 : IDLE_SECONDS;
        tv.tv_usec = 0;
        r = select(maxfd + 1, &rd, NULL, NULL, &tv);
        if (r < 0) { if (errno == EINTR) continue; goto out; }
        if (r == 0) { syslog(LOG_INFO, "%s:%s idle, closing", g_host, g_port); dbg("idle/linger timeout, closing"); break; }

        if (!client_done && FD_ISSET(g_in, &rd)) {
            ssize_t n = read(g_in, buf, sizeof(buf));
            if (n <= 0) { client_done = 1; dbg("Mail closed its side (%s)", n == 0 ? "EOF" : strerror(errno)); continue; }  /* Mail hung up */
            dbg_data("C>", buf, (size_t)n);
            if ((r = ssl_write_all(&ssl, buf, (size_t)n)) != 0) { syslog(LOG_ERR, "write to server: -0x%04x", (unsigned)-r); dbg("write to server failed -0x%04x", (unsigned)-r); goto out; }
        }
        if (FD_ISSET(srv.fd, &rd)) {
            r = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (r == 0 || r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == MBEDTLS_ERR_NET_CONN_RESET) { dbg("server closed the connection"); break; }
            if (r < 0) { syslog(LOG_ERR, "read from server: -0x%04x", (unsigned)-r); dbg("read from server failed -0x%04x", (unsigned)-r); goto out; }
            dbg_data("S>", buf, (size_t)r);
            if (write_all(g_out, buf, (size_t)r)) { dbg("write to Mail failed (errno %d)", errno); goto out; }
        }
    }
    mbedtls_ssl_close_notify(&ssl);
    rc = 0;
out:
    dbg("done (%s)", rc ? "error" : "ok");
    if (g_dbg >= 0) { close(g_dbg); g_dbg = -1; }
    mbedtls_net_free(&srv);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&ca);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    return rc;
}

/* ---- standalone listener (testing / non-launchd use) ------------------- */

static int listen_loop(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a;
    if (s < 0) return 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(s, 8) < 0) { perror("mailtls: listen"); return 1; }
    signal(SIGCHLD, SIG_IGN);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; return 1; }
        if (fork() == 0) {
            close(s);
            g_in = g_out = c;
            _exit(relay());
        }
        close(c);
    }
}

int main(int argc, char **argv)
{
    int ch, lport = 0;
    signal(SIGPIPE, SIG_IGN);
    openlog("mailtls", LOG_PID, LOG_MAIL);
    while ((ch = getopt(argc, argv, "skc:l:")) != -1) {
        switch (ch) {
            case 's': g_starttls = 1; break;
            case 'k': g_nodates = 1; break;
            case 'c': g_ca = optarg; break;
            case 'l': lport = atoi(optarg); break;
            default:
                fprintf(stderr, "usage: mailtls [-s] [-k] [-c cafile] [-l localport] host port\n");
                return 2;
        }
    }
    if (argc - optind != 2) {
        fprintf(stderr, "usage: mailtls [-s] [-k] [-c cafile] [-l localport] host port\n");
        return 2;
    }
    g_host = argv[optind];
    g_port = argv[optind + 1];
    g_imap = strcmp(g_port, "993") == 0 || strcmp(g_port, "143") == 0;
    if (lport) return listen_loop(lport);
    return relay();
}
