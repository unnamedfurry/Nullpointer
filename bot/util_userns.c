#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>

#include "includes.h"

static int rexec_setcap(int argc, char **argv)
{
    char exe[PATH_MAX + 1];
    char *setcap_paths[] = { "/usr/sbin/setcap", "/sbin/setcap", NULL };
    char *sudo_paths[] = { "/usr/bin/sudo", "/bin/sudo", NULL };
    int i, j, st;
    pid_t pid;
    extern char **environ;

    if (readlink("/proc/self/exe", exe, sizeof(exe) - 1) <= 0)
        return -1;
    exe[PATH_MAX] = '\0';

    for (i = 0; setcap_paths[i]; i++) {
        pid = fork();
        if (pid == -1) continue;
        if (pid == 0) {
            execl(setcap_paths[i], "setcap", "cap_net_raw+eip", exe, NULL);
            _exit(1);
        }
        waitpid(pid, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
            execv(exe, argv);
            return -1;
        }
    }

    for (i = 0; sudo_paths[i]; i++) {
        for (j = 0; setcap_paths[j]; j++) {
            pid = fork();
            if (pid == -1) continue;
            if (pid == 0) {
                execl(sudo_paths[i], "sudo", setcap_paths[j], "cap_net_raw+eip", exe, NULL);
                _exit(1);
            }
            waitpid(pid, &st, 0);
            if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
                execv(exe, argv);
                return -1;
            }
        }
    }

    return -1;
}

static int userns_try(void)
{
    int pipe_fd[2], carr_fd[2];
    pid_t pid;
    char path[64], buf[64], status;
    int fd;

    if (geteuid() == 0)
        return 0;

    if (pipe(pipe_fd) != 0 || pipe(carr_fd) != 0)
        return -1;

    pid = fork();
    if (pid < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        close(carr_fd[0]);
        close(carr_fd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipe_fd[1]);
        close(carr_fd[0]);
        if (unshare(CLONE_NEWUSER) != 0) {
            status = 1;
            write(carr_fd[1], &status, 1);
            close(pipe_fd[0]);
            close(carr_fd[1]);
            _exit(1);
        }
        status = 0;
        write(carr_fd[1], &status, 1);
        close(carr_fd[1]);
        {
            char c;
            if (read(pipe_fd[0], &c, 1) != 1) {
                close(pipe_fd[0]);
                _exit(1);
            }
        }
        close(pipe_fd[0]);
        return 0;
    }

    close(pipe_fd[0]);
    close(carr_fd[1]);
    if (read(carr_fd[0], &status, 1) != 1 || status != 0) {
        close(pipe_fd[1]);
        close(carr_fd[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }
    close(carr_fd[0]);
    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)pid);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        close(pipe_fd[1]);
        waitpid(pid, NULL, 0);
        return -1;
    }
    snprintf(buf, sizeof(buf), "0 %lu 1", (unsigned long)getuid());
    write(fd, buf, strlen(buf));
    close(fd);

    snprintf(path, sizeof(path), "/proc/%d/gid_map", (int)pid);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        close(pipe_fd[1]);
        waitpid(pid, NULL, 0);
        return -1;
    }
    snprintf(buf, sizeof(buf), "0 %lu 1", (unsigned long)getgid());
    write(fd, buf, strlen(buf));
    close(fd);

    write(pipe_fd[1], "x", 1);
    close(pipe_fd[1]);
    _exit(0);
}

static int rexec_capsh(int argc, char **argv)
{
    char exe[PATH_MAX + 1];
    char cmd[PATH_MAX + 256];
    char *capsh_paths[] = { "/usr/bin/capsh", "/bin/capsh", NULL };
    char *new_argv[] = { "capsh", "--keep=1", "--caps=cap_net_raw+ep", "--", "-c", cmd, NULL };
    int i, len;
    extern char **environ;

    if (readlink("/proc/self/exe", exe, sizeof(exe) - 1) <= 0)
        return -1;
    exe[PATH_MAX] = '\0';
    len = snprintf(cmd, sizeof(cmd), "exec %s", exe);
    for (i = 1; i < argc && len < (int)sizeof(cmd) - 32; i++)
        len += snprintf(cmd + len, sizeof(cmd) - len, " %s", argv[i]);

    for (i = 0; capsh_paths[i]; i++) {
        new_argv[0] = (char *)capsh_paths[i];
        execve(capsh_paths[i], new_argv, environ);
    }
    return -1;
}

static int rexec_unshare(int argc, char **argv)
{
    char exe[PATH_MAX + 1];
    char *unshare_paths[] = { "/usr/bin/unshare", "/bin/unshare", NULL };
    char *new_argv[64];
    int i;
    extern char **environ;

    if (readlink("/proc/self/exe", exe, sizeof(exe) - 1) <= 0)
        return -1;
    exe[PATH_MAX] = '\0';
    if (argc + 6 > 64)
        return -1;

    new_argv[0] = "unshare";
    new_argv[1] = "-U";
    new_argv[2] = "-r";
    new_argv[3] = "-f";
    new_argv[4] = exe;
    for (i = 0; i < argc; i++)
        new_argv[5 + i] = argv[i];
    new_argv[5 + argc] = NULL;

    for (i = 0; unshare_paths[i]; i++) {
        new_argv[0] = unshare_paths[i];
        execve(unshare_paths[i], new_argv, environ);
    }
    return -1;
}

static int rexec_proot(int argc, char **argv)
{
    char exe[PATH_MAX + 1];
    char *proot_paths[] = { "/usr/bin/proot", "/bin/proot", NULL };
    char *new_argv[64];
    int i;
    extern char **environ;

    if (readlink("/proc/self/exe", exe, sizeof(exe) - 1) <= 0)
        return -1;
    exe[PATH_MAX] = '\0';
    if (argc + 4 > 64)
        return -1;
    new_argv[0] = "proot";
    new_argv[1] = "-0";
    new_argv[2] = exe;
    for (i = 0; i < argc; i++)
        new_argv[3 + i] = argv[i];
    new_argv[3 + argc] = NULL;
    for (i = 0; proot_paths[i]; i++)
        execve(proot_paths[i], new_argv, environ);
    return -1;
}

static int rexec_bwrap(int argc, char **argv)
{
    char exe[PATH_MAX + 1];
    char *bwrap_paths[] = { "/usr/bin/bwrap", "/usr/bin/bubblewrap", "/bin/bwrap", NULL };
    char *new_argv[80];
    int i, n;
    extern char **environ;

    if (readlink("/proc/self/exe", exe, sizeof(exe) - 1) <= 0)
        return -1;
    exe[PATH_MAX] = '\0';
    if (argc + 10 > 80)
        return -1;
    n = 0;
    new_argv[n++] = "bwrap";
    new_argv[n++] = "--unshare-user";
    new_argv[n++] = "--uid"; new_argv[n++] = "0";
    new_argv[n++] = "--gid"; new_argv[n++] = "0";
    new_argv[n++] = "--ro-bind"; new_argv[n++] = "/"; new_argv[n++] = "/";
    new_argv[n++] = "--proc"; new_argv[n++] = "/proc";
    new_argv[n++] = "--dev"; new_argv[n++] = "/dev";
    new_argv[n++] = "--";
    new_argv[n++] = exe;
    for (i = 1; i < argc; i++)
        new_argv[n++] = argv[i];
    new_argv[n] = NULL;

    for (i = 0; bwrap_paths[i]; i++) {
        new_argv[0] = (char *)bwrap_paths[i];
        execve(bwrap_paths[i], new_argv, environ);
    }
    return -1;
}

static int rexec_run0(int argc, char **argv)
{
    char exe[PATH_MAX + 1];
    char *run0_paths[] = { "/usr/bin/run0", "/bin/run0", NULL };
    char *new_argv[64];
    int i;
    extern char **environ;

    if (readlink("/proc/self/exe", exe, sizeof(exe) - 1) <= 0)
        return -1;
    exe[PATH_MAX] = '\0';
    if (argc + 6 > 64)
        return -1;
    new_argv[0] = "run0";
    new_argv[1] = "run";
    new_argv[2] = "--no-ask-password";
    new_argv[3] = "--property=AmbientCapabilities=CAP_NET_RAW";
    new_argv[4] = "--";
    new_argv[5] = exe;
    for (i = 1; i < argc; i++)
        new_argv[5 + i] = argv[i];
    new_argv[5 + argc] = NULL;

    for (i = 0; run0_paths[i]; i++) {
        new_argv[0] = (char *)run0_paths[i];
        execve(run0_paths[i], new_argv, environ);
    }
    return -1;
}

static int rexec_sudo_capsh(int argc, char **argv)
{
    char exe[PATH_MAX + 1], cmd[PATH_MAX + 256];
    char *sudo_paths[] = { "/usr/bin/sudo", "/bin/sudo", NULL };
    char *capsh_paths[] = { "/usr/bin/capsh", "/bin/capsh", NULL };
    char *new_argv[] = { "sudo", "capsh", "--keep=1", "--caps=cap_net_raw+ep", "--", "-c", cmd, NULL };
    int i, j, len;
    extern char **environ;

    if (readlink("/proc/self/exe", exe, sizeof(exe) - 1) <= 0)
        return -1;
    exe[PATH_MAX] = '\0';
    len = snprintf(cmd, sizeof(cmd), "exec %s", exe);
    for (i = 1; i < argc && len < (int)sizeof(cmd) - 32; i++)
        len += snprintf(cmd + len, sizeof(cmd) - len, " %s", argv[i]);

    for (i = 0; sudo_paths[i]; i++) {
        for (j = 0; capsh_paths[j]; j++) {
            new_argv[0] = (char *)sudo_paths[i];
            new_argv[1] = (char *)capsh_paths[j];
            execve(sudo_paths[i], new_argv, environ);
        }
    }
    return -1;
}

static int rexec_doas_capsh(int argc, char **argv)
{
    char exe[PATH_MAX + 1], cmd[PATH_MAX + 256];
    char *doas_paths[] = { "/usr/bin/doas", "/bin/doas", NULL };
    char *capsh_paths[] = { "/usr/bin/capsh", "/bin/capsh", NULL };
    char *new_argv[] = { "doas", "-n", NULL, "--keep=1", "--caps=cap_net_raw+ep", "--", "-c", cmd, NULL };
    int i, j, len;
    extern char **environ;

    if (readlink("/proc/self/exe", exe, sizeof(exe) - 1) <= 0)
        return -1;
    exe[PATH_MAX] = '\0';
    len = snprintf(cmd, sizeof(cmd), "exec %s", exe);
    for (i = 1; i < argc && len < (int)sizeof(cmd) - 32; i++)
        len += snprintf(cmd + len, sizeof(cmd) - len, " %s", argv[i]);

    for (i = 0; doas_paths[i]; i++) {
        for (j = 0; capsh_paths[j]; j++) {
            new_argv[0] = (char *)doas_paths[i];
            new_argv[2] = (char *)capsh_paths[j];
            execve(doas_paths[i], new_argv, environ);
        }
    }
    return -1;
}

int util_privilege_try(int argc, char **argv)
{
    if (geteuid() == 0)
        return 0;
    if (userns_try() == 0)
        return 0;
    rexec_setcap(argc, argv);
    rexec_capsh(argc, argv);
    rexec_sudo_capsh(argc, argv);
    rexec_unshare(argc, argv);
    rexec_bwrap(argc, argv);
    rexec_proot(argc, argv);
    rexec_run0(argc, argv);
    rexec_doas_capsh(argc, argv);
    return -1;
}
