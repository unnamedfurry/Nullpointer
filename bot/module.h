#pragma once
#include "includes.h"

#define MODULE_NAME_MAX 64
#define MODULES_MAX     8

int  module_load_fd(int fd, const char *name);
void module_unload(const char *name);
void module_unload_all(void);
int  module_list(char *buf, int maxlen);
