#pragma once
#include "includes.h"

#define MODULE_NAME_MAX 64

int  module_load_fd(int fd, const char *name);
void module_unload(const char *name);
void module_unload_all(void);
