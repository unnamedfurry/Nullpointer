#pragma once

#include "includes.h"

#ifdef NP_TELNET
BOOL exploit_jupyter_try(ipv4_t ip, uint16_t port);
#else
#define exploit_jupyter_try(ip, port) (FALSE)
#endif
