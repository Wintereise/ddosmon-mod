/*
 * stdinc.h: Standard includes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

/*
 * Configuration parameters.
 */

/*
 * Expiry check time.
 */
#define EXPIRY_CHECK		30

/*
 * enable global DEBUG mode.
 */
//#undef DEBUG

/*
 * Stop editing here.
 */

#ifdef DEBUG
#define DPRINTF(msg, ...) printf("%s:%d (%s): " msg, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#else
#define DPRINTF(msg, ...) {}
#endif

#ifdef PREFIX
#define MODULEDIR PREFIX "/modules"
#define CONFIGDIR PREFIX "/etc"
#define CONFIGFILE PREFIX "/etc/ddosmon.conf"
#endif

#include "confparse.h"

extern time_t get_time(void);

extern size_t strlcat(char *dest, const char *src, size_t count);
extern size_t strlcpy(char *dest, const char *src, size_t count);

extern void module_cons(config_entry_t *ce);
