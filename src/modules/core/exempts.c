/*
 * exempts.c
 * Purpose: Exemptions against static or dynamic triggers.
 *
 * Copyright (c) 2009 - 2012, TortoiseLabs LLC.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "confparse.h"
#include "patricia.h"
#include "ipstate.h"
#include "hook.h"
#include "action.h"

typedef struct _exempt exempt_t;
typedef int (*exempt_validator_f)(packet_info_t *packet, iprecord_t *irec, exempt_t *e);

typedef enum {
	EXEMPT_TYPE_ANY = 0,
	EXEMPT_TYPE_SRC = 1,
	EXEMPT_TYPE_DST = 2,
	EXEMPT_TYPE_COUNT
} exempt_type_t;

struct _exempt {
	struct _exempt *next;
	unsigned int ip;
	unsigned short cidrlen; 
	exempt_validator_f val;
	exempt_type_t etype;
};

static exempt_t *e_list = NULL;

#ifndef INADDRSZ
#define INADDRSZ 4
#endif
#ifndef IN6ADDRSZ
#define IN6ADDRSZ 16
#endif
#ifndef INT16SZ
#define INT16SZ 2
#endif

static int
exempt_validator_any(packet_info_t *packet, iprecord_t *irec, exempt_t *e)
{
	char srcaddr[IN6ADDRSZ], dstaddr[IN6ADDRSZ], ip[IN6ADDRSZ];

	memcpy(srcaddr, &packet->pkt_src, INADDRSZ);
	memcpy(dstaddr, &packet->pkt_dst, INADDRSZ);
	memcpy(ip, &e->ip, INADDRSZ);

	if (comp_with_mask(srcaddr, ip, e->cidrlen))
		return 1;

	if (comp_with_mask(dstaddr, ip, e->cidrlen))
		return 1;

	return 0;
}

static int
exempt_validator_src(packet_info_t *packet, iprecord_t *irec, exempt_t *e)
{
	char srcaddr[IN6ADDRSZ], ip[IN6ADDRSZ];

	memcpy(srcaddr, &packet->pkt_src, INADDRSZ);
	memcpy(ip, &e->ip, INADDRSZ);

	return comp_with_mask(srcaddr, ip, e->cidrlen);
}

static int
exempt_validator_dst(packet_info_t *packet, iprecord_t *irec, exempt_t *e)
{
	char dstaddr[IN6ADDRSZ], ip[IN6ADDRSZ];

	memcpy(dstaddr, &packet->pkt_dst, INADDRSZ);
	memcpy(ip, &e->ip, INADDRSZ);

	return comp_with_mask(dstaddr, ip, e->cidrlen);
}

static exempt_validator_f exempt_validator_tab[EXEMPT_TYPE_COUNT] = {
	exempt_validator_any,
	exempt_validator_src,
	exempt_validator_dst
};

static void
hook_check_exempt(packet_info_t *packet, iprecord_t *irec, int *do_trigger)
{
	exempt_t *e;
	int ret;

	for (e = e_list; e != NULL; e = e->next)
	{
		ret = e->val(packet, irec, e);

		DPRINTF("eval %p res %d\n", e, ret);
		if (ret)
		{
			DPRINTF("should exempt this traffic %p (%p)\n", packet, irec);
			*do_trigger = 0;
			return;
		}
	}
}

void
module_cons(mowgli_eventloop_t *eventloop, config_entry_t *entry)
{
	config_entry_t *ce;

	for (ce = entry; ce != NULL; ce = ce->ce_next)
	{
		exempt_t *e;
		char cidr[INET6_ADDRSTRLEN + 10];
		char *len;

		strlcpy(cidr, ce->ce_varname, INET6_ADDRSTRLEN + 10);

		len = strrchr(cidr, '/');
		if (len == NULL)
			continue;

		*len++ = 0;

		e = calloc(sizeof(exempt_t), 1);
		e->next = e_list;
		inet_pton(AF_INET, cidr, &e->ip);
		e->cidrlen = atoi(len);

		e->etype = EXEMPT_TYPE_ANY;
		if (!strcasecmp(ce->ce_vardata, "any"))
			e->etype = EXEMPT_TYPE_ANY;
		else if (!strcasecmp(ce->ce_vardata, "src"))
			e->etype = EXEMPT_TYPE_SRC;
		else if (!strcasecmp(ce->ce_vardata, "dst"))
			e->etype = EXEMPT_TYPE_DST;
		e->val = exempt_validator_tab[e->etype];

		DPRINTF("cidr: %s/%d type %d (%s)\n", cidr, e->cidrlen, e->etype, ce->ce_vardata);

		e_list = e;
	}

	HOOK_REGISTER(HOOK_CHECK_EXEMPT, hook_check_exempt);
}
