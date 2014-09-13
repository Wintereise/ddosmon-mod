/*
 * nullable.c
 * Purpose: Threshold based exemptions
 *
 * Copyright (c) 2014 - AzureTemple, Inc.
 *
 * Adapted partially from code (c) 2009 - 2012, Tortoiselabs, LLC.
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
#include "patricia.h"
#include "ipstate.h"
#include "hook.h"
#include "action.h"

typedef struct _nullable nullable_t;
typedef int (*nullable_validator_f)(packet_info_t *packet, iprecord_t *irec, nullable_t *e);

typedef enum {
	NULLABLE_TYPE_ANY = 0,
	NULLABLE_TYPE_SRC = 1,
	NULLABLE_TYPE_DST = 2,
	NULLABLE_TYPE_COUNT
} nullable_type_t;

struct _nullable {
	struct _nullable *next;
	unsigned int ip;
	unsigned short cidrlen;
	nullable_validator_f val;
	nullable_type_t etype;
};

static nullable_t *e_list = NULL;

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
nullable_validator_any(packet_info_t *packet, iprecord_t *irec, nullable_t *e)
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
nullable_validator_src(packet_info_t *packet, iprecord_t *irec, nullable_t *e)
{
	char srcaddr[IN6ADDRSZ], ip[IN6ADDRSZ];

	memcpy(srcaddr, &packet->pkt_src, INADDRSZ);
	memcpy(ip, &e->ip, INADDRSZ);

	return comp_with_mask(srcaddr, ip, e->cidrlen);
}

static int
nullable_validator_dst(packet_info_t *packet, iprecord_t *irec, nullable_t *e)
{
	char dstaddr[IN6ADDRSZ], ip[IN6ADDRSZ];

	memcpy(dstaddr, &packet->pkt_dst, INADDRSZ);
	memcpy(ip, &e->ip, INADDRSZ);

	return comp_with_mask(dstaddr, ip, e->cidrlen);
}

static nullable_validator_f nullable_validator_tab[NULLABLE_TYPE_COUNT] = {
	nullable_validator_any,
	nullable_validator_src,
	nullable_validator_dst
};

static void
hook_check_nullable(packet_info_t *packet, iprecord_t *irec, int *do_trigger)
{
	nullable_t *e;
	int ret;

	for (e = e_list; e != NULL; e = e->next)
	{
		ret = e->val(packet, irec, e);

		DPRINTF("eval %p res %d\n", e, ret);
		if (ret)
		{
			DPRINTF("nullable list matched: should null this traffic %p (%p)\n", packet, irec);
			*do_trigger = 1;
			return;
		}
		else
		{
			DPRINTF("Triggers matched, but traffic is not defined to be nulled %p (%p)\n", packet, irec);
		}
	}
}

void
module_cons(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		nullable_t *e;
		char cidr[INET6_ADDRSTRLEN + 10];
		char *len;

		mowgli_strlcpy(cidr, ce->varname, sizeof cidr);

		len = strrchr(cidr, '/');
		if (len == NULL)
			continue;

		*len++ = 0;

		e = calloc(sizeof(nullable_t), 1);
		e->next = e_list;
		inet_pton(AF_INET, cidr, &e->ip);
		e->cidrlen = atoi(len);

		e->etype = NULLABLE_TYPE_ANY;
		if (!strcasecmp(ce->vardata, "any"))
			e->etype = NULLABLE_TYPE_ANY;
		else if (!strcasecmp(ce->vardata, "src"))
			e->etype = NULLABLE_TYPE_SRC;
		else if (!strcasecmp(ce->vardata, "dst"))
			e->etype = NULLABLE_TYPE_DST;
		e->val = nullable_validator_tab[e->etype];

		DPRINTF("cidr: %s/%d type %d (%s)\n", cidr, e->cidrlen, e->etype, ce->vardata);

		e_list = e;
	}

	HOOK_REGISTER(HOOK_CHECK_NULLABLE, hook_check_nullable);
}
