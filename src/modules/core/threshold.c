/*
 * threshold.c
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




typedef enum {
	THRESHOLD_TYPE_ANY = 0,
	THRESHOLD_TYPE_SRC = 1,
	THRESHOLD_TYPE_DST = 2,
	THRESHOLD_TYPE_COUNT
} threshold_type_t;

typedef struct _threshold {
	struct _threshold *next;
	unsigned int ip, mbps, pps;
	unsigned char protocol, tcp_synonly;
	unsigned short cidrlen;
	threshold_type_t etype;
} threshold_t;

static threshold_t *th_list[IPPROTO_MAX + 1];

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
threshold_validator_any(packet_info_t *packet, iprecord_t *irec, threshold_t *e)
{
	char srcaddr[IN6ADDRSZ], dstaddr[IN6ADDRSZ], ip[IN6ADDRSZ], temp[IN6ADDRSZ];

	memcpy(srcaddr, &packet->pkt_src, INADDRSZ);
	memcpy(dstaddr, &packet->pkt_dst, INADDRSZ);
	memcpy(ip, &e->ip, INADDRSZ);
    inet_ntop(AF_INET, &e->ip, temp, IN6ADDRSZ);
    DPRINTF("thres: looking up %s/%d\n", temp, e->cidrlen);

	if (comp_with_mask(srcaddr, ip, e->cidrlen))
		return 1;

	if (comp_with_mask(dstaddr, ip, e->cidrlen))
		return 1;

	return 0;
}

static int
threshold_validator_src(packet_info_t *packet, iprecord_t *irec, threshold_t *e)
{
	char srcaddr[IN6ADDRSZ], ip[IN6ADDRSZ];

	memcpy(srcaddr, &packet->pkt_src, INADDRSZ);
	memcpy(ip, &e->ip, INADDRSZ);

	return comp_with_mask(srcaddr, ip, e->cidrlen);
}

static int
threshold_validator_dst(packet_info_t *packet, iprecord_t *irec, threshold_t *e)
{
	char dstaddr[IN6ADDRSZ], ip[IN6ADDRSZ];

	memcpy(dstaddr, &packet->pkt_dst, INADDRSZ);
	memcpy(ip, &e->ip, INADDRSZ);

	return comp_with_mask(dstaddr, ip, e->cidrlen);
}


static int
check_range(packet_info_t *packet, iprecord_t *irec)
{
	threshold_t *e;
	int ret = 0, i = 0;
	DPRINTF("thres: looking %s e_list\n", "up");
	for (e = th_list[packet->ip_type]; e != NULL; e = e->next)
	{
	    DPRINTF("thres: e_list loop %d\n", i);
		ret = threshold_validator_any(packet, irec, e);
        if(ret)
            return ret;
        i++;
	}
}

static threshold_t
*find_range_definition(packet_info_t *packet, iprecord_t *irec)
{
    threshold_t *t;
    int ret;
    for (t = th_list[packet->ip_type]; t != NULL; t = t->next)
    {
        ret = threshold_validator_any(packet, irec, t);
        DPRINTF("thres: eval %p res %d\n", t, ret);
        if(ret)
        {
            return t;
        }
    }
}

static void
hook_check_thres(packet_info_t *packet, iprecord_t *irec, int *threshold_trigger, int pps, int mbps, int globalpps, int globalmbps)
{
    int enabled = check_range(packet, irec);
    if(!enabled)
    {
        DPRINTF("thres: not enabled for this range, skipping. %d\n", 0);
        return;
    }
    else
    {
        threshold_t *temp = find_range_definition(packet, irec);
        if(temp == NULL)
        {
            DPRINTF("thres: failed to find range definition, this is not meant to happen. %d\n", 0);
            return;
        }
        DPRINTF("thres: defined custom values are -> mbps: %d, pps: %d\n", temp->mbps, temp->pps);
        if(temp->pps && pps > temp->pps)
        {
            DPRINTF("thres: pps match found, %d is higher than %d. Global pps: %d\n", pps, temp->pps, globalpps);
            *threshold_trigger = 1;
        }

        if(temp->mbps && mbps > temp->mbps)
        {
            DPRINTF("thres: mbps match found, %d is higher than %d. Global mbps: %d\n", mbps, temp->mbps, globalmbps);
            *threshold_trigger = 1;
        }
    }
}

static void
parse_threshold(const char *cidr, mowgli_config_file_entry_t *entry)
{
    int ret;

    threshold_t *th, *e;
    th = calloc(sizeof(threshold_t), 1);

    mowgli_config_file_entry_t *ce;
    char netrange[INET6_ADDRSTRLEN + 10];
    char *len;

    mowgli_strlcpy(netrange, cidr, sizeof netrange);
    len = strrchr(netrange, '/');
    if(len == NULL)
    {
        return;
    }
    *len++ = 0;

    ret = inet_pton(AF_INET, netrange, &th->ip);
    DPRINTF("P to n ret is %d, for %s\n", ret, netrange);
    if (ret != 1)
    {
        return;
    }

    th->cidrlen = atoi(len);
    th->etype = THRESHOLD_TYPE_ANY;

    MOWGLI_ITER_FOREACH(ce, entry)
    {
        if (!strcasecmp(ce->varname, "mbps"))
            th->mbps = atoi(ce->vardata);
        else if (!strcasecmp(ce->varname, "pps"))
            th->pps = atoi(ce->vardata);
        else if (!strcasecmp(ce->varname, "protocol"))
        {
			if (!strcasecmp(ce->vardata, "tcp"))
				th->protocol = 6;
			else if (!strcasecmp(ce->vardata, "tcp-syn"))
			{
				th->protocol = 6;
				th->tcp_synonly = 1;
			}
			else if (!strcasecmp(ce->vardata, "udp"))
				th->protocol = 17;
			else if (!strcasecmp(ce->vardata, "icmp"))
				th->protocol = 1;
        }

    }
    DPRINTF("thres: range %s - mbps %d/pps %d/proto %d\n", netrange, th->mbps, th->pps, th->protocol);
    th->next = th_list[th->protocol];
    th_list[th->protocol] = th;
}

void
module_cons(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;

	memset(th_list, 0, sizeof(th_list));

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "range"))
			parse_threshold(ce->vardata, ce->entries);
	}

	HOOK_REGISTER(HOOK_CHECK_THRES, hook_check_thres);
}
