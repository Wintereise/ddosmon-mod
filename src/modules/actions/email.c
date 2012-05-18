/*
 * email.c
 * Purpose: Send network anomaly reports.
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

#include "autoconf.h"
#include "stdinc.h"
#include "ipstate.h"
#include "action.h"
#include "flowcache.h"
#include "patricia.h"

static char *alert_prefix, *alerts_from, *alerts_to, *mta;
static bool use_local_timezone;
static int max_flowcache_lines = -1;

typedef struct {
	char *alert_prefix;
	char *alerts_from;
	char *alerts_to;
	char *mta;
	int max_flowcache_lines;
} email_target_t;

#ifndef BUFSIZ
#define BUFSIZ 65535
#endif

static const char *
get_protocol(int proto)
{
	switch (proto)
	{
	case 1:
		return "ICMP";
		break;
	case 17:
		return "UDP";
		break;
	case 6:
		return "TCP";
		break;
	default:
		break;
	}

	return "???";
}

static void
list_flows(FILE *out, packet_info_t *packet, int max_lines)
{
	flowcache_dst_host_t *dst;
	patricia_node_t *node;
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
	int i = 0;
	time_t now = mowgli_eventloop_get_time(eventloop);
	int lines = max_lines;

	dst = flowcache_dst_host_lookup(&packet->pkt_dst);
	if (dst == NULL || dst->src_host_tree == NULL)
		return;

	inet_ntop(AF_INET, &packet->pkt_dst, dstbuf, INET6_ADDRSTRLEN);

	fprintf(out, "\nActive flows with destination '%s':\n", dstbuf);

	PATRICIA_WALK(dst->src_host_tree->head, node)
	{
		flowcache_src_host_t *src = node->data;
		int hashv;

		inet_ntop(AF_INET, &src->addr, srcbuf, INET6_ADDRSTRLEN);

		for (hashv = 0; hashv < FLOW_HASH_SIZE; hashv++)
		{
			flowcache_record_t *record;

			MOWGLI_ITER_FOREACH(record, src->flows[hashv])
			{
				time_t age = now - record->last_seen;

				if (age > 60)
					continue;

				if (--max_lines == 0)
					return;

				fprintf(out, "%-5d. %s:%u -> %s:%u\n       [%u bytes, %u packets, last seen %ld seconds ago]\n",
					++i, srcbuf, record->src_port, dstbuf, record->dst_port, record->bytes, record->packets, age);
			}
		}
	}
	PATRICIA_WALK_END;
}

static void
send_email(actiontype_t act, packet_info_t *packet, banrecord_t *rec, void *data)
{
	FILE *out;
	int pipfds[2];
	char timebuf[BUFSIZ];
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
	char emailbuf[BUFSIZ];
	time_t t;
	struct tm tm;
	email_target_t *target = data;

	snprintf(emailbuf, sizeof emailbuf, "%s %s", target->mta, target->alerts_to);

	inet_ntop(AF_INET, &packet->pkt_src, srcbuf, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, &packet->pkt_dst, dstbuf, INET6_ADDRSTRLEN);

	if (act != ACTION_BAN)
		return;

	time(&t);
	tm = use_local_timezone ? *localtime(&t) : *gmtime(&t);
	strftime(timebuf, sizeof(timebuf) - 1, "%a, %d %b %Y %H:%M:%S %z", &tm);

	if (pipe(pipfds) < 0)
		return;

	switch (fork())
	{
	case -1:
		return;
	case 0:
		close(pipfds[1]);
		dup2(pipfds[0], 0);
		execl("/bin/sh", "sh", "-c", emailbuf, NULL);
		_exit(255);
	}

	out = fdopen(pipfds[1], "w");
	fprintf(out, "From: %s\n", target->alerts_from);
	fprintf(out, "To: %s\n", target->alerts_to);
	fprintf(out, "Subject: %sAttack on IP %s at %s\n", target->alert_prefix ? target->alert_prefix : "", dstbuf, timebuf);
	fprintf(out, "X-Mailer: ddosmon/%s\n", PACKAGE_VERSION);
	fprintf(out, "Date: %s\n\n", timebuf);

	fprintf(out, "An attack has been detected against IP %s and may have been nullrouted.\n", dstbuf);

	t = rec->expiry_ts;
	tm = use_local_timezone ? *localtime(&t) : *gmtime(&t);
	strftime(timebuf, sizeof(timebuf) - 1, "%a, %d %b %Y %H:%M:%S %z", &tm);

	fprintf(out, "Any nullroute if placed will expire at: %s\n", timebuf);

	fprintf(out, "\nAttack statistics:\n");

	fprintf(out, "Source IP: %s/%d\n", srcbuf, packet->src_prt);
	fprintf(out, "Target IP: %s/%d\n", dstbuf, packet->dst_prt);
	fprintf(out, "Protocol : %s\n", get_protocol(packet->ip_type));

	fprintf(out, "\nQuantized attack statistics:\n");
	fprintf(out, "MBPS     : %.2f\n", (rec->irec.flows[packet->ip_type].flow / 1000000.));
	fprintf(out, "PPS      : %ld\n", rec->irec.flows[packet->ip_type].pps);
	fprintf(out, "AFLS     : %u\n", rec->irec.flows[packet->ip_type].count);

	list_flows(out, packet, target->max_flowcache_lines);

	fclose(out);
}

static void
parse_action(mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;
	email_target_t *email_target = calloc(sizeof(email_target_t), 1);

	email_target->alerts_from = alerts_from;
	email_target->alerts_to = alerts_to;
	email_target->alert_prefix = alert_prefix;
	email_target->mta = mta;
	email_target->max_flowcache_lines = max_flowcache_lines;

	MOWGLI_ITER_FOREACH(ce, entry->entries)
	{
		if (!strcasecmp(ce->varname, "from"))
			email_target->alerts_from = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "to"))
			email_target->alerts_to = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "alert-prefix"))
			email_target->alert_prefix = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "sendmail"))
			email_target->mta = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "max-flowcache-lines"))
			email_target->max_flowcache_lines = atoi(ce->vardata);
	}

	action_register(entry->vardata, send_email, email_target);
}

void
module_cons(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;
	static email_target_t email_target;

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "from"))
			alerts_from = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "to"))
			alerts_to = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "alert-prefix"))
			alert_prefix = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "sendmail"))
			mta = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "action"))
			parse_action(ce);
		else if (!strcasecmp(ce->varname, "use-local-timezone"))
			use_local_timezone = true;
		else if (!strcasecmp(ce->varname, "max-flowcache-lines"))
			max_flowcache_lines = atoi(ce->vardata);
	}

	email_target.alerts_from = alerts_from;
	email_target.alerts_to = alerts_to;
	email_target.mta = mta;
	email_target.alert_prefix = alert_prefix;
	email_target.max_flowcache_lines = max_flowcache_lines;

	action_register("email", send_email, &email_target);
}
