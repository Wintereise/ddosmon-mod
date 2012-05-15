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

#include "stdinc.h"
#include "ipstate.h"
#include "action.h"

static char *alerts_from, *alerts_to, *mta;

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
send_email(actiontype_t act, packet_info_t *packet, iprecord_t *rec, void *data)
{
	FILE *out;
	int pipfds[2];
	char timebuf[BUFSIZ];
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
	char emailbuf[BUFSIZ];
	time_t t;
	struct tm tm;

	snprintf(emailbuf, sizeof emailbuf, "%s %s", mta, alerts_to);

	inet_ntop(AF_INET, &packet->pkt_src, srcbuf, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, &packet->pkt_dst, dstbuf, INET6_ADDRSTRLEN);

	if (act != ACTION_BAN)
		return;

	time(&t);
	tm = *gmtime(&t);
	strftime(timebuf, sizeof(timebuf) - 1, "%a, %d %b %Y %H:%M:%S +0000", &tm);

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
	fprintf(out, "From: %s\n", alerts_from);
	fprintf(out, "To: %s\n", alerts_to);
	fprintf(out, "Subject: Attack on IP %s at %s\n", dstbuf, timebuf);
	fprintf(out, "Date: %s\n\n", timebuf);

	fprintf(out, "An attack has been detected against IP %s and was nulled for 30 minutes.\n", dstbuf);

	fprintf(out, "\nAttack statistics:\n");

	fprintf(out, "Source IP: %s/%d\n", srcbuf, packet->src_prt);
	fprintf(out, "Target IP: %s/%d\n", dstbuf, packet->dst_prt);
	fprintf(out, "Protocol : %s\n", get_protocol(packet->ip_type));

	fprintf(out, "\nQuantized attack statistics:\n");
	fprintf(out, "MBPS     : %.2f\n", (rec->flows[packet->ip_type].flow / 1000000.));
	fprintf(out, "PPS      : %ld\n", rec->flows[packet->ip_type].pps);
	fprintf(out, "AFLS     : %u\n", rec->flows[packet->ip_type].count);

	fclose(out);
}

void
module_cons(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "from"))
			alerts_from = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "to"))
			alerts_to = strdup(ce->vardata);
		else if (!strcasecmp(ce->varname, "sendmail"))
			mta = strdup(ce->vardata);
	}

	action_register("email", send_email, NULL);
}
