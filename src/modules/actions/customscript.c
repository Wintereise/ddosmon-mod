/*
 * customscript.c
 * Purpose: Run custom programs and shell scripts.
 *
 * Copyright (c) 2011 - 2012, TortoiseLabs LLC.
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

typedef struct _customscript {
	char *ban_program;
	char *unban_program;
} customscript_t;

static void
run_script(actiontype_t act, packet_info_t *packet, iprecord_t *rec, void *data)
{
	char dstbuf[INET6_ADDRSTRLEN];
	char *program = NULL;
	customscript_t *cs = data;

	inet_ntop(AF_INET, &packet->pkt_dst, dstbuf, INET6_ADDRSTRLEN);

	switch (act)
	{
	case ACTION_BAN:
		program = cs->ban_program;
		break;
	case ACTION_UNBAN:
		program = cs->unban_program;
		break;
	}

	if (!program)
	{
		DPRINTF("no program specified to run for action %d\n", act);
		return;
	}

	switch (fork())
	{
	case -1:
		return;
	case 0:
		DPRINTF("execl %s '%s'\n", program, dstbuf);
		execl(program, program, dstbuf, NULL);
		_exit(255);
	}
}

static void
parse_action(char *name, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;
	customscript_t *cs;
	char *ban_program = NULL, *unban_program = NULL;

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "ban_program"))
			ban_program = ce->vardata;
		else if (!strcasecmp(ce->varname, "unban_program"))
			unban_program = ce->vardata;
	}

	if (!ban_program || !unban_program)
		return;

	cs = calloc(sizeof(customscript_t), 1);
	cs->ban_program = strdup(ban_program);
	cs->unban_program = strdup(unban_program);

	action_register(name, run_script, cs);
}

void
module_cons(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "action"))
			parse_action(ce->vardata, ce->entries);
	}
}
