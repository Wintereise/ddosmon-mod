/*
 * customscript.c: run custom scripts
 */

#include "stdinc.h"
#include "ipstate.h"
#include "confparse.h"
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
parse_action(char *name, config_entry_t *entry)
{
	config_entry_t *ce;
	customscript_t *cs;
	char *ban_program = NULL, *unban_program = NULL;

	for (ce = entry; ce != NULL; ce = ce->ce_next)
	{
		if (!strcasecmp(ce->ce_varname, "ban_program"))
			ban_program = ce->ce_vardata;
		else if (!strcasecmp(ce->ce_varname, "unban_program"))
			unban_program = ce->ce_vardata;
	}

	if (!ban_program || !unban_program)
		return;

	cs = calloc(sizeof(customscript_t), 1);
	cs->ban_program = strdup(ban_program);
	cs->unban_program = strdup(unban_program);

	action_register(name, run_script, cs);
}

void
module_cons(config_entry_t *entry)
{
	config_entry_t *ce;

	for (ce = entry; ce != NULL; ce = ce->ce_next)
	{
		if (!strcasecmp(ce->ce_varname, "action"))
			parse_action(ce->ce_vardata, ce->ce_entries);
	}
}
