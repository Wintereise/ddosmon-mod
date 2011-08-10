#include "stdinc.h"
#include "action.h"

static action_t *a_list = NULL;

void
action_register(const char *action, action_f act, void *data)
{
	action_t *a;

	a = calloc(sizeof(action_t), 1);
	a->act = act;
	a->action = action;
	a->data = data;
	a->next = a_list;

	a_list = a;
}

action_t *
action_find(const char *action)
{
	action_t *a;

	for (a = a_list; a != NULL; a = a->next)
	{
		if (!strcasecmp(a->action, action))
			return a;
	}

	return NULL;
}
