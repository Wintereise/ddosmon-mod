#ifndef __ACTION_H__
#define __ACTION_H__

#include "packet.h"
#include "ipstate.h"

typedef enum {
	ACTION_BAN,
	ACTION_UNBAN
} actiontype_t;

typedef void (*action_f)(actiontype_t type, packet_info_t *info, iprecord_t *rec, void *data);

typedef struct _action {
	struct _action *next;

	const char *action;
	action_f act;
	void *data;
} action_t;

void action_register(const char *action, action_f act, void *data);
action_t *action_find(const char *action);

#endif
