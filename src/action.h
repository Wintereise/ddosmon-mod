/*
 * action.h
 * Purpose: Maintain list of possible actions.
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
	const char *action;
	action_f act;
	void *data;
} action_t;

typedef struct _banrecord {
	struct _banrecord *prev, *next;

	iprecord_t irec;
	packet_info_t pkt;
	void *trigger;

	time_t added;
	time_t expiry_ts;
} banrecord_t;

void action_register(const char *action, action_f act, void *data);
action_t *action_find(const char *action);

#endif
