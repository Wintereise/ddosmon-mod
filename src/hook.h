/*
 * hook.h
 * Purpose: fast non-flexible hook system
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

/*
 * fast non-flexible hook system
 *
 * to use:
 *   HOOK_CALL(HOOK_LOL, ...);
 *   HOOK_REGISTER(HOOK_LOL, lolfunc);
 *
 * do not exceed MAX_HOOKS.  if more hooks are needed, make
 * MAX_HOOKS a larger number.
 */

#ifndef __HOOK_H__
#define __HOOK_H__

#define MAX_HOOKS	(256)

typedef void (*hookfn_f)();

typedef struct _hook {
	struct _hook *next;
	hookfn_f func;
} hook_t;

extern hook_t *hook_list[MAX_HOOKS];

#define HOOK_CALL(HOOKID, ...)						\
	do {								\
		hook_t *h = hook_list[HOOKID], *n; 			\
		for (n = h; n != NULL; n = n->next) {			\
			n->func(__VA_ARGS__);				\
		}							\
	} while (0)

#define HOOK_CALL_NODATA(HOOKID)			\
	do {						\
		hook_t *h = hook_list[HOOKID], *n; 	\
		for (n = h; n != NULL; n = n->next) {	\
			n->func();			\
		}					\
	} while (0)

#define HOOK_REGISTER(HOOKID, FUNCTION)			\
	do {						\
		hook_t *h = hook_list[HOOKID], *n;	\
		n = calloc(sizeof(hook_t), 1);		\
		n->next = h;				\
		n->func = (hookfn_f) FUNCTION;		\
		hook_list[HOOKID] =  n;			\
	} while (0)

/* hook ids */
#define	HOOK_CHECK_TRIGGER	0
#define HOOK_CHECK_EXEMPT	1

#endif
