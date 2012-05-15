/*
 * modulefactory.c
 * Purpose: Load and instantiate modules.
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
#include "modulefactory.h"
#include "confparse.h"

#include <dlfcn.h>

void
module_open(mowgli_eventloop_t *eventloop, const char *name, config_entry_t *ce)
{
	void *dlptr;
	char path[16384];

	snprintf(path, 16384, "%s/%s.so", MODULEDIR, name);

	DPRINTF("Loading module %s with config database %p\n", path, ce);

	dlptr = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (dlptr == NULL)
	{
		fprintf(stderr, "Module %s failed to load: %s\n", path, dlerror());
		return;
	}

	/*
	 * this is needed because C1X is still utterly broken and assumes a function pointer
	 * can be anything. :( --nenolod
	 */
	union {
		void *symptr;
		module_cons_f mcf;
	} u;

	u.symptr = dlsym(dlptr, "module_cons");
	if (u.symptr == NULL)
	{
		dlclose(dlptr);
		return;
	}

	u.mcf(eventloop, ce);
}
