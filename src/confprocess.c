/*
 * confprocess.c
 * Purpose: Process 'ddosmon.conf' config file.
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
 * We only look for module{} blocks.  Anything else is skipped,
 * and anything inside the module block is handed to the newly
 * instantiated module.
 *
 * Neat, huh?
 */

#include "stdinc.h"
#include "ipstate.h"
#include "modulefactory.h"
#include "sourcefactory.h"

void
conf_process(mowgli_eventloop_t *eventloop)
{
	const char *path = CONFIGFILE;
	mowgli_config_file_t *cf;
	mowgli_config_file_entry_t *ce;

	DPRINTF("Parsing config file %s\n", path);

	cf = mowgli_config_file_load(path);
	if (cf == NULL)
		return;

	MOWGLI_ITER_FOREACH(ce, cf->entries)
	{
		if (!strcasecmp(ce->varname, "ipstate-expiry-time"))
			ip_expiry_time = atoi(ce->vardata);
		else if (!strcasecmp(ce->varname, "module"))
			module_open(eventloop, ce->vardata, ce->entries);
		else if (!strcasecmp(ce->varname, "source"))
			source_open(eventloop, ce->vardata, ce->entries);
	}

	DPRINTF("Config parsing %s completed\n", path);

	mowgli_config_file_free(cf);
}
