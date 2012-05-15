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
#include "confparse.h"
#include "modulefactory.h"

void
conf_process(mowgli_eventloop_t *eventloop)
{
	const char *path = CONFIGFILE;
	config_file_t *cf;
	config_entry_t *ce;

	DPRINTF("Parsing config file %s\n", path);

	cf = config_load(path);
	if (cf == NULL)
		return;

	for (ce = cf->cf_entries; ce != NULL; ce = ce->ce_next)
	{
		if (!strcasecmp(ce->ce_varname, "module"))
			module_open(eventloop, ce->ce_vardata, ce->ce_entries);
	}

	DPRINTF("Config parsing %s completed\n", path);
}
