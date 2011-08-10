/*
 * confprocess.c: Parse 'ddosmon.conf' config file.
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
conf_process(void)
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
			module_open(ce->ce_vardata, ce->ce_entries);
	}

	DPRINTF("Config parsing %s completed\n", path);
}
