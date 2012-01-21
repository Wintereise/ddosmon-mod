/*
 * modulefactory.c: Load and instantiate modules.
 */

#include "stdinc.h"
#include "modulefactory.h"
#include "confparse.h"

#include <dlfcn.h>

void
module_open(const char *name, config_entry_t *ce)
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

	u.mcf(ce);
}
