#ifndef __MODULEFACTORY_H
#define __MODULEFACTORY_H

#include "confparse.h"

typedef void (*module_cons_f)(config_entry_t *ce);
void module_open(const char *path, config_entry_t *ce);

#endif
