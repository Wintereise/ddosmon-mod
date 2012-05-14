/*
 * Copyright (C) 2005-2010 William Pitcock, et al.
 * Rights to this code are as documented in doc/LICENSE.
 */

#ifndef DDOSMON_CONFPARSE_H
#define DDOSMON_CONFPARSE_H

typedef struct _configfile config_file_t;
typedef struct _configentry config_entry_t;

struct _configfile
{
	char *cf_filename;
	config_entry_t *cf_entries;
	config_file_t *cf_next;
	int cf_curline;
	char *cf_mem;
};

struct _configentry
{
	config_file_t *ce_fileptr;

	int ce_varlinenum;
	char *ce_varname;
	char *ce_vardata;
	int ce_sectlinenum; /* line containing closing brace */

	config_entry_t *ce_entries;
	config_entry_t *ce_prevlevel;
	config_entry_t *ce_next;
};

/* confp.c */
void config_free(config_file_t *cfptr);
config_file_t *config_load(const char *filename);

void conf_process(void);

#endif
