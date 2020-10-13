#ifndef __IPCON_NAME_CACHE_H__
#define __IPCON_NAME_CACHE_H__

#include <linux/stringhash.h>
#include <linux/ctype.h>
#include "ipcon.h"
#include "ipcon_dbg.h"


static inline unsigned long str2hash(char *s)
{
	unsigned long hash = init_name_hash(0);
	char *p = s;

	while (*p)
		hash = partial_name_hash(tolower(*p++), hash);

	hash = end_name_hash(hash);

	return hash;
}

int nc_id_get(int id);
void nc_id_put(int id);
int nc_getid(char *name);
int nc_getname(int id, char *name);
const char *nc_refname(int id);
int nc_add(char *name, gfp_t flag);
int nc_init(void);
void nc_exit(void);

#endif
