#ifndef __IPCON_NAME_CACHE_H__
#define __IPCON_NAME_CACHE_H__

#include "ipcon.h"
#include "ipcon_dbg.h"


static inline unsigned long str2hash(char *s)
{
	unsigned long hash = init_name_hash();

	while (*s) {
		char c = *s;

		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';

		hash = partial_name_hash(c, hash);
		s++;
	}

	hash = end_name_hash(hash);

	return hash;
}

void nc_id_get(int id);
void nc_id_put(int id);
int nc_getid(char *name);
int nc_getname(int id, char *name);
const char *nc_refname(int id);
int nc_add(char *name, gfp_t flag);
int nc_init(void);
void nc_exit(void);

#endif
