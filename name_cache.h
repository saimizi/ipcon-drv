#ifndef __IPCON_NAME_CACHE_H__
#define __IPCON_NAME_CACHE_H__

#include "ipcon.h"
#include "ipcon_dbg.h"


#define NCH_HASH_BIT	4

struct nc_entry {
	struct hlist_node node;
	char name[IPCON_MAX_NAME_LEN];
	int id;
	atomic_t refcnt;

};

struct nc_head {
	rwlock_t lock;
	DECLARE_HASHTABLE(name_hash, NCH_HASH_BIT);
	struct idr idr;
};

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

static inline struct nc_head *nch_alloc(gfp_t flag)
{
	struct nc_head *nch = NULL;

	nch = kmalloc(sizeof(*nch), flag);
	if (nch) {
		rwlock_init(&nch->lock);
		hash_init(nch->name_hash);
		idr_init(&nch->idr);
	}

	return nch;
}

static inline void nch_free(struct nc_head *nch)
{
	if (nch) {
		struct nc_entry *nce = NULL;
		int bkt;

		idr_destroy(&nch->idr);

		if (!hash_empty(nch->name_hash))
			hash_for_each(nch->name_hash, bkt, nce, node) {
				hash_del(&nce->node);
				kfree(nce);
			}
		kfree(nch);
	}
}

static inline struct nc_entry *nce_alloc(char *name, gfp_t flag)
{
	struct nc_entry *nce = NULL;

	if (!name)
		return NULL;

	nce = kmalloc(sizeof(*nce), flag);
	if (nce) {
		INIT_HLIST_NODE(&nce->node);
		strcpy(nce->name, name);
		nce->id = 0;
		atomic_set(&nce->refcnt, 1);
	}

	return nce;
}

static inline int nc_add(struct nc_head *nch, char *name, gfp_t flag)
{
	int ret = -ENOENT;
	struct nc_entry *nce = NULL;

	do {
		int id = 0;

		if (!valid_name(name)) {
			ret = -EINVAL;
			break;
		}

		read_lock(&nch->lock);
		hash_for_each_possible(nch->name_hash, nce, node,
				str2hash(name))
			if (!strcmp(nce->name, name)) {
				atomic_inc(&nce->refcnt);
				ret = nce->id;
				break;
			}
		read_unlock(&nch->lock);

		if (ret > 0)
			break;

		nce = nce_alloc(name, flag);
		if (!nce) {
			ret = -ENOMEM;
			break;
		}

		idr_preload(flag);
		write_lock(&nch->lock);
		id = idr_alloc(&nch->idr, nce, 1, -1, GFP_NOWAIT);
		write_unlock(&nch->lock);
		idr_preload_end();

		if (id < 0) {
			kfree(nce);
			ret = id;
			break;
		}

		hash_add(nch->name_hash, &nce->node, str2hash(name));
		ret = nce->id = id;
	} while (0);

	return ret;

}

static inline int nc_getid(struct nc_head *nch, char *name)
{
	int ret = -ENOENT;
	struct nc_entry *nce = NULL;

	read_lock(&nch->lock);
	hash_for_each_possible(nch->name_hash, nce, node,
			str2hash(name))
		if (!strcmp(nce->name, name)) {
			ret = nce->id;
			break;
		}
	read_unlock(&nch->lock);

	return ret;
}

static inline int nc_getname(struct nc_head *nch, int id, char *name)
{
	struct nc_entry *nce = NULL;
	int ret = 0;

	read_lock(&nch->lock);
	nce = idr_find(&nch->idr, id);
	if (nce) {
		if (name)
			strcpy(name, nce->name);
	} else {
		ret = -ENOENT;
	}
	read_unlock(&nch->lock);

	return ret;
}

static inline const char *nc_refname(struct nc_head *nch, int id)
{
	struct nc_entry *nce = NULL;

	nce = idr_find(&nch->idr, id);
	if (nce)
		return nce->name;

	return NULL;
}

static inline int valid_id(struct nc_head *nch, int id)
{
	if (id <= 0)
		return 0;

	return !nc_getname(nch, id, NULL);
}


static inline void nch_detach(struct nc_head *nch, struct nc_entry *nce)
{
	idr_remove(&nch->idr, nce->id);
	hash_del(&nce->node);
}

static inline void nc_name_get(struct nc_head *nch, char *name)
{
	struct nc_entry *nce = NULL;

	read_lock(&nch->lock);
	hash_for_each_possible(nch->name_hash, nce, node,
			str2hash(name))
		if (!strcmp(nce->name, name))
			break;

	if (nce)
		atomic_inc(&nce->refcnt);
	read_unlock(&nch->lock);
}

static inline void nc_name_put(struct nc_head *nch, char *name)
{
	struct nc_entry *nce = NULL;

	write_lock(&nch->lock);
	hash_for_each_possible(nch->name_hash, nce, node,
			str2hash(name))
		if (!strcmp(nce->name, name))
			break;

	if (nce && atomic_sub_and_test(1, &nce->refcnt)) {
		nch_detach(nch, nce);
		kfree(nce);
	}
	write_lock(&nch->lock);
}

static inline void nc_id_get(struct nc_head *nch, int id)
{
	struct nc_entry *nce = NULL;

	read_lock(&nch->lock);
	nce = idr_find(&nch->idr, id);
	if (nce)
		atomic_inc(&nce->refcnt);
	read_unlock(&nch->lock);
}


static inline void nc_id_put(struct nc_head *nch, int id)
{
	struct nc_entry *nce = NULL;

	write_lock(&nch->lock);
	nce = idr_find(&nch->idr, id);
	if (nce && atomic_sub_and_test(1, &nce->refcnt)) {
		ipcon_dbg("remove name %s\n", nce->name);
		nch_detach(nch, nce);
		kfree(nce);
	}
	write_unlock(&nch->lock);
}
#endif
