#include <linux/hashtable.h>
#include <linux/idr.h>
#include "ipcon.h"
#include "ipcon_dbg.h"
#include "name_cache.h"

static struct nc_head *ipcon_nc;

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

static inline void __nch_detach(struct nc_head *nch, struct nc_entry *nce)
{
	idr_remove(&nch->idr, nce->id);
	hash_del(&nce->node);
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
		struct hlist_node *tmp;
		int bkt = 0;

		write_lock(&nch->lock);
		hash_for_each_safe(nch->name_hash, bkt, tmp, nce, node) {
			if (!atomic_sub_and_test(1, &nce->refcnt))
				ipcon_warn("name %s is freed with %d users.\n",
					nce->name,
					atomic_read(&nce->refcnt));
			__nch_detach(nch, nce);
			kfree(nce);
		}

		idr_destroy(&nch->idr);
		write_unlock(&nch->lock);
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

static inline int __nc_add(struct nc_head *nch, char *name, gfp_t flag)
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

static inline int __nc_getid(struct nc_head *nch, char *name)
{
	int ret = -ENOENT;
	struct nc_entry *nce = NULL;

	read_lock(&nch->lock);
	hash_for_each_possible(nch->name_hash, nce, node,
			str2hash(name))
		if (!strcmp(nce->name, name)) {
			ret = nce->id;
			atomic_inc(&nce->refcnt);
			break;
		}
	read_unlock(&nch->lock);
	return ret;
}

static inline int __nc_getname(struct nc_head *nch, int id, char *name)
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

static inline void __nc_name_get(struct nc_head *nch, char *name)
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

static inline void __nc_name_put(struct nc_head *nch, char *name)
{
	struct nc_entry *nce = NULL;

	write_lock(&nch->lock);
	hash_for_each_possible(nch->name_hash, nce, node,
			str2hash(name))
		if (!strcmp(nce->name, name))
			break;

	if (nce && atomic_sub_and_test(1, &nce->refcnt)) {
		__nch_detach(nch, nce);
		kfree(nce);
	}
	write_lock(&nch->lock);
}

static inline int __nc_id_get(struct nc_head *nch, int id)
{
	struct nc_entry *nce = NULL;

	read_lock(&nch->lock);
	nce = idr_find(&nch->idr, id);
	if (nce)
		atomic_inc(&nce->refcnt);
	read_unlock(&nch->lock);

	return id;
}


static inline void __nc_id_put(struct nc_head *nch, int id)
{
	struct nc_entry *nce = NULL;

	write_lock(&nch->lock);
	nce = idr_find(&nch->idr, id);
	if (nce && atomic_sub_and_test(1, &nce->refcnt)) {
		ipcon_dbg("remove name %s\n", nce->name);
		__nch_detach(nch, nce);
		kfree(nce);
	}
	write_unlock(&nch->lock);
}

int nc_id_get(int id)
{
	return __nc_id_get(ipcon_nc, id);
}

void nc_id_put(int id)
{
	return __nc_id_put(ipcon_nc, id);
}

int nc_getid(char *name)
{
	return __nc_getid(ipcon_nc, name);
}

int nc_getname(int id, char *name)
{
	return __nc_getname(ipcon_nc, id, name);
}

const char *nc_refname(int id)
{
	struct nc_entry *nce = NULL;

	nce = idr_find(&ipcon_nc->idr, id);
	if (nce)
		return nce->name;

	return NULL;
}

int nc_add(char *name, gfp_t flag)
{
	return __nc_add(ipcon_nc, name, flag);
}

int nc_init(void)
{
	int ret = 0;

	ipcon_nc = nch_alloc(GFP_KERNEL);
	if (!ipcon_nc)
		ret = -ENOMEM;

	return ret;
}

void nc_exit(void)
{
	nch_free(ipcon_nc);
}
