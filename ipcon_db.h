/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_TREE_H__
#define __IPCON_TREE_H__

#include <linux/version.h>
#include <linux/hashtable.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
#include <linux/stringhash.h>
#else
#include <linux/dcache.h>
#endif
#include <linux/string.h>
#include <linux/types.h>
#include "ipcon.h"
#include "ipcon_dbg.h"

#define IPN_HASH_BIT	4
struct ipcon_group_info {
	struct hlist_node igi_hname;
	struct hlist_node igi_hgroup;
	unsigned int group;
	char name[IPCON_MAX_NAME_LEN];
};

struct ipcon_peer_node {
	rwlock_t lock;
	char name[IPCON_MAX_NAME_LEN];
	__u32 port;
	__u32 ctrl_port;
	enum peer_type type;
	DECLARE_HASHTABLE(ipn_name_ht, IPN_HASH_BIT);
	DECLARE_HASHTABLE(ipn_group_ht, IPN_HASH_BIT);
	struct hlist_node ipn_hname;
	struct hlist_node ipn_hport;
	struct hlist_node ipn_hcport;
};

#define IPD_HASH_BIT	10

struct ipcon_peer_db {
	rwlock_t lock;
	DECLARE_HASHTABLE(ipd_name_ht, IPD_HASH_BIT);
	DECLARE_HASHTABLE(ipd_port_ht, IPD_HASH_BIT);
	DECLARE_HASHTABLE(ipd_cport_ht, IPD_HASH_BIT);
	rwlock_t group_bitmap_lock;
	unsigned long group_bitmap[BITS_TO_LONGS(IPCON_MAX_GROUP)];
	struct workqueue_struct *mc_wq;
	struct workqueue_struct *notify_wq;
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

#define ipd_rd_lock(db)				\
{						\
	ipcon_dbg_lock("wait ipd_rd_lock.\n");	\
	read_lock(&db->lock);			\
	ipcon_dbg_lock("got ipd_rd_lock.\n");	\
}


#define ipd_rd_unlock(db)				\
{							\
	read_unlock(&db->lock);				\
	ipcon_dbg_lock("release ipd_rd_lock.\n");	\
}

#define ipd_wr_lock(db)				\
{						\
	ipcon_dbg_lock("wait ipd_wr_lock.\n");	\
	write_lock(&db->lock);			\
	ipcon_dbg_lock("got ipd_wr_lock.\n");	\
}

#define ipd_wr_unlock(db)				\
{							\
	write_unlock(&db->lock);			\
	ipcon_dbg_lock("release ipd_wr_lock.\n");	\
}

#define ipn_rd_lock(ipn)			\
{						\
	ipcon_dbg_lock("wait ipn_rd_lock.\n");	\
	read_lock(&ipn->lock);			\
	ipcon_dbg_lock("got ipn_rd_lock.\n");	\
}

#define ipn_rd_unlock(ipn)				\
{							\
	read_unlock(&ipn->lock);			\
	ipcon_dbg_lock("release ipn_rd_lock.\n");	\
}

#define ipn_wr_lock(ipn)			\
{						\
	ipcon_dbg_lock("wait ipn_wr_lock.\n");	\
	write_lock(&ipn->lock);			\
	ipcon_dbg_lock("got ipn_wr_lock.\n");	\
}

#define ipn_wr_unlock(ipn)				\
{							\
	write_unlock(&ipn->lock);			\
	ipcon_dbg_lock("release ipn_wr_lock.\n");	\
}

static inline int group_inuse(struct ipcon_peer_db *db, int group)
{
	int ret = 0;

	read_lock(&db->group_bitmap_lock);
	ret = test_bit(group, db->group_bitmap);
	read_unlock(&db->group_bitmap_lock);

	return ret;
}

static inline void reg_group(struct ipcon_peer_db *db, int group)
{
	write_lock(&db->group_bitmap_lock);
	set_bit(group, db->group_bitmap);
	write_unlock(&db->group_bitmap_lock);
}

static inline int reg_new_group(struct ipcon_peer_db *db)
{
	int group = 0;

	write_lock(&db->group_bitmap_lock);
	group = find_first_zero_bit(db->group_bitmap,
			IPCON_MAX_GROUP);
	if (group < IPCON_MAX_GROUP)
		set_bit(group, db->group_bitmap);
	write_unlock(&db->group_bitmap_lock);

	return group;
}

static inline void unreg_group(struct ipcon_peer_db *db, int group)
{
	write_lock(&db->group_bitmap_lock);
	clear_bit(group, db->group_bitmap);
	write_unlock(&db->group_bitmap_lock);
}

struct ipcon_group_info *igi_alloc(char *name, unsigned int group, gfp_t flag);
void igi_del(struct ipcon_group_info *igi);
void igi_free(struct ipcon_group_info *igi);

struct ipcon_peer_node *ipn_alloc(__u32 port, __u32 ctrl_port,
				char *name, enum peer_type type, gfp_t flag);
void ipn_free(struct ipcon_peer_node *ipn);
struct ipcon_group_info *ipn_lookup_byname(struct ipcon_peer_node *ipn,
					char *grp_name);
struct ipcon_group_info *ipn_lookup_bygroup(struct ipcon_peer_node *ipn,
					unsigned long group);

int ipn_insert(struct ipcon_peer_node *ipn, struct ipcon_group_info *igi);
void ipn_del(struct ipcon_peer_node *ipn);

struct ipcon_peer_db *ipd_alloc(gfp_t flag);
struct ipcon_peer_node *ipd_lookup_byname(struct ipcon_peer_db *ipd,
					char *name);
struct ipcon_peer_node *ipd_lookup_byport(struct ipcon_peer_db *ipd,
					u32 port);

struct ipcon_peer_node *ipd_lookup_bycport(struct ipcon_peer_db *ipd,
					u32 port);

int ipd_insert(struct ipcon_peer_db *ipd, struct ipcon_peer_node *ipn);
void ipd_free(struct ipcon_peer_db *ipd);

static inline struct ipcon_group_info *ipd_get_igi(struct ipcon_peer_db *ipd,
					u32 port, unsigned int group)
{
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;

	ipn = ipd_lookup_byport(ipd, port);
	if (ipn)
		igi = ipn_lookup_bygroup(ipn, group);

	return igi;
}


#endif
