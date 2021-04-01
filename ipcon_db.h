/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_TREE_H__
#define __IPCON_TREE_H__

#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/types.h>
#include "ipcon.h"
#include "name_cache.h"
#include "ipcon_dbg.h"

#define IPN_HASH_BIT	4
struct ipcon_group_info {
	struct hlist_node igi_hname;
	struct hlist_node igi_hgroup;
	int group;
	int nameid;
	atomic_t refcnt;
	struct workqueue_struct *mc_wq;
	struct ipcon_peer_node *ipn;
};

struct filter_node {
	struct hlist_node node;
	enum ipcon_kevent_type type;
	int peer_nameid;
	int group_nameid;
};

#define IPCON_INVALID_PORT	0xFFFFFFFF
#define IPN_FLG_DISABLE_KEVENT_FILTER		(1 << 0)
struct ipcon_peer_node {
	rwlock_t lock;
	int nameid;
	enum peer_type type;
	__u32 ctrl_port;
	__u32 snd_port;
	__u32 rcv_port;
	DECLARE_HASHTABLE(ipn_name_ht, IPN_HASH_BIT);
	DECLARE_HASHTABLE(ipn_group_ht, IPN_HASH_BIT);
	DECLARE_HASHTABLE(filter_ht, IPN_HASH_BIT);
	struct hlist_node ipn_hname;
	struct hlist_node ipn_hsport;
	struct hlist_node ipn_hcport;
	struct hlist_node ipn_hrport;
	struct ipcon_peer_db *ipd;
	unsigned long flags;
#ifdef CONFIG_DEBUG_FS
	struct dentry *d;
#endif
};

#define IPD_HASH_BIT	10

struct ipcon_peer_db {
	rwlock_t lock;
	DECLARE_HASHTABLE(ipd_name_ht, IPD_HASH_BIT);
	DECLARE_HASHTABLE(ipd_sport_ht, IPD_HASH_BIT);
	DECLARE_HASHTABLE(ipd_cport_ht, IPD_HASH_BIT);
	DECLARE_HASHTABLE(ipd_rport_ht, IPD_HASH_BIT);
	rwlock_t group_bitmap_lock;
	unsigned long group_bitmap[BITS_TO_LONGS(IPCON_MAX_GROUP)];
	struct workqueue_struct *notify_wq;
};

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
	set_bit(group - 1, db->group_bitmap);
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

	return group + 1;
}

static inline void unreg_group(struct ipcon_peer_db *db, int group)
{
	write_lock(&db->group_bitmap_lock);
	clear_bit(group - 1, db->group_bitmap);
	write_unlock(&db->group_bitmap_lock);
}

static inline __u32 ipn_sndport(struct ipcon_peer_node *ipn)
{
	return ipn->snd_port;
}

static inline __u32 ipn_ctrlport(struct ipcon_peer_node *ipn)
{
	return ipn->ctrl_port;
}

static inline __u32 ipn_rcvport(struct ipcon_peer_node *ipn)
{
	return ipn->rcv_port;
}

struct ipcon_group_info *igi_alloc(int nameid, unsigned int group, gfp_t flag);
void igi_del(struct ipcon_group_info *igi);
void igi_free(struct ipcon_group_info *igi);

struct ipcon_peer_node *ipn_alloc(__u32 ctrl_port, __u32 snd_port,
		__u32 rcv_port, int nameid, enum peer_type type,
		unsigned long ipn_flags,  gfp_t flag);

void ipn_free(struct ipcon_peer_node *ipn);
unsigned int ipn_nameid(struct ipcon_peer_node *ipn);
struct ipcon_group_info *ipn_lookup_byname(struct ipcon_peer_node *ipn,
					int nameid);
struct ipcon_group_info *ipn_lookup_bygroup(struct ipcon_peer_node *ipn,
					unsigned long group);

int ipn_insert(struct ipcon_peer_node *ipn, struct ipcon_group_info *igi);
void ipn_del(struct ipcon_peer_node *ipn);

struct ipcon_peer_db *ipd_alloc(gfp_t flag);
struct ipcon_peer_node *ipd_lookup_byname(struct ipcon_peer_db *ipd,
					int nameid);
struct ipcon_peer_node *ipd_lookup_bysport(struct ipcon_peer_db *ipd,
					u32 port);

struct ipcon_peer_node *ipd_lookup_bycport(struct ipcon_peer_db *ipd,
					u32 port);

struct ipcon_peer_node *ipd_lookup_byrport(struct ipcon_peer_db *ipd,
					u32 port);

int ipd_insert(struct ipcon_peer_db *ipd, struct ipcon_peer_node *ipn);
void ipd_free(struct ipcon_peer_db *ipd);

int ipn_add_filter(struct ipcon_peer_node *ipn, enum ipcon_kevent_type type,
		int peer_nameid, int group_nameid, gfp_t flag);

int ipn_filter_kevent(struct ipcon_peer_node *ipn,
		struct ipcon_kevent *ik);

void ipn_remove_filter(struct ipcon_peer_node *ipn, enum ipcon_kevent_type type,
		int peer_nameid, int group_nameid);
#endif
