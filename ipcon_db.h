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
	struct sk_buff *last_grp_msg;
};

struct ipcon_peer_node {
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
	unsigned long group_bitmap[BITS_TO_LONGS(IPCON_MAX_GROUP)];
	DECLARE_HASHTABLE(ipd_name_ht, IPD_HASH_BIT);
	DECLARE_HASHTABLE(ipd_port_ht, IPD_HASH_BIT);
	DECLARE_HASHTABLE(ipd_cport_ht, IPD_HASH_BIT);
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

static inline void ipd_rd_lock(struct ipcon_peer_db *db)
{
	read_lock(&db->lock);
};

static inline void ipd_rd_unlock(struct ipcon_peer_db *db)
{
	read_unlock(&db->lock);
};

static inline void ipd_wr_lock(struct ipcon_peer_db *db)
{
	write_lock(&db->lock);
};

static inline int ipd_wr_trylock(struct ipcon_peer_db *db)
{
	return write_trylock(&db->lock);
};

static inline void ipd_wr_unlock(struct ipcon_peer_db *db)
{
	write_unlock(&db->lock);
};

static inline int group_inuse(struct ipcon_peer_db *ipd, int group)
{
	return test_bit(group, ipd->group_bitmap);
}

static inline void reg_group(struct ipcon_peer_db *ipd, int group)
{
	set_bit(group, ipd->group_bitmap);
}

static inline void unreg_group(struct ipcon_peer_db *ipd, int group)
{
	clear_bit(group, ipd->group_bitmap);
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
