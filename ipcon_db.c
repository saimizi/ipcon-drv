/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include "ipcon_db.h"

struct ipcon_group_info *igi_alloc(char *name, unsigned int group, gfp_t flag)
{
	struct ipcon_group_info *igi = NULL;

	if (!name)
		return NULL;

	igi = kmalloc(sizeof(*igi), flag);
	if (!igi)
		return NULL;

	strcpy(igi->name, name);
	igi->group = group;
	igi->last_grp_msg = NULL;
	INIT_HLIST_NODE(&igi->igi_hname);
	INIT_HLIST_NODE(&igi->igi_hgroup);

	return igi;
}

void igi_del(struct ipcon_group_info *igi)
{
	if (hash_hashed(&igi->igi_hname))
		hash_del(&igi->igi_hname);

	if (hash_hashed(&igi->igi_hgroup))
		hash_del(&igi->igi_hgroup);
}

void igi_free(struct ipcon_group_info *igi)
{
	if (!igi)
		return;

	igi_del(igi);
	kfree_skb(igi->last_grp_msg);
	kfree(igi);
}

struct ipcon_peer_node *ipn_alloc(__u32 port, __u32 ctrl_port,
		char *name, gfp_t flag)
{
	struct ipcon_peer_node *ipn;

	if (!name || !strlen(name) ||
		(strlen(name) > IPCON_MAX_NAME_LEN))
		return NULL;

	ipn = kmalloc(sizeof(*ipn), flag);
	if (!ipn)
		return NULL;

	ipn->port = port;
	ipn->ctrl_port = ctrl_port;
	hash_init(ipn->ipn_group_ht);
	hash_init(ipn->ipn_name_ht);
	INIT_HLIST_NODE(&ipn->ipn_hname);
	INIT_HLIST_NODE(&ipn->ipn_hport);
	INIT_HLIST_NODE(&ipn->ipn_hcport);
	strcpy(ipn->name, name);

	return ipn;
}

void ipn_free(struct ipcon_peer_node *ipn)
{
	struct ipcon_group_info *igi;
	unsigned long bkt;

	if (!ipn)
		return;

	ipn_del(ipn);
	if (!hash_empty(ipn->ipn_group_ht))
		hash_for_each(ipn->ipn_group_ht, bkt, igi, igi_hgroup) {
			igi_free(igi);
		}

	BUG_ON(!hash_empty(ipn->ipn_name_ht));

	kfree(ipn);
}


struct ipcon_group_info *ipn_lookup_byname(struct ipcon_peer_node *ipn,
				char *grp_name)
{
	struct ipcon_group_info *igi = NULL;

	if (!ipn || !grp_name)
		return NULL;

	hash_for_each_possible(ipn->ipn_name_ht, igi, igi_hname,
			str2hash(grp_name))
		if (!strcmp(igi->name, grp_name))
			return igi;

	return NULL;
}

struct ipcon_group_info *ipn_lookup_bygroup(struct ipcon_peer_node *ipn,
					unsigned long group)
{
	struct ipcon_group_info *igi = NULL;

	if (!ipn)
		return NULL;

	if (group > IPCON_MAX_GROUP)
		return NULL;

	hash_for_each_possible(ipn->ipn_group_ht, igi, igi_hgroup, group)
		if (igi->group == group)
			return igi;

	return NULL;
}

int ipn_insert(struct ipcon_peer_node *ipn, struct ipcon_group_info *igi)
{
	if (!ipn || !igi)
		return -EINVAL;

	if (hash_hashed(&igi->igi_hname))
		return -EINVAL;

	if (ipn_lookup_byname(ipn, igi->name) ||
		ipn_lookup_bygroup(ipn, igi->group))
		return -EEXIST;

	hash_add(ipn->ipn_name_ht, &igi->igi_hname, str2hash(igi->name));
	hash_add(ipn->ipn_group_ht, &igi->igi_hgroup, igi->group);

	return 0;
}


void ipn_del(struct ipcon_peer_node *ipn)
{
	if (hash_hashed(&ipn->ipn_hname))
		hash_del(&ipn->ipn_hname);

	if (hash_hashed(&ipn->ipn_hport))
		hash_del(&ipn->ipn_hport);

	if (hash_hashed(&ipn->ipn_hcport))
		hash_del(&ipn->ipn_hcport);
}

struct ipcon_peer_db *ipd_alloc(gfp_t flag)
{
	struct ipcon_peer_db *ipd = NULL;

	ipd = kmalloc(sizeof(*ipd), flag);
	if (!ipd)
		return NULL;

	rwlock_init(&ipd->lock);
	hash_init(ipd->ipd_name_ht);
	hash_init(ipd->ipd_port_ht);
	hash_init(ipd->ipd_cport_ht);
	memset(ipd->group_bitmap, 0, sizeof(ipd->group_bitmap));

	return ipd;
}

struct ipcon_peer_node *ipd_lookup_byname(struct ipcon_peer_db *ipd, char *name)
{
	struct ipcon_peer_node *cur = NULL;

	if (!ipd || !name)
		return NULL;

	hash_for_each_possible(ipd->ipd_name_ht, cur, ipn_hname, str2hash(name))
		if (!strcmp(cur->name, name))
			return cur;

	return NULL;
}

struct ipcon_peer_node *ipd_lookup_byport(struct ipcon_peer_db *ipd, u32 port)
{
	struct ipcon_peer_node *cur = NULL;

	if (!ipd)
		return NULL;

	hash_for_each_possible(ipd->ipd_port_ht, cur, ipn_hport, port)
		if (cur->port == port)
			return cur;

	return NULL;
}

struct ipcon_peer_node *ipd_lookup_bycport(struct ipcon_peer_db *ipd, u32 port)
{
	struct ipcon_peer_node *cur = NULL;

	if (!ipd)
		return NULL;

	hash_for_each_possible(ipd->ipd_cport_ht, cur, ipn_hcport, port)
		if (cur->ctrl_port == port)
			return cur;

	return NULL;
}

int ipd_insert(struct ipcon_peer_db *ipd, struct ipcon_peer_node *ipn)
{

	if (!ipd || !ipn)
		return -EINVAL;

	if (hash_hashed(&ipn->ipn_hname) ||
		hash_hashed(&ipn->ipn_hcport) ||
		hash_hashed(&ipn->ipn_hport))
		return -EINVAL;

	if (ipd_lookup_byname(ipd, ipn->name) ||
		ipd_lookup_bycport(ipd, ipn->ctrl_port) ||
		ipd_lookup_byport(ipd, ipn->port))
		return -EEXIST;

	hash_add(ipd->ipd_name_ht, &ipn->ipn_hname, str2hash(ipn->name));
	hash_add(ipd->ipd_port_ht, &ipn->ipn_hport, ipn->port);
	hash_add(ipd->ipd_cport_ht, &ipn->ipn_hcport, ipn->ctrl_port);

	return 0;
}

void ipd_free(struct ipcon_peer_db *ipd)
{
	if (!ipd)
		return;

	do {
		struct ipcon_peer_node *ipn;
		unsigned long bkt;

		if (!hash_empty(ipd->ipd_port_ht))
			hash_for_each(ipd->ipd_port_ht, bkt, ipn, ipn_hport)
				ipn_free(ipn);

		BUG_ON(!hash_empty(ipd->ipd_cport_ht));
		BUG_ON(!hash_empty(ipd->ipd_name_ht));

		kfree(ipd);

	} while (0);
}
