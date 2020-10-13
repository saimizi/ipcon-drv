/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include "ipcon_db.h"

struct ipcon_group_info *igi_alloc(int nameid, unsigned int group, gfp_t flag)
{
	struct ipcon_group_info *igi = NULL;

	igi = kmalloc(sizeof(*igi), flag);
	if (igi) {
		nc_id_get(nameid);
		igi->nameid = nameid;
		igi->group = group;
		INIT_HLIST_NODE(&igi->igi_hname);
		INIT_HLIST_NODE(&igi->igi_hgroup);
		atomic_set(&igi->refcnt, 1);
		igi->mc_wq = create_workqueue(nc_refname(nameid));
		if (!igi->mc_wq) {
			kfree(igi);
			igi = NULL;
		}
	}

	return igi;
}

void igi_del(struct ipcon_group_info *igi)
{
	if (!igi)
		return;

	if (hash_hashed(&igi->igi_hname))
		hash_del(&igi->igi_hname);

	if (hash_hashed(&igi->igi_hgroup))
		hash_del(&igi->igi_hgroup);
}

void igi_get(struct ipcon_group_info *igi)
{
	atomic_inc(&igi->refcnt);
}

void igi_put(struct ipcon_group_info *igi)
{
	if (!igi)
		return;

	if (atomic_sub_and_test(1, &igi->refcnt)) {
		igi_del(igi);
		nc_id_put(igi->nameid);

		flush_workqueue(igi->mc_wq);
		destroy_workqueue(igi->mc_wq);
		kfree(igi);
	}
}

void igi_free(struct ipcon_group_info *igi)
{
	igi_put(igi);
}

struct ipcon_peer_node *ipn_alloc(__u32 port, __u32 ctrl_port,
				int nameid, enum peer_type type, gfp_t flag)
{
	struct ipcon_peer_node *ipn;

	ipn = kmalloc(sizeof(*ipn), flag);
	if (ipn) {
		rwlock_init(&ipn->lock);
		ipn->port = port;
		ipn->ctrl_port = ctrl_port;
		ipn->type = type;
		hash_init(ipn->ipn_group_ht);
		hash_init(ipn->ipn_name_ht);
		hash_init(ipn->filter_ht);
		INIT_HLIST_NODE(&ipn->ipn_hname);
		INIT_HLIST_NODE(&ipn->ipn_hport);
		INIT_HLIST_NODE(&ipn->ipn_hcport);
		nc_id_get(nameid);
		ipn->nameid = nameid;
	}

	return ipn;
}

unsigned int ipn_nameid(struct ipcon_peer_node *ipn)
{
	return nc_id_get(ipn->nameid);
}

/* Return 1 if should be dropped */
int ipn_filter_kevent(struct ipcon_peer_node *ipn,
		struct ipcon_kevent *ik)
{
	int peer_nameid = 0;
	int grp_nameid = 0;
	struct filter_node *fnd = NULL;

	if (!ipn || !ik)
		return 1;

	switch (ik->type) {
	case IPCON_EVENT_PEER_ADD:
	case IPCON_EVENT_PEER_REMOVE:
		peer_nameid = nc_getid(ik->peer.name);
		hash_for_each_possible(ipn->filter_ht, fnd,
				node, peer_nameid) {
			if (fnd->type != ik->type)
				continue;

			if (fnd->peer_nameid == peer_nameid)
				return 0;
		}
		break;
	case IPCON_EVENT_GRP_ADD:
	case IPCON_EVENT_GRP_REMOVE:
		peer_nameid = nc_getid(ik->group.peer_name);
		grp_nameid = nc_getid(ik->group.name);
		hash_for_each_possible(ipn->filter_ht, fnd,
				node, peer_nameid) {
			if (fnd->type != ik->type)
				continue;

			if (fnd->peer_nameid == peer_nameid &&
				fnd->group_nameid == grp_nameid) {
				return 0;
			}
		}
		break;
	}

	return 1;
}

int ipn_add_filter(struct ipcon_peer_node *ipn, enum ipcon_kevent_type type,
		int peer_nameid, int group_nameid, gfp_t flag)
{
	struct filter_node *fnd = NULL;

	if (!ipn)
		return -EINVAL;

	/* if same filter has been added, just return success */
	hash_for_each_possible(ipn->filter_ht, fnd, node, peer_nameid)
		if (fnd->peer_nameid == peer_nameid &&
			fnd->group_nameid == group_nameid &&
			fnd->type == type)
			return 0;

	fnd = kmalloc(sizeof(*fnd), flag);
	if (!fnd)
		return -ENOMEM;

	fnd->type = type;
	nc_id_get(peer_nameid);
	fnd->peer_nameid = peer_nameid;

	if (type < IPCON_EVENT_GRP_ADD) {
		fnd->group_nameid = 0;
	} else {
		nc_id_get(group_nameid);
		fnd->group_nameid = group_nameid;
	}

	INIT_HLIST_NODE(&fnd->node);

	hash_add(ipn->filter_ht, &fnd->node, fnd->peer_nameid);

	return 0;
}

void ipn_remove_filter(struct ipcon_peer_node *ipn, enum ipcon_kevent_type type,
		int peer_nameid, int group_nameid)
{
	struct filter_node *fnd = NULL;

	if (!ipn)
		return;

	hash_for_each_possible(ipn->filter_ht, fnd, node, peer_nameid)
		if (fnd->peer_nameid == peer_nameid &&
			fnd->group_nameid == group_nameid &&
			fnd->type == type)
			break;

	if (fnd) {
		hash_del(&fnd->node);
		nc_id_put(fnd->peer_nameid);
		nc_id_put(fnd->group_nameid);
	}
}

void ipn_free(struct ipcon_peer_node *ipn)
{
	struct ipcon_group_info *igi = NULL;
	struct filter_node *fnd = NULL;
	struct hlist_node *tmp;
	unsigned long bkt;

	if (!ipn)
		return;

	ipn_del(ipn);
	if (!hash_empty(ipn->ipn_group_ht))
		hash_for_each_safe(ipn->ipn_group_ht, bkt, tmp, igi, igi_hgroup)
			igi_free(igi);

	if (!hash_empty(ipn->filter_ht))
		hash_for_each_safe(ipn->filter_ht, bkt, tmp, fnd, node) {
			hash_del(&fnd->node);
			nc_id_put(fnd->peer_nameid);
			nc_id_put(fnd->group_nameid);
		}


	BUG_ON(!hash_empty(ipn->ipn_name_ht));
	nc_id_put(ipn->nameid);
	kfree(ipn);
}


struct ipcon_group_info *ipn_lookup_byname(struct ipcon_peer_node *ipn,
					int nameid)
{
	struct ipcon_group_info *igi = NULL;

	hash_for_each_possible(ipn->ipn_name_ht, igi, igi_hname, nameid)
		if (igi->nameid == nameid)
			return igi;

	return NULL;
}

struct ipcon_group_info *ipn_lookup_bygroup(struct ipcon_peer_node *ipn,
					unsigned long group)
{
	struct ipcon_group_info *igi = NULL;

	if (group > IPCON_MAX_GROUP)
		return NULL;

	hash_for_each_possible(ipn->ipn_group_ht, igi, igi_hgroup, group)
		if (igi->group == group)
			return igi;

	return NULL;
}

int ipn_insert(struct ipcon_peer_node *ipn, struct ipcon_group_info *igi)
{
	if (hash_hashed(&igi->igi_hname))
		return -EINVAL;

	if (ipn_lookup_byname(ipn, igi->nameid) ||
		ipn_lookup_bygroup(ipn, igi->group))
		return -EEXIST;

	hash_add(ipn->ipn_name_ht, &igi->igi_hname, igi->nameid);
	hash_add(ipn->ipn_group_ht, &igi->igi_hgroup, igi->group);

	return 0;
}


void ipn_del(struct ipcon_peer_node *ipn)
{
	if (!ipn)
		return;

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

	memset((char *)ipd->group_bitmap, 0, sizeof(ipd->group_bitmap));
	rwlock_init(&ipd->group_bitmap_lock);
	rwlock_init(&ipd->lock);
	hash_init(ipd->ipd_name_ht);
	hash_init(ipd->ipd_port_ht);
	hash_init(ipd->ipd_cport_ht);

	do {
		ipd->notify_wq = create_workqueue("ipcon_notify");
		if (!ipd->notify_wq) {
			kfree(ipd);
			ipd = NULL;
		}

	} while (0);

	return ipd;
}

struct ipcon_peer_node *ipd_lookup_byname(struct ipcon_peer_db *ipd, int nameid)
{
	struct ipcon_peer_node *ipn = NULL;

	hash_for_each_possible(ipd->ipd_name_ht, ipn, ipn_hname, nameid)
		if (ipn->nameid == nameid)
			break;

	return ipn;
}

struct ipcon_peer_node *ipd_lookup_byport(struct ipcon_peer_db *ipd, u32 port)
{
	struct ipcon_peer_node *ipn = NULL;

	hash_for_each_possible(ipd->ipd_port_ht, ipn, ipn_hport, port)
		if (ipn->port == port)
			break;

	return ipn;
}

struct ipcon_peer_node *ipd_lookup_bycport(struct ipcon_peer_db *ipd, u32 port)
{
	struct ipcon_peer_node *ipn = NULL;

	hash_for_each_possible(ipd->ipd_cport_ht, ipn, ipn_hcport, port)
		if (ipn->ctrl_port == port)
			break;

	return ipn;
}

int ipd_insert(struct ipcon_peer_db *ipd, struct ipcon_peer_node *ipn)
{

	if (hash_hashed(&ipn->ipn_hname) ||
		hash_hashed(&ipn->ipn_hcport) ||
		hash_hashed(&ipn->ipn_hport))
		return -EINVAL;

	if (ipd_lookup_byname(ipd, ipn->nameid) ||
		ipd_lookup_bycport(ipd, ipn->ctrl_port) ||
		ipd_lookup_byport(ipd, ipn->port))
		return -EEXIST;

	hash_add(ipd->ipd_name_ht, &ipn->ipn_hname, ipn->nameid);
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
		struct hlist_node *tmp;

		flush_workqueue(ipd->notify_wq);
		destroy_workqueue(ipd->notify_wq);


		ipd_wr_lock(ipd)
		if (!hash_empty(ipd->ipd_port_ht))
			hash_for_each_safe(ipd->ipd_port_ht, bkt, tmp,
					ipn, ipn_hport)
				ipn_free(ipn);

		BUG_ON(!hash_empty(ipd->ipd_cport_ht));
		BUG_ON(!hash_empty(ipd->ipd_name_ht));
		ipd_wr_unlock(ipd)

		kfree(ipd);

	} while (0);
}
