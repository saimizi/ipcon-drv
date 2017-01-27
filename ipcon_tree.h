/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_TREE_H__
#define __IPCON_TREE_H__

#include <linux/string.h>
#include "ipcon.h"
#include "ipcon_dbg.h"


struct ipcon_tree_root {
	struct ipcon_tree_node *root;
	rwlock_t lock;
};

static inline void ipcon_rdlock_tree(struct ipcon_tree_root *itr)
{
	read_lock(&itr->lock);
};

static inline void ipcon_rdunlock_tree(struct ipcon_tree_root *itr)
{
	read_unlock(&itr->lock);
};

static inline void ipcon_wrlock_tree(struct ipcon_tree_root *itr)
{
	write_lock(&itr->lock);
};

static inline void ipcon_wrunlock_tree(struct ipcon_tree_root *itr)
{
	write_unlock(&itr->lock);
};

static inline void ipcon_init_tree(struct ipcon_tree_root *itr)
{
	rwlock_init(&itr->lock);
	itr->root = NULL;
};



struct ipcon_tree_node {
	struct ipcon_tree_node *parent;
	struct ipcon_tree_node *left;
	struct ipcon_tree_node *right;
	__u32 port;
	__u32 ctrl_port;
#if IPCON_MAX_SRV_NAME_LEN > IPCON_MAX_GRP_NAME_LEN
	char name[IPCON_MAX_SRV_NAME_LEN];
#else
	char name[IPCON_MAX_GRP_NAME_LEN];
#endif
	__u32 group;
	__u32 auth_key;
};

static inline int cp_valid_node(struct ipcon_tree_node *nd)
{
	if (!nd)
		return 0;

	if (strlen(nd->name) == 0)
		return 0;

	return 1;
}

static inline int cp_valid_srv_node(struct ipcon_tree_node *nd)
{
	if (!cp_valid_node(nd))
		return 0;

	if (!nd->port)
		return 0;

	if (nd->group != IPCON_NO_GROUP)
		return 0;

	if (strlen(nd->name) > (IPCON_MAX_SRV_NAME_LEN - 1))
		return 0;

	return 1;
}

static inline int cp_valid_grp_node(struct ipcon_tree_node *nd)
{
	if (!cp_valid_node(nd))
		return 0;

	if (!nd->ctrl_port)
		return 0;

	if (!valid_user_ipcon_group(nd->group))
		return 0;

	if (strlen(nd->name) > (IPCON_MAX_GRP_NAME_LEN - 1))
		return 0;

	return 1;
}

int cp_comp(struct ipcon_tree_node *n1, struct ipcon_tree_node *n2);
struct ipcon_tree_node *cp_alloc_srv_node(__u32 port,
				__u32 ctrl_port, char *name);
struct ipcon_tree_node *cp_alloc_grp_node(__u32 port, char *name, __u32 group);
void cp_free_node(struct ipcon_tree_node *nd);
int cp_detach_node(struct ipcon_tree_root *root, struct ipcon_tree_node *np);
struct ipcon_tree_node *cp_lookup(struct ipcon_tree_root *root, char *name);
int cp_insert(struct ipcon_tree_root *root, struct ipcon_tree_node *node);
int cp_walk_tree(struct ipcon_tree_node *root,
		int (*process_node)(struct ipcon_tree_node *, void *),
		void *para, int order, int stop_on_error);
void cp_free_tree(struct ipcon_tree_root *root);
void cp_print_tree(struct ipcon_tree_root *root);
struct ipcon_tree_node *cp_lookup_by_port(struct ipcon_tree_root *root,
		u32 port);

#endif
