/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_TREE_H__
#define __IPCON_TREE_H__

#include <linux/string.h>
#include "ipcon.h"
#include "ipcon_dbg.h"


struct ipcon_tree_node {
	__u32 port;
	char name[IPCON_MAX_SRV_NAME_LEN];
	__u32 group;
	__u32 auth_key;
#ifdef CONFIG_DEBUG_FS
	void *priv;
#endif
	struct ipcon_tree_node *parent;
	struct ipcon_tree_node *left;
	struct ipcon_tree_node *right;
};

static inline int cp_valid_node(struct ipcon_tree_node *nd)
{
	if (!nd)
		return 0;

	if (!nd->port)
		return 0;

	if (!valid_user_ipcon_group(nd->group)
		&& (nd->group != IPCON_NO_GROUP))
		return 0;

	if (strlen(nd->name) == 0 ||
		(strlen(nd->name) > IPCON_MAX_SRV_NAME_LEN - 1))
		return 0;

	return 1;
}

int cp_comp(struct ipcon_tree_node *n1, struct ipcon_tree_node *n2);
struct ipcon_tree_node *cp_alloc_node(__u32 port, char *name, __u32 group);
void cp_free_node(struct ipcon_tree_node *nd);
int cp_detach_node(struct ipcon_tree_node **root, struct ipcon_tree_node *nd);
struct ipcon_tree_node *cp_lookup(struct ipcon_tree_node *root, char *name);
int cp_insert(struct ipcon_tree_node **root, struct ipcon_tree_node *node);
int cp_walk_tree(struct ipcon_tree_node *root,
		int (*process_node)(struct ipcon_tree_node *, void *),
		void *para, int order, int stop_on_error);
void cp_free_tree(struct ipcon_tree_node *root);
void cp_print_tree(struct ipcon_tree_node *root);
struct ipcon_tree_node *cp_lookup_by_port(struct ipcon_tree_node *root,
		u32 port);

#endif
