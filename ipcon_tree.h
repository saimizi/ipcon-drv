/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_TREE_H__
#define __IPCON_TREE_H__

#include <linux/rbtree.h>
#include <linux/string.h>
#include "ipcon.h"
#include "ipcon_dbg.h"

struct ipcon_tree_node {
	struct rb_node node;
#if IPCON_MAX_SRV_NAME_LEN > IPCON_MAX_GRP_NAME_LEN
	char name[IPCON_MAX_SRV_NAME_LEN];
#else
	char name[IPCON_MAX_GRP_NAME_LEN];
#endif
	__u32 port;
	__u32 ctrl_port;
	__u32 group;
	struct sk_buff *last_grp_msg;
#ifdef CONFIG_DEBUG_FS
	void *priv;
#endif
};

struct tree_ops {
	int (*compare)(struct ipcon_tree_node *itn, void *key);
	void * (*getkey)(struct ipcon_tree_node *itn);
};

struct ipcon_tree_root {
	struct rb_root root;
	__u32 count;
	/* Only used by group tree */
	unsigned long group_bitmap[BITS_TO_LONGS(IPCON_MAX_GROUP_NUM)];
	rwlock_t lock;
	struct tree_ops *ops;
};

static inline void ipcon_rd_lock_tree(struct ipcon_tree_root *itr)
{
	read_lock(&itr->lock);
};

static inline void ipcon_rd_unlock_tree(struct ipcon_tree_root *itr)
{
	read_unlock(&itr->lock);
};

static inline void ipcon_wr_lock_tree(struct ipcon_tree_root *itr)
{
	write_lock(&itr->lock);
};

static inline int ipcon_wr_trylock_tree(struct ipcon_tree_root *itr)
{
	return write_trylock(&itr->lock);
};

static inline void ipcon_wr_unlock_tree(struct ipcon_tree_root *itr)
{
	write_unlock(&itr->lock);
};


static inline void ipcon_init_tree(struct ipcon_tree_root *itr,
			struct tree_ops *ops)
{
	int i = 0;

	rwlock_init(&itr->lock);

	for (i = 0; i < BITS_TO_LONGS(IPCON_MAX_GROUP_NUM); i++)
		itr->group_bitmap[i] = 0;

	itr->count = 0;
	itr->root.rb_node = NULL;
	itr->ops = ops;
};

/*
 * Compare two nodes by using name.
 */
static inline int compare_byname(struct ipcon_tree_node *n, void *name)
{
	return strcmp(n->name, (char *)name);
}

static inline void *getkey_byname(struct ipcon_tree_node *n)
{
	if (!n)
		return NULL;
	return (void *)n->name;
}

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

#define rbnd_to_treend(rbnd) rb_entry_safe(rbnd, struct ipcon_tree_node, node)

struct ipcon_tree_node *cp_alloc_srv_node(__u32 port,
				__u32 ctrl_port, char *name);
struct ipcon_tree_node *cp_alloc_grp_node(__u32 port, char *name, __u32 group);
void cp_free_node(struct ipcon_tree_node *nd);
int cp_detach_node(struct ipcon_tree_root *root, struct ipcon_tree_node *np);
struct ipcon_tree_node *cp_lookup(struct ipcon_tree_root *root, void *key);
int cp_insert(struct ipcon_tree_root *root, struct ipcon_tree_node *node);
void cp_free_tree(struct ipcon_tree_root *root);
void cp_print_tree(struct ipcon_tree_root *root);
struct ipcon_tree_node *cp_lookup_by_port(struct ipcon_tree_root *root,
		__u32 port);
#endif
