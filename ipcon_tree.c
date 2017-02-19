/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include "ipcon_tree.h"
#ifdef CONFIG_DEBUG_FS
#include "ipcon_debugfs.h"
#endif

struct ipcon_tree_node *cp_alloc_srv_node(__u32 port, __u32 ctrl_port,
					char *name)
{
	struct ipcon_tree_node *newnd;

	if (!name || !strlen(name) ||
		(strlen(name) > IPCON_MAX_SRV_NAME_LEN))
		return NULL;

	newnd = kmalloc(sizeof(struct ipcon_tree_node), GFP_ATOMIC);
	if (!newnd)
		return NULL;

	newnd->port = port;
	newnd->ctrl_port = ctrl_port;
	newnd->group = IPCON_NO_GROUP;
	strcpy(newnd->name, name);
	newnd->last_grp_msg = NULL;
#ifdef CONFIG_DEBUG_FS
	newnd->priv = NULL;
#endif

	return newnd;
}

struct ipcon_tree_node *cp_alloc_grp_node(__u32 ctrl_port,
					char *name, __u32 group)
{
	struct ipcon_tree_node *newnd;

	if (!name || !strlen(name) ||
		!valid_ipcon_group(group))
		return NULL;

	newnd = kmalloc(sizeof(struct ipcon_tree_node), GFP_ATOMIC);
	if (!newnd)
		return NULL;

	newnd->port = 0;
	newnd->ctrl_port = ctrl_port;
	strcpy(newnd->name, name);
	newnd->group = group;
	newnd->last_grp_msg = NULL;
#ifdef CONFIG_DEBUG_FS
	newnd->priv = NULL;
#endif

	return newnd;
}

void cp_free_node(struct ipcon_tree_node *nd)
{
	/* kfree_skb can deal with NULL */
	if (!nd)
		return;

	kfree_skb(nd->last_grp_msg);
	kfree(nd);
}

/*
 * This function __requires__ caller to assure np is a node of the root tree.
 */
int cp_detach_node(struct ipcon_tree_root *root, struct ipcon_tree_node *np)
{
	int ret = 0;

	if (!root || !np)
		return -EINVAL;

	rb_erase(&np->node, &root->root);
	root->count--;

#ifdef CONFIG_DEBUG_FS
	ipcon_debugfs_remove_entry(np);
#endif

	return ret;
}

struct ipcon_tree_node *cp_lookup(struct ipcon_tree_root *root, void *key)
{
	struct rb_node *nd = root->root.rb_node;

	if (!root || !root->ops || !key)
		return NULL;

	while (nd) {
		struct ipcon_tree_node *itn = rbnd_to_treend(nd);
		int result;

		result = root->ops->compare(itn, key);
		if (result < 0)
			nd = nd->rb_right;
		else if (result > 0)
			nd = nd->rb_left;
		else
			return itn;
	}

	return NULL;
}

int cp_insert(struct ipcon_tree_root *root, struct ipcon_tree_node *node)
{
	int ret = 0;
	struct rb_node **new = NULL;
	struct rb_node *parent = NULL;

	if (!root || !cp_valid_node(node))
		return -EINVAL;

	new = &(root->root.rb_node);

	while (*new) {
		struct ipcon_tree_node *itn = rbnd_to_treend(*new);
		int result;
		void *key = root->ops->getkey(node);

		result = root->ops->compare(itn, key);
		parent = *new;

		if (result < 0)
			new = &((*new)->rb_right);
		else if (result > 0)
			new = &((*new)->rb_left);
		else
			ret = -EEXIST;

		if (ret < 0)
			break;

	}

	if (!ret) {
		rb_link_node(&node->node, parent, new);
		rb_insert_color(&node->node, &root->root);
		root->count++;

#ifdef CONFIG_DEBUG_FS
		/*
		 * group_bitmap is only used in group tree in which
		 * ipcon_kern_event is reserved at ipcon_init
		 */
		ipcon_debugfs_add_entry(node, (root->group_bitmap[0] == 0));
#endif
	}

	return ret;
}

void cp_free_tree(struct ipcon_tree_root *root)
{
	struct rb_node *node = NULL;

	if (!root)
		return;

	do {
		node = rb_first(&root->root);
		if (node) {
			struct ipcon_tree_node *itn = rbnd_to_treend(node);

			if (!cp_detach_node(root, itn))
				cp_free_node(itn);
		}
	} while (node);
}

void cp_print_tree(struct ipcon_tree_root *root)
{
	int is_grp_tree = (root->group_bitmap[0] != 0);
	struct rb_node *node = NULL;

	if (!root)
		return;

	for (node = rb_first(&root->root); node; node = rb_next(node)) {
		struct ipcon_tree_node *itn = rbnd_to_treend(node);

		if (is_grp_tree)
			ipcon_info("%s %s grp: %lu ctrlport: %lu lastmsg? %s\n",
					"Group",
					itn->name,
					(unsigned long)itn->group,
					(unsigned long)itn->ctrl_port,
					itn->last_grp_msg ? "yes" : "no");
		else
			ipcon_info("%s %s port: %lu ctrlport: %lu\n",
					"Service",
					itn->name,
					(unsigned long)itn->port,
					(unsigned long)itn->ctrl_port);
	}
}

struct ipcon_tree_node *cp_lookup_by_port(struct ipcon_tree_root *root,
					__u32 port)
{
	struct rb_node *node = NULL;
	struct ipcon_tree_node *result = NULL;

	if (!port || !root)
		return NULL;

	for (node = rb_first(&root->root); node; node = rb_next(node)) {
		result = rbnd_to_treend(node);

		if (result->port == port)
			break;

		if (result->ctrl_port == port)
			break;

		result = NULL;
	}

	return result;
}
