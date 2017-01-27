/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include "ipcon_tree.h"

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

	newnd->left = newnd->right = newnd->parent = NULL;
	newnd->port = port;
	newnd->ctrl_port = ctrl_port;
	newnd->group = IPCON_NO_GROUP;
	strcpy(newnd->name, name);

	return newnd;
}

struct ipcon_tree_node *cp_alloc_grp_node(__u32 ctrl_port,
					char *name, __u32 group)
{
	struct ipcon_tree_node *newnd;

	if (!name || !strlen(name) ||
		!valid_user_ipcon_group(group))
		return NULL;

	if (!valid_user_ipcon_group(group) ||
		(strlen(name) > IPCON_MAX_GRP_NAME_LEN))
		return NULL;

	newnd = kmalloc(sizeof(struct ipcon_tree_node), GFP_ATOMIC);
	if (!newnd)
		return NULL;

	newnd->left = newnd->right = newnd->parent = NULL;
	newnd->ctrl_port = ctrl_port;
	strcpy(newnd->name, name);
	newnd->group = group;

	return newnd;
}

void cp_free_node(struct ipcon_tree_node *nd)
{
	kfree(nd);
}

int cp_detach_node(struct ipcon_tree_root *root, struct ipcon_tree_node *np)
{
	int ret = 0;
	struct ipcon_tree_node *nl = NULL;
	struct ipcon_tree_node *nr = NULL;

	if (!root || !np || !np->parent || !root->root)
		return -EINVAL;

	do {
		nl = np->parent;

		if (!nl || ((nl == np) && (nl != root->root))) {
			ret = -EINVAL;
			break;
		}

		if (nl == root->root)
			break;

	} while (nl);

	if (ret < 0)
		return ret;

	do {
		if (np->left && np->right) {
			nl = np->left;
			while (nl->right)
				nl = nl->right;

			nl->right = np->right;
			nr = np->left;
		} else if (np->left) {
			nr = np->left;
		} else if (np->right) {
			nr = np->right;
		} else {
			nr = NULL;
		}

		if (np->parent == np) {
			root->root = nr;
			if (nr)
				nr->parent = root->root;
		} else {
			if (np->parent->left == np)
				np->parent->left = nr;
			else
				np->parent->right = nr;

			if (nr)
				nr->parent = np->parent;
		}

		np->parent = np->right = np->left = NULL;

	} while (0);

	if (!ret)
		root->count--;

	return ret;
}

struct ipcon_tree_node *cp_lookup(struct ipcon_tree_root *root, char *name)
{
	struct ipcon_tree_node *result = NULL;

	if (!name || !root)
		return NULL;

	result = root->root;

	while (result) {
		int ret = strcmp(result->name, name);

		if (ret == 0)
			break;
		else if (ret > 0)
			result = result->left;
		else if (ret < 0)
			result = result->right;
		else
			result = NULL;
	}

	return result;
}

/*
 * Compare two nodes by using name.
 *
 * Return value
 * - n1 < n2: -1
 * - n1 = n2: 0
 * - n1 > n2: 1
 * - error:
 *	return a negative value beside -1.
 */
int cp_comp(struct ipcon_tree_node *n1, struct ipcon_tree_node *n2)
{
	int ret = 0;

	if (!cp_valid_node(n1) || !cp_valid_node(n2))
		return -EINVAL;

	ret = strcmp(n1->name, n2->name);
	if (ret < 0)
		ret = -1;

	if (ret > 0)
		ret = 1;

	return ret;
}

int cp_insert(struct ipcon_tree_root *root, struct ipcon_tree_node *node)
{
	int ret = 0;
	struct ipcon_tree_node *it = NULL;

	if (!root || !cp_valid_node(node))
		return -EINVAL;

	if (root->root == NULL) {
		root->root = node;
		node->parent = root->root;
	} else {
		it = root->root;

		while (it) {
			ret = cp_comp(it, node);
			if (ret == -1) {
				if (!it->right) {
					it->right = node;
					node->parent = it;
					ret = 0;
					break;
				}

				it = it->right;

			} else if (ret == 1) {
				if (!it->left) {
					it->left = node;
					node->parent = it;
					ret = 0;
					break;
				}

				it = it->left;

			} else {
				if (ret == 0)
					ret = -EEXIST;
				break;
			}
		}
	}

	if (!ret)
		root->count++;

	return ret;
}

int cp_walk_tree(struct ipcon_tree_node *root,
		int (*process_node)(struct ipcon_tree_node *, void *),
		void *para, int order, int stop_on_error)
{
	int ret = 0;

	if (!root)
		return ret;

	if (order == 1) {
		ret = process_node(root, para);
		if (stop_on_error && ret)
			return ret;
	}

	if (root->left) {
		ret = cp_walk_tree(root->left,
				process_node,
				para,
				order,
				stop_on_error);

		if (stop_on_error && ret)
			return ret;
	}

	if (order == 2) {
		ret = process_node(root, para);
		if (stop_on_error && ret)
			return ret;
	}

	if (root->right) {
		ret = cp_walk_tree(root->right,
				process_node,
				para,
				order,
				stop_on_error);

		if (stop_on_error && ret)
			return ret;
	}

	if (order == 3) {
		ret = process_node(root, para);
		if (stop_on_error && ret)
			return ret;
	}

	return ret;
}

static int walk_free_node(struct ipcon_tree_node *nd, void *para)
{
	if (nd->parent) {
		if (nd->parent->left == nd)
			nd->parent->left = NULL;

		if (nd->parent->right == nd)
			nd->parent->right = NULL;
	}

	cp_free_node(nd);

	return 0;
}

void cp_free_tree(struct ipcon_tree_root *root)
{
	cp_walk_tree(root->root, walk_free_node, NULL, 3, 0);
	root->root = NULL;
}

static int walk_print_node(struct ipcon_tree_node *nd, void *para)
{
	if (nd)
		ipcon_info("Service: %s@%d\n", nd->name, nd->port);

	return 0;
}

void cp_print_tree(struct ipcon_tree_root *root)
{
	cp_walk_tree(root->root, walk_print_node, NULL, 2, 0);
}

struct nd_search_info {
	u32 port;
	struct ipcon_tree_node *nd;
};

static int search_nd_by_port(struct ipcon_tree_node *nd, void *para)
{
	struct nd_search_info *nsi = (struct nd_search_info *)para;
	int ret = 0;

	if (nd->port == nsi->port) {
		nsi->nd = nd;
		ret = 1;
	}

	return ret;
}

struct ipcon_tree_node *cp_lookup_by_port(struct ipcon_tree_root *root,
					u32 port)
{
	struct nd_search_info result;
	int ret = 0;

	if (!port || !root || !root->root)
		return NULL;

	memset(&result, 0, sizeof(result));
	result.port = port;

	ret = cp_walk_tree(root->root, search_nd_by_port, &result, 2, 1);
	if (ret == 1)
		return result.nd;

	return NULL;
}
