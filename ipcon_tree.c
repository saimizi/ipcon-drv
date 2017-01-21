/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include "ipcon_tree.h"

struct ipcon_tree_node *cp_alloc_node(__u32 port, char *name, __u32 group)
{
	struct ipcon_tree_node *newnd;

	if (!name || !valid_user_ipcon_group(group))
		return NULL;

	if (!valid_user_ipcon_group(group) &&
		(group != IPCON_NO_GROUP))
		return NULL;

	/* TODO:
	 * Check whether cp_alloc_node() maybe called from
	 * an atomic context.
	 */
	newnd = kmalloc(sizeof(struct ipcon_tree_node), GFP_KERNEL);
	if (!newnd)
		return NULL;

	newnd->left = newnd->right = newnd->parent = NULL;
	newnd->port = port;
	strcpy(newnd->name, name);
	newnd->group = group;


	return newnd;
}

void cp_free_node(struct ipcon_tree_node *nd)
{
	kfree(nd);
}

int cp_detach_node(struct ipcon_tree_node **root, struct ipcon_tree_node *nd)
{
	struct ipcon_tree_node *np = NULL;

	if (!nd || !cp_valid_node(nd))
		return -EINVAL;

	if (nd->parent) {
		np = nd->parent;

		if (np->left == nd)
			np->left = NULL;
		else
			np->right = NULL;

		cp_insert(&np, nd->left);
		cp_insert(&np, nd->right);

		while (np->parent)
			np = np->parent;
	} else {
		if (nd->left) {
			np = nd->left;
			np->parent = NULL;
			cp_insert(&np, nd->right);
		} else if (nd->right) {
			np = nd->right;
			np->parent = NULL;
		}

	}

	nd->parent = nd->left = nd->right = NULL;

	*root = np;

	return 0;
}

struct ipcon_tree_node *cp_lookup(struct ipcon_tree_node *root, char *name)
{
	struct ipcon_tree_node *result = NULL;

	if (!name || !root || !cp_valid_node(root))
		return NULL;

	result = root;

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

int cp_insert(struct ipcon_tree_node **root, struct ipcon_tree_node *node)
{
	int ret = 0;
	struct ipcon_tree_node *it = NULL;

	if (!root || !cp_valid_node(node))
		return -EINVAL;

	if (*root == NULL) {
		*root = node;
		node->parent = NULL;
	} else {
		it = *root;

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

void cp_free_tree(struct ipcon_tree_node *root)
{
	cp_walk_tree(root, walk_free_node, NULL, 3, 0);
}

static int walk_print_node(struct ipcon_tree_node *nd, void *para)
{
	if (nd)
		ipcon_info("Service: %s@%d\n", nd->name, nd->port);

	return 0;
}

void cp_print_tree(struct ipcon_tree_node *root)
{
	cp_walk_tree(root, walk_print_node, NULL, 2, 0);
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

struct ipcon_tree_node *cp_lookup_by_port(struct ipcon_tree_node *root,
					u32 port)
{
	struct nd_search_info result;
	int ret = 0;

	if (!port || !root || !cp_valid_node(root))
		return NULL;

	memset(&result, 0, sizeof(result));
	result.port = port;

	ret = cp_walk_tree(root, search_nd_by_port, &result, 2, 1);
	if (ret == 1)
		return result.nd;

	return NULL;
}
