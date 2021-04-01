/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/hashtable.h>

#include "ipcon.h"
#include "ipcon_db.h"
#include "ipcon_dbg.h"

struct dentry *diret;
struct dentry *service_num;
struct dentry *group_num;
struct dentry *named_peers;
struct dentry *anon_peers;
u32 MaxGroupNum = IPCON_MAX_GROUP;
u32 MaxNameLength = IPCON_MAX_NAME_LEN;

static ssize_t entry_file_read(struct file *fp, char __user *user_buffer,
				size_t count, loff_t *position)
{
	char buf[512];
	char *p = NULL;
	struct ipcon_peer_node *ipn = file_inode(fp)->i_private;
	ssize_t ret = 0;
	int len;

	if (!ipn)
		return -EBADF;


	ipn_rd_lock(ipn);
	do {
		unsigned long bkt;
		struct hlist_node *tmp;
		struct ipcon_group_info *igi = NULL;

		p = buf;
		/* Peer Name */
		len = sprintf(p, "%-15s%s\n", "Name:",
				nc_refname(ipn->nameid));
		p += len;

		/* Ctrl port */
		len = sprintf(p, "%-15s%lu\n", "CtrlPort:",
				(unsigned long)ipn->ctrl_port);
		p += len;

		/* Send port */
		if (ipn->snd_port != IPCON_INVALID_PORT) {
			len = sprintf(p, "%-15s%lu\n", "SendPort:",
				(unsigned long)ipn->snd_port);
			p += len;
		}

		/* Receive port */
		if (ipn->rcv_port != IPCON_INVALID_PORT) {
			len = sprintf(p, "%-15s%lu\n", "RcvPort:",
				(unsigned long)ipn->rcv_port);
			p += len;
		}

		len = sprintf(p, "Groups:\n");
		p += len;

		hash_for_each_safe(ipn->ipn_group_ht, bkt, tmp, igi, igi_hgroup) {
			len = sprintf(p, "%32s %d\n",
				nc_refname(igi->nameid), igi->group);
			p += len;
		}

	} while (0);
	ipn_rd_unlock(ipn);


	ret = simple_read_from_buffer(user_buffer,
				count,
				position,
				buf,
				strlen(buf) + 1);

	return ret;
}

static const struct file_operations ipcon_debugfs_fops = {
	.read = entry_file_read,
};

int ipcon_debugfs_init(void)
{
	int ret = 0;

	diret = debugfs_create_dir("ipcon", NULL);

	debugfs_create_u32("MaxGroupNum",
			0644,
			diret,
			&MaxGroupNum);

	debugfs_create_u32("MaxNameLength",
			0644,
			diret,
			&MaxNameLength);

	named_peers = debugfs_create_dir("NamedPeers", diret);
	anon_peers= debugfs_create_dir("AnonPeers", diret);

	return ret;
}

void ipcon_debugfs_add_entry(struct ipcon_peer_node *ipn)
{
	struct dentry *d = NULL;
	struct dentry *parent = NULL;

	if (!ipn)
		return;

	if (ipn->type == PEER_TYPE_NORMAL)
		parent = named_peers;
	else 
		parent = anon_peers;


	d = debugfs_create_file(nc_refname(ipn->nameid),
				0644,
				parent,
				ipn,
				&ipcon_debugfs_fops);

	ipn->d = d;
}

void ipcon_debugfs_remove_entry(struct ipcon_peer_node *ipn)
{
	struct dentry *d = NULL;

	if (!ipn)
		return;

	d = ipn->d;
	debugfs_remove(d);
	ipn->d = NULL;
}

void ipcon_debugfs_exit(void)
{
	debugfs_remove_recursive(diret);
}
