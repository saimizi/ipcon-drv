/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#include "ipcon_tree.h"
#include "ipcon_genl.h"
#include "ipcon_dbg.h"

struct dentry *diret;
struct dentry *service_num;
struct dentry *group_num;
struct dentry *services;
struct dentry *groups;

struct ipcon_debugfs_data {
	int is_srv;
};

static ssize_t entry_file_read(struct file *fp, char __user *user_buffer,
				size_t count, loff_t *position)
{
	char buf[1024];
	char *p = NULL;
	struct ipcon_debugfs_data *idd = file_inode(fp)->i_private;
	struct ipcon_tree_node *nd = NULL;
	ssize_t ret = 0;

	if (!idd)
		return -EBADF;

	ipcon_debugfs_lock_tree(idd->is_srv);

	do {
		nd = ipcon_lookup_unlock(fp->f_path.dentry->d_iname,
					idd->is_srv);
		if (!nd) {
			ret = -ENOENT;
			break;
		}

		/* For a service entry, no last message. */
		if (idd->is_srv) {
			sprintf(buf,
				"Name:\t\t%s\nComPort:\t%lu\nCtlPort:\t%lu\n\n",
				nd->name,
				(unsigned long)nd->port,
				(unsigned long)nd->ctrl_port);
			break;
		}

		sprintf(buf,
			"Name:\t\t%s\nGroup:\t\t%lu\nComPort:\t%lu\nCtlPort:\t%lu\n\n",
			nd->name,
			(unsigned long)nd->group,
			(unsigned long)nd->port,
			(unsigned long)nd->ctrl_port);

		p = buf + strlen(buf);
		if (nd->last_grp_msg) {
			struct nlmsghdr *nlh = NULL;
			struct nlattr *attrbuf[IPCON_ATTR_MAX + 1];
			int hdrlen, err;
			int datalen = 0;
			char *data = NULL;
			int len;
			int i;
			char tmpc;

			nlh = nlmsg_hdr(nd->last_grp_msg);
			hdrlen = GENL_HDRLEN + ipcon_get_family()->hdrsize;
			err = nlmsg_parse(nlh,
					hdrlen,
					attrbuf,
					IPCON_ATTR_MAX,
					ipcon_get_policy());
			if (err < 0) {
				ret = err;
				break;
			}

			if (!attrbuf[IPCON_ATTR_DATA]) {
				ret = -EINVAL;
				break;
			}

			datalen = nla_len(attrbuf[IPCON_ATTR_DATA]);
			data = nla_data(attrbuf[IPCON_ATTR_DATA]);

			len = sprintf(p, "Last msg in this group:\n");
			p += len;
			len = sprintf(p, "  Size: %lu\n  Dump:\n",
						(unsigned long)datalen);
			p += len;

			if (nd->group) {

				for (i = 0; i < datalen; i++) {
					if (i > 40)
						break;

					if (data[i] == '\0')
						tmpc = '0';
					else
						tmpc = data[i];

					len = sprintf(p, " 0x%x(\'%c\')",
							tmpc, tmpc);
					p += len;
				}

				*p = '\n';
				p++;
				*p = '\0';
			} else {
				/* Group 0: ipcon_kevent */
				struct ipcon_kevent *ik =
					(struct ipcon_kevent *) data;
				char *event = NULL;
				char *name = NULL;
				__u32 port = 0;
				__u32 group = 0;

				switch (ik->type) {
				case IPCON_EVENT_PEER_REMOVE:
					event = "IPCON_EVENT_PEER_REMOVE";
					name = "-";
					port = ik->peer.portid;
					group = 0;
					break;
				case IPCON_EVENT_SRV_ADD:
					event = "IPCON_EVENT_SRV_ADD";
					name = ik->srv.name;
					port = ik->srv.portid;
					group = 0;
					break;
				case IPCON_EVENT_SRV_REMOVE:
					event = "IPCON_EVENT_SRV_REMOVE";
					name = ik->srv.name;
					port = ik->srv.portid;
					group = 0;
					break;
				case IPCON_EVENT_GRP_ADD:
					event = "IPCON_EVENT_GRP_ADD";
					name = ik->grp.name;
					group = ik->grp.groupid;
					port = 0;
					break;
				case IPCON_EVENT_GRP_REMOVE:
					event = "IPCON_EVENT_GRP_REMOVE";
					name = ik->grp.name;
					group = ik->grp.groupid;
					port = 0;
					break;
				default:
					event = "unknown";
					break;
				}

				len = sprintf(p, "    Event:\t%s\n", event);
				p += len;

				len = sprintf(p, "    Name :\t%s\n", name);
				p += len;

				len = sprintf(p, "    Port :\t%lu\n",
					(unsigned long)port);
				p += len;

				len = sprintf(p, "    Group:\t%lu\n",
					(unsigned long)group);
				p += len;

			}


		} else {
			sprintf(p, "No msg cached in this group.\n");
		}
	} while (0);

	ipcon_debugfs_unlock_tree(idd->is_srv);

	if (!ret)
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

int __init ipcon_debugfs_init(__u32 *srv_num, __u32 *grp_num)
{
	int ret = 0;

	diret = debugfs_create_dir("ipcon", NULL);

	if (srv_num)
		service_num = debugfs_create_u32("ServiceNum",
					0644,
					diret,
					srv_num);

	if (grp_num)
		service_num = debugfs_create_u32("GroupNum",
					0644,
					diret,
					grp_num);

	services = debugfs_create_dir("services", diret);
	groups = debugfs_create_dir("groups", diret);

	return ret;
}

/*
 * This function is called from cp_insert(),
 * the corresponding lock has been done in such a case.
 */
void ipcon_debugfs_add_entry(struct ipcon_tree_node *nd, int is_srv)
{
	struct dentry *d = NULL;
	struct dentry *parent = NULL;
	struct ipcon_debugfs_data *idd = NULL;

	if (!nd)
		return;

	idd = kmalloc(sizeof(*idd), GFP_ATOMIC);
	if (!idd)
		return;

	idd->is_srv = is_srv;

	if (is_srv)
		parent = services;
	else
		parent = groups;

	d = debugfs_create_file(nd->name,
				0644,
				parent,
				idd,
				&ipcon_debugfs_fops);

	nd->priv = (void *)d;
}

/*
 * This function is called from cp_detach_node(),
 * the corresponding lock has been done in such a case.
 */
void ipcon_debugfs_remove_entry(struct ipcon_tree_node *nd)
{
	struct dentry *d = NULL;

	if (!nd)
		return;

	d = nd->priv;
	debugfs_remove(d);
	nd->priv = NULL;
}

void __exit ipcon_debugfs_exit(void)
{
	debugfs_remove_recursive(diret);
}
