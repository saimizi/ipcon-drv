/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <asm/bitops.h>

#include "ipcon.h"
#include "ipcon_genl.h"
#include "ipcon_db.h"
#include "ipcon_dbg.h"
#ifdef CONFIG_DEBUG_FS
#include "ipcon_debugfs.h"
#endif

/* Reference
 * - inclue/net/netlink.h
 */

#define UNUSED_GROUP_NAME	"ipconG"
static struct genl_multicast_group ipcon_mcgroups[IPCON_MAX_GROUP];
static struct ipcon_peer_db *ipcon_db;

static struct genl_family ipcon_fam = {
	.id = GENL_ID_GENERATE,
	.name = IPCON_GENL_NAME,
	.hdrsize = IPCON_HDR_SIZE,
	.version = 1,
	.maxattr = IPCON_ATTR_MAX,
	.parallel_ops = false,	/* Consider to set it to true...*/
};

static const struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_MSG_TYPE] = {.type = NLA_U32},
	[IPCON_ATTR_PORT] = {.type = NLA_U32},
	[IPCON_ATTR_GROUP] = {.type = NLA_U32},
	[IPCON_ATTR_GRP_NAME] = {.type = NLA_NUL_STRING,
				.len = IPCON_MAX_NAME_LEN - 1 },
	[IPCON_ATTR_DATA] = {.type = NLA_BINARY, .len = IPCON_MAX_MSG_LEN},
	[IPCON_ATTR_FLAG] = {.type = NLA_FLAG},
	[IPCON_ATTR_PEER_NAME] = {.type = NLA_NUL_STRING,
				.len = IPCON_MAX_NAME_LEN - 1 },
};

static void ipcon_send_kevent(struct ipcon_kevent *ik, gfp_t flags, int lock)
{
	int ret = 0;
	struct sk_buff *msg = NULL;
	void *hdr = NULL;

	if (!ik)
		return;

	do {
		struct ipcon_group_info *igi = NULL;

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, flags);
		if (!msg)
			break;

		hdr = genlmsg_put(msg, 0, 0, &ipcon_fam, 0, IPCON_USR_MSG);
		if (!hdr) {
			nlmsg_free(msg);
			break;
		}

		ret = nla_put_u32(msg, IPCON_ATTR_MSG_TYPE,
				IPCON_MSG_MULTICAST);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			nlmsg_free(msg);
			break;
		}

		ret = nla_put_string(msg, IPCON_ATTR_GRP_NAME,
				IPCON_KERNEL_GROUP);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			nlmsg_free(msg);
			break;
		}

		ret = nla_put(msg, IPCON_ATTR_DATA, sizeof(*ik), ik);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			nlmsg_free(msg);
			break;
		}

		genlmsg_end(msg, hdr);

		/*
		 * ipcon_kevent() will be called from different context in which
		 * cp_grptree_root lock maybe locked or not locked. so do lock
		 * according to the caller setting.
		 */
		if (lock)
			ipd_wr_lock(ipcon_db);

		igi = ipd_get_igi(ipcon_db, 0, IPCON_KERNEL_GROUP_PORT);
		if (!igi)
			BUG();

		if (igi->last_grp_msg) {
			nlmsg_free(igi->last_grp_msg);
			igi->last_grp_msg = NULL;
		}

		skb_get(msg);
		igi->last_grp_msg = msg;

		if (lock)
			ipd_wr_unlock(ipcon_db);

		genlmsg_multicast(&ipcon_fam, msg, 0,
					IPCON_KERNEL_GROUP_PORT, flags);

	} while (0);
}

/*
 * This function is called from another context.
 */
static int ipcon_netlink_notify(struct notifier_block *nb,
				  unsigned long state,
				  void *_notify)
{
	struct netlink_notify *n = _notify;
	struct ipcon_kevent ik;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;
	int bkt = 0;

	if (n->protocol != NETLINK_GENERIC)
		return NOTIFY_DONE;

	if (state != NETLINK_URELEASE)
		return NOTIFY_DONE;

	ipd_wr_lock(ipcon_db);
	ipn = ipd_lookup_byport(ipcon_db, (u32)n->portid);
	if (ipn) {
		ipn_del(ipn);

		if (!hash_empty(ipn->ipn_group_ht)) {
			hash_for_each(ipn->ipn_group_ht, bkt, igi, igi_hgroup) {
				igi_del(igi);
				unreg_group(ipcon_db, igi->group);

				ik.type = IPCON_EVENT_GRP_REMOVE;

				strcpy(ik.grp.group_name, igi->name);
				ik.grp.group = igi->group +
					ipcon_fam.mcgrp_offset;
				strcpy(ik.grp.peer_name, ipn->name);
				ik.grp.port = ipn->port;
				ipcon_send_kevent(&ik, GFP_ATOMIC, 0);

				igi_free(igi);
			}
		}

		memset(&ik, 0, sizeof(ik));
		ik.type = IPCON_EVENT_PEER_REMOVE;
		strcpy(ik.peer.name, ipn->name);
		ik.peer.port = ipn->port;
		ipcon_send_kevent(&ik, GFP_ATOMIC, 0);

		ipn_free(ipn);

		/* Decrease reference count */
		module_put(THIS_MODULE);
	}
	ipd_wr_unlock(ipcon_db);

	return 0;
}


static int ipcon_srv_reslove(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 port = 0;
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	void *hdr;

	do {
		struct sk_buff *msg;

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_SRV_NAME]) {
			ret = -EINVAL;
			break;
		}

		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		if (msg_type != IPCON_MSG_UNICAST) {
			ret = -EINVAL;
			break;
		}

		nla_strlcpy(name, info->attrs[IPCON_ATTR_SRV_NAME],
				IPCON_MAX_NAME_LEN);

		ipd_rd_lock(ipcon_db);
		ipn = ipd_lookup_byname(ipcon_db, name);
		if (ipn)
			port = ipn->port;
		ipd_rd_unlock(ipcon_db);

		if (!port) {
			ret = -ENOENT;
			break;
		}

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = genlmsg_put(msg, 0, 0, &ipcon_fam, 0, IPCON_SRV_RESLOVE);

		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_u32(msg, IPCON_ATTR_PORT, port);
		genlmsg_end(msg, hdr);

		ret = genlmsg_reply(msg, info);

	} while (0);

	return ret;
}

static int ipcon_grp_reg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;
	__u32 port = 0;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_PORT] ||
		!info->attrs[IPCON_ATTR_GRP_NAME])
		return -EINVAL;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

	port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
	nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
		IPCON_MAX_NAME_LEN);

	if (!strcmp(IPCON_KERNEL_GROUP, name))
		return -EINVAL;

	ipd_wr_lock(ipcon_db);
	do {
		int id = 0;
		struct ipcon_kevent ik;

		id = find_first_zero_bit(ipcon_db->group_bitmap,
				IPCON_MAX_GROUP);

		if (id >= IPCON_MAX_GROUP) {
			ret = -ENOBUFS;
			break;
		}


		ipn = ipd_lookup_byport(ipcon_db, port);
		if (!ipn) {
			ret = -ENOENT;
			break;
		}

		if (ipn->ctrl_port != info->snd_portid) {
			ret = -EPERM;
			break;
		}

		igi = ipn_lookup_byname(ipn, name);
		if (igi) {
			ret = -EEXIST;
			break;
		}

		igi = igi_alloc(name, (u32)id, GFP_KERNEL);
		if (!igi) {
			ret = -ENOMEM;
			break;
		}

		ret = ipn_insert(ipn, igi);
		if (ret < 0) {
			igi_free(igi);
			break;
		}

		reg_group(ipcon_db, id);

		ik.type = IPCON_EVENT_GRP_ADD;
		strcpy(ik.grp.group_name, name);
		ik.grp.group = igi->group + ipcon_fam.mcgrp_offset;
		strcpy(ik.grp.peer_name, ipn->name);
		ik.grp.port = ipn->port;
		ipcon_send_kevent(&ik, GFP_ATOMIC, 0);

	} while (0);
	ipd_wr_unlock(ipcon_db);

	return ret;
}

static int ipcon_grp_unreg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 ctrl_port;
	__u32 port;
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;

	ipd_wr_lock(ipcon_db);
	do {
		struct ipcon_kevent ik;

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_PORT] ||
			!info->attrs[IPCON_ATTR_GRP_NAME]) {
			ret = -EINVAL;
			break;
		}

		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		if (msg_type != IPCON_MSG_UNICAST) {
			ret = -EINVAL;
			break;
		}

		ctrl_port = info->snd_portid;
		port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
		nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
				IPCON_MAX_NAME_LEN);

		ipn = ipd_lookup_byport(ipcon_db, port);
		if (!ipn) {
			ret = -ENOENT;
			break;
		}

		if (ipn->ctrl_port != ctrl_port) {
			ret = -EPERM;
			break;
		}

		igi = ipn_lookup_byname(ipn, name);
		if (!igi) {
			ret = -ENOENT;
			break;
		}

		igi_del(igi);

		ik.type = IPCON_EVENT_GRP_REMOVE;
		strcpy(ik.grp.group_name, name);
		ik.grp.group = igi->group + ipcon_fam.mcgrp_offset;
		strcpy(ik.grp.peer_name, ipn->name);
		ik.grp.port = ipn->port;
		ipcon_send_kevent(&ik, GFP_KERNEL, 0);

		igi_free(igi);

	} while (0);
	ipd_wr_unlock(ipcon_db);

	return ret;
}

static int ipcon_grp_reslove(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	char srvname[IPCON_MAX_NAME_LEN];
	__u32 ctrl_port;
	__u32 com_port;
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;
	void *hdr;
	int send_last_msg = 0;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_PORT] ||
		!info->attrs[IPCON_ATTR_SRV_NAME] ||
		!info->attrs[IPCON_ATTR_GRP_NAME])
		return  -EINVAL;

	ctrl_port = info->snd_portid;
	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

	com_port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
	nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
			IPCON_MAX_NAME_LEN);

	nla_strlcpy(srvname, info->attrs[IPCON_ATTR_SRV_NAME],
			IPCON_MAX_NAME_LEN);

	if (info->attrs[IPCON_ATTR_FLAG])
		send_last_msg = 1;

	ipd_rd_lock(ipcon_db);

	do {
		struct sk_buff *msg;

		ipn = ipd_lookup_byname(ipcon_db, srvname);
		if (!ipn) {
			ret = -ENOENT;
			break;
		}

		igi = ipn_lookup_byname(ipn, name);
		if (!igi) {
			ret = -ENOENT;
			break;
		}

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = genlmsg_put(msg, 0, 0, &ipcon_fam, 0, IPCON_GRP_RESLOVE);
		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		nla_put_u32(msg, IPCON_ATTR_GROUP,
				igi->group + ipcon_fam.mcgrp_offset);

		genlmsg_end(msg, hdr);
		ret = genlmsg_reply(msg, info);

		/*
		 * If target group found, Send cached last group message to
		 * communication port if required. since genlmsg_unicast() will
		 * consume the skbuff, a copy has to be created before sending.
		 *
		 * see ipcon_multicast_msg().
		 */
		if (send_last_msg && igi->last_grp_msg) {
			skb_get(igi->last_grp_msg);
			msg = igi->last_grp_msg;
			genlmsg_unicast(genl_info_net(info), msg, com_port);
			ipcon_dbg("ipcon_grp_reslove() send last_grp_msg to %lu ret = %d\n",
					(unsigned long) com_port, ret);
		}

	} while (0);

	ipd_rd_unlock(ipcon_db);

	return ret;
}

static int ipcon_multicast_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 ctrl_port;
	__u32 port;
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;
	void *hdr;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_PORT] ||
		!info->attrs[IPCON_ATTR_GRP_NAME] ||
		!info->attrs[IPCON_ATTR_DATA])
		return -EINVAL;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

	ctrl_port = info->snd_portid;
	port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
	nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
			IPCON_MAX_NAME_LEN);

	if (!strcmp(IPCON_KERNEL_GROUP, name))
		return -EINVAL;

	ipd_wr_lock(ipcon_db);
	do {
		struct sk_buff *msg = NULL;

		ipn = ipd_lookup_byport(ipcon_db, port);
		if (!ipn) {
			ret = -ENOENT;
			break;
		}

		if (ipn->ctrl_port != ctrl_port) {
			ret = -EPERM;
			break;
		}

		igi = ipn_lookup_byname(ipn, name);
		if (!igi) {
			ret = -ENOENT;
			break;
		}

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = genlmsg_put(msg, 0, 0, &ipcon_fam, 0, IPCON_USR_MSG);
		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		ret = nla_put_u32(msg, IPCON_ATTR_MSG_TYPE,
				IPCON_MSG_MULTICAST);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			nlmsg_free(msg);
			break;
		}

		ret = nla_put_string(msg, IPCON_ATTR_GRP_NAME, igi->name);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			nlmsg_free(msg);
			break;
		}

		ret = nla_put(msg, IPCON_ATTR_DATA,
				nla_len(info->attrs[IPCON_ATTR_DATA]),
				nla_data(info->attrs[IPCON_ATTR_DATA]));

		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			nlmsg_free(msg);
			break;
		}

		genlmsg_end(msg, hdr);

		/* Caching the last muticast message */
		if (igi->last_grp_msg)
			nlmsg_free(igi->last_grp_msg);

		skb_get(msg);
		igi->last_grp_msg = msg;

		genlmsg_multicast(&ipcon_fam, msg, ipn->ctrl_port,
				igi->group, GFP_KERNEL);

	} while (0);
	ipd_wr_unlock(ipcon_db);


	return ret;
}

static int ipcon_peer_reg(struct sk_buff *skb, struct genl_info *info)
{
	char name[IPCON_MAX_NAME_LEN];
	int ret = 0;
	struct ipcon_peer_node *ipn = NULL;
	__u32 port = 0;
	struct ipcon_kevent ik;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_PORT] ||
		!info->attrs[IPCON_ATTR_PEER_NAME])
		return -EINVAL;

	ipd_wr_lock(ipcon_db);
	do {
		port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
		nla_strlcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
				IPCON_MAX_NAME_LEN);

		ipn = ipn_alloc(port, info->snd_portid, name, GFP_KERNEL);
		if (!ipn) {
			ret = -ENOMEM;
			break;
		}

		ret = ipd_insert(ipcon_db, ipn);
		if (ret < 0) {
			ipn_free(ipn);
			break;
		}

		if (!try_module_get(THIS_MODULE)) {
			ret = -ENOMEM;
			ipn_free(ipn);
			break;
		}

		memset(&ik, 0, sizeof(ik));
		ik.type = IPCON_EVENT_PEER_ADD;
		strcpy(ik.peer.name, ipn->name);
		ik.peer.port = ipn->port;
		ipcon_send_kevent(&ik, GFP_ATOMIC, 0);

	} while (0);
	ipd_wr_unlock(ipcon_db);

	return ret;

}

static const struct genl_ops ipcon_ops[] = {
	{
		.cmd = IPCON_SRV_RESLOVE,
		.doit = ipcon_srv_reslove,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_GRP_REG,
		.doit = ipcon_grp_reg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_GRP_UNREG,
		.doit = ipcon_grp_unreg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_GRP_RESLOVE,
		.doit = ipcon_grp_reslove,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_MULTICAST_MSG,
		.doit = ipcon_multicast_msg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
	{
		.cmd = IPCON_PEER_REG,
		.doit = ipcon_peer_reg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
};


static struct notifier_block ipcon_netlink_notifier = {
	.notifier_call = ipcon_netlink_notify,
};

static int ipcon_kernel_init(void)
{
	struct ipcon_group_info *igi = NULL;
	struct ipcon_peer_node *ipn = NULL;
	int ret = 0;

	igi = igi_alloc(IPCON_KERNEL_GROUP, IPCON_KERNEL_GROUP_PORT,
			GFP_KERNEL);
	if (!igi)
		return -ENOMEM;

	ipn = ipn_alloc(0, 0, IPCON_GENL_NAME, GFP_KERNEL);
	if (!ipn) {
		igi_free(igi);
		return -ENOMEM;
	}

	ipcon_db = ipd_alloc(GFP_KERNEL);
	if (!ipcon_db) {
		ipn_free(ipn);
		return -ENOMEM;
	}

	ret = ipn_insert(ipn, igi);
	if (ret < 0) {
		ipn_free(ipn);
		ipd_free(ipcon_db);
		return ret;
	}

	ret = ipd_insert(ipcon_db, ipn);
	if (ret < 0) {
		ipn_free(ipn);
		ipd_free(ipcon_db);
		ipcon_db = NULL;
		return ret;
	}

	reg_group(ipcon_db, IPCON_KERNEL_GROUP_PORT);

	return ret;
}

int ipcon_genl_init(void)
{
	int ret = 0;
	int i = 0;

	ret = ipcon_kernel_init();
	if (ret < 0)
		return ret;

	for (i = 0; i < IPCON_MAX_GROUP; i++) {
		if (i)
			sprintf(ipcon_mcgroups[i].name, "%s%d",
					UNUSED_GROUP_NAME, i);
		else
			strcpy(ipcon_mcgroups[i].name, IPCON_KERNEL_GROUP);
	}

	ret = genl_register_family_with_ops_groups(&ipcon_fam, ipcon_ops,
						ipcon_mcgroups);
	if (ret) {
		ipd_free(ipcon_db);
		return ret;
	}

	ret = netlink_register_notifier(&ipcon_netlink_notifier);
	if (ret) {
		genl_unregister_family(&ipcon_fam);
		ipd_free(ipcon_db);
	}

	return ret;
}

void ipcon_genl_exit(void)
{

	netlink_unregister_notifier(&ipcon_netlink_notifier);
	genl_unregister_family(&ipcon_fam);
	ipd_free(ipcon_db);
}

#if 0
void ipcon_debugfs_lock_tree(int is_srv)
{
	if (is_srv)
		ipcon_rd_lock_tree(&cp_srvtree_root);
	else
		ipcon_rd_lock_tree(&cp_grptree_root);
}

void ipcon_debugfs_unlock_tree(int is_srv)
{
	if (is_srv)
		ipcon_rd_unlock_tree(&cp_srvtree_root);
	else
		ipcon_rd_unlock_tree(&cp_grptree_root);
}

struct ipcon_tree_node *ipcon_lookup_unlock(char *name, int is_srv)
{
	if (is_srv)
		return cp_lookup(&cp_srvtree_root, name);

	return cp_lookup(&cp_grptree_root, name);
}

const struct nla_policy *ipcon_get_policy(void)
{
	return (const struct nla_policy *)ipcon_policy;
}

const struct genl_family *ipcon_get_family(void)
{
	return (const struct genl_family *)&ipcon_fam;
}
#endif
