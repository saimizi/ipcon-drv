/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <asm/bitops.h>

#include "af_netlink.h"

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
	.name = IPCON_NAME,
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
	[IPCON_ATTR_SRC_PEER] = {.type = NLA_NUL_STRING,
				.len = IPCON_MAX_NAME_LEN - 1 },
};

static int ipcon_filter(struct sock *dsk, struct sk_buff *skb, void *data)
{
	struct ipcon_peer_node *ipn = NULL;

	ipn = ipd_lookup_byport(ipcon_db, nlk_sk(dsk)->portid);
	if (!ipn) {
		ipcon_warn("Drop multicast msg to suspicious port %lu\n",
			(unsigned long)nlk_sk(dsk)->portid);
		return 1;
	}

	ipcon_dbg("Multicast to %s@%lu.\n",
			ipn->name,
			(unsigned long)ipn->port);

	return 0;
}

static int ipcon_multicast(struct sk_buff *skb, u32 port, unsigned int group,
		gfp_t flags)
{
	int ret = 0;
	struct genl_family *family = &ipcon_fam;
	struct net *net = &init_net;


	do {
		if (WARN_ON_ONCE(group >= family->n_mcgrps)) {
			ret = -EINVAL;
			break;
		}

		group += family->mcgrp_offset;
		NETLINK_CB(skb).dst_group = group;

		ret = netlink_broadcast_filtered(net->genl_sock,
				skb,
				port,
				group,
				flags,
				ipcon_filter,
				NULL);

	} while (0);

	return ret;
}

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

		ipcon_multicast(msg, 0, IPCON_KERNEL_GROUP_PORT, flags);

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
	/*
	 * Since both ctrl port and com port resides in a single
	 * peer, only use com port can remove peer node (ipn).
	 */
	ipn = ipd_lookup_byport(ipcon_db, (u32)n->portid);
	if (ipn) {
		ipn_del(ipn);

		if (!hash_empty(ipn->ipn_group_ht)) {
			hash_for_each(ipn->ipn_group_ht, bkt, igi, igi_hgroup) {
				igi_del(igi);
				unreg_group(ipcon_db, igi->group);

				ipcon_dbg("Group %s.%s@%d removed.\n",
					ipn->name, igi->name, igi->group);

				ik.type = IPCON_EVENT_GRP_REMOVE;
				strcpy(ik.group.name, igi->name);
				strcpy(ik.group.peer_name, ipn->name);

				ipcon_send_kevent(&ik, GFP_ATOMIC, 0);

				igi_free(igi);
			}
		}

		ik.type = IPCON_EVENT_PEER_REMOVE;
		strcpy(ik.peer.name, ipn->name);
		ipcon_send_kevent(&ik, GFP_ATOMIC, 0);

		ipn_free(ipn);

		/* Decrease reference count */
		module_put(THIS_MODULE);
	}
	ipd_wr_unlock(ipcon_db);

	return 0;
}


static int ipcon_peer_reslove(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	void *hdr;
	int flag = 0;

	do {
		struct sk_buff *msg;

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_PEER_NAME]) {
			ret = -EINVAL;
			break;
		}

		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		if (msg_type != IPCON_MSG_UNICAST) {
			ret = -EINVAL;
			break;
		}

		nla_strlcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
				IPCON_MAX_NAME_LEN);

		ipd_rd_lock(ipcon_db);
		ipn = ipd_lookup_byname(ipcon_db, name);
		if (ipn)
			flag = 1;
		ipd_rd_unlock(ipcon_db);

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = genlmsg_put(msg, 0, 0, &ipcon_fam, 0, IPCON_PEER_RESLOVE);

		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		if (flag)
			nla_put_flag(msg, IPCON_ATTR_FLAG);
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

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_GRP_NAME])
		return -EINVAL;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

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
			ipcon_err("No free group id.");
			ret = -ENOBUFS;
			break;
		}


		ipn = ipd_lookup_bycport(ipcon_db, info->snd_portid);
		if (!ipn) {
			ipcon_err("No port %lu found\n.",
					(unsigned long)info->snd_portid);
			ret = -ENOENT;
			break;
		}

		igi = ipn_lookup_byname(ipn, name);
		if (igi) {
			ipcon_err("Group %s existed.\n", name);
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
		ipcon_dbg("Group %s.%s@%d registered.\n",
				ipn->name, igi->name, id);

		ik.type = IPCON_EVENT_GRP_ADD;
		strcpy(ik.group.name, name);
		strcpy(ik.group.peer_name, ipn->name);
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
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;

	ipd_wr_lock(ipcon_db);
	do {
		struct ipcon_kevent ik;

		if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
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
		nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
				IPCON_MAX_NAME_LEN);

		ipn = ipd_lookup_bycport(ipcon_db, ctrl_port);
		if (!ipn) {
			ret = -ENOENT;
			break;
		}

		igi = ipn_lookup_byname(ipn, name);
		if (!igi) {
			ret = -ENOENT;
			break;
		}
		ipcon_dbg("Group %s.%s@%d removed.\n",
				ipn->name, igi->name, igi->group);

		unreg_group(ipcon_db, igi->group);
		igi_del(igi);

		ik.type = IPCON_EVENT_GRP_REMOVE;
		strcpy(ik.group.name, name);
		strcpy(ik.group.peer_name, ipn->name);
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
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_peer_node *self = NULL;
	struct ipcon_group_info *igi = NULL;
	void *hdr;
	int send_last_msg = 0;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_SRV_NAME] ||
		!info->attrs[IPCON_ATTR_GRP_NAME])
		return  -EINVAL;

	ctrl_port = info->snd_portid;
	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

	nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
			IPCON_MAX_NAME_LEN);

	nla_strlcpy(srvname, info->attrs[IPCON_ATTR_SRV_NAME],
			IPCON_MAX_NAME_LEN);

	if (info->attrs[IPCON_ATTR_FLAG])
		send_last_msg = 1;

	ipd_rd_lock(ipcon_db);

	do {
		struct sk_buff *msg;

		self = ipd_lookup_bycport(ipcon_db, info->snd_portid);
		BUG_ON(!self);

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

		/* FIXME : this is NOT the right place to do it.
		 * If target group found, Send cached last group message to
		 * communication port if required. since genlmsg_unicast() will
		 * consume the skbuff, a copy has to be created before sending.
		 *
		 * see ipcon_multicast_msg().
		 */
		if (send_last_msg && igi->last_grp_msg) {
			skb_get(igi->last_grp_msg);
			msg = igi->last_grp_msg;
			if (msg->sk)
				msg->sk = NULL;
			genlmsg_unicast(genl_info_net(info), msg, self->port);
			ipcon_dbg("Send last msg of %s.%s to %s@%lu.\n",
					ipn->name,
					igi->name,
					self->name,
					(unsigned long) self->port);
		}

	} while (0);

	ipd_rd_unlock(ipcon_db);

	return ret;
}

static int ipcon_unicast_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 msg_type;
	struct ipcon_peer_node *self = NULL;
	struct ipcon_peer_node *ipn = NULL;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_PEER_NAME] ||
		!info->attrs[IPCON_ATTR_SRC_PEER] ||
		!info->attrs[IPCON_ATTR_DATA])
		return -EINVAL;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

	nla_strlcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
			IPCON_MAX_NAME_LEN);

	if (!strcmp(IPCON_NAME, name))
		return -EINVAL;

	ipd_rd_lock(ipcon_db);
	do {
		struct sk_buff *msg = skb_clone(skb, GFP_KERNEL);

		self = ipd_lookup_bycport(ipcon_db, info->snd_portid);
		BUG_ON(!self);

		ipn = ipd_lookup_byname(ipcon_db, name);
		if (!ipn) {
			ipcon_err("%s: Peer %s not found.\n", __func__, name);
			ret = -ENOENT;
			break;
		}

		ipcon_dbg("Msg %s@%lu --> %s@%lu\n",
				self->name,
				(unsigned long)self->port,
				ipn->name,
				(unsigned long)ipn->port);

		ret = genlmsg_unicast(genl_info_net(info), msg,
				ipn->port);


	} while (0);
	ipd_rd_unlock(ipcon_db);

	return ret;
}

static int ipcon_multicast_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 ctrl_port;
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_GRP_NAME] ||
		!info->attrs[IPCON_ATTR_DATA])
		return -EINVAL;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_MULTICAST)
		return -EINVAL;

	ctrl_port = info->snd_portid;
	nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
			IPCON_MAX_NAME_LEN);

	if (!strcmp(IPCON_KERNEL_GROUP, name))
		return -EINVAL;

	ipd_wr_lock(ipcon_db);
	do {
		struct sk_buff *msg = skb_clone(skb, GFP_KERNEL);

		ipn = ipd_lookup_bycport(ipcon_db, ctrl_port);
		if (!ipn) {
			ret = -ENOENT;
			break;
		}

		igi = ipn_lookup_byname(ipn, name);
		if (!igi) {
			ret = -ENOENT;
			break;
		}

		ipcon_dbg("Send msg to group %s.%s.\n",
				ipn->name, igi->name);

		ret = ipcon_multicast(msg, ipn->ctrl_port, igi->group,
				GFP_KERNEL);

		if (ret < 0)
			break;

		ipcon_dbg("Update last msg of %s.%s.\n",
				ipn->name, igi->name);

		/* Caching the last muticast message */
		if (igi->last_grp_msg)
			nlmsg_free(igi->last_grp_msg);

		igi->last_grp_msg = skb_clone(skb, GFP_KERNEL);



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
		ipcon_send_kevent(&ik, GFP_ATOMIC, 0);

	} while (0);
	ipd_wr_unlock(ipcon_db);

	return ret;

}

static const struct genl_ops ipcon_ops[] = {
	{
		.cmd = IPCON_PEER_RESLOVE,
		.doit = ipcon_peer_reslove,
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
		.cmd = IPCON_USR_MSG,
		.doit = ipcon_unicast_msg,
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

	ipn = ipn_alloc(0, 0, IPCON_NAME, GFP_KERNEL);
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
