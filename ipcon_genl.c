/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <asm/bitops.h>

#include "af_netlink.h"
#include "ipcon_in.h"

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
	[IPCON_ATTR_PEER_TYPE] = {.type = NLA_U32},
};

static inline int is_publisher(struct ipcon_peer_node *ipn)
{
	return (ipn->type == PUBLISHER ||
		ipn->type == SERVICE_PUBLISHER);
}

static inline int is_service(struct ipcon_peer_node *ipn)
{
	return (ipn->type == SERVICE ||
		ipn->type == SERVICE_PUBLISHER);
}

static inline int is_anon(struct ipcon_peer_node *ipn)
{
	return (ipn->type == ANON);
}

static inline int can_rcv_msg(struct ipcon_peer_node *ipn)
{
	return (ipn->type != PUBLISHER);
}

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
	int real_group = group + family->mcgrp_offset;

	do {
		if (WARN_ON_ONCE(group >= family->n_mcgrps)) {
			ret = -EINVAL;
			break;
		}

		/* if no listener, just return as 0 */
		if (!netlink_has_listeners(net->genl_sock, real_group)) {
			ipcon_dbg("%s: No listener in group %d\n",
				__func__, group);
			break;
		}

		NETLINK_CB(skb).dst_group = group;
		ret = netlink_broadcast_filtered(net->genl_sock,
				skb,
				port,
				real_group,
				flags,
				ipcon_filter,
				NULL);

	} while (0);

	return ret;
}

struct ipcon_work {
	struct work_struct work;
	void *data;
};

static struct ipcon_work *iw_alloc(work_func_t func, u32 datalen, gfp_t flags)
{
	struct ipcon_work *iw = NULL;

	iw = kmalloc(sizeof(*iw), flags);
	if (iw) {
		INIT_WORK(&iw->work, func);
		iw->data = kmalloc(datalen, flags);
		if (!iw->data)
			kfree(iw);
	}

	return iw;
}

static void iw_free(struct ipcon_work *iw)
{
	kfree(iw->data);
	kfree(iw);
}

static void ipcon_send_kevent_msg(struct ipcon_kevent *ik)
{
	int ret = 0;
	struct sk_buff *msg = NULL;
	void *hdr;

	if (!ik)
		return;

	do {
		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
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

		ipcon_multicast(msg, 0, IPCON_KERNEL_GROUP_PORT, GFP_KERNEL);

	} while (0);
}

static void ipcon_kevent_worker(struct work_struct *work)
{
	struct ipcon_work *iw = container_of(work, struct ipcon_work, work);
	struct ipcon_kevent *ik = iw->data;

	ipcon_dbg("enter kevent: %d\n", ik->type);

	ipcon_send_kevent_msg(ik);

	/*
	 * this will free struct work_struct "work" itself.
	 * workqueue implementation will not access work anymore.
	 * see comment in process_one_work() of workqueue.c
	 */
	iw_free(iw);
	ipcon_dbg("exit.\n");
}

static void ipcon_notify_worker(struct work_struct *work)
{
	struct ipcon_work *iw = container_of(work, struct ipcon_work, work);
	u32 port = *((u32 *)iw->data);
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;
	struct ipcon_kevent *ik = NULL;
	int bkt = 0;

	if (!port)
		return;

	ipcon_dbg("enter port: %lu\n", (unsigned long)port);

	do {
		/*
		 * Since both ctrl port and com port resides in a single
		 * peer, only use com port can remove peer node (ipn).
		 */
		ipd_wr_lock(ipcon_db);
		ipn = ipd_lookup_byport(ipcon_db, port);
		ipn_del(ipn);
		ipd_wr_unlock(ipcon_db);

		if (!ipn)
			break;

		/* Decrease reference count */
		module_put(THIS_MODULE);

		/* No need notify user space for an anonymous peer */
		if (is_anon(ipn))
			break;

		if (!hash_empty(ipn->ipn_group_ht)) {
			hash_for_each(ipn->ipn_group_ht, bkt, igi, igi_hgroup) {
				struct ipcon_work *iw_mc = NULL;

				igi_del(igi);
				unreg_group(ipcon_db, igi->group);

				ipcon_dbg("Group %s.%s@%d removed.\n",
					ipn->name, igi->name, igi->group);

				/* TODO Add completion here */
				ipcon_clear_multicast_user(&ipcon_fam,
						igi->group);

				iw_mc = iw_alloc(ipcon_kevent_worker,
						sizeof(*ik), GFP_KERNEL);
				if (iw_mc) {
					ik = iw_mc->data;
					ik->type = IPCON_EVENT_GRP_REMOVE;
					strcpy(ik->group.name, igi->name);
					strcpy(ik->group.peer_name, ipn->name);
					queue_work(ipcon_db->mc_wq,
							&iw_mc->work);
				}

				igi_free(igi);
			}
		}

		/*
		 * Only notify user space for a service peer.
		 * for a publisher, only group name is meaningful, not peer
		 * name.
		 */
		if (is_service(ipn)) {
			struct ipcon_work *iw_mc = NULL;

			iw_mc = iw_alloc(ipcon_kevent_worker,
					sizeof(*ik), GFP_KERNEL);
			if (iw_mc) {
				ik = iw_mc->data;
				ik->type = IPCON_EVENT_PEER_REMOVE;
				strcpy(ik->peer.name, ipn->name);
				queue_work(ipcon_db->mc_wq, &iw_mc->work);
			}
		}
	} while (0);

	ipn_free(ipn);
	iw_free(iw);
	ipcon_dbg("exit\n");
}

struct ipcon_multicast_worker_data {
	unsigned int group;
	struct sk_buff *msg;
};

static void ipcon_multicast_worker(struct work_struct *work)
{
	struct ipcon_work *iw = container_of(work, struct ipcon_work, work);
	struct ipcon_multicast_worker_data *imwd = iw->data;

	ipcon_dbg("%s: group: %d\n", __func__, imwd->group);

	if (imwd->group == IPCON_KERNEL_GROUP_PORT)
		return;

	ipcon_multicast(imwd->msg, 0, imwd->group, GFP_KERNEL);

	iw_free(iw);
}

/*
 * This function is called from another context.
 */
static int ipcon_netlink_notify(struct notifier_block *nb,
			  unsigned long state, void *_notify)
{
	struct netlink_notify *n = _notify;
	struct ipcon_work *iw = NULL;

	if (n->protocol != NETLINK_GENERIC)
		return NOTIFY_DONE;

	if (state != NETLINK_URELEASE)
		return NOTIFY_DONE;

	iw = iw_alloc(ipcon_notify_worker, sizeof(n->portid), GFP_ATOMIC);
	if (iw) {
		*((u32 *)iw->data) = n->portid;
		queue_work(ipcon_db->notify_wq, &iw->work);
	}

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

static int ipn_reg_group(struct ipcon_peer_node *ipn, char *name,
		unsigned int group)
{
	int ret = 0;
	struct ipcon_group_info *igi = NULL;
	struct ipcon_group_info *existed = NULL;
	struct ipcon_kevent *ik;
	struct ipcon_work *iw = NULL;

	do {
		igi = igi_alloc(name, (u32)group, GFP_ATOMIC);
		if (!igi) {
			ret = -ENOMEM;
			break;
		}

		ipn_wr_lock(ipn);
		existed = ipn_lookup_byname(ipn, name);
		if (!existed)
			ret = ipn_insert(ipn, igi);
		else
			ret = -EEXIST;
		ipn_wr_unlock(ipn);

		if (ret < 0) {
			igi_free(igi);
			break;
		}

		ipcon_dbg("Group %s.%s@%d registered.\n",
			ipn->name, igi->name, group);

		iw = iw_alloc(ipcon_kevent_worker, sizeof(*ik), GFP_ATOMIC);
		if (iw) {
			ik = iw->data;

			ik->type = IPCON_EVENT_GRP_ADD;
			strcpy(ik->group.name, name);
			strcpy(ik->group.peer_name, ipn->name);
			queue_work(ipcon_db->mc_wq, &iw->work);
		}
	} while (0);

	return ret;
}

static int ipn_unreg_group(struct ipcon_peer_node *ipn, char *name,
		unsigned int *group)
{
	int ret = 0;
	struct ipcon_group_info *igi = NULL;
	struct ipcon_kevent *ik;
	struct ipcon_work *iw = NULL;

	do {
		ipn_wr_lock(ipn);
		igi = ipn_lookup_byname(ipn, name);
		igi_del(igi);
		ipn_wr_unlock(ipn);

		if (!igi) {
			ret = -ESRCH;
			break;
		}


		*group = igi->group;

		ipcon_dbg("Group %s.%s@%d unregistered.\n",
			ipn->name, igi->name, igi->group);

		iw = iw_alloc(ipcon_kevent_worker, sizeof(*ik), GFP_ATOMIC);
		if (iw) {
			ik = iw->data;

			ik->type = IPCON_EVENT_GRP_REMOVE;
			strcpy(ik->group.name, name);
			strcpy(ik->group.peer_name, ipn->name);
			queue_work(ipcon_db->mc_wq, &iw->work);
		}

		igi_free(igi);
	} while (0);

	return ret;
}

static int ipcon_grp_reg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	int id = 0;

	ipcon_dbg("enter.\n");
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

	id = reg_new_group(ipcon_db);
	if (id >= IPCON_MAX_GROUP)
		return -ENOBUFS;

	ipd_rd_lock(ipcon_db);
	do {
		ipn = ipd_lookup_bycport(ipcon_db, info->snd_portid);
		if (!ipn) {
			ipcon_err("No port %lu found\n.",
					(unsigned long)info->snd_portid);
			ret = -ESRCH;
			break;
		}

		if (!is_publisher(ipn)) {
			ipcon_err("%s: %s is not a publisher.\n",
					__func__, ipn->name);
			ret = -EPERM;
			break;
		}

		ret = ipn_reg_group(ipn, name, id);

	} while (0);
	ipd_rd_unlock(ipcon_db);

	if (ret < 0)
		unreg_group(ipcon_db, id);

	ipcon_dbg("exit (%d).\n", ret);
	return ret;
}

static int ipcon_grp_unreg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 ctrl_port;
	__u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	unsigned int group = 0;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_GRP_NAME])
		return -EINVAL;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

	ipd_rd_lock(ipcon_db);
	do {
		ctrl_port = info->snd_portid;
		nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
				IPCON_MAX_NAME_LEN);

		ipn = ipd_lookup_bycport(ipcon_db, ctrl_port);
		if (!ipn) {
			ret = -ESRCH;
			break;
		}

		if (!is_publisher(ipn)) {
			ipcon_err("%s: %s is not a publisher.\n",
					__func__, ipn->name);
			ret = -EINVAL;
			break;
		}

		ret = ipn_unreg_group(ipn, name, &group);

	} while (0);
	ipd_rd_unlock(ipcon_db);

	if (!ret)
		ipcon_clear_multicast_user(&ipcon_fam, group);

	/*
	 * Unregister group id at last, so that group id will not be reused
	 * during ipcon_clear_multicast_user which maybe sleep.
	 */
	unreg_group(ipcon_db, group);

	return ret;
}

/*
 * FIXME:
 * Since we can not register group in ipcon driver at present, a race condition
 * between ADD_MEMBERSHIP in user land and ipcon_grp_unreg() may happen, which
 * can not be avoided. ipcon_grp_reslove should be replaced with something like
 * ipcon_join_grp()...
 */
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
	int send_last_msg = 0;
	unsigned int group = 0;

	ipcon_dbg("enter.\n");

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
		self = ipd_lookup_bycport(ipcon_db, info->snd_portid);
		BUG_ON(!self);

		ipn = ipd_lookup_byname(ipcon_db, srvname);
		if (!ipn) {
			ret = -ESRCH;
			break;
		}

		ipn_rd_lock(ipn);
		if (!is_publisher(ipn)) {
			ret = -ESRCH;
			break;
		}

		igi = ipn_lookup_byname(ipn, name);
		if (!igi) {
			ret = -ESRCH;
			break;
		}

		group = igi->group + ipcon_fam.mcgrp_offset;
		ipn_rd_unlock(ipn);
	} while (0);
	ipd_rd_unlock(ipcon_db);

	/*
	 * Send group id to user land so that it can use it to do
	 * ADD_MEMBERSHIP. Too bad...
	 */
	do {
		struct sk_buff *msg;
		void *hdr;

		if (ret)
			break;

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
		nla_put_u32(msg, IPCON_ATTR_GROUP, group);

		genlmsg_end(msg, hdr);
		ret = genlmsg_reply(msg, info);
	} while (0);

	ipcon_dbg("%s exit(%d).\n", __func__, ret);
	return ret;
}

static int ipcon_unicast_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 msg_type;
	struct ipcon_peer_node *self = NULL;
	struct ipcon_peer_node *ipn = NULL;
	u32 tport = 0;
	struct sk_buff *msg = skb_clone(skb, GFP_KERNEL);

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_PEER_NAME] ||
		!info->attrs[IPCON_ATTR_SRC_PEER] ||
		!info->attrs[IPCON_ATTR_DATA])
		return -EINVAL;

	if (!msg)
		return -ENOMEM;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_UNICAST)
		return -EINVAL;

	nla_strlcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
			IPCON_MAX_NAME_LEN);

	if (!strcmp(IPCON_NAME, name))
		return -EINVAL;

	ipd_rd_lock(ipcon_db);
	do {

		self = ipd_lookup_bycport(ipcon_db, info->snd_portid);
		BUG_ON(!self);

		ipn = ipd_lookup_byname(ipcon_db, name);
		if (!ipn) {
			ipcon_err("%s: Peer %s not found.\n", __func__, name);
			ret = -ESRCH;
			break;
		}

		if (!can_rcv_msg(ipn)) {
			ipcon_err("%s: %s can not receive mesage.\n",
					__func__, ipn->name);

			ret = -EPERM;
			break;
		}

		tport = ipn->port;
		ipcon_dbg("Msg %s@%lu --> %s@%lu\n",
				self->name,
				(unsigned long)self->port,
				ipn->name,
				(unsigned long)ipn->port);
	} while (0);
	ipd_rd_unlock(ipcon_db);

	if (!ret)
		ret = genlmsg_unicast(genl_info_net(info), msg, tport);
	else
		kfree_skb(msg);

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
	unsigned int group = 0;
	struct sk_buff *msg = skb_clone(skb, GFP_KERNEL);
	struct ipcon_work *iw = NULL;
	int sync = 0;

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_GRP_NAME] ||
		!info->attrs[IPCON_ATTR_DATA])
		return -EINVAL;

	if (!msg)
		return -ENOMEM;

	msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
	if (msg_type != IPCON_MSG_MULTICAST)
		return -EINVAL;

	ctrl_port = info->snd_portid;
	nla_strlcpy(name, info->attrs[IPCON_ATTR_GRP_NAME],
			IPCON_MAX_NAME_LEN);

	if (!strcmp(IPCON_KERNEL_GROUP, name))
		return -EINVAL;

	if (info->attrs[IPCON_ATTR_FLAG])
		sync = 1;

	ipd_rd_lock(ipcon_db);
	do {
		ipn = ipd_lookup_bycport(ipcon_db, ctrl_port);
		if (!ipn) {
			ret = -ESRCH;
			break;
		}

		if (!is_publisher(ipn)) {
			ipcon_err("%s: %s is not a publisher.\n",
					__func__, ipn->name);
			ret = -EPERM;
			break;
		}

		ipn_rd_lock(ipn);
		igi = ipn_lookup_byname(ipn, name);
		if (!igi)
			ret = -ESRCH;
		else
			group = igi->group;
		ipn_rd_unlock(ipn);
	} while (0);
	ipd_rd_unlock(ipcon_db);

	/*
	 * Ok, send multicast message.
	 *
	 * If sync is specified, ipcon_multicast() is called directly, which
	 * will not return until message is deliveried.
	 *
	 * If sync is not specified, just queue the message to make worker do
	 * it later, which maybe not deliveried if sender unregister the group
	 * before the message is deliveried.
	 */

	do {
		struct ipcon_multicast_worker_data *imwd = NULL;

		if (ret < 0)
			break;

		if (sync) {
			ret = ipcon_multicast(msg, 0, group, GFP_KERNEL);
			break;
		}

		iw = iw_alloc(ipcon_multicast_worker,
				sizeof(*imwd), GFP_ATOMIC);

		if (!iw) {
			ret = -ENOMEM;
			break;
		}

		imwd = iw->data;
		imwd->group = group;
		imwd->msg = msg;
		queue_work(ipcon_db->mc_wq, &iw->work);

	} while (0);

	if (ret < 0)
		kfree_skb(msg);

	return ret;
}

static int ipcon_peer_reg(struct sk_buff *skb, struct genl_info *info)
{
	char name[IPCON_MAX_NAME_LEN];
	int ret = 0;
	struct ipcon_peer_node *ipn = NULL;
	u32 port = 0;
	struct ipcon_kevent *ik;
	struct ipcon_work *iw = NULL;
	u32 peer_type = 0;

	ipcon_dbg("%s enter.\n", __func__);

	if (!info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_PORT] ||
		!info->attrs[IPCON_ATTR_PEER_TYPE] ||
		!info->attrs[IPCON_ATTR_PEER_NAME])
		return -EINVAL;

	ipd_wr_lock(ipcon_db);
	do {
		port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
		if (!port) {
			ret = -EINVAL;
			break;
		}

		nla_strlcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
				IPCON_MAX_NAME_LEN);

		peer_type = nla_get_u32(info->attrs[IPCON_ATTR_PEER_TYPE]);
		if (peer_type >= (u32)MAX_PEER_TYPE) {
			ret = -EINVAL;
			ipcon_dbg("%s: Invalid peer type %lu.\n",
				__func__, (unsigned long)peer_type);
			break;
		}

		ipn = ipn_alloc(port, info->snd_portid, name,
				(enum peer_type)peer_type, GFP_ATOMIC);
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

		if (is_service(ipn)) {
			iw = iw_alloc(ipcon_kevent_worker,
					sizeof(*ik), GFP_ATOMIC);
			if (iw) {
				ik = iw->data;
				ik->type = IPCON_EVENT_PEER_ADD;
				strcpy(ik->peer.name, ipn->name);
				queue_work(ipcon_db->mc_wq, &iw->work);
			}
		}

	} while (0);
	ipd_wr_unlock(ipcon_db);

	ipcon_dbg("%s exit(%d).\n", __func__, ret);
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

	ipn = ipn_alloc(0, 0, IPCON_NAME, SERVICE_PUBLISHER, GFP_KERNEL);
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
