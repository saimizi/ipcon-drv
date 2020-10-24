/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <asm/bitops.h>

#include "ipcon.h"
#include "ipcon_msg.h"
#include "ipcon_nl.h"
#include "ipcon_db.h"
#include "name_cache.h"
#include "ipcon_dbg.h"
#include "../af_netlink.h"

/* Reference
 * - inclue/net/netlink.h
 */

#define UNUSED_GROUP_NAME	"ipconG"



static struct sock *ipcon_nl_sock;
static struct ipcon_peer_db *ipcon_db;
static struct ipcon_peer_node *ipn_kernel;
static struct ipcon_group_info *igi_kernel;
DEFINE_MUTEX(ipcon_mutex);

static const struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_CPORT] = {
		.type = NLA_U32,
	},

	[IPCON_ATTR_SPORT] = {
		.type = NLA_U32,
	},

	[IPCON_ATTR_RPORT] = {
		.type = NLA_U32,
	},

	[IPCON_ATTR_GROUP] = {
		.type = NLA_U32,
	},

	[IPCON_ATTR_PEER_NAME] = {
		.type = NLA_NUL_STRING,
		.len = IPCON_MAX_NAME_LEN - 1,
	},

	[IPCON_ATTR_GROUP_NAME] = {
		.type = NLA_NUL_STRING,
		.len = IPCON_MAX_NAME_LEN - 1,
	},

	[IPCON_ATTR_DATA] = {
		.type = NLA_BINARY,
		.len = MAX_IPCONMSG_DATA_SIZE,
	},

	[IPCON_ATTR_FLAG] = {
		.type =	NLA_U32,
	},
};

static inline int is_anon(struct ipcon_peer_node *ipn)
{
	return (ipn->type == PEER_TYPE_ANON);
}


void ipcon_clear_multicast_user(unsigned int group)
{
	struct net *net;

	netlink_table_grab();
	rcu_read_lock();
	for_each_net_rcu(net) {
		__netlink_clear_multicast_users(ipcon_nl_sock, group);
	}
	rcu_read_unlock();
	netlink_table_ungrab();
}

static int ipcon_kevent_filter(struct sock *dsk, struct sk_buff *skb, void *data)
{
	struct ipcon_peer_node *ipn = NULL;
	unsigned long ipn_flags;
	int skip = 0;

	ipn = ipd_lookup_byrport(ipcon_db, nlk_sk(dsk)->portid);
	if (!ipn) {
		ipcon_warn("Drop multicast msg to suspicious port %lu\n",
			(unsigned long)nlk_sk(dsk)->portid);
		return 1;
	}

	if (ipn  == ipn_kernel)
		return 1;


	/* data is only present for ipcon_kevent when sending ipcon kevent */
	do {
		ipn_rd_lock(ipn);
		ipn_flags = ipn->flags;
		ipn_rd_unlock(ipn);

		if (ipn_flags & IPN_FLG_DISABLE_KEVENT_FILTER) {
			skip = 0;
			break;
		}

		skip = ipn_filter_kevent(ipn, data);
		if (skip) {
			struct ipcon_kevent *ik = data;
			char *event = NULL;
			char *peer_name = NULL;
			char *group_name = NULL;

			switch (ik->type) {
			case IPCON_EVENT_PEER_ADD:
				event = "IPCON_EVENT_PEER_ADD";
				peer_name = ik->peer.name;
				break;
			case IPCON_EVENT_PEER_REMOVE:
				event = "IPCON_EVENT_PEER_REMOVE";
				peer_name = ik->peer.name;
				break;
			case IPCON_EVENT_GRP_ADD:
				event = "IPCON_EVENT_GRP_ADD";
				peer_name = ik->group.peer_name;
				group_name = ik->group.name;
				break;
			case IPCON_EVENT_GRP_REMOVE:
				event = "IPCON_EVENT_GRP_REMOVE";
				peer_name = ik->group.peer_name;
				group_name = ik->group.name;
				break;
			}

			if (group_name)
				ipcon_dbg("Drop notify to %s : %s %s %s\n",
					nc_refname(ipn->nameid),
					event,
					peer_name,
					group_name);
			else
				ipcon_dbg("Drop notify to %s : %s %s\n",
					nc_refname(ipn->nameid),
					event,
					peer_name);
		}
	} while (0);

	if (!skip) {
		ipcon_dbg("Multicast to %s@%lu.\n",
			nc_refname(ipn->nameid),
			(unsigned long)ipn_rcvport(ipn));
	}

	return skip;
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

static void ipcon_kevent_worker(struct work_struct *work)
{
	struct ipcon_work *iw = container_of(work, struct ipcon_work, work);
	struct ipcon_kevent *ik = iw->data;

	ipcon_dbg("enter kevent: %d\n", ik->type);

	do {
		struct sk_buff	*msg = ipconmsg_new(GFP_KERNEL);
		void *p = NULL;

		if (!msg) {
			ipcon_err("%s: no memory for skb.", __func__);
			break;
		}

		p = ipconmsg_put(msg, 0, 0, IPCON_MULTICAST_MSG, 0);

		nla_put_string(msg, IPCON_ATTR_PEER_NAME, IPCON_NAME);
		nla_put_string(msg, IPCON_ATTR_GROUP_NAME,
				IPCON_KERNEL_GROUP_NAME);
		nla_put(msg, IPCON_ATTR_DATA, sizeof(*ik), ik);

		ipconmsg_end(msg, p);

		ipcon_multicast_filtered(msg, 0, IPCON_KERNEL_GROUP, GFP_KERNEL,
				ipcon_kevent_filter, ik);

		iw_free(iw);
	} while (0);
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
	struct hlist_node *tmp;

	if (!port)
		return;

	ipcon_dbg("enter port: %lu\n", (unsigned long)port);

	do {
		struct ipcon_work *iw_mc = NULL;
		/*
		 * Only use rcv port to remove peer node (ipn).
		 * Because ipcon_kevent_filter uses rport to judge suspicious
		 * port.
		 */
		ipn = ipd_lookup_byrport(ipcon_db, port);
		ipn_del(ipn);
		if (!ipn)
			break;

		/* Decrease reference count */
		module_put(THIS_MODULE);

#if 0
		/* No need notify user space for an anonymous peer */
		if (is_anon(ipn))
			break;
#endif

		if (!hash_empty(ipn->ipn_group_ht)) {
			hash_for_each_safe(ipn->ipn_group_ht, bkt, tmp,
					igi, igi_hgroup) {
				struct ipcon_work *iw_mc = NULL;

				igi_del(igi);

				flush_workqueue(igi->mc_wq);

				/* clear users */
				ipcon_clear_multicast_user(igi->group);


				ipcon_dbg("Group %s.%s@%d removed.\n",
					nc_refname(ipn->nameid),
					nc_refname(igi->nameid),
					igi->group);

				iw_mc = iw_alloc(ipcon_kevent_worker,
						sizeof(*ik), GFP_KERNEL);
				if (iw_mc) {
					ik = iw_mc->data;
					ik->type = IPCON_EVENT_GRP_REMOVE;
					nc_getname(igi->nameid, ik->group.name);
					nc_getname(ipn->nameid,
							ik->group.peer_name);
					queue_work(igi_kernel->mc_wq,
							&iw_mc->work);
				}

				igi_free(igi);

				unreg_group(ipcon_db, igi->group);
			}
		}

		/*
		 * Only notify user space for a service peer.
		 * for a publisher, only group name is meaningful, not peer
		 * name.
		 */

		iw_mc = iw_alloc(ipcon_kevent_worker, sizeof(*ik), GFP_KERNEL);
		if (iw_mc) {
			ik = iw_mc->data;
			ik->type = IPCON_EVENT_PEER_REMOVE;
			nc_getname(ipn->nameid, ik->peer.name);
			queue_work(igi_kernel->mc_wq, &iw_mc->work);
		}
	} while (0);

	ipn_free(ipn);
	iw_free(iw);
	ipcon_dbg("exit\n");
}

struct ipcon_multicast_worker_data {
	struct ipcon_group_info *igi;
	__u32	sender_port;
	struct sk_buff *skb;
};

static void ipcon_multicast_worker(struct work_struct *work)
{
	struct ipcon_work *iw = container_of(work, struct ipcon_work, work);
	struct ipcon_multicast_worker_data *imwd = iw->data;
	struct ipcon_group_info *igi = imwd->igi;

	ipcon_dbg("%s: group: %d\n", __func__, igi->group);

	if (igi->group == IPCON_KERNEL_GROUP)
		return;

	ipcon_multicast(imwd->skb, imwd->sender_port, igi->group, GFP_KERNEL);
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

	if (n->protocol != NETLINK_IPCON)
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

static int ipcon_peer_reslove(struct sk_buff *skb, struct ipcon_peer_node *self)
{
	int ret = 0;
	struct ipcon_peer_node *ipn = NULL;
	int nameid = 0;
	char name[IPCON_MAX_NAME_LEN];
	struct nlattr *tb[NUM_IPCON_ATTR];

	ipcon_dbg("enter.\n");
	do {
		ret = ipconmsg_parse(skb, tb, IPCON_ATTR_MAX,
				ipcon_policy, NULL);
		if (ret < 0)
			break;

		if (!tb[IPCON_ATTR_PEER_NAME]) {
			ret = -EINVAL;
			break;
		}

		nla_strlcpy(name, tb[IPCON_ATTR_PEER_NAME], IPCON_MAX_NAME_LEN);
		if (!valid_name(name)) {
			ret = -EINVAL;
			break;
		}

		nameid = nc_add(name, GFP_KERNEL);
		if (nameid < 0)
			return nameid;

		ipn_add_filter(self, IPCON_EVENT_PEER_ADD,
				nameid, 0, GFP_KERNEL);
		ipn_add_filter(self, IPCON_EVENT_PEER_REMOVE,
				nameid, 0, GFP_KERNEL);

		ipn = ipd_lookup_byname(ipcon_db, nameid);
		if (!ipn)
			ret = -ENOENT;

		nc_id_put(nameid);



	} while (0);

	ipcon_dbg("leave ret= %d\n", ret);
	return ret;
}

static int ipn_reg_group(struct ipcon_peer_node *ipn, int nameid,
		unsigned int group)
{
	int ret = 0;
	struct ipcon_group_info *igi = NULL;
	struct ipcon_group_info *existed = NULL;
	struct ipcon_kevent *ik;
	struct ipcon_work *iw = NULL;

	ipcon_dbg("enter.\n");
	do {
		igi = igi_alloc(nameid, (u32)group, GFP_ATOMIC);
		if (!igi) {
			ret = -ENOMEM;
			break;
		}

		existed = ipn_lookup_byname(ipn, nameid);
		if (!existed)
			ret = ipn_insert(ipn, igi);
		else
			ret = -EEXIST;

		if (ret < 0) {
			igi_free(igi);
			break;
		}

		iw = iw_alloc(ipcon_kevent_worker, sizeof(*ik), GFP_ATOMIC);
		if (iw) {
			ik = iw->data;

			ik->type = IPCON_EVENT_GRP_ADD;
			nc_getname(igi->nameid, ik->group.name);
			nc_getname(ipn->nameid, ik->group.peer_name);

			ipcon_dbg("Group %s.%s@%d registered.\n",
				ik->group.peer_name,
				ik->group.name,
				group);
			queue_work(igi_kernel->mc_wq, &iw->work);
		}
	} while (0);
	ipcon_dbg("exit (%d).\n", ret);

	return ret;
}

static int ipcon_grp_reg(struct sk_buff *skb, struct ipcon_peer_node *self)
{
	int ret = 0;
	int id = 0;
	int nameid = 0;
	char name[IPCON_MAX_NAME_LEN];
	struct nlattr *tb[NUM_IPCON_ATTR];

	ipcon_dbg("enter.\n");
	ret = ipconmsg_parse(skb, tb, IPCON_ATTR_MAX, ipcon_policy, NULL);
	if (ret < 0)
		return ret;

	if (!tb[IPCON_ATTR_GROUP_NAME])
		return -EINVAL;

	nla_strlcpy(name, tb[IPCON_ATTR_GROUP_NAME], IPCON_MAX_NAME_LEN);
	nameid = nc_add(name, GFP_KERNEL);
	if (nameid < 0)
		return nameid;

	id = reg_new_group(ipcon_db);
	if (id > IPCON_MAX_GROUP)
		return -ENOBUFS;

	ret = ipn_reg_group(self, nameid, id);
	if (ret < 0)
		unreg_group(ipcon_db, id);

	nc_id_put(nameid);

	ipcon_dbg("exit (%d).\n", ret);
	return ret;
}

static int ipcon_grp_unreg(struct sk_buff *skb, struct ipcon_peer_node *self)
{
	int ret = 0;
	struct ipcon_group_info *igi = NULL;
	int nameid = 0;
	char name[IPCON_MAX_NAME_LEN];
	struct nlattr *tb[NUM_IPCON_ATTR];

	ipcon_dbg("enter.\n");

	ret = ipconmsg_parse(skb, tb, IPCON_ATTR_MAX, ipcon_policy, NULL);
	if (ret < 0)
		return ret;

	if (!tb[IPCON_ATTR_GROUP_NAME])
		return -EINVAL;

	nla_strlcpy(name, tb[IPCON_ATTR_GROUP_NAME], IPCON_MAX_NAME_LEN);
	if (!valid_name(name))
		return -EINVAL;

	nameid = nc_getid(name);
	if (nameid < 0)
		return nameid;


	igi = ipn_lookup_byname(self, nameid);
	/*
	 * Isolate this group from peer, so that no new group message
	 * accepted. igi_del() can deal with NULL.
	 */
	igi_del(igi);

	if (!igi)
		ret = -ESRCH;

	nc_id_put(nameid);

	if (!ret) {
		DEFINE_WAIT(wait);
		struct ipcon_work *iw = NULL;
		struct ipcon_kevent *ik;

		flush_workqueue(igi->mc_wq);

		/* clear users */
		ipcon_clear_multicast_user(igi->group);

		/* send group remove kevent */
		iw = iw_alloc(ipcon_kevent_worker, sizeof(*ik), GFP_KERNEL);
		if (iw) {
			ik = iw->data;

			ik->type = IPCON_EVENT_GRP_REMOVE;
			nc_getname(igi->nameid, ik->group.name);
			nc_getname(self->nameid, ik->group.peer_name);

			ipcon_dbg("Group %s.%s@%d removed.\n",
				ik->group.peer_name,
				ik->group.name,
				igi->group);

			queue_work(igi_kernel->mc_wq, &iw->work);
		}

		/* free igi */
		igi_free(igi);

		/* mark group id be reusable. */
		unreg_group(ipcon_db, igi->group);
	}

	ipcon_dbg("exit (%d).\n", ret);
	return ret;
}

static int ipcon_grp_reslove(struct sk_buff *skb, struct ipcon_peer_node *self)
{
	int ret = 0;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;
	unsigned int group = 0;
	int group_nameid = 0;
	int peer_nameid = 0;
	struct nlattr *tb[NUM_IPCON_ATTR];
	char peer_name[IPCON_MAX_NAME_LEN];
	char group_name[IPCON_MAX_NAME_LEN];


	ipcon_dbg("enter.\n");
	ret = ipconmsg_parse(skb, tb, IPCON_ATTR_MAX, ipcon_policy, NULL);
	if (ret < 0)
		return ret;

	if (!tb[IPCON_ATTR_GROUP_NAME] || !tb[IPCON_ATTR_PEER_NAME])
		return -EINVAL;

	nla_strlcpy(peer_name, tb[IPCON_ATTR_PEER_NAME], IPCON_MAX_NAME_LEN);
	nla_strlcpy(group_name, tb[IPCON_ATTR_GROUP_NAME], IPCON_MAX_NAME_LEN);
	if (!valid_name(peer_name) || !valid_name(group_name))
		return -EINVAL;

	group_nameid = nc_getid(group_name);
	if (group_nameid < 0)
		return group_nameid;

	peer_nameid = nc_getid(peer_name);
	if (peer_nameid < 0) {
		nc_id_put(group_nameid);
		return peer_nameid;
	}

	do {

		ipn_add_filter(self, IPCON_EVENT_GRP_ADD,
				peer_nameid, group_nameid, GFP_KERNEL);
		ipn_add_filter(self, IPCON_EVENT_GRP_REMOVE,
				peer_nameid, group_nameid, GFP_KERNEL);

		ipn = ipd_lookup_byname(ipcon_db, peer_nameid);
		if (!ipn) {
			ret = -ENOENT;
			break;
		}

		igi = ipn_lookup_byname(ipn, group_nameid);
		if (igi)
			group = igi->group;
		else
			ret = -ENOENT;

	} while (0);

	nc_id_put(peer_nameid);
	nc_id_put(group_nameid);

	if (ret == 0) {
		do {
			struct sk_buff	*msg = ipconmsg_new(GFP_KERNEL);
			void *p = NULL;

			if (!msg) {
				ret = -ENOMEM;
				break;
			}

			p = ipconmsg_put(msg, 0, ipconmsg_seq(skb),
					IPCON_GRP_RESLOVE, 0);

			nla_put_u32(msg, IPCON_ATTR_GROUP, group);
			ipconmsg_end(msg, p);
			ret = ipcon_unicast(msg, ipconmsg_srcport(skb));

		} while (0);

	}

	ipcon_dbg("%s exit(%d).\n", __func__, ret);
	return ret;
}


/**
 * ipconmsg_unicast - unicast a netlink message
 * @skb: netlink message as socket buffer
 * @portid: netlink portid of the destination socket
 */
int ipcon_unicast(struct sk_buff *skb, __u32 port)
{
	int ret = 0;

	do {
		BUG_ON(!ipcon_nl_sock);

		if (!skb) {
			ret = -EINVAL;
			break;
		}

		/* nlmsg_unicast return 0 when success and negative on error */
		ret = nlmsg_unicast(ipcon_nl_sock, skb, port);

	} while (0);

	return ret;
}


int ipcon_multicast_filtered(struct sk_buff *skb, __u32 exclusive_port,
	__u32 group, gfp_t flags,
	int (*filter)(struct sock *dsk, struct sk_buff *skb, void *data),
	void *filter_data)
{
	int ret = 0;

	do {
		BUG_ON(!ipcon_nl_sock);

		if (!skb) {
			ret = -EINVAL;
			break;
		}

                /* if no listener, just return as 0 */
                if (!netlink_has_listeners(ipcon_nl_sock, group)) {
                        ipcon_dbg("%s: No listener in group %d\n",
                                __func__, group);
                        break;
                }

		NETLINK_CB(skb).dst_group = group;
		ret = netlink_broadcast_filtered(ipcon_nl_sock,
                                skb,
                                exclusive_port,
                                group,
                                flags,
                                filter,
                                filter_data);
	} while (0);

	return ret >= 0 ? 0 : ret;
}

int ipcon_multicast(struct sk_buff *skb, __u32 exclusive_port,
	__u32 group, gfp_t flags)
{
	return ipcon_multicast_filtered(skb, exclusive_port, group,
			flags, NULL, NULL);
}

static int ipcon_unicast_msg(struct sk_buff *skb, struct ipcon_peer_node *self)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	struct ipcon_peer_node *ipn = NULL;
	u32 tport = 0;
	int nameid = 0;
	struct nlattr *tb[NUM_IPCON_ATTR];
	char peer_name[IPCON_MAX_NAME_LEN];


	ret = ipconmsg_parse(skb, tb, IPCON_ATTR_MAX, ipcon_policy, NULL);
	if (ret < 0)
		return ret;

	if (!tb[IPCON_ATTR_PEER_NAME] || !tb[IPCON_ATTR_DATA])
		return -EINVAL;

	nla_strlcpy(peer_name, tb[IPCON_ATTR_PEER_NAME], IPCON_MAX_NAME_LEN);
	if (!valid_name(peer_name))
		return -EINVAL;

	if (!strcmp(IPCON_NAME, peer_name))
		return -EINVAL;

	nameid = nc_getid(peer_name);
	if (nameid < 0)
		return nameid;

	do {
		void *p = NULL;
		struct sk_buff	*msg = NULL;

		ipn = ipd_lookup_byname(ipcon_db, nameid);
		if (!ipn) {
			ipcon_err("%s: Peer %s not found.\n",
				__func__, name);

			ret = -ESRCH;
			break;
		}
		tport = ipn_rcvport(ipn);

		msg = ipconmsg_new(GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		p = ipconmsg_put(msg, 0, 0, IPCON_USR_MSG, 0);

		nla_put(msg, IPCON_ATTR_DATA,
			nla_len(tb[IPCON_ATTR_DATA]),
			nla_data(tb[IPCON_ATTR_DATA]));

		nla_put_string(msg, IPCON_ATTR_PEER_NAME,
				nc_refname(self->nameid));

		ipconmsg_end(msg, p);

		ret = ipcon_unicast(msg, tport);

	} while (0);
	nc_id_put(nameid);

	return ret;
}

static int ipcon_multicast_msg(struct sk_buff *skb, struct ipcon_peer_node *self)
{
	int ret = 0;
	struct ipcon_group_info *igi = NULL;
	int group_nameid = 0;
	int peer_nameid = 0;
	struct nlattr *tb[NUM_IPCON_ATTR];
	char group_name[IPCON_MAX_NAME_LEN];
	int sync = 0;

	ret = ipconmsg_parse(skb, tb, IPCON_ATTR_MAX, ipcon_policy, NULL);
	if (ret < 0)
		return ret;

	if (!tb[IPCON_ATTR_GROUP_NAME] || !tb[IPCON_ATTR_DATA])
		return -EINVAL;

	if (tb[IPCON_ATTR_FLAG] &&
		(nla_get_u32(tb[IPCON_ATTR_FLAG]) &
		 IPCON_FLG_MULTICAST_SYNC))
		sync = 1;

	nla_strlcpy(group_name, tb[IPCON_ATTR_GROUP_NAME], IPCON_MAX_NAME_LEN);
	if (!valid_name(group_name))
		return -EINVAL;

	group_nameid = nc_getid(group_name);
	if (group_nameid < 0)
		return group_nameid;


	do {
		void *p = NULL;
		struct sk_buff	*msg = NULL;

		peer_nameid = ipn_nameid(self);

		igi = ipn_lookup_byname(self, group_nameid);
		if (!igi) {
			ret = -ESRCH;
			break;
		}

		msg = ipconmsg_new(GFP_KERNEL);

		p = ipconmsg_put(msg, 0, 0, IPCON_MULTICAST_MSG, 0);
		nla_put_string(msg, IPCON_ATTR_PEER_NAME,
				nc_refname(peer_nameid));

		nla_put_string(msg, IPCON_ATTR_GROUP_NAME,
				nc_refname(group_nameid));

		nla_put(msg, IPCON_ATTR_DATA,
			nla_len(tb[IPCON_ATTR_DATA]),
			nla_data(tb[IPCON_ATTR_DATA]));

		ipconmsg_end(msg, p);

		/*
		 * Ok, send multicast message.
		 *
		 * If sync is specified, ipcon_multicast() is called directly,
		 * which will not return until message is deliveried.
		 *
		 * If sync is not specified, just queue the message to make
		 * worker do it later, which maybe not deliveried if sender
		 * unregister the group before the message is deliveried.
		 */
		if (sync) {
			ret = ipcon_multicast(msg, ipn_rcvport(self),
					igi->group, GFP_KERNEL);

		} else {
			struct ipcon_multicast_worker_data *imwd;
			struct ipcon_work *iw = NULL;

			iw = iw_alloc(ipcon_multicast_worker,
					sizeof(*imwd), GFP_ATOMIC);
			if (!iw) {
				ret = -ENOMEM;
				break;
			}

			imwd = iw->data;
			imwd->igi = igi;
			imwd->sender_port = ipn_rcvport(self);
			imwd->skb = msg;
			queue_work(igi->mc_wq, &iw->work);
		}
	} while (0);

	nc_id_put(group_nameid);
	nc_id_put(peer_nameid);

	return ret;
}

static int ipcon_peer_reg(struct sk_buff *skb, struct ipcon_peer_node *self)
{
	int ret = 0;
	struct ipcon_kevent *ik;
	struct ipcon_work *iw = NULL;
	enum peer_type peer_type = PEER_TYPE_NORMAL;
	int nameid = 0;
	struct nlattr *tb[NUM_IPCON_ATTR];
	char name[IPCON_MAX_NAME_LEN];
	__u32 snd_port;
	__u32 rcv_port;
	__u32 peer_flag;
	unsigned long ipn_flag = 0;

	ipcon_dbg("enter.\n");

	ret = ipconmsg_parse(skb, tb, IPCON_ATTR_MAX, ipcon_policy, NULL);
	if (ret < 0)
		return ret;

	if (!tb[IPCON_ATTR_PEER_NAME] ||
		!tb[IPCON_ATTR_SPORT] ||
		!tb[IPCON_ATTR_RPORT])
		return -EINVAL;

	nla_strlcpy(name, tb[IPCON_ATTR_PEER_NAME], IPCON_MAX_NAME_LEN);
	snd_port = nla_get_u32(tb[IPCON_ATTR_SPORT]);
	rcv_port = nla_get_u32(tb[IPCON_ATTR_RPORT]);

	if (tb[IPCON_ATTR_FLAG]) {
		peer_flag = nla_get_u32(tb[IPCON_ATTR_FLAG]);
		if (peer_flag & IPCON_FLG_ANON_PEER)
			peer_type = PEER_TYPE_ANON;

		if (peer_flag & IPCON_FLG_DISABL_KEVENT_FILTER)
			ipn_flag |= IPN_FLG_DISABLE_KEVENT_FILTER;
	}

	nameid = nc_add(name, GFP_KERNEL);
	if (nameid < 0)
		return nameid;

	do {
		BUG_ON(self);

		self = ipn_alloc(ipconmsg_srcport(skb),
				snd_port,
				rcv_port,
				nameid,
				peer_type,
				ipn_flag,
				GFP_KERNEL);

		if (!self) {
			nc_id_put(nameid);
			ret = -ENOMEM;
			break;
		}

		ret = ipd_insert(ipcon_db, self);
		if (ret < 0)
			break;

		if (!try_module_get(THIS_MODULE)) {
			ret = -ENOMEM;
			break;
		}

	} while (0);

	if (!ret) {
		iw = iw_alloc(ipcon_kevent_worker,
				sizeof(*ik), GFP_ATOMIC);
		if (iw) {

			ik = iw->data;
			ik->type = IPCON_EVENT_PEER_ADD;
			nc_getname(self->nameid, ik->peer.name);
			queue_work(igi_kernel->mc_wq, &iw->work);
		}
	} else {
		ipn_free(self);
	}

	nc_id_put(nameid);

	ipcon_dbg("exit (%d).\n", ret);
	return ret;
}

static struct notifier_block ipcon_netlink_notifier = {
	.notifier_call = ipcon_netlink_notify,
};

static int ipcon_kernel_init(void)
{
	int ret = 0;
	int kpeer_nameid = 0;
	int kgroup_nameid = 0;

	do {
		ret = nc_init();
		if (ret < 0)
			break;

		kpeer_nameid = nc_add(IPCON_NAME, GFP_KERNEL);
		if (kpeer_nameid < 0) {
			ret = kpeer_nameid;
			break;
		}

		kgroup_nameid = nc_add(IPCON_KERNEL_GROUP_NAME,
				GFP_KERNEL);
		if (kgroup_nameid < 0) {
			ret = kgroup_nameid;
			break;
		}


		igi_kernel = igi_alloc(kgroup_nameid, IPCON_KERNEL_GROUP,
				GFP_KERNEL);
		if (!igi_kernel) {
			ret = -ENOMEM;
			break;
		}

		ipn_kernel = ipn_alloc(0, 0, 0, kpeer_nameid,
				PEER_TYPE_NORMAL,
				0,
				GFP_KERNEL);
		if (!ipn_kernel) {
			ret = -ENOMEM;
			break;
		}

		ret = ipn_insert(ipn_kernel, igi_kernel);
		if (ret < 0)
			break;

		ipcon_db = ipd_alloc(GFP_KERNEL);
		if (!ipcon_db) {
			ret = -ENOMEM;
			break;
		}

		ret = ipd_insert(ipcon_db, ipn_kernel);
		if (ret < 0)
			break;

		reg_group(ipcon_db, IPCON_KERNEL_GROUP);

	} while (0);

	if (ret < 0) {
		nc_exit();
		ipd_free(ipcon_db);
	}

	if (kgroup_nameid > 0)
		nc_id_put(kgroup_nameid);

	if (kpeer_nameid > 0)
		nc_id_put(kpeer_nameid);

	return ret;
}

static void ipcon_kernel_destroy(void)
{
	nc_exit();
	ipd_free(ipcon_db);
}

static int ipcon_rcv(struct sk_buff *skb, struct nlmsghdr *nlh,
		struct netlink_ext_ack *ack)
{
	int ret = 0;
	int type = nlh->nlmsg_type;
	struct ipcon_peer_node *self = NULL;

	ipcon_dbg("enter\n");

	switch (type) {
	case IPCON_PEER_REG:
		self = ipd_lookup_bycport(ipcon_db, ipconmsg_srcport(skb));
		ret = ipcon_peer_reg(skb, self);
		break;

	case IPCON_PEER_RESLOVE:
		self = ipd_lookup_bycport(ipcon_db, ipconmsg_srcport(skb));
		if (!self) {
			ret = -ENXIO;
			break;
		}

		ret = ipcon_peer_reslove(skb, self);
		break;

	case IPCON_GRP_REG:
		self = ipd_lookup_bycport(ipcon_db, ipconmsg_srcport(skb));
		if (!self) {
			ret = -ENXIO;
			break;
		}

		ret = ipcon_grp_reg(skb, self);
		break;

	case IPCON_GRP_UNREG:
		self = ipd_lookup_bycport(ipcon_db, ipconmsg_srcport(skb));
		if (!self) {
			ret = -ENXIO;
			break;
		}

		ret = ipcon_grp_unreg(skb, self);
		break;

	case IPCON_GRP_RESLOVE:
		self = ipd_lookup_bycport(ipcon_db, ipconmsg_srcport(skb));
		if (!self) {
			ret = -ENXIO;
			break;
		}

		ret = ipcon_grp_reslove(skb, self);
		break;

	case IPCON_USR_MSG:
		self = ipd_lookup_bysport(ipcon_db, ipconmsg_srcport(skb));
		if (!self) {
			ret = -ENXIO;
			break;
		}

		ret = ipcon_unicast_msg(skb, self);
		break;

	case IPCON_MULTICAST_MSG:
		self = ipd_lookup_bysport(ipcon_db, ipconmsg_srcport(skb));
		if (!self) {
			ret = -ENXIO;
			break;
		}

		ret = ipcon_multicast_msg(skb, self);
		break;

	default:
		ipcon_err("Unknow msg type: %x\n", type);
		ret = -EINVAL;

	};

	ipcon_dbg("ret = %d\n", ret);
	return ret;
}

void ipcon_nl_rcv_msg(struct sk_buff *skb)
{
	/*
	 * Sequentialize the message receiving from user application.
	 * this protects internal structures so that no
	 * seperated protetion needed.
	 *
	 * The possible potential confilc processing is
	 * - Other user process's asychronizing call.
	 * - netlink notifier.
	 *   see ipcon_netlink_notifier().
	 */
	mutex_lock(&ipcon_mutex);
	netlink_rcv_skb(skb, &ipcon_rcv);
	mutex_unlock(&ipcon_mutex);
}


int ipcon_nl_init(void)
{
	int ret = 0;

	struct netlink_kernel_cfg cfg = {
		.input  = ipcon_nl_rcv_msg,
		.groups	= IPCON_MAX_GROUP,
		.flags	= NL_CFG_F_NONROOT_RECV,
	};

	ipcon_nl_sock = netlink_kernel_create(&init_net, NETLINK_IPCON, &cfg);
	if (!ipcon_nl_sock) {
		ipcon_err("Failed to create netlink socket.\n");
		ret = -ENOMEM;
	}

	ret = ipcon_kernel_init();
	if (ret < 0)
		return ret;

	ret = netlink_register_notifier(&ipcon_netlink_notifier);
	if (ret)
		ipcon_kernel_destroy();

	return ret;
}

void ipcon_nl_exit(void)
{
	netlink_unregister_notifier(&ipcon_netlink_notifier);
	ipcon_kernel_destroy();
}
