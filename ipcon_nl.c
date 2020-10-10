/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <asm/bitops.h>

#include "af_netlink.h"

#include "ipcon.h"
#include "ipcon_nl.h"
#include "ipcon_db.h"
#include "name_cache.h"
#include "ipcon_dbg.h"
#ifdef CONFIG_DEBUG_FS
#include "ipcon_debugfs.h"
#endif

/* Reference
 * - inclue/net/netlink.h
 */

#define UNUSED_GROUP_NAME	"ipconG"
static struct sock *ipcon_nl_sock;
static struct ipcon_peer_db *ipcon_db;
DEFINE_MUTEX(ipcon_mutex);


struct ipcon_msghdr *ipcon_msghdr_clone(struct ipcon_msghdr *imh,
		gfp_t flags)
{
	struct ipcon_msghdr *result = NULL;

	if (!imh)
		return NULL;

	result = kmalloc(ipconmsg_size(imh), flags);
	if (!result)
		return NULL;

	memcpy(result, imh, ipconmsg_size(imh));

	return result;
}


static inline int is_anon(struct ipcon_peer_node *ipn)
{
	return (ipn->type == PEER_TYPE_ANON);
}


void ipcon_clear_multicast_user(struct genl_family *family, unsigned int group)
{
	struct net *net;

	netlink_table_grab();
	rcu_read_lock();
	for_each_net_rcu(net) {
		__netlink_clear_multicast_users(net->genl_sock,
						family->mcgrp_offset + group);
	}
	rcu_read_unlock();
	netlink_table_ungrab();
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

	/* data is only present for ipcon_kevent when sending ipcon kevent */
	if (data) {
		int skip = 0;

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

			ipcon_dbg("Drop notify to %s : %s %s %s\n",
				nc_refname(ipn->nameid),
				event,
				peer_name,
				group_name);
		}
		return skip;
	}

	ipcon_dbg("Multicast to %s@%lu.\n",
			nc_refname(ipn->nameid),
			(unsigned long)ipn->port);

	return 0;
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


	ipcon_multicast(0, IPCON_TYPE_MSG, IPCON_KERNEL_GROUP_PORT,
				ik, sizeof(*ik), GFP_KERNEL);

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
	struct hlist_node *tmp;

	if (!port)
		return;

	ipcon_dbg("enter port: %lu\n", (unsigned long)port);

	do {
		struct ipcon_work *iw_mc = NULL;
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
			hash_for_each_safe(ipn->ipn_group_ht, bkt, tmp,
					igi, igi_hgroup) {
				struct ipcon_work *iw_mc = NULL;
				DEFINE_WAIT(wait);

				igi_del(igi);

				/*
				 * wait all messages under delivering are
				 * processed
				 */
				add_wait_queue(&igi->wq, &wait);
				while (atomic_read(&igi->msg_sending_cnt)) {
					prepare_to_wait(&igi->wq,
						&wait, TASK_INTERRUPTIBLE);
					schedule();
				}
				finish_wait(&igi->wq, &wait);

				/* clear users */
				ipcon_clear_multicast_user(&ipcon_fam,
						igi->group);


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
					queue_work(ipcon_db->mc_wq,
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
			queue_work(ipcon_db->mc_wq, &iw_mc->work);
		}
	} while (0);

	ipn_free(ipn);
	iw_free(iw);
	ipcon_dbg("exit\n");
}

struct ipcon_multicast_worker_data {
	struct ipcon_group_info *igi;
	__u32	sender_port;
	void *msg;
};

static void ipcon_multicast_worker(struct work_struct *work)
{
	struct ipcon_work *iw = container_of(work, struct ipcon_work, work);
	struct ipcon_multicast_worker_data *imwd = iw->data;
	struct ipcon_group_info *igi = imwd->igi;

	ipcon_dbg("%s: group: %d\n", __func__, igi->group);

	if (igi->group == IPCON_KERNEL_GROUP_PORT)
		return;

	ipcon_multicast(imwd->sender_port,
			IPCON_TYPE_MSG,
			imwd->igi->group,
			imwd->msg,
			ipconmsg_size(imh),
			GFP_KERNEL);

	kfree(imwd->msg);

	/* if group is under un-registering, wake up the process...*/
	if (atomic_sub_and_test(1, &igi->msg_sending_cnt))
		wake_up(&igi->wq);

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

static int ipcon_peer_reslove(__u32 sender_port, struct ipcon_msghdr *imh,
		struct ipcon_msghdr **ack)
{
	int ret = -ENOENT;
	struct ipcon_peer_node *ipn = NULL;
	int nameid = 0;

	do {

		if (!valid_name(imh->peer_name)) {
			ret = -EINVAL;
			break;
		}

		nameid = nc_getid(imh->peer_name);
		if (nameid > 0) {
			ipd_rd_lock(ipcon_db);
			ipn = ipd_lookup_byname(ipcon_db, nameid);
			if (ipn)
				ret = 0;
			ipd_rd_unlock(ipcon_db);
		}
		nc_id_put(nameid);

	} while (0);

	return ret;
}

static int ipn_reg_group(struct ipcon_peer_node *ipn, int nameid,
		unsigned int group, struct ipcon_msghdr **ack)
{
	int ret = 0;
	struct ipcon_group_info *igi = NULL;
	struct ipcon_group_info *existed = NULL;
	struct ipcon_kevent *ik;
	struct ipcon_work *iw = NULL;

	do {
		igi = igi_alloc(nameid, (u32)group, GFP_ATOMIC);
		if (!igi) {
			ret = -ENOMEM;
			break;
		}

		ipn_wr_lock(ipn);
		existed = ipn_lookup_byname(ipn, nameid);
		if (!existed)
			ret = ipn_insert(ipn, igi);
		else
			ret = -EEXIST;
		ipn_wr_unlock(ipn);

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
			queue_work(ipcon_db->mc_wq, &iw->work);
		}
	} while (0);

	return ret;
}

static int ipcon_grp_reg(__u32 sender_port, struct ipcon_msghdr *imh,
		struct ipcon_msghdr **ack)
{
	int ret = 0;
	struct ipcon_peer_node *ipn = NULL;
	int id = 0;
	int nameid = 0;

	ipcon_dbg("enter.\n");

	nameid = nc_add(imh->group_name, GFP_KERNEL);
	if (nameid < 0)
		return nameid;

	id = reg_new_group(ipcon_db);
	if (id >= IPCON_MAX_GROUP)
		return -ENOBUFS;

	ipd_rd_lock(ipcon_db);
	do {
		ipn = ipd_lookup_bycport(ipcon_db, sender_port);
		if (!ipn) {
			ipcon_err("No port %lu found\n.",
					(unsigned long)info->snd_portid);
			ret = -ESRCH;
			break;
		}

		ret = ipn_reg_group(ipn, nameid, id);

	} while (0);
	ipd_rd_unlock(ipcon_db);

	if (ret < 0)
		unreg_group(ipcon_db, id);

	nc_id_put(nameid);

	ipcon_dbg("exit (%d).\n", ret);
	return ret;
}

static int ipcon_grp_unreg(__u32 sender_port, struct ipcon_msghdr *imh,
		struct ipcon_msghdr **ack)
{
	int ret = 0;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;
	int nameid = 0;

	if (!valid_name(imh->group_name))
		return -EINVAL;

	nameid = nc_getid(imh->group_name);
	if (nameid < 0)
		return nameid;

	ipd_rd_lock(ipcon_db);
	do {

		ipn = ipd_lookup_bycport(ipcon_db, sender_port);
		if (!ipn) {
			ret = -ESRCH;
			break;
		}

		ipn_wr_lock(ipn);
		igi = ipn_lookup_byname(ipn, nameid);
		/*
		 * Isolate this group from peer, so that no new group message
		 * accepted. igi_del() can deal with NULL.
		 */
		igi_del(igi);
		ipn_wr_unlock(ipn);

		if (!igi)
			ret = -ESRCH;

	} while (0);
	ipd_rd_unlock(ipcon_db);
	nc_id_put(nameid);

	if (!ret) {
		DEFINE_WAIT(wait);
		struct ipcon_work *iw = NULL;
		struct ipcon_kevent *ik;

		/* wait all messages under delivering are processed */
		add_wait_queue(&igi->wq, &wait);
		while (atomic_read(&igi->msg_sending_cnt)) {
			prepare_to_wait(&igi->wq, &wait, TASK_INTERRUPTIBLE);
			schedule();
		}
		finish_wait(&igi->wq, &wait);

		/* clear users */
		ipcon_clear_multicast_user(&ipcon_fam, igi->group);

		/* send group remove kevent */
		iw = iw_alloc(ipcon_kevent_worker, sizeof(*ik), GFP_KERNEL);
		if (iw) {
			ik = iw->data;

			ik->type = IPCON_EVENT_GRP_REMOVE;
			nc_getname(igi->nameid, ik->group.name);
			nc_getname(ipn->nameid, ik->group.peer_name);

			ipcon_dbg("Group %s.%s@%d removed.\n",
				ik->group.peer_name,
				ik->group.name,
				igi->group);

			queue_work(ipcon_db->mc_wq, &iw->work);
		}

		/* free igi */
		igi_free(igi);

		/* mark group id be reusable. */
		unreg_group(ipcon_db, igi->group);
	}

	return ret;
}

/*
 * FIXME:
 * Since we can not register group in ipcon driver at present, a race condition
 * between ADD_MEMBERSHIP in user land and ipcon_grp_unreg() may happen, which
 * can not be avoided. ipcon_grp_reslove should be replaced with something like
 * ipcon_join_grp()...
 */
static int ipcon_grp_reslove(__u32 sender_port, struct ipcon_msghdr *imh,
		struct ipcon_msghdr **ack)
{
	int ret = 0;
	___u32 msg_type;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_peer_node *self = NULL;
	struct ipcon_group_info *igi = NULL;
	unsigned int group = 0;
	int grp_nameid = 0;
	int srv_nameid = 0;

	ipcon_dbg("enter.\n");


	if (!valid_name(imh->group_name))
		return -EINVAL;

	grp_nameid = nc_getid(imh->group_name);
	if (grp_nameid < 0)
		return grp_nameid;

	if (!valid_name(imh->peer_name)) {
		nc_id_put(grp_nameid);
		return -EINVAL;
	}

	srv_nameid = nc_getid(imh->peer_name);
	if (srv_nameid < 0) {
		nc_id_put(grp_nameid);
		return srv_nameid;
	}

	ipd_rd_lock(ipcon_db);
	do {
		ipn = ipd_lookup_byname(ipcon_db, srv_nameid);
		if (!ipn) {
			ret = -ESRCH;
			break;
		}

		ipn_rd_lock(ipn);
		igi = ipn_lookup_byname(ipn, grp_nameid);
		if (igi)
			group = igi->group;
		else
			ret = -ESRCH;
		ipn_rd_unlock(ipn);

	} while (0);
	ipd_rd_unlock(ipcon_db);

	nc_id_put(srv_nameid);
	nc_id_put(grp_nameid);

	if (!ret) {
		struct ipcon_msghdr *imh = alloc_ipconmsg(0, GFP_KERNEL);

		imh->cmd = IPCON_GRP_RESLOVE;
		imh->group = group;

		*ack = imh;

	}

	ipcon_dbg("%s exit(%d).\n", __func__, ret);
	return ret;
}


int ipcon_unicast(u32 pid, int type, void *data, size_t size, gfp_t flags)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int ret = 0;

	do {
		if (!ipcon_nl_sock)
			break;

		skb = alloc_skb(NLMSG_SPACE(size), flags);
		if (!skb) {
			ret = -ENOMEM;
			break;
		}

		nlh = nlmsg_put(skb, 0, 0, type, size, 0);
		if (!nlh) {
			ret = -ENOMEM;
			kfree_skb(skb);
			break;
		}

		memcpy(nlmsg_data(nlh), data, size);

		/*
		 * netlink_unicast() called from nlmsg_unicast()
		 * takes ownership of the skb and frees it itself.
		 */
		ret = nlmsg_unicast(ipcon_nl_sock, skb, pid);

	} while (0);

	return ret >= 0 ? 0 : ret;
}

static int ipcon_multicast(u32 sender_port, int type, unsigned int group,
		void *data, size_t size, gfp_t flags)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int ret = 0;

	do {
		if (!ipcon_nl_sock || !group) {
			ret = -EINVAL;
			break;
		}

		skb = alloc_skb(NLMSG_SPACE(size), flags);
		if (!skb) {
			ret = -ENOMEM;
			break;
		}

		nlh = nlmsg_put(skb, sender_port, 0, type, size, 0);
		if (!nlh) {
			ret = -ENOMEM;
			kfree_skb(skb);
			break;
		}

		memcpy(nlmsg_data(nlh), data, size);
		nlmsg_end(skb, nlh);

		/*
		 * netlink_broadcast_filtered() called from nlmsg_multicast
		 * takes ownership of the skb and frees it itself.
		 */
		ret = nlmsg_multicast(ipcon_nl_sock, skb,
				sender_port, group, flags);

		/*
		 * If no process suscribes the group,
		 * just return as success.
		 */
		if ((ret > 0) || (ret == -ESRCH))
			ret = 0;

	} while (0);

	return ret;
}


static int ipcon_unicast_msg(__u32 sender_port, struct ipcon_msghdr *imh)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	__u32 msg_type;
	struct ipcon_peer_node *self = NULL;
	struct ipcon_peer_node *ipn = NULL;
	u32 tport = 0;
	int nameid = 0;


	if (!strcmp(IPCON_NAME, imh->peer_name))
		return -EINVAL;

	if (!valid_name(imh->peer_name))
		return -EINVAL;

	nameid = nc_getid(imh->peer_name);
	if (nameid < 0)
		return nameid;

	ipd_rd_lock(ipcon_db);
	do {
		ipn = ipd_lookup_byname(ipcon_db, nameid);
		if (!ipn) {
			ipcon_err("%s: Peer %s not found.\n",
				__func__, name);

			ret = -ESRCH;
			break;
		}

		tport = ipn->port;

		/* replace pear_name with the sender name */
		strcpy(imh->peer_name, nc_refname(nameid));
	} while (0);
	ipd_rd_unlock(ipcon_db);
	nc_id_put(nameid);

	if (!ret) {
		ret = ipcon_unicast(tport,
				IPCON_TYPE_MSG,
				imh,
				ipconmsg_size(imh));
	}

	return ret;
}

static int ipcon_multicast_msg(__u32 sender_port, struct ipcon_msghdr *imh)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_group_info *igi = NULL;
	struct sk_buff *msg = skb_clone(skb, GFP_KERNEL);
	struct ipcon_work *iw = NULL;
	int nameid = 0;


	if (!valid_name(imh->group_name))
		return -EINVAL;

	nameid = nc_getid(imh->group_name);
	if (nameid < 0)
		return nameid;

	ipd_rd_lock(ipcon_db);
	do {
		ipn = ipd_lookup_bycport(ipcon_db, sender_port);
		if (!ipn) {
			ret = -ESRCH;
			break;
		}

		/* Set up peer name of the group owner */
		strcpy(imh->peer_name, nc_refname(ipn->nameid));

		ipn_rd_lock(ipn);
		igi = ipn_lookup_byname(ipn, nameid);
		if (igi)
			atomic_inc(&igi->msg_sending_cnt);
		else
			ret = -ESRCH;
		ipn_rd_unlock(ipn);
	} while (0);
	ipd_rd_unlock(ipcon_db);
	nc_id_put(nameid);

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

		if (imh->flags & IPCON_FLG_MULTICAST_SYNC) {
			ret = ipcon_multicast(sender_port,
					IPCON_TYPE_MSG,
					igi->group,
					imh,
					ipconmsg_size(imh),
					GFP_KERNEL);

			/*
			 * if group is under un-registering, wake up the
			 * process...
			 */
			if (atomic_sub_and_test(1, &igi->msg_sending_cnt))
				wake_up(&igi->wq);
			break;
		}

		iw = iw_alloc(ipcon_multicast_worker,
				sizeof(*imwd), GFP_ATOMIC);

		if (!iw) {
			ret = -ENOMEM;
			break;
		}

		imwd = iw->data;
		imwd->igi = igi;
		imwd->sender_port = sender_port;
		imwd->msg = ipcon_msghdr_clone(imh, GFP_KERNEL);
		if (!imwd->msg) {
			ret = -ENOMEM;
			break;
		}

		queue_work(ipcon_db->mc_wq, &iw->work);

	} while (0);

	if (ret < 0)
		kfree_skb(msg);

	return ret;
}

static int ipcon_peer_reg(__u32 sender_port, struct ipcon_msghdr *imh,
		struct ipcon_msghdr **ack)
{
	int ret = 0;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_kevent *ik;
	struct ipcon_work *iw = NULL;
	enum peer_type peer_type = PEER_TYPE_NORMAL;
	int nameid = 0;

	ipcon_dbg("%s enter.\n", __func__);

	if (!valid_name(imh->peer_name))
		return -EINVAL;

	nameid = nc_add(imh->peer_name, GFP_ATOMIC);
	if (nameid < 0)
		return nameid;

	if (imh->flags & IPCON_FLG_ANON_PEER)
		peer_type = PEER_TYPE_ANON;

	ipd_wr_lock(ipcon_db);
	do {

		/* Only ctrl port registered, communication port is dummy */
		ipn = ipn_alloc(0, sender_port, nameid, peer_type, GFP_ATOMIC);
		if (!ipn) {
			nc_id_put(nameid);
			ret = -ENOMEM;
			break;
		}

		ret = ipd_insert(ipcon_db, ipn);
		if (ret < 0)
			break;

		if (!try_module_get(THIS_MODULE)) {
			ret = -ENOMEM;
			break;
		}

	} while (0);
	ipd_wr_unlock(ipcon_db);

	if (!ret) {
		iw = iw_alloc(ipcon_kevent_worker,
				sizeof(*ik), GFP_ATOMIC);
		if (iw) {
			ik = iw->data;
			ik->type = IPCON_EVENT_PEER_ADD;
			nc_getname(ipn->nameid, ik->peer.name);
			queue_work(ipcon_db->mc_wq, &iw->work);
		}
	} else {
		ipn_free(ipn);
	}

	nc_id_put(nameid);

	ipcon_dbg("%s exit(%d).\n", __func__, ret);
	return ret;
}

static int ipcon_peer_reg_comm(_u32 sender_port, struct ipcon_msghdr *imh)
{
	int ret = 0;
	struct ipcon_peer_node *ipn = NULL;
	struct ipcon_kevent *ik;
	struct ipcon_work *iw = NULL;
	int nameid = 0;

	ipcon_dbg("%s enter.\n", __func__);

	if (!valid_name(imh->peer_name))
		return -EINVAL;

	nameid = nc_getid(imh->peer_name);
	if (nameid < 0)
		return nameid;

	ipd_wr_lock(ipcon_db);
	do {

		/* Only ctrl port registered, communication port is dummy */
		ipn = ipd_lookup_byname(ipcon_db, nameid);
		if (!ipn) {
			ipcon_err("No ipn for %s found.", imh->peer_name);
			ret = -EINVAL;
			break;
		}

		ret = ipn_set_comm_port(sender_port);
		if (ret < 0)
			break;

	} while (0);
	ipd_wr_unlock(ipcon_db);

	nc_id_put(nameid);

	ipcon_dbg("%s exit(%d).\n", __func__, ret);
	return ret;
}

static struct notifier_block ipcon_netlink_notifier = {
	.notifier_call = ipcon_netlink_notify,
};

static int ipcon_kernel_init(void)
{
	struct ipcon_group_info *igi = NULL;
	struct ipcon_peer_node *ipn = NULL;
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

		kgroup_nameid = nc_add(IPCON_KERNEL_GROUP,
				GFP_KERNEL);
		if (kgroup_nameid < 0) {
			ret = kgroup_nameid;
			break;
		}


		igi = igi_alloc(kgroup_nameid, IPCON_KERNEL_GROUP_PORT,
				GFP_KERNEL);
		if (!igi) {
			ret = -ENOMEM;
			break;
		}

		ipn = ipn_alloc(0, 0, kpeer_nameid,
				SERVICE_PUBLISHER, GFP_KERNEL);
		if (!ipn) {
			ret = -ENOMEM;
			break;
		}

		ret = ipn_insert(ipn, igi);
		if (ret < 0)
			break;

		ipcon_db = ipd_alloc(GFP_KERNEL);
		if (!ipcon_db) {
			ret = -ENOMEM;
			break;
		}


		ret = ipd_insert(ipcon_db, ipn);
		if (ret < 0)
			break;

		reg_group(ipcon_db, IPCON_KERNEL_GROUP_PORT);

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

static int ipcon_kernel_destroy(void)
{
	nc_exit();
	ipd_free(ipcon_db);
}

static int ipcon_bind(struct net *net, int group)
{
	struct sock *sk = net->genl_sock;
	struct netlink_sock *nlk = nlk_sk(sk);
	struct ipcon_peer_node *ipn = NULL;
	int ret = 0;

	ipd_rd_lock(ipcon_db);
	ipn = ipd_lookup_byport(ipcon_db, nlk->portid);
	ipd_rd_unlock(ipcon_db);

	/*
	 * Only IPCON netlink soket is permmited to join the IPCON socket's mc
	 * group.
	 */
	if (!ipn) {
		ipcon_err("Netlink socket %lu is not a ipcon socket\n.",
				(unsigned long)nlk->portid);
		ret = -EPERM;
	}

	return ret;
}

static int ipcon_ubind(struct net *net, int group)
{
	return 0;
}

static int ipcon_ctl_handler(__u32 sender_port, struct ipcon_msghdr *imh)
{
	int ret = 0;
	struct ipcon_msghdr *ack = NULL;

	do {
		switch (imh->cmd) {
		case IPCON_PEER_REG:
			ret = ipcon_peer_reg(sender_port, imh, &ack);
			break;
		case IPCON_PEER_REG_COMM:
			ret = ipcon_peer_reg_comm(sender_port, imh, &ack);
			break;
		case IPCON_PEER_RESLOVE:
			ret = ipcon_peer_reslove(sender_port, imh, &ack);
			break;
		case IPCON_GRP_REG:
			ret = ipcon_grp_reg(sender_port, imh, &ack);
			break;
		case IPCON_GRP_UNREG:
			ret = ipcon_grp_unreg(sender_port, imh, &ack);
			break;
		case IPCON_GRP_RESLOVE:
			ret = ipcon_grp_reslove(sender_port, imh, &ack);
			break;
		default:
			ret = -EINVAL;
		};

		if (ret == 0) {
			if (ack) {
				ret = ipcon_unicast(sender_port,
						IPCON_TYPE_CTL,
						ack,
						ipconmsg_size(ack));

				kfree(ack);
				/*
				 * we want to ack by ourselves, return -EINTR
				 * will skip sending ACK in netlink_rcv_skb().
				 */
				if (ret == 0)
					ret = -EINTR;
			}
		}

	} while 0;

	return ret;
}

static int ipcon_msg_handler(__u32 sender_port, struct ipcon_msghdr *imh)
{
	int ret = 0;

	do {
		switch (imh->cmd) {
		case IPCON_USR_MSG:
			ret = ipcon_unicast_msg(sender_port, imh);
			break;
		case IPCON_MULTICAST_MSG:
			ret = ipcon_multicast_msg(sender_port, imh);
			break;
		default:
			ret = -EINVAL;
		};
	} while 0;

	return ret;
}

static int ipcon_rcv(struct sk_buff *skb, struct nlmsghdr *nlh,
		struct netlink_ext_ack *ack)
{
	int ret = 0;
	int type = nlh->nlmsg_type;
	struct ipcon_msghdr *imh = NLMSG_DATA(nlh);

	switch (type) {
	case IPCON_TYPE_CTL:
		ret = ipcon_ctl_handler(nlh->nlmsg_pid, im);
		break;
	case IPCON_TYPE_MSG:
		ret = ipcon_msg_handler(nlh->nlmsg_pid, im);
		break;
	default:
		ipcon_err("Unknow msg type: %x\n", type);
		ret = -EINVAL;

	};

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
	int i = 0;

	struct netlink_kernel_cfg cfg = {
		.input  = ipcon_nl_rcv_msg,
		.group	= IPCON_MAX_GROUP,
		.flags	= NL_CFG_F_NONROOT_RECV,
		.bind	= ipcon_bind,
		.unbind	= ipcon_unbind,
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

void ipcon_genl_exit(void)
{
	netlink_unregister_notifier(&ipcon_netlink_notifier);
	ipcon_kernel_destroy();
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
