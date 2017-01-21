/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <asm/bitops.h>

#include "ipcon.h"
#include "ipcon_genl.h"
#include "ipcon_tree.h"
#include "ipcon_dbg.h"

/* Reference
 * - inclue/net/netlink.h
 */

#define UNUSED_GROUP_NAME	"unused"
static struct genl_multicast_group ipcon_mcgroups[IPCON_MAX_GROUP_NUM];
static struct ipcon_tree_node *cp_tree_root;

static struct genl_family ipcon_fam = {
	.id = GENL_ID_GENERATE,
	.name = IPCON_GENL_NAME,
	.hdrsize = IPCON_HDR_SIZE,
	.version = 1,
	.maxattr = IPCON_ATTR_MAX,
};

static const struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_MSG_TYPE] = {.type = NLA_U32},
	[IPCON_ATTR_PORT] = {.type = NLA_U32},
	[IPCON_ATTR_SRV_NAME] = {.type = NLA_NUL_STRING,
				.len = IPCON_MAX_SRV_NAME_LEN - 1 },
	[IPCON_ATTR_SRV_GROUP] = {.type = NLA_U32},
	[IPCON_ATTR_DATA] = {.type = NLA_BINARY, .len = IPCON_MAX_MSG_LEN},
};

/* Group 0 is reserved for ipcon kernel module */
static int ipcon_alloc_group(unsigned long group, char *name)
{

	if (!name)
		return -EINVAL;

	if (group == IPCON_NO_GROUP)
		return group;

	if (group == IPCON_AUTO_GROUP) {
		int i = 0;

		for (i = 1; i < IPCON_MAX_GROUP_NUM; i++) {
			if (!strcmp(ipcon_mcgroups[i].name,
				UNUSED_GROUP_NAME)) {
				strcpy(ipcon_mcgroups[i].name, name);
				return i;
			}
		}

		return  -ENOSPC;
	}

	if (!valid_user_ipcon_group(group))
		return -EINVAL;

	if (!strcmp(ipcon_mcgroups[group].name, UNUSED_GROUP_NAME)) {
		strcpy(ipcon_mcgroups[group].name, name);
		return group;
	}

	return -EEXIST;
}

static void ipcon_free_group(unsigned long group)
{
	if (!valid_user_ipcon_group(group))
		return;

	if (!strcmp(ipcon_mcgroups[group].name, UNUSED_GROUP_NAME))
		return;

	strcpy(ipcon_mcgroups[group].name, UNUSED_GROUP_NAME);
}

/*
 * This function is called from another context.
 */
static int ipcon_netlink_notify(struct notifier_block *nb,
				  unsigned long state,
				  void *_notify)
{
	return 0;
}

#if 0
static int ipcon_get_selfid(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			&ipcon_fam, 0, IPCON_GET_SELFID);

	if (!hdr)
		return -ENOBUFS;

	if (nla_put_u32(msg, IPCON_ATTR_PORT_ID, info->snd_portid))
		genlmsg_cancel(msg, hdr);
	else
		genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);
}
#endif

static int ipcon_srv_reg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_SRV_NAME_LEN];
	struct sk_buff *msg = NULL;
	void *hdr = NULL;
	__u32 port;
	__u32 msg_type;
	__u32 group = IPCON_NO_GROUP;
	struct ipcon_tree_node *nd = NULL;

	ipcon_info("ipcon_srv_reg() enter.\n");
	do {

		if (!info || !info->attrs[IPCON_ATTR_MSG_TYPE] ||
			!info->attrs[IPCON_ATTR_PORT] ||
			!info->attrs[IPCON_ATTR_SRV_NAME] ||
			!info->attrs[IPCON_ATTR_SRV_GROUP]) {
			ret = -EINVAL;
			break;
		}

		ret = nlmsg_validate(info->nlhdr,
				IPCON_HDR_SIZE,
				IPCON_ATTR_MAX,
				ipcon_policy);
		if (ret < 0) {
			ipcon_err("%s : wrong message.\n", __func__);
			break;
		}
		msg_type = nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]);
		port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
		nla_strlcpy(name, info->attrs[IPCON_ATTR_SRV_NAME],
			IPCON_MAX_SRV_NAME_LEN);
		group = nla_get_u32(info->attrs[IPCON_ATTR_SRV_GROUP]);

		ret = ipcon_alloc_group(group, name);
		if (ret < 0) {
			ipcon_err("failed to alloc group (%d).\n", ret);
			break;
		}
		group = (__u32)ret;


		nd = cp_alloc_node(port, name, group);
		if (!nd) {
			ret = -ENOMEM;
			break;
		}

		ret = cp_insert(&cp_tree_root, nd);
		if (ret < 0)
			break;

		ipcon_info("Msg type: %lu\n", (unsigned long) msg_type);
		ipcon_info("Srv port: %lu\n", (unsigned long) port);
		ipcon_info("Srv name: %s\n", name);
		ipcon_info("Srv group: %lu\n", (unsigned long) group);

		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
				&ipcon_fam, 0, IPCON_SRV_REG);
		if (!hdr) {
			ret = -ENOBUFS;
			break;
		}

		ret = nla_put_u32(msg, IPCON_ATTR_MSG_TYPE, IPCON_MSG_UNICAST);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			break;
		}

		ret = nla_put_u32(msg, IPCON_ATTR_PORT, port);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			break;
		}

		ret = nla_put_string(msg, IPCON_ATTR_SRV_NAME, name);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			break;
		}

		ret = nla_put_u32(msg, IPCON_ATTR_SRV_GROUP, group);
		if (ret < 0) {
			genlmsg_cancel(msg, hdr);
			break;
		}

		genlmsg_end(msg, hdr);

	} while (0);

	if (ret < 0) {
		kfree_skb(msg);
		ipcon_free_group(group);
		cp_free_node(nd);
		return ret;
	}


	return genlmsg_reply(msg, info);
}

static const struct genl_ops ipcon_ops[] = {
	{
		.cmd = IPCON_SRV_REG,
		.doit = ipcon_srv_reg,
		.policy = ipcon_policy,
		/*.flags = GENL_ADMIN_PERM,*/
	},
};


static struct notifier_block ipcon_netlink_notifier = {
	.notifier_call = ipcon_netlink_notify,
};

int ipcon_genl_init(void)
{
	int ret = 0;
	int i = 0;

	for (i = 0; i < IPCON_MAX_GROUP_NUM; i++) {
		if (i)
			strcpy(ipcon_mcgroups[i].name, UNUSED_GROUP_NAME);
		else
			strcpy(ipcon_mcgroups[i].name, IPCON_KERNEL_GROUP_NAME);
	}

	ret = genl_register_family_with_ops_groups(&ipcon_fam, ipcon_ops,
						ipcon_mcgroups);

	if (ret)
		return ret;

	ret = netlink_register_notifier(&ipcon_netlink_notifier);
	if (ret)
		genl_unregister_family(&ipcon_fam);

	return ret;
}

void ipcon_genl_exit(void)
{

	netlink_unregister_notifier(&ipcon_netlink_notifier);
	genl_unregister_family(&ipcon_fam);
}

