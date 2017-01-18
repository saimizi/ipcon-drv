/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <asm/bitops.h>

#include "ipcon.h"
#include "ipcon_genl.h"
#include "ipcon_dbg.h"

/* Reference
 * - inclue/net/netlink.h
 */

static struct genl_family ipcon_fam = {
	.id = GENL_ID_GENERATE,
	.name = IPCON_GENL_NAME,
	.hdrsize = IPCON_HDR_SIZE,
	.version = 1,
	.maxattr = IPCON_ATTR_MAX,
};

enum ipcon_multicast_groups {
	IPCON_MCGRP0,
	IPCON_MCGRP1,
};

static const struct genl_multicast_group ipcon_mcgroups[] = {
	[IPCON_MCGRP0] = {.name = "ipcon_kernel",},
	[IPCON_MCGRP1] = {.name = "ipcon_user",},
};

static const struct nla_policy ipcon_policy[NUM_IPCON_ATTR] = {
	[IPCON_ATTR_MSG_TYPE] = {.type = NLA_U32},
	[IPCON_ATTR_SRV_PORT] = {.type = NLA_U32},
	[IPCON_ATTR_SRV_NAME] = {.type = NLA_NUL_STRING,
				.len = IPCON_MAX_SRV_NAME_LEN - 1 },
	[IPCON_ATTR_SRV_GROUP] = {.type = NLA_U32},
	[IPCON_ATTR_DATA] = {.type = NLA_BINARY, .len = IPCON_MAX_MSG_LEN},
};

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

	ipcon_info("ipcon_srv_reg() enter.\n");

	if (!info || !info->attrs[IPCON_ATTR_MSG_TYPE] ||
		!info->attrs[IPCON_ATTR_SRV_PORT] ||
		!info->attrs[IPCON_ATTR_SRV_NAME] ||
		!info->attrs[IPCON_ATTR_SRV_GROUP])
		return -EINVAL;

	ret = nlmsg_validate(info->nlhdr,
			IPCON_HDR_SIZE,
			IPCON_ATTR_MAX,
			ipcon_policy);
	if (ret < 0) {
		ipcon_err("%s : wrong message.\n", __func__);
		return ret;
	}

	if (info->attrs[IPCON_ATTR_MSG_TYPE])
		ipcon_info("Msg type: %lu\n", (unsigned long)
			nla_get_u32(info->attrs[IPCON_ATTR_MSG_TYPE]));
	ipcon_info("Srv port: %lu\n", (unsigned long)
			nla_get_u32(info->attrs[IPCON_ATTR_SRV_PORT]));
	nla_strlcpy(name, info->attrs[IPCON_ATTR_SRV_NAME],
			IPCON_MAX_SRV_NAME_LEN);
	ipcon_info("Srv name: %s\n", name);
	ipcon_info("Srv group: %lu\n", (unsigned long)
			nla_get_u32(info->attrs[IPCON_ATTR_SRV_GROUP]));


	return ret;
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

