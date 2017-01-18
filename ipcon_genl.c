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

static struct genl_family ipcon_fam = {
	.id = GENL_ID_GENERATE,
	.name = IPCON_GENL_NAME,
	.hdrsize = 0,
	.version = 1,
	.maxattr = IPCON_ATTR_LAST,
};

enum ipcon_multicast_groups {
	IPCON_MCGRP0,
	IPCON_MCGRP1,
};

static const struct genl_multicast_group ipcon_mcgroups[] = {
	[IPCON_MCGRP0] = {.name = "ipcon_kernel",},
	[IPCON_MCGRP1] = {.name = "ipcon_user",},
};

static const struct nla_policy ipcon_policy[IPCON_ATTR_LAST] = {
	[IPCON_ATTR_REAL_SIZE] = {.type = NLA_U32},
	[IPCON_ATTR_PORT_ID] = {.type = NLA_U32},
	[IPCON_ATTR_SRV_NAME] = {.type = NLA_NUL_STRING,
				.len = IPCON_MAX_SRV_NAME_LEN - 1 },
	[IPCON_ATTR_SRV_GROUP] = {.type = NLA_U32},
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

static int ipcon_srv_reg(struct sk_buff *skb, struct genl_info *info)
{
	return 0;
}

static const struct genl_ops ipcon_ops[] = {
	{
		.cmd = IPCON_GET_SELFID,
		.doit = ipcon_get_selfid,
		.policy = ipcon_policy,
	},
	{
		.cmd = IPCON_SRV_REG,
		.doit = ipcon_srv_reg,
		.policy = ipcon_policy,
		.flags = GENL_ADMIN_PERM,
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

