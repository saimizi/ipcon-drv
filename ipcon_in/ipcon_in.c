#include <net/genetlink.h>
#include "af_netlink.h"

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
EXPORT_SYMBOL(ipcon_clear_multicast_user);
