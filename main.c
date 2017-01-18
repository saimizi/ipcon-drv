/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include <net/sock.h>
#include <net/netlink.h>
#include "ipcon.h"
#include "ipcon_genl.h"
#include "ipcon_dbg.h"

static int ipcon_init(void)
{
	int ret = 0;

	ret = ipcon_genl_init();
	if (ret)
		ipcon_err("init failed (%d).\n", ret);
	else
		ipcon_err("init successfully.\n");

	return ret;
}

static void ipcon_exit(void)
{
	ipcon_info("exit.\n");
	ipcon_genl_exit();
}

module_init(ipcon_init);
module_exit(ipcon_exit);

MODULE_DESCRIPTION("IPC Over Netlink(IPCON) Driver");
MODULE_LICENSE("GPL");
