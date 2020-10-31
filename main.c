/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include <net/sock.h>
#include <net/netlink.h>
#include "ipcon.h"
#include "ipcon_nl.h"
#include "ipcon_dbg.h"

#ifdef CONFIG_DEBUG_FS
#include "ipcon_debugfs.h"
#endif

static int ipcon_init(void)
{
	int ret = 0;

#ifdef CONFIG_DEBUG_FS
	ipcon_debugfs_init();
#endif
	ret = ipcon_nl_init();

	if (ret == 0) {
		ipcon_err("init successfully.\n");

	} else {
		ipcon_err("init failed (%d).\n", ret);
#ifdef CONFIG_DEBUG_FS
		ipcon_debugfs_exit();
#endif
	}

	return ret;
}

static void ipcon_exit(void)
{
#ifdef CONFIG_DEBUG_FS
	ipcon_debugfs_exit();
#endif
	ipcon_nl_exit();
	ipcon_info("exit.\n");
}

module_init(ipcon_init);
module_exit(ipcon_exit);

MODULE_DESCRIPTION("IPC Over Netlink(IPCON) Driver");
MODULE_LICENSE("GPL");
