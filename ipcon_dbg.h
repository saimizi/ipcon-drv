/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_DBG_H__
#define __IPCON_DBG_H__

#define ipcon_err(fmt, ...) \
	pr_err("[ipcon] " fmt, ##__VA_ARGS__)

#define ipcon_warn(fmt, ...) \
	pr_warn("[ipcon] " fmt, ##__VA_ARGS__)

#define ipcon_info(fmt, ...) \
	pr_info("[ipcon] " fmt, ##__VA_ARGS__)

#define ipcon_dbg(fmt, ...) \
	pr_debug("[ipcon] %s-%d " fmt, __func__, __LINE__, ##__VA_ARGS__)


#endif
