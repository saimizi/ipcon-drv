/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_DBG_H__
#define __IPCON_DBG_H__

#define ipcon_err	pr_err
#define ipcon_warn	pr_warn
#define ipcon_info	pr_info
#define ipcon_dbg	pr_debug

#ifdef DEBUG_LOCK
#define ipcon_dbg_lock(fmt, ...) \
	pr_err("[ipcon] %s-%d " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define ipcon_dbg_lock(a)
#endif

#endif
