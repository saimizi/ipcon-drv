/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_DBG_H__
#define __IPCON_DBG_H__

#define ipcon_err(fmt, ...) \
	printk(KERN_ERR "[ipcon] %s-%d " fmt,__func__, __LINE__, ##__VA_ARGS__)

#define ipcon_info(fmt, ...) \
	printk(KERN_INFO "[ipcon] %s-%d " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define ipcon_dbg(fmt, ...) \
	printk(KERN_DEBUG "[ipcon] %s-%d " fmt, __func__, __LINE__, ##__VA_ARGS__)

#endif
