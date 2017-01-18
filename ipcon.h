/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#define IPCON_GENL_NAME		"ipcon"
#define IPCON_MAX_SRV_NAME_LEN	32

/*
 * This is the maximum length of user message
 * that ipcon supposed to carry.
 */
#define IPCON_MAX_MSG_LEN	512

#define IPCON_HDR_SIZE	0

/* IPCON_ATTR_MSG_TYPE */
#define IPCON_MSG_UNICAST	1
#define IPCON_MSG_MULTICAST	2

/* IPCON_ATTR_SRV_GROUP */
#define IPCON_AUTO_GROUP	0
#define IPCON_MAX_GROUP		2

enum {
	IPCON_ATTR_UNSPEC,
	IPCON_ATTR_MSG_TYPE,
	IPCON_ATTR_SRV_PORT,
	IPCON_ATTR_SRV_NAME,
	IPCON_ATTR_SRV_GROUP,
	IPCON_ATTR_DATA,

	/* Add attr here */

	IPCON_ATTR_AFTER_LAST,
	NUM_IPCON_ATTR = IPCON_ATTR_AFTER_LAST,
	IPCON_ATTR_MAX = IPCON_ATTR_AFTER_LAST - 1
};

/* IPCON commands */
enum {
	IPCON_SRV_REG,
	IPCON_SRV_UNREG,
	IPCON_SRV_RESLOVE,
	IPCON_GROUP_RESLOVE,
	IPCON_MULICAST_MSG,
	MSG_MAX,
};

#endif
