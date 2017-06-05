/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#include <linux/genetlink.h>

#define IPCON_NAME		"ipcon"
#define IPCON_KERNEL_GROUP	"ipcon_kevent"
#define IPCON_MAX_NAME_LEN	64
#define IPCON_MAX_GROUP		48


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
#define IPCON_KERNEL_GROUP_PORT	0

enum {
	IPCON_ATTR_UNSPEC,
	IPCON_ATTR_MSG_TYPE,
	IPCON_ATTR_PORT,
	IPCON_ATTR_SRV_NAME,
	IPCON_ATTR_GROUP,
	IPCON_ATTR_GRP_NAME,
	IPCON_ATTR_DATA,
	IPCON_ATTR_FLAG,
	IPCON_ATTR_PEER_NAME,
	IPCON_ATTR_SRC_PEER,
	IPCON_ATTR_PEER_TYPE,
	/* Add attr here */

	IPCON_ATTR_AFTER_LAST,
	NUM_IPCON_ATTR = IPCON_ATTR_AFTER_LAST,
	IPCON_ATTR_MAX = IPCON_ATTR_AFTER_LAST - 1
};

/* IPCON commands */
enum {
	IPCON_PEER_REG,
	IPCON_PEER_RESLOVE,
	IPCON_GRP_REG,
	IPCON_GRP_UNREG,
	IPCON_GRP_RESLOVE,
	IPCON_MULTICAST_MSG,
	IPCON_USR_MSG,
	IPCON_CMD_MAX,
};

enum peer_type {
	ANON,
	PUBLISHER,
	SERVICE,
	SERVICE_PUBLISHER,
	MAX_PEER_TYPE
};

static inline int valid_ipcon_group(__u32 group)
{
	return (group < IPCON_MAX_GROUP - 1);
}

static inline int valid_user_ipcon_group(__u32 group)
{
	return (group && valid_ipcon_group(group));
}

enum ipcon_kevent_type {
	IPCON_EVENT_PEER_ADD,
	IPCON_EVENT_PEER_REMOVE,
	IPCON_EVENT_GRP_ADD,
	IPCON_EVENT_GRP_REMOVE,
};

struct ipcon_kevent {
	enum ipcon_kevent_type type;
	union {
		struct {
			char name[IPCON_MAX_NAME_LEN];
			char peer_name[IPCON_MAX_NAME_LEN];
		} group;
		struct {
			char name[IPCON_MAX_NAME_LEN];
		} peer;
	};
};

#endif
