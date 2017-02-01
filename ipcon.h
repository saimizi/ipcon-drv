/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#include <linux/genetlink.h>

#define IPCON_GENL_NAME		"ipcon"
#define IPCON_KERNEL_GROUP_NAME	"ipcon_kevent"
#define IPCON_MAX_SRV_NAME_LEN	32
#define IPCON_MAX_GRP_NAME_LEN	GENL_NAMSIZ
#define IPCON_MAX_GROUP_NUM	48


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
#define IPCON_KERNEL_GROUP	0
#define IPCON_AUTO_GROUP	(IPCON_MAX_GROUP_NUM + 1)
#define IPCON_NO_GROUP		(IPCON_MAX_GROUP_NUM + 2)

enum {
	IPCON_ATTR_UNSPEC,
	IPCON_ATTR_MSG_TYPE,
	IPCON_ATTR_PORT,
	IPCON_ATTR_SRV_NAME,
	IPCON_ATTR_GROUP,
	IPCON_ATTR_GRP_NAME,
	IPCON_ATTR_DATA,
	IPCON_ATTR_FLAG,

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
	IPCON_GRP_REG,
	IPCON_GRP_UNREG,
	IPCON_GRP_RESLOVE,
	IPCON_MULTICAST_MSG,
	IPCON_USR_MSG,
	IPCON_CMD_MAX,
};

static inline int valid_ipcon_group(__u32 group)
{
	return (group < IPCON_MAX_GROUP_NUM - 1);
}

static inline int valid_user_ipcon_group(__u32 group)
{
	return (group && valid_ipcon_group(group));
}

enum ipcon_kevent_type {
	IPCON_EVENT_SRV_ADD,
	IPCON_EVENT_SRV_REMOVE,
	IPCON_EVENT_GRP_ADD,
	IPCON_EVENT_GRP_REMOVE,
	IPCON_EVENT_PEER_REMOVE,
};

struct ipcon_kevent {
	enum ipcon_kevent_type type;
	union {
		struct {
			char name[IPCON_MAX_SRV_NAME_LEN];
			__u32 portid;
		} srv;
		struct {
			char name[IPCON_MAX_GRP_NAME_LEN];
			__u32 groupid;
		} grp;
		struct {
			__u32 portid;
		} peer;
	};
};

#endif
