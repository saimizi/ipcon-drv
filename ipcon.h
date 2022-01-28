/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

/* Netlink protocol id for ipcon */
#define NETLINK_IPCON		29

#define IPCON_NAME		"ipcon"
#define IPCON_KERNEL_GROUP_NAME	"ipcon_kevent"
#define IPCON_MAX_NAME_LEN	32
#define IPCON_MAX_GROUP		128

enum peer_type {
	PEER_TYPE_ANON,
	PEER_TYPE_NORMAL,
	PEER_TYPE_KERNEL,
	PEER_TYPE_MAX,
};

/* IPCON Message types*/
enum ipcon_msg_type {
	IPCON_PEER_REG = 100,
	IPCON_PEER_RESLOVE,
	IPCON_GRP_REG,
	IPCON_GRP_UNREG,
	IPCON_GRP_RESLOVE,
	IPCON_CTL_CMD_MAX,

	IPCON_USR_MSG,
	IPCON_MULTICAST_MSG,
	IPCON_TYPE_MAX,
};

#define IPCON_FLG_ANON_PEER		(1 << 0)
#define IPCON_FLG_MULTICAST_SYNC	(1 << 1)
#define IPCON_FLG_DISABL_KEVENT_FILTER	(1 << 2)
#define IPCON_FLG_RCV_IF		(1 << 3)
#define IPCON_FLG_SND_IF		(1 << 4)

enum {
	IPCON_ATTR_UNSPEC,
	IPCON_ATTR_CPORT,	/* ctrl port */
	IPCON_ATTR_SPORT,	/* sending port */
	IPCON_ATTR_RPORT,	/* receiving port */
	IPCON_ATTR_GROUP,
	IPCON_ATTR_PEER_NAME,
	IPCON_ATTR_GROUP_NAME,
	IPCON_ATTR_DATA,
	IPCON_ATTR_FLAG,
	/* Add attr here */

	IPCON_ATTR_AFTER_LAST,
	NUM_IPCON_ATTR = IPCON_ATTR_AFTER_LAST,
	IPCON_ATTR_MAX = IPCON_ATTR_AFTER_LAST - 1
};

struct ipconmsghdr {
	__u32	reserved;
};

#define MAX_IPCONMSG_DATA_SIZE	2048
#define IPCONMSG_HDRLEN	NLMSG_ALIGN(sizeof(struct ipconmsghdr*))


static inline int valid_ipcon_group(__u32 group)
{
	return (group < IPCON_MAX_GROUP - 1);
}

static inline int valid_user_ipcon_group(__u32 group)
{
	return (group && valid_ipcon_group(group));
}

static inline int valid_name(char *name)
{
	int len = 0;

	if (!name)
		return 0;

	len = (int)strlen(name);

	if (!len || len > IPCON_MAX_NAME_LEN)
		return 0;

	return 1;
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
