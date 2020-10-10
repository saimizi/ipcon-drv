/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

/* Netlink protocol id for ipcon */
#define NETLINK_IPCON		29

#define IPCON_NAME		"ipcon"
#define IPCON_KERNEL_GROUP	"ipcon_kevent"
#define IPCON_MAX_NAME_LEN	32
#define IPCON_MAX_GROUP		128

enum peer_type {
	PEER_TYPE_ANON,
	PEER_TYPE_NORMAL,
	PEER_TYPE_MAX,
};

enum ipcon_msg_type {
	IPCON_TYPE_CTL = 0,
	IPCON_TYPE_MSG,
	IPCON_TYPE_MAX,
};

/* IPCON commands */
enum {
	IPCON_PEER_REG,
	IPCON_PEER_REG_COMM,
	IPCON_PEER_RESLOVE,
	IPCON_GRP_REG,
	IPCON_GRP_UNREG,
	IPCON_GRP_RESLOVE,
	IPCON_CTL_CMD_MAX,

	IPCON_USR_MSG,
	IPCON_MULTICAST_MSG,
	IPCON_CMD_MAX,
};

#define IPCON_FLG_ANON_PEER		(1 << 0)
#define IPCON_FLG_MULTICAST_SYNC	(1 << 1)

/* IPCON message format */
struct ipcon_msghdr {
	__u32 size;	/* User data real size */
	__u32 refcnt;	/* Reference counter */
	__u32 cmd;	/* ipcon command */
	__u32 flags;	/* Flag used by command */
	__u32 group;
	char group_name[IPCON_MAX_SRV_NAME_LEN];
	char peer_name[IPCON_MAX_SRV_NAME_LEN];
};


#define MAX_IPCON_MSG_PAYLOAD_SIZE	512
#define MAX_IPCON_MSG_LEN \
	(sizeof(struct ipcon_msghdr) + MAX_IPCON_MSG_PAYLOAD_SIZE)

#define IPCONMSG_ALIGNTO		4U
#define IPCONMSG_ALIGN(len) \
	(((len)+IPCONMSG_ALIGNTO-1) & ~(IPCONMSG_ALIGNTO-1))
#define IPCONMSG_HDRLEN \
	((int) IPCONMSG_ALIGN(sizeof(struct ipcon_msghdr)))

#define IPCONMSG_LENGTH(len) ((len) + IPCONMSG_HDRLEN)
#define IPCONMSG_SPACE(len) IPCONMSG_ALIGN(IPCONMSG_LENGTH(len))
#define IPCONMSG_DATA(ipconh) \
		((void *)(((char *)ipconh) + IPCONMSG_LENGTH(0)))


static inline size_t ipconmsg_size(struct ipcon_msghdr *imh)
{
	return IPCONMSG_SPACE(ipconh->size);
}

static inline struct ipcon_msghdr *alloc_ipconmsg(__u32 size, gfp_t flags)
{
	struct ipcon_msghdr *result = NULL;

	if (size > MAX_IPCON_MSG_PAYLOAD_SIZE)
		return NULL;

	result = kmalloc(IPCONMSG_SPACE(size), flags);
	if (result) {
		memset(result, 0, sizeof(*result));
		result->ipconmsg_len = IPCONMSG_SPACE(size);
		result->size = size;
		result->refcnt = 1;
	}

	return result;
}

static inline void ipcon_ref(struct ipcon_msghdr **rim)
{
	struct ipcon_msghdr *im;

	if (!rim || !(*rim))
		return;

	im = *rim;

	im->refcnt++;
}

static inline void ipcon_unref(struct ipcon_msghdr **rim)
{
	struct ipcon_msghdr *im;

	if (!rim || !(*rim))
		return;

	im = *rim;

	if (im->refcnt)
		im->refcnt--;

	if (!im->refcnt) {
		kfree(im);
		*rim = NULL;
	}
}

/*
 * This is the maximum length of user message
 * that ipcon supposed to carry.
 */
#define IPCON_MAX_MSG_LEN	2048

#define IPCON_HDR_SIZE	0

/* IPCON_ATTR_MSG_TYPE */
#define IPCON_MSG_UNICAST	1
#define IPCON_MSG_MULTICAST	2

/* IPCON_ATTR_SRV_GROUP */
#define IPCON_KERNEL_GROUP_PORT	0

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
