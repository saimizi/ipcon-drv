/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_MSG_H__
#define __IPCON_MSG_H__

#include "ipcon.h"

static inline struct ipcon_msghdr *ipconmsg_hdr(struct sk_buff *skb)
{
	return nlmsg_data(nlmsg_hdr(skb));
}

static inline __u8 ipconmsg_cmd(struct sk_buff *skb)
{
	return ipconmsg_hdr(skb)->cmd;
}

static inline __u32 ipconmsg_srcport(struct sk_buff *skb)
{
	return NETLINK_CB(skb).portid;
}

static inline __u32 ipconmsg_seq(struct sk_buff *skb)
{
	return nlmsg_hdr(skb)->nlmsg_seq;
}

int ipconmsg_parse(struct sk_buff *skb,
	struct nlattr *tb[], int maxtype, const struct nla_policy *policy,
	struct netlink_ext_ack *extack);
struct sk_buff *ipconmsg_new(gfp_t flags);

void *ipconmsg_put(struct sk_buff *skb, __u32 portid, __u32 seq,
		enum ipcon_msg_type type, int flags, __u8 cmd);

static inline void *ipconmsg_put_ctl(struct sk_buff *skb, __u32 seq, int flags, __u8 cmd)
{
	return ipconmsg_put(skb, 0, seq, IPCON_TYPE_CTL, flags, cmd);
}

static inline void *ipconmsg_put_msg(struct sk_buff *skb, __u32 seq, int flags, __u8 cmd)
{
	return ipconmsg_put(skb, 0, seq, IPCON_TYPE_MSG, flags, cmd);
}

/**
 * ipconmsg_end - Finalize a ipcon netlink message
 * @skb: socket buffer the message is stored in
 * @p: return value of ipconmsg_put()
 */
static inline void ipconmsg_end(struct sk_buff *skb, void *p)
{
	return nlmsg_end(skb, p - IPCONMSG_HDRLEN - NLMSG_HDRLEN);
}

/**
 * ipconmsg_cancel - Cancel construction of a ipcon netlink message
 * @skb: socket buffer the message is stored in
 * @p: return value of ipconmsg_put()
 */
static inline void ipconmsg_cancel(struct sk_buff *skb, void *p)
{
	return nlmsg_cancel(skb, p - IPCONMSG_HDRLEN - NLMSG_HDRLEN);
}

#endif

