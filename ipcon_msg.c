/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <net/netlink.h>
#include "ipcon.h"
#include "ipcon_msg.h"

/**
 * ipconmsg_parse - parse attributes of a ipcon message
 * @skb: ipcon netlink message
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @policy: validation policy
 * @extack: extended ACK report struct
 */
int ipconmsg_parse(struct sk_buff *skb,
				struct nlattr *tb[], int maxtype,
				const struct nla_policy *policy,
				struct netlink_ext_ack *extack)
{
	return nlmsg_parse(nlmsg_hdr(skb),
			IPCONMSG_HDRLEN,
			tb, maxtype, policy, extack);
}

/**
 * ipconmsg_new - Allocate a new ipcon netlink message
 * @flags: the type of memory to allocate.
 */
struct sk_buff *ipconmsg_new(gfp_t flags)
{
	return nlmsg_new(NLMSG_DEFAULT_SIZE, flags);
}

__u32 ipconmsg_global_seq;

/**
 * ipconmsg_put - Add ipcon netlink header to netlink message
 * @skb: socket buffer holding the message
 * @portid: netlink portid of caller
 * @seq: sequence number (usually the one of the sender)
 * @flags: netlink message flags
 *
 * Returns pointer to user specific header
 */
void *ipconmsg_put(struct sk_buff *skb, __u32 portid, __u32 seq,
		enum ipcon_msg_type type, int flags)
{
	struct nlmsghdr *nlh;
	struct ipconmsghdr *hdr;

	if (!flags)
		flags |= NLM_F_REQUEST;

	nlh = nlmsg_put(skb, portid, seq, type, IPCONMSG_HDRLEN, flags);
	if (!nlh)
		return NULL;

	hdr = nlmsg_data(nlh);
	hdr->reserved = ++ipconmsg_global_seq;

	return (char *) hdr + IPCONMSG_HDRLEN;
}
