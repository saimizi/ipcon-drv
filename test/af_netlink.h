/* SPDX-License-Identifier: GPL-2.0 */
/*
 * af_netlink.h - Local definitions for netlink internals
 * 
 * This file provides necessary internal netlink definitions for out-of-tree
 * module compilation. These definitions are extracted from the kernel's
 * internal af_netlink.h and net/netlink/af_netlink.c files.
 * 
 * Note: These are internal kernel APIs and may change between kernel versions.
 * This header is provided for compatibility with out-of-tree module builds.
 */

#ifndef _AF_NETLINK_H
#define _AF_NETLINK_H

#include <linux/netlink.h>
#include <net/sock.h>

/*
 * Netlink socket structure - simplified version for portid access
 * This mirrors the internal netlink_sock structure layout for portid field
 */
struct netlink_sock {
	struct sock sk;
	u32 portid;
	/* ... other fields not needed for our usage ... */
};

/*
 * nlk_sk - Get netlink socket from generic socket
 * @sk: Generic socket pointer
 *
 * Returns the netlink socket structure from a generic socket.
 * This replicates the internal nlk_sk() function.
 */
static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

/*
 * Note: __netlink_clear_multicast_users is already declared in linux/netlink.h
 * We don't need to redeclare it here as it's available in newer kernels.
 */

/*
 * netlink_broadcast_filtered - Broadcast with filtering support
 * @sk: Netlink socket
 * @skb: Socket buffer to broadcast
 * @portid: Sender's port ID
 * @group: Multicast group
 * @flags: Allocation flags
 * @filter: Filter function
 * @filter_data: Data for filter function
 *
 * This function is not exported in the public kernel API but is needed
 * for filtering functionality. We provide a wrapper that falls back to
 * standard netlink_broadcast when filtering is not critical.
 */
static inline int netlink_broadcast_filtered(
	struct sock *sk, struct sk_buff *skb, u32 portid, u32 group,
	gfp_t flags,
	int (*filter)(struct sock *dsk, struct sk_buff *skb, void *data),
	void *filter_data)
{
	/*
	 * For out-of-tree builds, we fall back to standard netlink_broadcast.
	 * This reduces functionality but maintains compatibility.
	 * 
	 * Note: filter and filter_data parameters are ignored in this implementation.
	 * For full filtering support, the module should be built in-tree where
	 * the internal netlink_broadcast_filtered function is available.
	 */
	return netlink_broadcast(sk, skb, portid, group, flags);
}

#endif /* _AF_NETLINK_H */