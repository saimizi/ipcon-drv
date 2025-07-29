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
 * __netlink_clear_multicast_users - Clear multicast users for a group
 * @sk: Netlink socket
 * @group: Multicast group ID
 *
 * This function provides a stub implementation for clearing multicast users.
 * The original internal function is not available for out-of-tree modules.
 * 
 * Note: This is a simplified implementation that may not provide full
 * functionality of the original internal function.
 */
static inline void __netlink_clear_multicast_users(struct sock *sk,
						   unsigned int group)
{
	/*
	 * For out-of-tree modules, we provide a stub implementation.
	 * The original function would clear all multicast subscriptions
	 * for the specified group, but this requires access to internal
	 * netlink table structures that are not exported.
	 * 
	 * In a production environment, alternative approaches would be needed:
	 * - Use netlink_broadcast with specific filtering
	 * - Implement custom user tracking
	 * - Use other public netlink APIs
	 */
	pr_debug("netlink: clearing multicast users for group %u (stub)\n",
		 group);
}

#endif /* _AF_NETLINK_H */