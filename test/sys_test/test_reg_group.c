#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include "ipcon.h"

static struct nl_sock *sock = NULL;

static int register_peer(const char *name)
{
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc_simple(IPCON_PEER_REG, 0);
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		return -1;
	}

	ret = nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);
	if (ret < 0) {
		fprintf(stderr, "Failed to add peer name attribute\n");
		nlmsg_free(msg);
		return -1;
	}

	ret = nl_send_auto(sock, msg);
	nlmsg_free(msg);
	if (ret < 0) {
		fprintf(stderr, "Failed to send peer registration message\n");
		return -1;
	}

	return 0;
}

static int register_group(const char *group_name)
{
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc_simple(IPCON_GRP_REG, 0);
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		return -1;
	}

	ret = nla_put_string(msg, IPCON_ATTR_GROUP_NAME, group_name);
	if (ret < 0) {
		fprintf(stderr, "Failed to add group name attribute\n");
		nlmsg_free(msg);
		return -1;
	}

	ret = nl_send_auto(sock, msg);
	nlmsg_free(msg);
	if (ret < 0) {
		fprintf(stderr, "Failed to send group registration message\n");
		return -1;
	}

	return 0;
}

int main()
{
	int ret = 0;

	sock = nl_socket_alloc();
	if (!sock) {
		printf("TEST FAILED: Could not allocate netlink socket\n");
		return 1;
	}

	if (nl_connect(sock, NETLINK_IPCON) < 0) {
		printf("TEST FAILED: Could not connect netlink socket\n");
		nl_socket_free(sock);
		return 1;
	}

	if (register_peer("test_peer") != 0) {
		printf("TEST FAILED: Could not register peer\n");
		ret = 1;
		goto out;
	}

	if (register_group("test_group") != 0) {
		printf("TEST FAILED: Could not register group\n");
		ret = 1;
		goto out;
	}

	printf("TEST PASSED: Group registration successful\n");

out:
	nl_close(sock);
	nl_socket_free(sock);
	return ret;
}
