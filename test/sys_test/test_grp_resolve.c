#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include "ipcon.h"

#define TEST_PEER_NAME "test_peer_resolve"
#define TEST_GROUP_NAME "test_group_resolve"

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

static int resolve_group(const char *peer_name, const char *group_name)
{
	struct nl_msg *msg;
	int ret;
	struct nl_msg *resp = NULL;
	struct nlattr *attrs[NUM_IPCON_ATTR];
	struct sockaddr_nl nladdr;
	unsigned char *buf = NULL;

	msg = nlmsg_alloc_simple(IPCON_GRP_RESLOVE, 0);
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		return -1;
	}

	ret = nla_put_string(msg, IPCON_ATTR_PEER_NAME, peer_name);
	if (ret < 0) {
		fprintf(stderr, "Failed to add peer name attribute\n");
		nlmsg_free(msg);
		return -1;
	}

	ret = nla_put_string(msg, IPCON_ATTR_GROUP_NAME, group_name);
	if (ret < 0) {
		fprintf(stderr, "Failed to add group name attribute\n");
		nlmsg_free(msg);
		return -1;
	}

	ret = nl_send_auto(sock, msg);
	if (ret < 0) {
		fprintf(stderr, "Failed to send group resolve message\n");
		nlmsg_free(msg);
		return -1;
	}

	// Wait for response
	ret = nl_recv(sock, &nladdr, &buf, NULL);
	if (ret <= 0) {
		fprintf(stderr, "Failed to receive response\n");
		nlmsg_free(msg);
		return -1;
	}

	resp = nlmsg_convert(buf);
	if (!resp) {
		fprintf(stderr, "Failed to convert response to nl_msg\n");
		free(buf);
		nlmsg_free(msg);
		return -1;
	}

	ret = nla_parse(attrs, IPCON_ATTR_MAX,
			nlmsg_attrdata(nlmsg_hdr(resp), 0),
			nlmsg_attrlen(nlmsg_hdr(resp), 0), NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to parse response attributes\n");
		nlmsg_free(resp);
		nlmsg_free(msg);
		return -1;
	}

	if (!attrs[IPCON_ATTR_GROUP]) {
		fprintf(stderr, "Response missing group attribute\n");
		nlmsg_free(resp);
		nlmsg_free(msg);
		return -1;
	}

	printf("Resolved group ID: %u\n", nla_get_u32(attrs[IPCON_ATTR_GROUP]));

	nlmsg_free(resp);
	nlmsg_free(msg);
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

	// Register test peer
	if (register_peer(TEST_PEER_NAME) != 0) {
		printf("TEST FAILED: Could not register peer\n");
		ret = 1;
		goto out;
	}

	// Register test group
	if (register_group(TEST_GROUP_NAME) != 0) {
		printf("TEST FAILED: Could not register group\n");
		ret = 1;
		goto out;
	}

	// Test group resolution
	if (resolve_group(TEST_PEER_NAME, TEST_GROUP_NAME) != 0) {
		printf("TEST FAILED: Could not resolve group\n");
		ret = 1;
		goto out;
	}

	printf("TEST PASSED: Group resolution successful\n");

out:
	nl_close(sock);
	nl_socket_free(sock);
	return ret;
}
