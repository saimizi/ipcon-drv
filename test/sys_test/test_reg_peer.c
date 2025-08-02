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
	struct sockaddr_nl dst;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	dst.nl_pid = 0;
	dst.nl_groups = 0;

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		return -1;
	}

	nlmsg_set_dst(msg, &dst);
	nlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, IPCON_PEER_REG,
		  IPCONMSG_HDRLEN, NLM_F_REQUEST);

	ret = nla_put_string(msg, IPCON_ATTR_PEER_NAME, name);
	if (ret < 0) {
		fprintf(stderr, "Failed to add peer name attribute\n");
		nlmsg_free(msg);
		return -1;
	}

	ret = nla_put_u32(msg, IPCON_ATTR_SPORT, 1000);
	ret = nla_put_u32(msg, IPCON_ATTR_RPORT, 1001);
	ret = nla_put_u32(msg, IPCON_ATTR_FLAG, 0);

	nl_complete_msg(sock, msg);

	ret = nl_send_auto(sock, msg);
	nlmsg_free(msg);
	if (ret < 0) {
		fprintf(stderr, "Failed to send peer registration message\n");
		return -1;
	}
	ret = nl_recvmsgs_default(sock);
	if (ret < 0) {
		fprintf(stderr, "Failed to send peer registration message\n");
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

	printf("TEST PASSED: Peer registration successful\n");

out:
	nl_close(sock);
	nl_socket_free(sock);
	return ret;
}
