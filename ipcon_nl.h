#ifndef __IPCON_GENL_H__
#define __IPCON_GENL_H__

int ipcon_nl_init(void);
void ipcon_nl_exit(void);

int ipcon_unicast(struct sk_buff *skb, __u32 port);
int ipcon_multicast(struct sk_buff *skb, __u32 sndport,
		__u32 group, gfp_t flags);

#endif
