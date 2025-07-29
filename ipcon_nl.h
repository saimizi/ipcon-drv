#ifndef __IPCON_GENL_H__
#define __IPCON_GENL_H__

#define IPCON_KERNEL_GROUP 1

int ipcon_nl_init(void);
void ipcon_nl_exit(void);

int ipcon_unicast(struct sk_buff *skb, __u32 port);
int ipcon_multicast(struct sk_buff *skb, __u32 sndport, __u32 group,
		    gfp_t flags);
int ipcon_multicast_filtered(struct sk_buff *skb, __u32 exclusive_port,
			     __u32 group, gfp_t flags,
			     int (*filter)(struct sock *dsk,
					   struct sk_buff *skb, void *data),
			     void *filter_data);

#endif
