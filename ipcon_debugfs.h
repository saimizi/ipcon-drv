#ifndef __IPCON_DEBUGFS_H__
#define __IPCON_DEBUGFS_H__

int __init ipcon_debugfs_init(__u32 *srv_num, __u32 *grp_num);
void __exit ipcon_debugfs_exit(void);
void ipcon_debugfs_add_entry(struct ipcon_tree_node *nd, int is_srv);
void ipcon_debugfs_remove_entry(struct ipcon_tree_node *nd);
int ipcon_debugfs_remove_srv(struct ipcon_tree_node *nd);

#endif
