#ifndef __IPCON_GENL_H__
#define __IPCON_GENL_H__

int ipcon_genl_init(void);
void ipcon_genl_exit(void);

#ifdef CONFIG_DEBUG_FS
void ipcon_debugfs_lock_tree(int is_srv);
void ipcon_debugfs_unlock_tree(int is_srv);
struct ipcon_tree_node *ipcon_lookup_unlock(char *name, int is_srv);
const struct nla_policy *ipcon_get_policy(void);
const struct genl_family *ipcon_get_family(void);
#endif

#endif
