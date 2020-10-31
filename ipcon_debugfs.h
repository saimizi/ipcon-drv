#ifndef __IPCON_DEBUGFS_H__
#define __IPCON_DEBUGFS_H__

#include "ipcon_db.h"

int ipcon_debugfs_init(void);
void ipcon_debugfs_exit(void);
void ipcon_debugfs_add_entry(struct ipcon_peer_node *ipn);
void ipcon_debugfs_remove_entry(struct ipcon_peer_node *ipn);
#endif
