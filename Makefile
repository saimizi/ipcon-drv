obj-${CONFIG_IPCON} += main.o ipcon_nl.o ipcon_db.o name_cache.o
CFLAGS_ipcon_genl.o += -Inet/netlink
