obj-${CONFIG_IPCON} += main.o ipcon_nl.o ipcon_msg.o ipcon_db.o name_cache.o
obj-${CONFIG_DEBUG_FS} += ipcon_debugfs.o
CFLAGS_ipcon_nl.o := -O0
CFLAGS_ipcon_msg.o := -O0
CFLAGS_ipcon_db.o := -O0
CFLAGS_name_cache.o := -O0
