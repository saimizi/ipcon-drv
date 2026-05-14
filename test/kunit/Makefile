# SPDX-License-Identifier: GPL-2.0
#
# Makefile for IPCON KUnit tests
#
# When patching ipcon into the kernel source tree, add this to
# drivers/net/ipcon/Makefile:
#
#   obj-$(CONFIG_IPCON_KUNIT_TEST) += test/kunit/
#
# For out-of-tree CI testing, see .github/workflows/

# Include paths for IPCON headers (parent directory since tests are in test/)
ccflags-y += -I$(src)/..

obj-$(CONFIG_IPCON_KUNIT_TEST) += name_cache_test.o
obj-$(CONFIG_IPCON_KUNIT_TEST) += ipcon_db_test.o
