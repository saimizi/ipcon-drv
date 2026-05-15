# SPDX-License-Identifier: GPL-2.0
#
# Makefile for IPCON KUnit tests (CI out-of-tree build)
#
# obj-y is used here because the CI bypasses Kconfig.
# For in-tree builds, use: obj-$(CONFIG_IPCON_KUNIT_TEST)

obj-y += name_cache_test.o
obj-y += ipcon_db_test.o

# Include paths for IPCON headers
ccflags-y += -I$(src)/..
