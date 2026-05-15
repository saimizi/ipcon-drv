// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for IPCON peer database (ipcon_db)
 *
 * Copyright (C) 2025 Seimizu Joukan
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "ipcon.h"
#include "ipcon_db.h"
#include "name_cache.h"

static void ipcon_db_test_create_free(struct kunit *test)
{
	struct ipcon_peer_db *db;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	ipd_free(db);
	nc_exit();
}

static void ipcon_db_test_group_bitmap(struct kunit *test)
{
	struct ipcon_peer_db *db;

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	KUNIT_EXPECT_FALSE(test, group_inuse(db, 1));
	KUNIT_EXPECT_FALSE(test, group_inuse(db, IPCON_MAX_GROUP));

	reg_group(db, 1);
	KUNIT_EXPECT_TRUE(test, group_inuse(db, 1));

	unreg_group(db, 1);
	KUNIT_EXPECT_FALSE(test, group_inuse(db, 1));

	ipd_free(db);
}

static struct kunit_case ipcon_db_test_cases[] = {
	KUNIT_CASE(ipcon_db_test_create_free),
	KUNIT_CASE(ipcon_db_test_group_bitmap),
	{}
};

static struct kunit_suite ipcon_db_test_suite = {
	.name = "ipcon-db",
	.test_cases = ipcon_db_test_cases,
};

kunit_test_suite(ipcon_db_test_suite);
