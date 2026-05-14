// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for IPCON name_cache
 *
 * Copyright (C) 2025 Seimizu Joukan
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "ipcon.h"
#include "name_cache.h"

/*
 * This KUnit test file tests the name_cache functionality when built
 * in-tree as part of the kernel. The nc_init()/nc_exit() functions
 * depend on the kernel's IDR and slab allocator which are available
 * in the KUnit environment.
 *
 * For out-of-tree CI builds, see the userspace compatibility test
 * in test/compat/ directory.
 */

static void nc_test_create_destroy(struct kunit *test)
{
	/* Verify name_cache init/exit cycle works */
	KUNIT_EXPECT_EQ(test, nc_init(), 0);
	nc_exit();

	/* Init again - should work after a fresh init */
	KUNIT_EXPECT_EQ(test, nc_init(), 0);
	nc_exit();
}

static void nc_test_add_lookup(struct kunit *test)
{
	int id;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	id = nc_add("test_peer", GFP_KERNEL);
	KUNIT_EXPECT_GT(test, id, 0);

	/* Lookup by name should return same ID */
	KUNIT_EXPECT_EQ(test, nc_getid("test_peer"), id);

	/* Lookup by ID should return correct name */
	{
		char buf[IPCON_MAX_NAME_LEN];
		KUNIT_EXPECT_EQ(test, nc_getname(id, buf), 0);
		KUNIT_EXPECT_STR_EQ(test, buf, "test_peer");
	}

	nc_exit();
}

static void nc_test_ref_counting(struct kunit *test)
{
	int id;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	/* nc_add returns a reference */
	id = nc_add("counter_test", GFP_KERNEL);
	KUNIT_ASSERT_GT(test, id, 0);

	/* nc_getid adds another reference */
	KUNIT_EXPECT_EQ(test, nc_getid("counter_test"), id);

	/* Put back the extra reference from nc_getid */
	nc_id_put(id);

	/* Put the initial reference from nc_add */
	nc_id_put(id);

	/* After all refs released, name should no longer be found */
	/* Note: With delayed destruction, nc_getid may still fail */
	KUNIT_EXPECT_LT(test, nc_getid("counter_test"), 0);

	nc_exit();
}

static void nc_test_invalid_name(struct kunit *test)
{
	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	/* NULL name should fail */
	KUNIT_EXPECT_LT(test, nc_add(NULL, GFP_KERNEL), 0);

	/* Empty name should fail */
	KUNIT_EXPECT_LT(test, nc_add("", GFP_KERNEL), 0);

	/* Very long name should fail */
	{
		char long_name[IPCON_MAX_NAME_LEN + 10];
		memset(long_name, 'x', sizeof(long_name) - 1);
		long_name[sizeof(long_name) - 1] = '\0';
		KUNIT_EXPECT_LT(test, nc_add(long_name, GFP_KERNEL), 0);
	}

	/* Lookup of non-existent name should fail */
	KUNIT_EXPECT_LT(test, nc_getid("nonexistent"), 0);

	/* Lookup of non-existent ID should fail */
	{
		char buf[IPCON_MAX_NAME_LEN];
		KUNIT_EXPECT_LT(test, nc_getname(9999, buf), 0);
	}

	nc_exit();
}

static void nc_test_multiple_names(struct kunit *test)
{
	int id1, id2, id3;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	id1 = nc_add("alpha", GFP_KERNEL);
	id2 = nc_add("beta", GFP_KERNEL);
	id3 = nc_add("gamma", GFP_KERNEL);

	KUNIT_EXPECT_GT(test, id1, 0);
	KUNIT_EXPECT_GT(test, id2, 0);
	KUNIT_EXPECT_GT(test, id3, 0);

	/* Each name should have unique ID */
	KUNIT_EXPECT_NE(test, id1, id2);
	KUNIT_EXPECT_NE(test, id2, id3);
	KUNIT_EXPECT_NE(test, id1, id3);

	/* Re-adding same name should return same ID */
	KUNIT_EXPECT_EQ(test, nc_add("alpha", GFP_KERNEL), id1);

	nc_exit();
}

static void nc_test_refname_valid(struct kunit *test)
{
	int id;
	const char *ref;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	id = nc_add("ref_test", GFP_KERNEL);
	KUNIT_ASSERT_GT(test, id, 0);

	/* nc_refname should return valid pointer while ref held by nc_add */
	ref = nc_refname(id);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, ref);
	if (ref)
		KUNIT_EXPECT_STR_EQ(test, ref, "ref_test");

	nc_id_put(id);
	nc_exit();
}

static struct kunit_case nc_test_cases[] = {
	KUNIT_CASE(nc_test_create_destroy),
	KUNIT_CASE(nc_test_add_lookup),
	KUNIT_CASE(nc_test_ref_counting),
	KUNIT_CASE(nc_test_invalid_name),
	KUNIT_CASE(nc_test_multiple_names),
	KUNIT_CASE(nc_test_refname_valid),
	{}
};

static struct kunit_suite nc_test_suite = {
	.name = "ipcon-name-cache",
	.test_cases = nc_test_cases,
};

kunit_test_suite(nc_test_suite);
