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

/*
 * Helper: register a test peer in the database
 */
static struct ipcon_peer_node *
create_test_peer(struct kunit *test, struct ipcon_peer_db *db, const char *name,
		 enum peer_type type, u32 ctrl_port, u32 snd_port, u32 rcv_port,
		 unsigned long flags)
{
	int nameid, commid;
	struct ipcon_peer_node *ipn;
	const char *process_name = "kunit_test";

	nameid = nc_add(name, GFP_KERNEL);
	KUNIT_ASSERT_GT(test, nameid, 0);

	commid = nc_add(process_name, GFP_KERNEL);
	KUNIT_ASSERT_GT(test, commid, 0);

	ipn = ipn_alloc(ctrl_port, snd_port, rcv_port, nameid, commid,
			current->pid, type, flags, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ipn);

	KUNIT_ASSERT_EQ(test, ipd_insert(db, ipn), 0);

	nc_id_put(nameid);
	nc_id_put(commid);

	return ipn;
}

static void ipcon_db_test_create_free(struct kunit *test)
{
	struct ipcon_peer_db *db;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	ipd_free(db);
	nc_exit();
}

static void ipcon_db_test_insert_lookup_name(struct kunit *test)
{
	struct ipcon_peer_db *db;
	struct ipcon_peer_node *ipn, *found;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	ipn = create_test_peer(test, db, "test_srv", PEER_TYPE_NORMAL, 100, 200,
			       300, 0);

	/* Lookup by name */
	found = ipd_lookup_byname(db, ipn->nameid);
	KUNIT_EXPECT_PTR_EQ(test, found, ipn);

	/* Lookup by ctrl port */
	found = ipd_lookup_bycport(db, 100);
	KUNIT_EXPECT_PTR_EQ(test, found, ipn);

	/* Lookup by snd port */
	found = ipd_lookup_bysport(db, 200);
	KUNIT_EXPECT_PTR_EQ(test, found, ipn);

	/* Lookup by rcv port */
	found = ipd_lookup_byrport(db, 300);
	KUNIT_EXPECT_PTR_EQ(test, found, ipn);

	ipd_free(db);
	nc_exit();
}

static void ipcon_db_test_insert_duplicate(struct kunit *test)
{
	struct ipcon_peer_db *db;
	struct ipcon_peer_node *ipn1, *ipn2;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	ipn1 = create_test_peer(test, db, "dup_peer", PEER_TYPE_NORMAL, 101,
				201, 301, 0);

	/* Second peer with same name should fail */
	ipn2 = ipn_alloc(102, 202, 302, ipn1->nameid, ipn1->commid,
			 current->pid, PEER_TYPE_NORMAL, 0, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ipn2);
	KUNIT_EXPECT_LT(test, ipd_insert(db, ipn2), 0);
	ipn_free(ipn2);

	ipd_free(db);
	nc_exit();
}

static void ipcon_db_test_invalid_lookup(struct kunit *test)
{
	struct ipcon_peer_db *db;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	/* Lookup non-existent peer */
	KUNIT_EXPECT_NULL(test, ipd_lookup_byname(db, 999));
	KUNIT_EXPECT_NULL(test, ipd_lookup_bycport(db, 999));
	KUNIT_EXPECT_NULL(test, ipd_lookup_bysport(db, 999));
	KUNIT_EXPECT_NULL(test, ipd_lookup_byrport(db, 999));

	/* All INVALID_PORT lookups should return NULL */
	KUNIT_EXPECT_NULL(test, ipd_lookup_bycport(db, IPCON_INVALID_PORT));
	KUNIT_EXPECT_NULL(test, ipd_lookup_bysport(db, IPCON_INVALID_PORT));
	KUNIT_EXPECT_NULL(test, ipd_lookup_byrport(db, IPCON_INVALID_PORT));

	ipd_free(db);
	nc_exit();
}

static void ipcon_db_test_group_bitmap(struct kunit *test)
{
	struct ipcon_peer_db *db;

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	/* Initially no groups should be in use */
	KUNIT_EXPECT_FALSE(test, group_inuse(db, 1));
	KUNIT_EXPECT_FALSE(test, group_inuse(db, 50));
	KUNIT_EXPECT_FALSE(test, group_inuse(db, IPCON_MAX_GROUP));

	/* Register a group */
	reg_group(db, 1);
	KUNIT_EXPECT_TRUE(test, group_inuse(db, 1));

	/* Unregister group */
	unreg_group(db, 1);
	KUNIT_EXPECT_FALSE(test, group_inuse(db, 1));

	/* Register multiple groups */
	reg_group(db, 10);
	reg_group(db, 20);
	reg_group(db, 30);
	KUNIT_EXPECT_TRUE(test, group_inuse(db, 10));
	KUNIT_EXPECT_TRUE(test, group_inuse(db, 20));
	KUNIT_EXPECT_TRUE(test, group_inuse(db, 30));

	/* Unregister one, others still present */
	unreg_group(db, 20);
	KUNIT_EXPECT_TRUE(test, group_inuse(db, 10));
	KUNIT_EXPECT_FALSE(test, group_inuse(db, 20));
	KUNIT_EXPECT_TRUE(test, group_inuse(db, 30));

	/* reg_new_group should work and mark range */
	{
		int gid = reg_new_group(db);
		KUNIT_EXPECT_GT(test, gid, 0);
		KUNIT_EXPECT_TRUE(test, group_inuse(db, gid));
	}

	ipd_free(db);
}

static void ipcon_db_test_peer_anon_type(struct kunit *test)
{
	struct ipcon_peer_db *db;
	struct ipcon_peer_node *ipn;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	/* Create anonymous peer */
	ipn = create_test_peer(test, db, "anon_1", PEER_TYPE_ANON, 200,
			       IPCON_INVALID_PORT, IPCON_INVALID_PORT,
			       IPCON_FLG_ANON_PEER);
	KUNIT_EXPECT_EQ(test, ipn->type, PEER_TYPE_ANON);

	/* Cannot lookup by invalid ports */
	KUNIT_EXPECT_NULL(test, ipd_lookup_bysport(db, IPCON_INVALID_PORT));
	KUNIT_EXPECT_NULL(test, ipd_lookup_byrport(db, IPCON_INVALID_PORT));

	/* Can still lookup by name and ctrl */
	KUNIT_EXPECT_PTR_EQ(test, ipd_lookup_byname(db, ipn->nameid), ipn);
	KUNIT_EXPECT_PTR_EQ(test, ipd_lookup_bycport(db, 200), ipn);

	ipd_free(db);
	nc_exit();
}

static void ipcon_db_test_group_insert_remove(struct kunit *test)
{
	struct ipcon_peer_db *db;
	struct ipcon_peer_node *ipn;
	struct ipcon_group_info *igi;
	int group_nameid;

	KUNIT_ASSERT_EQ(test, nc_init(), 0);

	db = ipd_alloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, db);

	ipn = create_test_peer(test, db, "grp_peer", PEER_TYPE_NORMAL, 301, 302,
			       303, 0);

	/* Add a group */
	group_nameid = nc_add("test_group", GFP_KERNEL);
	KUNIT_ASSERT_GT(test, group_nameid, 0);

	reg_group(db, 42);
	igi = igi_alloc(group_nameid, 42, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, igi);

	KUNIT_EXPECT_EQ(test, ipn_insert(ipn, igi), 0);

	/* Verify group lookup by name and group ID */
	KUNIT_EXPECT_PTR_EQ(test, ipn_lookup_byname(ipn, group_nameid), igi);
	KUNIT_EXPECT_PTR_EQ(test, ipn_lookup_bygroup(ipn, 42), igi);

	/* Duplicate group insert should fail */
	KUNIT_EXPECT_EQ(test, ipn_insert(ipn, igi), -EEXIST);

	nc_id_put(group_nameid);
	ipd_free(db);
	nc_exit();
}

static struct kunit_case ipcon_db_test_cases[] = {
	KUNIT_CASE(ipcon_db_test_create_free),
	KUNIT_CASE(ipcon_db_test_insert_lookup_name),
	KUNIT_CASE(ipcon_db_test_insert_duplicate),
	KUNIT_CASE(ipcon_db_test_invalid_lookup),
	KUNIT_CASE(ipcon_db_test_group_bitmap),
	KUNIT_CASE(ipcon_db_test_peer_anon_type),
	KUNIT_CASE(ipcon_db_test_group_insert_remove),
	{}
};

static struct kunit_suite ipcon_db_test_suite = {
	.name = "ipcon-db",
	.test_cases = ipcon_db_test_cases,
};

kunit_test_suite(ipcon_db_test_suite);
