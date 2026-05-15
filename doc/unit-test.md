# IPCON Driver Unit Tests

This document describes the unit testing infrastructure for the IPCON driver,
how tests are structured, and how to add new tests.

## Test Framework: KUnit

The IPCON driver uses **KUnit** — the Linux kernel's official unit testing
framework. KUnit tests run in kernel space and can test kernel internals
(memory allocation, locking, data structures) without mocking.

KUnit tests are compiled into the kernel and executed at boot time.

## Test Suites

### name_cache tests (`test/kunit/name_cache_test.c`)

| Test | Description |
|------|-------------|
| `nc_test_create_destroy` | Init/exit cycle |
| `nc_test_add_lookup` | Add name, lookup by name and ID |
| `nc_test_ref_counting` | Reference count management |
| `nc_test_invalid_name` | NULL, empty, and too-long names |
| `nc_test_multiple_names` | Multiple unique names |
| `nc_test_refname_valid` | Valid pointer from nc_refname |

**6 tests total**

### ipcon_db tests (`test/kunit/ipcon_db_test.c`)

| Test | Description |
|------|-------------|
| `ipcon_db_test_create_free` | Allocate and free peer database |
| `ipcon_db_test_insert_lookup_name` | Insert peer, lookup by all 4 hash tables |
| `ipcon_db_test_insert_duplicate` | Reject duplicate peer insertion |
| `ipcon_db_test_invalid_lookup` | Lookup non-existent peer and invalid ports |
| `ipcon_db_test_group_bitmap` | Group register/unregister/renew |
| `ipcon_db_test_peer_anon_type` | Anonymous peer with INVALID_PORT |
| `ipcon_db_test_group_insert_remove` | Group allocation, insert, lookup |

**7 tests total**

## How Tests Work

Each test file declares a test suite using the KUnit macros:

```c
#include <kunit/test.h>

static void my_test(struct kunit *test)
{
    // Test logic with assertions
    KUNIT_EXPECT_EQ(test, actual, expected);
}

static struct kunit_case my_cases[] = {
    KUNIT_CASE(my_test),
    {},
};

static struct kunit_suite my_suite = {
    .name = "my-suite",
    .test_cases = my_cases,
};

kunit_test_suite(my_suite);
```

The `kunit_test_suite()` macro registers the suite so it runs automatically
when the kernel boots with KUnit enabled.

## KUnit Assertion Reference

| Macro | Purpose |
|-------|---------|
| `KUNIT_EXPECT_EQ(test, a, b)` | Assert a == b (integer) |
| `KUNIT_EXPECT_NE(test, a, b)` | Assert a != b |
| `KUNIT_EXPECT_LT(test, a, b)` | Assert a < b |
| `KUNIT_EXPECT_GT(test, a, b)` | Assert a > b |
| `KUNIT_EXPECT_STREQ(test, a, b)` | Assert string equality |
| `KUNIT_EXPECT_TRUE(test, c)` | Assert boolean true |
| `KUNIT_EXPECT_FALSE(test, c)` | Assert boolean false |
| `KUNIT_EXPECT_NULL(test, p)` | Assert NULL pointer |
| `KUNIT_EXPECT_NOT_ERR_OR_NULL(test, p)` | Assert valid pointer |
| `KUNIT_EXPECT_PTR_EQ(test, a, b)` | Assert pointer equality |
| `KUNIT_ASSERT_EQ(test, a, b)` | Hard assert (aborts test on failure) |

## Adding New Tests

### 1. Create a new test file

```c
// test/kunit/my_new_test.c
// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include "ipcon.h"

static void my_new_feature_test(struct kunit *test)
{
    // Test code using kernel APIs directly
    KUNIT_EXPECT_EQ(test, 42, 42);
}

static struct kunit_case my_new_cases[] = {
    KUNIT_CASE(my_new_feature_test),
    {},
};

static struct kunit_suite my_new_suite = {
    .name = "my-new-feature",
    .test_cases = my_new_cases,
};

kunit_test_suite(my_new_suite);
```

### 2. Register in Makefile

Add to `test/kunit/Makefile`:

```makefile
obj-$(CONFIG_IPCON_KUNIT_TEST) += my_new_test.o
ccflags-y += -I$(src)/..
```

### 3. In-tree build (for local testing)

Apply the kernel patches from `doc/patches/`, then:

```bash
cd linux-source
cp -r /path/to/ipcon-drv net/netlink/ipcon/
make menuconfig  # Enable CONFIG_IPCON, CONFIG_IPCON_KUNIT_TEST
make -j$(nproc)
```

### 4. Run with UML (quick testing)

```bash
cd linux-source
cp test/kunit/*.c lib/kunit/
echo "obj-y += name_cache_test.o ipcon_db_test.o my_new_test.o" >> lib/kunit/Makefile
cat > .kunitconfig << 'EOF'
CONFIG_KUNIT=y
EOF
python3 tools/testing/kunit/kunit.py run --arch=um --timeout=300
```

## CI Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs KUnit tests
using UML (User Mode Linux) to avoid requiring real hardware or VMs.

**Caching strategy:**
- Kernel source is cached (`kunit-src-6.12`) — downloaded once
- UML build artifacts are cached (`kunit-uml-v2-6.12-<hash>`) — rebuilt only
  when test/driver source changes
- Cache key includes `hashFiles('test/kunit/*.c','*.c','*.h','Kconfig')`

**Test execution flow:**
1. Download/cache kernel source
2. Copy KUnit test files + driver headers to `lib/kunit/`
3. Append test objects to `lib/kunit/Makefile`
4. Run `python3 tools/testing/kunit/kunit.py run --arch=um`
5. Upload test results as CI artifact

## CI Jobs

| Job | What it tests | Time |
|-----|---------------|------|
| Code Style | clang-format check | ~30s |
| Build (6.1/6.6/6.12 LTS) | Compile on x86_64 + aarch64 | ~3 min |
| KUnit | name_cache + ipcon_db unit tests via UML | ~2 min (cached) |
| Static Analysis | cppcheck | ~30s |

## Writing Good Tests

1. **Test one thing per test case** — Each test function should verify one
   specific behavior. If it fails, you know exactly what broke.

2. **Use KUNIT_EXPECT_ for non-fatal assertions** — The test continues after
   a failure, reporting all issues. Use KUNIT_ASSERT_ only when the test
   cannot continue (e.g., initialization failure).

3. **Initialize and cleanup** — Each test is independent. Set up state at the
   start and clean up at the end. The name cache (`nc_init()/nc_exit()`) is
   a global resource—be careful with test ordering.

4. **Test edge cases** — NULL pointers, empty strings, boundary values,
   invalid parameters. These often find real bugs.

5. **Don't test the framework** — Test your code, not KUnit or the kernel.
   Focus on the driver's data structures and logic.

## Troubleshooting

**"missing expected subtest" errors:**
This happens when kernel log output (e.g., `pr_err`, `pr_info`) interleaves
with KUnit's TAP output. Avoid printing from test code.

**Test crashes (BUG_ON, Oops):**
A kernel bug. The KUnit output will show `[CRASHED]` for the suite.
Check the kernel log for the actual panic message. Common causes:
- `ipd_free()` BUG_ON — peer not properly cleaned up from all hashtables
- Workqueue operations — not all workqueue APIs work in UML

**Build failures in CI:**
- Missing include paths → add `ccflags-y += -I$(src)/..`
- Undefined symbols → driver source files must be compiled alongside tests
