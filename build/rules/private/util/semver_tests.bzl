load("@bazel_skylib//lib:unittest.bzl", "asserts", "unittest")
load(":semver.bzl", "semver")

def _semver_parse_test(ctx):
    env = unittest.begin(ctx)

    v1_0_0 = semver.parse("v1.0.0")
    asserts.equals(env, 1, v1_0_0.major)
    asserts.equals(env, 0, v1_0_0.minor)
    asserts.equals(env, 0, v1_0_0.patch)

    v1_0 = semver.parse("v1.0")
    asserts.equals(env, 1, v1_0_0.major)
    asserts.equals(env, 0, v1_0_0.minor)
    asserts.equals(env, 0, v1_0_0.patch)

    v1_0_foo = semver.parse("v1.0.foo")
    asserts.equals(env, None, v1_0_foo)

    return unittest.end(env)

semver_parse_test = unittest.make(_semver_parse_test)

def _semver_equal_test(ctx):
    env = unittest.begin(ctx)

    left = semver.parse("v1.0.0")
    right = semver.parse("v1.0.0")
    asserts.true(env, semver.equal(left, right))

    right = semver.parse("v1.0.1")
    asserts.false(env, semver.equal(left, right))

    right = semver.parse("v1.1.0")
    asserts.false(env, semver.equal(left, right))

    right = semver.parse("v2.0.0")
    asserts.false(env, semver.equal(left, right))

    return unittest.end(env)

semver_equal_test = unittest.make(_semver_equal_test)

def _semver_gt_test(ctx):
    env = unittest.begin(ctx)

    left = semver.parse("v1.0.0")
    right = semver.parse("v0.9.9")
    asserts.true(env, semver.gt(left, right))

    right = semver.parse("v0.99.0")
    asserts.true(env, semver.gt(left, right))

    right = semver.parse("v0.9.99")
    asserts.true(env, semver.gt(left, right))

    right = semver.parse("v1.0.1")
    asserts.false(env, semver.gt(left, right))

    right = semver.parse("v1.1.0")
    asserts.false(env, semver.gt(left, right))

    right = semver.parse("v2.0.0")
    asserts.false(env, semver.gt(left, right))

    return unittest.end(env)

semver_gt_test = unittest.make(_semver_gt_test)

def _semver_lt_test(ctx):
    env = unittest.begin(ctx)

    left = semver.parse("v1.0.0")
    right = semver.parse("v1.0.1")
    asserts.true(env, semver.lt(left, right))

    right = semver.parse("v1.10.0")
    asserts.true(env, semver.lt(left, right))

    right = semver.parse("v2.0.0")
    asserts.true(env, semver.lt(left, right))

    right = semver.parse("v2.99.0")
    asserts.true(env, semver.lt(left, right))

    right = semver.parse("v0.9.9")
    asserts.false(env, semver.lt(left, right))

    right = semver.parse("v0.9.0")
    asserts.false(env, semver.lt(left, right))

    return unittest.end(env)

semver_lt_test = unittest.make(_semver_lt_test)

def _semver_gte_test(ctx):
    env = unittest.begin(ctx)

    left = semver.parse("v1.0.0")
    right = semver.parse("v0.9.9")
    asserts.true(env, semver.gte(left, right))

    right = semver.parse("v1.0.0")
    asserts.true(env, semver.gte(left, right))

    return unittest.end(env)

semver_gte_test = unittest.make(_semver_gte_test)

def _semver_lte_test(ctx):
    env = unittest.begin(ctx)

    left = semver.parse("v1.0.0")
    right = semver.parse("v1.0.1")
    asserts.true(env, semver.lte(left, right))

    right = semver.parse("v1.0.0")
    asserts.true(env, semver.lte(left, right))

    return unittest.end(env)

semver_lte_test = unittest.make(_semver_lte_test)

def semver_test_suite():
    unittest.suite(
        "semver_tests",
        semver_parse_test,
        semver_equal_test,
        semver_gt_test,
        semver_lt_test,
        semver_gte_test,
        semver_lte_test,
    )
