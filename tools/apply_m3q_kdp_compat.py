#!/usr/bin/env python3
"""Reproduce the proven m3q KernelSU Samsung-KDP refcount fallback.

This is intentionally a fail-closed source transform over the pinned
Root-My-Galaxy KernelSU v3.2.5 Samsung patch. If the upstream source no
longer matches the audited input, abort instead of guessing.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"{label}: expected exactly one source match, found {count}; "
            "refusing to modify an unverified source revision"
        )
    return text.replace(old, new, 1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()

    source = args.source
    text = source.read_text(encoding="utf-8")

    text = replace_once(
        text,
        """#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
typedef unsigned int (*kdp_usecount_sub_and_test_t)(int nr, struct cred *cred);
#else
typedef unsigned int (*kdp_usecount_dec_and_test_t)(struct cred *cred);
#endif""",
        """typedef unsigned int (*kdp_usecount_sub_and_test_t)(int nr, struct cred *cred);
typedef unsigned int (*kdp_usecount_dec_and_test_t)(struct cred *cred);""",
        "KDP refcount typedefs",
    )

    text = replace_once(
        text,
        """#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static kdp_usecount_sub_and_test_t kdp_usecount_sub_and_test_fn;
#else
static kdp_usecount_dec_and_test_t kdp_usecount_dec_and_test_fn;
#endif""",
        """static kdp_usecount_sub_and_test_t kdp_usecount_sub_and_test_fn;
static kdp_usecount_dec_and_test_t kdp_usecount_dec_and_test_fn;""",
        "KDP refcount function pointers",
    )

    text = replace_once(
        text,
        """static void samsung_kdp_commit_worker(struct work_struct *work)
{""",
        """static void samsung_kdp_put_cred_many(const struct cred *cred, int nr)
{
    struct cred *mutable_cred = (struct cred *)cred;

    if (!mutable_cred)
        return;

    if (kdp_usecount_sub_and_test_fn) {
        if (kdp_usecount_sub_and_test_fn(nr, mutable_cred))
            __put_cred(mutable_cred);
        return;
    }

    while (nr-- > 0) {
        if (kdp_usecount_dec_and_test_fn(mutable_cred)) {
            __put_cred(mutable_cred);
            break;
        }
    }
}

static void samsung_kdp_commit_worker(struct work_struct *work)
{""",
        "KDP multi-put helper insertion",
    )

    text = replace_once(
        text,
        """    ksu_put_cred(old_cred);
    ksu_put_cred(old_cred);""",
        """    samsung_kdp_put_cred_many(old_cred, 2);""",
        "KDP old credential release",
    )

    text = replace_once(
        text,
        """#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (mutable_cred && kdp_usecount_sub_and_test_fn(1, mutable_cred))
#else
    if (mutable_cred && kdp_usecount_dec_and_test_fn(mutable_cred))
#endif
        __put_cred(mutable_cred);""",
        """    if (!mutable_cred)
        return;

    if (kdp_usecount_sub_and_test_fn) {
        if (kdp_usecount_sub_and_test_fn(1, mutable_cred))
            __put_cred(mutable_cred);
    } else if (kdp_usecount_dec_and_test_fn(mutable_cred)) {
        __put_cred(mutable_cred);
    }""",
        "KDP single credential release",
    )

    text = replace_once(
        text,
        """#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    kdp_usecount_sub_and_test_fn = (kdp_usecount_sub_and_test_t)ksu_resolve_symbol_for_functable_hook(
        \"kdp_usecount_sub_and_test\");
    if (!kdp_usecount_sub_and_test_fn) {
        pr_err(\"Samsung KDP credential functions unavailable\\n\");
        return -ENOENT;
    }
#else
    kdp_usecount_dec_and_test_fn = (kdp_usecount_dec_and_test_t)ksu_resolve_symbol_for_functable_hook(
        \"kdp_usecount_dec_and_test\");
    if (!kdp_usecount_dec_and_test_fn) {
        pr_err(\"Samsung KDP credential functions unavailable\\n\");
        return -ENOENT;
    }
#endif""",
        """    kdp_usecount_dec_and_test_fn = (kdp_usecount_dec_and_test_t)ksu_resolve_symbol_for_functable_hook(
        \"kdp_usecount_dec_and_test\");
    if (!kdp_usecount_dec_and_test_fn) {
        kdp_usecount_sub_and_test_fn = (kdp_usecount_sub_and_test_t)ksu_resolve_symbol_for_functable_hook(
            \"kdp_usecount_sub_and_test\");
    }
    if (!kdp_usecount_dec_and_test_fn && !kdp_usecount_sub_and_test_fn) {
        pr_err(\"Samsung KDP credential functions unavailable\\n\");
        return -ENOENT;
    }""",
        "KDP runtime resolver fallback",
    )

    required = (
        '\"kdp_usecount_sub_and_test\"',
        '\"kdp_usecount_dec_and_test\"',
        "samsung_kdp_put_cred_many(old_cred, 2);",
    )
    for marker in required:
        if marker not in text:
            raise SystemExit(f"postcondition failed: missing {marker}")

    forbidden = (
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)\n"
        "typedef unsigned int (*kdp_usecount_sub_and_test_t)"
    )
    if forbidden in text:
        raise SystemExit("postcondition failed: version-gated refcount typedef remains")

    source.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
