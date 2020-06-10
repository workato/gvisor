"""Bazel build rule for libseccomp."""

load("@rules_foreign_cc//tools/build_defs:configure.bzl", "configure_make")

# This is a rule to build libseccomp for tests.
configure_make(
    name = "libseccomp",
    lib_source = "@com_github_seccomp_libseccomp//:all",
    visibility = ["//:sandbox"],
)
