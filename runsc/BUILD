load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "runsc",
    srcs = [
        "main.go",
        "version.go",
    ],
    pure = True,
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"main.version": "{STABLE_VERSION}"},
    deps = [
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/platform",
        "//runsc/cmd",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

# The runsc-race target is a race-compatible BUILD target. This must be built
# via: bazel build --features=race :runsc-race
#
# This is neccessary because the race feature must apply to all dependencies
# due a bug in gazelle file selection.  The pure attribute must be off because
# the race detector requires linking with non-Go components, although we still
# require a static binary.
#
# Note that in the future this might be convertible to a compatible target by
# using the pure and static attributes within a select function, but select is
# not currently compatible with string attributes [1].
#
# [1] https://github.com/bazelbuild/bazel/issues/1698
go_binary(
    name = "runsc-race",
    srcs = [
        "main.go",
        "version.go",
    ],
    static = True,
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"main.version": "{STABLE_VERSION}"},
    deps = [
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/platform",
        "//runsc/cmd",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

sh_test(
    name = "version_test",
    size = "small",
    srcs = ["version_test.sh"],
    args = ["$(location :runsc)"],
    data = [":runsc"],
    tags = ["noguitar"],
)
