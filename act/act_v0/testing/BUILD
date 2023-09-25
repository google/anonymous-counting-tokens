# Copyright 2023 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])

proto_library(
    name = "transcript_proto",
    srcs = ["transcript.proto"],
    deps = ["//act:act_proto"],
)

cc_proto_library(
    name = "transcript_cc_proto",
    deps = [":transcript_proto"],
)

cc_binary(
    name = "generate_transcript",
    srcs = ["generate_transcript.cc"],
    deps = [
        ":transcript_cc_proto",
        "//act",
        "//act:act_cc_proto",
        "//act/act_v0",
        "//act/act_v0:act_v0_cc_proto",
        "//act/act_v0:parameters",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@private_join_and_compute//private_join_and_compute/util:proto_util",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

filegroup(
    name = "transcripts",
    testonly = 1,
    srcs = glob(["transcripts/*"]),
)

cc_test(
    name = "golden_transcript_test",
    srcs = ["golden_transcript_test.cc"],
    data = [
        ":transcripts",
    ],
    deps = [
        ":transcript_cc_proto",
        "//act",
        "//act:act_cc_proto",
        "//act/act_v0",
        "//act/act_v0:act_v0_cc_proto",
        "//act/act_v0:parameters",
        "@com_github_google_googletest//:gtest_main",
        "@private_join_and_compute//private_join_and_compute/util:proto_util",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
        "@private_join_and_compute//private_join_and_compute/util:status_testing_includes",
    ],
)
