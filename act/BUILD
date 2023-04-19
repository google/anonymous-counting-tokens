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

# Contains implementations for Anonymous Counting Tokens.

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])

proto_library(
    name = "act_proto",
    srcs = ["act.proto"],
    deps = ["//act/act_v0:act_v0_proto"],
)

cc_proto_library(
    name = "act_cc_proto",
    deps = [":act_proto"],
)

cc_library(
    name = "act",
    hdrs = ["act.h"],
    deps = [
        ":act_cc_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

cc_library(
    name = "fake_act",
    srcs = ["fake_act.cc"],
    hdrs = ["fake_act.h"],
    deps = [
        ":act",
        ":act_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

cc_test(
    name = "fake_act_test",
    srcs = [
        "fake_act_test.cc",
    ],
    deps = [
        ":fake_act",
        "@com_github_google_googletest//:gtest_main",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
        "@private_join_and_compute//private_join_and_compute/util:status_testing_includes",
    ],
)
