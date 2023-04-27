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
    name = "act_v0_proto",
    srcs = ["act_v0.proto"],
    deps = [
        "@private_join_and_compute//private_join_and_compute/crypto/dodis_yampolskiy_prf:bb_oblivious_signature_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/dodis_yampolskiy_prf:dy_verifiable_random_function_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/proto:big_num_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/proto:camenisch_shoup_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/proto:pedersen_proto",
    ],
)

cc_proto_library(
    name = "act_v0_cc_proto",
    deps = [":act_v0_proto"],
)

cc_library(
    name = "act_v0",
    srcs = ["act_v0.cc"],
    hdrs = ["act_v0.h"],
    deps = [
        ":act_v0_cc_proto",
        "//act",
        "//act:act_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/crypto:camenisch_shoup",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
        "@private_join_and_compute//private_join_and_compute/crypto:pedersen_over_zn",
        "@private_join_and_compute//private_join_and_compute/crypto/dodis_yampolskiy_prf:bb_oblivious_signature",
        "@private_join_and_compute//private_join_and_compute/crypto/dodis_yampolskiy_prf:bb_oblivious_signature_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/dodis_yampolskiy_prf:dy_verifiable_random_function",
        "@private_join_and_compute//private_join_and_compute/crypto/dodis_yampolskiy_prf:dy_verifiable_random_function_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/proto:ec_point_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/proto:proto_util",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
    ],
)

cc_test(
    name = "act_v0_test",
    srcs = ["act_v0_test.cc"],
    deps = [
        ":act_v0",
        ":act_v0_cc_proto",
        ":parameters",
        "//act",
        "//act:act_cc_proto",
        "@com_github_google_googletest//:gtest_main",
        "@private_join_and_compute//private_join_and_compute/crypto:bn_util",
        "@private_join_and_compute//private_join_and_compute/crypto:camenisch_shoup",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
        "@private_join_and_compute//private_join_and_compute/crypto:pedersen_over_zn",
        "@private_join_and_compute//private_join_and_compute/crypto/dodis_yampolskiy_prf:bb_oblivious_signature_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/dodis_yampolskiy_prf:dy_verifiable_random_function_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/proto:big_num_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/proto:camenisch_shoup_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto/proto:pedersen_cc_proto",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
        "@private_join_and_compute//private_join_and_compute/util:status_testing_includes",
    ],
)

cc_library(
    name = "parameters",
    srcs = ["parameters.cc"],
    hdrs = ["parameters.h"],
    deps = [
        ":act_v0_cc_proto",
        "//act:act_cc_proto",
        "@private_join_and_compute//private_join_and_compute/crypto:ec_util",
    ],
)

cc_test(
    name = "parameters_test",
    size = "enormous",
    srcs = ["parameters_test.cc"],
    deps = [
        ":act_v0",
        ":parameters",
        "//act",
        "//act:act_cc_proto",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/strings",
        "@private_join_and_compute//private_join_and_compute/util:status_includes",
        "@private_join_and_compute//private_join_and_compute/util:status_testing_includes",
    ],
)
