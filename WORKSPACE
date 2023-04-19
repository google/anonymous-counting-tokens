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

"""WORKSPACE file for Anonymous Counting Tokens code."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

# Private Join and Compute
http_archive(
    name = "private_join_and_compute",
    sha256 = "6026c6522b0119e48b697492d184ee60be97071344c2788095fcb2a489ad905f",
    strip_prefix = "private-join-and-compute-e028e59420a9c36328705ed5064408de03d229a8",
    urls = ["https://github.com/google/private-join-and-compute/archive/e028e59420a9c36328705ed5064408de03d229a8.zip"],
)

# loads boringssl, absl, googletest, protobuf.
load("@private_join_and_compute//bazel:pjc_deps.bzl", "pjc_deps")
pjc_deps()

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
protobuf_deps()

# gRPC
# must be included separately, since we need to load transitive deps of grpc for
# some of the pjc deps.
http_archive(
    name = "com_github_grpc_grpc",
    sha256 = "feaeeb315133ea5e3b046c2c0231f5b86ef9d297e536a14b73e0393335f8b157", 
    strip_prefix = "grpc-1.51.3",
    urls = [
        "https://github.com/grpc/grpc/archive/v1.51.3.tar.gz",
    ],
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
grpc_deps()

load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")
grpc_extra_deps()