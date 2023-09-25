/*
 * Copyright 2023 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "act/act.h"
#include "act/act.pb.h"
#include "act/act_v0/act_v0.h"
#include "act/act_v0/testing/transcript.pb.h"
#include "private_join_and_compute/util/proto_util.h"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {
namespace {

const char kTranscriptPathBase[] = "act/act_v0/testing/transcripts/";

TEST(GoldenTranscriptTest, TranscriptPassesValidityTests) {
  auto act = AnonymousCountingTokensV0::Create();

  std::vector<std::string> transcript_paths;

  for (const auto& entry :
       std::filesystem::directory_iterator(kTranscriptPathBase)) {
    transcript_paths.push_back(std::string(entry.path()));
  }

  for (const auto& transcript_path : transcript_paths) {
    ASSERT_OK_AND_ASSIGN(
        Transcript transcript,
        ProtoUtils::ReadProtoFromFile<Transcript>(transcript_path));

    EXPECT_OK(act->CheckClientParameters(
        transcript.scheme_parameters(),
        transcript.client_parameters().public_parameters(),
        transcript.server_parameters().public_parameters(),
        transcript.server_parameters().private_parameters()));

    std::vector<std::string> client_fingerprints(
        transcript.fingerprints().begin(), transcript.fingerprints().end());
    EXPECT_OK(act->CheckTokensRequest(
        client_fingerprints, transcript.tokens_request(),
        transcript.scheme_parameters(),
        transcript.client_parameters().public_parameters(),
        transcript.server_parameters().public_parameters(),
        transcript.server_parameters().private_parameters()));

    std::vector<std::string> messages(transcript.messages().begin(),
                                      transcript.messages().end());
    EXPECT_OK(act->VerifyTokensResponse(
        messages, transcript.tokens_request(),
        transcript.tokens_request_private_state(), transcript.tokens_response(),
        transcript.scheme_parameters(),
        transcript.client_parameters().public_parameters(),
        transcript.client_parameters().private_parameters(),
        transcript.server_parameters().public_parameters()));
  }
}

}  // namespace
}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute
