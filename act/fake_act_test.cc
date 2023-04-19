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

#include "act/fake_act.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "private_join_and_compute/util/status.inc"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {
namespace {

TEST(FakeActTest, FingerprintsAreEqualExactlyWhenMessagesAreEqual) {
  auto fake_act = FakeAnonymousCountingTokens::Create();

  std::vector<std::string> messages_1 = {"m1", "m2"};
  std::vector<std::string> fingerprints_1;

  std::vector<std::string> messages_2 = {"m3", "m1"};
  std::vector<std::string> fingerprints_2;

  // Empty parameters for testing the fake.
  SchemeParameters scheme_parameters;
  ClientPublicParameters client_public_parameters;
  ClientPrivateParameters client_private_parameters;
  ServerPublicParameters server_public_parameters;

  ASSERT_OK_AND_ASSIGN(
      std::tie(fingerprints_1, std::ignore, std::ignore),
      fake_act->GenerateTokensRequest(
          messages_1, scheme_parameters, client_public_parameters,
          client_private_parameters, server_public_parameters));
  ASSERT_OK_AND_ASSIGN(
      std::tie(fingerprints_2, std::ignore, std::ignore),
      fake_act->GenerateTokensRequest(
          messages_2, scheme_parameters, client_public_parameters,
          client_private_parameters, server_public_parameters));

  // Only the fingerprints for "m1" should be the same.
  EXPECT_EQ(fingerprints_1[0], fingerprints_2[1]);
  EXPECT_NE(fingerprints_1[0], fingerprints_2[0]);
  EXPECT_NE(fingerprints_1[1], fingerprints_2[1]);
  EXPECT_NE(fingerprints_1[1], fingerprints_2[0]);
}

TEST(FakeActTest, DifferentTokensAreNotEqual) {
  auto fake_act = FakeAnonymousCountingTokens::Create();

  std::vector<std::string> messages = {"m1", "m2"};
  // Empty parameters and messages for testing the fake.
  TokensRequest tokens_request;
  TokensRequestPrivateState tokens_request_private_state;
  TokensResponse tokens_response;
  SchemeParameters scheme_parameters;
  ClientPublicParameters client_public_parameters;
  ClientPrivateParameters client_private_parameters;
  ServerPublicParameters server_public_parameters;

  ASSERT_OK_AND_ASSIGN(
      std::vector<Token> tokens,
      fake_act->RecoverTokens(
          messages, tokens_request, tokens_request_private_state,
          tokens_response, scheme_parameters, client_public_parameters,
          client_private_parameters, server_public_parameters));

  EXPECT_NE(tokens[0].SerializeAsString(), tokens[1].SerializeAsString());
}

}  // namespace
}  // namespace anonymous_counting_tokens

}  // namespace private_join_and_compute
