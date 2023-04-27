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

#include "act/act_v0/parameters.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "act/act.h"
#include "act/act.pb.h"
#include "act/act_v0/act_v0.h"
#include "private_join_and_compute/util/status.inc"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {
namespace {

Status EndToEndTest(SchemeParameters scheme_parameters, int num_messages) {
  std::unique_ptr<AnonymousCountingTokens> act =
      AnonymousCountingTokensV0::Create();

  // Generate server parameters.
  ASSIGN_OR_RETURN(ServerParameters server_parameters,
                   act->GenerateServerParameters(scheme_parameters));

  // Generate client parameters and check them.
  ASSIGN_OR_RETURN(
      ClientParameters client_parameters,
      act->GenerateClientParameters(scheme_parameters,
                                    server_parameters.public_parameters()));

  RETURN_IF_ERROR(act->CheckClientParameters(
      scheme_parameters, client_parameters.public_parameters(),
      server_parameters.public_parameters(),
      server_parameters.private_parameters()));

  // Generate messages.
  std::vector<std::string> messages;
  messages.reserve(num_messages);
  for (int i = 0; i < num_messages; ++i) {
    messages.push_back(absl::StrCat("message", i));
  }

  // Generate Tokens Request and check it.
  std::vector<std::string> client_fingerprints;
  TokensRequest tokens_request;
  TokensRequestPrivateState tokens_request_private_state;
  ASSIGN_OR_RETURN(
      std::tie(client_fingerprints, tokens_request,
               tokens_request_private_state),
      act->GenerateTokensRequest(messages, scheme_parameters,
                                 client_parameters.public_parameters(),
                                 client_parameters.private_parameters(),
                                 server_parameters.public_parameters()));
  RETURN_IF_ERROR(act->CheckTokensRequest(
      client_fingerprints, tokens_request, scheme_parameters,
      client_parameters.public_parameters(),
      server_parameters.public_parameters(),
      server_parameters.private_parameters()));

  // Generate Tokens Response and check it.
  ASSIGN_OR_RETURN(
      TokensResponse tokens_response,
      act->GenerateTokensResponse(tokens_request, scheme_parameters,
                                  client_parameters.public_parameters(),
                                  server_parameters.public_parameters(),
                                  server_parameters.private_parameters()));
  RETURN_IF_ERROR(act->VerifyTokensResponse(
      messages, tokens_request, tokens_request_private_state, tokens_response,
      scheme_parameters, client_parameters.public_parameters(),
      client_parameters.private_parameters(),
      server_parameters.public_parameters()));

  // Extract Tokens.
  ASSIGN_OR_RETURN(
      std::vector<Token> tokens,
      act->RecoverTokens(messages, tokens_request, tokens_request_private_state,
                         tokens_response, scheme_parameters,
                         client_parameters.public_parameters(),
                         client_parameters.private_parameters(),
                         server_parameters.public_parameters()));

  // Verify Tokens.
  if (tokens.size() != num_messages) {
    return absl::InvalidArgumentError("Wrong number of tokens produced");
  }
  for (int i = 0; i < num_messages; ++i) {
    RETURN_IF_ERROR(act->VerifyToken(messages[i], tokens[i], scheme_parameters,
                                     server_parameters.public_parameters(),
                                     server_parameters.private_parameters()));
  }
  return absl::OkStatus();
}

TEST(ActV0ParametersTest, EndToEndWithTestParameters) {
  EXPECT_OK(EndToEndTest(ActV0TestSchemeParameters(), 3));
}

TEST(ActV0ParametersTest, EndToEndWithBatch16Parameters) {
  EXPECT_OK(EndToEndTest(ActV0Batch16SchemeParameters(), 16));
}

TEST(ActV0ParametersTest, EndToEndWithBatch32Parameters) {
  EXPECT_OK(EndToEndTest(ActV0Batch32SchemeParameters(), 32));
}

TEST(ActV0ParametersTest, EndToEndWithBatch32Cs2Modulus2048Parameters) {
  EXPECT_OK(EndToEndTest(
      ActV0SchemeParametersPedersen32Modulus2048CamenischShoupVector2(), 32));
}

TEST(ActV0ParametersTest, EndToEndWithCustomParameters) {
  int pedersen_batch_size = 32;
  int modulus_length_bits = 1576;
  int camenisch_shoup_vector_length = 2;
  EXPECT_OK(EndToEndTest(
      ActV0SchemeParameters(pedersen_batch_size, modulus_length_bits,
                            camenisch_shoup_vector_length),
      32));
}

// More extensive tests are in act_v0_test.cc. These tests simply ensure that
// the parameters are functional.

}  // namespace
}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute
