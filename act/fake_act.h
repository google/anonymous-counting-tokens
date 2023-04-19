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

#ifndef PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_FAKE_ACT_H_
#define PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_FAKE_ACT_H_

#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "act/act.h"
#include "act/act.pb.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {

// A fake, insecure implementation of Anonymous Counting Tokens for
// testing/stubbing purposes only. This should NOT be used in production: it
// doesn't have any of the desired security properties.
class FakeAnonymousCountingTokens : public AnonymousCountingTokens {
 public:
  static const size_t kFakeTokenNonceLengthBits = 256;

  // Returns an instance of FakeAnonymousCountingTokens.
  static std::unique_ptr<AnonymousCountingTokens> Create();

  ~FakeAnonymousCountingTokens() override = default;

  // Returns empty Server parameters.
  StatusOr<ServerParameters> GenerateServerParameters(
      const SchemeParameters& scheme_parameters) override;

  // Returns empty Client parameters.
  StatusOr<ClientParameters> GenerateClientParameters(
      const SchemeParameters& scheme_parameters,
      const ServerPublicParameters& server_public_parameters) override;

  // Always returns "Ok".
  Status CheckClientParameters(
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) override;

  // For this fake implementation, the client fingerprints are the same as the
  // messages (this is insecure).
  StatusOr<std::tuple<std::vector<std::string>, TokensRequest,
                      TokensRequestPrivateState>>
  GenerateTokensRequest(
      absl::Span<const std::string> messages,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) override;

  // Always returns "Ok".
  Status CheckTokensRequest(
      absl::Span<const std::string> client_fingerprints,
      const TokensRequest& tokens_request,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) override;

  // Returns an empty TokensResponse.
  StatusOr<TokensResponse> GenerateTokensResponse(
      const TokensRequest& tokens_request,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) override;

  // Always returns "Ok".
  Status VerifyTokensResponse(
      absl::Span<const std::string> messages,
      const TokensRequest& tokens_request,
      const TokensRequestPrivateState& tokens_request_private_state,
      const TokensResponse& tokens_response,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) override;

  // Returns a set of tokens containing randomly generated "nonce"  values, and
  // all other fields empty.
  StatusOr<std::vector<Token>> RecoverTokens(
      absl::Span<const std::string> messages,
      const TokensRequest& tokens_request,
      const TokensRequestPrivateState& tokens_request_private_state,
      const TokensResponse& tokens_response,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) override;

  // Always returns "Ok".
  Status VerifyToken(
      std::string m, const Token& token,
      const SchemeParameters& scheme_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) override;

 protected:
  FakeAnonymousCountingTokens() = default;
};

}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_FAKE_ACT_H_
