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

#ifndef PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_H_
#define PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_H_

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "act/act.pb.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {

// Abstract class for methods related to Anonymous Counting Tokens.
class AnonymousCountingTokens {
 public:
  virtual ~AnonymousCountingTokens() = default;

  // Implementations should return a fresh set of Server parameters
  // corresponding to these SchemeParameters.
  virtual StatusOr<ServerParameters> GenerateServerParameters(
      const SchemeParameters& scheme_parameters) = 0;

  // Implementations should return a fresh set of Client parameters
  // corresponding to these SchemeParameters and ServerPublicParameters.
  virtual StatusOr<ClientParameters> GenerateClientParameters(
      const SchemeParameters& scheme_parameters,
      const ServerPublicParameters& server_public_parameters) = 0;

  // Implementations should verify the consistency of these
  // ClientPublicParameters with the Server and scheme parameters.
  virtual Status CheckClientParameters(
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) = 0;

  // Implementations should generate a tuple of client_fingerprints,
  // TokensRequest and TokensRequestPrivateState for the given set of messages.
  virtual StatusOr<std::tuple<std::vector<std::string>, TokensRequest,
                              TokensRequestPrivateState>>
  GenerateTokensRequest(
      absl::Span<const std::string> messages,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) = 0;

  // Implementations should return OkStatus on a valid request.
  virtual Status CheckTokensRequest(
      absl::Span<const std::string> client_fingerprints,
      const TokensRequest& tokens_request,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) = 0;

  // Implementations should return the TokensResponse.
  virtual StatusOr<TokensResponse> GenerateTokensResponse(
      const TokensRequest& tokens_request,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) = 0;

  // Implementations should return OkStatus on a valid response.
  virtual Status VerifyTokensResponse(
      absl::Span<const std::string> messages,
      const TokensRequest& tokens_request,
      const TokensRequestPrivateState& tokens_request_private_state,
      const TokensResponse& tokens_response,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) = 0;

  // Implementations should return a vector of tokens corresponding to the
  // supplied messages.
  virtual StatusOr<std::vector<Token>> RecoverTokens(
      absl::Span<const std::string> messages,
      const TokensRequest& tokens_request,
      const TokensRequestPrivateState& tokens_request_private_state,
      const TokensResponse& tokens_response,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) = 0;

  // Implementations should return OkStatus on valid tokens.
  virtual Status VerifyToken(
      std::string m, const Token& token,
      const SchemeParameters& scheme_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) = 0;

 protected:
  AnonymousCountingTokens() = default;
};

}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_H_
