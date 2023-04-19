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

#ifndef PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_V0_ACT_V0_H_
#define PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_V0_ACT_V0_H_

#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "act/act.h"
#include "act/act.pb.h"
#include "private_join_and_compute/util/status.inc"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {

// An implementation of vO Anonymous Counting Tokens.
class AnonymousCountingTokensV0 : public AnonymousCountingTokens {
 public:
  static std::unique_ptr<AnonymousCountingTokens> Create();

  // Returns a fresh set of Server parameters corresponding to these
  // SchemeParameters. Fails with InvalidArgument if the parameters don't
  // correspond to ACT v0.
  StatusOr<ServerParameters> GenerateServerParameters(
      const SchemeParameters& scheme_parameters) override;

  // Returns a fresh set of Client parameters corresponding to these
  // SchemeParameters and ServerPublicParameters. Fails with InvalidArgument if
  // the parameters don't correspond to ACT v0.
  StatusOr<ClientParameters> GenerateClientParameters(
      const SchemeParameters& scheme_parameters,
      const ServerPublicParameters& server_public_parameters) override;

  // Verifies the consistency of the  ClientPublicParameters with the Server and
  // scheme parameters. Fails with InvalidArgument if the parameters don't
  // correspond to ACT v0.
  Status CheckClientParameters(
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) override;

  // Returns a tuple of client_fingerprints, TokensRequest and
  // TokensRequestPrivateState for the given set of messages. Fails with
  // InvalidArgument if the parameters don't correspond to ACT v0.
  StatusOr<std::tuple<std::vector<std::string>, TokensRequest,
                      TokensRequestPrivateState>>
  GenerateTokensRequest(
      absl::Span<const std::string> messages,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) override;

  // Returns OkStatus on a valid request. Fails with InvalidArgument if the
  // parameters don't correspond to ACT v0.
  Status CheckTokensRequest(
      absl::Span<const std::string> client_fingerprints,
      const TokensRequest& tokens_request,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) override;

  // Returns the TokensResponse. Fails with InvalidArgument if the parameters
  // don't correspond to ACT v0.
  StatusOr<TokensResponse> GenerateTokensResponse(
      const TokensRequest& tokens_request,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) override;

  // Returns OkStatus on a valid response. Fails with InvalidArgument if the
  // parameters don't correspond to ACT v0.
  Status VerifyTokensResponse(
      absl::Span<const std::string> messages,
      const TokensRequest& tokens_request,
      const TokensRequestPrivateState& tokens_request_private_state,
      const TokensResponse& tokens_response,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) override;

  // Returns a vector of tokens corresponding to the supplied messages. Fails
  // with InvalidArgument if the parameters don't correspond to ACT v0.
  StatusOr<std::vector<Token>> RecoverTokens(
      absl::Span<const std::string> messages,
      const TokensRequest& tokens_request,
      const TokensRequestPrivateState& tokens_request_private_state,
      const TokensResponse& tokens_response,
      const SchemeParameters& scheme_parameters,
      const ClientPublicParameters& client_public_parameters,
      const ClientPrivateParameters& client_private_parameters,
      const ServerPublicParameters& server_public_parameters) override;

  // Returns OkStatus on valid tokens. Fails with InvalidArgument if the
  // parameters don't correspond to ACT v0.
  Status VerifyToken(
      std::string m, const Token& token,
      const SchemeParameters& scheme_parameters,
      const ServerPublicParameters& server_public_parameters,
      const ServerPrivateParameters& server_private_parameters) override;

 protected:
  AnonymousCountingTokensV0() = default;
};

}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_V0_ACT_V0_H_
