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

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "act/act.pb.h"
#include "private_join_and_compute/crypto/context.h"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {

// Returns an instance of FakeAnonymousCountingTokens.
std::unique_ptr<AnonymousCountingTokens> FakeAnonymousCountingTokens::Create() {
  return absl::WrapUnique<FakeAnonymousCountingTokens>(
      new FakeAnonymousCountingTokens());
}

// Returns empty Server parameters.
StatusOr<ServerParameters>
FakeAnonymousCountingTokens::GenerateServerParameters(
    const SchemeParameters& scheme_parameters) {
  return ServerParameters::default_instance();
}

// Returns empty Client parameters.
StatusOr<ClientParameters>
FakeAnonymousCountingTokens::GenerateClientParameters(
    const SchemeParameters& scheme_parameters,
    const ServerPublicParameters& server_public_parameters) {
  return ClientParameters::default_instance();
}

// Always returns "Ok".
Status FakeAnonymousCountingTokens::CheckClientParameters(
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ServerPrivateParameters& server_private_parameters) {
  return absl::OkStatus();
}

// For this fake implementation, the client fingerprints are the same as the
// messages (this is insecure).
StatusOr<std::tuple<std::vector<std::string>, TokensRequest,
                    TokensRequestPrivateState>>
FakeAnonymousCountingTokens::GenerateTokensRequest(
    absl::Span<const std::string> messages,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ClientPrivateParameters& client_private_parameters,
    const ServerPublicParameters& server_public_parameters) {
  return std::make_tuple(
      std::vector<std::string>(messages.begin(), messages.end()),
      TokensRequest::default_instance(),
      TokensRequestPrivateState::default_instance());
}

// Always returns "Ok".
Status FakeAnonymousCountingTokens::CheckTokensRequest(
    absl::Span<const std::string> client_fingerprints,
    const TokensRequest& tokens_request,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ServerPrivateParameters& server_private_parameters) {
  return absl::OkStatus();
}

// Returns an empty TokensResponse.
StatusOr<TokensResponse> FakeAnonymousCountingTokens::GenerateTokensResponse(
    const TokensRequest& tokens_request,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ServerPrivateParameters& server_private_parameters) {
  return TokensResponse::default_instance();
}

// Always returns "Ok".
Status FakeAnonymousCountingTokens::VerifyTokensResponse(
    absl::Span<const std::string> messages, const TokensRequest& tokens_request,
    const TokensRequestPrivateState& tokens_request_private_state,
    const TokensResponse& tokens_response,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ClientPrivateParameters& client_private_parameters,
    const ServerPublicParameters& server_public_parameters) {
  return absl::OkStatus();
}

// Returns a set of tokens containing randomly generated "nonce"  values, and
// all other fields empty.
StatusOr<std::vector<Token>> FakeAnonymousCountingTokens::RecoverTokens(
    absl::Span<const std::string> messages, const TokensRequest& tokens_request,
    const TokensRequestPrivateState& tokens_request_private_state,
    const TokensResponse& tokens_response,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ClientPrivateParameters& client_private_parameters,
    const ServerPublicParameters& server_public_parameters) {
  Context context;
  BigNum nonce_bound = context.One().Lshift(kFakeTokenNonceLengthBits);

  std::vector<Token> result;
  result.reserve(messages.size());
  for (size_t i = 0; i < messages.size(); ++i) {
    Token fake_token;
    fake_token.set_nonce_bytes(
        context.GenerateRandLessThan(nonce_bound).ToBytes());
    result.push_back(fake_token);
  }

  return std::move(result);
}

// Always returns "Ok".
Status FakeAnonymousCountingTokens::VerifyToken(
    std::string m, const Token& token,
    const SchemeParameters& scheme_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ServerPrivateParameters& server_private_parameters) {
  return absl::OkStatus();
}

}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute
