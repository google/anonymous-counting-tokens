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

#include <cstddef>
#include <string>
#include <tuple>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "act/act.h"
#include "act/act.pb.h"
#include "act/act_v0/act_v0.h"
#include "act/act_v0/act_v0.pb.h"
#include "act/act_v0/parameters.h"
#include "act/act_v0/testing/transcript.pb.h"
#include "private_join_and_compute/util/proto_util.h"
#include "private_join_and_compute/util/status.inc"

ABSL_FLAG(std::string, transcript_path, "",
          "Prefix of file to which the generated transcript will be "
          "written/read from.");

ABSL_FLAG(bool, verify, false,
          "If true, will attempt to read the transcript from the specified "
          "path to verify it.");

namespace private_join_and_compute {
namespace anonymous_counting_tokens {
namespace {

absl::Status GenerateTranscript(absl::string_view transcript_path) {
  SchemeParameters scheme_parameters =
      private_join_and_compute::anonymous_counting_tokens::
          ActV0SchemeParametersPedersen32Modulus2048CamenischShoupVector2();
  auto act = AnonymousCountingTokensV0::Create();

  ASSIGN_OR_RETURN(ServerParameters server_parameters,
                   act->GenerateServerParameters(scheme_parameters));
  ASSIGN_OR_RETURN(
      ClientParameters client_parameters,
      act->GenerateClientParameters(scheme_parameters,
                                    server_parameters.public_parameters()));
  std::vector<std::string> messages;
  size_t num_messages =
      scheme_parameters.scheme_parameters_v0().pedersen_batch_size();
  messages.reserve(num_messages);
  for (int i = 0; i < num_messages; ++i) {
    messages.push_back(absl::StrCat("message", i));
  }
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

  ASSIGN_OR_RETURN(
      TokensResponse tokens_response,
      act->GenerateTokensResponse(tokens_request, scheme_parameters,
                                  client_parameters.public_parameters(),
                                  server_parameters.public_parameters(),
                                  server_parameters.private_parameters()));

  ASSIGN_OR_RETURN(
      std::vector<Token> tokens,
      act->RecoverTokens(messages, tokens_request, tokens_request_private_state,
                         tokens_response, scheme_parameters,
                         client_parameters.public_parameters(),
                         client_parameters.private_parameters(),
                         server_parameters.public_parameters()));

  Transcript transcript;
  *transcript.mutable_scheme_parameters() = scheme_parameters;
  *transcript.mutable_server_parameters() = server_parameters;
  *transcript.mutable_client_parameters() = client_parameters;
  *transcript.mutable_messages() = {messages.begin(), messages.end()};
  *transcript.mutable_fingerprints() = {client_fingerprints.begin(),
                                        client_fingerprints.end()};
  *transcript.mutable_tokens_request() = tokens_request;
  *transcript.mutable_tokens_request_private_state() =
      tokens_request_private_state;
  *transcript.mutable_tokens_response() = tokens_response;
  *transcript.mutable_tokens() = {tokens.begin(), tokens.end()};

  return ProtoUtils::WriteProtoToFile(transcript, transcript_path);
}

absl::Status VerifyTranscript(absl::string_view transcript_path) {
  ASSIGN_OR_RETURN(Transcript transcript,
                   ProtoUtils::ReadProtoFromFile<Transcript>(transcript_path));

  auto act = AnonymousCountingTokensV0::Create();

  if (!transcript.has_scheme_parameters() ||
      !transcript.scheme_parameters().has_scheme_parameters_v0() ||
      transcript.scheme_parameters()
              .scheme_parameters_v0()
              .pedersen_batch_size() <= 0) {
    return InvalidArgumentError(
        "VerifyTranscript: transcript should have a SchemeParametersV0 with a "
        "positive pedersen_batch_size.");
  }

  RETURN_IF_ERROR(act->CheckClientParameters(
      transcript.scheme_parameters(),
      transcript.client_parameters().public_parameters(),
      transcript.server_parameters().public_parameters(),
      transcript.server_parameters().private_parameters()));

  std::vector<std::string> client_fingerprints(
      transcript.fingerprints().begin(), transcript.fingerprints().end());
  RETURN_IF_ERROR(act->CheckTokensRequest(
      client_fingerprints, transcript.tokens_request(),
      transcript.scheme_parameters(),
      transcript.client_parameters().public_parameters(),
      transcript.server_parameters().public_parameters(),
      transcript.server_parameters().private_parameters()));

  std::vector<std::string> messages(transcript.messages().begin(),
                                    transcript.messages().end());
  RETURN_IF_ERROR(act->VerifyTokensResponse(
      messages, transcript.tokens_request(),
      transcript.tokens_request_private_state(), transcript.tokens_response(),
      transcript.scheme_parameters(),
      transcript.client_parameters().public_parameters(),
      transcript.client_parameters().private_parameters(),
      transcript.server_parameters().public_parameters()));

  return OkStatus();
}

}  // namespace
}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  std::string transcript_path = absl::GetFlag(FLAGS_transcript_path);

  bool verify = absl::GetFlag(FLAGS_verify);
  if (verify) {
    CHECK_OK(
        private_join_and_compute::anonymous_counting_tokens::VerifyTranscript(
            transcript_path));
    LOG(INFO) << "Successfully verified transcript.";
  } else {
    CHECK_OK(
        private_join_and_compute::anonymous_counting_tokens::GenerateTranscript(
            transcript_path));
    LOG(INFO) << "Successfully generated transcript.";
  }

  return 0;
}
