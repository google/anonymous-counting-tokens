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

#include "act/act_v0/act_v0.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "act/act.h"
#include "act/act.pb.h"
#include "act/act_v0/act_v0.pb.h"
#include "act/act_v0/parameters.h"
#include "private_join_and_compute/crypto/camenisch_shoup.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/bb_oblivious_signature.pb.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/dy_verifiable_random_function.pb.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/pedersen_over_zn.h"
#include "private_join_and_compute/crypto/proto/big_num.pb.h"
#include "private_join_and_compute/crypto/proto/camenisch_shoup.pb.h"
#include "private_join_and_compute/crypto/proto/pedersen.pb.h"
#include "private_join_and_compute/util/status.inc"
#include "private_join_and_compute/util/status_testing.inc"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {
namespace {

using ::testing::HasSubstr;
using testing::StatusIs;

const int kTestCurveId = NID_X9_62_prime256v1;

class AnonymousCountingTokensV0Test : public ::testing::Test {
 protected:
  static std::string GetRandomOraclePrefix() {
    return "TestRandomOraclePrefix";
  }

  static SchemeParameters GetSchemeParameters() {
    return ActV0TestSchemeParameters();
  }

  static void SetUpTestSuite() {
    std::unique_ptr<AnonymousCountingTokens> act =
        AnonymousCountingTokensV0::Create();
    ServerParameters server_parameters_temp =
        act->GenerateServerParameters(GetSchemeParameters()).value();
    server_parameters_ = new ServerParameters(server_parameters_temp);
  }

  static void TearDownTestSuite() { delete server_parameters_; }

  void SetUp() override {
    anonymous_counting_tokens_ = AnonymousCountingTokensV0::Create();

    ASSERT_OK_AND_ASSIGN(auto ec_group_do_not_use_later,
                         ECGroup::Create(kTestCurveId, &ctx_));
    ec_group_ = std::make_unique<ECGroup>(std::move(ec_group_do_not_use_later));

    // Deserialize components of the precomputed server parameters.
    ASSERT_OK_AND_ASSIGN(PedersenOverZn::Parameters pedersen_parameters,
                         PedersenOverZn::ParseParametersProto(
                             &ctx_, server_parameters_->public_parameters()
                                        .server_public_parameters_v0()
                                        .pedersen_parameters()));
    ASSERT_OK_AND_ASSIGN(
        pedersen_,
        PedersenOverZn::Create(&ctx_, pedersen_parameters.gs,
                               pedersen_parameters.h, pedersen_parameters.n));

    dy_prf_base_g_ = std::make_unique<ECPoint>(
        ec_group_
            ->CreateECPoint(server_parameters_->public_parameters()
                                .server_public_parameters_v0()
                                .prf_base_g())
            .value());

    cs_public_key_ = std::make_unique<CamenischShoupPublicKey>(
        ParseCamenischShoupPublicKeyProto(
            &ctx_, server_parameters_->public_parameters()
                       .server_public_parameters_v0()
                       .camenisch_shoup_public_key())
            .value());
    cs_private_key_ = std::make_unique<CamenischShoupPrivateKey>(
        ParseCamenischShoupPrivateKeyProto(
            &ctx_, server_parameters_->private_parameters()
                       .server_private_parameters_v0()
                       .camenisch_shoup_private_key())
            .value());

    public_camenisch_shoup_ = std::make_unique<PublicCamenischShoup>(
        &ctx_, cs_public_key_->n, cs_public_key_->s, cs_public_key_->g,
        cs_public_key_->ys);
    private_camenisch_shoup_ = std::make_unique<PrivateCamenischShoup>(
        &ctx_, cs_public_key_->n, cs_public_key_->s, cs_public_key_->g,
        cs_public_key_->ys, cs_private_key_->xs);

    ASSERT_OK_AND_ASSIGN(
        client_parameters_,
        anonymous_counting_tokens_->GenerateClientParameters(
            GetSchemeParameters(), server_parameters_->public_parameters()));
  }

  // Holds a transcript for an EndToEnd request.
  struct Transcript {
    std::vector<std::string> fingerprints;
    TokensRequest tokens_request;
    TokensRequestPrivateState tokens_request_private_state;
    TokensResponse tokens_response;
    std::vector<Token> tokens;
  };

  // Generates an end-to-end request transcript. Does not verify request or
  // response proofs.
  StatusOr<Transcript> GenerateTranscript(
      absl::Span<const std::string> messages) {
    Transcript transcript;
    ASSIGN_OR_RETURN(
        std::tie(transcript.fingerprints, transcript.tokens_request,
                 transcript.tokens_request_private_state),
        anonymous_counting_tokens_->GenerateTokensRequest(
            messages, GetSchemeParameters(),
            client_parameters_.public_parameters(),
            client_parameters_.private_parameters(),
            server_parameters_->public_parameters()));

    ASSIGN_OR_RETURN(transcript.tokens_response,
                     anonymous_counting_tokens_->GenerateTokensResponse(
                         transcript.tokens_request, GetSchemeParameters(),
                         client_parameters_.public_parameters(),
                         server_parameters_->public_parameters(),
                         server_parameters_->private_parameters()));

    ASSIGN_OR_RETURN(
        transcript.tokens,
        anonymous_counting_tokens_->RecoverTokens(
            messages, transcript.tokens_request,
            transcript.tokens_request_private_state, transcript.tokens_response,
            GetSchemeParameters(), client_parameters_.public_parameters(),
            client_parameters_.private_parameters(),
            server_parameters_->public_parameters()));

    return std::move(transcript);
  }

  // Server Parameters, generated once and available to be reused across tests
  // to save expensive safe modulus computation.
  static ServerParameters* server_parameters_;

  // Instance of AnonymousCountingTokensV0.
  std::unique_ptr<AnonymousCountingTokens> anonymous_counting_tokens_;

  Context ctx_;
  std::unique_ptr<ECGroup> ec_group_;

  // Deserialized objects from the saved serialized parameters above.
  std::unique_ptr<PedersenOverZn> pedersen_;
  std::unique_ptr<ECPoint> dy_prf_base_g_;
  std::unique_ptr<CamenischShoupPublicKey> cs_public_key_;
  std::unique_ptr<CamenischShoupPrivateKey> cs_private_key_;
  std::unique_ptr<PublicCamenischShoup> public_camenisch_shoup_;
  std::unique_ptr<PrivateCamenischShoup> private_camenisch_shoup_;

  // Client parameters for AnonymousCountingTokensV0.
  ClientParameters client_parameters_;
};

ServerParameters* AnonymousCountingTokensV0Test::server_parameters_ = nullptr;

TEST_F(AnonymousCountingTokensV0Test, ServerParametersHasNonEmptyFields) {
  // Expect all fields are nonempty.
  EXPECT_TRUE(server_parameters_->has_public_parameters());
  EXPECT_TRUE(server_parameters_->public_parameters()
                  .has_server_public_parameters_v0());
  EXPECT_FALSE(server_parameters_->public_parameters()
                   .server_public_parameters_v0()
                   .prf_base_g()
                   .empty());
  EXPECT_TRUE(server_parameters_->public_parameters()
                  .server_public_parameters_v0()
                  .has_pedersen_parameters());
  EXPECT_TRUE(server_parameters_->public_parameters()
                  .server_public_parameters_v0()
                  .has_camenisch_shoup_public_key());
  EXPECT_TRUE(server_parameters_->public_parameters()
                  .server_public_parameters_v0()
                  .has_bb_oblivious_signature_public_key());

  EXPECT_TRUE(server_parameters_->has_private_parameters());
  EXPECT_TRUE(server_parameters_->private_parameters()
                  .has_server_private_parameters_v0());
  EXPECT_TRUE(server_parameters_->private_parameters()
                  .server_private_parameters_v0()
                  .has_camenisch_shoup_private_key());
  EXPECT_TRUE(server_parameters_->private_parameters()
                  .server_private_parameters_v0()
                  .has_bb_oblivious_signature_private_key());
}

TEST_F(AnonymousCountingTokensV0Test, GeneratesDifferentServerParameters) {
  ASSERT_OK_AND_ASSIGN(ServerParameters other_server_parameters,
                       anonymous_counting_tokens_->GenerateServerParameters(
                           GetSchemeParameters()));

  // Expect all fields in the public parameters are different across the 2
  // keys.
  EXPECT_NE(server_parameters_->public_parameters()
                .server_public_parameters_v0()
                .prf_base_g(),
            other_server_parameters.public_parameters()
                .server_public_parameters_v0()
                .prf_base_g());
  EXPECT_NE(server_parameters_->public_parameters()
                .server_public_parameters_v0()
                .pedersen_parameters()
                .gs()
                .serialized_big_nums(0),
            other_server_parameters.public_parameters()
                .server_public_parameters_v0()
                .pedersen_parameters()
                .gs()
                .serialized_big_nums(0));
  EXPECT_NE(server_parameters_->public_parameters()
                .server_public_parameters_v0()
                .camenisch_shoup_public_key()
                .ys()
                .serialized_big_nums(0),
            other_server_parameters.public_parameters()
                .server_public_parameters_v0()
                .camenisch_shoup_public_key()
                .ys()
                .serialized_big_nums(0));
  EXPECT_NE(server_parameters_->public_parameters()
                .server_public_parameters_v0()
                .bb_oblivious_signature_public_key()
                .encrypted_k(0)
                .u(),
            other_server_parameters.public_parameters()
                .server_public_parameters_v0()
                .bb_oblivious_signature_public_key()
                .encrypted_k(0)
                .u());
  EXPECT_NE(server_parameters_->public_parameters()
                .server_public_parameters_v0()
                .bb_oblivious_signature_public_key()
                .encrypted_y(0)
                .u(),
            other_server_parameters.public_parameters()
                .server_public_parameters_v0()
                .bb_oblivious_signature_public_key()
                .encrypted_y(0)
                .u());
}

TEST_F(AnonymousCountingTokensV0Test, ClientParametersHaveValidFields) {
  EXPECT_TRUE(client_parameters_.has_public_parameters());
  EXPECT_TRUE(
      client_parameters_.public_parameters().has_client_public_parameters_v0());
  EXPECT_TRUE(client_parameters_.public_parameters()
                  .client_public_parameters_v0()
                  .has_dy_vrf_public_key());

  EXPECT_TRUE(client_parameters_.has_private_parameters());
  EXPECT_TRUE(client_parameters_.private_parameters()
                  .has_client_private_parameters_v0());
  EXPECT_TRUE(client_parameters_.private_parameters()
                  .client_private_parameters_v0()
                  .has_dy_vrf_private_key());
}

TEST_F(AnonymousCountingTokensV0Test, GeneratesDifferentClientParameters) {
  ASSERT_OK_AND_ASSIGN(
      ClientParameters other_client_parameters,
      anonymous_counting_tokens_->GenerateClientParameters(
          GetSchemeParameters(), server_parameters_->public_parameters()));

  EXPECT_NE(client_parameters_.public_parameters()
                .client_public_parameters_v0()
                .dy_vrf_public_key()
                .commit_prf_key(),
            other_client_parameters.public_parameters()
                .client_public_parameters_v0()
                .dy_vrf_public_key()
                .commit_prf_key());
}

TEST_F(AnonymousCountingTokensV0Test, ProofFromOtherClientParametersFails) {
  ASSERT_OK_AND_ASSIGN(
      ClientParameters other_client_parameters,
      anonymous_counting_tokens_->GenerateClientParameters(
          GetSchemeParameters(), server_parameters_->public_parameters()));

  *client_parameters_.mutable_public_parameters()
       ->mutable_client_public_parameters_v0()
       ->mutable_dy_vrf_generate_keys_proof() =
      other_client_parameters.public_parameters()
          .client_public_parameters_v0()
          .dy_vrf_generate_keys_proof();

  EXPECT_THAT(
      anonymous_counting_tokens_->CheckClientParameters(
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(AnonymousCountingTokensV0Test, ClientParametersPassCheck) {
  EXPECT_OK(anonymous_counting_tokens_->CheckClientParameters(
      GetSchemeParameters(), client_parameters_.public_parameters(),
      server_parameters_->public_parameters(),
      server_parameters_->private_parameters()));
}

TEST_F(AnonymousCountingTokensV0Test, ClientParametersWithoutActV0FailCheck) {
  client_parameters_.mutable_public_parameters()
      ->clear_client_public_parameters_v0();

  EXPECT_THAT(anonymous_counting_tokens_->CheckClientParameters(
                  GetSchemeParameters(), client_parameters_.public_parameters(),
                  server_parameters_->public_parameters(),
                  server_parameters_->private_parameters()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("CheckClientParameters")));
}

TEST_F(AnonymousCountingTokensV0Test, EmptyClientParametersProofFailsCheck) {
  client_parameters_.mutable_public_parameters()
      ->mutable_client_public_parameters_v0()
      ->clear_dy_vrf_generate_keys_proof();

  EXPECT_THAT(
      anonymous_counting_tokens_->CheckClientParameters(
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(AnonymousCountingTokensV0Test, GeneratesTokenRequest) {
  EXPECT_OK(anonymous_counting_tokens_->GenerateTokensRequest(
      {"message_0", "message_1", "message_2"}, GetSchemeParameters(),
      client_parameters_.public_parameters(),
      client_parameters_.private_parameters(),
      server_parameters_->public_parameters()));
}

TEST_F(AnonymousCountingTokensV0Test, FingerprintsMatchOnlyForEqualMessages) {
  std::vector<std::string> fingerprints_1;
  ASSERT_OK_AND_ASSIGN(
      std::tie(fingerprints_1, std::ignore, std::ignore),
      anonymous_counting_tokens_->GenerateTokensRequest(
          {"message_0", "message_1", "message_2"}, GetSchemeParameters(),
          client_parameters_.public_parameters(),
          client_parameters_.private_parameters(),
          server_parameters_->public_parameters()));

  std::vector<std::string> fingerprints_2;
  ASSERT_OK_AND_ASSIGN(
      std::tie(fingerprints_2, std::ignore, std::ignore),
      anonymous_counting_tokens_->GenerateTokensRequest(
          {"message_2", "message_3", "message_4"}, GetSchemeParameters(),
          client_parameters_.public_parameters(),
          client_parameters_.private_parameters(),
          server_parameters_->public_parameters()));

  // Fingerprints should be equal only for "message_2".
  EXPECT_EQ(fingerprints_1[2], fingerprints_2[0]);

  for (size_t i = 1; i < fingerprints_1.size(); ++i) {
    for (size_t j = 0; j < fingerprints_2.size(); ++j) {
      if (!(i == 2 && j == 0)) {
        EXPECT_NE(fingerprints_1[i], fingerprints_2[j]);
      }
    }
  }
}

TEST_F(AnonymousCountingTokensV0Test, TokensRequestIsValid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  EXPECT_OK(anonymous_counting_tokens_->CheckTokensRequest(
      transcript.fingerprints, transcript.tokens_request, GetSchemeParameters(),
      client_parameters_.public_parameters(),
      server_parameters_->public_parameters(),
      server_parameters_->private_parameters()));
}

TEST_F(AnonymousCountingTokensV0Test,
       TokensRequestProofFailsWithDifferentFingerprints) {
  std::vector<std::string> messages_1 = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages_1));
  std::vector<std::string> messages_2 = {"message_4", "message_5", "message_6"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages_2));
  // fingerprints from the second transcript should not allow the proof to
  // verify.
  EXPECT_THAT(
      anonymous_counting_tokens_->CheckTokensRequest(
          transcript_2.fingerprints, transcript_1.tokens_request,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("failed")));
}

TEST_F(AnonymousCountingTokensV0Test,
       TokensRequestProofFailsWithWrongNumberOfFingerprints) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  // delete one of the fingerprints.
  transcript.fingerprints.pop_back();
  EXPECT_THAT(
      anonymous_counting_tokens_->CheckTokensRequest(
          transcript.fingerprints, transcript.tokens_request,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Number")));
}

TEST_F(AnonymousCountingTokensV0Test,
       BbSignatureRequestFromDifferentTranscriptIsInvalid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));
  // Replace the bb oblivious signature request from the first transcript with
  // that from the second.
  *transcript_1.tokens_request.mutable_tokens_request_v0()
       ->mutable_bb_oblivious_signature_request() =
      transcript_2.tokens_request.tokens_request_v0()
          .bb_oblivious_signature_request();
  EXPECT_THAT(
      anonymous_counting_tokens_->CheckTokensRequest(
          transcript_1.fingerprints, transcript_1.tokens_request,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(AnonymousCountingTokensV0Test,
       FingerprintsProofFromDifferentTranscriptIsInvalid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));
  // Replace the fingerprints proof from the first transcript with
  // that from the second.
  *transcript_1.tokens_request.mutable_tokens_request_v0()
       ->mutable_part_1()
       ->mutable_fingerprints_proof() =
      transcript_2.tokens_request.tokens_request_v0()
          .part_1()
          .fingerprints_proof();
  EXPECT_THAT(
      anonymous_counting_tokens_->CheckTokensRequest(
          transcript_1.fingerprints, transcript_1.tokens_request,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("failed")));
}

TEST_F(AnonymousCountingTokensV0Test,
       BbSignatureRequestProofFromDifferentTranscriptIsInvalid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));
  // Replace the bb signature request proof from the first transcript with
  // that from the second.
  *transcript_1.tokens_request.mutable_tokens_request_v0()
       ->mutable_bb_oblivious_signature_request_proof() =
      transcript_2.tokens_request.tokens_request_v0()
          .bb_oblivious_signature_request_proof();
  EXPECT_THAT(
      anonymous_counting_tokens_->CheckTokensRequest(
          transcript_1.fingerprints, transcript_1.tokens_request,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(AnonymousCountingTokensV0Test, EmptyRequestIsInvalid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  transcript.tokens_request.clear_tokens_request_v0();
  EXPECT_THAT(anonymous_counting_tokens_->CheckTokensRequest(
                  transcript.fingerprints, transcript.tokens_request,
                  GetSchemeParameters(), client_parameters_.public_parameters(),
                  server_parameters_->public_parameters(),
                  server_parameters_->private_parameters()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("supplied parameters")));
}

TEST_F(AnonymousCountingTokensV0Test,
       RequestWithoutFingerprintsProofIsInvalid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  transcript.tokens_request.mutable_tokens_request_v0()
      ->mutable_part_1()
      ->clear_fingerprints_proof();
  EXPECT_THAT(
      anonymous_counting_tokens_->CheckTokensRequest(
          transcript.fingerprints, transcript.tokens_request,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Number")));
}

TEST_F(AnonymousCountingTokensV0Test,
       RequestWithoutBbSignatureRequestProofIsInvalid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  transcript.tokens_request.mutable_tokens_request_v0()
      ->clear_bb_oblivious_signature_request_proof();
  EXPECT_THAT(
      anonymous_counting_tokens_->CheckTokensRequest(
          transcript.fingerprints, transcript.tokens_request,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          server_parameters_->public_parameters(),
          server_parameters_->private_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("number")));
}

TEST_F(AnonymousCountingTokensV0Test, GeneratesTokenResponse) {
  TokensRequest tokens_request;
  ASSERT_OK_AND_ASSIGN(
      std::tie(std::ignore, tokens_request, std::ignore),
      anonymous_counting_tokens_->GenerateTokensRequest(
          {"message_0", "message_1", "message_2"}, GetSchemeParameters(),
          client_parameters_.public_parameters(),
          client_parameters_.private_parameters(),
          server_parameters_->public_parameters()));

  EXPECT_OK(anonymous_counting_tokens_->GenerateTokensResponse(
      tokens_request, GetSchemeParameters(),
      client_parameters_.public_parameters(),
      server_parameters_->public_parameters(),
      server_parameters_->private_parameters()));
}

TEST_F(AnonymousCountingTokensV0Test, TokensResponseIsValid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));
  EXPECT_OK(anonymous_counting_tokens_->VerifyTokensResponse(
      messages, transcript.tokens_request,
      transcript.tokens_request_private_state, transcript.tokens_response,
      GetSchemeParameters(), client_parameters_.public_parameters(),
      client_parameters_.private_parameters(),
      server_parameters_->public_parameters()));
}

TEST_F(AnonymousCountingTokensV0Test,
       TokensResponseIsInvalidForProofFromAnotherTranscript) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));
  // Put the proof from the second transcript into the first
  *transcript_1.tokens_response.mutable_tokens_response_v0()
       ->mutable_bb_oblivious_signature_response_proof() =
      transcript_2.tokens_response.tokens_response_v0()
          .bb_oblivious_signature_response_proof();
  EXPECT_THAT(
      anonymous_counting_tokens_->VerifyTokensResponse(
          messages, transcript_1.tokens_request,
          transcript_1.tokens_request_private_state,
          transcript_1.tokens_response, GetSchemeParameters(),
          client_parameters_.public_parameters(),
          client_parameters_.private_parameters(),
          server_parameters_->public_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(AnonymousCountingTokensV0Test,
       TokensResponseIsInvalidForRequestFromAnotherTranscript) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript_1, GenerateTranscript(messages));
  ASSERT_OK_AND_ASSIGN(Transcript transcript_2, GenerateTranscript(messages));
  // The request and state from transcript_1 should be inconsistent with the
  // response from transcript_2.
  EXPECT_THAT(
      anonymous_counting_tokens_->VerifyTokensResponse(
          messages, transcript_1.tokens_request,
          transcript_1.tokens_request_private_state,
          transcript_2.tokens_response, GetSchemeParameters(),
          client_parameters_.public_parameters(),
          client_parameters_.private_parameters(),
          server_parameters_->public_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Failed")));
}

TEST_F(AnonymousCountingTokensV0Test, EmptyResponseShouldBeInvalid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  transcript.tokens_response.clear_tokens_response_v0();

  EXPECT_THAT(
      anonymous_counting_tokens_->VerifyTokensResponse(
          messages, transcript.tokens_request,
          transcript.tokens_request_private_state, transcript.tokens_response,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          client_parameters_.private_parameters(),
          server_parameters_->public_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("parameters")));
}

TEST_F(AnonymousCountingTokensV0Test, EmptyResponseProofShouldBeInvalid) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  transcript.tokens_response.mutable_tokens_response_v0()
      ->clear_bb_oblivious_signature_response_proof();

  EXPECT_THAT(
      anonymous_counting_tokens_->VerifyTokensResponse(
          messages, transcript.tokens_request,
          transcript.tokens_request_private_state, transcript.tokens_response,
          GetSchemeParameters(), client_parameters_.public_parameters(),
          client_parameters_.private_parameters(),
          server_parameters_->public_parameters()),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("number")));
}

TEST_F(AnonymousCountingTokensV0Test, ProducesValidTokens) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};

  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  EXPECT_EQ(messages.size(), transcript.tokens.size());

  for (size_t i = 0; i < messages.size(); ++i) {
    EXPECT_OK(anonymous_counting_tokens_->VerifyToken(
        messages[i], transcript.tokens[i], GetSchemeParameters(),
        server_parameters_->public_parameters(),
        server_parameters_->private_parameters()));
  }
}

TEST_F(AnonymousCountingTokensV0Test, TokensDoNotVerifyWithWrongMessages) {
  std::vector<std::string> messages = {"message_1", "message_2", "message_3"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  for (size_t i = 0; i < messages.size(); ++i) {
    EXPECT_THAT(
        anonymous_counting_tokens_->VerifyToken(
            "wrong_message", transcript.tokens[i], GetSchemeParameters(),
            server_parameters_->public_parameters(),
            server_parameters_->private_parameters()),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("fails to match the token")));
  }
}

TEST_F(AnonymousCountingTokensV0Test, TokensHaveUniqueNonces) {
  std::vector<std::string> messages = {"message_1", "message_2"};
  ASSERT_OK_AND_ASSIGN(Transcript transcript, GenerateTranscript(messages));

  EXPECT_NE(transcript.tokens[0].nonce(), transcript.tokens[1].nonce());
}

}  // namespace
}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute
