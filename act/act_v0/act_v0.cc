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

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "act/act.pb.h"
#include "act/act_v0/act_v0.pb.h"
#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/camenisch_shoup.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/bb_oblivious_signature.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/bb_oblivious_signature.pb.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/dy_verifiable_random_function.h"
#include "private_join_and_compute/crypto/dodis_yampolskiy_prf/dy_verifiable_random_function.pb.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/pedersen_over_zn.h"
#include "private_join_and_compute/crypto/proto/ec_point.pb.h"
#include "private_join_and_compute/crypto/proto/proto_util.h"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {

namespace {

StatusOr<std::unique_ptr<BbObliviousSignature>> CreateBbObliviousSignature(
    const SchemeParametersV0& scheme_parameters_v0,
    const ServerPublicParametersV0& server_public_parameters_v0, Context* ctx,
    ECGroup* ec_group, PedersenOverZn* pedersen,
    PublicCamenischShoup* public_camenisch_shoup) {
  proto::BbObliviousSignatureParameters bb_oblivious_signature_parameters;
  bb_oblivious_signature_parameters.set_challenge_length_bits(
      scheme_parameters_v0.challenge_length_bits());
  bb_oblivious_signature_parameters.set_security_parameter(
      scheme_parameters_v0.security_parameter());
  bb_oblivious_signature_parameters.set_random_oracle_prefix(
      scheme_parameters_v0.random_oracle_prefix());
  bb_oblivious_signature_parameters.set_base_g(
      server_public_parameters_v0.prf_base_g());
  *bb_oblivious_signature_parameters.mutable_pedersen_parameters() =
      server_public_parameters_v0.pedersen_parameters();
  *bb_oblivious_signature_parameters.mutable_camenisch_shoup_public_key() =
      server_public_parameters_v0.camenisch_shoup_public_key();

  return BbObliviousSignature::Create(
      std::move(bb_oblivious_signature_parameters), ctx, ec_group,
      public_camenisch_shoup, pedersen);
}

StatusOr<std::unique_ptr<DyVerifiableRandomFunction>> CreateDyVrf(
    const SchemeParametersV0& scheme_parameters_v0,
    const ServerPublicParametersV0& server_public_parameters_v0, Context* ctx,
    ECGroup* ec_group, PedersenOverZn* pedersen) {
  proto::DyVrfParameters dy_vrf_parameters;
  dy_vrf_parameters.set_challenge_length_bits(
      scheme_parameters_v0.challenge_length_bits());
  dy_vrf_parameters.set_security_parameter(
      scheme_parameters_v0.security_parameter());
  dy_vrf_parameters.set_random_oracle_prefix(
      scheme_parameters_v0.random_oracle_prefix());
  dy_vrf_parameters.set_dy_prf_base_g(server_public_parameters_v0.prf_base_g());
  *dy_vrf_parameters.mutable_pedersen_parameters() =
      server_public_parameters_v0.pedersen_parameters();

  return DyVerifiableRandomFunction::Create(std::move(dy_vrf_parameters), ctx,
                                            ec_group, pedersen);
}

// Used to generate the client-independent portion of the nonce. A different
// nonce is chosen for each element in the batched token request.
StatusOr<std::vector<BigNum>> GetNoncesForTokenRequest(
    Context* ctx, const SchemeParameters& scheme_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ClientPublicParameters& client_public_parameters,
    const TokensRequestV0::Part1& tokens_request_part_1,
    uint64_t num_messages) {
  // Parses bit length of the random challenge from scheme parameters.
  uint64_t challenge_length_bits =
      scheme_parameters.scheme_parameters_v0().challenge_length_bits();
  // Computes the upper bound of the challenge and input to the random oracle.
  BigNum challenge_upper_bound = ctx->One().Lshift(challenge_length_bits);

  // Note that the random oracle prefix is implicitly included as part of the
  // parameters being serialized in the statement proto. We skip including it
  // again here to avoid unnecessary duplication.
  std::string challenge_string = "GetNoncesForTokenRequest:";
  auto challenge_sos =
      std::make_unique<google::protobuf::io::StringOutputStream>(
          &challenge_string);
  auto challenge_cos =
      std::make_unique<google::protobuf::io::CodedOutputStream>(
          challenge_sos.get());
  challenge_cos->SetSerializationDeterministic(true);
  challenge_cos->WriteVarint64(scheme_parameters.ByteSizeLong());
  challenge_cos->WriteString(SerializeAsStringInOrder(scheme_parameters));
  challenge_cos->WriteVarint64(server_public_parameters.ByteSizeLong());
  challenge_cos->WriteString(
      SerializeAsStringInOrder(server_public_parameters));
  challenge_cos->WriteVarint64(client_public_parameters.ByteSizeLong());
  challenge_cos->WriteString(
      SerializeAsStringInOrder(client_public_parameters));
  challenge_cos->WriteVarint64(tokens_request_part_1.ByteSizeLong());
  challenge_cos->WriteString(SerializeAsStringInOrder(tokens_request_part_1));
  challenge_cos->WriteVarint64(num_messages);

  // Delete the serialization objects to make sure they clean up and write.
  challenge_cos.reset();
  challenge_sos.reset();

  std::vector<BigNum> outputs;
  outputs.reserve(num_messages);
  for (uint64_t i = 0; i < num_messages; ++i) {
    std::string random_oracle_input_i = absl::StrCat(challenge_string, ",", i);
    outputs.push_back(
        ctx->RandomOracleSha512(random_oracle_input_i, challenge_upper_bound));
  }

  return std::move(outputs);
}

}  // namespace

std::unique_ptr<AnonymousCountingTokens> AnonymousCountingTokensV0::Create() {
  return absl::WrapUnique<AnonymousCountingTokensV0>(
      new AnonymousCountingTokensV0());
}

// Returns a fresh set of Server parameters corresponding to these
// SchemeParameters. Fails with InvalidArgument if the parameters don't
// correspond to ACT v0.
StatusOr<ServerParameters> AnonymousCountingTokensV0::GenerateServerParameters(
    const SchemeParameters& scheme_parameters) {
  if (!scheme_parameters.has_scheme_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::GenerateServerParameters: supplied "
        "parameters do not correspond to ACTv0.");
  }

  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();

  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));

  // Choose base g.
  ASSIGN_OR_RETURN(ECPoint dy_prf_base_g, ec_group.GetRandomGenerator());

  // Generate RSA-Modulus and Camenisch-Shoup encryption key.
  CamenischShoupKey camenisch_shoup_key = GenerateCamenischShoupKey(
      &ctx, scheme_parameters_v0.modulus_length_bits(),
      scheme_parameters_v0.camenisch_shoup_s(),
      scheme_parameters_v0.vector_encryption_length());

  BigNum n = camenisch_shoup_key.n;

  auto camenisch_shoup_public_key = std::make_unique<CamenischShoupPublicKey>(
      CamenischShoupPublicKey{camenisch_shoup_key.n, camenisch_shoup_key.s,
                              camenisch_shoup_key.vector_encryption_length,
                              camenisch_shoup_key.g, camenisch_shoup_key.ys});
  auto camenisch_shoup_private_key = std::make_unique<CamenischShoupPrivateKey>(
      CamenischShoupPrivateKey{camenisch_shoup_key.xs});

  auto public_camenisch_shoup = std::make_unique<PublicCamenischShoup>(
      &ctx, camenisch_shoup_public_key->n, camenisch_shoup_public_key->s,
      camenisch_shoup_public_key->g, camenisch_shoup_public_key->ys);

  // Generate Pedersen Parameters.
  PedersenOverZn::Parameters pedersen_parameters =
      PedersenOverZn::GenerateParameters(
          &ctx, n, scheme_parameters_v0.pedersen_batch_size());

  ASSIGN_OR_RETURN(
      std::unique_ptr<PedersenOverZn> pedersen,
      PedersenOverZn::Create(&ctx, pedersen_parameters.gs,
                             pedersen_parameters.h, pedersen_parameters.n));

  ServerParameters server_parameters;

  ServerPublicParametersV0* server_public_parameters_v0 =
      server_parameters.mutable_public_parameters()
          ->mutable_server_public_parameters_v0();
  ASSIGN_OR_RETURN(*server_public_parameters_v0->mutable_prf_base_g(),
                   dy_prf_base_g.ToBytesCompressed());
  *server_public_parameters_v0->mutable_pedersen_parameters() =
      PedersenOverZn::ParametersToProto(pedersen_parameters);
  *server_public_parameters_v0->mutable_camenisch_shoup_public_key() =
      CamenischShoupPublicKeyToProto(*camenisch_shoup_public_key);

  ServerPrivateParametersV0* server_private_parameters_v0 =
      server_parameters.mutable_private_parameters()
          ->mutable_server_private_parameters_v0();
  *server_private_parameters_v0->mutable_camenisch_shoup_private_key() =
      CamenischShoupPrivateKeyToProto(*camenisch_shoup_private_key);

  // Generate Boneh-Boyen Oblivious Signature object. This call is safe even
  // with the partially-ready server_public_parameters.
  ASSIGN_OR_RETURN(
      std::unique_ptr<BbObliviousSignature> bb_oblivious_signature,
      CreateBbObliviousSignature(scheme_parameters_v0,
                                 *server_public_parameters_v0, &ctx, &ec_group,
                                 pedersen.get(), public_camenisch_shoup.get()));

  // Generate Boneh-Boyen Oblivious Signature key.
  ASSIGN_OR_RETURN(
      std::tie(*server_public_parameters_v0
                    ->mutable_bb_oblivious_signature_public_key(),
               *server_private_parameters_v0
                    ->mutable_bb_oblivious_signature_private_key()),
      bb_oblivious_signature->GenerateKeys());

  return std::move(server_parameters);
}

// Returns a fresh set of Client parameters corresponding to these
// SchemeParameters and ServerPublicParameters. Fails with InvalidArgument if
// the parameters don't correspond to ACT v0.
StatusOr<ClientParameters> AnonymousCountingTokensV0::GenerateClientParameters(
    const SchemeParameters& scheme_parameters,
    const ServerPublicParameters& server_public_parameters) {
  if (!scheme_parameters.has_scheme_parameters_v0() ||
      !server_public_parameters.has_server_public_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::GenerateClientParameters: supplied "
        "parameters do not correspond to ACT v0.");
  }

  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();
  const ServerPublicParametersV0& server_public_parameters_v0 =
      server_public_parameters.server_public_parameters_v0();

  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));

  // Deserialize Pedersen Params
  ASSIGN_OR_RETURN(
      std::unique_ptr<PedersenOverZn> pedersen,
      PedersenOverZn::FromProto(
          &ctx, server_public_parameters_v0.pedersen_parameters()));

  // Generate Client VRF object.
  ASSIGN_OR_RETURN(
      std::unique_ptr<DyVerifiableRandomFunction> dy_vrf,
      CreateDyVrf(scheme_parameters_v0, server_public_parameters_v0, &ctx,
                  &ec_group, pedersen.get()));

  ClientParameters client_parameters;
  ClientPublicParametersV0* client_public_parameters_v0 =
      client_parameters.mutable_public_parameters()
          ->mutable_client_public_parameters_v0();
  ClientPrivateParametersV0* client_private_parameters_v0 =
      client_parameters.mutable_private_parameters()
          ->mutable_client_private_parameters_v0();

  ASSIGN_OR_RETURN(
      std::tie(
          *client_public_parameters_v0->mutable_dy_vrf_public_key(),
          *client_private_parameters_v0->mutable_dy_vrf_private_key(),
          *client_public_parameters_v0->mutable_dy_vrf_generate_keys_proof()),
      dy_vrf->GenerateKeyPair());

  return std::move(client_parameters);
}

// Verifies the consistency of the  ClientPublicParameters with the Server and
// scheme parameters. Fails with InvalidArgument if the parameters don't
// correspond to ACT v0.
Status AnonymousCountingTokensV0::CheckClientParameters(
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ServerPrivateParameters& server_private_parameters) {
  if (!scheme_parameters.has_scheme_parameters_v0() ||
      !client_public_parameters.has_client_public_parameters_v0() ||
      !server_public_parameters.has_server_public_parameters_v0() ||
      !server_private_parameters.has_server_private_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::CheckClientParameters: supplied "
        "parameters do not correspond to ACT v0.");
  }

  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();
  const ServerPublicParametersV0& server_public_parameters_v0 =
      server_public_parameters.server_public_parameters_v0();
  const ClientPublicParametersV0& client_public_parameters_v0 =
      client_public_parameters.client_public_parameters_v0();
  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));

  // Deserialize Pedersen Params
  ASSIGN_OR_RETURN(
      std::unique_ptr<PedersenOverZn> pedersen,
      PedersenOverZn::FromProto(
          &ctx, server_public_parameters_v0.pedersen_parameters()));

  // Generate Client VRF object.
  ASSIGN_OR_RETURN(
      std::unique_ptr<DyVerifiableRandomFunction> dy_vrf,
      CreateDyVrf(scheme_parameters_v0, server_public_parameters_v0, &ctx,
                  &ec_group, pedersen.get()));

  // Verify the proof for the Client's VRF key.
  return dy_vrf->VerifyGenerateKeysProof(
      client_public_parameters_v0.dy_vrf_public_key(),
      client_public_parameters_v0.dy_vrf_generate_keys_proof());
}

// Returns a tuple of client_fingerprints, TokensRequest and
// TokensRequestPrivateState for the given set of messages. Fails with
// InvalidArgument if the parameters don't correspond to ACT v0.
StatusOr<std::tuple<std::vector<std::string>, TokensRequest,
                    TokensRequestPrivateState>>
AnonymousCountingTokensV0::GenerateTokensRequest(
    absl::Span<const std::string> messages,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ClientPrivateParameters& client_private_parameters,
    const ServerPublicParameters& server_public_parameters) {
  if (!scheme_parameters.has_scheme_parameters_v0() ||
      !client_public_parameters.has_client_public_parameters_v0() ||
      !client_private_parameters.has_client_private_parameters_v0() ||
      !server_public_parameters.has_server_public_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::GenerateTokensRequest: supplied "
        "parameters do not correspond to ACT v0.");
  }

  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();
  const ClientPublicParametersV0& client_public_parameters_v0 =
      client_public_parameters.client_public_parameters_v0();
  const ClientPrivateParametersV0& client_private_parameters_v0 =
      client_private_parameters.client_private_parameters_v0();
  const ServerPublicParametersV0& server_public_parameters_v0 =
      server_public_parameters.server_public_parameters_v0();

  TokensRequest tokens_request_proto;
  TokensRequestV0* tokens_request_v0 =
      tokens_request_proto.mutable_tokens_request_v0();
  TokensRequestV0::Part1* tokens_request_v0_part_1 =
      tokens_request_v0->mutable_part_1();
  TokensRequestPrivateState tokens_request_private_state;

  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));

  // Deserialize and create cryptographic objects.
  ASSIGN_OR_RETURN(
      std::unique_ptr<PedersenOverZn> pedersen,
      PedersenOverZn::FromProto(
          &ctx, server_public_parameters_v0.pedersen_parameters()));
  ASSIGN_OR_RETURN(
      std::unique_ptr<PublicCamenischShoup> public_camenisch_shoup,
      PublicCamenischShoup::FromProto(
          &ctx, server_public_parameters_v0.camenisch_shoup_public_key()));
  ASSIGN_OR_RETURN(
      ECPoint dy_prf_base_g,
      ec_group.CreateECPoint(server_public_parameters_v0.prf_base_g()));

  ASSIGN_OR_RETURN(
      std::unique_ptr<DyVerifiableRandomFunction> dy_vrf,
      CreateDyVrf(scheme_parameters_v0, server_public_parameters_v0, &ctx,
                  &ec_group, pedersen.get()));

  // Deserialize Boneh-Boyen Oblivious Signature parameters and keys
  ASSIGN_OR_RETURN(
      std::unique_ptr<BbObliviousSignature> bb_oblivious_signature,
      CreateBbObliviousSignature(scheme_parameters_v0,
                                 server_public_parameters_v0, &ctx, &ec_group,
                                 pedersen.get(), public_camenisch_shoup.get()));

  // 1) Hash all messages to the exponent group/ BigNums.
  std::vector<BigNum> hashed_messages;
  hashed_messages.reserve(messages.size());
  for (size_t i = 0; i < messages.size(); ++i) {
    hashed_messages.push_back(
        ctx.RandomOracleSha512(messages[i], ec_group.GetOrder()));
  }

  // 2) Commit to hashed messages.
  ASSIGN_OR_RETURN(
      PedersenOverZn::CommitmentAndOpening commit_and_open_messages,
      pedersen->Commit(hashed_messages));
  tokens_request_v0_part_1->set_commit_messages(
      commit_and_open_messages.commitment.ToBytes());

  // 3) Generate client nonces and commit to them.
  std::vector<BigNum> client_nonces;
  client_nonces.reserve(messages.size());
  for (size_t i = 0; i < messages.size(); ++i) {
    client_nonces.push_back(ec_group.GeneratePrivateKey());
  }
  ASSIGN_OR_RETURN(
      PedersenOverZn::CommitmentAndOpening commit_and_open_client_nonces,
      pedersen->Commit(client_nonces));
  tokens_request_v0_part_1->set_commit_client_nonces(
      commit_and_open_client_nonces.commitment.ToBytes());

  // 4) Perform a VRF on the committed messages and serialize as fingerprints.
  ASSIGN_OR_RETURN(
      std::vector<ECPoint> prf_evaluations,
      dy_vrf->Apply(hashed_messages,
                    client_private_parameters_v0.dy_vrf_private_key()));
  std::vector<std::string> fingerprints;
  fingerprints.reserve(prf_evaluations.size());
  for (size_t i = 0; i < prf_evaluations.size(); ++i) {
    ASSIGN_OR_RETURN(std::string fingerprint,
                     prf_evaluations[i].ToBytesCompressed());
    fingerprints.push_back(std::move(fingerprint));
  }

  // Also create the proof that the fingerprints were correctly generated.
  ASSIGN_OR_RETURN(*tokens_request_v0_part_1->mutable_fingerprints_proof(),
                   dy_vrf->GenerateApplyProof(
                       hashed_messages, prf_evaluations,
                       client_public_parameters_v0.dy_vrf_public_key(),
                       client_private_parameters_v0.dy_vrf_private_key(),
                       commit_and_open_messages));

  // 5) Generate server nonces by hashing the preceding portion of the request.
  ASSIGN_OR_RETURN(std::vector<BigNum> server_nonces,
                   GetNoncesForTokenRequest(
                       &ctx, scheme_parameters, server_public_parameters,
                       client_public_parameters, *tokens_request_v0_part_1,
                       messages.size()));
  // We commit the "server_nonces" with randomness 0, which is ok since they
  // are known to both parties, and furthermore will be homomorphically added to
  // the "client_nonces" which have properly generated randomness.
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment commit_server_nonces,
                   pedersen->CommitWithRand(server_nonces, ctx.Zero()));

  // 6) Homomorphically compute commitments to the nonces (rs)
  std::vector<BigNum> nonces;
  nonces.reserve(messages.size());
  for (size_t i = 0; i < messages.size(); ++i) {
    // No mod performed here, since the homomorphic addition of the commitments
    // will not be mod-ed, and we want consistency.
    nonces.push_back(server_nonces[i] + client_nonces[i]);
  }
  PedersenOverZn::Commitment commit_nonce = pedersen->Add(
      commit_server_nonces, commit_and_open_client_nonces.commitment);
  PedersenOverZn::Opening commit_nonce_opening =
      commit_and_open_client_nonces.opening;

  *tokens_request_private_state.mutable_tokens_request_private_state_v0()
       ->mutable_nonces() = BigNumVectorToProto(nonces);

  // 7) Generate Boneh-Boyen Oblivious Signature Request request.
  ASSIGN_OR_RETURN(
      std::tie(
          *tokens_request_v0->mutable_bb_oblivious_signature_request(),
          *tokens_request_v0->mutable_bb_oblivious_signature_request_proof(),
          *tokens_request_private_state
               .mutable_tokens_request_private_state_v0()
               ->mutable_bb_oblivious_signature_request_private_state()),
      bb_oblivious_signature->GenerateRequestAndProof(
          hashed_messages, nonces,
          server_public_parameters_v0.bb_oblivious_signature_public_key(),
          commit_and_open_messages, {commit_nonce, commit_nonce_opening}));

  return std::make_tuple(std::move(fingerprints),
                         std::move(tokens_request_proto),
                         std::move(tokens_request_private_state));
}

// Returns OkStatus on a valid request. Fails with InvalidArgument if the
// parameters don't correspond to ACT v0.
Status AnonymousCountingTokensV0::CheckTokensRequest(
    absl::Span<const std::string> client_fingerprints,
    const TokensRequest& tokens_request,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ServerPrivateParameters& server_private_parameters) {
  if (!tokens_request.has_tokens_request_v0() ||
      !scheme_parameters.has_scheme_parameters_v0() ||
      !client_public_parameters.has_client_public_parameters_v0() ||
      !server_public_parameters.has_server_public_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::GenerateTokensResponse: supplied "
        "parameters do not correspond to ACT v0.");
  }

  const TokensRequestV0& tokens_request_v0 = tokens_request.tokens_request_v0();
  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();
  const ClientPublicParametersV0& client_public_parameters_v0 =
      client_public_parameters.client_public_parameters_v0();
  const ServerPublicParametersV0& server_public_parameters_v0 =
      server_public_parameters.server_public_parameters_v0();

  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));

  // Deserialize and create cryptographic objects.
  ASSIGN_OR_RETURN(
      std::unique_ptr<PedersenOverZn> pedersen,
      PedersenOverZn::FromProto(
          &ctx, server_public_parameters_v0.pedersen_parameters()));
  ASSIGN_OR_RETURN(
      std::unique_ptr<PublicCamenischShoup> public_camenisch_shoup,
      PublicCamenischShoup::FromProto(
          &ctx, server_public_parameters_v0.camenisch_shoup_public_key()));

  // Construct the DY VRF object
  ASSIGN_OR_RETURN(
      std::unique_ptr<DyVerifiableRandomFunction> dy_vrf,
      CreateDyVrf(scheme_parameters_v0, server_public_parameters_v0, &ctx,
                  &ec_group, pedersen.get()));

  PedersenOverZn::Commitment commit_messages = ctx.CreateBigNum(
      tokens_request.tokens_request_v0().part_1().commit_messages());

  std::vector<ECPoint> deserialized_fingerprints;
  deserialized_fingerprints.reserve(client_fingerprints.size());
  for (size_t i = 0; i < client_fingerprints.size(); ++i) {
    ASSIGN_OR_RETURN(ECPoint deserialized_fingerprint,
                     ec_group.CreateECPoint(client_fingerprints[i]));

    // Test that the deserialized fingerprint reserializes to the exact same
    // value.
    ASSIGN_OR_RETURN(std::string reserialized_fingerprint,
                     deserialized_fingerprint.ToBytesCompressed());
    if (reserialized_fingerprint != client_fingerprints[i]) {
      return absl::InvalidArgumentError(absl::StrCat(
          "AnonymousCountingTokensV0::CheckTokensRequest: client_fingerprints[",
          i,
          "] comes out to a different value when serialized and "
          "deserialized."));
    }

    deserialized_fingerprints.push_back(std::move(deserialized_fingerprint));
  }

  RETURN_IF_ERROR(dy_vrf->VerifyApplyProof(
      deserialized_fingerprints,
      client_public_parameters_v0.dy_vrf_public_key(), commit_messages,
      tokens_request_v0.part_1().fingerprints_proof()));

  // Deserialize Boneh-Boyen Oblivious Signature parameters and keys
  ASSIGN_OR_RETURN(
      std::unique_ptr<BbObliviousSignature> bb_oblivious_signature,
      CreateBbObliviousSignature(scheme_parameters_v0,
                                 server_public_parameters_v0, &ctx, &ec_group,
                                 pedersen.get(), public_camenisch_shoup.get()));

  // Regenerate the commitments to messages and nonces (rs) by replaying the
  // steps the client took to generate them.
  PedersenOverZn::Commitment commit_client_nonces = ctx.CreateBigNum(
      tokens_request.tokens_request_v0().part_1().commit_client_nonces());

  ASSIGN_OR_RETURN(
      std::vector<BigNum> server_nonces,
      GetNoncesForTokenRequest(
          &ctx, scheme_parameters, server_public_parameters,
          client_public_parameters, tokens_request.tokens_request_v0().part_1(),
          tokens_request.tokens_request_v0()
              .bb_oblivious_signature_request()
              .num_messages()));
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment commit_server_nonces,
                   pedersen->CommitWithRand(server_nonces, ctx.Zero()));
  PedersenOverZn::Commitment commit_nonce =
      pedersen->Add(commit_server_nonces, commit_client_nonces);

  return bb_oblivious_signature->VerifyRequest(
      server_public_parameters_v0.bb_oblivious_signature_public_key(),
      tokens_request_v0.bb_oblivious_signature_request(),
      tokens_request_v0.bb_oblivious_signature_request_proof(), commit_messages,
      commit_nonce);
}

// Returns the TokensResponse. Fails with InvalidArgument if the parameters
// don't correspond to ACT v0.
StatusOr<TokensResponse> AnonymousCountingTokensV0::GenerateTokensResponse(
    const TokensRequest& tokens_request,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ServerPrivateParameters& server_private_parameters) {
  if (!tokens_request.has_tokens_request_v0() ||
      !scheme_parameters.has_scheme_parameters_v0() ||
      !client_public_parameters.has_client_public_parameters_v0() ||
      !server_public_parameters.has_server_public_parameters_v0() ||
      !server_private_parameters.has_server_private_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::GenerateTokensResponse: supplied "
        "parameters do not correspond to ACT v0.");
  }

  const TokensRequestV0& tokens_request_v0 = tokens_request.tokens_request_v0();
  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();
  const ServerPublicParametersV0& server_public_parameters_v0 =
      server_public_parameters.server_public_parameters_v0();
  const ServerPrivateParametersV0& server_private_parameters_v0 =
      server_private_parameters.server_private_parameters_v0();

  TokensResponse tokens_response;
  TokensResponseV0* tokens_response_v0 =
      tokens_response.mutable_tokens_response_v0();

  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));

  // Deserialize and create cryptographic objects.
  ASSIGN_OR_RETURN(
      std::unique_ptr<PedersenOverZn> pedersen,
      PedersenOverZn::FromProto(
          &ctx, server_public_parameters_v0.pedersen_parameters()));
  ASSIGN_OR_RETURN(
      std::unique_ptr<PublicCamenischShoup> public_camenisch_shoup,
      PublicCamenischShoup::FromProto(
          &ctx, server_public_parameters_v0.camenisch_shoup_public_key()));
  ASSIGN_OR_RETURN(
      std::unique_ptr<PrivateCamenischShoup> private_camenisch_shoup,
      PrivateCamenischShoup::FromProto(
          &ctx, server_public_parameters_v0.camenisch_shoup_public_key(),
          server_private_parameters_v0.camenisch_shoup_private_key()));

  // Deserialize Boneh-Boyen Oblivious Signature parameters and keys
  ASSIGN_OR_RETURN(
      std::unique_ptr<BbObliviousSignature> bb_oblivious_signature,
      CreateBbObliviousSignature(scheme_parameters_v0,
                                 server_public_parameters_v0, &ctx, &ec_group,
                                 pedersen.get(), public_camenisch_shoup.get()));

  // Regenerate the commitments to messages and nonces (rs) by replaying the
  // steps the client took to generate them.
  PedersenOverZn::Commitment commit_messages = ctx.CreateBigNum(
      tokens_request.tokens_request_v0().part_1().commit_messages());
  PedersenOverZn::Commitment commit_client_nonces = ctx.CreateBigNum(
      tokens_request.tokens_request_v0().part_1().commit_client_nonces());

  ASSIGN_OR_RETURN(
      std::vector<BigNum> server_nonces,
      GetNoncesForTokenRequest(
          &ctx, scheme_parameters, server_public_parameters,
          client_public_parameters, tokens_request.tokens_request_v0().part_1(),
          tokens_request.tokens_request_v0()
              .bb_oblivious_signature_request()
              .num_messages()));
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment commit_server_nonces,
                   pedersen->CommitWithRand(server_nonces, ctx.Zero()));
  PedersenOverZn::Commitment commit_nonce =
      pedersen->Add(commit_server_nonces, commit_client_nonces);

  // Generate response and proof for the Boneh-Boyen Oblivious Signature.
  ASSIGN_OR_RETURN(
      std::tie(
          *tokens_response_v0->mutable_bb_oblivious_signature_response(),
          *tokens_response_v0->mutable_bb_oblivious_signature_response_proof()),
      bb_oblivious_signature->GenerateResponseAndProof(
          tokens_request_v0.bb_oblivious_signature_request(),
          server_public_parameters_v0.bb_oblivious_signature_public_key(),
          server_private_parameters_v0.bb_oblivious_signature_private_key(),
          commit_messages, commit_nonce, private_camenisch_shoup.get()));

  return std::move(tokens_response);
}

// Returns OkStatus on a valid response. Fails with InvalidArgument if the
// parameters don't correspond to ACT v0.
Status AnonymousCountingTokensV0::VerifyTokensResponse(
    absl::Span<const std::string> messages, const TokensRequest& tokens_request,
    const TokensRequestPrivateState& tokens_request_private_state,
    const TokensResponse& tokens_response,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ClientPrivateParameters& client_private_parameters,
    const ServerPublicParameters& server_public_parameters) {
  if (!tokens_request.has_tokens_request_v0() ||
      !tokens_response.has_tokens_response_v0() ||
      !tokens_request_private_state.has_tokens_request_private_state_v0() ||
      !scheme_parameters.has_scheme_parameters_v0() ||
      !client_public_parameters.has_client_public_parameters_v0() ||
      !client_private_parameters.has_client_private_parameters_v0() ||
      !server_public_parameters.has_server_public_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::VerifyTokensResponse: supplied "
        "parameters do not correspond to ACT v0.");
  }

  const TokensRequestV0& tokens_request_v0 = tokens_request.tokens_request_v0();
  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();
  const ServerPublicParametersV0& server_public_parameters_v0 =
      server_public_parameters.server_public_parameters_v0();
  const TokensResponseV0& tokens_response_v0 =
      tokens_response.tokens_response_v0();

  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));

  // Deserialize and create cryptographic objects.
  ASSIGN_OR_RETURN(
      std::unique_ptr<PedersenOverZn> pedersen,
      PedersenOverZn::FromProto(
          &ctx, server_public_parameters_v0.pedersen_parameters()));
  ASSIGN_OR_RETURN(
      std::unique_ptr<PublicCamenischShoup> public_camenisch_shoup,
      PublicCamenischShoup::FromProto(
          &ctx, server_public_parameters_v0.camenisch_shoup_public_key()));

  // Deserialize Boneh-Boyen Oblivious Signature parameters and keys
  ASSIGN_OR_RETURN(
      std::unique_ptr<BbObliviousSignature> bb_oblivious_signature,
      CreateBbObliviousSignature(scheme_parameters_v0,
                                 server_public_parameters_v0, &ctx, &ec_group,
                                 pedersen.get(), public_camenisch_shoup.get()));

  // Regenerate the commitments to messages and nonces (rs) by replaying the
  // steps the client took to generate them.
  PedersenOverZn::Commitment commit_messages = ctx.CreateBigNum(
      tokens_request.tokens_request_v0().part_1().commit_messages());
  PedersenOverZn::Commitment commit_client_nonces = ctx.CreateBigNum(
      tokens_request.tokens_request_v0().part_1().commit_client_nonces());

  ASSIGN_OR_RETURN(
      std::vector<BigNum> server_nonces,
      GetNoncesForTokenRequest(
          &ctx, scheme_parameters, server_public_parameters,
          client_public_parameters, tokens_request.tokens_request_v0().part_1(),
          tokens_request.tokens_request_v0()
              .bb_oblivious_signature_request()
              .num_messages()));
  ASSIGN_OR_RETURN(PedersenOverZn::Commitment commit_server_nonces,
                   pedersen->CommitWithRand(server_nonces, ctx.Zero()));
  PedersenOverZn::Commitment commit_nonce =
      pedersen->Add(commit_server_nonces, commit_client_nonces);

  return bb_oblivious_signature->VerifyResponse(
      server_public_parameters_v0.bb_oblivious_signature_public_key(),
      tokens_response_v0.bb_oblivious_signature_response(),
      tokens_response_v0.bb_oblivious_signature_response_proof(),
      tokens_request_v0.bb_oblivious_signature_request(), commit_messages,
      commit_nonce);
}

// Returns a vector of tokens corresponding to the supplied messages. Fails
// with InvalidArgument if the parameters don't correspond to ACT v0.
StatusOr<std::vector<Token>> AnonymousCountingTokensV0::RecoverTokens(
    absl::Span<const std::string> messages, const TokensRequest& tokens_request,
    const TokensRequestPrivateState& tokens_request_private_state,
    const TokensResponse& tokens_response,
    const SchemeParameters& scheme_parameters,
    const ClientPublicParameters& client_public_parameters,
    const ClientPrivateParameters& client_private_parameters,
    const ServerPublicParameters& server_public_parameters) {
  if (!tokens_request.has_tokens_request_v0() ||
      !tokens_request_private_state.has_tokens_request_private_state_v0() ||
      !tokens_response.has_tokens_response_v0() ||
      !scheme_parameters.has_scheme_parameters_v0() ||
      !client_public_parameters.has_client_public_parameters_v0() ||
      !client_private_parameters.has_client_private_parameters_v0() ||
      !server_public_parameters.has_server_public_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::VerifyTokensResponse: supplied "
        "parameters do not correspond to ACT v0.");
  }

  const TokensRequestV0& tokens_request_v0 = tokens_request.tokens_request_v0();
  const TokensRequestPrivateStateV0& tokens_request_private_state_v0 =
      tokens_request_private_state.tokens_request_private_state_v0();
  const TokensResponseV0& tokens_response_v0 =
      tokens_response.tokens_response_v0();
  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();
  const ServerPublicParametersV0& server_public_parameters_v0 =
      server_public_parameters.server_public_parameters_v0();

  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));

  // Deserialize and create cryptographic objects.
  ASSIGN_OR_RETURN(
      std::unique_ptr<PedersenOverZn> pedersen,
      PedersenOverZn::FromProto(
          &ctx, server_public_parameters_v0.pedersen_parameters()));
  ASSIGN_OR_RETURN(
      std::unique_ptr<PublicCamenischShoup> public_camenisch_shoup,
      PublicCamenischShoup::FromProto(
          &ctx, server_public_parameters_v0.camenisch_shoup_public_key()));
  ASSIGN_OR_RETURN(
      ECPoint dy_prf_base_g,
      ec_group.CreateECPoint(server_public_parameters_v0.prf_base_g()));

  // Deserialize Boneh-Boyen Oblivious Signature parameters and keys
  ASSIGN_OR_RETURN(
      std::unique_ptr<BbObliviousSignature> bb_oblivious_signature,
      CreateBbObliviousSignature(scheme_parameters_v0,
                                 server_public_parameters_v0, &ctx, &ec_group,
                                 pedersen.get(), public_camenisch_shoup.get()));

  // Extract message PRF evaluations
  ASSIGN_OR_RETURN(std::vector<ECPoint> signatures,
                   bb_oblivious_signature->ExtractResults(
                       tokens_response_v0.bb_oblivious_signature_response(),
                       tokens_request_v0.bb_oblivious_signature_request(),
                       tokens_request_private_state_v0
                           .bb_oblivious_signature_request_private_state()));

  // Package tokens.
  std::vector<BigNum> nonces =
      ParseBigNumVectorProto(&ctx, tokens_request_private_state_v0.nonces());

  std::vector<Token> tokens;
  tokens.reserve(messages.size());
  for (size_t i = 0; i < messages.size(); ++i) {
    Token token;
    TokenV0* token_v0 = token.mutable_token_v0();
    token.set_nonce_bytes(nonces[i].ToBytes());
    ASSIGN_OR_RETURN(*token_v0->mutable_bb_signature(),
                     signatures[i].ToBytesCompressed());
    tokens.push_back(std::move(token));
  }

  return std::move(tokens);
}

// Returns OkStatus on valid tokens. Fails with InvalidArgument if the
// parameters don't correspond to ACT v0.
Status AnonymousCountingTokensV0::VerifyToken(
    std::string m, const Token& token,
    const SchemeParameters& scheme_parameters,
    const ServerPublicParameters& server_public_parameters,
    const ServerPrivateParameters& server_private_parameters) {
  if (!token.has_token_v0() || !scheme_parameters.has_scheme_parameters_v0() ||
      !server_public_parameters.has_server_public_parameters_v0() ||
      !server_private_parameters.has_server_private_parameters_v0()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::VerifyToken: supplied "
        "parameters do not correspond to ACT v0.");
  }

  const TokenV0& token_v0 = token.token_v0();
  const SchemeParametersV0& scheme_parameters_v0 =
      scheme_parameters.scheme_parameters_v0();
  const ServerPublicParametersV0& server_public_parameters_v0 =
      server_public_parameters.server_public_parameters_v0();
  const ServerPrivateParametersV0& server_private_parameters_v0 =
      server_private_parameters.server_private_parameters_v0();

  Context ctx;
  ASSIGN_OR_RETURN(ECGroup ec_group,
                   ECGroup::Create(scheme_parameters_v0.prf_ec_group(), &ctx));
  ASSIGN_OR_RETURN(
      ECPoint dy_prf_base_g,
      ec_group.CreateECPoint(server_public_parameters_v0.prf_base_g()));
  BigNum k = ctx.CreateBigNum(
      server_private_parameters_v0.bb_oblivious_signature_private_key().k());
  BigNum y = ctx.CreateBigNum(
      server_private_parameters_v0.bb_oblivious_signature_private_key().y());

  BigNum hashed_message = ctx.RandomOracleSha512(m, ec_group.GetOrder());
  BigNum nonce = ctx.CreateBigNum(token.nonce_bytes());

  // Verify that reserializing the nonce comes out to the same value.
  if (nonce.ToBytes() != token.nonce_bytes()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::VerifyToken: nonce comes out to different "
        "value when serialized and deserialized.");
  }

  ASSIGN_OR_RETURN(ECPoint signature_from_token,
                   ec_group.CreateECPoint(token_v0.bb_signature()));

  // Verify that reserializing the signature comes out to the same value
  ASSIGN_OR_RETURN(std::string reserialized_signature_from_token,
                   signature_from_token.ToBytesCompressed());
  if (reserialized_signature_from_token != token_v0.bb_signature()) {
    return absl::InvalidArgumentError(
        "AnonymousCountingTokensV0::VerifyToken: bb_signature comes out to "
        "different value when serialized and deserialized.");
  }

  ASSIGN_OR_RETURN(
      BigNum inverted_exponent,
      (hashed_message + k + (nonce * y)).ModInverse(ec_group.GetOrder()));
  ASSIGN_OR_RETURN(ECPoint signature_by_evaluation,
                   dy_prf_base_g.Mul(inverted_exponent));
  if (signature_by_evaluation != signature_from_token) {
    return absl::InvalidArgumentError(
        "ACTV0::VerifyToken: Boneh-boyen signature on message and nonce fails "
        "to match the token.");
  }

  return absl::OkStatus();
}

}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute
