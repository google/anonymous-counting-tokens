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

#include <string>

#include "act/act_v0/act_v0.pb.h"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {

SchemeParameters ActV0TestSchemeParameters() {
  int test_modulus_length = 1536;
  int batch_size = 3;
  std::string random_oracle_prefix = "ActV0TestSchemeParameters";

  SchemeParameters scheme_parameters;
  SchemeParametersV0* scheme_parameters_v0 =
      scheme_parameters.mutable_scheme_parameters_v0();
  scheme_parameters_v0->set_security_parameter(kDefaultSecurityParameter);
  scheme_parameters_v0->set_challenge_length_bits(kDefaultChallengeLength);
  scheme_parameters_v0->set_modulus_length_bits(test_modulus_length);
  scheme_parameters_v0->set_camenisch_shoup_s(kDefaultCamenischShoupS);
  scheme_parameters_v0->set_vector_encryption_length(batch_size);
  scheme_parameters_v0->set_pedersen_batch_size(batch_size);
  scheme_parameters_v0->set_prf_ec_group(kDefaultCurveId);
  scheme_parameters_v0->set_random_oracle_prefix(random_oracle_prefix);

  return scheme_parameters;
}

SchemeParameters ActV0Batch16SchemeParameters() {
  int batch_size = 16;
  std::string random_oracle_prefix = "ActV0Batch16SchemeParameters";

  SchemeParameters scheme_parameters;
  SchemeParametersV0* scheme_parameters_v0 =
      scheme_parameters.mutable_scheme_parameters_v0();
  scheme_parameters_v0->set_security_parameter(kDefaultSecurityParameter);
  scheme_parameters_v0->set_challenge_length_bits(kDefaultChallengeLength);
  scheme_parameters_v0->set_modulus_length_bits(kDefaultModulusLengthBits);
  scheme_parameters_v0->set_camenisch_shoup_s(kDefaultCamenischShoupS);
  scheme_parameters_v0->set_vector_encryption_length(batch_size);
  scheme_parameters_v0->set_pedersen_batch_size(batch_size);
  scheme_parameters_v0->set_prf_ec_group(kDefaultCurveId);
  scheme_parameters_v0->set_random_oracle_prefix(random_oracle_prefix);

  return scheme_parameters;
}

SchemeParameters ActV0Batch32SchemeParameters() {
  int batch_size = 32;
  std::string random_oracle_prefix = "ActV0Batch32SchemeParameters";

  SchemeParameters scheme_parameters;
  SchemeParametersV0* scheme_parameters_v0 =
      scheme_parameters.mutable_scheme_parameters_v0();
  scheme_parameters_v0->set_security_parameter(kDefaultSecurityParameter);
  scheme_parameters_v0->set_challenge_length_bits(kDefaultChallengeLength);
  scheme_parameters_v0->set_modulus_length_bits(kDefaultModulusLengthBits);
  scheme_parameters_v0->set_camenisch_shoup_s(kDefaultCamenischShoupS);
  scheme_parameters_v0->set_vector_encryption_length(batch_size);
  scheme_parameters_v0->set_pedersen_batch_size(batch_size);
  scheme_parameters_v0->set_prf_ec_group(kDefaultCurveId);
  scheme_parameters_v0->set_random_oracle_prefix(random_oracle_prefix);

  return scheme_parameters;
}

// Returns parameters supporting 32 messages in a batch, with CS vector
// encryption length set to 2, and modulus length 2048.
SchemeParameters
ActV0SchemeParametersPedersen32Modulus2048CamenischShoupVector2() {
  int pedersen_batch_size = 32;
  int modulus_length = 2048;
  int camensich_shoup_vector_encryption_length = 2;

  return ActV0SchemeParameters(pedersen_batch_size, modulus_length,
                               camensich_shoup_vector_encryption_length);
}

// Returns custom parameters.
SchemeParameters ActV0SchemeParameters(int pedersen_batch_size,
                                       int modulus_length_bits,
                                       int camenisch_shoup_vector_length) {
  std::string random_oracle_prefix = absl::StrCat(
      "ActV0SchemeParametersPedersenBatchSize", pedersen_batch_size,
      "ModulusLengthBits", modulus_length_bits, "CamenischShoupVectorLength",
      camenisch_shoup_vector_length);

  SchemeParameters scheme_parameters;
  SchemeParametersV0* scheme_parameters_v0 =
      scheme_parameters.mutable_scheme_parameters_v0();
  scheme_parameters_v0->set_security_parameter(kDefaultSecurityParameter);
  scheme_parameters_v0->set_challenge_length_bits(kDefaultChallengeLength);
  scheme_parameters_v0->set_modulus_length_bits(modulus_length_bits);
  scheme_parameters_v0->set_camenisch_shoup_s(kDefaultCamenischShoupS);
  scheme_parameters_v0->set_vector_encryption_length(
      camenisch_shoup_vector_length);
  scheme_parameters_v0->set_pedersen_batch_size(pedersen_batch_size);
  scheme_parameters_v0->set_prf_ec_group(kDefaultCurveId);
  scheme_parameters_v0->set_random_oracle_prefix(random_oracle_prefix);

  return scheme_parameters;
}

}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute
