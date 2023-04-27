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

#ifndef PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_V0_PARAMETERS_H_
#define PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_V0_PARAMETERS_H_

#include <string>

#include "act/act.pb.h"
#include "private_join_and_compute/crypto/ec_group.h"

namespace private_join_and_compute {
namespace anonymous_counting_tokens {

const int kDefaultSecurityParameter = 128;
const int kDefaultChallengeLength = 128;
const int kDefaultCamenischShoupS = 1;
const int kDefaultCurveId = NID_X9_62_prime256v1;
const int kDefaultModulusLengthBits = 3072;

// Returns parameters appropriate only for testing (smaller modulus of 1536
// bits, smaller batch size of 3).
SchemeParameters ActV0TestSchemeParameters();

// Returns parameters supporting 16 messages in a batch, with both Pedersen and
// CS parameters set to 16, and modulus length 3072.
SchemeParameters ActV0Batch16SchemeParameters();

// Returns parameters supporting 32 messages in a batch, with both Pedersen and
// CS parameters set to 32, and modulus length 3072.
SchemeParameters ActV0Batch32SchemeParameters();

// Returns parameters supporting 32 messages in a batch, with CS vector
// encryption length set to 2, and modulus length 2048.
//
// These parameters are currently the best-optimized for performance.
SchemeParameters
ActV0SchemeParametersPedersen32Modulus2048CamenischShoupVector2();

// Returns custom parameters.
SchemeParameters ActV0SchemeParameters(int pedersen_batch_size,
                                       int modulus_length_bits,
                                       int camenisch_shoup_vector_length);

}  // namespace anonymous_counting_tokens
}  // namespace private_join_and_compute

#endif  // PRIVATE_JOIN_AND_COMPUTE_ANONYMOUS_COUNTING_TOKENS_ACT_V0_PARAMETERS_H_
