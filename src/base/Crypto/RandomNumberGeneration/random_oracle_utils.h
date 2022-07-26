//
// Copyright (C) 2021 Stealth Software Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Description:
//   Various implementations of Random Oracles.

#ifndef RANDOM_ORACLE_UTILS_H
#define RANDOM_ORACLE_UTILS_H

#include "Crypto/RandomNumberGeneration/prg_utils.h"

namespace crypto {

enum class RandomOracleType {
  NONE,
  AES_ENCRYPT_PLUS_PRG,
  SHA_256,
};

// Holds all of the input parameters required to perform evaluation
// of a Random Oracle.
struct RandomOracleParams {
  RandomOracleType type_;

  // Domain and range size of the RO.
  // NOTE: The former is used by RandomOracleType::SHA_256, the latter is
  // not presently used by any actual code (but is provided as a natural
  // extension of the former). RandomOracleType::AES_ENCRYPT_PLUS_PRG doesn't
  // use either of these, but instead populates the corresponding fields
  // of prg_params_ (see below).
  uint64_t num_domain_bits_;
  uint64_t num_range_bits_;

  // In case the RO uses a PRG as a subroutine, this field holds the
  // necessary parameters to apply the PRG.
  random_number::PseudoRandomGeneratorParams prg_params_;

  RandomOracleParams() {
    type_ = RandomOracleType::NONE;
    num_domain_bits_ = 0;
    num_range_bits_ = 0;
  }
};

// Implementation of RO of type AES_ENCRYPT_PLUS_PRG.
// This RO maps: Z_N x {0, 1}^lambda -> {0, 1}^s, via:
//          RO(m, k) = PRG(E_k(m | m | ... | m)), where:
//   - N = 2^64, and so first input is an uint64_t value (8 bytes)
//   - lambda = security parameter (for underlying AES encryption)
//   - s is arbitrary, and is specified by prg_params.range_bits_
//   - E_k(): AES-encryption under (lambda-bit) key 'k'
//   - (m | m | ... | m): Represents the binary representation of m, concatenated
//     with itself enough times to form a lambda-bit input (for common/current
//     parameters, lambda = 128, and since m is 8 bytes = 64 bits, we'll just need
//     to concatenate once: (m | m)
//   - PRG: {0, 1}^lambda -> {0, 1}^s. Currently, this PRG is instantiated via
//     ApplyAesPrg(), which is defined as:
//        PRG(x) = AES_x(0) | AES_x(1) | ... | AES_x(s / 128)
// More specifically, this RO is defined as follows:
//   - lambda must match one of the supported key sizes for AES Encryption
//     (see aes*_encrypt in Crypto/Encryption/windows_encryption_utils.h).
//   - The value 'm' is treated as a sequence of 64 (= CHAR_BIT * sizeof(uint64_t)
//     bits; and this sequence is repeated (concatenated with itself) until
//     lambda bits are formed. If 64 does not divide lambda, then the number of times
//     m can be concatenated with itself to form lambda bits won't be exact; in
//     this case, the last concatenation will contain the trailing bits
//     of the sequence of bits representing m. NOTE: We demand that
//       64 <= lambda,
//     so that we don't introduce obvious collisions in the RO.
//     Let m' denote this sequence of lambda bits.
//  - Succinctly: RO(input) = PRG(E_k(m'))
// where:
//   m = value represented by first 8 bytes of input
//   m' = m | m | ... | m (lambda / num_bits_in_m blocks of m-binary string)
//   lambda = CHAR_BIT * (input.size() - 8) (Also, should have prg_params.domain_bits_ = lambda)
//   s = specified by user, in prg_params.range_bits_
//   AES-key = input[8], ..., input.back()
// On input, prg_params should have type_ = AES_W_INPUT_AS_KEY and have
// range_bits_ set as desired.
// Output is put in (the back of) output (i.e. 'output' is not overwritten,
// so existing bytes will remain, and new RO bytes are appended).
// Number of bytes in output will be prg_params.range_bits_ / CHAR_BIT
// (in case prg_params.range_bits_ is not evenly divisible by CHAR_BIT,
// one extra byte of randomness will have been generated; user can ignore
// the extra bits (e.g. by ignoring the first bits of the first byte of
// output).
extern bool AesPlusPrgROEvaluate(
    const random_number::PseudoRandomGeneratorParams& prg_params,
    const uint64_t& num_input_bytes,
    const unsigned char* input,
    std::vector<unsigned char>* output);
// Same as above, with alternate API.
inline bool AesPlusPrgROEvaluate(
    const random_number::PseudoRandomGeneratorParams& prg_params,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output) {
  return AesPlusPrgROEvaluate(prg_params, input.size(), input.data(), output);
}

// SHA256. num_domain_bits / 8 should equal input.size(). At the end, output
// will have size 256 / 8.
extern bool ShaROEvaluate(
    const uint64_t& num_input_bytes,
    const unsigned char* input,
    std::vector<unsigned char>* output);
inline bool ShaROEvaluate(
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output) {
  return ShaROEvaluate(input.size(), input.data(), output);
}

// Evaluates a Random Oracle according to params. Output is put in
// (the back of) output (i.e. 'output' is not overwritten, so existing
// bytes will remain, and new RO bytes are appended).
extern bool ROEvaluate(
    const RandomOracleParams& params,
    const uint64_t& num_input_bytes,
    const unsigned char* input,
    std::vector<unsigned char>* output);
inline bool ROEvaluate(
    const RandomOracleParams& params,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output) {
  return ROEvaluate(params, input.size(), input.data(), output);
}

}  // namespace crypto

#endif
