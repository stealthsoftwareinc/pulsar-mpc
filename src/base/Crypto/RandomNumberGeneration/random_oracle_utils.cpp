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

#include "random_oracle_utils.h"

#include "Crypto/Encryption/aes_utils.h"
#include "Crypto/RandomNumberGeneration/prg_utils.h"
#include "global_utils.h"

#include <cstring>

// For Nettle's sha256_XXX()
#include <nettle/sha2.h>

using namespace crypto::encryption;
using namespace crypto::random_number;
using namespace string_utils;
using namespace std;

namespace crypto {

bool AesPlusPrgROEvaluate(
    const PseudoRandomGeneratorParams& prg_params,
    const uint64_t& num_input_bytes,
    const unsigned char* input,
    vector<unsigned char>* output) {
  if (num_input_bytes < 1 + sizeof(uint64_t)) {
    DLOG_ERROR("Not enough bytes in input: " + Itoa(num_input_bytes));
    return false;
  }

  // Extract the first sizeof(uint64_t) bytes of input as value 'm'.
  const uint64_t m = *((const uint64_t*) input);

  // Extract the next bytes as 'key'.
  vector<unsigned char> key;
  key.insert(key.begin(), input + sizeof(uint64_t), input + num_input_bytes);
  //PHBkey.insert(key.begin(), input.begin() + sizeof(uint64_t), input.end());
  const uint64_t key_bytes = key.size();

  // The sequence of bytes representing the value 'm' will be repeated,
  // forming a sequence of key_bytes bytes. Make sure sizeof(uint64_t) <= key_bytes.
  if (key_bytes < sizeof(uint64_t)) {
    DLOG_ERROR(
        "Cannot represent 'm' (" + Itoa(m) + ") in 'key.size()' bytes (" +
        Itoa(key_bytes));
    return false;
  }

  // Form the concatenated string: (binary) m | (binary) m | ... | (binary) m
  vector<unsigned char> m_repeated(
      sizeof(uint64_t) * (key_bytes / sizeof(uint64_t)));
  for (size_t i = 0; i < key_bytes / sizeof(uint64_t); ++i) {
    memcpy(
        m_repeated.data() + sizeof(uint64_t) * i,
        (unsigned char*) &m,
        sizeof(uint64_t));
  }
  // If sizeof(uint64_t) does not divide key_bytes, complete m_repeated (so that it is
  // exactly key_bytes bytes) by using (the appropriate number of) trailing
  // bytes of m. Note: Since key_bytes >= sizeof(uint64_t), we can just use the first
  // bytes of key_bytes to grab the trailing bytes of m.
  const int num_bytes_needed = key_bytes % sizeof(uint64_t);
  for (int i = 0; i < num_bytes_needed; ++i) {
    m_repeated.push_back(m_repeated[sizeof(uint64_t) - num_bytes_needed + i]);
  }

  // Perform AES encryption (under key) of plaintext 'm_repeated'.
  vector<unsigned char> aes_ciphertext;
  AesParams aes_params;
  aes_params.use_type_ = UseType::PRG;
  if (!AesEncrypt(aes_params, key, m_repeated, &aes_ciphertext)) {
    DLOG_ERROR("ROEvaluate Failed: Underlying AesEncrypt failed.");
    return false;
  }

  // Run the underlying PRG to get the RO output.
  return ApplyPrg(prg_params, aes_ciphertext, output);
}

bool ShaROEvaluate(
    const uint64_t& num_input_bytes,
    const unsigned char* input,
    vector<unsigned char>* output) {
  sha256_ctx sha_ctx;
  sha256_init(&sha_ctx);
  sha256_update(&sha_ctx, num_input_bytes, input);
  output->resize(32);
  sha256_digest(&sha_ctx, SHA256_DIGEST_SIZE, output->data());
  return true;
}

bool ROEvaluate(
    const RandomOracleParams& params,
    const uint64_t& num_input_bytes,
    const unsigned char* input,
    vector<unsigned char>* output) {
  switch (params.type_) {
    case RandomOracleType::NONE:
      return false;
    case RandomOracleType::AES_ENCRYPT_PLUS_PRG:
      return AesPlusPrgROEvaluate(
          params.prg_params_, num_input_bytes, input, output);
    case RandomOracleType::SHA_256:
      return ShaROEvaluate(num_input_bytes, input, output);
    default: {
      return false;
    }
  }

  return true;
}

}  // namespace crypto
