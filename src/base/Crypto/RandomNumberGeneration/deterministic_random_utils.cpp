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

#include "deterministic_random_utils.h"

#include "GenericUtils/char_casting_utils.h"
#include "MathUtils/constants.h"  // For slice
#include "global_utils.h"

#include <cstring>  // For memset.
#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <vector>

using namespace math_utils;
using namespace string_utils;
using namespace std;

namespace crypto {
namespace random_number {

static const int kBytesInAesKey = 16;
static bool kIsSeedInitialized = false;
static uint8_t kCounter[16] = {0};
static aes128_ctx kAesContext;

void ClearRandomSeed() {
  kIsSeedInitialized = false;
  for (int i = 0; i < 16; ++i) {
    *(kCounter + i) = (uint8_t) 0;
  }
}

bool RandomBit(const vector<unsigned char>& seed) {
  return RandomByte(seed) & (unsigned char) 1;
}

unsigned char RandomByte(const vector<unsigned char>& seed) {
  unsigned char to_return = 0;
  RandomBytes(seed, 1, &to_return);
  return to_return;
}

void RandomBytes(
    const vector<unsigned char>& seed,
    const uint64_t& num_bytes,
    vector<unsigned char>* buffer) {
  uint64_t orig_size = buffer->size();
  buffer->resize(orig_size + num_bytes, (unsigned char) 0);
  RandomBytes(seed, num_bytes, buffer->data() + orig_size);
}

void RandomBytes(
    const vector<unsigned char>& seed,
    const uint64_t& num_bytes,
    unsigned char* buffer) {
  // Set kAesContext, if not done already.
  if (!kIsSeedInitialized) {
    aes128_set_encrypt_key(&kAesContext, seed.data());
    kIsSeedInitialized = true;
  }

  uint64_t num_remaining_bytes = num_bytes;
  uint64_t current_chunk_size;
  uint64_t current_index = 0;
  while (num_remaining_bytes > 0) {
    current_chunk_size = num_remaining_bytes <= UINT_MAX ?
        num_remaining_bytes :
        UINT_MAX / kBytesInAesKey * kBytesInAesKey;
    memset(buffer + current_index, 0, current_chunk_size);
#if defined AWS_LINUX
    ctr_crypt(
        &kAesContext,
        (nettle_crypt_func*) aes128_encrypt,
        kBytesInAesKey,
        kCounter,
        current_chunk_size,
        buffer + current_index,
        buffer + current_index);
#else
    ctr_crypt(
        &kAesContext,
        (nettle_cipher_func*) aes128_encrypt,
        kBytesInAesKey,
        kCounter,
        current_chunk_size,
        buffer + current_index,
        buffer + current_index);
#endif
    current_index += current_chunk_size;
    num_remaining_bytes -= current_chunk_size;
  }
}

slice RandomSlice(const vector<unsigned char>& seed) {
  vector<unsigned char> buffer;
  RandomBytes(seed, sizeof(slice), &buffer);
  return CharVectorToSlice(buffer);
}

uint32_t Random32BitInt(const vector<unsigned char>& seed) {
  vector<unsigned char> buffer;
  RandomBytes(seed, (sizeof(uint32_t)), &buffer);
  return CharVectorToValue<uint32_t>(buffer);
}

uint64_t Random64BitInt(const vector<unsigned char>& seed) {
  vector<unsigned char> buffer;
  RandomBytes(seed, (sizeof(uint64_t)), &buffer);
  return CharVectorToValue<uint64_t>(buffer);
}

unsigned short RandomShortInt(const vector<unsigned char>& seed) {
  vector<unsigned char> buffer;
  RandomBytes(seed, (sizeof(unsigned short)), &buffer);
  return CharVectorToValue<unsigned short>(buffer);
}

uint32_t RandomInModulus(
    const vector<unsigned char>& seed, const uint32_t& modulus) {
  uint32_t to_return;
  if (!RandomInModulus(seed, modulus, &to_return)) {
    return 0;
  }
  return to_return;
}

uint64_t RandomInModulus(
    const vector<unsigned char>& seed, const uint64_t& modulus) {
  uint64_t to_return;
  if (!RandomInModulus(seed, modulus, &to_return)) {
    return 0;
  }
  return to_return;
}

bool RandomInModulus(
    const vector<unsigned char>& seed,
    const uint32_t& modulus,
    uint32_t* random) {
  if (modulus == 1) {
    *random = 0;
    return true;
  }

  // Get the number of bytes in modulus (to get a range for how big of a
  // number to generate).
  int bits = 1;
  uint64_t temp = 2;
  uint32_t mask = 1;
  while (temp < modulus) {
    bits++;
    temp *= 2;
    mask *= 2;
    mask |= 1;
  }

  const int bytes = bits / CHAR_BIT + (bits % CHAR_BIT > 0);

  vector<unsigned char> buffer;
  do {
    buffer.clear();
    RandomBytes(seed, bytes, &buffer);

    // Cast randomly generated bytes as an uint32. We treat the leading bytes
    // of buffer as the least-significant, since 'bytes' may be less than
    // sizeof(uint32_t), in which case only the first elements of buffer
    // are valid/set (in RandomBytes() above); plus, since this is just
    // generating random values, there is no need to e.g. preserve endianess.
    *random = uint32_t(buffer[0]);
    for (int i = 1; i < bytes; ++i) {
      *random |= ((uint32_t) buffer[i]) << (CHAR_BIT * i);
    }

    // Adjust random as necessary:
    // If bits is not a multiple of 8 (CHAR_BIT), then there will be extra
    // random bits that were generated (This is a product of being forced to
    // use a RandomBytes() call instead of RandomBits()).
    // Clear those extra random bits, to increase the chance that the random
    // value generated is actually smaller than 'modulus'.
    *random &= mask;
    // Make sure the random number generated is within [0..modulus].
    // NOTE: Since we generated randomness in [0..2^bits - 1], in the worst case,
    // modulus = 2^b, in which case bits = b + 1, and then there is (roughly) a
    // 50% chance random > modulus.
  } while (*random >= modulus);

  return true;
}

bool RandomInModulus(
    const vector<unsigned char>& seed,
    const uint64_t& modulus,
    uint64_t* random) {
  if (modulus <= 0 || modulus > std::numeric_limits<uint64_t>::max()) {
    LOG_FATAL("Bad input to RandomInModulus().");
  }
  if (modulus <= 0) LOG_FATAL("Bad input to RandomInModulus().");
  if (modulus == 1) {
    *random = 0;
    return true;
  }

  // Get the number of bytes in modulus (to get a range for how big of a
  // number to generate).
  int bits = 1;
  uint64_t temp = 2;
  uint64_t mask = 1;
  while (temp < modulus) {
    bits++;
    temp *= 2;
    mask *= 2;
    mask |= 1;
  }

  const int bytes = bits / CHAR_BIT + (bits % CHAR_BIT > 0);

  vector<unsigned char> buffer;
  do {
    buffer.clear();
    RandomBytes(seed, bytes, &buffer);

    // Cast randomly generated bytes as an uint64. We treat the leading bytes
    // of buffer as the least-significant, since 'bytes' may be less than
    // sizeof(uint64_t), in which case only the first elements of buffer
    // are valid/set (in RandomBytes() above); plus, since this is just
    // generating random values, there is no need to e.g. preserve endianess.
    *random = uint64_t(buffer[0]);
    for (int i = 1; i < bytes; ++i) {
      *random |= ((uint64_t) buffer[i]) << (CHAR_BIT * i);
    }

    // Adjust random as necessary:
    // If bits is not a multiple of 8 (CHAR_BIT), then there will be extra
    // random bits that were generated (This is a product of being forced to
    // use a RandomBytes() call instead of RandomBits()).
    // Clear those extra random bits, to increase the chance that the random
    // value generated is actually smaller than 'modulus'.
    *random &= mask;
    // Make sure the random number generated is within [0..modulus].
    // NOTE: Since we generated randomness in [0..2^bits - 1], in the worst case,
    // modulus = 2^b, in which case bits = b + 1, and then there is (roughly) a
    // 50% chance random > modulus.
  } while (*random >= modulus);

  return true;
}

}  // namespace random_number
}  // namespace crypto
