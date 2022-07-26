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

#include "aes_utils.h"
#include "Crypto/RandomNumberGeneration/random_utils.h"
#include "global_utils.h"

#include <climits>  // For CHAR_BIT
#include <cstring>  // For mem* operations.
#include <vector>

using namespace string_utils;
using namespace std;

namespace crypto {
namespace encryption {

// The supported AES Key sizes (in bits).
const uint64_t kAesKeySizes[] = {128, 256};

// The number of bytes in AES key.
static const int kNumBytesInAes128Key = 128 / CHAR_BIT;
static const int kNumBytesInAes256Key = 256 / CHAR_BIT;

const int kNumBlocksInAes128Schedule = 11;  // 10 rounds.
const int kNumBlocksInAes256Schedule = 15;  // 14 rounds.

// For Aes-Encryption when EncryptionKeyType is RANDOM, we need to store
// the (encrypted) randomly generated (symmetric) encryption key. I don't
// know how many bytes this key may be; in tests, I've seen it be 140 bytes.
// Encryption will fail if we don't set this large enough; so pick something
// bigger than 140. Note that picking something too big is okay, as we'll
// resize the storage container appropriately; we just need to make sure
// to allocate enough bytes ahead of time.
// TODO(PHB): Determine if there is a way to know what to set this to.
static const unsigned long kMaxEncryptedAes128KeySize = 512;
static const unsigned long kMaxEncryptedAes256KeySize = 1024;

bool IsValidAesKey(const uint64_t& key) {
  for (const uint64_t& valid_key : kAesKeySizes) {
    if (key == valid_key) return true;
  }
  return false;
}

bool GetNumAesKeyBytes(const uint64_t& input_bytes, uint64_t* key_bytes) {
  for (const uint64_t& key_bits : kAesKeySizes) {
    if (key_bits / CHAR_BIT >= input_bytes) {
      *key_bytes = key_bits / CHAR_BIT;
      return true;
    }
  }
  return false;
}

bool IsCompatibleAesParams(const AesParams& params) {
  // Sanity check EncryptionKeyType is compatible with EncryptionPlatform.
  if (params.key_type_ == EncryptionKeyType::PASSWORD &&
      params.platform_ != EncryptionPlatform::PLATFORM) {
    return false;
  }
  if (params.key_type_ == EncryptionKeyType::SCHEDULE &&
      params.platform_ != EncryptionPlatform::NATIVE) {
    return false;
  }

  // Sanity-check only one of UseType or Encryption mode was specified, or
  // if both are specified, that they are consistent.
  if (params.use_type_ != UseType::UNKNOWN &&
      params.mode_ != EncryptionMode::UNKNOWN) {
    if (params.use_type_ == UseType::PRG &&
        params.mode_ != EncryptionMode::ECB) {
      return false;
    }
    if (params.use_type_ == UseType::ENC &&
        params.mode_ == EncryptionMode::ECB) {
      return false;
    }
  }

  // ENC mode not currently supported for NATIVE.
  if ((params.use_type_ == UseType::ENC || params.mode_ == EncryptionMode::CBC ||
       params.mode_ == EncryptionMode::CTR) &&
      params.platform_ == EncryptionPlatform::NATIVE) {
    return false;
  }

  // CBC mode note currently supported for NETTLE.
  if (params.mode_ == EncryptionMode::CBC &&
      params.platform_ == EncryptionPlatform::NETTLE) {
    return false;
  }

  return true;
}

AesBlock CharVectorTo128Bits(
    const uint8_t* const input, const size_t input_size) {
  return AesBlock::FromBytes(input, input + input_size);
}

AesBlock CharVectorTo128Bits(const uint8_t* const input) {
  return CharVectorTo128Bits(input, kNumBytesInAesBlock);
}

AesBlock CharVectorTo128Bits(
    const vector<uint8_t>& input, const size_t start_index) {
  if (input.size() <= start_index)
    LOG_FATAL("Bad input to CharVectorTo128Bits()");
  return AesBlock::FromBytes(input.cbegin() + start_index, input.cend());
}

AesBlock CharVectorTo128Bits(const vector<uint8_t>& input) {
  return CharVectorTo128Bits(input, 0);
}

void CharVectorToVectorOf128Bits(
    const vector<uint8_t>& input, AesBlock* const output) {
  if (output == nullptr) LOG_FATAL("Null input to CharVectorToVectorOf128Bits.");
  if (input.size() % kNumBytesInAes128Key != 0) {
    LOG_FATAL(
        "Bad input size (" + Itoa((uint64_t) input.size()) +
        ") to CharVectorToVectorOf128Bits.");
  }
  const size_t num_outputs = input.size() / kNumBytesInAes128Key;
  for (size_t i = 0; i < num_outputs; ++i) {
    output[i] = CharVectorTo128Bits(input, kNumBytesInAes128Key * i);
  }
}

void Native128BitsToCharVector(
    const AesBlock& input, vector<uint8_t>* const output) {
  const size_t orig_output_size = output->size();
  output->resize(orig_output_size + kNumBytesInAes128Key);
  input.ToBytes(output->begin() + orig_output_size);
}

void VectorOf128BitsToCharVector(
    const size_t num_inputs,
    const AesBlock* const input,
    vector<uint8_t>* const output) {
  for (size_t i = 0; i < num_inputs; ++i) {
    Native128BitsToCharVector(input[i], output);
  }
}

void CreateScheduleFromKey(const Aes128Key& k, Aes128EncKey* const ek) {
  *ek = Aes128EncKey(k);
}

void CreateDecryptionScheduleFromEncryptionSchedule(
    const Aes128EncKey& ek, Aes128DecKey* const dk) {
  *dk = Aes128DecKey(ek);
}

void CreateDecryptionScheduleFromEncryptionKey(
    const Aes128Key& k, Aes128DecKey* const dk) {
  *dk = Aes128DecKey(k);
}

#if (AES_UTILS_HAVE_AESNI)
AesniAesBlock::AesniAesBlock() { b_ = _mm_setzero_si128(); }
AesniAesBlock::AesniAesBlock(const uint8_t* const b) {
  b_ = _mm_set_epi8(
      b[15],
      b[14],
      b[13],
      b[12],
      b[11],
      b[10],
      b[9],
      b[8],
      b[7],
      b[6],
      b[5],
      b[4],
      b[3],
      b[2],
      b[1],
      b[0]);
}
AesniAesBlock::AesniAesBlock(const uint64_t b) {
  b_ = _mm_set_epi32(
      0, 0, static_cast<uint32_t>(b >> 32), static_cast<uint32_t>(b >> 0));
}

AesniAesBlock AesniAesBlock::operator&(const AesniAesBlock& other) const {
  return AesniAesBlock(_mm_and_si128(b_, other.b_));
}

AesniAesBlock AesniAesBlock::operator^(const AesniAesBlock& other) const {
  return AesniAesBlock(_mm_xor_si128(b_, other.b_));
}

void AesniAesBlock::operator&=(const AesniAesBlock& other) {
  b_ = b_ & other.b_;
}

void AesniAesBlock::operator^=(const AesniAesBlock& other) {
  b_ = b_ ^ other.b_;
}

/*
  bool AesniAesBlock::operator==(const AesniAesBlock& other) const {
    // The following snippet is from stackoverflow, for comparing two __m128i
    // values, and should be updated accordingly with (a, b) -> (b_, other.b_).
    __m128i vcmp = (__m128i)_mm_cmpneq_ps(a, b); // compare a, b for inequality
    uint16_t test = _mm_movemask_epi8(vcmp); // extract results of comparison
    if (test == 0xffff)
        // *all* elements not equal
    else if (test != 0)
        // *some* elements not equal
    else
        // no elements not equal, i.e. all elements equal
  }
  bool AesniAesBlock::operator!=(const AesniAesBlock& other) const {
    return !(*this == other);
  }
  */

void AesniAesBlock::ToByteArray(uint8_t* input) const {
  *input++ = (uint8_t) _mm_extract_epi8(b_, 0);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 1);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 2);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 3);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 4);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 5);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 6);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 7);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 8);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 9);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 10);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 11);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 12);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 13);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 14);
  *input++ = (uint8_t) _mm_extract_epi8(b_, 15);
}

AesniAes128EncKey::AesniAes128EncKey(const AesniAes128Key& key) {
  w_[0].b_ = key.b_;
  w_[1].b_ =
      Aes128ExpandHelper(w_[0].b_, _mm_aeskeygenassist_si128(w_[0].b_, 1));
  w_[2].b_ =
      Aes128ExpandHelper(w_[1].b_, _mm_aeskeygenassist_si128(w_[1].b_, 2));
  w_[3].b_ =
      Aes128ExpandHelper(w_[2].b_, _mm_aeskeygenassist_si128(w_[2].b_, 4));
  w_[4].b_ =
      Aes128ExpandHelper(w_[3].b_, _mm_aeskeygenassist_si128(w_[3].b_, 8));
  w_[5].b_ =
      Aes128ExpandHelper(w_[4].b_, _mm_aeskeygenassist_si128(w_[4].b_, 16));
  w_[6].b_ =
      Aes128ExpandHelper(w_[5].b_, _mm_aeskeygenassist_si128(w_[5].b_, 32));
  w_[7].b_ =
      Aes128ExpandHelper(w_[6].b_, _mm_aeskeygenassist_si128(w_[6].b_, 64));
  w_[8].b_ =
      Aes128ExpandHelper(w_[7].b_, _mm_aeskeygenassist_si128(w_[7].b_, 128));
  w_[9].b_ =
      Aes128ExpandHelper(w_[8].b_, _mm_aeskeygenassist_si128(w_[8].b_, 27));
  w_[10].b_ =
      Aes128ExpandHelper(w_[9].b_, _mm_aeskeygenassist_si128(w_[9].b_, 54));
}

AesniAesBlock AesniAes128EncKey::Aes128Encrypt(const AesniAesBlock& x) const {
  __m128i y;
  y = _mm_xor_si128(x, w_[0]);
  y = _mm_aesenc_si128(y, w_[1]);
  y = _mm_aesenc_si128(y, w_[2]);
  y = _mm_aesenc_si128(y, w_[3]);
  y = _mm_aesenc_si128(y, w_[4]);
  y = _mm_aesenc_si128(y, w_[5]);
  y = _mm_aesenc_si128(y, w_[6]);
  y = _mm_aesenc_si128(y, w_[7]);
  y = _mm_aesenc_si128(y, w_[8]);
  y = _mm_aesenc_si128(y, w_[9]);
  y = _mm_aesenclast_si128(y, w_[10]);
  return AesniAesBlock(y);
}

void AesniAes128EncKey::ToNativeType(__m128i* output) const {
  for (size_t i = 0; i < 11; ++i) {
    *output++ = w_[i].b_;
  }
}

__m128i AesniAes128EncKey::Aes128ExpandHelper(
    const __m128i& a, const __m128i& b) {
  __m128i c;
  c = a;
  c = _mm_xor_si128(c, _mm_slli_si128(a, 4));
  c = _mm_xor_si128(c, _mm_slli_si128(a, 8));
  c = _mm_xor_si128(c, _mm_slli_si128(a, 12));
  c = _mm_xor_si128(c, _mm_shuffle_epi32(b, 255));
  return c;
}

AesniAes128DecKey::AesniAes128DecKey(const AesniAes128EncKey& ek) {
  // Decryption key (schedule) is the reverse of the encryption key (schedule).
  w_[0] = ek.w_[10];
  for (int i = 1; i < 10; ++i) {
    w_[i] = _mm_aesimc_si128(ek.w_[10 - i]);
  }
  w_[10] = ek.w_[0];
}

AesniAesBlock AesniAes128DecKey::Aes128Decrypt(const AesniAesBlock& y) const {
  __m128i x;
  x = _mm_xor_si128(y, w_[0]);
  x = _mm_aesdec_si128(x, w_[1]);
  x = _mm_aesdec_si128(x, w_[2]);
  x = _mm_aesdec_si128(x, w_[3]);
  x = _mm_aesdec_si128(x, w_[4]);
  x = _mm_aesdec_si128(x, w_[5]);
  x = _mm_aesdec_si128(x, w_[6]);
  x = _mm_aesdec_si128(x, w_[7]);
  x = _mm_aesdec_si128(x, w_[8]);
  x = _mm_aesdec_si128(x, w_[9]);
  x = _mm_aesdeclast_si128(x, w_[10]);
  return x;
}

void AesniAes128DecKey::ToNativeType(__m128i* output) const {
  for (size_t i = 0; i < 11; ++i) {
    *output++ = w_[i].b_;
  }
}

#endif

// ============================= AES-128 PLATFORM ENCRYPT ========================
// API's 1 + 2 + 3.
bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  if (type == EncryptionKeyType::KEY && key.size() != kNumBytesInAes128Key) {
    DLOG_ERROR(
        "Failed to Aes128PlatformEncrypt(): key size (" +
        Itoa((uint64_t) key.size()) +
        ") "
        "doesn't match kNumBytesInAes128Key (" +
        Itoa(kNumBytesInAes128Key) + ")");
    return false;
  }
  if (mode == EncryptionMode::ECB && input.size() > kNumBytesInAes128Key) {
    LOG_ERROR("ECB mode not valid for more than 128 bits.");
    return false;
  }

  // Size output to match the size of input, possibly + 16 if the number of
  // bytes in input is not divisible by 16 (= 128 / CHAR_BIT).
  if (input.size() > UINT_MAX) {
    LOG_FATAL("Too many bytes to encrypt: " + Itoa((uint64_t) input.size()));
  }
  const uint32_t num_input_bytes = (uint32_t) input.size();
  const uint32_t num_remainder_bytes = num_input_bytes % kNumBytesInAes128Key;
  const uint32_t num_output_bytes = num_input_bytes +
      (num_remainder_bytes == 0 ? 0 :
                                  (kNumBytesInAes128Key - num_remainder_bytes));
  const size_t original_size = output->size();
  output->resize(original_size + num_output_bytes);

  if (type == EncryptionKeyType::KEY) {
    PlatformAes128Encrypt(
        key.data(),
        num_input_bytes,
        input.data(),
        num_output_bytes,
        output->data() + original_size,
        mode);
  } else if (type == EncryptionKeyType::PASSWORD) {
    PlatformAes128Encrypt(
        (uint32_t) key.size(),
        key.data(),
        num_input_bytes,
        input.data(),
        num_output_bytes,
        output->data() + original_size,
        mode);
  } else if (type == EncryptionKeyType::RANDOM) {
    if (decryption_key != nullptr) {
      decryption_key->resize(kMaxEncryptedAes128KeySize);
    }
    uint32_t actual_dec_key_size = 0;
    PlatformAes128Encrypt(
        num_input_bytes,
        input.data(),
        num_output_bytes,
        output->data() + original_size,
        (uint32_t) decryption_key->size(),
        decryption_key->data(),
        &actual_dec_key_size,
        mode);
    if (decryption_key != nullptr) {
      decryption_key->resize(actual_dec_key_size);
    }
  } else {
    LOG_ERROR("Unsupported EncryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  return true;
}

// API's 1 + 2 + 3, Batch mode.
bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {
  if (type == EncryptionKeyType::KEY && key.size() != kNumBytesInAes128Key) {
    DLOG_ERROR(
        "Failed to Aes128PlatformEncrypt(): key size (" +
        Itoa((uint64_t) key.size()) +
        "( "
        "doesn't match kNumBytesInAes128Key (" +
        Itoa(kNumBytesInAes128Key) + ")");
    return false;
  }

  // The underlying AES128-Encrypt function will concatenate all of
  // the ciphertexts into a single sequence of continguous bytes. Since
  // vector<vector<unsigned char>> is *not* contiguous, we cannot simply
  // pass in output->data() to the underlying AES128-Encrypt function.
  // Insted, we'll create a temporary structure for holding the (continugous)
  // ciphertexts, and upon return, we'll copy these into output.
  // Similarly, the plaintext messages is assumed to be a contiguous block of
  // (concatenated) bytes, so we'll need to copy 'inputs' into a single vector.
  if (inputs.size() > UINT_MAX) {
    LOG_FATAL("Too many bytes to encrypt: " + Itoa((uint64_t) inputs.size()));
  }
  const uint32_t num_messages = (uint32_t) inputs.size();
  vector<unsigned char> plaintexts;
  uint32_t plaintext_sizes[num_messages];
  uint32_t ciphertext_sizes[num_messages];
  uint32_t total_ciphertexts_size = 0;
  for (size_t i = 0; i < num_messages; ++i) {
    // Size output to match the size of input, possibly + 16 if the number of
    // bytes in input is not divisible by 16 (= 128 / CHAR_BIT).
    if (inputs[i].size() > UINT_MAX) {
      LOG_FATAL(
          "Too many bytes to encrypt: " + Itoa((uint64_t) inputs[i].size()));
    }
    const uint32_t num_input_bytes = (uint32_t) inputs[i].size();
    if (mode == EncryptionMode::ECB && num_input_bytes > kNumBytesInAes128Key) {
      LOG_ERROR(
          "Message " + Itoa((uint64_t) i + 1) +
          " too big: ECB mode can be "
          "applied to plaintexts of size at most 128 bits.");
      return false;
    }
    const int num_remainder_bytes = num_input_bytes % kNumBytesInAes128Key;
    const uint32_t num_output_bytes = num_input_bytes +
        (num_remainder_bytes == 0 ?
             0 :
             (kNumBytesInAes128Key - num_remainder_bytes));
    plaintext_sizes[i] = num_input_bytes;
    ciphertext_sizes[i] = num_output_bytes;
    total_ciphertexts_size += num_output_bytes;
    plaintexts.insert(plaintexts.end(), inputs[i].begin(), inputs[i].end());
  }
  vector<unsigned char> ciphertexts(total_ciphertexts_size);

  if (type == EncryptionKeyType::KEY) {
    PlatformAes128Encrypt(
        num_messages,
        key.data(),
        plaintext_sizes,
        plaintexts.data(),
        ciphertext_sizes,
        ciphertexts.data(),
        mode);
  } else if (type == EncryptionKeyType::PASSWORD) {
    PlatformAes128Encrypt(
        num_messages,
        (uint32_t) key.size(),
        key.data(),
        plaintext_sizes,
        plaintexts.data(),
        ciphertext_sizes,
        ciphertexts.data(),
        mode);
  } else if (type == EncryptionKeyType::RANDOM) {
    if (decryption_key != nullptr) {
      decryption_key->resize(kMaxEncryptedAes128KeySize);
    }
    uint32_t actual_dec_key_size = 0;
    PlatformAes128Encrypt(
        num_messages,
        plaintext_sizes,
        plaintexts.data(),
        ciphertext_sizes,
        ciphertexts.data(),
        (uint32_t) decryption_key->size(),
        decryption_key->data(),
        &actual_dec_key_size,
        mode);
    if (decryption_key != nullptr) {
      decryption_key->resize(actual_dec_key_size);
    }
  } else {
    LOG_ERROR("Unsupported EncryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  // Now copy data from ciphertexts to output.
  uint32_t current_index = 0;
  for (const uint32_t current_ciphertext_size : ciphertext_sizes) {
    outputs->push_back(vector<unsigned char>());
    outputs->back().insert(
        outputs->back().end(),
        ciphertexts.data() + current_index,
        ciphertexts.data() + current_index + current_ciphertext_size);
    current_index += current_ciphertext_size;
  }

  return true;
}

// API 1 + 2.
bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  return Aes128PlatformEncrypt(mode, type, key, input, nullptr, output);
}
// API 1 + 2, Batch mode.
bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  return Aes128PlatformEncrypt(mode, type, key, inputs, nullptr, outputs);
}
// API 3.
bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  return Aes128PlatformEncrypt(
      mode,
      EncryptionKeyType::RANDOM,
      vector<unsigned char>(),
      input,
      decryption_key,
      output);
}
// API 3, Batch mode.
bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {
  return Aes128PlatformEncrypt(
      mode,
      EncryptionKeyType::RANDOM,
      vector<unsigned char>(),
      inputs,
      decryption_key,
      outputs);
}

// ============================= AES-128 NETTLE ENCRYPT ========================
// API's 1 and 3.
bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  if (mode == EncryptionMode::ECB) {
    return Aes128NettleBlockEncrypt(type, key, input, decryption_key, output);
  }

  if (type == EncryptionKeyType::RANDOM) {
    vector<unsigned char> temp_key;
    vector<unsigned char>* key_ptr =
        (decryption_key == nullptr ? &temp_key : decryption_key);
    crypto::random_number::RandomBytes(kNumBytesInAes128Key, key_ptr);
    aes128_ctx context;
    aes128_set_encrypt_key(&context, key_ptr->data());
    return Aes128NettleEncrypt(&context, input, output);
  } else if (type == EncryptionKeyType::KEY) {
    if (key.size() != kNumBytesInAes128Key) {
      DLOG_ERROR(
          "Failed to Aes128NettleEncrypt(): wrong key size (" +
          Itoa((uint64_t) key.size()) +
          ") for KeyType: " + Itoa(static_cast<int>(type)));
      return false;
    }
    aes128_ctx context;
    aes128_set_encrypt_key(&context, key.data());
    return Aes128NettleEncrypt(&context, input, output);
  } else {
    LOG_ERROR("Unsupported EncryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  return true;
}

// API's 1 and 3, Batch mode.
bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {
  if (mode == EncryptionMode::ECB) {
    return Aes128NettleBlockEncrypt(type, key, inputs, decryption_key, outputs);
  }

  // Set aes_ctx from key.
  aes128_ctx context;
  if (type == EncryptionKeyType::RANDOM) {
    vector<unsigned char> temp_key;
    vector<unsigned char>* key_ptr =
        (decryption_key == nullptr ? &temp_key : decryption_key);
    crypto::random_number::RandomBytes(kNumBytesInAes128Key, key_ptr);
    aes128_set_encrypt_key(&context, key_ptr->data());
  } else if (type == EncryptionKeyType::KEY) {
    if (key.size() != kNumBytesInAes128Key) {
      DLOG_ERROR(
          "Failed to Aes128NettleEncrypt(): wrong key size (" +
          Itoa((uint64_t) key.size()) +
          ") for KeyType: " + Itoa(static_cast<int>(type)));
      return false;
    }
    aes128_set_encrypt_key(&context, key.data());
  } else {
    LOG_ERROR("Unsupported EncryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  return Aes128NettleEncrypt(&context, inputs, outputs);
}

// API's 1 and 3, ECB mode.
bool Aes128NettleBlockEncrypt(
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  if (input.size() > kNumBytesInAes128Key)
    LOG_FATAL("Bad input to Aes128NettleBlockEncrypt");
  if (type == EncryptionKeyType::RANDOM) {
    vector<unsigned char> temp_key;
    vector<unsigned char>* key_ptr =
        (decryption_key == nullptr ? &temp_key : decryption_key);
    crypto::random_number::RandomBytes(kNumBytesInAes128Key, key_ptr);
    aes128_ctx context;
    aes128_set_encrypt_key(&context, key_ptr->data());
    return Aes128NettleBlockEncrypt(&context, input, output);
  } else if (type == EncryptionKeyType::KEY) {
    if (key.size() != kNumBytesInAes128Key) {
      DLOG_ERROR(
          "Failed to Aes128NettleBlockEncrypt(): wrong key size (" +
          Itoa((uint64_t) key.size()) +
          ") for KeyType: " + Itoa(static_cast<int>(type)));
      return false;
    }
    aes128_ctx context;
    aes128_set_encrypt_key(&context, key.data());
    return Aes128NettleBlockEncrypt(&context, input, output);
  } else {
    LOG_ERROR("Unsupported EncryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  return true;
}

// API's 1 and 3, ECB mode, Batch mode.
bool Aes128NettleBlockEncrypt(
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {
  if (outputs == nullptr) LOG_FATAL("Bad input to Aes128NettleBlockEncrypt.");
  // Set aes_ctx from key.
  aes128_ctx context;
  if (type == EncryptionKeyType::RANDOM) {
    vector<unsigned char> temp_key;
    vector<unsigned char>* key_ptr =
        (decryption_key == nullptr ? &temp_key : decryption_key);
    crypto::random_number::RandomBytes(kNumBytesInAes128Key, key_ptr);
    aes128_set_encrypt_key(&context, key_ptr->data());
  } else if (type == EncryptionKeyType::KEY) {
    if (key.size() != kNumBytesInAes128Key) {
      DLOG_ERROR(
          "Failed to Aes128NettleEncrypt(): wrong key size (" +
          Itoa((uint64_t) key.size()) +
          ") for KeyType: " + Itoa(static_cast<int>(type)));
      return false;
    }
    aes128_set_encrypt_key(&context, key.data());
  } else {
    LOG_ERROR("Unsupported EncryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  // Loop through inputs, encrypting each using aes_ctx.
  outputs->resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    if (!Aes128NettleBlockEncrypt(&context, inputs[i], &((*outputs)[i]))) {
      return false;
    }
  }

  return true;
}

// API 1.
bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  return Aes128NettleEncrypt(
      mode, EncryptionKeyType::KEY, key, input, nullptr, output);
}
// API 1, Batch mode.
bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  return Aes128NettleEncrypt(
      mode, EncryptionKeyType::KEY, key, inputs, nullptr, outputs);
}
// API 3.
bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  return Aes128NettleEncrypt(
      mode,
      EncryptionKeyType::RANDOM,
      vector<unsigned char>(),
      input,
      decryption_key,
      output);
}
// API 3, Batch mode.
bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {
  return Aes128NettleEncrypt(
      mode,
      EncryptionKeyType::RANDOM,
      vector<unsigned char>(),
      inputs,
      decryption_key,
      outputs);
}
// API 4: aes_ctx provided.
bool Aes128NettleEncrypt(
    aes128_ctx* context,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  const size_t orig_output_size = output->size();
  output->resize(orig_output_size + input.size());
  uint8_t zero[kNumBytesInAes128Key] = {0};
#if defined AWS_LINUX
  ctr_crypt(
      context,
      (nettle_crypt_func*) aes128_encrypt,
      kNumBytesInAes128Key,
      zero,
      input.size(),
      output->data() + orig_output_size,
      input.data());
#else
  ctr_crypt(
      context,
      (nettle_cipher_func*) aes128_encrypt,
      kNumBytesInAes128Key,
      zero,
      input.size(),
      output->data() + orig_output_size,
      input.data());
#endif

  return true;
}
// API 4: aes_ctx provided, Batch mode.
bool Aes128NettleEncrypt(
    aes128_ctx* context,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  if (outputs == nullptr) LOG_FATAL("Bad input to Aes128NettleEncrypt");
  outputs->resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const vector<unsigned char>& input_i = inputs[i];
    if (!Aes128NettleEncrypt(context, input_i, &((*outputs)[i]))) {
      return false;
    }
  }

  return true;
}

// API 4: aes_ctx provided, ECB mode.
bool Aes128NettleBlockEncrypt(
    aes128_ctx* context,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  if (input.size() > kNumBytesInAes128Key || output == nullptr) {
    LOG_FATAL("Bad input to Aes128NettleBlockEncrypt");
  }

  // aes_encrypt demands inputs of 128 bits, but this Aes128NettleBlockEncrypt()
  // function accepts inputs of fewer bits. 0-pad if necessary.
  vector<unsigned char> zero_padded_input;
  const size_t num_missing_bytes = kNumBytesInAes128Key - input.size();
  if (num_missing_bytes > 0) {
    zero_padded_input.resize(kNumBytesInAes128Key, (unsigned char) 0);
    for (size_t i = 0; i < input.size(); ++i) {
      zero_padded_input[num_missing_bytes + i] = input[i];
    }
  }
  const vector<unsigned char>& input_to_use =
      num_missing_bytes > 0 ? zero_padded_input : input;
  const size_t orig_output_size = output->size();
  output->resize(orig_output_size + kNumBytesInAes128Key);
  aes128_encrypt(
      context,
      kNumBytesInAes128Key,
      output->data() + orig_output_size,
      input_to_use.data());

  return true;
}
// API 4: aes_ctx provided, ECB mode, Batch mode.
bool Aes128NettleBlockEncrypt(
    aes128_ctx* context,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  if (outputs == nullptr) LOG_FATAL("Bad input to Aes128NettleBlockEncrypt");
  outputs->resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const vector<unsigned char>& input_i = inputs[i];
    if (!Aes128NettleBlockEncrypt(context, input_i, &((*outputs)[i]))) {
      return false;
    }
  }

  return true;
}

aes128_ctx AesCtxFromKey(const vector<unsigned char>& key) {
  aes128_ctx to_return;
  aes128_set_encrypt_key(&to_return, key.data());
  return to_return;
}

// ============================= AES-128 NATIVE ENCRYPT ========================
// API's 1 + 3.
bool Aes128NativeEncrypt(
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  // Currently, NATIVE encryption only supported for ECB mode, which is
  // insecure as a stream cipher, so we only allow encryption of (up to) one block.
  if (input.size() > kNumBytesInAes128Key) {
    LOG_FATAL("Aes128NativeEncrypt not supported for stream cipher mode");
  }

  const vector<unsigned char>* kv;
  vector<unsigned char> temp_key;
  if (type == EncryptionKeyType::RANDOM) {
    vector<unsigned char>* key_ptr =
        (decryption_key == nullptr) ? &temp_key : decryption_key;
    crypto::random_number::RandomBytes(kNumBytesInAes128Key, key_ptr);
    kv = key_ptr;
  } else if (type == EncryptionKeyType::KEY) {
    if (key.size() != kNumBytesInAes128Key) {
      DLOG_ERROR(
          "Failed to Aes128NativeEncrypt(): wrong key size (" +
          Itoa((uint64_t) key.size()) +
          ") for KeyType: " + Itoa(static_cast<int>(type)));
      return false;
    }
    kv = &key;
  } else {
    LOG_ERROR("Unsupported EncryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  const Aes128EncKey ek = Aes128EncKey(Aes128Key::FromBytes(kv->cbegin()));

  // Encrypt.
  Native128BitsToCharVector(
      ek.Aes128Encrypt(AesBlock::FromBytes(input.cbegin(), input.cend())),
      output);

  return true;
}

// API's 1 + 3, Batch mode.
bool Aes128NativeEncrypt(
    const EncryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {

  const vector<unsigned char>* kv;
  vector<unsigned char> temp_key;
  if (type == EncryptionKeyType::RANDOM) {
    vector<unsigned char>* key_ptr =
        (decryption_key == nullptr ? &temp_key : decryption_key);
    crypto::random_number::RandomBytes(kNumBytesInAes128Key, key_ptr);
    kv = key_ptr;
  } else if (type == EncryptionKeyType::KEY) {
    if (key.size() != kNumBytesInAes128Key) {
      DLOG_ERROR(
          "Failed to Aes128NativeEncrypt(): wrong key size (" +
          Itoa((uint64_t) key.size()) +
          ") for KeyType: " + Itoa(static_cast<int>(type)));
      return false;
    }
    kv = &key;
  } else {
    LOG_ERROR(
        "Bad type to Aes128NativeEncrypt: " + Itoa(static_cast<int>(type)));
    return false;
  }

  const Aes128EncKey ek = Aes128EncKey(Aes128Key::FromBytes(kv->cbegin()));

  // Loop through inputs, encrypting them one by one.
  outputs->resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const vector<unsigned char>& input_i = inputs[i];
    // Currently, NATIVE encryption only supported for ECB mode, which is
    // insecure as a stream cipher, so we only allow encryption of (up to) one block.
    if (input_i.size() > kNumBytesInAes128Key) {
      LOG_FATAL("Aes128NativeEncrypt not supported for stream cipher mode");
    }
    Native128BitsToCharVector(
        ek.Aes128Encrypt(AesBlock::FromBytes(input_i.cbegin(), input_i.cend())),
        &((*outputs)[i]));
  }

  return true;
}

// API 1.
bool Aes128NativeEncrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  return Aes128NativeEncrypt(
      EncryptionKeyType::KEY, key, input, nullptr, output);
}
// API 1, Batch mode.
bool Aes128NativeEncrypt(
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  return Aes128NativeEncrypt(
      EncryptionKeyType::KEY, key, inputs, nullptr, outputs);
}
// API 3.
bool Aes128NativeEncrypt(
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  return Aes128NativeEncrypt(
      EncryptionKeyType::RANDOM,
      vector<unsigned char>(),
      input,
      decryption_key,
      output);
}
// API 3, Batch mode.
bool Aes128NativeEncrypt(
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {
  return Aes128NativeEncrypt(
      EncryptionKeyType::RANDOM,
      vector<unsigned char>(),
      inputs,
      decryption_key,
      outputs);
}

// API 4.
AesBlock Aes128NativeEncrypt(const Aes128EncKey& ek, const AesBlock& input) {
  return ek.Aes128Encrypt(input);
}

/* DEPRECATED.
// API 4, Batch Mode.
bool Aes128NativeEncrypt(
    const int num_blocks, const __m128i* schedule, const __m128i* input,
    __m128i* output) {
  for (int i = 0; i < num_blocks; ++i) {
    output[i] = Aes128NativeEncrypt(schedule, *(input + i));
  }

  return true;
}
*/

// ================================== AES ENCRYPT ==============================
// Generic API, with AesParams.
bool AesEncrypt(
    const AesParams& params,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  const unsigned int num_key_bits =
      static_cast<unsigned int>(CHAR_BIT * key.size());
  if (!IsValidAesKey(num_key_bits)) {
    DLOG_ERROR("Failed to AesEncrypt: Invalid AES Key: " + Itoa(num_key_bits));
    return false;
  }
  if (!IsCompatibleAesParams(params)) {
    DLOG_ERROR("Failed to AesEncrypt: Incompatible AesParams");
    return false;
  }

  // Go through the valid key sizes, calling the appropriate AesXEncrypt().
  if (num_key_bits == 128) {
    if (params.platform_ == EncryptionPlatform::PLATFORM) {
      // Determine mode from params; or if not specified, default for
      // PLATFORM (currently only windows) is CBC.
      const EncryptionMode mode = params.mode_ != EncryptionMode::UNKNOWN ?
          params.mode_ :
          (params.use_type_ == UseType::UNKNOWN ?
               EncryptionMode::CBC :
               (params.use_type_ == UseType::PRG ? EncryptionMode::ECB :
                                                   EncryptionMode::CBC));
      return Aes128PlatformEncrypt(
          mode, params.key_type_, key, input, decryption_key, output);
    } else if (params.platform_ == EncryptionPlatform::NETTLE) {
      // Determine mode from params; or if not specified, default for
      // NETTLE is CTR.
      const EncryptionMode mode = params.mode_ != EncryptionMode::UNKNOWN ?
          params.mode_ :
          (params.use_type_ == UseType::UNKNOWN ?
               EncryptionMode::CTR :
               (params.use_type_ == UseType::PRG ? EncryptionMode::ECB :
                                                   EncryptionMode::CTR));
      return Aes128NettleEncrypt(
          mode, params.key_type_, key, input, decryption_key, output);
    } else {
      return Aes128NativeEncrypt(
          params.key_type_, key, input, decryption_key, output);
    }
    // TODO(PHB): Implement additional AesXEncrypt() functions for various
    // key_sizes X, based on params.platform_.
    //} else if (num_key_bits == 256) {
    //  return Aes256Encrypt(EncryptionKeyType::KEY, key, input, output);
  }

  // Couldn't find an implemented AesXEncrypt for X = num_key_bits.
  DLOG_ERROR("Failed to AesEncrypt: Unsupported AES Key: " + Itoa(num_key_bits));
  return false;
}

// Generic API, with AesParams, Batch mode.
bool AesEncrypt(
    const AesParams& params,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {
  const unsigned int num_key_bits =
      static_cast<unsigned int>(CHAR_BIT * key.size());
  if (!IsValidAesKey(num_key_bits)) {
    DLOG_ERROR("Failed to AesEncrypt: Invalid AES Key: " + Itoa(num_key_bits));
    return false;
  }
  if (!IsCompatibleAesParams(params)) {
    DLOG_ERROR("Failed to AesEncrypt: Incompatible AesParams");
    return false;
  }

  // Go through the valid key sizes, calling the appropriate AesXEncrypt().
  if (num_key_bits == 128) {
    if (params.platform_ == EncryptionPlatform::PLATFORM) {
      // Determine mode from params; or if not specified, default for
      // PLATFORM (currently only windows) is CBC.
      const EncryptionMode mode = params.mode_ != EncryptionMode::UNKNOWN ?
          params.mode_ :
          (params.use_type_ == UseType::UNKNOWN ?
               EncryptionMode::CBC :
               (params.use_type_ == UseType::PRG ? EncryptionMode::ECB :
                                                   EncryptionMode::CBC));
      return Aes128PlatformEncrypt(
          mode, params.key_type_, key, inputs, decryption_key, outputs);
    } else if (params.platform_ == EncryptionPlatform::NETTLE) {
      // Determine mode from params; or if not specified, default for
      // NETTLE is CTR.
      const EncryptionMode mode = params.mode_ != EncryptionMode::UNKNOWN ?
          params.mode_ :
          (params.use_type_ == UseType::UNKNOWN ?
               EncryptionMode::CTR :
               (params.use_type_ == UseType::PRG ? EncryptionMode::ECB :
                                                   EncryptionMode::CTR));
      return Aes128NettleEncrypt(
          mode, params.key_type_, key, inputs, decryption_key, outputs);
    } else {
      return Aes128NativeEncrypt(
          params.key_type_, key, inputs, decryption_key, outputs);
    }
    // TODO(PHB): Implement additional AesXEncrypt() functions for various
    // key_sizes X.
    //} else if (num_key_bits == 256) {
    //  return Aes256Encrypt(EncryptionKeyType::KEY, key, inputs, outputs);
  }

  // Couldn't find an implemented AesXEncrypt for X = num_key_bits.
  DLOG_ERROR("Failed to AesEncrypt: Unsupported AES Key: " + Itoa(num_key_bits));
  return false;
}

// Generic API, no AesParams.
bool AesEncrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* decryption_key,
    vector<unsigned char>* output) {
  const unsigned int num_key_bits =
      static_cast<unsigned int>(CHAR_BIT * key.size());
  if (!IsValidAesKey(num_key_bits)) {
    DLOG_ERROR("Failed to AesEncrypt: Invalid AES Key: " + Itoa(num_key_bits));
    return false;
  }

  // Go through the valid key sizes, calling the appropriate AesXEncrypt().
  if (num_key_bits == 128) {
    return Aes128NettleEncrypt(
        EncryptionMode::CTR,
        EncryptionKeyType::KEY,
        key,
        input,
        decryption_key,
        output);
    // TODO(PHB): Implement additional AesXEncrypt() functions for various
    // key_sizes X.
    //} else if (num_key_bits == 256) {
    //  return Aes256Encrypt(EncryptionKeyType::KEY, key, input, output);
  }

  // Couldn't find an implemented AesXEncrypt for X = num_key_bits.
  DLOG_ERROR("Failed to AesEncrypt: Unsupported AES Key: " + Itoa(num_key_bits));
  return false;
}

// Generic API, no AesParams, Batch mode.
bool AesEncrypt(
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<unsigned char>* decryption_key,
    vector<vector<unsigned char>>* outputs) {
  const unsigned int num_key_bits =
      static_cast<unsigned int>(CHAR_BIT * key.size());
  if (!IsValidAesKey(num_key_bits)) {
    DLOG_ERROR("Failed to AesEncrypt: Invalid AES Key: " + Itoa(num_key_bits));
    return false;
  }

  // Go through the valid key sizes, calling the appropriate AesXEncrypt().
  if (num_key_bits == 128) {
    return Aes128NettleEncrypt(
        EncryptionMode::CTR,
        EncryptionKeyType::KEY,
        key,
        inputs,
        decryption_key,
        outputs);
    // TODO(PHB): Implement additional AesXEncrypt() functions for various
    // key_sizes X.
    //} else if (num_key_bits == 256) {
    //  return Aes256Encrypt(EncryptionKeyType::KEY, key, inputs, outputs);
  }

  // Couldn't find an implemented AesXEncrypt for X = num_key_bits.
  DLOG_ERROR("Failed to AesEncrypt: Unsupported AES Key: " + Itoa(num_key_bits));
  return false;
}

// ================================== DECRYPT ==================================

bool Aes128PlatformDecrypt(
    const EncryptionMode mode,
    const DecryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  if (input.size() > UINT_MAX) {
    LOG_FATAL("Too many bytes to decrypt: " + Itoa((uint64_t) input.size()));
  }
  if (type == DecryptionKeyType::KEY && key.size() != kNumBytesInAes128Key) {
    DLOG_ERROR(
        "Failed to Aes128PlatformDecrypt(): key size (" +
        Itoa((uint64_t) key.size()) +
        "( "
        "doesn't match kNumBytesInAes128Key (" +
        Itoa(kNumBytesInAes128Key) + ")");
    return false;
  }
  if (mode == EncryptionMode::ECB && input.size() != kNumBytesInAes128Key) {
    LOG_ERROR("ECB mode not valid for blocks of size != 128 bits.");
    return false;
  }

  // Size output to match the size of input.
  const size_t original_size = output->size();
  output->resize(original_size + input.size());

  if (type == DecryptionKeyType::KEY) {
    PlatformAes128Decrypt(
        key.data(),
        (uint32_t) input.size(),
        input.data(),
        (uint32_t) input.size(),
        output->data() + original_size,
        mode);
  } else if (type == DecryptionKeyType::PASSWORD) {
    PlatformAes128Decrypt(
        false,
        (uint32_t) key.size(),
        key.data(),
        (uint32_t) input.size(),
        input.data(),
        (uint32_t) input.size(),
        output->data() + original_size,
        mode);
  } else if (type == DecryptionKeyType::RANDOM) {
    PlatformAes128Decrypt(
        true,
        (uint32_t) key.size(),
        key.data(),
        (uint32_t) input.size(),
        input.data(),
        (uint32_t) input.size(),
        output->data() + original_size,
        mode);
  } else {
    LOG_ERROR("Unsupported DecryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  return true;
}

// Batch mode.
bool Aes128PlatformDecrypt(
    const EncryptionMode mode,
    const DecryptionKeyType type,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  if (type == DecryptionKeyType::KEY && key.size() != kNumBytesInAes128Key) {
    DLOG_ERROR(
        "Failed to Aes128PlatformDecrypt(): key size (" +
        Itoa((uint64_t) key.size()) +
        "( "
        "doesn't match kNumBytesInAes128Key (" +
        Itoa(kNumBytesInAes128Key) + ")");
    return false;
  }

  // The underlying AES128-Decrypt function will write concatenate all of
  // the plaintext into a single sequence of continguous bytes. Since
  // vector<vector<unsigned char>> is *not* contiguous, we cannot simply
  // pass in output->data() to the underlying AES128-Decrypt function.
  // Insted, we'll create a temporary structure for holding the (continugous)
  // plaintexts, and upon return, we'll copy these into output.
  // Similarly, the ciphertext messages is assumed to be a contiguous block of
  // (concatenated) bytes, so we'll need to copy 'inputs' into a single vector.
  if (inputs.size() > UINT_MAX) {
    LOG_FATAL("Too many bytes to decrypt: " + Itoa((uint64_t) inputs.size()));
  }
  const uint32_t num_messages = (uint32_t) inputs.size();
  vector<unsigned char> ciphertexts;
  uint32_t plaintext_sizes[num_messages];
  uint32_t total_plaintexts_size = 0;
  for (size_t i = 0; i < num_messages; ++i) {
    // Size output to match the size of input.
    if (inputs[i].size() > UINT_MAX) {
      LOG_FATAL(
          "Too many bytes to encrypt: " + Itoa((uint64_t) inputs[i].size()));
    }
    const uint32_t num_input_bytes = (uint32_t) inputs[i].size();
    if (num_input_bytes % kNumBytesInAes128Key != 0 ||
        (mode == EncryptionMode::ECB &&
         num_input_bytes != kNumBytesInAes128Key)) {
      LOG_ERROR(
          "Unexpected number of bytes in ciphertext " + Itoa((uint64_t) i + 1));
      return false;
    }
    plaintext_sizes[i] = num_input_bytes;
    total_plaintexts_size += num_input_bytes;
    ciphertexts.insert(ciphertexts.end(), inputs[i].begin(), inputs[i].end());
  }
  vector<unsigned char> plaintexts(total_plaintexts_size);

  if (type == DecryptionKeyType::KEY) {
    PlatformAes128Decrypt(
        num_messages,
        key.data(),
        plaintext_sizes,
        ciphertexts.data(),
        plaintext_sizes,
        plaintexts.data(),
        mode);
  } else if (type == DecryptionKeyType::PASSWORD) {
    PlatformAes128Decrypt(
        num_messages,
        false,
        (uint32_t) key.size(),
        key.data(),
        plaintext_sizes,
        ciphertexts.data(),
        plaintext_sizes,
        plaintexts.data(),
        mode);
  } else if (type == DecryptionKeyType::RANDOM) {
    PlatformAes128Decrypt(
        num_messages,
        true,
        (uint32_t) key.size(),
        key.data(),
        plaintext_sizes,
        ciphertexts.data(),
        plaintext_sizes,
        plaintexts.data(),
        mode);
  } else {
    LOG_ERROR("Unsupported DecryptionKeyType: " + Itoa(static_cast<int>(type)));
    return false;
  }

  // Now copy data from plaintexts to output.
  uint32_t current_index = 0;
  for (const uint32_t current_plaintext_size : plaintext_sizes) {
    outputs->push_back(vector<unsigned char>());
    outputs->back().insert(
        outputs->back().end(),
        plaintexts.data() + current_index,
        plaintexts.data() + current_index + current_plaintext_size);
    current_index += current_plaintext_size;
  }

  return true;
}

// API 1.
bool Aes128NettleDecrypt(
    const EncryptionMode mode,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  if (key.size() != kNumBytesInAes128Key) {
    DLOG_ERROR(
        "Failed to Aes128NettleDecrypt(): wrong key size (" +
        Itoa((uint64_t) key.size()) + ").");
    return false;
  }
  aes128_ctx context;
  if (mode == EncryptionMode::ECB) {
    aes128_set_decrypt_key(&context, key.data());
    return Aes128NettleBlockDecrypt(&context, input, output);
  } else {
    // CTR mode uses same context for encrypt as decrypt.
    aes128_set_encrypt_key(&context, key.data());
    return Aes128NettleDecrypt(&context, input, output);
  }
}

// API 1, Batch mode.
bool Aes128NettleDecrypt(
    const EncryptionMode mode,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  if (outputs == nullptr || key.size() != kNumBytesInAes128Key) {
    LOG_FATAL("Bad input to Aes128NettleDecrypt.");
  }
  // Set aes_ctx from key.
  aes128_ctx context;
  if (mode == EncryptionMode::ECB) {
    aes128_set_decrypt_key(&context, key.data());
    // Loop through inputs, decrypting each using aes_ctx.
    for (const vector<unsigned char>& input_i : inputs) {
      outputs->push_back(vector<unsigned char>());
      if (!Aes128NettleBlockDecrypt(&context, input_i, &(outputs->back()))) {
        return false;
      }
    }
  } else {
    // CTR mode uses same context for encrypt as decrypt.
    aes128_set_encrypt_key(&context, key.data());
    // Loop through inputs, decrypting each using aes_ctx.
    for (const vector<unsigned char>& input_i : inputs) {
      outputs->push_back(vector<unsigned char>());
      if (!Aes128NettleDecrypt(&context, input_i, &(outputs->back()))) {
        return false;
      }
    }
  }

  return true;
}

// API 4.
bool Aes128NettleDecrypt(
    aes128_ctx* context,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  const size_t orig_output_size = output->size();
  output->resize(orig_output_size + input.size());
  uint8_t zero[kNumBytesInAes128Key] = {0};
#if defined AWS_LINUX
  ctr_crypt(
      context,
      (nettle_crypt_func*) aes128_encrypt,
      kNumBytesInAes128Key,
      zero,
      input.size(),
      output->data() + orig_output_size,
      input.data());
#else
  ctr_crypt(
      context,
      (nettle_cipher_func*) aes128_encrypt,
      kNumBytesInAes128Key,
      zero,
      input.size(),
      output->data() + orig_output_size,
      input.data());
#endif
  return true;
}

// API 4, Batch mode.
bool Aes128NettleDecrypt(
    aes128_ctx* context,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  if (outputs == nullptr) LOG_FATAL("Bad input to Aes128NettleDecrypt.");
  for (const vector<unsigned char>& input_i : inputs) {
    outputs->push_back(vector<unsigned char>());
    if (!Aes128NettleDecrypt(context, input_i, &(outputs->back()))) {
      return false;
    }
  }
  return true;
}

// API 4, ECB Mode.
bool Aes128NettleBlockDecrypt(
    aes128_ctx* context,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  if (output == nullptr || input.size() != kNumBytesInAes128Key) {
    LOG_FATAL("Bad input to Aes128NettleBlockDecrypt.");
  }
  const size_t orig_output_size = output->size();
  output->resize(orig_output_size + input.size());
  aes128_decrypt(
      context,
      kNumBytesInAes128Key,
      output->data() + orig_output_size,
      input.data());
  return true;
}

// API 4, ECB mode, Batch mode.
bool Aes128NettleBlockDecrypt(
    aes128_ctx* context,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  if (outputs == nullptr) LOG_FATAL("Bad input to Aes128NettleBlockDecrypt.");
  for (const vector<unsigned char>& input_i : inputs) {
    outputs->push_back(vector<unsigned char>());
    if (!Aes128NettleBlockDecrypt(context, input_i, &(outputs->back()))) {
      return false;
    }
  }
  return true;
}

// API 1.
bool Aes128NativeDecrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  // NATIVE Encrypt/Decrypt currently only supported in ECB mode, so all
  // ciphertexts should be 128 bits.
  if (output == nullptr || input.size() != kNumBytesInAes128Key) {
    LOG_FATAL("Bad input to Aes128NativeDecrypt.");
  }
  if (key.size() != kNumBytesInAes128Key) {
    DLOG_ERROR(
        "Failed to Aes128NativeDecrypt(): wrong key size (" +
        Itoa((uint64_t) key.size()) + ".");
    return false;
  }

  // Use API 4 for batch decrypt.
  // DEPRECATED. NATIVE Encrypt/Decrypt currently only supported in ECB mode,
  // which is only secure for a single block. I'll keep this code around for
  // demonstrative purposes, in case this ever changes.
  /*
  const size_t num_blocks = input.size() / kNumBytesInAes128Key;
  __m128i* input_as_bits = new __m128i[num_blocks];
  __m128i* output_as_bits = new __m128i[num_blocks];
  CharVectorToVectorOf128Bits(input, input_as_bits);
  Aes128NativeDecrypt(num_blocks, schedule, input_as_bits, output_as_bits);
  VectorOf128BitsToCharVector(num_blocks, output_as_bits, output);
  // Clean-up.
  delete[] input_as_bits;
  delete[] output_as_bits;
  */

  Aes128DecKey const dk = Aes128DecKey(Aes128Key::FromBytes(key.cbegin()));

  // Decrypt.
  Native128BitsToCharVector(
      dk.Aes128Decrypt(AesBlock::FromBytes(input.cbegin())), output);

  return true;
}

// API 1, Batch mode.
bool Aes128NativeDecrypt(
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  Aes128DecKey const dk = Aes128DecKey(Aes128Key::FromBytes(key.cbegin()));

  // Loop through inputs, encrypting them one by one.
  outputs->resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const vector<unsigned char>& input_i = inputs[i];
    if (input_i.size() != kNumBytesInAes128Key) {
      LOG_ERROR(
          "Unexpected ciphertext size: " + Itoa((uint64_t) input_i.size()));
      return false;
    }
    Native128BitsToCharVector(
        dk.Aes128Decrypt(AesBlock::FromBytes(input_i.cbegin())),
        &((*outputs)[i]));
  }

  return true;
}

// API 4.
AesBlock Aes128NativeDecrypt(Aes128DecKey const& dk, AesBlock const& input) {
  return dk.Aes128Decrypt(input);
}

/* DEPRECATED.
// API 4, Batch mode.
bool Aes128NativeDecrypt(
    const int num_blocks, const __m128i* schedule, const __m128i* input,
    __m128i* output) {
  // Decryption is the same as Encryption, just with the reversed schedule
  // (schdule is assumed to already have been reversed upon input here).
  return Aes128NativeEncrypt(num_blocks, schedule, input, output);
}
*/

// ================================== AES DECRYPT ==============================
// Generic API for AES-Decryption.
bool AesDecrypt(
    const AesParams& params,
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  const unsigned int num_key_bits =
      static_cast<unsigned int>(CHAR_BIT * key.size());
  if (!IsValidAesKey(num_key_bits)) {
    DLOG_ERROR("Failed to AesDecrypt: Invalid AES Key: " + Itoa(num_key_bits));
    return false;
  }
  if (params.key_type_ == EncryptionKeyType::RANDOM ||
      !IsCompatibleAesParams(params)) {
    DLOG_ERROR("Failed to AesDecrypt: Incompatible AesParams");
    return false;
  }

  // Go through the valid key sizes, calling the appropriate AesXEncrypt().
  if (num_key_bits == 128) {
    if (params.platform_ == EncryptionPlatform::PLATFORM) {
      // Determine mode from params; or if not specified, default for
      // PLATFORM (currently only windows) is CBC.
      const EncryptionMode mode = params.mode_ != EncryptionMode::UNKNOWN ?
          params.mode_ :
          (params.use_type_ == UseType::UNKNOWN ?
               EncryptionMode::CBC :
               (params.use_type_ == UseType::PRG ? EncryptionMode::ECB :
                                                   EncryptionMode::CBC));
      return Aes128PlatformDecrypt(mode, params.key_type_, key, input, output);
    } else if (params.platform_ == EncryptionPlatform::NETTLE) {
      // Determine mode from params; or if not specified, default for
      // NETTLE is CTR.
      const EncryptionMode mode = params.mode_ != EncryptionMode::UNKNOWN ?
          params.mode_ :
          (params.use_type_ == UseType::UNKNOWN ?
               EncryptionMode::CTR :
               (params.use_type_ == UseType::PRG ? EncryptionMode::ECB :
                                                   EncryptionMode::CTR));
      return Aes128NettleDecrypt(mode, key, input, output);
    } else {
      return Aes128NativeDecrypt(key, input, output);
    }
    // TODO(PHB): Implement additional AesXDecrypt() functions for various
    // key_sizes X.
    //} else if (num_key_bits == 256) {
    //  return Aes256Decrypt(DecryptionKeyType::KEY, key, input, output);
  }

  // Couldn't find an implemented AesXDecrypt for X = num_key_bits.
  DLOG_ERROR("Failed to AesDecrypt: Unsupported AES Key: " + Itoa(num_key_bits));
  return false;
}

// Generic API for AES-Decryption, Batch mode.
bool AesDecrypt(
    const AesParams& params,
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  const unsigned int num_key_bits =
      static_cast<unsigned int>(CHAR_BIT * key.size());
  if (!IsValidAesKey(num_key_bits)) {
    DLOG_ERROR("Failed to AesDecrypt: Invalid AES Key: " + Itoa(num_key_bits));
    return false;
  }
  if (params.key_type_ == EncryptionKeyType::RANDOM ||
      !IsCompatibleAesParams(params)) {
    DLOG_ERROR("Failed to AesDecrypt: Incompatible AesParams");
    return false;
  }

  // Go through the valid key sizes, calling the appropriate AesXEncrypt().
  if (num_key_bits == 128) {
    if (params.platform_ == EncryptionPlatform::PLATFORM) {
      // Determine mode from params; or if not specified, default for
      // PLATFORM (currently only windows) is CBC.
      const EncryptionMode mode = params.mode_ != EncryptionMode::UNKNOWN ?
          params.mode_ :
          (params.use_type_ == UseType::UNKNOWN ?
               EncryptionMode::CBC :
               (params.use_type_ == UseType::PRG ? EncryptionMode::ECB :
                                                   EncryptionMode::CBC));
      return Aes128PlatformDecrypt(mode, params.key_type_, key, inputs, outputs);
    } else if (params.platform_ == EncryptionPlatform::NETTLE) {
      // Determine mode from params; or if not specified, default for
      // NETTLE is CTR.
      const EncryptionMode mode = params.mode_ != EncryptionMode::UNKNOWN ?
          params.mode_ :
          (params.use_type_ == UseType::UNKNOWN ?
               EncryptionMode::CTR :
               (params.use_type_ == UseType::PRG ? EncryptionMode::ECB :
                                                   EncryptionMode::CTR));
      return Aes128NettleDecrypt(mode, key, inputs, outputs);
    } else {
      return Aes128NativeDecrypt(key, inputs, outputs);
    }
    // TODO(PHB): Implement additional AesXDecrypt() functions for various
    // key_sizes X.
    //} else if (num_key_bits == 256) {
    //  return Aes256Decrypt(DecryptionKeyType::KEY, key, inputs, outputs);
  }

  // Couldn't find an implemented AesXDecrypt for X = num_key_bits.
  DLOG_ERROR("Failed to AesDecrypt: Unsupported AES Key: " + Itoa(num_key_bits));
  return false;
}

// Generic API for AES-Decryption, no AesParams.
bool AesDecrypt(
    const vector<unsigned char>& key,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  const unsigned int num_key_bits =
      static_cast<unsigned int>(CHAR_BIT * key.size());
  if (!IsValidAesKey(num_key_bits)) {
    DLOG_ERROR("Failed to AesDecrypt: Invalid AES Key: " + Itoa(num_key_bits));
    return false;
  }

  // Go through the valid key sizes, calling the appropriate AesXEncrypt().
  if (num_key_bits == 128) {
    return Aes128NettleDecrypt(EncryptionMode::CTR, key, input, output);
    // TODO(PHB): Implement additional AesXDecrypt() functions for various
    // key_sizes X.
    //} else if (num_key_bits == 256) {
    //  return Aes256Decrypt(DecryptionKeyType::KEY, key, input, output);
  }

  // Couldn't find an implemented AesXDecrypt for X = num_key_bits.
  DLOG_ERROR("Failed to AesDecrypt: Unsupported AES Key: " + Itoa(num_key_bits));
  return false;
}

// Generic API for AES-Decryption, no AesParams, Batch mode.
bool AesDecrypt(
    const vector<unsigned char>& key,
    const vector<vector<unsigned char>>& inputs,
    vector<vector<unsigned char>>* outputs) {
  const unsigned int num_key_bits =
      static_cast<unsigned int>(CHAR_BIT * key.size());
  if (!IsValidAesKey(num_key_bits)) {
    DLOG_ERROR("Failed to AesDecrypt: Invalid AES Key: " + Itoa(num_key_bits));
    return false;
  }

  // Go through the valid key sizes, calling the appropriate AesXEncrypt().
  if (num_key_bits == 128) {
    return Aes128NettleDecrypt(EncryptionMode::CTR, key, inputs, outputs);
    // TODO(PHB): Implement additional AesXDecrypt() functions for various
    // key_sizes X.
    //} else if (num_key_bits == 256) {
    //  return Aes256Decrypt(DecryptionKeyType::KEY, key, inputs, outputs);
  }

  // Couldn't find an implemented AesXDecrypt for X = num_key_bits.
  DLOG_ERROR("Failed to AesDecrypt: Unsupported AES Key: " + Itoa(num_key_bits));
  return false;
}

}  // namespace encryption
}  // namespace crypto
