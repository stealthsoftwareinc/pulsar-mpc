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

#include "prg_utils.h"

#include "Crypto/Encryption/aes_utils.h"
#include "GenericUtils/char_casting_utils.h"
#include "StringUtils/string_utils.h"

#include <climits>  // For CHAR_BIT
#include <cstdint>  // For [u]int64_t
#include <memory>  // For unique_ptr
#include <vector>

using string_utils::Itoa;
using namespace crypto::encryption;
using namespace std;

namespace crypto {
namespace random_number {

// It may or may not be a good idea (in terms of security of the PRG) to allow an
// under-specified AES-Key for PRG's implemented via PRGType::AES_W_INPUT_AS_KEY.
// We control whether this is allowed via following global flag, which defaults
// to false, so that users must explicitly override value (via
// SetAllowUnderSpecifiedAesKey()) in order to allow it.
static bool kAllowUnderSpecifiedAesKey = false;
void SetAllowUnderSpecifiedAesKey(const bool set_to) {
  kAllowUnderSpecifiedAesKey = set_to;
}

bool ApplyAesPrg(
    const uint64_t& num_output_bits,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  if (output == nullptr) LOG_FATAL("Null input to ApplyAesPrg()");
  const size_t orig_input_bytes = input.size();
  uint64_t key_bytes = 0;
  if (!GetNumAesKeyBytes(orig_input_bytes, &key_bytes) ||
      key_bytes < sizeof(unsigned long) ||
      !IsValidAesKey(key_bytes * CHAR_BIT) ||
      (!kAllowUnderSpecifiedAesKey && orig_input_bytes < key_bytes)) {
    LOG_ERROR(
        "Bad key size (" + Itoa(key_bytes * CHAR_BIT) +
        " bits). "
        "For AES key less than " +
        string_utils::Itoa(sizeof(unsigned long)) +
        " bytes, you need to update the way you form the fixed plaintext "
        "(i.e. it shouldn't be a sequence of unsigned long ints).");
    return false;
  }

  // 0-pad input to be full AES-key size, if necessary.
  const vector<unsigned char>* input_ptr = &input;
  vector<unsigned char> zero_padded_input;
  if (orig_input_bytes < key_bytes) {
    zero_padded_input = input;
    zero_padded_input.resize(key_bytes);
    for (uint64_t i = 0; i < key_bytes - orig_input_bytes; ++i) {
      zero_padded_input[orig_input_bytes + i] = 0;
    }
    input_ptr = &zero_padded_input;
  }

  const uint64_t key_bits = key_bytes * CHAR_BIT;
  const uint64_t num_output_bytes =
      num_output_bits / CHAR_BIT + (num_output_bits % CHAR_BIT == 0 ? 0 : 1);
  const uint64_t orig_output_size = output->size();
  const uint64_t final_output_size = orig_output_size + num_output_bytes;

  // The AesPrg works by encrypting a fixed plaintext string (of the appropriate
  // number of bytes) under key = 'input'. Create the plaintext string, which
  // is simply a sequence of bytes:
  //   (key_bytes) 0 | (key_bytes) 1 | ... | (key_bytes) (m - 1),
  // where:
  //   N = Number of bytes in AES key (input.size()); i.e. N = num_key_bits / CHAR_BIT
  //   m = num_output_bits / num_key_bits; or possibly 1 more than this if
  //       num_output_bits is not divisible by num_key_bits

  // There is some annoying things to handle if input.size() does not evenly
  // divide num_output_bits. We'll handle the "remainder" bytes first, and
  // then deal with the rest.
  const uint64_t m =
      num_output_bits / key_bits + (num_output_bits % key_bits == 0 ? 0 : 1);
  const uint64_t num_remainder_bits = num_output_bits % key_bits;
  unsigned long chunk_index = 0;
  if (num_remainder_bits != 0) {
    vector<unsigned char> first_fixed_plaintext_chunk(key_bytes, 0);

    if (!AesEncrypt(*input_ptr, first_fixed_plaintext_chunk, output)) {
      DLOG_ERROR("ApplyAesPrg Failed: Underlying AesEncrypt failed.");
      return false;
    }

    // This block (inside num_remainder_bits != 0) is meant to handle the extra
    // output bits (in case the number of bits in a ciphertext does not evenly
    // divide the number of output bits, so we create one extra ciphertext, but
    // the don't use all of its bits). Since we generated the full number of bits
    // (bytes) in an AES ciphertext block, get rid of the extra bytes:
    //   num_remainder_bytes = num_remainder_bits / CHAR_BIT +
    //                         num_remainder_bits % CHAR_BIT == 0 ? 0 : 1
    const size_t num_remainder_bytes = num_remainder_bits / CHAR_BIT +
        (num_remainder_bits % CHAR_BIT == 0 ? 0 : 1);
    const size_t new_output_size = output->size();
    output->erase(
        output->begin() + orig_output_size,
        output->begin() + (new_output_size - num_remainder_bytes));

    // Now, zero-out the leading bits of output, if necessary.
    // UPDATE: Actually, it is better to have the caller do this, as the
    // caller will have to deal with the fact that 'num_output_bits' is
    // actually represented in output.size() * CHAR_BIT bits; i.e. caller
    // will have to decide (in case CHAR_BIT does not divide num_output_bits)
    // which bits to ignore; its better here to keep the full randomness, in
    // case e.g. the caller decides to keep the *first* num_output_bits
    // bits of output, rather than the *last* num_output_bits.
    //const int num_remainder_bits_in_byte = num_remainder_bits % CHAR_BIT;
    //if (num_remainder_bits_in_byte != 0) {
    //  (*output)[orig_output_size] &=
    //      (unsigned char) (~((unsigned char) 0)) >>
    //      (CHAR_BIT - num_remainder_bits_in_byte);
    //}
    chunk_index = 1;
  }

  // The only bytes are the remainder bytes, if num_output_bits < key_bits.
  if (num_output_bits < key_bits) return true;

  // Now that the remainder bits have been handled, do the rest.
  vector<unsigned char> fixed_plaintext(num_output_bits / CHAR_BIT, 0);
  for (unsigned long i = chunk_index; i < m; ++i) {
    vector<unsigned char> current_plaintext_block;
    ValueToCharVector<unsigned long>(i, &current_plaintext_block);
    for (size_t j = 0; j < sizeof(unsigned long); ++j) {
      const unsigned long fixed_plaintext_block_index =
          num_remainder_bits == 0 ? i : i - 1;
      fixed_plaintext
          [fixed_plaintext_block_index * key_bytes +
           (key_bytes - sizeof(unsigned long)) + j] = current_plaintext_block[j];
    }
  }

  // Set PRG output:
  //   AES_PRG(input) = E_input(fixed_plaintext)
  // where E_input() represents AES encryption under key 'input'.
  if (!AesEncrypt(*input_ptr, fixed_plaintext, output)) {
    DLOG_ERROR("Failed to ApplyAesPrg: Underlying AesEncrypt failed.");
    return false;
  }

  // The underlying AES may not have fine-grained control of how many bytes it
  // outputs: output will be in chunks of AES-KEYSIZE (= input.size()) bytes.
  // Trim the output to be the appropriate number of bytes.
  // NOTE: Since this is a PRG, it doesn't really matter which bytes are trimmed,
  // so long as it is done in a consistent way (so that PRG is deterministic);
  // but since the PRG is appending bytes to output (as opposed to clearing it
  // and then writing to it), it is easier to trim the trailing bytes.
  if (output->size() > final_output_size) {
    output->resize(final_output_size);
  }

  return true;
}

bool ApplyFixedKeyAesPrg(
    const FixedKeyAesPrgParams& params,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  if (output == nullptr) LOG_FATAL("Null input to ApplyFixedKeyAesPrg()");
  if (params.implementation_type_ != EncryptionPlatform::PLATFORM &&
      params.implementation_type_ != EncryptionPlatform::NETTLE &&
      params.implementation_type_ != EncryptionPlatform::NATIVE) {
    LOG_FATAL("Bad input to ApplyFixedKeyAesPrg: Only supported "
              "implementation_types_ are: PLATFORM, NETTLE, NATIVE.");
  }
  if (params.aes_key_bits_ != 128) {
    LOG_FATAL("FixedKeyAes currently only supported for AES-128");
  }
  const size_t key_bytes = params.aes_key_bits_ / CHAR_BIT;
  const size_t input_bytes = input.size();
  if (input_bytes > key_bytes) {
    LOG_FATAL("FixedKeyAes cannot be applied to input bigger than AES key size "
              "(currently AES-128).");
  }
  // Sanity check that 'input' represents a valid input to the PRG, i.e.
  // that it lies in the domain of the PRG, i.e. that the number of bits
  // represented by 'input' is at most the number of bits in the PRG domain.
  const size_t domain_bytes = params.domain_bits_ / CHAR_BIT +
      (params.domain_bits_ % CHAR_BIT == 0 ? 0 : 1);
  if (input_bytes > domain_bytes) {
    LOG_FATAL(
        "Bad input to ApplyFixedKeyAesPrg: " + Itoa(input_bytes) + ", " +
        Itoa(params.domain_bits_));
  }

  // There are (currently) three options for how the Fixed-Aes PRG is
  // implemented, as determined by implementation_type_:
  //   - For EncryptionPlatform::PLATFORM, use params.fixed_keys_
  //   - For EncryptionPlatform::NATIVE, use params.schedules_
  //   - For EncryptionPlatform::NETTLE, use params.contexts_
  // For the latter two, schedules_ (resp. contexts_) may not be set yet,
  // as they can each be derived from fixed_keys_. If this is the case,
  // derive them now.
  const vector<vector<unsigned char>>& fixed_keys = params.fixed_keys_;
  size_t num_blocks;
  bool use_schedules_from_params = false;
  vector<Aes128EncKey> schedules_store;
  vector<Aes128EncKey>* schedules = nullptr;
  vector<aes128_ctx> contexts;
  if (params.implementation_type_ == EncryptionPlatform::PLATFORM) {
    num_blocks = fixed_keys.size();
  } else if (params.implementation_type_ == EncryptionPlatform::NATIVE) {
    // Get schedules for each key, either directly via params (if set), or
    // construct them from params.fixed_keys_.
    if (params.schedules_.empty()) {
      num_blocks = fixed_keys.size();
      schedules_store.reserve(num_blocks);
      for (size_t i = 0; i < num_blocks; ++i) {
        schedules_store.push_back(
            Aes128EncKey(CharVectorTo128Bits(fixed_keys[i])));
      }
      schedules = &schedules_store;
    } else {
      num_blocks = params.schedules_.size();
      use_schedules_from_params = true;
    }
  } else if (params.implementation_type_ == EncryptionPlatform::NETTLE) {
    // Get contexts for each key, either directly via params (if set), or
    // construct them from params.fixed_keys_.
    if (params.contexts_ == nullptr || params.contexts_->empty()) {
      num_blocks = fixed_keys.size();
      contexts.resize(num_blocks);
      for (size_t i = 0; i < num_blocks; ++i) {
        const vector<unsigned char>& fixed_key = fixed_keys[i];
        contexts[i] = AesCtxFromKey(fixed_key);
      }
    } else {
      num_blocks = params.contexts_->size();
    }
  }

  // Sanity-check sizes are compatible.
  const uint64_t& num_output_bits = params.range_bits_;
  if (num_blocks * 128 < num_output_bits) {
    LOG_FATAL(
        "Not enough fixed keys/schedules set in ApplyFixedKeyAesPrg(): " +
        Itoa(num_blocks) + ", " + Itoa(num_output_bits));
  }
  const uint64_t num_output_bytes =
      num_output_bits / CHAR_BIT + (num_output_bits % CHAR_BIT == 0 ? 0 : 1);
  const uint64_t orig_output_size = output->size();
  const uint64_t final_output_size = orig_output_size + num_output_bytes;
  output->resize(final_output_size);

  // Compute AES_k_i(x) for each key/schedule k_i.
  vector<AesBlock> output_as_bits;
  vector<unsigned char>* output_as_bytes = nullptr;
  if (params.implementation_type_ == EncryptionPlatform::PLATFORM) {
    output_as_bytes = new vector<unsigned char>();
    for (size_t i = 0; i < num_blocks; ++i) {
      if (!Aes128PlatformEncrypt(
              EncryptionMode::ECB,
              EncryptionKeyType::KEY,
              fixed_keys[i],
              input,
              output_as_bytes)) {
        DLOG_ERROR("Failed to Aes128PlatformEncrypt in ApplyFixedKeyAesPrg.");
        delete output_as_bytes;
        return false;
      }
    }
  } else if (params.implementation_type_ == EncryptionPlatform::NATIVE) {
    output_as_bits.reserve(num_blocks);
    const AesBlock x = CharVectorTo128Bits(input);
    for (size_t i = 0; i < num_blocks; ++i) {
      if (use_schedules_from_params) {
        output_as_bits.push_back(params.schedules_[i].Aes128Encrypt(x));
      } else {
        output_as_bits.push_back((*schedules)[i].Aes128Encrypt(x));
      }
    }
  } else if (params.implementation_type_ == EncryptionPlatform::NETTLE) {
    output_as_bytes = new vector<unsigned char>();
    for (size_t i = 0; i < num_blocks; ++i) {
      if (!Aes128NettleBlockEncrypt(
              contexts.empty() ? &((*params.contexts_)[i]) : &(contexts[i]),
              input,
              output_as_bytes)) {
        DLOG_ERROR("Failed to Aes128NettleEncrypt in ApplyFixedKeyAesPrg.");
        delete output_as_bytes;
        return false;
      }
    }
  }

  // Set output to be:
  //   (AES_k1(x) XOR x)  |  (AES_k2(x) XOR x)  |  ... | (AES_kn(x) XOR x)
  uint64_t num_bytes_still_needed = num_output_bytes;
  for (size_t i = 0; i < num_blocks; ++i) {
    uint64_t current_block_bytes = key_bytes;
    if (i == num_blocks - 1) {
      current_block_bytes = num_bytes_still_needed;
      if (current_block_bytes > key_bytes) {
        LOG_FATAL("To few schedules for desired output range.");
      }
    }
    vector<unsigned char> output_i;
    if (params.implementation_type_ == EncryptionPlatform::NATIVE) {
      Native128BitsToCharVector(output_as_bits[i], &output_i);
    }
    // We iterate over the bytes of this block from right-most to left-most
    // (i.e. reverse order of the standard) because we'll keep only the tail
    // bytes of the output of the PRG (in case not all bytes are to be used,
    // which happens iff this is the last block and the number of range bytes
    // for the PRG is not a multiple of AES key size): We keep the tail bytes
    // instead of leading bytes because in the use-case that |x| < 128 bits and
    // n = num_schdules (i.e. num_blocks) is '1', then since we 0-padded 'x' (w/
    // leading '0's), it makes sense to use the trailing bits of 'x' in the XOR.
    for (size_t j = 0; j < current_block_bytes; ++j) {
      const unsigned char input_j =
          j < input_bytes ? input[input_bytes - 1 - j] : (unsigned char) 0;
      const uint64_t pos_to_set =
          orig_output_size + i * key_bytes + current_block_bytes - 1 - j;
      const uint64_t pos_to_use = key_bytes * i + key_bytes - 1 - j;
      if (params.implementation_type_ == EncryptionPlatform::PLATFORM ||
          params.implementation_type_ == EncryptionPlatform::NETTLE) {
        (*output)[pos_to_set] = (*output_as_bytes)[pos_to_use] ^ input_j;
      } else if (params.implementation_type_ == EncryptionPlatform::NATIVE) {
        (*output)[pos_to_set] = output_i[key_bytes - 1 - j] ^ input_j;
      }
      num_bytes_still_needed--;
      if (num_bytes_still_needed == 0) break;
    }
  }

  if (output_as_bytes != nullptr) {
    delete output_as_bytes;
  }

  return true;
}

bool ApplyFixedKeyAesPrg(
    const size_t num_blocks,
    const Aes128EncKey* const schedules,
    const AesBlock& input,
    AesBlock* const output) {
  for (size_t i = 0; i < num_blocks; ++i) {
    output[i] = schedules[i].Aes128Encrypt(input) ^ input;
  }
  return true;
}

bool ApplySingleFixedKeyAesPrg(
    const FixedKeyAesPrgParams& params,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  if (output == nullptr) LOG_FATAL("Null input to ApplySingleFixedKeyAesPrg()");
  if (params.implementation_type_ != EncryptionPlatform::PLATFORM &&
      params.implementation_type_ != EncryptionPlatform::NETTLE &&
      params.implementation_type_ != EncryptionPlatform::NATIVE) {
    LOG_FATAL("Bad input to ApplySingleFixedKeyAesPrg: Only supported "
              "implementation_types_ are: PLATFORM, NETTLE, NATIVE.");
  }
  if (params.aes_key_bits_ != 128) {
    LOG_FATAL("FixedKeyAes currently only supported for AES-128");
  }
  const size_t key_bytes = params.aes_key_bits_ / CHAR_BIT;
  const size_t input_bytes = input.size();
  if (input_bytes > key_bytes) {
    LOG_FATAL("FixedKeyAes cannot be applied to input bigger than AES key size "
              "(currently AES-128).");
  }
  // Sanity check that 'input' represents a valid input to the PRG, i.e.
  // that it lies in the domain of the PRG, i.e. that the number of bits
  // represented by 'input' is at most the number of bits in the PRG domain.
  const size_t domain_bytes = params.domain_bits_ / CHAR_BIT +
      (params.domain_bits_ % CHAR_BIT == 0 ? 0 : 1);
  if (input_bytes > domain_bytes) {
    LOG_FATAL(
        "Bad input to ApplySingleFixedKeyAesPrg: " + Itoa(input_bytes) + ", " +
        Itoa(params.domain_bits_));
  }

  // There are (currently) three options for how the Fixed-Aes PRG is
  // implemented, as determined by implementation_type_:
  //   - For EncryptionPlatform::PLATFORM, use params.fixed_keys_
  //   - For EncryptionPlatform::NATIVE, use params.schedules_
  //   - For EncryptionPlatform::NETTLE, use params.contexts_
  // For the latter two, schedules_ (resp. contexts_) may not be set yet,
  // as they can each be derived from fixed_keys_. If this is the case,
  // derive them now.
  const vector<vector<unsigned char>>& fixed_keys = params.fixed_keys_;
  const size_t num_blocks = params.range_bits_ / params.aes_key_bits_ +
      (params.range_bits_ % params.aes_key_bits_ == 0 ? 0 : 1);
  Aes128EncKey schedule;
  vector<aes128_ctx> contexts;
  if (params.implementation_type_ == EncryptionPlatform::PLATFORM) {
    // Nothing to do.
  } else if (params.implementation_type_ == EncryptionPlatform::NATIVE) {
    // Get schedules for each key, either directly via params (if set), or
    // construct them from params.fixed_keys_.
    if (params.schedules_.empty()) {
      schedule = Aes128EncKey(CharVectorTo128Bits(fixed_keys[0]));
    } else {
      schedule = params.schedules_[0];
    }
  } else if (params.implementation_type_ == EncryptionPlatform::NETTLE) {
    // Get contexts for each key, either directly via params (if set), or
    // construct them from params.fixed_keys_.
    if (params.contexts_ == nullptr || params.contexts_->empty()) {
      contexts.resize(1);
      contexts[0] = AesCtxFromKey(fixed_keys[0]);
    }
  }

  // Sanity-check sizes are compatible.
  const uint64_t& num_output_bits = params.range_bits_;
  const uint64_t num_output_bytes =
      num_output_bits / CHAR_BIT + (num_output_bits % CHAR_BIT == 0 ? 0 : 1);
  const uint64_t orig_output_size = output->size();
  const uint64_t final_output_size = orig_output_size + num_output_bytes;
  output->resize(final_output_size);

  // Compute AES_k(x+i) for each i \in [0..num_blocks - 1].
  vector<AesBlock> output_as_bits;
  vector<unsigned char>* output_as_bytes = nullptr;
  if (params.implementation_type_ == EncryptionPlatform::PLATFORM ||
      params.implementation_type_ == EncryptionPlatform::NETTLE) {
    output_as_bytes = new vector<unsigned char>();
    vector<unsigned char> xored_input(key_bytes, 0);
    for (uint64_t i = 0; i < num_blocks; ++i) {
      vector<unsigned char> i_as_vector;
      if (!ValueToByteString<uint64_t>(i, &i_as_vector)) {
        delete output_as_bytes;
        return false;
      }
      for (size_t j = 0; j < key_bytes; ++j) {
        xored_input[j] =
            (unsigned char) (i_as_vector[j] ^ ((j < key_bytes - input_bytes) ? 0 : input[j - (key_bytes - input_bytes)]));
      }
      if (params.implementation_type_ == EncryptionPlatform::PLATFORM &&
          !Aes128PlatformEncrypt(
              EncryptionMode::ECB,
              EncryptionKeyType::KEY,
              fixed_keys[0],
              xored_input,
              output_as_bytes)) {
        DLOG_ERROR(
            "Failed to Aes128PlatformEncrypt in ApplySingleFixedKeyAesPrg.");
        delete output_as_bytes;
        return false;
      }
      if (params.implementation_type_ == EncryptionPlatform::NETTLE &&
          !Aes128NettleBlockEncrypt(
              contexts.empty() ? &((*params.contexts_)[0]) : &(contexts[0]),
              xored_input,
              output_as_bytes)) {
        DLOG_ERROR(
            "Failed to Aes128NettleEncrypt in ApplySingleFixedKeyAesPrg.");
        delete output_as_bytes;
        return false;
      }
    }
  } else if (params.implementation_type_ == EncryptionPlatform::NATIVE) {
    output_as_bits.reserve(num_blocks);
    AesBlock orig_x = CharVectorTo128Bits(input);
    for (size_t i = 0; i < num_blocks; ++i) {
      AesBlock x = orig_x ^ AesBlock(static_cast<uint64_t>(i));
      output_as_bits.push_back(schedule.Aes128Encrypt(x));
    }
  }

  // Set output to be:
  //   (AES_k(x) XOR x)  |  (AES_k(x+1) XOR x+1)  |  ... | (AES_k(x+m) XOR x+m)
  uint64_t num_bytes_still_needed = num_output_bytes;
  vector<unsigned char> xored_input(key_bytes, 0);
  for (uint64_t i = 0; i < num_blocks; ++i) {
    vector<unsigned char> i_as_vector;
    if (!ValueToByteString<uint64_t>(i, &i_as_vector)) {
      return false;
    }
    for (size_t j = 0; j < key_bytes; ++j) {
      xored_input[j] =
          (unsigned char) (i_as_vector[j] ^ ((j < key_bytes - input_bytes) ? 0 : input[j - (key_bytes - input_bytes)]));
    }
    uint64_t current_block_bytes = key_bytes;
    if (i == num_blocks - 1) {
      current_block_bytes = num_bytes_still_needed;
      if (current_block_bytes > key_bytes) {
        LOG_FATAL("To few schedules for desired output range.");
      }
    }
    vector<unsigned char> output_i;
    if (params.implementation_type_ == EncryptionPlatform::NATIVE) {
      Native128BitsToCharVector(output_as_bits[i], &output_i);
    }
    // We iterate over the bytes of this block from right-most to left-most
    // (i.e. reverse order of the standard) because we'll keep only the tail
    // bytes of the output of the PRG (in case not all bytes are to be used,
    // which happens iff this is the last block and the number of range bytes
    // for the PRG is not a multiple of AES key size): We keep the tail bytes
    // instead of leading bytes because in the use-case that |x| < 128 bits and
    // n = num_schdules (i.e. num_blocks) is '1', then since we 0-padded 'x' (w/
    // leading '0's), it makes sense to use the trailing bits of 'x' in the XOR.
    for (size_t j = 0; j < current_block_bytes; ++j) {
      const unsigned char input_j =
          j < input_bytes ? xored_input[input_bytes - 1 - j] : (unsigned char) 0;
      const uint64_t pos_to_set =
          orig_output_size + i * key_bytes + current_block_bytes - 1 - j;
      const uint64_t pos_to_use = key_bytes * i + key_bytes - 1 - j;
      if (params.implementation_type_ == EncryptionPlatform::PLATFORM ||
          params.implementation_type_ == EncryptionPlatform::NETTLE) {
        (*output)[pos_to_set] = (*output_as_bytes)[pos_to_use] ^ input_j;
      } else if (params.implementation_type_ == EncryptionPlatform::NATIVE) {
        (*output)[pos_to_set] = output_i[key_bytes - 1 - j] ^ input_j;
      }
      num_bytes_still_needed--;
      if (num_bytes_still_needed == 0) break;
    }
  }

  if (output_as_bytes != nullptr) {
    delete output_as_bytes;
  }

  return true;
}

bool ApplySingleFixedKeyAesPrg(
    const size_t num_blocks,
    const Aes128EncKey* const schedule,
    const AesBlock& input,
    AesBlock* const output) {
  for (size_t i = 0; i < num_blocks; ++i) {
    const AesBlock x_xor_i = input ^ AesBlock(static_cast<uint64_t>(i));
    output[i] = schedule[0].Aes128Encrypt(x_xor_i) ^ x_xor_i;
  }
  return true;
}

bool ApplyPrg(
    const PseudoRandomGeneratorParams& params,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  switch (params.type_) {
    case PseudoRandomGeneratorType::NONE:
      return false;
    case PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY:
      return ApplyAesPrg(params.range_bits_, input, output);
    case PseudoRandomGeneratorType::AES_FIXED_KEY:
      return ApplyFixedKeyAesPrg(
          *((const FixedKeyAesPrgParams*) &params), input, output);
    case PseudoRandomGeneratorType::AES_SINGLE_FIXED_KEY:
      return ApplySingleFixedKeyAesPrg(
          *((const FixedKeyAesPrgParams*) &params), input, output);
    default: {
      return false;
    }
  }

  return true;
}

}  // namespace random_number
}  // namespace crypto
