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
//
// Description:
// Implements Cryptographically-sound PRGs.
// Currently, there are three* options for how the PRG is instantiated, each
// which use the AES-Encryption as the backbone:
//   1) G: {0,1}^128 -> {0,1}^(128*m) via G(x) = AES_x(0) | AES_x(1) | ... | AES_x(m)
//   2) G: {0,1}^128 -> {0,1}^(128*m) via G(x) = (AES_k1(x) XOR x) | ... | (AES_km(x) XOR x)
//        where k1, ..., km are pre-defined (and fixed) keys
//   3) G: {0,1}^128 -> {0,1}^(128*m) via G(x) = (AES_k(x) XOR x) | ... | (AES_k(x+m) XOR (x+m))
//        where k is a single pre-defined (and fixed) key, and 'seed' (input) x is modified
//        in some way (e.g. incremented by 1 from one block to the next).
// ApplyAesPrg() implements use-case (1); ApplyFixedKeyAesPrg() does use-case (2),
// ApplySingleFixedKeyAesPrg() does use-case (3).
// * Note: We used to also support an MST-epsilon PRG, but this has been deprecated
// as this PRG is no longer considered sufficiently secure.
//
// ApplyPrg() is a generic API that calls one of the top three PRGs above, but there
// is no default behavior, i.e. caller must decide which of the above use-cases
// to use, and then either call that function directly, or call ApplyPrg with
// the PseudoRandomGeneratorParams params.type_ specifiying which use-case to do:
//   AES_W_INPUT_AS_KEY <-> ApplyAesPrg(),
//   AES_FIXED_KEY <-> ApplyFixedKeyAesPrg(),
//   AES_SINGLE_FIXED_KEY <-> ApplySingleFixedKeyAesPrg()
// Otherwise, can call the desired PRG's API directly.
//
// NOTE 1: For all the PRGs above, the only supported domain (size)
// is 128 bits, or more generally, whatever key (sizes) are supprted by AES.
// Attempting to muck with inputs of other lengths (e.g. 0-padding shorter inputs,
// or doing some sort of twiddling of longer inputs) is messy and prone to insecure
// instantiations. Instead, deal with inputs of other sizes by e.g. using a Random
// Oracle or secure hash to guarantee inputs of appropriate AES key size (128 bits).
//
// NOTE 2: The third (single fixed-key AES) PRG above is only hypothesized to be
// secure (well, they're all only hypothetically secure, but the third one is an
// even bigger question mark, as it hasn't been thoroughly accepted in the literature,
// nor reduced to any of the others).
//
// NOTE 3: Performance/Running time:
// See https://docs.google.com/document/d/1V3PGAlluKwdozYzFv8uYHkK-JpmmbMh6x93B9bCj7Sk/edit#
// for a full discussion.
// In terms of which PRG to use under PRG parameters (domain size, range size, number of calls):
//   - Use (2) if your PRG has small domain and range
//   - Use (3) if you have a single call (or a small number of calls) to a PRG: 128 -> n bits
// For example, FSS Eval() should use (2).

#ifndef PRG_UTILS_H
#define PRG_UTILS_H

#include "Crypto/Encryption/aes_utils.h"  // For kNumBlocksInAes128Schedule
#include <nettle/aes.h>  // For aes_ctx, aes_encrypt, etc.

#include <cstdint>  // For [u]int64_t
#include <memory>  // For unique_ptr
#include <vector>

namespace crypto {
namespace random_number {

enum class PseudoRandomGeneratorType {
  NONE,
  // PRG that is instantiated via AES Encryption, using the PRG input as
  // the encryption key, and whose output is the encryption of a *fixed*
  // plaintext (of appropriate size) under this key:
  //   PRG(x) = AES_x(0) | AES_x(1) | ... | AES_x(m)
  AES_W_INPUT_AS_KEY,
  // PRG that is instantiated using fixed key(s). The number of fixed
  // keys required depends on output size:
  //   PRG(x) = (AES_k1(x) XOR x) | (AES_k2(x) XOR x) | ... | (AES_km(x) XOR x)
  AES_FIXED_KEY,
  AES_SINGLE_FIXED_KEY,
};

// Parameters that get passed into ApplyPrg(). Include the PRG (type) to use,
// and the number of input/output bits.
struct PseudoRandomGeneratorParams {
  PseudoRandomGeneratorType type_;

  // The number of bytes in the domain of the PRG.
  uint64_t domain_bits_;
  // The number of bytes in the range of the PRG.
  uint64_t range_bits_;

  PseudoRandomGeneratorParams() {
    type_ = PseudoRandomGeneratorType::NONE;
    domain_bits_ = 0;
    range_bits_ = 0;
  }
};

// Parameters needed for the AES_[SINGLE_]FIXED_KEY PrgType.
struct FixedKeyAesPrgParams : public PseudoRandomGeneratorParams {
  // The size (bytes) of AES-key (currently only AES-128 is supported).
  int aes_key_bits_;

  // The implementation of AES to use: Platform (e.g. Windows), Native, or Nettle.
  crypto::encryption::EncryptionPlatform implementation_type_;

  // Once set, each inner-vector should have size 'aes_key_bits_ / CHAR_BIT', and
  // the outer-vector should have size (at least) range_bits_ / aes_key_bits_.
  // For implementation_type_ == EncryptionPlatform::PLATFORM, these are the
  // keys that will be used.
  std::vector<std::vector<unsigned char>> fixed_keys_;

  // For implementation_type_ == EncryptionPlatform::NATIVE, we can convert the
  // keys to schedules, and then use the schedules directly (so that we don't
  // incur the cost of converting keys -> schedules each time we call PRG).
  // The number of schedules must be (at least) range_bits_ / aes_key_bits_.
  // Note that schedules_.size() corresponds to the number of keys, i.e. there
  // is one schedule per key.
  std::vector<crypto::encryption::Aes128EncKey> schedules_;

  // For implementation_type_ == EncryptionPlatform::NETTLE, we can convert
  // the keys to aes_ctx, and then use the aes_ctx directly (so that we don't
  // incur the cost of converting keys -> aes_ctx each time we call PRG).
  // The vector below should have size equal to the number of fixed keys.
  std::vector<aes128_ctx>* contexts_;

  FixedKeyAesPrgParams() {
    type_ = PseudoRandomGeneratorType::AES_FIXED_KEY;
    domain_bits_ = 0;
    range_bits_ = 0;
    aes_key_bits_ = 0;
    implementation_type_ = crypto::encryption::EncryptionPlatform::NATIVE;
    contexts_ = nullptr;
  }
  // Copy-Constructor.
  FixedKeyAesPrgParams(const FixedKeyAesPrgParams& other) {
    type_ = other.type_;
    domain_bits_ = other.domain_bits_;
    range_bits_ = other.range_bits_;
    aes_key_bits_ = other.aes_key_bits_;
    implementation_type_ = other.implementation_type_;
    fixed_keys_ = other.fixed_keys_;
    schedules_ = other.schedules_;
    // Shallow-copy of contexts_, so the vector elements (pointers to aes_ctx)
    // are just copies of the original pointers; caller is responsible for making
    // sure the underlying aes_ctx objects remain in scope (not deleted) for as
    // long as they are needed.
    contexts_ = other.contexts_;
  }
  // Move-Constructor.
  FixedKeyAesPrgParams(FixedKeyAesPrgParams&& other) {
    type_ = other.type_;
    domain_bits_ = other.domain_bits_;
    range_bits_ = other.range_bits_;
    aes_key_bits_ = other.aes_key_bits_;
    implementation_type_ = other.implementation_type_;
    fixed_keys_ = other.fixed_keys_;
    schedules_ = other.schedules_;
    contexts_ = other.contexts_;
  }
  // Destructor.
  ~FixedKeyAesPrgParams() {
    // The underlying aex_ctx objects are not deleted here; caller (whoever
    // set the objects pointed to originally) is responsible for deleting them.
    if (contexts_ != nullptr) {
      contexts_->clear();
    }
    schedules_.clear();
  }
  // Copy-Assignment.
  FixedKeyAesPrgParams& operator=(const FixedKeyAesPrgParams& other) {
    FixedKeyAesPrgParams temp(other);  // Re-use copy-constructor.
    *this = std::move(temp);  // Re-use move-assignment.
    return *this;
  }
  // Move-Assignment.
  FixedKeyAesPrgParams& operator=(FixedKeyAesPrgParams&& other) {
    type_ = other.type_;
    domain_bits_ = other.domain_bits_;
    range_bits_ = other.range_bits_;
    aes_key_bits_ = other.aes_key_bits_;
    implementation_type_ = other.implementation_type_;
    fixed_keys_ = other.fixed_keys_;
    schedules_ = other.schedules_;
    contexts_ = other.contexts_;
    return *this;
  }
};

// Applies AES-PRG:
//   PRG(x) = AES_x(0) | AES_x(1) | ... | AES_x(m)
// i.e. the PRG input 'x' is treated as the encryption key (and hence
// |x| = domain_bits_ must be one of the supported AES key sizes), and whose
// output is the encryption of a *fixed* plaintext (of appropriate size) under
// this key. More details:
// An implementation of a PRG using AES Encryption as the backbone: User provides
// a 16-byte encrytption key and the desired number of bytes for the PRG output.
// This function will encrypt a (fixed) plaintext string, and the ciphertext
// will be the output of the PRG.
// NOTE 1: We may chop-off the leading bits (and even bytes) of the ciphertext,
// to reduce the size of the output vector to exactly 'num_output_bits'.
// In particular, the ciphertext will have size a multiple of the key size
// (e.g. a multiple of 128 for AES-128), so if desired_bits is not a multiple
// of the key size, then we'll chop-off the extra leading bits of the ciphertext.
// Here, by "chop-off", we mean:
//   1) Remove extra (leading) bytes, so that output has the right number of bytes:
//      num_output_bits / CHAR_BIT, perhaps one more than this if num_output_bits
//      is not divisible by 8
//   2) If 8 does not divide num_output_bits, let:
//        remainder_bits = num_output_bits % CHAR_BIT
//      Then in the first byte of output, make all but the last 'remainder_bits'
//      of the byte equal to zero.
// Note that we don't actually do (2) here, as it is better to have the caller
// do this: The caller will have to deal with the fact that 'num_output_bits' is
// actually represented in output.size() * CHAR_BIT bits; i.e. in the case that
// CHAR_BIT does not divide num_output_bits, the caller will have to decide
// which bits to ignore. Since we don't know what bits caller will ignore (i.e.
// they might decide to ignore the *last* bits instead of ignoring the *leading*
// bits), it is better to keep the full randomness in output.
// NOTE 2: It may be desirable to allow under-specified inputs (i.e. inputs
// that are less than 16 bytes = 128 bits): for such inputs, we can 0-pad
// them and use the 0-padded (16 byte) input as the AES key. Because
// implementing the PRG this way may have security implications, the default
// is to turn this ability off (so calling ApplyAesPrg with input not equal
// to 16 bytes will fail); users can toggle this behavior to be allowed by
// calling SetAllowUnderSpecifiedAesKey(true).
extern bool ApplyAesPrg(
    const uint64_t& num_output_bits,
    // Will be used as key to AES; and must be exactly 16 bytes (see comment
    // above flag 'kAllowUnderSpecifiedAesKey' in prg_utils.cpp).
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// See NOTE 2 above.
extern void SetAllowUnderSpecifiedAesKey(const bool set_to);

// Applies "fixed-key" aes:
//   PRG(x) = (AES_k1(x) XOR x) | (AES_k2(x) XOR x) | ... | (AES_km(x) XOR x)
// The keys ("k1", "k2", ..., "km" in the example above) must all be 128 bits
// (this is currently the only supported AES-fixed key size), and are specified
// in params.fixed_keys_.
// Regarding PRG Domain Size:
//   Since AES_ki demands inputs 'x' of 128 bits (and also because the output
//   of AES_ki(x) will be 128 bits, and this must match the size of 'x' in order
//   to XOR them together), we 0-pad 'x' to be 128 bits. In particular, we
//   require input.size() <= 16 bytes (= 128 bits).
// Regarding PRG Range Size:
//   We concatenate 'parms.schedules_.size()' blocks of size 128 bits together.
//   Thus, the output of PRG(x) will have (128 * m) bits, where m is
//   params.schedules_.size(). If desired range is not a multiple of 128 bits, this
//   fn will remove the excessive bytes from the *last* block: (AES_km(x) XOR x)
//   (If params.range_bits_ is not a multiple of CHAR_BIT, caller will be
//    responsible for trimming 'output' as desired).
// The way that fixed-key AES is applied depends on params.implementation type:
//   - For EncryptionPlatform::PLATFORM, use params.fixed_keys_
//   - For EncryptionPlatform::NATIVE, use params.schedules_
//   - For EncryptionPlatform::NETTLE, use params.contexts_
// For the latter two, params.schedules_ (resp. params.contexts_) may not be set
// on input, as they can each be derived from fixed_keys_.
// NOTE: If you will be calling ApplyFixedKeyAesPrg() many (>100k) times, it is
// more efficient to use the API below.
extern bool ApplyFixedKeyAesPrg(
    const FixedKeyAesPrgParams& params,
    const std::vector<unsigned char>& input,  // Input 'x' to PRG. Size <= 16.
    std::vector<unsigned char>* output);
// Same to above, with modified API (for optimized performance); see e.g. output logging
// of running prg_utils_test.exe, as well as the API for Aes128NativeEncrypt().
// On input, schedules should already be populated (of size 11 * num_blocks);
// and output should already be allocated (of size num_blocks).
// TODO(paul): For all functions below that take in AesBlock or Aes128EncKey,
// generalize aes_utils.h to template these, and then update the functions
// here to be templated and take in the more general input types for these;
// see Quinn's recommendation in Mattermost (channel 'quinn') message on
// July 09 (11:51am).
extern bool ApplyFixedKeyAesPrg(
    const std::size_t num_blocks,
    const crypto::encryption::Aes128EncKey* key,
    const crypto::encryption::AesBlock& input,
    crypto::encryption::AesBlock* output);

// Applies "single fixed-key" aes:
//   PRG(x) = (AES_k(x) XOR x) | (AES_k(x+1) XOR (x+1)) | ... | (AES_k(x+m) XOR (x+m))
// The key 'k' must be 128 bits (this is currently the only supported AES-fixed key size).
// Regarding PRG Domain Size (|x|):
//   Since AES_k demands inputs 'x' of 128 bits (and also because the output
//   of AES_k(x) will be 128 bits, and this must match the size of 'x' in order
//   to XOR them together), we 0-pad 'x' to be 128 bits. In particular, we
//   require input.size() <= 16 bytes (= 128 bits).
// Regarding PRG Range Size:
//   We concatenate 'parms.schedules_.size()' blocks of size 128 bits together.
//   Thus, the output of PRG(x) will have (128 * m) bits, where m is
//   params.schedules_.size(). If desired range is not a multiple of 128 bits, this
//   fn will remove the excessive bytes from the *last* block: (AES_k(x+m) XOR (x+m))
//   (If params.range_bits_ is not a multiple of CHAR_BIT, caller will be
//    responsible for trimming 'output' as desired).
// The way that fixed-key AES is applied depends on params.implementation type:
//   - For EncryptionPlatform::PLATFORM, use params.fixed_keys_
//   - For EncryptionPlatform::NATIVE, use params.schedules_
//   - For EncryptionPlatform::NETTLE, use params.contexts_
// For the latter two, params.schedules_ (resp. params.contexts_) may not be set
// on input, as they can each be derived from fixed_keys_.
// NOTE: If you will be calling ApplySingleFixedKeyAesPrg() many (>100k) times, it is
// more efficient to use the API below.
extern bool ApplySingleFixedKeyAesPrg(
    const FixedKeyAesPrgParams& params,
    const std::vector<unsigned char>& input,  // Input 'x' to PRG. Size <= 16.
    std::vector<unsigned char>* output);
// Same to above, with modified API (for optimized performance).
// On input, 'schedule' should already be populated
// and output should already be allocated (of size num_blocks).
extern bool ApplySingleFixedKeyAesPrg(
    const std::size_t num_blocks,
    const crypto::encryption::Aes128EncKey* key,
    const crypto::encryption::AesBlock& input,
    crypto::encryption::AesBlock* output);

// Applies a PRG to input, yielding output.
// NOTE: Typically, input.size() should equal params.domain_bits_, but this
// is not enforced here, as some applications may wish to use input differently.
extern bool ApplyPrg(
    const PseudoRandomGeneratorParams& params,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);

}  // namespace random_number
}  // namespace crypto

#endif
