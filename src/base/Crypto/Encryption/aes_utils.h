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
//
// Wrapper for AES Encryption. Note that the actual protocols for doing the
// encryption will be platform specific (e.g. windows_encryption_utils.h/cpp
// for Windows); use these functions as a wrapper, so that calling code can
// be platform-agnostic.
//
// Currently, only AES-128 and AES-256 are supported.
//
// NOTE: Actual input (message length) is naturally the same size as the
// AES key (currently, always 128 or 256 bits). However, we support arbitrary
// messages sizes (unless EncryptionMode = ECB, in which case the message
// size must be at most key size). In particular:
//   (a) For CTR EncryptionMode, any size message is naturally supported;
//   (b) For non-CTR mode and message size < |key| bits, message is 0-padded
//       w/ leading NULL bytes;
//   (c) For non-CTR and non-ECB mode (currently that just leaves CBC mode)
//       and for message size > |key| bits, the message is split into |key|-bit
//       blocks, and CBC mode is applied (if the last block has < |key| bits,
//       it gets 0-padded just like (b) above)
//
// AES can be implemented in different modes (specified via 'UseType' or
// 'EncryptionMode'), and the mode to use depends on use-case:
//   a) For use as (backbone to) a PRG/RO, ECB mode is sufficient
//   b) For use as encryption/decryption, stream-cipher (CBC or CTR) mode is used
//      NOTE: CTR may be superior to CBC, due to parallelizability and
//      resilience against block-changing attacks, but is not available in
//      some of the underlying libraries, e.g. Windows.
//      Even better would be to use an AE protocol, such as GCM, but this is
//      not currently done.
//
// There are several options available for how AES is invoked/instantiated:
//   a) Underlying Library: Current options are:
//        1) OS/Platform-Specific, e.g. Windows Crypt Library for Windows
//           (Currently, this option is only supported for Windows OS)
//        2) Nettle
//        3) Native. Currently, only supports ECB mode.
//      The underlying library that gets used is specified via 'EncryptionPlatform'.
//      TODO(PHB): Consider supporting openssl as a fourth option.
//   b) Specification of Key. Current options are:
//        1) User provides key directly
//        2) User's platform password is used to generate a key
//           NOTE: Only supported in use-case (1) above: Platform
//        3) Generate a random key
//        4) User provides a "schedule" (Only supported in use-case (3) above: Native).
//        5) User provides an aes_ctx (Only relevant for use-case (2) above: Nettle).
//      The mechanism for specifying/constructing keys is controlled via
//      'EncryptionKeyType'
//

#ifndef AES_UTILS_H
#define AES_UTILS_H

#include <climits>  // For CHAR_BIT
#include <cstdint>  // For [u]int64_t
#include <cstring>  // For std::memory operations (e.g. memcpy, memset, memmove).
#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <vector>

#if (defined(AES_UTILS_HAVE_AESNI))
// Assume the user knows better than us.
#elif (defined(__x86_64__) || defined(_M_X64))
#define AES_UTILS_HAVE_AESNI 1
#else
#define AES_UTILS_HAVE_AESNI 0
#endif

#if (defined(AES_UTILS_HAVE_AARCH64))
// Assume the user knows better than us.
#elif (defined(__aarch64__))
// TODO: Change this to 1 once Aarch64Aes* is implemented.
#define AES_UTILS_HAVE_AARCH64 0
#else
#define AES_UTILS_HAVE_AARCH64 0
#endif

#if (AES_UTILS_HAVE_AESNI)
#include <immintrin.h>  // For __m128i.
#endif

namespace crypto {
namespace encryption {

// Holds the valid Key sizes (in bits) for which aes_utils has an existing
// implementation.
extern const uint64_t kAesKeySizes[];
// The number of 128-bit blocks in the 'schedule' for AES-128 (currently, this is 11).
extern const int kNumBlocksInAes128Schedule;
// The number of 256-bit blocks in the 'schedule' for AES-256 (currently, this is 11).
extern const int kNumBlocksInAes256Schedule;
// The number of bytes in the AES key, currently 16 (for 128-bit AES key).
const int kNumBytesInAesBlock = 16;

// Returns whether the provided key is valid, i.e. whether it exists in kAesKeySizes.
extern bool IsValidAesKey(const uint64_t& key);

// Returns the smallest supported AES key that is at least as big as the input.
extern bool GetNumAesKeyBytes(const uint64_t& input_bytes, uint64_t* key_bytes);

// Forward declare the Nettle implementation.
class NettleAesBlock;
typedef NettleAesBlock NettleAes128Key;
class NettleAes128EncKey;
class NettleAes128DecKey;

// Forward declare the AES-NI implementation.
#if (AES_UTILS_HAVE_AESNI)
class AesniAesBlock;
typedef AesniAesBlock AesniAes128Key;
class AesniAes128EncKey;
class AesniAes128DecKey;
#endif

// Forward declare the AArch64 implementation.
#if (AES_UTILS_HAVE_AARCH64)
class Aarch64AesBlock;
typedef Aarch64AesBlock Aarch64Aes128Key;
class Aarch64Aes128EncKey;
class Aarch64Aes128DecKey;
#endif

// Define plain AesXXX to be a reasonable default implementation.
#if (AES_UTILS_HAVE_AESNI)
typedef AesniAesBlock AesBlock;
typedef AesniAes128Key Aes128Key;
typedef AesniAes128EncKey Aes128EncKey;
typedef AesniAes128DecKey Aes128DecKey;
#elif (AES_UTILS_HAVE_AARCH64)
typedef Aarch64AesBlock AesBlock;
typedef Aarch64Aes128Key Aes128Key;
typedef Aarch64Aes128EncKey Aes128EncKey;
typedef Aarch64Aes128DecKey Aes128DecKey;
#else
typedef NettleAesBlock AesBlock;
typedef NettleAes128Key Aes128Key;
typedef NettleAes128EncKey Aes128EncKey;
typedef NettleAes128DecKey Aes128DecKey;
#endif

// Converts a block in generic form (e.g. an array of bytes) to the
// 'AesBlock' format.
// NOTE: It is assumed that the InputIterator 'first' has exactly kNumBytesInAesBlock
// elements (bytes):
//   - If input has *fewer* than kNumBytesInAesBlock elements: use alternate API for
//     AesBlockFromBytes (below) that provides an 'end' pointer/"Sentinel", and
//     effectively 0-pads in input to kNumBytesInAesBlock bytes.
//   - If input has *more* than kNumBytesInAesBlock elements: only the first
//     kNumBytesInAesBlock elements are used (the rest are ignored).
template<class InputIterator, class AesBlockType = AesBlock>
static AesBlockType AesBlockFromBytes(InputIterator first) {
  uint8_t b[kNumBytesInAesBlock];
  for (int i = 0; i < kNumBytesInAesBlock; ++i) {
    b[i] = *first++;
  }
  return AesBlockType(b);
}
// Same as above, but with an 'end' pointer, indicating where to stop.
template<class InputIterator, class Sentinel, class AesBlockType = AesBlock>
static AesBlockType AesBlockFromBytes(InputIterator first, Sentinel last) {
  uint8_t b[kNumBytesInAesBlock];
  int i = 0;
  while (i < kNumBytesInAesBlock && first != last) {
    b[i++] = *first++;
  }

  // If fewer than 16 bytes were passed in, shift block 'b' by 0-padding.
  if (i < kNumBytesInAesBlock) {
    std::memmove(b + kNumBytesInAesBlock - i, b, i);
    std::memset(b, 0, kNumBytesInAesBlock - i);
  }

  return AesBlockType(b);
}

// Default definition of an AES block is to use NETTLE, which in particular
// just treats a block as 16 bytes.
class NettleAesBlock {
  friend class NettleAes128EncKey;
  friend class NettleAes128DecKey;

public:
  NettleAesBlock() { std::memset(b_, 0, kNumBytesInAesBlock); }

  NettleAesBlock(const uint8_t* const b) {
    std::memcpy(b_, b, kNumBytesInAesBlock);
  }

  // Allow initialization via 8-bytes, which is defined to 0-pad the first
  // 8 bytes, and then use the passed in value for the trailing 8 bytes.
  NettleAesBlock(const uint64_t b) {
    std::memset(b_, 0, sizeof(uint64_t));
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
      b_[sizeof(uint64_t) + i] = static_cast<uint8_t>(
          b >> ((CHAR_BIT * sizeof(uint64_t)) - CHAR_BIT * (i + 1)));
    }
  }

  // Operator overloads.
  NettleAesBlock operator&(const NettleAesBlock& other) const {
    uint8_t b[kNumBytesInAesBlock];
    for (int i = 0; i < kNumBytesInAesBlock; ++i) {
      b[i] = b_[i] & other.b_[i];
    }
    return NettleAesBlock(b);
  }
  NettleAesBlock operator^(const NettleAesBlock& other) const {
    uint8_t b[kNumBytesInAesBlock];
    for (int i = 0; i < kNumBytesInAesBlock; ++i) {
      b[i] = b_[i] ^ other.b_[i];
    }
    return NettleAesBlock(b);
  }
  void operator&=(const NettleAesBlock& other) {
    for (int i = 0; i < kNumBytesInAesBlock; ++i) {
      b_[i] = b_[i] & other.b_[i];
    }
  }
  void operator^=(const NettleAesBlock& other) {
    for (int i = 0; i < kNumBytesInAesBlock; ++i) {
      b_[i] = b_[i] ^ other.b_[i];
    }
  }
  // See comments above the corresonding operators in AesniAesBlock
  // for why the two operators below are commented-out.
  /*
  bool operator==(const NettleAesBlock& other) const {
    for (int i = 0; i < kNumBytesInAesBlock; ++i) {
      if (b_[i] != other.b_[i]) return false;
    }
    return true;
  }
  bool operator!=(const NettleAesBlock& other) const {
    return !(*this == other);
  }
  */

  // Converts the present NettleAesBlock to the specified type.
  template<class OutputIterator>
  void ToBytes(OutputIterator first) const {
    for (int i = 0; i < kNumBytesInAesBlock; ++i)
      *first++ = b_[i];
  }

  // Reverse of above: Converts given representation (in bytes) to
  // NettleAesBlock type.
  template<class InputIterator>
  static NettleAesBlock FromBytes(InputIterator first) {
    return AesBlockFromBytes(first);
  }
  // Same as above, with an 'end' position provided for the input.
  template<class InputIterator, class Sentinel>
  static NettleAesBlock FromBytes(InputIterator first, Sentinel last) {
    return AesBlockFromBytes(first, last);
  }

private:
  uint8_t b_[kNumBytesInAesBlock];
};

class NettleAes128EncKey {
  friend class NettleAes128DecKey;

public:
  NettleAes128EncKey() {
    const uint8_t k[kNumBytesInAesBlock] = {0};
    aes128_set_encrypt_key(&context_, k);
  }

  NettleAes128EncKey(const NettleAes128Key& k) {
    aes128_set_encrypt_key(&context_, k.b_);
  }

  NettleAesBlock Aes128Encrypt(const NettleAesBlock& x) const {
    uint8_t y[kNumBytesInAesBlock];
    aes128_encrypt(&context_, kNumBytesInAesBlock, y, x.b_);
    return NettleAesBlock(y);
  }

private:
  struct aes128_ctx context_;
};

class NettleAes128DecKey {
public:
  NettleAes128DecKey() {
    const uint8_t k[kNumBytesInAesBlock] = {0};
    aes128_set_decrypt_key(&context_, k);
  }

  NettleAes128DecKey(const NettleAes128Key& k) {
    aes128_set_decrypt_key(&context_, k.b_);
  }

  NettleAes128DecKey(const NettleAes128EncKey& ek) {
    aes128_invert_key(&context_, &ek.context_);
  }

  NettleAesBlock Aes128Decrypt(const NettleAesBlock& y) const {
    uint8_t x[kNumBytesInAesBlock];
    aes128_decrypt(&context_, kNumBytesInAesBlock, x, y.b_);
    return NettleAesBlock(x);
  }

private:
  struct aes128_ctx context_;
};

#if (AES_UTILS_HAVE_AESNI)
class AesniAesBlock {
  friend class AesniAes128EncKey;
  friend class AesniAes128DecKey;

public:
  AesniAesBlock();
  AesniAesBlock(const uint8_t* const b);
  AesniAesBlock(const __m128i b) : b_(b) {}
  AesniAesBlock(const uint64_t b);

  operator __m128i() const { return b_; }

  AesniAesBlock operator&(const AesniAesBlock& other) const;
  AesniAesBlock operator^(const AesniAesBlock& other) const;
  void operator&=(const AesniAesBlock& other);
  void operator^=(const AesniAesBlock& other);
  // I currently don't need the following operators anywhere; if this
  // changes, it is probably safe just to uncomment-out (also uncomment-out
  // the corresponding functions in NettleAesBlock and AArch64AesBlock,
  // and in the .cpp file).
  /*
  bool operator==(const AesniAesBlock& other) const;
  bool operator!=(const AesniAesBlock& other) const;
  */

  // Output AesniAesBlock as a byte array.
  template<class OutputIterator>
  void ToBytes(OutputIterator first) const {
    std::vector<uint8_t> temp(kNumBytesInAesBlock);
    ToByteArray(temp.data());
    for (size_t i = 0; i < kNumBytesInAesBlock; ++i) {
      *first++ = temp[i];
    }
  }
  // Same as above, for default datatype.
  // On input, 'input' should already be allocated kNumBytesInAesBlock bytes.
  void ToByteArray(uint8_t* input) const;

  // Reverse of above: Set a AesniAesBlock from a byte array.
  template<class InputIterator>
  static AesniAesBlock FromBytes(InputIterator first) {
    return AesBlockFromBytes(first);
  }
  // Same as above, with an end pointer.
  template<class InputIterator, class Sentinel>
  static AesniAesBlock FromBytes(InputIterator first, Sentinel last) {
    return AesBlockFromBytes(first, last);
  }

private:
  __m128i b_;
};

class AesniAes128EncKey {
  friend class AesniAes128DecKey;

public:
  AesniAes128EncKey() {}

  AesniAes128EncKey(const AesniAes128Key& key);

  AesniAes128EncKey(const __m128i* schedule) {
    for (int i = 0; i < 11; ++i)
      w_[i] = AesniAesBlock(schedule[i]);
  }

  AesniAesBlock Aes128Encrypt(const AesniAesBlock& x) const;

  // Convert w_ to the native architecture type (__m128i).
  // 'output' should be pre-allocated 11 __m128i elements.
  void ToNativeType(__m128i* output) const;

private:
  AesniAesBlock w_[11];
  static __m128i Aes128ExpandHelper(const __m128i& a, const __m128i& b);
};

class AesniAes128DecKey {
public:
  AesniAes128DecKey() {}

  AesniAes128DecKey(const AesniAes128Key& k) :
      AesniAes128DecKey(AesniAes128EncKey(k)) {}

  AesniAes128DecKey(const AesniAes128EncKey& ek);

  AesniAesBlock Aes128Decrypt(const AesniAesBlock& y) const;

  // Convert w_ to the native architecture type (__m128i).
  // 'output' should be pre-allocated 11 __m128i elements.
  void ToNativeType(__m128i* output) const;

private:
  AesniAesBlock w_[11];
};
#endif

#if (AES_UTILS_HAVE_AARCH64)

// TODO

#endif

// Specifies how the calling code will use the ciphertext: Directly (as ciphertext,
// i.e. an encryption scheme) or as a backbone to a PRG/RO. This in turn will
// determine the encryption mode: block or stream cipher (i.e. ECB vs. CBC or CTR).
// NOTE: 'PRG' is a bit of a misnomer, since e.g. AES-PRG (see prg_utils.h) is
// implemented using AES in ENC mode; in other words, probably makes sense not
// to use UseType at all, and explicitly indicate if block or stream cipher is
// required (they have different security guarantees) by specifying EncryptionMode.
enum class UseType {
  UNKNOWN,
  PRG,
  ENC,
};

// Same as above, but for direct-specification of the mode. In particular, there
// is a correspondence between UseType and EncryptionMode:
//   - PRG <-> ECB
//   - ENC <-> CBC, for Platform (Windows)
//             CTR, for Nettle
//             NULL, for Native (currently, only PRG/ECB mode supported for Native)
enum class EncryptionMode {
  UNKNOWN,
  ECB,
  CBC,
  CTR,
};

// For Aes Encryption/Decryption, there are several options for how the user
// would like to generate the Encryption/Decryption Key; this enumerates them.
enum class EncryptionKeyType {
  KEY,  // Key provided directly from caller
  PASSWORD,  // Use a provided password to generate a key. Only valid for 'PLATFORM'.
  RANDOM,  // Randomly generate a key; which can be returned to caller for later use
  SCHEDULE,  // Key has already been expanded by user. Only valid for 'NATIVE'.
};

// Determines whether platform tools (e.g. CryptEncrypt for Windows), nettle,
// or direct access to AES hardware will be used to encrypt.
enum class EncryptionPlatform {
  PLATFORM,  // Use platform (e.g. Windows) tools
  NETTLE,  // Use Nettle library/tools
  NATIVE,  // Access AES-Hardware directly
};

// Holds EncryptionKeyType and EncryptionPlatform.
struct AesParams {
  // Only one of the following two fields should be set, or if both are set,
  // they should be set in accordance to the mapping between them: see comment
  // above EncryptionMode above.
  UseType use_type_;
  EncryptionMode mode_;

  EncryptionKeyType key_type_;
  EncryptionPlatform platform_;
  // Used only if key_type_ is RANDOM or PASSWORD, and if non-null, the
  // generated key will be stored here.
  // Owned by caller.
  std::vector<unsigned char>* decryption_key_;

  AesParams() {
    use_type_ = UseType::UNKNOWN;
    mode_ = EncryptionMode::UNKNOWN;
    key_type_ = EncryptionKeyType::KEY;
    platform_ = EncryptionPlatform::NETTLE;
    decryption_key_ = nullptr;
  }
};

typedef EncryptionKeyType DecryptionKeyType;

// ================================ AES-128 ====================================
// ============================ AES-128 Encrypt ================================
// Discussion: There are 4 APIs for Aes-128 Encryption:
//   1) User provides (symmetric) AES-128 key
//   2) User provides a password, which generates a (symmetric) Aes-128 key
//   3) No key or password provided; a random Aes-128 key will be generated,
//      and optionally returned to the caller so they can later decrypt with it
//   4) User provides the AES "schedule" (for Native) or aes_ctx (for Nettle)
// Note that there are various ways of implementing AES-Encryption:
//   A) Use a Platform-provided AES tools, e.g. CryptEncrypt for Windows
//   B) Use Nettle
//   C) Use Native architecture to directly access built-in AES functionality
// Not all of the four API's are available for all three implementations:
//   - API 1: A, B, and C
//   - API 2: A
//   - API 3: A, B, and C
//   - API 4: B and C
// Platform-dependent implementations (i.e. (A)) is done (for API's 1-3) in the
// platform-specific implementation files, e.g. windows_encryption_utils.h.
// Platform-independent implementations (i.e. (B) and (C)) is done (for API's
// 1, 3, and 4) in aes_utils.cpp.
// Some API's are generic and can support mulitple options 1-4 above; in this
// case, the EncryptionKeyType parameter dictates which API should be used.
// Similarly, the EncryptionPlatform parameter dictates selection of (A) - (C).
// Also, each API can be run in Batch or Single mode; use the former if you
// want to encrypt multiple messages using the same key (may save time, e.g.
// for Windows, the Crypto setup will be done just once).
// For each API, the ciphertext is appended (push_back) to 'output'; i.e.
// caller should NOT size output ahead of time to fit the ciphertext, and also
// any bytes already in output will not be overwritten.
//
// ======================== AES-128 Platform-Encrypt ===========================
// The following are for APIs 1-3 above, and for implementation A (Platform).
// For APIs 1 and 2, key should be non-empty, while for API 3, it is ignored.
// Similarly, decryption_key is ignored for APIs 1 and 2 (and can be null),
// and it is used (if not null) to store the generated key for API 3.
// For API 1, key.size() must be 16 bytes = (128 / CHAR_BIT).
extern bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* decryption_key,
    std::vector<unsigned char>* output);
// Generic API for all 3, Batch Mode.
extern bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// API 1 + 2. EncryptionKeyType should be either KEY or PASSWORD.
extern bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// API 1 + 2: Batch Mode. EncryptionKeyType should be either KEY or PASSWORD.
extern bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// API 3.
extern bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* decryption_key,
    std::vector<unsigned char>* output);
// API 3: Batch Mode.
extern bool Aes128PlatformEncrypt(
    const EncryptionMode mode,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// ====================== END AES-128 Platform-Encrypt =========================
// ======================== AES-128 Nettle-Encrypt ===========================
// The following are for APIs 1, 3, and 4 above, and for implementation B (Nettle).
// API's 1 and 3 have a generic API that can support either, as well as API-
// specific API's.

// Generic API for 1 and 3, Batch Mode.
// For API 1, key.size() must be 16 bytes, and decryption_key is ignored (can be null)
// For API 3, key is ignored, while decryption_key is populated (if non-null)
extern bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* decryption_key,
    std::vector<unsigned char>* output);
// Generic API for 1 and 3, Batch Mode.
extern bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// Generic API for 1 and 3, ECB mode.
extern bool Aes128NettleBlockEncrypt(
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* decryption_key,
    std::vector<unsigned char>* output);
// Generic API for 1 and 3, ECB Mode, Batch Mode.
extern bool Aes128NettleBlockEncrypt(
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// API 1.
extern bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// API 1, Batch Mode.
extern bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// API 3.
extern bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* decryption_key,
    std::vector<unsigned char>* output);
// API 3, Batch Mode.
extern bool Aes128NettleEncrypt(
    const EncryptionMode mode,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// API 4: aes_ctx provided.
extern bool Aes128NettleEncrypt(
    // No 'const' specified, because some Nettle API's require non-const.
    aes128_ctx* context,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// API 4: aes_ctx provided, Batch mode.
extern bool Aes128NettleEncrypt(
    // No 'const' specified, because some Nettle API's require non-const.
    aes128_ctx* context,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// API 4: aes_ctx provided, ECB mode.
extern bool Aes128NettleBlockEncrypt(
    // No 'const' specified, because some Nettle API's require non-const.
    aes128_ctx* context,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// API 4: aes_ctx provided, ECB mode, Batch mode.
extern bool Aes128NettleBlockEncrypt(
    // No 'const' specified, because some Nettle API's require non-const.
    aes128_ctx* context,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// Helper function for Nettle.
extern aes128_ctx AesCtxFromKey(const std::vector<unsigned char>& key);
// ====================== END AES-128 Nettle-Encrypt =========================
// ======================== AES-128 Native-Encrypt ===========================
// The following are for APIs 1, 3, and 4 above, and for implementation C (Native).
// API's 1 and 3 have a generic API that can support either, as well as API-
// specific API's.
// Currently, Aes128NativeEncrypt() is only supported in ECB mode, and hence
// it is not secure as a stream cipher. Thus, we demand 'input' is (at most)
// 128 bits (inputs fewer than 128-bits will be 0-padded (prepended NULL chars).

// Generic API for 1 and 3, Batch Mode.
// For API 1, key.size() must be 16 bytes, and decryption_key is ignored (can be null)
// For API 3, key is ignored, while decryption_key is populated (if non-null)
extern bool Aes128NativeEncrypt(
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* decryption_key,
    std::vector<unsigned char>* output);
// Generic API for 1 and 3, Batch Mode.
extern bool Aes128NativeEncrypt(
    const EncryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// API 1.
extern bool Aes128NativeEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// API 1. Batch Mode.
extern bool Aes128NativeEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// API 3.
extern bool Aes128NativeEncrypt(
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* decryption_key,
    std::vector<unsigned char>* output);
// API 3: Batch Mode.
extern bool Aes128NativeEncrypt(
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// API 4.
// schedule should have size 11.
extern AesBlock Aes128NativeEncrypt(
    const Aes128EncKey& key, const AesBlock& input);
// DEPRECATED. Aes128NativeEncrypt() is currently only supported in ECB mode,
// which is insecure when encrypting multiple blocks, so there is no
// reason why we should need to encrypt more than one block.
// I'll leave this code here as a template, in case it is needed in the future.
// API 4, Bach mode.
// On input, 'schedule' should have size 11, input should have size num_blocks,
// and 'output' should have num_blocks (of sizeof(AesBlock) bytes) allocated.
/*
extern bool Aes128NativeEncrypt(
    const int num_blocks, const AesBlock* schedule, const AesBlock* input,
    AesBlock* output);
*/

// Conversion tools:
//   vector<unsigned char> (16 bytes) -> AesBlock
// For each of the below:
//   - If input.size() is larger than kNumBytesInAesBlock, then only the first
//     kNumBytesInAesBlock elements will be used.
//   - If input.size() is smaller than kNumBytesInAesBlock, then it will be
//     0-padded up to kNumBytesInAesBlock elements.
extern AesBlock CharVectorTo128Bits(
    const std::vector<uint8_t>& input, const size_t start_index);
extern AesBlock CharVectorTo128Bits(const std::vector<uint8_t>& input);
// Same as above, but with unsigned char array instead of vector.
extern AesBlock CharVectorTo128Bits(
    const uint8_t* input, const size_t input_size);
// Same as above, but assumes 'input' has appropriate length (kNumBytesInAesBlock).
extern AesBlock CharVectorTo128Bits(const uint8_t* input);
//   vector<unsigned char> (?? bytes) -> AesBlock*
//     The output should have already allocated appropriate memory.
extern void CharVectorToVectorOf128Bits(
    const std::vector<uint8_t>& input, AesBlock* output);
//   AesBlock -> vector<unsigned char> (16 bytes)
//     Appends to end of 'output'.
extern void Native128BitsToCharVector(
    const AesBlock& input, std::vector<uint8_t>* output);
//   AesBlock* -> vector<unsigned char> (16 * N bytes; N = size of input vector)
//     'input' should represent a vector of 'num_inputs' elements.
//     Appends to end of 'output'.
extern void VectorOf128BitsToCharVector(
    const size_t num_inputs,
    const AesBlock* input,
    std::vector<uint8_t>* output);
// On input, schedule should already have allocated 11 * sizeof(AesBlock).
extern void CreateScheduleFromKey(const Aes128Key& key, Aes128EncKey* schedule);
// ====================== END AES-128 Native-Encrypt =========================
// ========================== END AES-128 Encrypt ==============================

// ============================ AES-128 Decrypt ================================
// Discussion: There are four Decryption API's, corresponding to the four
// Encryption API's above, and also the same three implementation options.
// However, Platform implementations (option (A) above) support API's 1-3 only,
// while Nettle and Native implementations (options (B) and (C)) above) support
// API's 1 and 4 only.
// Also, there is a Batch mode or Single mode for each.
// Since AES-128 Encryption creates ciphertexts in blocks of 128 bits (16 bytes),
// the ciphertext 'input' should have size divisible by 16.

// ======================= AES-128 Platform-Decrypt ============================
// Generic API to support APIs 1-3 mentioned above. The provided 'key' will
// be interpreted according to the provided type.
extern bool Aes128PlatformDecrypt(
    const EncryptionMode mode,
    const DecryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// Batch Mode.
extern bool Aes128PlatformDecrypt(
    const EncryptionMode mode,
    const DecryptionKeyType type,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// ===================== END AES-128 Platform-Decrypt ==========================
// ======================= AES-128 Nettle-Decrypt ============================
// Generic API to support API 1 mentioned above.
extern bool Aes128NettleDecrypt(
    const EncryptionMode mode,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// Batch Mode.
extern bool Aes128NettleDecrypt(
    const EncryptionMode mode,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// Generic API to support API 4 mentioned above.
extern bool Aes128NettleDecrypt(
    // No 'const' specified, because some Nettle API's require non-const.
    aes128_ctx* context,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// Batch Mode.
extern bool Aes128NettleDecrypt(
    // No 'const' specified, because some Nettle API's require non-const.
    aes128_ctx* context,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// Same as above, for ECB mode.
extern bool Aes128NettleBlockDecrypt(
    // No 'const' specified, because some Nettle API's require non-const.
    aes128_ctx* context,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// Batch Mode.
extern bool Aes128NettleBlockDecrypt(
    // No 'const' specified, because some Nettle API's require non-const.
    aes128_ctx* context,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// ===================== END AES-128 Nettle-Decrypt ==========================
// ======================= AES-128 Native-Decrypt ============================
// Generic API to support API 1 mentioned above.
extern bool Aes128NativeDecrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// Batch Mode.
extern bool Aes128NativeDecrypt(
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// Generic API to support API 4 mentioned above.
extern AesBlock Aes128NativeDecrypt(
    const Aes128DecKey& key, const AesBlock& input);
// DEPRECATED. Aes128NativeEncrypt() is currently unsupported in ECB mode,
// which is insecure when encrypting multiple blocks, so there is no
// reason why we should need to decrypt more than one block.
// I'll leave this code here as a template, in case it is needed in the future.
// API 4, Batch Mode.
// On input 'schedule' should have size 11, input should have size 'num_blocks',
// and 'output' should have num_blocks (of sizeof(AesBlock) bytes) allocated.
/*
extern bool Aes128NativeDecrypt(
    const int num_blocks, const AesBlock* schedule, const AesBlock* input,
    AesBlock* output);
*/

// Helper function: Gets the decryption schedule from the (encryption) key.
// On input, dec_schedule should already have allocated appropriate memory
// (i.e. slots foo 11 AesBlock elements).
extern void CreateDecryptionScheduleFromEncryptionKey(
    const Aes128Key& enc_key, Aes128DecKey* dec_schedule);
// Same as above, but input is Encryption schedule (as opposed to enc key).
extern void CreateDecryptionScheduleFromEncryptionSchedule(
    const Aes128EncKey& enc_key, Aes128DecKey* dec_schedule);
// ===================== END AES-128 Native-Decrypt ==========================
// ========================== END AES-128 Decrypt ==============================
// ============================== END AES-128 ==================================

// ========================= Generic AES Encrypt ===============================
// The API's below will use the key size to determine which underlying
// AES-XXX protocol to use. Note that if you want to use Aes Encryption
// with a password (which is used to create the Aes Encryption Key) or
// use a randomly generated key (where the (encrypted) key used can
// optionally be returned as part of the API), then you'll need to
// directly call the appropriate AES-XXX method above (instead of using one
// of the 'generic' APIs below).
// Use the API's that take in AesParams if you want control over which of the
// API's 1-4 and/or implementation types A-C are used (see lengthy discussion
// above); if AesParams are not specified, the default is to use API 1 (KEY)
// and implementation B (Nettle).
//
// Note that the encryption is added to the *end* of 'output', in case
// output is non-empty when passed-in.
extern bool AesEncrypt(
    const AesParams& params,
    // Byte-string representation of the key, i.e. key.size() = num bytes in key
    const std::vector<unsigned char>& key,
    // Byte-string representation of the plaintext.
    const std::vector<unsigned char>& input,
    // Holds decryption key (for API 2, where encryption key is created).
    std::vector<unsigned char>* decryption_key,
    // Byte-string representation of the ciphertext.
    std::vector<unsigned char>* output);
// Same as above, but without container for decryption key.
inline bool AesEncrypt(
    const AesParams& params,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output) {
  return AesEncrypt(params, key, input, nullptr, output);
}
// Same as above, except no params.
extern bool AesEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* decryption_key,
    std::vector<unsigned char>* output);
// Same as above, but without container for decryption key.
inline bool AesEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output) {
  return AesEncrypt(key, input, nullptr, output);
}
// Same as above, but Batch Mode: encrypts multiple plaintexts (under same key).
// Since the underlying Encrypt algorithm may have overhead for e.g. key setup, this
// function can speed things up if you have many encryptions under the same key.
extern bool AesEncrypt(
    const AesParams& params,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// Same as above, but with no container for decryption key.
inline bool AesEncrypt(
    const AesParams& params,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs) {
  return AesEncrypt(params, key, inputs, nullptr, outputs);
}
// Same as above, except no params.
extern bool AesEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<unsigned char>* decryption_key,
    std::vector<std::vector<unsigned char>>* outputs);
// Same as above, but with no container for decryption key.
inline bool AesEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs) {
  return AesEncrypt(key, inputs, nullptr, outputs);
}
// ======================= END Generic AES Encrypt =============================

// ========================= Generic AES Decrypt ===============================
// The API's below will use the key size to determine which underlying
// AES-XXX protocol to use. Note that if you want to use Aes Decryption
// with a password (which is used to create the Aes Decryption Key) or
// use an (encrypted) decryption key that was generated randomly and returned
// to a prior call to AesEncrypt, then you'll need to call the
// appropriate AESXXXDecrypt method above.
extern bool AesDecrypt(
    const AesParams& params,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// Same as above, using default values for AesParams.
extern bool AesDecrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* output);
// Same as above, but decrypts multiple ciphertexts (under same key).
extern bool AesDecrypt(
    const AesParams& params,
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// Same as above, using default values for AesParams.
extern bool AesDecrypt(
    const std::vector<unsigned char>& key,
    const std::vector<std::vector<unsigned char>>& inputs,
    std::vector<std::vector<unsigned char>>* outputs);
// ======================= END Generic AES Decrypt =============================

// ========= Platform-Dependent Encryption/Decryption Wrapper Functions ========
// These functions are implemented in [windows | linux]_encryption_utils.cpp,
// as opposed to aes_utils.cpp, so that we don't need any system-dependent code.

// =========================== PlatformAes128Encrypt ===========================
// API 1: User provides encryption key.
extern void PlatformAes128Encrypt(
    const unsigned char* key,
    const uint32_t num_plaintext_bytes,
    const unsigned char* plaintext,
    const uint32_t num_ciphertext_bytes,
    unsigned char* ciphertext,
    const EncryptionMode mode);
// API 1: Batch mode.
extern void PlatformAes128Encrypt(
    const uint32_t num_messages,
    const unsigned char* key,
    const uint32_t num_plaintext_bytes[],
    const unsigned char* plaintext,
    const uint32_t num_ciphertext_bytes[],
    unsigned char* ciphertext,
    const EncryptionMode mode);
// API 2: User provides a password.
extern void PlatformAes128Encrypt(
    const uint32_t num_password_bytes,
    const unsigned char* password,
    const uint32_t num_plaintext_bytes,
    const unsigned char* plaintext,
    const uint32_t num_ciphertext_bytes,
    unsigned char* ciphertext,
    const EncryptionMode mode);
// API 2: Batch mode.
extern void PlatformAes128Encrypt(
    const uint32_t num_messages,
    const uint32_t num_password_bytes,
    const unsigned char* password,
    const uint32_t num_plaintext_bytes[],
    const unsigned char* plaintext,
    const uint32_t num_ciphertext_bytes[],
    unsigned char* ciphertext,
    const EncryptionMode mode);
// API 3: Generate an encryption key, and store it in 'encrypted_symmetric_key'
// if non-null (if encrypted_symmetric_key is null, the encryption key will be
// lost, so decrypting later is impossible; this use-case may still be useful in
// some settings, so it is supported here). If non-null, encrypted_symmetric_key
// must have already allocated 'max_enc_sym_key_bytes' (either through [m]alloc
// for a raw char pointer, or via resize() for vectors); only the first
// 'actual_enc_sym_key_bytes' should be used (e.g. resize a vector on return).
// NOTE: In order to decrypt the ciphertext later, the 'encrypted_symmetric_key'
// will have to first be decrypted. The encryption of the random symmetric key
// is inturn done using a key that gets generated for the User; and is fetchable
// only by the same User (via CryptGetUserKey()).
extern void PlatformAes128Encrypt(
    const uint32_t num_plaintext_bytes,
    const unsigned char* plaintext,
    const uint32_t num_ciphertext_bytes,
    unsigned char* ciphertext,
    const uint32_t max_enc_sym_key_bytes,
    unsigned char* encrypted_symmetric_key,
    uint32_t* actual_enc_sym_key_bytes,
    const EncryptionMode mode);
// API 3: Batch mode.
extern void PlatformAes128Encrypt(
    const uint32_t num_messages,
    const uint32_t num_plaintext_bytes[],
    const unsigned char* plaintext,
    const uint32_t num_ciphertext_bytes[],
    unsigned char* ciphertext,
    const uint32_t max_enc_sym_key_bytes,
    unsigned char* encrypted_symmetric_key,
    uint32_t* actual_enc_sym_key_bytes,
    const EncryptionMode mode);
// ========================== END PlatformAes128Encrypt =========================

// ============================ PlatformAes128Decrypt ===========================
// Discussion:
// There are 3 API's for Decrypt, corresponding to the 3 API's for Encrypt:
//   1) Encryption via key
//   2) Encryption via provided password (which generated the encryption key)
//   3) Encryption via randomly generated password, which was stored
// As with encrypt, each API can be run in batch mode or for a single ciphertext.
// For all APIs, the provided 'plaintext' container must have already allocated
// 'num_plaintext_bytes' (either through [m]alloc for a raw char pointer, or via
// resize() for vectors).
// Passing in 'num_plaintext_bytes' is redundant, since this should exactly
// 'num_ciphertext_bytes'; but we keep it in the API, to make it clear that
// this much memory has already been allocated for 'plaintext'.
//
// API 1: Decryption with decryption key provided directly (matches API 1 above)
// Note that the provided key is the same one provided to the corresponding
// PlatformAes128Encrypt() call when the ciphertext was created.
extern void PlatformAes128Decrypt(
    const unsigned char* key,
    const uint32_t num_ciphertext_bytes,
    const unsigned char* ciphertext,
    const uint32_t num_plaintext_bytes,
    unsigned char* plaintext,
    const EncryptionMode mode);
// API 1: Batch mode.
extern void PlatformAes128Decrypt(
    const uint32_t num_messages,
    const unsigned char* key,
    const uint32_t num_ciphertext_bytes[],
    const unsigned char* ciphertext,
    const uint32_t num_plaintext_bytes[],
    unsigned char* plaintext,
    const EncryptionMode mode);
// API 2 + 3: Decryption with a password or with (encrypted) decryption key
// We toggle behavior (API 2 vs. API 3) based on the 'is_key_encrypted'
// parameter: if true, this is API 3, otherwise it is API 2.
// For API 2, the password is provided in the 'key' parameter, and it should
// be the same one provided to the corresponding PlatformAes128Encrypt() call
// when the ciphertext was created.
// For API 3, the (encrypted) decryption key is provided in the 'key' parameter,
// and it should be the key that was returned in 'encrypted_symmetric_key'
// when the corresponding PlatformAes128Encrypt() call was made.
extern void PlatformAes128Decrypt(
    const bool is_key_encrypted,
    const uint32_t num_key_bytes,
    const unsigned char* key,
    const uint32_t num_ciphertext_bytes,
    const unsigned char* ciphertext,
    const uint32_t num_plaintext_bytes,
    unsigned char* plaintext,
    const EncryptionMode mode);
// API 2 + 3: Batch mode.
extern void PlatformAes128Decrypt(
    const uint32_t num_messages,
    const bool is_key_encrypted,
    const uint32_t num_key_bytes,
    const unsigned char* key,
    const uint32_t num_ciphertext_bytes[],
    const unsigned char* ciphertext,
    const uint32_t num_plaintext_bytes[],
    unsigned char* plaintext,
    const EncryptionMode mode);
// ========================== END PlatformAes128Decrypt =========================

// ======= END Platform-Dependent Encryption/Decryption Wrapper Functions ======

}  // namespace encryption
}  // namespace crypto

#endif
