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
//   Utility functions for implementing the Paillier Cryptosystem,
//   including Encryption and Oblivious Transfer.

#ifndef PAILLIER_H
#define PAILLIER_H

#include "GenericUtils/char_casting_utils.h"  // For CharVectorToValue
#include "MathUtils/large_int.h"

#include <string>
#include <vector>

using math_utils::LargeInt;

namespace crypto {
namespace encryption {

// Paillier cryptosystem needs to be roughly 2k bits to be secure.
static const uint32_t kPaillierCryptosystemBits = 2048;

// The Message space of the Paillier Cryptosystem: All messages will be cast
// as LargeInt before encrypting, so the Plaintext space of the cryptosystem
// (as well as the ciphertext space) is LargeInt. However, after decrypting,
// we may want to cast back to another data type; this enum describes what
// type to convert the decrypted ciphertexts to.
enum class PlaintextType {
  LARGE_INT,
  UINT32,
  UINT64,
  BIT_STRING,
  BYTE_STRING,
};

// Parameters for Paillier Crypto System.
//   - Public Key = (n, g); where n = pq, and g is generator for Z*_n^2
//   - Secret Key = (lambda, mu); where lambda = lcm(p - 1, q - 1) and
//                  mu = (L(g^lambda (mod n^2)))^-1 (mod n)
// See Key Generation on Paillier Cryptosystem wiki:
// https://en.wikipedia.org/wiki/Paillier_cryptosystem#Key_generation
struct PaillierPublicKey {
  LargeInt n_;
  LargeInt n_squared_;
  LargeInt g_;

  PaillierPublicKey() {}

  virtual ~PaillierPublicKey() {}

  PaillierPublicKey(const PaillierPublicKey& x) {
    n_ = x.n_;
    n_squared_ = x.n_squared_;
    g_ = x.g_;
  }

  PaillierPublicKey& operator=(const PaillierPublicKey& x) {
    n_ = x.n_;
    n_squared_ = x.n_squared_;
    g_ = x.g_;
    return *this;
  }

  bool operator==(const PaillierPublicKey& x) {
    return (n_ == x.n_ && n_squared_ == x.n_squared_ && g_ == x.g_);
  }
};

struct PaillierSecretKey {
  LargeInt n_;
  LargeInt n_squared_;
  LargeInt lambda_;
  LargeInt mu_;

  PaillierSecretKey() {}

  virtual ~PaillierSecretKey() {}

  PaillierSecretKey(const PaillierSecretKey& x) {
    n_ = x.n_;
    n_squared_ = x.n_squared_;
    lambda_ = x.lambda_;
    mu_ = x.mu_;
  }

  PaillierSecretKey& operator=(const PaillierSecretKey& x) {
    n_ = x.n_;
    n_squared_ = x.n_squared_;
    lambda_ = x.lambda_;
    mu_ = x.mu_;
    return *this;
  }

  // NOTE: Ditto above note, as to why I don't input a 'const' parameter.
  bool operator==(PaillierSecretKey& x) {
    return (
        n_ == x.n_ && n_squared_ == x.n_squared_ && lambda_ == x.lambda_ &&
        mu_ == x.mu_);
  }
};

// Parameters to construct Paillier keys. May also hold the generated key(s).
struct PaillierParams {
  // The minimum number of bits for the Paillier primes p, q.
  uint32_t modulus_bits_;

  PaillierPublicKey public_key_;
  PaillierSecretKey secret_key_;

  // Paillier Cryptosystem is implemented using LargeInt.
  // However, the underlying message space might be much smaller than Z_n;
  // i.e. it might be smallish values (e.g. uint32_t), or even a sequence of
  // bits/bytes. These fields direct how to decrypt to the appropriate date type.
  PlaintextType type_;
  // In case type_ is [BIT | BYTE]_STRING, this gives the number of bytes
  // (resp. bits) in each secret.
  uint32_t plaintext_size_;

  // In case the paillier keys should be read from/written to file.
  std::string key_file_n_;
  std::string key_file_g_;
  std::string key_file_lambda_;
  std::string key_file_mu_;

  // Whether the public, secret keys should be read-in from file.
  bool read_keys_from_file_;

  // Whether the public, secret keys should be written to file.
  bool write_keys_to_file_;

  PaillierParams() {
    modulus_bits_ = kPaillierCryptosystemBits;
    type_ = PlaintextType::LARGE_INT;
    plaintext_size_ = 0;
    key_file_n_ = "";
    key_file_g_ = "";
    key_file_lambda_ = "";
    key_file_mu_ = "";
    read_keys_from_file_ = false;
    write_keys_to_file_ = false;
  }
};

// Encrypts 'plaintext' using the provided Paillier public key 'key', using the
// formula: c = g^m * r^n (mod n^2).
extern bool PaillierEncrypt(
    const LargeInt& plaintext,
    const PaillierPublicKey& key,
    LargeInt* ciphertext);
// Same as above, but takes in an int, and converts it to LargeInt.
inline bool PaillierEncrypt(
    const int plaintext, const PaillierPublicKey& key, LargeInt* ciphertext) {
  const LargeInt message((int32_t) plaintext);
  const bool return_value = PaillierEncrypt(message, key, ciphertext);
  return return_value;
}
// Same as above, but takes in an int64_t, and converts it to LargeInt.
inline bool PaillierEncrypt(
    const int64_t& plaintext,
    const PaillierPublicKey& key,
    LargeInt* ciphertext) {
  const LargeInt message(plaintext);
  const bool return_value = PaillierEncrypt(message, key, ciphertext);
  return return_value;
}

// Decrypts 'ciphertext', stores result as a byte (unsigned char) array, where
// the char array is the appropriate cast of message space type; i.e. if type is:
//   - LARGE_INT: Then 'plaintext' is the char array returned by LargeIntToByteString().
//   - UINT32: Then 'plaintext' will have size 4 (= 32 / CHAR_BIT), and the uint32
//             can be recovered via CharVectorToValue(*plaintext)
//   - UINT64: Then 'plaintext' will have size 8 (= 64 / CHAR_BIT), and the uint64
//             can be recovered via CharVectorToValue(*plaintext)
//   - BYTE_STRING: Then 'plaintext' will have size 'plaintext_size', and it will
//                  be the LargeInt value (cast as char array), and padded with
//                  leading 0's to bring it to 'plaintext_size'.
//   - BIT_STRING:  Then 'plaintext' will have size 'plaintext_size', and it will
//                  be the LargeInt value (cast as char array), and padded with
//                  leading 0's to bring it to 'plaintext_size'.
// In the case that type is UINT32 or UINT64, returns false if the LargeInt plaintext
// is larger than max(uint32_t) (resp. max(uint64_t)).
// The 'plaintext_size' input is ignored, unless type is BYTE_STRING or BIT_STRING.
extern bool PaillierDecrypt(
    const PlaintextType type,
    const uint32_t plaintext_size,
    const PaillierSecretKey& secret_key,
    const LargeInt& ciphertext,
    std::vector<unsigned char>* plaintext);
// Same as above, but stores plaintext in the provided LargeInt.
extern bool PaillierDecrypt(
    const PaillierSecretKey& secret_key,
    const LargeInt& ciphertext,
    LargeInt* plaintext);
// Same as above, but assumes message space is uint32_t.
inline bool PaillierDecrypt(
    const PaillierSecretKey& secret_key,
    const LargeInt& ciphertext,
    uint32_t* plaintext) {
  std::vector<unsigned char> temp;
  if (!PaillierDecrypt(
          PlaintextType::UINT32, 0, secret_key, ciphertext, &temp)) {
    return false;
  }
  *plaintext = CharVectorToValue<uint32_t>(temp);
  return true;
}
// Same as above, but assumes message space is uint64_t.
inline bool PaillierDecrypt(
    const PaillierSecretKey& secret_key,
    const LargeInt& ciphertext,
    uint64_t* plaintext) {
  std::vector<unsigned char> temp;
  if (!PaillierDecrypt(
          PlaintextType::UINT64, 0, secret_key, ciphertext, &temp)) {
    return false;
  }
  *plaintext = CharVectorToValue<uint64_t>(temp);
  return true;
}

// Read in a Paillier public key from file.
extern bool ReadPaillierPublicKey(
    const std::string& n_filename,
    const std::string& g_filename,
    PaillierPublicKey* key);
// Read in a Paillier secret key from file.
extern bool ReadPaillierSecretKey(
    const std::string& n_filename,
    const std::string& lambda_filename,
    const std::string& mu_filename,
    PaillierSecretKey* key);
// Write a Paillier public key to file.
extern bool WritePaillierPublicKey(
    const std::string& n_filename,
    const std::string& g_filename,
    const PaillierPublicKey& key);
// Write a Paillier secret key to file.
extern bool WritePaillierSecretKey(
    const std::string& lambda_filename,
    const std::string& mu_filename,
    const PaillierSecretKey& key);

// Generates a Paillier (public_key, secret_key) pair (stored in params->
// public_key_, secret_key_), either by reading them from file (if
// params->[public | secret]_key_file_ is non-empty) or by generating random
// primes of the appropriate number of modulus_bits_.
extern bool GeneratePaillierParameters(PaillierParams* params);
// Same as above, but doesn't check any files first (just generates keys
// based on random primes of size 'modulus_bits').
extern bool GeneratePaillierParameters(
    const uint32_t& modulus_bits,
    PaillierPublicKey* public_key,
    PaillierSecretKey* secret_key);

// Given ciphertext, which has form:
//   g^m * r^n (mod n^2)
// This functions resets ciphertext so that it still decrypts to 'm', but
// has new randomness r':
//   g^m * r'^n (mod n^2)
// More specifically, computes:
//   c_new = c_old * r^n (mod n^2)
// for a random r.
extern void PaillierRerandomize(
    const LargeInt& n, const LargeInt& n_squared, LargeInt* ciphertext);
// Same as above, but computes n_squared.
extern void PaillierRerandomize(const LargeInt& n, LargeInt* ciphertext);

// Given two ciphertexts c_1 = E(p_1) and c_2 = E(p_2), computes:
//   c_1 * c_2 (mod n^2),
// which decrypts to p_1 + p_2.
extern void PaillierSum(
    const LargeInt& c_1,
    const LargeInt& c_2,
    const LargeInt& n_squared,
    LargeInt* result);
// Same as above, but takes in the public key instead of n^2.
inline void PaillierSum(
    const LargeInt& c_1,
    const LargeInt& c_2,
    PaillierPublicKey& key,
    LargeInt* result) {
  PaillierSum(c_1, c_2, key.n_squared_, result);
}

// Given ciphertext c = E(p) and plaintext p', computes:
//   c^p' (mod n^2),
// which decrypts to p * p'.
extern void PaillierProduct(
    const LargeInt& c,
    const LargeInt& plaintext,
    const LargeInt& n_squared,
    LargeInt* result);
// Same as above, but takes in the public key instead of n^2.
inline void PaillierProduct(
    const LargeInt& c,
    const LargeInt& plaintext,
    PaillierPublicKey& key,
    LargeInt* result) {
  PaillierProduct(c, plaintext, key.n_squared_, result);
}

// This function implements the formula:
//   a^b + c^d (mod e)
// which appears frequently in Paillier Cryptosystems (e.g. when encrypting or
// adding two ciphertexts). In particular, if a = c_1 represents a ciphertext
// (say of plaintext p_1), and c = c_2 represents a second ciphertext (say of
// plaintext p_2), and e is the Paillier modululs n^2, then this function computes:
//   c_1^b + c_2^d (mod n^2)
// which is an encryption of the plaintext:
//   (b * p_1) + (d * p_2)
extern void PaillierHomomorphicCombination(
    const LargeInt& a,
    const LargeInt& b,
    const LargeInt& c,
    const LargeInt& d,
    const LargeInt& e,
    LargeInt* result);

}  // namespace encryption
}  // namespace crypto

#endif
