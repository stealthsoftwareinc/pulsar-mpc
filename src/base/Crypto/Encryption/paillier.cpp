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

#include "paillier.h"

#include "Crypto/RandomNumberGeneration/random_utils.h"
#include "FileReaderUtils/read_file_utils.h"
#include "MathUtils/large_int.h"
#include "global_utils.h"

#include <fstream>
#include <string>
#include <vector>

using namespace crypto::random_number;
using namespace file_reader_utils;
using namespace math_utils;
using namespace string_utils;
using namespace std;

// 4G - 4MB; setting this to 4G doesn't work, as that (exactly) overflows unsigned long.
static const unsigned long kMaxBufferSize =
    (unsigned long) 4 * 1024 * 1024 * 1023;

// Generating a Paillier prime number isn't guaranteed to be successful;
// indeed, it often fails, because we're trying to generate a prime via
//   p = 2 * prime + 1
// which often is *not* prime. This caps the number of attempts, preventing
// hanging on this too long (program will abort, and can be reevaluated to
// better handle performance).
// NOTE: The number of times 2 * p + 1 fails to be prime depends on |p|.
// For |p| = 512 bits, it is ~100 failures, while for |p| = 2048, it is ~1000 failures.
// This number will need to be adjusted if kPaillierCryptosystemBits increases
// (as security relies on larger and larger primes for Paillier).
static const unsigned int kMaxFailedPaillierPrimeGeneration = 10000;

// Generating Paillier parameter 'mu' can fail, if Paillier parameter 'g'
// does not have a multiplicative inverse in Z_n^2. If so, a new candidate
// for 'g' will be tried, and so on. This caps the number of failed attempts.
static const unsigned int kMaxFailedMuGeneration = 10;

namespace crypto {
namespace encryption {

// Anonymous namespace for "private" functions.
namespace {

// Generates one of the primes {p, q} used for Paillier cryptosystem.
bool GeneratePaillierPrime(const uint32_t& modulus_bits, LargeInt* prime) {
  // First, find the largest value expressable in 'modulus_bits'.
  LargeInt modulus = pow(LargeInt(2), modulus_bits);

  int num_failed_attempts = -1;
  do {
    ++num_failed_attempts;

    // First, pick a random value in [0, modulus).
    LargeInt baseline = RandomInModulus(modulus);

    // Pick a prime close to baseline.
    // TODO(PHB): This code attempts to find a prime p = 2p' + 1. However, there
    // is no real reason not to just try p = 2m + 1 (where m is not necessarily
    // prime), other than perhaps? Sophie-Germain conjecture that 2p' + 1 is
    // more likely to be prime than 2m + 1. If time becomes an issue, consider
    // switching to 2m + 1, which eliminates the call to NextPrime() below
    // (and then would change the following line to: *prime = baseline * 2 + 1;
    LargeInt temp = NextPrime(baseline);

    // Set 'prime' = 2 * prime + 1. This will guarantee pq vs. (p - 1) * (q - 1)
    // are relatively prime; however, the resulting value is prime with
    // low probability, so we need to repeat this process many times until
    // it actually *is* prime.
    *prime = temp * 2 + 1;

    // Make sure 'prime' is actually prime.
  } while (!IsPrime(*prime) &&
           num_failed_attempts < (int) kMaxFailedPaillierPrimeGeneration);

  return num_failed_attempts < (int) kMaxFailedPaillierPrimeGeneration;
}

// Computes L(input), where L is the Paillier "L" function:
//   L(x) = (x - 1) / n
// https://en.wikipedia.org/wiki/Paillier_cryptosystem#Key_generation
void PaillierLFunction(
    const LargeInt& n, const LargeInt& input, LargeInt* output) {
  *output = (input - 1) / n;
}

// Given inputs lambda and n (and n^2), generates a random generator g \in Z_n^2
// and computes mu = (L(g^lambda (mod n^2)))^-1.
bool GeneratePaillierMu(
    const LargeInt& lambda,
    const LargeInt& n,
    const LargeInt& n_squared,
    LargeInt* g,
    LargeInt* mu) {
  int num_failed_attempts = -1;
  bool has_inverse = false;
  int generator_first_try = 2;
  do {
    num_failed_attempts++;

    // NOTE: A better? (more secure?) implementation would be to try a truly
    // random value g \in Z_n^2 for a generator, which can be done by using
    // the commented-out line below (i.e. the RandomInModulus() function).
    // We instead just try g = {2, 3, 4, ...}, because RandomInModulus()
    // takes time (and perhaps just doing g = {2, 3, ...} doesn't cost security?).
    // TODO(PHB): Ensure that using g = {2, 3, 4, ...} doesn't compromise security.
    //*g = RandomInModulus(n_squared);
    *g = (uint32_t) generator_first_try;
    ++generator_first_try;

    // Compute g^lambda (mod n^2).
    LargeInt g_pow_lambda = pow(*g, lambda, n_squared);

    // Compute L(g^lambda (mod n^2)).
    LargeInt paillier_l_function;
    PaillierLFunction(n, g_pow_lambda, &paillier_l_function);

    // Compute mu = L(g^lambda (mod n^2))^-1, where inverse is w.r.t. mod n,
    // if it exists.
    has_inverse = InverseModN(paillier_l_function, n, mu);
  } while (!has_inverse && num_failed_attempts < (int) kMaxFailedMuGeneration);

  return true;
}

}  // namespace

bool PaillierEncrypt(
    const LargeInt& plaintext,
    const PaillierPublicKey& key,
    LargeInt* ciphertext) {
  // Make sure plaintext does not exceed Paillier modulus.
  if (plaintext >= key.n_) {
    LOG_ERROR(
        "Unable to PaillierEncrypt(): Message size exceeds "
        "Paillier modulus size: \n" +
        key.n_.Print() + "\nvs.\n" + plaintext.Print());
    return false;
  }

  // Generate randomness 'r' to use.
  const LargeInt r = RandomInModulus(key.n_);

  // Set ciphertext: g^m * r^n (mod n^2).
  PaillierHomomorphicCombination(
      key.g_, plaintext, r, key.n_, key.n_squared_, ciphertext);

  return true;
}

bool PaillierDecrypt(
    const PlaintextType type,
    const uint32_t plaintext_size,
    const PaillierSecretKey& secret_key,
    const LargeInt& ciphertext,
    vector<unsigned char>* plaintext) {
  LargeInt decryption;
  if (!PaillierDecrypt(secret_key, ciphertext, &decryption)) return false;

  if (type == PlaintextType::UINT32) {
    ValueToCharVector<uint32_t>(decryption.GetValue()->GetUInt32(), plaintext);
    return true;
  } else if (type == PlaintextType::UINT64) {
    ValueToCharVector<uint64_t>(decryption.GetValue()->GetUInt32(), plaintext);
    return true;
  } else if (
      type == PlaintextType::LARGE_INT || type == PlaintextType::BYTE_STRING ||
      type == PlaintextType::BIT_STRING) {
    // Make sure decryption fits in the number of bytes specified.
    const int actual_plaintext_bytes = decryption.NumBytes();
    const int plaintext_bytes =
        plaintext_size > 0 ? plaintext_size : actual_plaintext_bytes;
    if (plaintext_bytes < actual_plaintext_bytes) {
      LOG_ERROR(
          "Failed to PaillierDecrypt() to BYTE string. Expected num bytes: " +
          Itoa(plaintext_bytes) +
          ", LargeInt size: " + Itoa(actual_plaintext_bytes));
      return false;
    }

    // If plaintext can be represented in fewer bits than specified, 0-pad so
    // that it is exactly the number of bits specified.
    if (actual_plaintext_bytes < plaintext_bytes) {
      const size_t orig_size = plaintext->size();
      plaintext->resize(orig_size + (plaintext_bytes - actual_plaintext_bytes));
      for (int i = 0; i < plaintext_bytes - actual_plaintext_bytes; ++i) {
        (*plaintext)[orig_size + i] = (unsigned char) 0;
      }
    }
    // LARGE_INT, BYTE_STRING, and BIT_STRING are all handled identically, since
    // we'll be storing the plaintext in a char array, and LargeInt does
    // conversion of value <-> char array in Big Endian, i.e. so that the bytes
    // represent the byte/binary string of the value.
    LargeIntToByteString(decryption, plaintext);
    return true;
  }

  // Should've already returned above.
  LOG_ERROR(
      "Failed to PaillierDecrypt(): Unsupported PlaintextType: " +
      Itoa(static_cast<int>(type)));
  return false;
}

bool PaillierDecrypt(
    const PaillierSecretKey& secret_key,
    const LargeInt& ciphertext,
    LargeInt* plaintext) {
  // Compute c^lambda (mod n^2).
  // NOTE: The line below is the bottleneck of Decrypt; all other operations here
  // (and in the other PaillierDecrypt() methods) contribute negligible amount of
  // time compared to this line.
  const LargeInt temp =
      pow(ciphertext, secret_key.lambda_, secret_key.n_squared_);

  // Apply Paillier function L(c^lambda (mod n^2)).
  PaillierLFunction(secret_key.n_, temp, plaintext);

  // Compute plaintext = [L(c^lambda (mod n^2)) * mu] (mod n).
  *plaintext = (*plaintext * secret_key.mu_) % secret_key.n_;

  return true;
}

bool ReadPaillierPublicKey(
    const string& n_filename, const string& g_filename, PaillierPublicKey* key) {
  if (key == nullptr || n_filename.empty() || g_filename.empty()) {
    LOG_FATAL("Null input to ReadPaillierPublicKey().");
  }

  // Open key file holding 'n'.
  // Open ate (at_end), so we can read the number of bytes.
  ifstream n_key_file(n_filename, ios::ate | ifstream::binary);
  if (!n_key_file.is_open()) {
    return false;
  }

  // Make sure file can be read into memory.
  int64_t file_size = n_key_file.tellg();
  unsigned long block_size =
      static_cast<unsigned long>(min(kMaxBufferSize, (unsigned long) file_size));
  if (block_size != (uint64_t) file_size) {
    LOG_ERROR(
        "Unable to handle Paillier Key file '" + n_filename +
        "': It is too big!");
    return false;
  }

  // Read file into a character array.
  vector<char> buffer(block_size);
  n_key_file.seekg(0, ios::beg);
  n_key_file.read(buffer.data(), block_size);
  n_key_file.close();

  // Cast buffer (character array) as an LargeInt.
  key->n_ = LargeInt::ByteStringToLargeInt(buffer);

  // Set n_squared_.
  key->n_squared_ = key->n_ * key->n_;

  // Open key file holding 'g'.
  ifstream g_key_file(g_filename, ios::ate | ifstream::binary);
  if (!g_key_file.is_open()) {
    return false;
  }

  // Make sure file can be read into memory.
  file_size = g_key_file.tellg();
  block_size =
      static_cast<unsigned long>(min(kMaxBufferSize, (unsigned long) file_size));
  if (block_size != (uint64_t) file_size) {
    LOG_ERROR(
        "Unable to handle Paillier Key file '" + g_filename +
        "': It is too big!");
    return false;
  }

  // Read file into a character array.
  buffer.clear();
  buffer.resize(block_size);
  g_key_file.seekg(0, ios::beg);
  g_key_file.read(buffer.data(), block_size);
  g_key_file.close();

  // Cast buffer (character array) as an LargeInt.
  key->g_ = LargeInt::ByteStringToLargeInt(buffer);

  return true;
}

bool ReadPaillierSecretKey(
    const string& n_filename,
    const string& lambda_filename,
    const string& mu_filename,
    PaillierSecretKey* key) {
  if (key == nullptr || n_filename.empty() || lambda_filename.empty() ||
      mu_filename.empty()) {
    LOG_FATAL("Null input to ReadPaillierSecretKey().");
  }

  // Open key file holding 'n'.
  // Open ate (at_end), so we can read the number of bytes.
  ifstream n_key_file(n_filename, ios::ate | ifstream::binary);
  if (!n_key_file.is_open()) {
    return false;
  }

  // Make sure file can be read into memory.
  int64_t file_size = n_key_file.tellg();
  unsigned long block_size =
      static_cast<unsigned long>(min(kMaxBufferSize, (unsigned long) file_size));
  if (block_size != (uint64_t) file_size) {
    LOG_ERROR(
        "Unable to handle Paillier Key file '" + n_filename +
        "': It is too big!");
    return false;
  }

  // Read file into a character array.
  vector<char> buffer(block_size);
  n_key_file.seekg(0, ios::beg);
  n_key_file.read(buffer.data(), block_size);
  n_key_file.close();

  // Cast buffer (character array) as a LargeInt.
  key->n_ = LargeInt::ByteStringToLargeInt(buffer);

  // Set n_squared_.
  key->n_squared_ = key->n_ * key->n_;

  // Open key file holding 'lambda'.
  ifstream lambda_key_file(lambda_filename, ios::ate | ifstream::binary);
  if (!lambda_key_file.is_open()) {
    return false;
  }

  // Make sure file can be read into memory.
  file_size = lambda_key_file.tellg();
  block_size =
      static_cast<unsigned long>(min(kMaxBufferSize, (unsigned long) file_size));
  if (block_size != (uint64_t) file_size) {
    LOG_ERROR(
        "Unable to handle Paillier Key file '" + lambda_filename +
        "': It is too big!");
    return false;
  }

  // Read file into a character array.
  buffer.clear();
  buffer.resize(block_size);
  lambda_key_file.seekg(0, ios::beg);
  lambda_key_file.read(buffer.data(), block_size);
  lambda_key_file.close();

  // Cast buffer (character array) as a LargeInt.
  key->lambda_ = LargeInt::ByteStringToLargeInt(buffer);

  // Open key file holding 'mu'.
  ifstream mu_key_file(mu_filename, ios::ate | ifstream::binary);
  if (!mu_key_file.is_open()) {
    return false;
  }

  // Make sure file can be read into memory.
  file_size = mu_key_file.tellg();
  block_size =
      static_cast<unsigned long>(min(kMaxBufferSize, (unsigned long) file_size));
  if (block_size != (uint64_t) file_size) {
    LOG_ERROR(
        "Unable to handle Paillier Key file '" + mu_filename +
        "': It is too big!");
    return false;
  }

  // Read file into a character array.
  buffer.clear();
  buffer.resize(block_size);
  mu_key_file.seekg(0, ios::beg);
  mu_key_file.read(buffer.data(), block_size);
  mu_key_file.close();

  // Cast buffer (character array) as a LargeInt.
  key->mu_ = LargeInt::ByteStringToLargeInt(buffer);

  return true;
}

bool WritePaillierPublicKey(
    const string& n_filename,
    const string& g_filename,
    const PaillierPublicKey& key) {
  if (n_filename.empty() || g_filename.empty()) {
    LOG_FATAL("Null input to WritePaillierPublicKey().");
  }

  // Open Key file for 'n_'.
  if (!CreateDir(GetDirectory(n_filename))) {
    LOG_ERROR("Unable to write to Paillier Key file '" + n_filename + "'.");
    return false;
  }
  ofstream n_outfile(n_filename.c_str(), ofstream::binary);
  if (!n_outfile.is_open()) {
    LOG_ERROR("Unable to write to Paillier Key file '" + n_filename + "'.");
    return false;
  }

  // Write key to file.
  vector<unsigned char> n_buffer;
  LargeIntToByteString(key.n_, &n_buffer);
  n_outfile.write((char*) n_buffer.data(), n_buffer.size());

  // Close file.
  n_outfile.close();

  // Open Key file for 'g_'.
  if (!CreateDir(GetDirectory(g_filename))) {
    LOG_ERROR("Unable to write to Paillier Key file '" + g_filename + "'.");
    return false;
  }
  ofstream g_outfile(g_filename.c_str(), ofstream::binary);
  if (!g_outfile.is_open()) {
    LOG_ERROR("Unable to write to Paillier Key file '" + g_filename + "'.");
    return false;
  }

  // Write key to file.
  vector<unsigned char> g_buffer;
  LargeIntToByteString(key.g_, &g_buffer);
  g_outfile.write((char*) g_buffer.data(), g_buffer.size());

  // Close file.
  g_outfile.close();

  return true;
}

bool WritePaillierSecretKey(
    const string& lambda_filename,
    const string& mu_filename,
    const PaillierSecretKey& key) {
  if (lambda_filename.empty() || mu_filename.empty()) {
    LOG_FATAL("Null input to WritePaillierSecretKey().");
  }

  // Open Key file for 'lambda_'.
  if (!CreateDir(GetDirectory(lambda_filename))) {
    LOG_ERROR("Unable to write to Paillier Key file '" + lambda_filename + "'.");
    return false;
  }
  ofstream lambda_outfile(lambda_filename.c_str(), ofstream::binary);
  if (!lambda_outfile.is_open()) {
    LOG_ERROR("Unable to write to Paillier Key file '" + lambda_filename + "'.");
    return false;
  }

  // Write key to file.
  vector<unsigned char> lambda_buffer;
  LargeIntToByteString(key.lambda_, &lambda_buffer);
  lambda_outfile.write((char*) lambda_buffer.data(), lambda_buffer.size());

  // Close file.
  lambda_outfile.close();

  // Open Key file for 'mu_'.
  if (!CreateDir(GetDirectory(mu_filename))) {
    LOG_ERROR("Unable to write to Paillier Key file '" + mu_filename + "'.");
    return false;
  }
  ofstream mu_outfile(mu_filename.c_str(), ofstream::binary);
  if (!mu_outfile.is_open()) {
    LOG_ERROR("Unable to write to Paillier Key file '" + mu_filename + "'.");
    return false;
  }

  // Write key to file.
  vector<unsigned char> mu_buffer;
  LargeIntToByteString(key.mu_, &mu_buffer);
  mu_outfile.write((char*) mu_buffer.data(), mu_buffer.size());

  // Close file.
  mu_outfile.close();

  return true;
}

bool GeneratePaillierParameters(PaillierParams* params) {
  if (params == nullptr)
    LOG_FATAL("Null input to GeneratePaillierParameters().");

  // Read keys from file, if appropriate.
  if (params->read_keys_from_file_) {
    if (!ReadPaillierPublicKey(
            params->key_file_n_, params->key_file_g_, &params->public_key_) ||
        !ReadPaillierSecretKey(
            params->key_file_n_,
            params->key_file_lambda_,
            params->key_file_mu_,
            &params->secret_key_)) {
      LOG_ERROR("Unable to read Paillier Parameters from file.");
      return false;
    }
  } else if (!GeneratePaillierParameters(
                 params->modulus_bits_,
                 &params->public_key_,
                 &params->secret_key_)) {
    LOG_ERROR("Unable to generate Paillier Parameters.");
    return false;
  }

  // Now write keys to file, if appropriate.
  if (params->write_keys_to_file_) {
    return (
        WritePaillierPublicKey(
            params->key_file_n_, params->key_file_g_, params->public_key_) &&
        WritePaillierSecretKey(
            params->key_file_lambda_,
            params->key_file_mu_,
            params->secret_key_));
  }

  return true;
}

bool GeneratePaillierParameters(
    const uint32_t& modulus_bits,
    PaillierPublicKey* public_key,
    PaillierSecretKey* secret_key) {
  // Generate the Paillier primes 'p' and 'q'.
  LargeInt p, q;
  // NOTE: Dividing by 2 in the first parameter below is because the
  // Paillier modulus is for the overall system N = pq, and thus
  // N having X bits means p and q each have X / 2 bits.
  if (!GeneratePaillierPrime(modulus_bits / 2, &p) ||
      !GeneratePaillierPrime(modulus_bits / 2, &q)) {
    DLOG_ERROR(
        "Failed to Generate Paillier Parameters: Choice of primes p and q "
        "is a randomized process, and the restriction that p = (2p' - 1), "
        "and similarly for q, means that such primes may not be found "
        "even after the (" +
        Itoa(kMaxFailedPaillierPrimeGeneration) +
        " attempts that are made. Re-running this process (which will "
        "automatically use new randomness) will likely result in success.");
    return false;
  }

  // Set n_ = p * q;
  public_key->n_ = p * q;
  secret_key->n_ = public_key->n_;

  // Compute n^2.
  public_key->n_squared_ = public_key->n_ * public_key->n_;
  secret_key->n_squared_ = public_key->n_squared_;

  // Compute lambda = lcm(p - 1, q - 1).
  secret_key->lambda_ = lcm(p - 1, q - 1);

  // Set random generator 'g' and Paillier parameter \mu.
  if (!GeneratePaillierMu(
          secret_key->lambda_,
          public_key->n_,
          public_key->n_squared_,
          &public_key->g_,
          &secret_key->mu_)) {
    DLOG_ERROR("Failed to GeneratePaillierParameters(), because "
               "GeneratePaillierMu() failed.");
    return false;
  }

  return true;
}

void PaillierRerandomize(
    const LargeInt& n, const LargeInt& n_squared, LargeInt* ciphertext) {
  // Generate randomness 'r' to use.
  const LargeInt randomness = RandomInModulus(n);

  // r = r^n (mod n^2)
  // TODO(PHB): See note below about the bottleneck of computing r^n (mod n^2),
  // which is likewise the case for this function.
  const LargeInt r = pow(randomness, n, n_squared);

  // c = c * r^n (mod n^2)
  *ciphertext = (*ciphertext * r) % n_squared;
}

void PaillierRerandomize(const LargeInt& n, LargeInt* ciphertext) {
  PaillierRerandomize(n, n * n, ciphertext);
}

void PaillierSum(
    const LargeInt& c_1,
    const LargeInt& c_2,
    const LargeInt& n_squared,
    LargeInt* result) {
  *result = (c_1 * c_2) % n_squared;  // result = c_1 * c_2 (mod n^2)
}

void PaillierProduct(
    const LargeInt& c,
    const LargeInt& plaintext,
    const LargeInt& n_squared,
    LargeInt* result) {
  *result = pow(c, plaintext, n_squared);  // result = c^p (mod n^2)
}

void PaillierHomomorphicCombination(
    const LargeInt& a,
    const LargeInt& b,
    const LargeInt& c,
    const LargeInt& d,
    const LargeInt& e,
    LargeInt* result) {

  // TODO(PHB): When PaillierHomomorphicCombination() is used as a subroutine
  // of PaillierEncrypt, the step below corresponds to computing:
  //   r^n (mod n^2)
  // and it is the bottleneck in terms of computation time. Figure out a way
  // to reduce this burden (e.g. precompute {r^n_i} for a bunch of r_i's);
  // or, is there another way to quickly get a bunch of {r^n_i}, e.g. just
  // compute r^n (mod n^2) for one fixed value of r, and then can quickly
  // get a bunch more r'^n (mod n^2) by doing some manipulation of r^n?
  *result = (pow(a, b, e) * pow(c, d, e)) % e;
}

}  // namespace encryption
}  // namespace crypto
