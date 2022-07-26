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

#include "oblivious_transfer_utils.h"

#include "Crypto/Encryption/paillier.h"
#include "Crypto/RandomNumberGeneration/prg_utils.h"
#include "Crypto/RandomNumberGeneration/random_oracle_utils.h"
#include "Crypto/RandomNumberGeneration/random_utils.h"
#include "FileReaderUtils/read_file_utils.h"  // For Read,WriteFile().
#include "GenericUtils/char_casting_utils.h"
#include "GenericUtils/thread.h"
#include "GenericUtils/thread_utils.h"
#include "MathUtils/AbstractAlgebra/group.h"  // For Group functions.
#include "MathUtils/constants.h"  // For slice
#include "MathUtils/large_int.h"  // For LargeInt.
#include "Networking/socket.h"
#include "global_utils.h"

#include <climits>  // For CHAR_BIT
#include <cstring>  // For memcpy
#include <memory>  // For unique_ptr
#include <string>
#include <unistd.h>  // For usleep.
#include <vector>

using namespace crypto::encryption;
using namespace crypto::random_number;
using namespace file_reader_utils;
using namespace math_utils;
using namespace networking;
using namespace string_utils;
using namespace test_utils;
using namespace std;

namespace crypto {

// Anonymous namespace for "private" functions.
namespace {

static const int kNumBytesInSlice = sizeof(slice);
static const int kNumBitsInSlice = kNumBytesInSlice * CHAR_BIT;
// Generate LargeInt constants '1' and '0' once at outset.
static const LargeInt kLargeZero = LargeInt(0);
static const LargeInt kLargeOne = LargeInt(1);

// Checks if 'return_codes' is one of a handful of common failure reasons, and
// if so, returns a targeted error message for these. Otherwise, returns the
// number of return codes, and their string representations.
string GetBadListenReturnCodeMessage(const set<ListenReturnCode>& return_codes) {
  const size_t num_return_codes = return_codes.size();

  if (num_return_codes == 0) {
    return "No Listen Return Code.";
  }

  string code_str = ".";
  if (return_codes.size() == 1) {
    const ListenReturnCode code = *(return_codes.begin());
    if (code == ListenReturnCode::NO_ACTIVITY) {
      code_str = ": Exceeded Timeout waiting for Client.";
    } else {
      code_str = ": " + Itoa(static_cast<int>(*(return_codes.begin()))) + ").";
    }
  }

  if (num_return_codes == 1 &&
      *return_codes.begin() == ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
    return "Received unexpected number of bytes.\nThis likely means "
           "Client and "
           "Server are not in-sync\nin terms of what step of the MPC "
           "protocol "
           "they are currently at.\nBe sure both parties both "
           "have/don't have "
           "the requisite OT files.";
  }

  string return_code_str =
      "Listen Return Codes (" + Itoa(num_return_codes) + "):";
  for (const ListenReturnCode& code_i : return_codes) {
    return_code_str += " " + GetListenReturnCodeString(code_i);
  }

  return return_code_str;
}

// Generates the ciphertexts (c_0, c_1) = (E(c_0), E(c_1)), where the
// ordering of the ciphertexts (w.r.t. first/second coordinate of the pair)
// depends on selection_bit.
bool GeneratePaillierEncryptedSelectionBit(
    PaillierPublicKey& key,
    const bool& selection_bit,
    pair<LargeInt, LargeInt>* ciphertexts) {
  // Generate ciphertexts.
  if (!PaillierEncrypt(
          selection_bit ? kLargeZero : kLargeOne, key, &ciphertexts->first) ||
      !PaillierEncrypt(
          selection_bit ? kLargeOne : kLargeZero, key, &ciphertexts->second)) {
    DLOG_ERROR("Failed to encrypt selection bit.");
    return false;
  }

  return true;
}

bool ClientComputePaillierCiphertext(
    PaillierPublicKey& public_key,
    const bool selection_bit,
    vector<unsigned char>* ciphertexts_and_sizes) {
  pair<LargeInt, LargeInt> ciphertext_pair;
  if (!GeneratePaillierEncryptedSelectionBit(
          public_key, selection_bit, &ciphertext_pair)) {
    DLOG_ERROR("Failure in ClientComputePaillierCiphertext(): Unable to "
               "GeneratePaillierEncryptedSelectionBit");
    return false;
  }

  // We want to first put the sizes of the two ciphertexts into
  // ciphertexts_and_sizes, and then put in the actual ciphertexts.
  // Unfortunately, we don't know the sizes (number of bytes) yet.
  // Instead, we'll insert dummy sizes, then insert the ciphertexts,
  // at which point we'll know the sizes, and we can update the size entries.
  const size_t orig_size = ciphertexts_and_sizes->size();
  if (!ValueToCharVector<int>(0, ciphertexts_and_sizes) ||
      !ValueToCharVector<int>(0, ciphertexts_and_sizes)) {
    DLOG_ERROR("Failure in ClientComputePaillierCiphertext(): "
               "Unable to parse ciphertext sizes");
    return false;
  }

  // Append first ciphertext to ciphertexts_and_sizes.
  LargeIntToByteString(ciphertext_pair.first, ciphertexts_and_sizes);
  const int num_first_ciphertext_bytes =
      (int) (ciphertexts_and_sizes->size() - orig_size - (2 * sizeof(int)));
  LargeIntToByteString(ciphertext_pair.second, ciphertexts_and_sizes);
  const int num_second_ciphertext_bytes =
      (int) (ciphertexts_and_sizes->size() - orig_size - (2 * sizeof(int)) - num_first_ciphertext_bytes);
  int* first_ciphertext_size =
      (int*) (ciphertexts_and_sizes->data() + orig_size);
  *first_ciphertext_size = num_first_ciphertext_bytes;
  int* second_ciphertext_size =
      (int*) (ciphertexts_and_sizes->data() + orig_size + sizeof(int));
  *second_ciphertext_size = num_second_ciphertext_bytes;

  return true;
}

// A structure that holds the inputs (and outputs) the Client uses/generates
// when encrypting the {E(0), E(1)} pairs for Paillier OT.
struct ClientGeneratePaillierCiphertextParams {
  // =============================== Inputs ====================================
  PaillierPublicKey* public_key_;
  vector<bool> selection_bits_;

  // =============================== Outputs ====================================
  vector<unsigned char>* ciphertexts_and_sizes_;
  bool success_;
  string error_msg_;

  ClientGeneratePaillierCiphertextParams() {
    public_key_ = nullptr;
    ciphertexts_and_sizes_ = nullptr;
    success_ = false;
    error_msg_ = "";
  }
};

// The callback function used by Sub-threads to compute the the (Paillier)
// encrypted pairs {E(0), E(1)} based on Client's selection bits.
unsigned ClientComputePaillierCiphertextCallback(void* args) {
  ClientGeneratePaillierCiphertextParams* ciphertext_info =
      (ClientGeneratePaillierCiphertextParams*) args;
  for (size_t i = 0; i < ciphertext_info->selection_bits_.size(); ++i) {
    if (!ClientComputePaillierCiphertext(
            *ciphertext_info->public_key_,
            ciphertext_info->selection_bits_[i],
            ciphertext_info->ciphertexts_and_sizes_)) {
      ciphertext_info->success_ = false;
      ciphertext_info->error_msg_ +=
          "Failed to ClientComputePaillierCiphertext() for secret " + Itoa(i);
      DLOG_ERROR("Failed ClientComputePaillierCiphertext for i: " + Itoa(i));
      return 1;
    }
  }

  ciphertext_info->success_ = true;
  return 0;
}

// Performs the computation of E(s_b), the ciphertext the Server
// generates and returns to the Client during Paillier 1-2 OT.
bool ServerComputePaillierCiphertext(
    const ServerSecretPair& secrets,
    const pair<LargeInt, LargeInt>& client_ciphertexts,
    const LargeInt& n,
    const LargeInt& n_squared,
    uint64_t* total_ciphertext_size,
    LargeInt* ciphertext) {
  // Cast Server's secrets as LargeInt.
  const LargeInt s0 = LargeInt::ByteStringToLargeInt(secrets.s0_);
  const LargeInt s1 = LargeInt::ByteStringToLargeInt(secrets.s1_);

  // Make sure Server's secrets can fit in the given Paillier message space.
  if (s0 >= n || s1 >= n) {
    DLOG_ERROR(
        "Unable to encrypt secret s0:\n" + s0.Print() + "\nor s1:\n" +
        s1.Print() + "\nas one of them exceeds n:\n" + n.Print());
    return false;
  }

  // Perform the "Paillier-OT" computation:
  //   E(s_b) = s_0 * E(~b) + s_1 * E(b)
  //          = s_0 * first_ciphertext + s_1 * second_ciphertext
  PaillierHomomorphicCombination(
      client_ciphertexts.first,
      s0,
      client_ciphertexts.second,
      s1,
      n_squared,
      ciphertext);

  // Rerandomize ciphertext. This is necessary for security, since otherwise
  // the Client may be able to decipher *both* secrets. This is because Client
  // knows the randomness r0 and r1 that were used to generate the original
  // ciphertexts. So if s0 and s1 are known to be small (e.g. bits), then
  // Client can do exhaustive search for {a, b} of
  //   r0^a * r1^b
  // and find the values for 'a' and 'b' such that the following quantity
  // matches the value of the ciphertext that the Client receives:
  //   g^(m0*a + m1*b) * (r0^a * r1^b)^n
  PaillierRerandomize(n, n_squared, ciphertext);
  *total_ciphertext_size += ciphertext->NumBytes();

  return true;
}

// A structure that holds all of the inputs (and outputs) necessary to
// generate a set of ciphertexts {E(s_b)} to return to the Client in Paillier OT.
struct ServerGeneratePaillierCiphertextParams {
  // =============================== Inputs ====================================
  vector<ServerSecretPair*> secrets_;
  LargeInt* paillier_n_;
  LargeInt* paillier_n_squared_;
  vector<pair<LargeInt, LargeInt>*> client_ciphertexts_;

  // =============================== Outputs ====================================
  vector<LargeInt*> ciphertexts_;
  vector<uint64_t> ciphertext_sizes_;
  bool success_;
  string error_msg_;

  ServerGeneratePaillierCiphertextParams() {
    paillier_n_ = nullptr;
    paillier_n_squared_ = nullptr;
    success_ = false;
    error_msg_ = "";
  }

  void SetNumCiphertexts(const size_t& num_ciphertexts) {
    secrets_.resize(num_ciphertexts, nullptr);
    ciphertexts_.resize(num_ciphertexts, nullptr);
    client_ciphertexts_.resize(num_ciphertexts, nullptr);
    ciphertext_sizes_.resize(num_ciphertexts, 0);
  }
};

// The callback function used by Sub-threads to homomorphically compute the
// ciphertext E(s_b) that the Server returns to the Client.
unsigned ServerComputePaillierCiphertextCallback(void* args) {
  ServerGeneratePaillierCiphertextParams* params =
      (ServerGeneratePaillierCiphertextParams*) args;
  if (params->secrets_.size() != params->client_ciphertexts_.size() ||
      params->secrets_.size() != params->ciphertext_sizes_.size() ||
      params->secrets_.size() != params->ciphertexts_.size()) {
    LOG_FATAL("Bad input to ServerComputeCiphertextCallback().");
  }
  for (size_t i = 0; i < params->secrets_.size(); ++i) {
    if (!ServerComputePaillierCiphertext(
            *params->secrets_[i],
            *params->client_ciphertexts_[i],
            *(params->paillier_n_),
            *(params->paillier_n_squared_),
            &(params->ciphertext_sizes_[i]),
            params->ciphertexts_[i])) {
      params->success_ = false;
      params->error_msg_ += "Server's secret too big for Message space.";
      return 1;
    }
  }

  params->success_ = true;
  return 0;
}

bool ClientPaillierDecryptAndStoreSecret(
    const PlaintextType type,
    const int plaintext_size,
    PaillierSecretKey& secret_key,
    const int ciphertext_size,
    const unsigned char* ciphertext_buffer,
    vector<unsigned char>* secret) {
  // Parse byte array representing the ciphertext into an LargeInt.
  LargeInt ciphertext =
      LargeInt::ByteStringToLargeInt(ciphertext_buffer, ciphertext_size);

  if (!PaillierDecrypt(type, plaintext_size, secret_key, ciphertext, secret)) {
    DLOG_ERROR("Failed to ClientPaillierDecryptAndStoreSecret(): "
               "failure decrypting ciphertext.");
    return false;
  }

  return true;
}

// A structure that holds al of the inputs (and outputs) necessary to
// decrypt a (contiguous) subset of the Server's secrets.
struct ClientDecryptPaillierCiphertextParams {
  // =============================== Inputs ====================================
  // If this subset consists of secrets indexes in [a, b] (i.e. secrets
  // s_a, s_a+1, ..., s_a+N), then secret_index_first_ = a and
  // num_secrets_in_block_ = N.
  int64_t secret_index_first_;
  uint64_t num_secrets_in_block_;

  // Decryption key.
  PaillierSecretKey* secret_key_;

  // Data type to decrypt to.
  PlaintextType type_;
  int plaintext_size_;

  // Holds the sizes of *all* ciphertext sizes (not just the relevant subset);
  // so the relevant block should be used, i.e. the indices in
  // [secret_index_first_, secret_index_first_ + num_secrets_in_block_ - 1]
  // should be used.
  vector<int>* ciphertext_sizes_;

  // A pointer to the first ciphertext (E(s_a)); all other ciphertexts follow it.
  unsigned char* first_ciphertext_ptr_;

  // For logging purposes, thread index that is operating on these params.
  int thread_index_;

  // =============================== Outputs ====================================
  vector<vector<unsigned char>*> secrets_;
  bool success_;
  string error_msg_;

  ClientDecryptPaillierCiphertextParams() {
    secret_index_first_ = -1;
    num_secrets_in_block_ = 0;
    secret_key_ = nullptr;
    type_ = PlaintextType::LARGE_INT;
    plaintext_size_ = 0;
    ciphertext_sizes_ = nullptr;
    first_ciphertext_ptr_ = nullptr;
    success_ = false;
    error_msg_ = "";
    thread_index_ = -1;
  }
};

// The callback function used by Sub-threads to (Paillier) decrypt the
// secrets {E(s_b)} the Server sent to the Client.
unsigned ClientPaillierDecryptCiphertextCallback(void* args) {
  ClientDecryptPaillierCiphertextParams* params =
      (ClientDecryptPaillierCiphertextParams*) args;
  // Sanity-Check params indices are consistent.
  if (params == nullptr || params->num_secrets_in_block_ == 0 ||
      params->secret_key_ == nullptr || params->ciphertext_sizes_ == nullptr ||
      params->first_ciphertext_ptr_ == nullptr ||
      (params->secrets_.size() != (size_t) params->num_secrets_in_block_) ||
      ((size_t) (params->secret_index_first_ + params->num_secrets_in_block_) >
       params->ciphertext_sizes_->size())) {
    params->error_msg_ = "Bad input to ClientDecryptCiphertextCallback().";
    params->success_ = false;
    return 1;
  }

  // Go through the num_secrets_in_block_ secrets (starting at index
  // secret_index_first_), decrypting each and putting it in the
  // appropriate index of secrets_.
  uint64_t current_index = 0;
  for (uint64_t i = 0; i < params->num_secrets_in_block_; ++i) {
    const int ciphertext_size =
        (*params->ciphertext_sizes_)[params->secret_index_first_ + i];

    if (!ClientPaillierDecryptAndStoreSecret(
            params->type_,
            params->plaintext_size_,
            *params->secret_key_,
            ciphertext_size,
            params->first_ciphertext_ptr_ + current_index,
            params->secrets_[i])) {
      params->success_ = false;
      params->error_msg_ += "Decryption failed for secret " + Itoa(i);
      return 1;
    }
    current_index += ciphertext_size;
  }

  params->success_ = true;
  return 0;
}

bool ClientApplyPrg(
    const PseudoRandomGeneratorParams& prg_params,
    const vector<unsigned char>& input,
    vector<unsigned char>* output) {
  return ApplyPrg(prg_params, input, output);
}

struct ClientApplyPrgParams {
  // =============================== Inputs ====================================
  // If this subset consists of secrets indexes in [a, b] (i.e. secrets
  // s_a, s_a+1, ..., s_a+N), then secret_index_first_ = a and
  // num_secrets_in_block_ = N.
  uint64_t secret_index_first_;
  uint64_t num_secrets_in_block_;

  const PseudoRandomGeneratorParams* prg_params_;

  // Holds the secrets s_b (not just the relevant subset);
  // so the relevant block should be used, i.e. the indices in
  // [secret_index_first_, secret_index_first_ + num_secrets_in_block_ - 1].
  const vector<ClientSelectionBitAndSecret>* orig_secrets_;

  // For logging purposes, thread index that is operating on these params.
  int thread_index_;

  // =============================== Outputs ====================================
  // prg_secrets_ should already have the right size; the vectors in positions
  // [secret_index_first_, secret_index_first_ + num_secrets_in_block_)
  // will be set.
  vector<vector<unsigned char>>* prg_secrets_;
  bool success_;
  string error_msg_;

  ClientApplyPrgParams() {
    secret_index_first_ = 0;
    num_secrets_in_block_ = 0;
    prg_params_ = nullptr;
    orig_secrets_ = nullptr;
    prg_secrets_ = nullptr;
    success_ = false;
    error_msg_ = "";
  }
};

unsigned ClientApplyPrgCallback(void* args) {
  ClientApplyPrgParams* params = (ClientApplyPrgParams*) args;
  // Sanity-Check params indices are consistent.
  if (params == nullptr || params->num_secrets_in_block_ == 0 ||
      params->prg_params_ == nullptr || params->orig_secrets_ == nullptr ||
      params->prg_secrets_ == nullptr ||
      params->orig_secrets_->size() != params->prg_secrets_->size() ||
      ((size_t) (params->secret_index_first_ + params->num_secrets_in_block_) >
       params->orig_secrets_->size())) {
    params->error_msg_ = "Bad input to ClientApplyPrgCallback().";
    params->success_ = false;
    return 1;
  }

  // Go through the num_secrets_in_block_ secrets (starting at index
  // secret_index_first_), XOR'ing them and storing in xored_secrets_.
  for (uint64_t i = params->secret_index_first_;
       i < params->secret_index_first_ + params->num_secrets_in_block_;
       ++i) {
    if (!ClientApplyPrg(
            *params->prg_params_,
            (*params->orig_secrets_)[i].s_b_,
            &((*params->prg_secrets_)[i]))) {
      params->success_ = false;
      params->error_msg_ +=
          "Decryption failed for thread " + Itoa(params->thread_index_);
      return 1;
    }
  }

  params->success_ = true;
  return 0;
}

bool ServerApplyPrgAndXorSecrets(
    const uint64_t& m_bytes,
    const uint64_t& n_bytes,
    const uint64_t& start_index,
    const uint64_t& num_secrets_to_process,
    const PseudoRandomGeneratorParams& prg_params,
    const vector<ServerSecretPair>& random_secrets,
    const vector<ServerSecretPair>& original_secrets,
    vector<ServerSecretPair>* xored_secrets) {
  const size_t orig_xored_secrets_size = xored_secrets->size();
  xored_secrets->resize(orig_xored_secrets_size + num_secrets_to_process);
  for (uint64_t i = start_index; i < start_index + num_secrets_to_process; ++i) {
    const ServerSecretPair& orig_pair = original_secrets[i];
    const ServerSecretPair& random_pair = random_secrets[i];
    ServerSecretPair& xored_secret_i =
        (*xored_secrets)[orig_xored_secrets_size + i - start_index];

    // Apply PRG to first random secret z0.
    vector<unsigned char> prg_z0;
    if (random_pair.s0_.size() != m_bytes ||
        !ApplyPrg(prg_params, random_pair.s0_, &prg_z0)) {
      DLOG_ERROR("Unable to extend secret " + Itoa(i) + " to n-bits using PRG.");
      return false;
    }

    // Apply PRG to second random secret z1.
    vector<unsigned char> prg_z1;
    if (random_pair.s1_.size() != m_bytes ||
        !ApplyPrg(prg_params, random_pair.s1_, &prg_z1)) {
      DLOG_ERROR("Unable to extend secret " + Itoa(i) + " to n-bits using PRG.");
      return false;
    }

    // XOR the original secrets (s0, s1) with the PRG'ed random secrets
    // (prg(z0), prg(z1)).
    if (prg_z0.size() != n_bytes || orig_pair.s0_.size() != n_bytes ||
        prg_z1.size() != n_bytes || orig_pair.s1_.size() != n_bytes) {
      DLOG_ERROR("Unexpected size mismatch in ServerApplyPrgAndXorSecrets().");
      return false;
    }
    xored_secret_i.s0_.resize(n_bytes);
    xored_secret_i.s1_.resize(n_bytes);
    for (size_t j = 0; j < n_bytes; ++j) {
      xored_secret_i.s0_[j] = prg_z0[j] ^ orig_pair.s0_[j];
      xored_secret_i.s1_[j] = prg_z1[j] ^ orig_pair.s1_[j];
    }
  }

  return true;
}

// A structure that holds all of the inputs (and outputs) necessary to
// xor a set of secrets.
struct ServerXorPrgSecretsParams {
  // =============================== Inputs ====================================
  // If this subset consists of secrets indexes in [a, b] (i.e. secrets
  // s_a, s_a+1, ..., s_a+N), then secret_index_first_ = a and
  // num_secrets_in_block_ = N.
  uint64_t secret_index_first_;
  uint64_t num_secrets_in_block_;

  uint64_t m_bytes_;
  uint64_t n_bytes_;

  const PseudoRandomGeneratorParams* prg_params_;

  // Holds the original (resp. random) secrets (not just the relevant subset);
  // so the relevant block should be used, i.e. the indices in
  // [secret_index_first_, secret_index_first_ + num_secrets_in_block_ - 1].
  const vector<ServerSecretPair>* orig_secrets_;
  const vector<ServerSecretPair>* random_secrets_;

  // For logging purposes, thread index that is operating on these params.
  int thread_index_;

  // =============================== Outputs ====================================
  vector<ServerSecretPair>* xored_secrets_;
  bool success_;
  string error_msg_;

  ServerXorPrgSecretsParams() {
    secret_index_first_ = 0;
    num_secrets_in_block_ = 0;
    m_bytes_ = 0;
    n_bytes_ = 0;
    prg_params_ = nullptr;
    orig_secrets_ = nullptr;
    random_secrets_ = nullptr;
    xored_secrets_ = nullptr;
    success_ = false;
    error_msg_ = "";
  }
};

// The callback function used by Sub-threads to do Server XOR (for PrgOT).
unsigned ServerXorPrgSecretsCallback(void* args) {
  ServerXorPrgSecretsParams* params = (ServerXorPrgSecretsParams*) args;
  // Sanity-Check params indices are consistent.
  if (params == nullptr || params->num_secrets_in_block_ == 0 ||
      params->prg_params_ == nullptr || params->orig_secrets_ == nullptr ||
      params->random_secrets_ == nullptr || params->xored_secrets_ == nullptr ||
      params->orig_secrets_->size() != params->random_secrets_->size() ||
      ((size_t) (params->secret_index_first_ + params->num_secrets_in_block_) >
       params->orig_secrets_->size())) {
    params->error_msg_ = "Bad input to ServerXorPrgSecretsCallback().";
    params->success_ = false;
    return 1;
  }

  // Go through the num_secrets_in_block_ secrets (starting at index
  // secret_index_first_), XOR'ing them and storing in xored_secrets_.
  if (!ServerApplyPrgAndXorSecrets(
          params->m_bytes_,
          params->n_bytes_,
          params->secret_index_first_,
          params->num_secrets_in_block_,
          *params->prg_params_,
          *params->random_secrets_,
          *params->orig_secrets_,
          params->xored_secrets_)) {
    params->success_ = false;
    params->error_msg_ +=
        "Decryption failed for thread " + Itoa(params->thread_index_);
    return 1;
  }

  params->success_ = true;
  return 0;
}

bool ServerROEvaluate(
    const uint64_t& bit_index,
    const uint64_t& m_byte_index,
    const int m_bit_in_byte_index,
    const RandomOracleParams& ro_params,
    const vector<unsigned char>& x_j0,
    const vector<unsigned char>& x_j1,
    const vector<ClientSelectionBitAndSecret>& q_bit_and_secret,
    vector<unsigned char>* buffer) {
  const uint64_t k = q_bit_and_secret.size();

  // Form the pairs (j, q_j) and (j, q_j \xor s), which will be fed into
  // random oracle H.
  vector<unsigned char> j_and_q_j;
  // Add 'j' to j_and_q_j.
  if (!ValueToCharVector<uint64_t>(bit_index, &j_and_q_j)) {
    DLOG_ERROR(
        "Failed to ServerROEvaluate() at m_byte_index: " + Itoa(m_byte_index) +
        ": Unable to convert value to char vector.");
    return false;
  }
  // Copy j from j_and_q_j (which doesn't have q_j yet) to j_and_q_j_xor_s.
  vector<unsigned char> j_and_q_j_xor_s = j_and_q_j;

  // Add q_j (= j^th row of Matrix "Q") to j_and_q_j and j_and_q_j_xor_s
  // (see notation from IKNP, Figure 1).
  // Note that "Q" represents a m x k Matrix. However, it is stored in
  // q_bit_and_secret[j].s_b_; i.e. we have easy-access to the m-bit (byte)
  // columns of the Q-matrix, but what we'll need is access to the rows.
  // Form row-vector q_j from the column vectors of Q.
  // NOTE 1: Use only m-bits of each secret (underlying OT protocol
  // packed these into m / CHAR_BIT bytes).
  // NOTE 2: We'll actually pack row-vector q_j, which has k bits, into
  // (k / CHAR_BIT = params.num_security_param_bytes_) bytes (note that
  // k is necessarily divisible by CHAR_BIT, since  k is the size of
  // q_bit_and_secret, which in turn is CHAR_BIT * params.num_security_param_bytes_).
  const size_t num_j_bytes = j_and_q_j.size();
  const size_t num_k_bytes = k / CHAR_BIT;
  j_and_q_j.resize(num_j_bytes + num_k_bytes);
  j_and_q_j_xor_s.resize(num_j_bytes + num_k_bytes);
  int k_index = 0;
  for (size_t k_byte_index = 0; k_byte_index < num_k_bytes; ++k_byte_index) {
    unsigned char q_j_byte_i = 0;
    unsigned char q_j_xor_s_byte_i = 0;
    for (int k_bit_in_byte_index = 0; k_bit_in_byte_index < CHAR_BIT;
         ++k_bit_in_byte_index) {
      const unsigned char& q_byte_j_of_col_k =
          q_bit_and_secret[k_index].s_b_[m_byte_index];
      // Pick out the relevant bit from this byte: at m_bit_in_byte_index.
      const bool q_ijl =
          (q_byte_j_of_col_k & (1 << (CHAR_BIT - 1 - m_bit_in_byte_index))) != 0;
      // Set the appropriate bit of this (row) byte's value: bit index of
      // this (row) byte is k_bit_in_byte_index.
      if (q_ijl) {
        q_j_byte_i =
            (unsigned char) (q_j_byte_i | (1 << (CHAR_BIT - 1 - k_bit_in_byte_index)));
      }
      if (q_ijl != q_bit_and_secret[k_index].b_) {
        q_j_xor_s_byte_i =
            (unsigned char) (q_j_xor_s_byte_i | (1 << (CHAR_BIT - 1 - k_bit_in_byte_index)));
      }
      ++k_index;
    }
    j_and_q_j[num_j_bytes + k_byte_index] = q_j_byte_i;
    j_and_q_j_xor_s[num_j_bytes + k_byte_index] = q_j_xor_s_byte_i;
  }

  // Compute H(j, q_j) and H(j, q_j \xor s).
  vector<unsigned char> ro_output_zero, ro_output_one;
  if (!ROEvaluate(ro_params, j_and_q_j, &ro_output_zero) ||
      !ROEvaluate(ro_params, j_and_q_j_xor_s, &ro_output_one)) {
    DLOG_ERROR(
        "Failed to ServerROEvaluate(): RO evaluation failed at bit " +
        Itoa(m_bit_in_byte_index) + " of byte " + Itoa(m_byte_index));
    return false;
  }

  // Compute y_j0 = x_j0 \xor H(j, q_j), and y_j1 = x_j1 \xor H(j, q_j \xor s).
  if (x_j0.size() != x_j1.size() ||
      ro_output_zero.size() != ro_output_one.size() ||
      x_j0.size() != ro_output_zero.size()) {
    LOG_FATAL(
        "Mismatching parameters in ServerROEvaluate(), x_j0.size(): " +
        Itoa(x_j0.size()) + ", x_j1.size(): " + Itoa(x_j1.size()) +
        ", ro_output_zero.size(): " + Itoa(ro_output_zero.size()) +
        ", ro_output_one.size(): " + Itoa(ro_output_one.size()) +
        ", ro_params.prg_params_.domain_bits_: " +
        Itoa(ro_params.prg_params_.domain_bits_) +
        ", ro_params.prg_params_.range_bits_: " +
        Itoa(ro_params.prg_params_.range_bits_));
  }
  const size_t orig_secret_bytes = x_j0.size();
  // Add y_j0 to buffer.
  const size_t orig_buffer_size = buffer->size();
  buffer->resize(orig_buffer_size + (orig_secret_bytes * 2));
  for (size_t i = 0; i < orig_secret_bytes; ++i) {
    // Add y_j0 = x_j0 \xor H(j, q_j) to buffer.
    (*buffer)[orig_buffer_size + i] =
        (unsigned int) x_j0[i] ^ (unsigned int) ro_output_zero[i];
  }
  // Add y_j1 to buffer.
  for (size_t i = 0; i < orig_secret_bytes; ++i) {
    // Add y_j1 = x_j1 \xor H(j, q_j \xor s) to buffer.
    (*buffer)[orig_buffer_size + orig_secret_bytes + i] =
        (unsigned int) x_j1[i] ^ (unsigned int) ro_output_one[i];
  }

  return true;
}

// A structure that holds all of the inputs (and outputs) necessary to
// do ServerROEvaluate.
struct ServerROEvaluateParams {
  // =============================== Inputs ====================================
  // This thread will process num_bytes_to_process_ bytes, starting from
  // byte_index_.
  uint64_t bit_index_;
  uint64_t byte_index_;
  uint64_t num_bytes_to_process_;

  const RandomOracleParams* ro_params_;

  // Holds the original (resp. random) secrets (not just the relevant subset);
  // so the relevant block should be used, i.e. the indices in
  // [secret_index_first_, secret_index_first_ + num_secrets_in_block_ - 1].
  const vector<ServerSecretPair>* secrets_;
  const vector<ClientSelectionBitAndSecret>* q_bit_and_secret_;

  // For logging purposes, thread index that is operating on these params.
  int thread_index_;

  // =============================== Outputs ====================================
  vector<vector<unsigned char>>* buffer_;
  bool success_;
  string error_msg_;

  ServerROEvaluateParams() {
    bit_index_ = 0;
    byte_index_ = 0;
    num_bytes_to_process_ = 0;
    ro_params_ = nullptr;
    secrets_ = nullptr;
    q_bit_and_secret_ = nullptr;
    buffer_ = nullptr;
    success_ = false;
    error_msg_ = "";
  }
};

unsigned ServerROEvaluateCallback(void* args) {
  ServerROEvaluateParams* params = (ServerROEvaluateParams*) args;
  // Sanity-Check params indices are consistent.
  if (params == nullptr || params->num_bytes_to_process_ <= 0 ||
      params->ro_params_ == nullptr || params->secrets_ == nullptr ||
      params->q_bit_and_secret_ == nullptr || params->buffer_ == nullptr ||
      params->secrets_->size() != params->buffer_->size()) {
    params->error_msg_ = "Bad input to ServerROEvaluateCallback().";
    params->success_ = false;
    return 1;
  }

  const uint64_t m = params->secrets_->size();
  // Compute {(y_j0, y_j1)}, store results in vector<unsigned char>
  // for easy sending to Client.
  // Notation:
  //   - Q is m x k matrix, stored as a size-k vector, with the i^th column
  //     (for i \in [0..k-1]) holding the m-bit column vector packed into
  //     (m / 8) bytes, and stored in q_bit_and_secret[i].s_b_.
  uint64_t bit_index = params->bit_index_;
  // Loop through the rows of Q (8 rows at a time, since the m-bit column
  // vectors are actually stored in block of (m / 8) bytes.
  for (size_t m_byte_index = params->byte_index_;
       m_byte_index < params->byte_index_ + params->num_bytes_to_process_;
       ++m_byte_index) {
    const int bits_in_this_byte =
        (m_byte_index == 0 && m % CHAR_BIT != 0) ? (m % CHAR_BIT) : CHAR_BIT;
    // Loop through the 8 bits (rows) of the current byte (block of 8 rows).
    for (int m_bit_in_byte_index = CHAR_BIT - bits_in_this_byte;
         m_bit_in_byte_index < CHAR_BIT;
         ++m_bit_in_byte_index) {
      if (bit_index >= m) LOG_FATAL("Bit index too big.");
      if (!ServerROEvaluate(
              bit_index,
              m_byte_index,
              m_bit_in_byte_index,
              *params->ro_params_,
              (*params->secrets_)[bit_index].s0_,
              (*params->secrets_)[bit_index].s1_,
              *params->q_bit_and_secret_,
              &((*params->buffer_)[bit_index]))) {
        params->success_ = false;
        params->error_msg_ +=
            "Failure in ServerROEvaluateCallback() for thread " +
            Itoa(params->thread_index_) +
            "Unable to ServerROEvaluate for m_byte_index: " +
            Itoa(m_byte_index) +
            " and m_bit_in_byte_index: " + Itoa(m_bit_in_byte_index);
        return 1;
      }
      bit_index++;
    }
  }

  return 0;
}

bool ClientROEvaluate(
    const uint64_t& secret_index,
    const uint64_t& m_byte_index,
    const int m_bit_in_byte_index,
    const RandomOracleParams& ro_params,
    const vector<vector<unsigned char>>& y_0,
    const vector<vector<unsigned char>>& y_1,
    const vector<ServerSecretPair>& T,
    vector<ClientSelectionBitAndSecret>* selection_bits_and_output_secret) {
  // Extract row T_j from Matrix "T" (see notation from IKNP, Figure 1).
  // Note that "T" represents a m x k Matrix. However, it is stored in
  // T[j].s0_; i.e. we have easy-access to the m-bit (byte) columns of the
  // T-matrix, but what we'll need is access to the rows. Form row-vector T_j
  // from the column vectors of T.
  const uint64_t k = T.size();
  vector<unsigned char> j_and_T_j;
  // Add 'j' to j_and_T_j.
  if (!ValueToCharVector<uint64_t>(secret_index, &j_and_T_j)) {
    DLOG_ERROR(
        "Failure in ClientROEvaluate(): Unable to add secret_index " +
        Itoa(secret_index) +
        " to j_and_T_j for m_byte_index: " + Itoa(m_byte_index) +
        " and m_bit_in_byte_index: " + Itoa(m_bit_in_byte_index));
    return false;
  }

  // Add T_j to j_and_T_j.
  const size_t num_j_bytes = j_and_T_j.size();
  const size_t num_k_bytes = k / CHAR_BIT;
  j_and_T_j.resize(num_j_bytes + num_k_bytes);
  int k_index = 0;
  for (size_t k_byte_index = 0; k_byte_index < num_k_bytes; ++k_byte_index) {
    unsigned char T_j_byte_i = 0;
    for (int k_bit_in_byte_index = 0; k_bit_in_byte_index < CHAR_BIT;
         ++k_bit_in_byte_index) {
      const unsigned char& t_byte_j_of_col_k = T[k_index].s0_[m_byte_index];
      // Pick out the relevant bit from this byte: at m_bit_in_byte_index.
      const bool t_kjl =
          (t_byte_j_of_col_k & (1 << (CHAR_BIT - 1 - m_bit_in_byte_index))) != 0;
      if (t_kjl) {
        T_j_byte_i =
            (unsigned char) (T_j_byte_i | (1 << (CHAR_BIT - 1 - k_bit_in_byte_index)));
      }
      ++k_index;
    }
    j_and_T_j[num_j_bytes + k_byte_index] = T_j_byte_i;
  }

  // Compute H(j, T_j).
  vector<unsigned char> ro_output_j;
  if (!ROEvaluate(ro_params, j_and_T_j, &ro_output_j)) {
    DLOG_ERROR(
        "Failed to ClientROEvaluate(): RO evaluation failed at j = " +
        Itoa(m_byte_index));
    return false;
  }

  // Compute z_j = y_jb \xor H(j, T_j).
  ClientSelectionBitAndSecret& bit_and_secret_j =
      (*selection_bits_and_output_secret)[secret_index];
  const bool r_j = bit_and_secret_j.b_;
  const vector<unsigned char>& y_jb =
      r_j ? y_1[secret_index] : y_0[secret_index];
  if (y_jb.size() != ro_output_j.size()) {
    LOG_FATAL("Mismatching parameters in ClientROEvaluate().");
  }
  const size_t bytes_per_secret = y_jb.size();
  bit_and_secret_j.s_b_.resize(bytes_per_secret);
  for (size_t i = 0; i < bytes_per_secret; ++i) {
    // Add z_j = y_jb \xor H(j, T_j) to buffer.
    bit_and_secret_j.s_b_[i] =
        (unsigned int) y_jb[i] ^ (unsigned int) ro_output_j[i];
  }

  return true;
}

// A structure that holds all of the inputs (and outputs) necessary to
// do ClientROEvaluate.
struct ClientROEvaluateParams {
  // =============================== Inputs ====================================
  // This thread will process num_bytes_to_process_ bytes, starting from
  // byte_index_.
  uint64_t bit_index_;
  uint64_t byte_index_;
  uint64_t num_bytes_to_process_;

  const RandomOracleParams* ro_params_;

  // Holds the original (resp. random) secrets (not just the relevant subset);
  // so the relevant block should be used, i.e. the indices in
  // [secret_index_first_, secret_index_first_ + num_secrets_in_block_ - 1].
  const vector<vector<unsigned char>>* y_0_;
  const vector<vector<unsigned char>>* y_1_;
  const vector<ServerSecretPair>* T_;

  // For logging purposes, thread index that is operating on these params.
  int thread_index_;

  // =============================== Outputs ====================================
  vector<ClientSelectionBitAndSecret>* selection_bits_and_output_secret_;
  bool success_;
  string error_msg_;

  ClientROEvaluateParams() {
    bit_index_ = 0;
    byte_index_ = 0;
    num_bytes_to_process_ = 0;
    ro_params_ = nullptr;
    y_0_ = nullptr;
    y_1_ = nullptr;
    T_ = nullptr;
    selection_bits_and_output_secret_ = nullptr;
    success_ = false;
    error_msg_ = "";
  }
};

unsigned ClientROEvaluateCallback(void* args) {
  ClientROEvaluateParams* params = (ClientROEvaluateParams*) args;
  // Sanity-Check params indices are consistent.
  if (params == nullptr || params->num_bytes_to_process_ <= 0 ||
      params->ro_params_ == nullptr || params->T_ == nullptr ||
      params->y_0_ == nullptr || params->y_1_ == nullptr ||
      params->selection_bits_and_output_secret_ == nullptr ||
      params->y_0_->size() != params->y_1_->size()) {
    params->error_msg_ = "Bad input to ClientROEvaluateCallback().";
    params->success_ = false;
    return 1;
  }

  // Loop through the rows of T (8 rows at a time, since the m-bit column
  // vectors are actually stored in block of (m / 8) bytes.
  const uint64_t m = params->selection_bits_and_output_secret_->size();
  uint64_t secret_index = params->bit_index_;
  for (size_t m_byte_index = params->byte_index_;
       m_byte_index < params->byte_index_ + params->num_bytes_to_process_;
       ++m_byte_index) {
    const int bits_in_this_byte =
        (m_byte_index == 0 && m % CHAR_BIT != 0) ? (m % CHAR_BIT) : CHAR_BIT;
    // Loop through the 8 bits (rows) of the current byte (block of 8 rows).
    for (int m_bit_in_byte_index = CHAR_BIT - bits_in_this_byte;
         m_bit_in_byte_index < CHAR_BIT;
         ++m_bit_in_byte_index) {
      if (secret_index >= m) LOG_FATAL("secret index too big.");
      if (!ClientROEvaluate(
              secret_index,
              m_byte_index,
              m_bit_in_byte_index,
              *params->ro_params_,
              *params->y_0_,
              *params->y_1_,
              *params->T_,
              params->selection_bits_and_output_secret_)) {
        params->success_ = false;
        params->error_msg_ += "Failure in ClientROEvaluate() for thread " +
            Itoa(params->thread_index_) +
            "Unable to ClientROEvaluate for m_byte_index: " +
            Itoa(m_byte_index) +
            " and m_bit_in_byte_index: " + Itoa(m_bit_in_byte_index);
        return 1;
      }
      secret_index++;
    }
  }

  return 0;
}

// The callback function used by Socket to determine if all of the expected
// bytes of the Paillier Public Key have been received. Specifically, the first
// bytes of the ReceivedData.buffer_ should indicate the number of bytes in the
// key; so test the rest of the buffer_ to see if it is this size. The socket_id
// is ignored (there is only one expected use-case of this function, which
// involves a single connection); it is included in the API so that this
// function is a valid callback for ListenParams.receive_data_.
// Returns true regardless, but sets stats->abort_listening_with_code_
// appropriately.
bool ReceivePaillierPublicKey(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceivePaillierPublicKey(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // The first things sent are the sizes (as int) of the public key components
  // (n, g). Return (will keep Listening) if these haven't been received yet.
  if (num_recd_bytes < 2 * sizeof(int)) {
    return true;
  }

  const char* rec_buffer = buffer.empty() ? data->char_buffer_ : buffer.data();

  const int n_size = CharVectorToValue<int>((const unsigned char*) rec_buffer);
  const int g_size =
      CharVectorToValue<int>((const unsigned char*) rec_buffer + sizeof(int));

  // Return (will keep listening) if not all the expected bytes have been received.
  if (num_recd_bytes < 2 * sizeof(int) + n_size + g_size) {
    // Now that we know expected size of buffer, reserve this size, to
    // minimize the number of resizes that occur.
    if (!buffer.empty()) {
      data->buffer_.reserve(2 * sizeof(int) + n_size + g_size);
    }
    return true;
  }

  // We've received enough bytes. Alert Socket to stop listening on this connection
  // (set the return code to be OK if the exact number of expected bytes were read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > 2 * sizeof(int) + n_size + g_size) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

// The callback function used by Socket to determine if all of the expected
// bytes have been received. Specifically, the first bytes of the
// ReceivedData.buffer_ should indicate the size of each of the ciphertexts
// that will be sent; so test the rest of the buffer_ to see if it is this size.
// The socket_id is ignored (there is only one expected use-case of this
// function, which involves a single connection); it is included in the API so
// that this function is a valid callback for ListenParams.receive_data_.
// Returns true regardless, but sets stats->abort_listening_with_code_
// appropriately.
bool ReceiveEncryptedSelectionBits(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceiveEncryptedSelectionBits(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // The first two things that should be sent is:
  //   1) The number of secret pairs (uint64_t)
  //   2) The total number of ciphertext bytes (uint64_t)
  // Return if these haven't been received yet.
  if (num_recd_bytes < 2 * sizeof(uint64_t)) {
    return true;
  }

  const char* rec_buffer = buffer.empty() ? data->char_buffer_ : buffer.data();

  // Fetch the total number of ciphertext bytes.
  const uint64_t num_ciphertext_bytes = CharVectorToValue<uint64_t>(
      (const unsigned char*) rec_buffer + sizeof(uint64_t));

  // Go through, and sum up the total number of expected bytes (add up all the
  // bytes of all the expected ciphertext pairs).
  uint64_t num_expected_bytes =
      2 * sizeof(uint64_t) +  // For the (2) items listed above
      num_ciphertext_bytes;

  // Return (will keep listening) if not all the expected bytes have been received.
  if (num_recd_bytes < num_expected_bytes) {
    // Now that we know expected size of buffer, reserve this size, to
    // minimize the number of resizes that occur.
    if (!buffer.empty()) {
      data->buffer_.reserve(num_expected_bytes);
    }
    return true;
  }

  // We've received enough bytes. Alert Socket to stop listening on this connection
  // (set the return code to be OK if the exact number of expected bytes were read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > num_expected_bytes) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

// The callback function used by Socket to determine if all of the expected
// bytes have been received. Specifically:
//   1) The first bytes indicate the number of (encrypted) secrets (uint64_t)
//   2) The next bytes indicate the number of bits per secret (int)
//   3) The next bytes indicate the total size of all ciphertext bytes (uint64_t)
// Thus, the total number of expected bytes is:
//   sizeof(uint64_t) + sizeof(int) + sizeof(uint64_t) + (n * B * sizeof(int)) + N;
// where 'n' represents the total number of ciphertexts (1), B is the number
// of bits in each secret (2) and N is the total size of all ciphertexts (3).
// The socket_id is ignored (there is only one expected use-case of this
// function, which involves a single connection); it is included in the API so
// that this function is a valid callback for ListenParams.receive_data_.
// Returns true regardless, but sets stats->abort_listening_with_code_
// appropriately.
bool ReceivePaillierSecrets(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceivePaillierSecrets(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // The first thing that should be sent is the number of secrets, then
  // the number of total ciphertext bytes; return if this hasn't been received yet.
  if (num_recd_bytes < 2 * sizeof(uint64_t)) {
    return true;
  }

  const char* rec_buffer = buffer.empty() ? data->char_buffer_ : buffer.data();

  // Fetch the number of ciphertexts to expect.
  const uint64_t num_secrets =
      CharVectorToValue<uint64_t>((const unsigned char*) rec_buffer);

  // Fetch the total number of ciphertext bytes to expect.
  uint64_t total_ciphertext_size = CharVectorToValue<int64_t>(
      (const unsigned char*) rec_buffer + sizeof(uint64_t));

  // Compute the total expected size:
  //   2 * sizeof(uint64_t) + num_secrets * sizeof(int) + total_ciphertext_size,
  // where the 'num_secrets * sizeof(int)' part comes from describing the size
  // (sizeof(int) bytes) of the 'num_secrets' ciphertexts.
  const uint64_t num_expected_bytes =
      2 * sizeof(uint64_t) + (num_secrets * sizeof(int)) + total_ciphertext_size;

  // Return (will keep listening) if not all the expected bytes have been received.
  if (num_recd_bytes < num_expected_bytes) {
    // Now that we know expected size of buffer, reserve this size, to
    // minimize the number of resizes that occur.
    if (!buffer.empty()) {
      data->buffer_.reserve(num_expected_bytes);
    }
    return true;
  }

  // We've received enough bytes. Alert Socket to stop listening on this connection
  // (set the return code to be OK if the exact number of expected bytes were read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > num_expected_bytes) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

// The callback function used by Socket to determine if all of the expected
// bytes have been received. Specifically:
//   1) The first bytes indicate the number of (encrypted) secrets (uint64_t)
//   2) The next bytes indicate the number of bits per secret (int)
//   3) The next bytes indicate the total size of all ciphertext bytes (uint64_t)
// Thus, the total number of expected bytes is:
//   sizeof(uint64_t) + sizeof(int) + sizeof(uint64_t) + (n * B * sizeof(int)) + N;
// where 'n' represents the total number of ciphertexts (1), B is the number
// of bits in each secret (2) and N is the total size of all ciphertexts (3).
// The socket_id is ignored (there is only one expected use-case of this
// function, which involves a single connection); it is included in the API so
// that this function is a valid callback for ListenParams.receive_data_.
// Returns true regardless, but sets stats->abort_listening_with_code_
// appropriately.
bool ReceivePrgXoredSecrets(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceivePrgXoredSecrets(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // The first thing that should be sent is the number of secrets, then
  // the number of bytes per secret; return if this hasn't been received yet.
  if (num_recd_bytes < 2 * sizeof(uint64_t)) {
    return true;
  }

  const char* rec_buffer = buffer.empty() ? data->char_buffer_ : buffer.data();

  // Fetch the number of secrets to expect.
  const uint64_t num_secrets =
      CharVectorToValue<uint64_t>((const unsigned char*) rec_buffer);

  // Fetch the number of bytes per secret.
  uint64_t secret_size = CharVectorToValue<int64_t>(
      (const unsigned char*) rec_buffer + sizeof(uint64_t));

  // Compute the total expected size:
  //   2 * sizeof(uint64_t) +
  //   2 * num_secrets * secret_size,
  const uint64_t num_expected_bytes =
      num_secrets * secret_size * 2 + 2 * sizeof(uint64_t);

  // Return (will keep listening) if not all the expected bytes have been received.
  if (num_recd_bytes < num_expected_bytes) {
    // Now that we know expected size of buffer, reserve this size, to
    // minimize the number of resizes that occur.
    if (!buffer.empty()) {
      data->buffer_.reserve(num_expected_bytes);
    }
    return true;
  }

  // We've received enough bytes. Alert Socket to stop listening on this connection
  // (set the return code to be OK if the exact number of expected bytes were read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > num_expected_bytes) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

// The callback function used by Socket to determine if all of the expected
// bytes of IKNP OT Extension Protocol (Step 3) have been received.
// Specifically, the first (sizeof(uint64_t)) bytes of the ReceivedData.buffer_
// should indicate the number of secrets, the next (sizeof(uint64_t)) bytes
// hold the secret size, and the next bytes are the pairs {(y_j0, y_j1)}
// (See Figure 1 of IKNP OT Extension paper). Test buffer to see if the
// expected number of bytes have been received. The socket_id
// is ignored (there is only one expected use-case of this function, which
// involves a single connection); it is included in the API so that this
// function is a valid callback for ListenParams.receive_data_.
// Returns true regardless, but sets stats->abort_listening_with_code_
// appropriately.
bool ReceiveIKNPStepThree(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceiveIKNPStepThree(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // The first things sent are the number of secrets (uint64_t) and the
  // size of each secret (uint64_t).
  // Return (will keep Listening) if these haven't been received yet.
  if (num_recd_bytes < 2 * sizeof(uint64_t)) {
    return true;
  }

  const char* rec_buffer = buffer.empty() ? data->char_buffer_ : buffer.data();

  const uint64_t num_secrets =
      CharVectorToValue<uint64_t>((const unsigned char*) rec_buffer);
  const uint64_t secret_size = CharVectorToValue<uint64_t>(
      (const unsigned char*) rec_buffer + sizeof(uint64_t));

  // Return (will keep listening) if not all the expected bytes have been received:
  //   2 * sizeof(uint64_t) + // To express 'num_secrets' and 'secret_size'
  //   2 * secret_size * num_secrets  // All of the (num_secrets) pairs of (y_j0, y_j1).
  if (num_recd_bytes < 2 * sizeof(uint64_t) + 2 * num_secrets * secret_size) {
    // Now that we know expected size of buffer, reserve this size, to
    // minimize the number of resizes that occur.
    if (!buffer.empty()) {
      data->buffer_.reserve(
          2 * sizeof(uint64_t) + 2 * num_secrets * secret_size);
    }
    return true;
  }

  // We've received enough bytes. Alert Socket to stop listening on this connection
  // (set the return code to be OK if the exact number of expected bytes were read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > 2 * sizeof(uint64_t) + 2 * num_secrets * secret_size) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

bool ServerIKNPStepThree(
    const int num_threads,
    const RandomOracleParams& ro_params,
    const vector<ServerSecretPair>& secrets,
    const vector<ClientSelectionBitAndSecret>& q_bit_and_secret,
    vector<vector<unsigned char>>* buffer) {
  // Fetch m (see notation of IKNP) from input vectors.
  const uint64_t m = secrets.size();
  buffer->resize(m);

  // Divy up the work of xor'ing the secrets by assigning roughly
  //   m / num_threads
  // computations to each thread.
  //   1) m may not be divisible by num_threads
  //   2) We will break m-bits into m / 8 bytes; we want each thread
  //      to process bytes, so we don't want to paritition m at
  //      non-byte points; i.e. the number of tasks assigned to a
  //      thread should be divisible by CHAR_BIT (except possible for
  //      the first thread, if m is not divisible by CHAR_BIT).
  const uint64_t avg_num_tasks_per_thread = m / num_threads;
  // Round down to nearest multiple of 8.
  const uint64_t num_tasks_per_thread =
      avg_num_tasks_per_thread - (avg_num_tasks_per_thread % CHAR_BIT);
  if (num_tasks_per_thread % CHAR_BIT != 0) LOG_FATAL("Bad input.");
  const uint64_t num_bytes_per_thread = num_tasks_per_thread / CHAR_BIT;
  const uint64_t num_tasks_for_first_thread =
      m - num_tasks_per_thread * (num_threads - 1);
  const uint64_t num_bytes_in_first_task =
      num_tasks_for_first_thread / CHAR_BIT +
      (num_tasks_for_first_thread % CHAR_BIT == 0 ? 0 : 1);
  const int num_threads_to_use = num_tasks_per_thread == 0 ? 1 : num_threads;

  unique_ptr<Thread> t;
  CreateThreadMaster(&t);
  // Keep a pointer to each thread, so they may be terminated.
  vector<unique_ptr<ThreadParams>> thread_ids;
  CreateVectorOfThreadParams(num_threads_to_use, &thread_ids);

  // Spawn each thread to perform its task of computing the ciphertext.
  uint64_t current_bit_index = 0;
  vector<ServerROEvaluateParams> params_holder(
      num_threads_to_use, ServerROEvaluateParams());
  for (int i = 0; i < num_threads_to_use; ++i) {
    const uint64_t num_bits_for_thread_i =
        i == 0 ? num_tasks_for_first_thread : num_tasks_per_thread;
    // Create a structure that will be passed to the function that actually
    // performs the ciphertext computation.
    ServerROEvaluateParams& params_i = params_holder[i];
    params_i.bit_index_ = current_bit_index;
    params_i.byte_index_ =
        i == 0 ? 0 : num_bytes_in_first_task + (i - 1) * num_bytes_per_thread;
    params_i.num_bytes_to_process_ =
        i == 0 ? num_bytes_in_first_task : num_bytes_per_thread;
    params_i.ro_params_ = &ro_params;
    params_i.secrets_ = &secrets;
    params_i.q_bit_and_secret_ = &q_bit_and_secret;
    params_i.thread_index_ = i;
    params_i.buffer_ = buffer;

    t->StartThread(
        (void*) &ServerROEvaluateCallback, &params_i, thread_ids[i].get());
    current_bit_index += num_bits_for_thread_i;
  }

  // Halt main thread until all threads have finished.
  bool all_threads_successful = true;
  for (int i = 0; i < num_threads_to_use; ++i) {
    t->WaitForThread(thread_ids[i].get());
    if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
      all_threads_successful = false;
      DLOG_ERROR(
          "Thread " + Itoa(i) + " was unsuccesful:\n" +
          params_holder[i].error_msg_);
    }
  }
  if (!all_threads_successful) {
    return false;
  }

  return true;
}

bool ServerIKNPStepThreeSend(
    const bool is_black_box,
    Socket* connection,
    const uint64_t& num_secrets, /* "m" from IKNP Figure 1 */
    const uint64_t& secret_size, /* "l" from IKNP Figure 1 */
    const vector<vector<unsigned char>>& buffer) {
  if (buffer.empty()) {
    // Done communicating with Client (at least for IKNP). Close connection.
    if (!is_black_box) connection->Reset();
    return true;
  }

  // Send the number of secrets to expect.
  if (!connection->SendDataNoFlush(
          (unsigned char*) &num_secrets, sizeof(uint64_t)) ||
      SendReturnCode::SUCCESS !=
          connection->SendData(
              (unsigned char*) &secret_size, sizeof(uint64_t))) {
    DLOG_ERROR("Failure in ServerIKNPStepThreeSend(): Failed to SendData.");
    return false;
  }

  // Send the buffer (consisting of all the pairs ({y_j0, y_j1}) to Client.
  // For efficiency, we only want to call SendData once, so we'll compact
  // buffer into a single vector.
  // First, compute the size of that vector (alternatively, we could just
  // loop through 'buffer' once, and call 'push_back' each time, but that
  // will incur the cost of potentially many resizes/copying; so we opt
  // for speed and precompute the total size).
  uint64_t num_total_bytes = 0;
  for (const vector<unsigned char>& buffer_i : buffer) {
    num_total_bytes += buffer_i.size();
  }
  vector<unsigned char> buffer_all(num_total_bytes);
  uint64_t current_index = 0;
  for (const vector<unsigned char>& buffer_i : buffer) {
    for (uint64_t j = 0; j < buffer_i.size(); ++j) {
      buffer_all[current_index] = buffer_i[j];
      ++current_index;
    }
  }

  // Now send.
  if (SendReturnCode::SUCCESS !=
      connection->SendData(buffer_all.data(), num_total_bytes)) {
    DLOG_ERROR("Failure in ServerIKNPStepThreeSend(): Failed to SendData.");
    return false;
  }

  // Done communicating with Client (at least for IKNP). Close connection.
  if (!is_black_box) connection->Reset();

  return true;
}

bool ClientIKNPStepThreeReceive(
    const bool is_black_box,
    Socket* connection,
    vector<vector<unsigned char>>* y_0,
    vector<vector<unsigned char>>* y_1) {
  uint64_t num_secrets = 0;
  uint64_t secret_size = 0;
  bool received_extra_bytes = false;
  const bool is_cookie_socket =
      connection->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = connection->GetListenParams();
    uint64_t num_first_comm_bytes = 2 * sizeof(uint64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (connection->GetReceivedBytes().size() != 1)
      LOG_FATAL("Unexpected number of Servers");
    connection->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    num_secrets = CharVectorToValue<uint64_t>(received_data);
    secret_size = CharVectorToValue<uint64_t>(sizeof(uint64_t), received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes = 2 * num_secrets * secret_size;
    if (num_second_comm_bytes > INT_MAX) {
      LOG_FATAL("Too many bytes to receive.");
    }
    params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
    connection->ResetForReceive();
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_second_comm_bytes);
    return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    ListenParams params;
    params.receive_data_ = &ReceiveIKNPStepThree;
    connection->SetListenParams(params);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      // If IKNP OT is used as an underlying black box OT protocol, then it is possible
      // that the present connection received not only the Server's secrets, but also
      // the *next* communication from the Server (based on whatever the parent OT
      // protocol dictates the Server should send next, after having sent the secrets).
      // In this case, Client may have received more bytes than expected.
      if (return_codes.size() == 1 && is_black_box &&
          *(return_codes.begin()) ==
              ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
        received_extra_bytes = true;
      } else {
        DLOG_ERROR(
            "Client failed to get Server's secret(s). Socket Error "
            "Message:\n" +
            connection->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  }

  // Done communicating with Server; just need to process the received bytes.
  // Go ahead and close the connection, so that the ip/port can be used
  // while this processing is being done.
  // Before closing connection, need to swap data buffer into a local copy, as
  // Reset()ing the connection will clear the buffer; but note that
  // 'SwapBuffer' doesn't take time, since the underlying 'swap' doesn't
  // copy all elements, it just swaps pointers.
  vector<char> received_data;
  if (connection->GetReceivedBytes().size() != 1)
    LOG_FATAL("Unexpected number of Servers");
  connection->SwapBuffer(0, &received_data);

  // Parse num_secrets and secret_size (the first 16 bytes of the received data).
  if (!is_cookie_socket) {
    num_secrets = CharVectorToValue<uint64_t>(received_data);
    secret_size = CharVectorToValue<uint64_t>(sizeof(uint64_t), received_data);
  }

  // Now parse the rest of the buffer, which is all of the {(y_j0, y_j1)} pairs.
  uint64_t buffer_index = is_cookie_socket ? 0 : 2 * sizeof(uint64_t);
  y_0->resize(num_secrets, vector<unsigned char>());
  y_1->resize(num_secrets, vector<unsigned char>());
  for (uint64_t j = 0; j < num_secrets; ++j) {
    vector<unsigned char>& y_j0 = (*y_0)[j];
    vector<unsigned char>& y_j1 = (*y_1)[j];
    y_j0.insert(
        y_j0.begin(),
        received_data.data() + buffer_index,
        received_data.data() + buffer_index + secret_size);
    buffer_index += secret_size;
    y_j1.insert(
        y_j1.begin(),
        received_data.data() + buffer_index,
        received_data.data() + buffer_index + secret_size);
    buffer_index += secret_size;
  }

  // Save any extra bytes (which represent the *next* part of the communication
  // between Sender and Receiver).
  const uint64_t num_extra_bytes = received_data.size() - buffer_index;
  if ((num_extra_bytes == 0) == received_extra_bytes) {
    DLOG_ERROR("Detected extra bytes received, but none found.");
    return false;
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        received_data.data() + buffer_index,
        num_extra_bytes);
  }
  // Done communicating with Server (at least for IKNP). Close connnection.
  if (!is_black_box) connection->Reset();
  else if (!connection->ResetForReceive(extra_bytes)) {
    DLOG_ERROR("Unable to save extra bytes for the next communication.");
    return false;
  }

  return true;
}

bool ClientIKNPStepFour(
    const int num_threads,
    const RandomOracleParams& ro_params,
    const vector<vector<unsigned char>>& y_0,
    const vector<vector<unsigned char>>& y_1,
    const vector<ServerSecretPair>& T,
    vector<ClientSelectionBitAndSecret>* selection_bits_and_output_secret) {
  // Fetch m (see notation of IKNP) from input vectors.
  const uint64_t m = selection_bits_and_output_secret->size();
  if (y_0.size() != m || y_1.size() != m) {
    LOG_FATAL("Bad input to ClientIKNPStepFour()");
  }

  // Divy up the work of xor'ing the secrets by assigning roughly
  //   m / num_threads
  // computations to each thread.
  //   1) m may not be divisible by num_threads
  //   2) We will break m-bits into m / 8 bytes; we want each thread
  //      to process bytes, so we don't want to paritition m at
  //      non-byte points; i.e. the number of tasks assigned to a
  //      thread should be divisible by CHAR_BIT (except possible for
  //      the first thread, if m is not divisible by CHAR_BIT).
  const uint64_t avg_num_tasks_per_thread = m / num_threads;
  // Round down to nearest multiple of 8.
  const uint64_t num_tasks_per_thread =
      avg_num_tasks_per_thread - (avg_num_tasks_per_thread % CHAR_BIT);
  if (num_tasks_per_thread % CHAR_BIT != 0) LOG_FATAL("Bad input");
  const uint64_t num_bytes_per_thread = num_tasks_per_thread / CHAR_BIT;
  const uint64_t num_tasks_for_first_thread =
      m - num_tasks_per_thread * (num_threads - 1);
  const uint64_t num_bytes_in_first_task =
      num_tasks_for_first_thread / CHAR_BIT +
      (num_tasks_for_first_thread % CHAR_BIT == 0 ? 0 : 1);
  const int num_threads_to_use = num_tasks_per_thread == 0 ? 1 : num_threads;

  unique_ptr<Thread> t;
  CreateThreadMaster(&t);
  // Keep a pointer to each thread, so they may be terminated.
  vector<unique_ptr<ThreadParams>> thread_ids;
  CreateVectorOfThreadParams(num_threads_to_use, &thread_ids);

  // Spawn each thread to perform its task of computing the ciphertext.
  uint64_t current_bit_index = 0;
  vector<ClientROEvaluateParams> params_holder(
      num_threads_to_use, ClientROEvaluateParams());
  for (int i = 0; i < num_threads_to_use; ++i) {
    const uint64_t num_bits_for_thread_i =
        i == 0 ? num_tasks_for_first_thread : num_tasks_per_thread;
    // Create a structure that will be passed to the function that actually
    // performs the ciphertext computation.
    ClientROEvaluateParams& params_i = params_holder[i];
    params_i.bit_index_ = current_bit_index;
    params_i.byte_index_ =
        i == 0 ? 0 : num_bytes_in_first_task + (i - 1) * num_bytes_per_thread;
    params_i.num_bytes_to_process_ =
        i == 0 ? num_bytes_in_first_task : num_bytes_per_thread;
    params_i.ro_params_ = &ro_params;
    params_i.y_0_ = &y_0;
    params_i.y_1_ = &y_1;
    params_i.T_ = &T;
    params_i.selection_bits_and_output_secret_ =
        selection_bits_and_output_secret;
    params_i.thread_index_ = i;

    t->StartThread(
        (void*) &ClientROEvaluateCallback, &params_i, thread_ids[i].get());
    current_bit_index += num_bits_for_thread_i;
  }

  // Halt main thread until all threads have finished.
  bool all_threads_successful = true;
  for (int i = 0; i < num_threads_to_use; ++i) {
    t->WaitForThread(thread_ids[i].get());
    if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
      all_threads_successful = false;
      DLOG_ERROR(
          "Thread " + Itoa(i) + " was unsuccesful:\n" +
          params_holder[i].error_msg_);
    }
  }
  if (!all_threads_successful) {
    return false;
  }

  return true;
}

// Uses the given connection to Listen() for public parameters sent from Client.
bool ServerSetupPaillierParameters(
    Socket* connection, PaillierPublicKey* public_key) {
  int n_size = 0;
  int g_size = 0;
  bool received_extra_bytes = false;
  const bool is_cookie_socket =
      connection->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = connection->GetListenParams();
    uint64_t num_first_comm_bytes = 2 * sizeof(int);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (connection->GetReceivedBytes().size() != 1)
      LOG_FATAL("Unexpected number of Servers");
    connection->SwapBuffer(0, &received_data);

    // Parse n_size and g_size (the first 16 bytes of the received data).
    n_size = CharVectorToValue<int>(received_data);
    g_size = CharVectorToValue<int>(sizeof(int), received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes = n_size + g_size;
    if (num_second_comm_bytes > INT_MAX) {
      LOG_FATAL("Too many bytes to receive.");
    }
    params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
    connection->ResetForReceive();
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_second_comm_bytes);
    return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    // Listen for public parameters from Client.
    ListenParams params;
    params.receive_data_ = &ReceivePaillierPublicKey;
    connection->SetListenParams(params);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      // If IKNP OT is used as an underlying black box OT protocol, then it is possible
      // that the present connection received not only the Server's secrets, but also
      // the *next* communication from the Server (based on whatever the parent OT
      // protocol dictates the Server should send next, after having sent the secrets).
      // In this case, Client may have received more bytes than expected.
      if (return_codes.size() == 1 &&
          *(return_codes.begin()) ==
              ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
        received_extra_bytes = true;
      } else {
        DLOG_ERROR(
            "Failed communication with Client. Socket Error "
            "Message:\n" +
            connection->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  }

  if (connection->GetReceivedBytes().size() != 1)
    LOG_FATAL("Unexpected number of Servers");
  vector<char> received_data;
  connection->SwapBuffer(0, &received_data);

  // Parse received public parameters n and g.
  if (!is_cookie_socket) {
    n_size = CharVectorToValue<int>(received_data);
    g_size = CharVectorToValue<int>(sizeof(int), received_data);
  }
  uint64_t buffer_offset = is_cookie_socket ? 0 : 2 * sizeof(int);
  public_key->n_ = LargeInt::ByteStringToLargeInt(
      received_data.data() + buffer_offset, n_size);
  public_key->g_ = LargeInt::ByteStringToLargeInt(
      received_data.data() + buffer_offset + n_size, g_size);

  // Compute n^2.
  public_key->n_squared_ = public_key->n_ * public_key->n_;

  // Save any extra bytes (which represent the *next* part of the communication
  // between Sender and Receiver).
  const uint64_t num_expected_bytes = n_size + g_size + buffer_offset;
  const uint64_t num_extra_bytes = received_data.size() - num_expected_bytes;
  if ((num_extra_bytes == 0) == received_extra_bytes) {
    DLOG_ERROR("Detected extra bytes received, but none found.");
    return false;
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        received_data.data() + num_expected_bytes,
        num_extra_bytes);
  }
  if (!connection->ResetForReceive(extra_bytes)) {
    DLOG_ERROR("Unable to save extra bytes for the next communication.");
    return false;
  }

  return true;
}

// Send Paillier (public) parameters to Server.
bool ClientSendPaillierParameters(
    Socket* connection, const PaillierParams& paillier_params) {
  const LargeInt& n = paillier_params.public_key_.n_;
  const LargeInt& g = paillier_params.public_key_.g_;
  const int n_size = n.NumBytes();
  const int g_size = g.NumBytes();
  if (n_size <= 0 || g_size <= 0) LOG_FATAL("Invalid Paillier parameters.");

  // Store everything in one buffer, so that there is a single send().
  const int total_size = (int) (n_size + g_size + 2 * sizeof(int));
  vector<unsigned char> all_bytes;
  ValueToCharVector<int>(n_size, &all_bytes);
  ValueToCharVector<int>(g_size, &all_bytes);
  LargeIntToByteString(n, &all_bytes);
  LargeIntToByteString(g, &all_bytes);
  if (SendReturnCode::SUCCESS !=
      connection->SendData(all_bytes.data(), total_size)) {
    DLOG_ERROR(
        "Failure sending Paillier parameters to Sender: '" +
        connection->GetErrorMessage() + "'");
    return false;
  }

  return true;
}

// Receive encrypted selection bits from the Client.
// The outer vector has size equal to the number of OT's being performed, the
// inner vector has size equal to the number of bits in each secret.
// Returns empty string on success, otherwise an error message.
string ServerReceivePaillierSelectionBits(
    Socket* connection, vector<pair<LargeInt, LargeInt>>* client_ciphertexts) {
  uint64_t num_secrets = 0;
  bool received_extra_bytes = false;
  const bool is_cookie_socket =
      connection->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = connection->GetListenParams();
    uint64_t num_first_comm_bytes = 2 * sizeof(uint64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      string error_msg = "Client failed to get Server's secret(s). "
                         "Socket Error Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes);
      return error_msg;
    }
    vector<char> received_data;
    if (connection->GetReceivedBytes().size() != 1)
      LOG_FATAL("Unexpected number of Servers");
    connection->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    num_secrets = CharVectorToValue<uint64_t>(received_data);
    const uint64_t total_size =
        CharVectorToValue<uint64_t>(sizeof(uint64_t), received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes = total_size;
    if (num_second_comm_bytes > INT_MAX) {
      LOG_FATAL("Too many bytes to receive.");
    }
    params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
    connection->ResetForReceive();
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_second_comm_bytes);
    return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      string error_msg = "Client failed to get Server's secret(s). "
                         "Socket Error Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes);
      return error_msg;
    }
  } else {
    // Listen for encrypted selection bits from Client.
    ListenParams params;
    params.receive_data_ = &ReceiveEncryptedSelectionBits;
    connection->SetListenParams(params);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      // If IKNP OT is used as an underlying black box OT protocol, then it is possible
      // that the present connection received not only the Server's secrets, but also
      // the *next* communication from the Server (based on whatever the parent OT
      // protocol dictates the Server should send next, after having sent the secrets).
      // In this case, Client may have received more bytes than expected.
      if (return_codes.size() == 1 &&
          *(return_codes.begin()) ==
              ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
        received_extra_bytes = true;
      } else {
        string error_msg = "Failed to get (encrypted) Client's "
                           "selection bits. Error Message: '" +
            connection->GetErrorMessage() + "'\n";
        error_msg += GetBadListenReturnCodeMessage(return_codes);
        return error_msg;
      }
    }
  }

  // Parse data received from Client.
  if (connection->GetReceivedBytes().size() != 1)
    LOG_FATAL("Unexpected number of Servers");
  vector<char> received_data;
  connection->SwapBuffer(0, &received_data);

  // The first bytes of the received data represents the number of
  // ciphertext pairs that should be expected.
  if (!is_cookie_socket) {
    num_secrets = CharVectorToValue<uint64_t>(received_data);
  }

  // The next bytes represent the total number of (ciphertext) bytes. This was
  // only needed to indicate when to stop listening; here we just skip over
  // these bytes.
  uint64_t buffer_index = is_cookie_socket ? 0 : 2 * sizeof(uint64_t);

  // The next bytes are the ciphertext sizes and actual ciphertexts.
  client_ciphertexts->resize(num_secrets, pair<LargeInt, LargeInt>());
  for (uint64_t i = 0; i < num_secrets; ++i) {
    pair<LargeInt, LargeInt>& current_ciphertext_pair = (*client_ciphertexts)[i];
    // Fetch the size of the first ciphertext.
    const int c0_size = CharVectorToValue<int>(buffer_index, received_data);
    buffer_index += sizeof(int);
    // Fetch the size of the second ciphertext.
    const int c1_size = CharVectorToValue<int>(buffer_index, received_data);
    buffer_index += sizeof(int);

    // Read first ciphertext.
    LargeInt& c0 = current_ciphertext_pair.first;
    c0 = LargeInt::ByteStringToLargeInt(
        received_data.data() + buffer_index, c0_size);
    buffer_index += c0_size;

    // Read second ciphertext.
    LargeInt& c1 = current_ciphertext_pair.second;
    c1 = LargeInt::ByteStringToLargeInt(
        received_data.data() + buffer_index, c1_size);
    buffer_index += c1_size;
  }

  // Save any extra bytes (which represent the *next* part of the communication
  // between Sender and Receiver).
  const uint64_t num_extra_bytes = received_data.size() - buffer_index;
  if ((num_extra_bytes == 0) == received_extra_bytes) {
    return "Detected extra bytes received, but none found.";
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        received_data.data() + buffer_index,
        num_extra_bytes);
  }
  if (!connection->ResetForReceive(extra_bytes)) {
    return "Unable to save extra bytes for the next communication.";
  }

  return "";
}

// Encrypt and send selection bits to Server.
bool ClientSendPaillierSelectionBits(
    const int num_threads,
    Socket* connection,
    PaillierPublicKey& public_key,
    const vector<ClientSelectionBitAndSecret>&
        selection_bits_and_output_secret) {
  if (selection_bits_and_output_secret.empty()) {
    return true;
  }

  const uint64_t num_secrets = selection_bits_and_output_secret.size();

  // Generate ciphertexts for {E(0), E(1)}, where order of this pair depends
  // on selection bit {b_i}.
  // We (optionally) split this task into multiple threads, since the task of
  // computing the ciphertext E(s_b) from E(0) and E(b) can be expensive.
  // The following buffer will hold all the information to be sent to Server:
  // all of the ciphertext pairs (including the size of each). The outer
  // vector will have size 'num_threads' (or '1', in case num_threads <= 1),
  // and each inner vector will have size equal to the number of bytes
  // generated by that thread.
  vector<vector<unsigned char>> buffer;
  if (num_threads > 1) {
    buffer.resize(num_threads);

    // Divy up the work of generating the ciphertexts by assigning
    //   num_secrets / num_threads
    // computations to each thread.
    const uint64_t num_tasks_per_thread = num_secrets / num_threads;
    const uint64_t remainder = num_secrets % num_threads;

    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    // Keep a pointer to each thread, so they may be terminated.
    vector<unique_ptr<ThreadParams>> thread_ids;
    CreateVectorOfThreadParams(num_threads, &thread_ids);

    // Spawn each thread to perform its task of computing the ciphertext.
    int current_index = 0;
    vector<ClientGeneratePaillierCiphertextParams> params_holder(
        num_threads, ClientGeneratePaillierCiphertextParams());
    for (int i = 0; i < num_threads; ++i) {
      const uint64_t num_tasks_for_thread_i =
          num_tasks_per_thread + ((uint64_t) i < remainder ? 1 : 0);
      vector<unsigned char>& buffer_i = buffer[i];

      // Create a structure that will be passed to the function that actually
      // performs the ciphertext computation.
      ClientGeneratePaillierCiphertextParams& ciphertext_info = params_holder[i];
      ciphertext_info.public_key_ = &public_key;
      ciphertext_info.ciphertexts_and_sizes_ = &buffer_i;
      ciphertext_info.selection_bits_.resize(num_tasks_for_thread_i);
      for (uint64_t j = 0; j < num_tasks_for_thread_i; ++j) {
        ciphertext_info.selection_bits_[j] =
            selection_bits_and_output_secret[current_index].b_;
        current_index++;
      }

      t->StartThread(
          (void*) &ClientComputePaillierCiphertextCallback,
          &ciphertext_info,
          thread_ids[i].get());
    }

    // Halt main thread until all threads have finished.
    bool all_threads_successful = true;
    for (int i = 0; i < num_threads; ++i) {
      t->WaitForThread(thread_ids[i].get());
      if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
        all_threads_successful = false;
        DLOG_ERROR(
            "Thread " + Itoa(i) + " was unsuccesful:\n" +
            params_holder[i].error_msg_);
      }
    }
    if (!all_threads_successful) {
      return false;
    }
  } else {
    buffer.resize(1, vector<unsigned char>());
    for (size_t i = 0; i < num_secrets; ++i) {
      if (!ClientComputePaillierCiphertext(
              public_key, selection_bits_and_output_secret[i].b_, &buffer[0])) {
        return false;
      }
    }
  }

  // Send the number of ciphertext pairs to expect.
  if (!connection->SendDataNoFlush(
          (unsigned char*) &num_secrets, sizeof(uint64_t))) {
    DLOG_ERROR("Failure in ClientSendPaillierSelectionBits(): Unable "
               "to SendData");
    return false;
  }

  // Send total number of ciphertext bytes.
  uint64_t total_ciphertext_size = 0;
  for (const auto& buffer_i : buffer) {
    total_ciphertext_size += buffer_i.size();
  }
  if (!connection->SendDataNoFlush(
          (unsigned char*) &total_ciphertext_size, sizeof(uint64_t))) {
    DLOG_ERROR("Failure in ClientSendPaillierSelectionBits(): Unable to "
               "SendData");
    return false;
  }

  // Send ciphertexts and sizes.
  for (size_t i = 0; i < buffer.size(); ++i) {
    const vector<unsigned char>& buffer_i = buffer[i];
    if (SendReturnCode::SUCCESS !=
        connection->SendData(buffer_i.data(), buffer_i.size())) {
      DLOG_ERROR("Failed to send selection bits for thread " + Itoa(i));
      return false;
    }
  }

  return true;
}

// Use the Client's encrypted selection bits to form {E(s_b)} for each of the
// Server's pair of secrets.
bool ServerComputePaillierCiphertexts(
    ServerPaillierOTParams* params,
    vector<pair<LargeInt, LargeInt>>& client_ciphertexts,
    uint64_t* total_ciphertexts_size,
    vector<LargeInt>* ciphertexts_to_return) {
  // Verify the expected number of ciphertext pairs were received (should match
  // the number of secret (pairs) the Server has).
  const size_t num_secrets = params->secrets_->size();
  if (num_secrets == 0) {
    return true;
  }
  if (client_ciphertexts.size() != num_secrets) {
    DLOG_ERROR(
        "Failure in ServerComputePaillierCiphertexts(): Mismatching "
        "sizes of client_ciphertexts (" +
        Itoa(client_ciphertexts.size()) + ") vs. num_secrets (" +
        Itoa(num_secrets) + ")");
    return false;
  }

  // Initialize ciphertexts_to_return by setting it to the proper size.
  ciphertexts_to_return->resize(params->secrets_->size());

  // Initialize total_ciphertexts_size to zero.
  *total_ciphertexts_size = 0;

  // Utilize the homomorphic properties of Paillier to form ciphertexts {E(s_b)}.
  // We (optionally) split this task into multiple threads, since the task of
  // computing the ciphertext E(s_b) from E(0) and E(b) can be expensive.
  const int num_threads = params->num_threads_ > 0 ? params->num_threads_ : 1;
  if (num_threads > 1) {
    // Divy up the work of generating the ciphertexts by assigning
    //   num_secrets / num_threads
    // computations to each thread.
    const uint64_t num_tasks_per_thread = num_secrets / num_threads;
    const uint64_t remainder = num_secrets % num_threads;

    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    // Keep a pointer to each thread, so they may be terminated.
    vector<unique_ptr<ThreadParams>> thread_ids;
    CreateVectorOfThreadParams(num_threads, &thread_ids);

    // Spawn each thread to perform its task of computing the ciphertext.
    int current_index = 0;
    vector<ServerGeneratePaillierCiphertextParams> params_holder(
        num_threads, ServerGeneratePaillierCiphertextParams());
    for (int i = 0; i < num_threads; ++i) {
      const uint64_t num_tasks_for_thread_i =
          num_tasks_per_thread + ((uint64_t) i < remainder ? 1 : 0);
      // Create a structure that will be passed to the function that actually
      // performs the ciphertext computation.
      ServerGeneratePaillierCiphertextParams& ciphertext_info = params_holder[i];
      ciphertext_info.SetNumCiphertexts(num_tasks_for_thread_i);
      ciphertext_info.paillier_n_ = &params->key_.n_;
      ciphertext_info.paillier_n_squared_ = &params->key_.n_squared_;
      for (uint64_t j = 0; j < num_tasks_for_thread_i; ++j) {
        ciphertext_info.secrets_[j] = &((*params->secrets_)[current_index]);
        ciphertext_info.client_ciphertexts_[j] =
            &(client_ciphertexts[current_index]);
        ciphertext_info.ciphertexts_[j] =
            &((*ciphertexts_to_return)[current_index]);
        current_index++;
      }

      t->StartThread(
          (void*) &ServerComputePaillierCiphertextCallback,
          &ciphertext_info,
          thread_ids[i].get());
    }

    // Halt main thread until all threads have finished.
    bool all_threads_successful = true;
    for (int i = 0; i < num_threads; ++i) {
      t->WaitForThread(thread_ids[i].get());
      for (const uint64_t& ciphertext_size :
           params_holder[i].ciphertext_sizes_) {
        *total_ciphertexts_size += ciphertext_size;
      }
      if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
        all_threads_successful = false;
        DLOG_ERROR(
            "Thread " + Itoa(i) + " was unsuccesful:\n" +
            params_holder[i].error_msg_);
      }
    }
    if (!all_threads_successful) {
      return false;
    }
  } else {
    for (size_t i = 0; i < num_secrets; ++i) {
      if (!ServerComputePaillierCiphertext(
              (*params->secrets_)[i],
              client_ciphertexts[i],
              params->key_.n_,
              params->key_.n_squared_,
              total_ciphertexts_size,
              &(*ciphertexts_to_return)[i])) {
        DLOG_ERROR(
            "Failure in ServerComputePaillierCiphertexts(): Failed to "
            "ServerComputePaillierCiphertext at secret " +
            Itoa(i));
        return false;
      }
    }
  }

  return true;
}

// Returns the Server's ciphertexts {E(s_b)} to the Client.
bool ServerSendPaillierSecrets(
    const bool is_black_box,
    Socket* connection,
    const uint64_t& total_ciphertexts_size,
    const vector<LargeInt>& ciphertexts) {
  if (ciphertexts.empty()) {
    if (!is_black_box) connection->Reset();
    return true;
  }

  // Send the number of ciphertexts to expect.
  const uint64_t num_secrets = ciphertexts.size();
  if (!connection->SendDataNoFlush(
          (unsigned char*) &num_secrets, sizeof(uint64_t))) {
    DLOG_ERROR("Failure in ServerSendPaillierSecrets(): Unable to SendData.");
    return false;
  }

  // Send the total size of all the ciphertexts.
  if (!connection->SendDataNoFlush(
          (unsigned char*) &total_ciphertexts_size, sizeof(uint64_t))) {
    DLOG_ERROR("Failure in ServerSendPaillierSecrets(): Unable to SendData.");
    return false;
  }

  // Send the ciphertext sizes to Client.
  vector<int> ciphertext_sizes(num_secrets);
  vector<unsigned char> all_ciphertexts;
  for (uint64_t i = 0; i < num_secrets; ++i) {
    const LargeInt& ciphertext_i = ciphertexts[i];
    ciphertext_sizes[i] = ciphertext_i.NumBytes();
    LargeIntToByteString(ciphertext_i, &all_ciphertexts);
  }

  // Now send the actual ciphertexts to Client.
  // Send the ciphertext.
  if (!connection->SendDataNoFlush(
          (char*) ciphertext_sizes.data(), num_secrets * sizeof(int)) ||
      SendReturnCode::SUCCESS !=
          connection->SendData(all_ciphertexts.data(), all_ciphertexts.size())) {
    DLOG_ERROR("Failure in ServerSendPaillierSecrets(): Unable to SendData.");
    return false;
  }

  // Done communicating with Client. Close connnection.
  if (!is_black_box) connection->Reset();

  return true;
}

// Sends A = g^a to Client.
bool ServerDiffieHellmanSendA(const bool, Socket* connection, GroupElement* A) {
  unsigned char* a_enc = nullptr;
  uint64_t num_bytes = 0;
  if (!A->Encode(&num_bytes, &a_enc)) {
    if (a_enc) free(a_enc);
    return false;
  }

  // Send the number of ciphertexts to expect.
  if (!connection->SendDataNoFlush(
          (unsigned char*) &num_bytes, sizeof(uint64_t)) ||
      SendReturnCode::SUCCESS != connection->SendData(a_enc, num_bytes)) {
    DLOG_ERROR("Failure in ServerDiffieHellmanSendA(): Unable to SendData.");
    if (a_enc) free(a_enc);
    return false;
  }

  // Clean-up.
  if (a_enc) free(a_enc);

  return true;
}

// A structure to hold all of the inputes and outputs necessary to run
// ClientDiffieHellmanComputeBs.
struct ClientDiffieHellmanComputeBsParams {
  // =============================== Inputs ====================================
  uint64_t start_index_;
  uint64_t num_secrets_;

  const GroupElement* g_;
  const GroupElement* A_;
  const vector<LargeInt>* b_;
  const vector<ClientSelectionBitAndSecret>* selection_bits_and_output_secret_;
  const RandomOracleParams* ro_params_;

  // =============================== Outputs ===================================
  vector<vector<unsigned char>>* keys_;
  vector<vector<unsigned char>>* bytes_;

  ClientDiffieHellmanComputeBsParams() {
    start_index_ = 0;
    num_secrets_ = 0;
    g_ = nullptr;
    A_ = nullptr;
    b_ = nullptr;
    selection_bits_and_output_secret_ = nullptr;
    ro_params_ = nullptr;
    keys_ = nullptr;
    bytes_ = nullptr;
  }
};

// This function takes in the element A received from the Server and
// computes the elements B (one for each pair of secrets) to be sent
// to the Server. It also computes the keys that the Client will use
// at the end of the OT protocal to decrypt the final secrets from the
// Server.
//
// inputs:
//
// 'start_index': The (index of the) first secret to process
// 'num_secrets': how many secrets to read.
// 'g': The generator of the group (agreed at beginning of protocol by
// Client and Server).
// 'A': Element of the group generated randomly by Server.
// 'b': Vector of exponents generated randomly by Client.
// 'selection_bits_and_output_secret': Vector of bits and secrets
// maintained by Client.
// 'ro_params': Random Oracle Params used to generate keys.
// 'keys': Vector of keys generated by Client to decrypt final messages.
// 'bytes': Vector of intermediate computations generated by Client to
// send back to Server.
bool ClientDiffieHellmanComputeBs(
    const uint64_t start_index,
    const uint64_t num_secrets,
    const GroupElement* g,
    const GroupElement* A,
    const vector<LargeInt>* b,
    const vector<ClientSelectionBitAndSecret>* selection_bits_and_output_secret,
    const RandomOracleParams* ro_params,
    vector<vector<unsigned char>>* keys,
    vector<vector<unsigned char>>* bytes) {
  for (uint64_t i = start_index; i < start_index + num_secrets; ++i) {
    // Grab selection bit.
    const bool c = (*selection_bits_and_output_secret)[i].b_;

    // Make the B's.
    unique_ptr<GroupElement> B(CreateGroupElementCopy(*g));
    (*B) *= (*b)[i];
    if (c) {
      (*B) += *A;
    }

    // Encode B (= either g^b_i or A*g^b_i, depending on selection bit c_i).
    unsigned char* b_enc = nullptr;
    uint64_t num_bytes = 0;
    if (!B->Encode(&num_bytes, &b_enc)) {
      LOG_ERROR("Unable to encode B for i = " + Itoa(i));
      if (b_enc) free(b_enc);
      return false;
    }
    (*bytes)[i].resize(num_bytes);
    memcpy((char*) (*bytes)[i].data(), (char*) b_enc, num_bytes);
    if (b_enc) free(b_enc);

    // Store hash as key.
    unique_ptr<GroupElement> key_preimage(CreateGroupElementCopy(*A));
    (*key_preimage) *= (*b)[i];
    unsigned char* key_preimage_enc = nullptr;
    uint64_t num_bytes_key_preimage = 0;
    if (!key_preimage->Encode(&num_bytes_key_preimage, &key_preimage_enc)) {
      LOG_ERROR("Unable to encode A^b for i = " + Itoa(i));
      if (key_preimage_enc) free(key_preimage_enc);
      return false;
    }
    if (!ROEvaluate(
            *ro_params,
            num_bytes_key_preimage,
            key_preimage_enc,
            &((*keys)[i]))) {
      LOG_ERROR("Unable ROEvaluate for i = " + Itoa(i));
      if (key_preimage_enc) free(key_preimage_enc);
      return false;
    }

    // Clean-up.
    if (key_preimage_enc) free(key_preimage_enc);

    // TODO(paul): Currently, only AES-128 is supported. Our keys, which
    // are the output of our RO (which is currently SHA-256), don't work.
    // So we need to either support AES-256, or truncate the SHA output to
    // 128 bits. For now, we do the former (which may have security
    // implications, for now having 128 bits instead of 256; although it's still
    // using the SHA256 algorithm).
    (*keys)[i].resize(16);
  }

  return true;
}

// Callback function to compute ClientDiffieHellmanComputeBs in
// multi-threaded case.
unsigned ClientDiffieHellmanComputeBsCallback(void* args) {
  ClientDiffieHellmanComputeBsParams* client_params =
      (ClientDiffieHellmanComputeBsParams*) args;
  if (!ClientDiffieHellmanComputeBs(
          client_params->start_index_,
          client_params->num_secrets_,
          client_params->g_,
          client_params->A_,
          client_params->b_,
          client_params->selection_bits_and_output_secret_,
          client_params->ro_params_,
          client_params->keys_,
          client_params->bytes_)) {
    DLOG_ERROR("Failed to compute ClientDiffieHellmanComputeBs");
    return 1;
  }
  return 0;
}

// Receives A = g^a from Server, and returns { B_i } to Server, where:
//   B_i = g^(b_i)  if c_i = 0
//   B_i = Ag^(b_i) if c_i = 1
bool ClientDiffieHellmanReceiveA(
    const bool,
    const bool,
    const int num_threads,
    Socket* connection,
    const GroupElement* g,
    const vector<LargeInt>& b,
    const vector<ClientSelectionBitAndSecret>& selection_bits_and_output_secret,
    const RandomOracleParams& ro_params,
    vector<vector<unsigned char>>* keys) {
  // Listen for A = g^a from Server.
  const bool is_cookie_socket =
      connection->GetSocketType() == SocketType::COOKIE;
  bool received_extra_bytes = false;
  if (is_cookie_socket) {
    ListenParams params = connection->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(int64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (connection->GetReceivedBytes().size() != 1)
      LOG_FATAL("Unexpected number of Servers");
    connection->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    uint64_t num_bytes = CharVectorToValue<uint64_t>(received_data);

    // Now, listen for all of the secrets.
    if (num_bytes > INT_MAX) {
      LOG_FATAL("Too many bytes to receive.");
    }
    params.receive_buffer_max_size_ = (int) num_bytes;
    connection->ResetForReceive();
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
    return_codes = connection->Listen();
    // NOTE: The underlying CookieSocket::recv() functionality *must* support
    // calling recv(N), and receiving *more than* N bytes, and when this happens,
    // it must save the extra bytes somewhere, such that the *next* time
    // CookieSocket::recv(M) is called, then the overflow/storage is first checked/
    // drained, and then if additional bytes are needed, then keep reading.
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    ListenParams params;
    params.receive_data_ = &ReceiveInt64Bytes;
    connection->SetListenParams(params);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      // If IKNP OT is used as an underlying black box OT protocol, then it is
      // possible that the present connection received not only the Server's
      // secrets, but also the *next* communication from the Server (based on
      // whatever the parent OT protocol dictates the Server should send next,
      // after having sent the secrets). In this case, Client may have received
      // more bytes than expected.
      if (return_codes.size() == 1 &&
          *(return_codes.begin()) ==
              ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
        received_extra_bytes = true;
      } else {
        DLOG_ERROR(
            "Failed communication with Server. Socket Error "
            "Message:\n" +
            connection->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  }

  vector<char> received_data;
  if (connection->GetReceivedBytes().size() != 1) {
    LOG_FATAL("Unexpected number of Servers");
  }
  connection->SwapBuffer(0, &received_data);

  const uint64_t num_incoming_bytes = is_cookie_socket ?
      received_data.size() :
      CharVectorToValue<uint64_t>(received_data);
  const uint64_t offset = is_cookie_socket ? 0 : sizeof(uint64_t);
  const uint64_t num_secrets = b.size();

  // Get an group element with the same properties as g.
  unique_ptr<GroupElement> A(CreateGroupElementCopy(*g));
  // Parse 'A'.
  A->Decode(
      num_incoming_bytes,
      ((const unsigned char*) received_data.data()) + offset);

  vector<vector<unsigned char>> all_b(num_secrets, vector<unsigned char>());

  if (num_threads > 1) {
    // Divy up the work of generating the ciphertexts by assigning
    //   (num_secrets / num_threads) computations to each thread.
    const uint64_t num_tasks_per_thread = num_secrets / num_threads;
    const uint64_t remainder = num_secrets % num_threads;

    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    // Keep a pointer to each thread, so they may be terminated.
    vector<unique_ptr<ThreadParams>> thread_ids;
    CreateVectorOfThreadParams(num_threads, &thread_ids);

    uint64_t current_index = 0;
    vector<ClientDiffieHellmanComputeBsParams> params_holder(
        num_threads, ClientDiffieHellmanComputeBsParams());

    for (int i = 0; i < num_threads; ++i) {
      const uint64_t num_tasks_for_thread_i =
          num_tasks_per_thread + ((uint64_t) i < remainder ? 1 : 0);
      ClientDiffieHellmanComputeBsParams& client_info = params_holder[i];
      // add start and num_tasks_per_thread for vector of secrets
      client_info.start_index_ = current_index;
      client_info.num_secrets_ = num_tasks_for_thread_i;
      client_info.g_ = g;
      client_info.A_ = A.get();
      client_info.b_ = &b;
      client_info.selection_bits_and_output_secret_ =
          &selection_bits_and_output_secret;
      client_info.ro_params_ = &ro_params;
      client_info.keys_ = keys;
      client_info.bytes_ = &all_b;

      t->StartThread(
          (void*) &ClientDiffieHellmanComputeBsCallback,
          &client_info,
          thread_ids[i].get());
      current_index += num_tasks_for_thread_i;
    }

    bool all_threads_successful = true;
    for (int i = 0; i < num_threads; ++i) {
      t->WaitForThread(thread_ids[i].get());
      if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
        all_threads_successful = false;
        DLOG_ERROR("Thread " + Itoa(i) + " was unsuccesful:\n");
      }
    }
    if (!all_threads_successful) {
      return false;
    }
  } else {
    if (!ClientDiffieHellmanComputeBs(
            0,
            num_secrets,
            g,
            A.get(),
            &b,
            &selection_bits_and_output_secret,
            &ro_params,
            keys,
            &all_b)) {
      return false;
    }
  }

  // Send all_b.
  vector<unsigned char> b_sizes(num_secrets * sizeof(uint64_t));
  uint64_t num_outgoing_bytes = b_sizes.size();
  for (uint64_t i = 0; i < num_secrets; ++i) {
    const uint64_t size_b = all_b[i].size();
    ValueToByteString<uint64_t>(size_b, b_sizes.data() + i * sizeof(uint64_t));
    num_outgoing_bytes += size_b;
  }

  if (!connection->SendDataNoFlush(
          (unsigned char*) &num_outgoing_bytes, sizeof(uint64_t)) ||
      !connection->SendDataNoFlush(b_sizes.data(), b_sizes.size())) {
    DLOG_ERROR(
        "Failure sending B's to Sender: '" + connection->GetErrorMessage() +
        "'");
  }

  // Combine the bytes of the num_secrets Bs into one buffer to reduce
  // the number of transmissions back to the Server.
  vector<unsigned char> to_send(num_outgoing_bytes - b_sizes.size());
  unsigned char* inserter = to_send.data();
  for (uint64_t i = 0; i < num_secrets; ++i) {
    const uint64_t num_bytes = all_b[i].size();
    memcpy(inserter, all_b[i].data(), num_bytes);
    inserter += num_bytes;
  }

  if (SendReturnCode::SUCCESS !=
      connection->SendData(
          to_send.data(), num_outgoing_bytes - b_sizes.size())) {
    DLOG_ERROR(
        "Failure sending B's to Sender: '" + connection->GetErrorMessage() +
        "'");
    return false;
  }

  // Save any extra bytes (which represent the *next* part of the communication
  // between Sender and Receiver).
  const uint64_t num_extra_bytes =
      received_data.size() - (num_incoming_bytes + offset);

  if ((num_extra_bytes == 0) == received_extra_bytes) {
    LOG_ERROR("Detected extra bytes received, but none found.");
    return false;
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        received_data.data() + num_incoming_bytes + offset,
        num_extra_bytes);
  }
  if (!connection->ResetForReceive(extra_bytes)) {
    LOG_ERROR("Unable to save extra bytes for the next communication.");
    return false;
  }

  return true;
}

// A structure to hold all of the inputes and outputs necessary to run
// ServerDiffieHellmanEncryptSecrets.
struct ServerDiffieHellmanEncryptSecretsParams {
  // =============================== Inputs ====================================
  uint64_t start_index_;
  uint64_t num_secrets_;
  LargeInt a_;
  const GroupElement* a_times_negative_A_;
  const RandomOracleParams* ro_params_;
  const AesParams* enc_params_;
  const unsigned char* first_b_ptr_;
  const vector<uint64_t>* b_sizes_;
  const vector<ServerSecretPair>* secrets_;

  // =============================== Outputs ===================================
  uint64_t num_outgoing_bytes_for_thread_;
  vector<vector<unsigned char>>* e_0_;
  vector<vector<unsigned char>>* e_1_;

  ServerDiffieHellmanEncryptSecretsParams() {
    start_index_ = 0;
    num_secrets_ = 0;
    a_ = LargeInt::Zero();
    a_times_negative_A_ = nullptr;
    ro_params_ = nullptr;
    enc_params_ = nullptr;
    first_b_ptr_ = nullptr;
    b_sizes_ = nullptr;
    secrets_ = nullptr;

    num_outgoing_bytes_for_thread_ = 0;
    e_0_ = nullptr;
    e_1_ = nullptr;
  }
};

// This function take in the Bs (one for each pair of secrets) sent by
// the client and use them to encrypt the secrets.
// inputs:
//
// 'start_index': The (index of the) first secret to process
// 'num_secrets': how many secrets to read.
// 'a': exponent generated randomly by the Server.
// Client and Server).
// 'a_times_negative_A': literally (-a_) * A, where A is the group element generated by the Server at the beginning of the protocal.
// 'ro_params': Random Oracle parameters used to generate keys.
// 'enc_params': Encryption parameters used to encrypt the secrets.
// 'first_b_ptr': which slice of the buffer sent by the Client is to be decoded in this thread.
// 'secrets': Vector of secrets held by the Server.
// 'num_outgoing_bytes_for_thread': Number of bytes processsed in this thread.
// 'e_0': Vector of encrypted secrets computed by Server to be sent to the Client corresponding to the bit b=0.
// 'e_1': Vector of encrypted secrets computed by Server to be sent to the Client corresponding to the bit b=1.
bool ServerDiffieHellmanEncryptSecrets(
    const uint64_t start_index,
    const uint64_t num_secrets,
    const LargeInt a,
    const GroupElement* a_times_negative_A,
    const RandomOracleParams* ro_params,
    const AesParams* enc_params,
    const unsigned char* first_b_ptr,
    const vector<uint64_t>* b_sizes,
    const vector<ServerSecretPair>* secrets,
    uint64_t* num_outgoing_bytes_for_thread,
    vector<vector<unsigned char>>* e_0,
    vector<vector<unsigned char>>* e_1) {
  unique_ptr<GroupElement> b(
      CreateIdentityGroupElement(*(a_times_negative_A->GetConstProperties())));

  for (uint64_t i = start_index; i < start_index + num_secrets; ++i) {
    const uint64_t& num_bytes_i = (*b_sizes)[i];
    b->Decode(num_bytes_i, first_b_ptr);
    first_b_ptr += num_bytes_i;
    (*b) *= a;

    unique_ptr<GroupElement> b_alt(CreateGroupElementCopy(*b));
    (*b_alt) += *a_times_negative_A;
    unsigned char* b_enc = nullptr;
    unsigned char* b_alt_enc = nullptr;
    uint64_t b_enc_size = 0;
    uint64_t b_alt_enc_size = 0;
    if (!b->Encode(&b_enc_size, &b_enc) ||
        !b_alt->Encode(&b_alt_enc_size, &b_alt_enc)) {
      if (b_enc) free(b_enc);
      if (b_alt_enc) free(b_alt_enc);
      return false;
    }

    vector<unsigned char> key_0, key_1;
    if (!ROEvaluate(*ro_params, b_enc_size, b_enc, &key_0) ||
        !ROEvaluate(*ro_params, b_alt_enc_size, b_alt_enc, &key_1)) {
      if (b_enc) free(b_enc);
      if (b_alt_enc) free(b_alt_enc);
      return false;
    }

    // Clean-up.
    if (b_enc) free(b_enc);
    if (b_alt_enc) free(b_alt_enc);

    const ServerSecretPair& secrets_i = (*secrets)[i];
    // TODO(paul): Currently, only AES-128 is supported. Our keys, which
    // are the output of our RO (which is currently SHA-256), don't work.
    // So we need to either support AES-256, or truncate the SHA output to
    // 128 bits. For now, we do the former (which may have security
    // implications, for now having 128 bits instead of 256; although it's still
    // using the SHA256 algorithm).
    key_0.resize(16);
    key_1.resize(16);

    if (!AesEncrypt(*enc_params, key_0, secrets_i.s0_, &((*e_0)[i])) ||
        !AesEncrypt(*enc_params, key_1, secrets_i.s1_, &((*e_1)[i]))) {
      return false;
    }
    *num_outgoing_bytes_for_thread += (*e_0)[i].size() + (*e_1)[i].size();
  }

  return true;
}

// Callback function to compute ServerDiffieHellmanEncryptSecrets in
// multi-threaded case.
unsigned ServerDiffieHellmanEncryptSecretsCallback(void* args) {
  ServerDiffieHellmanEncryptSecretsParams* server_params =
      (ServerDiffieHellmanEncryptSecretsParams*) args;

  if (!ServerDiffieHellmanEncryptSecrets(
          server_params->start_index_,
          server_params->num_secrets_,
          server_params->a_,
          server_params->a_times_negative_A_,
          server_params->ro_params_,
          server_params->enc_params_,
          server_params->first_b_ptr_,
          server_params->b_sizes_,
          server_params->secrets_,
          &(server_params->num_outgoing_bytes_for_thread_),
          server_params->e_0_,
          server_params->e_1_)) {
    DLOG_ERROR("Failed to compute ServerDiffieHellmanEncryptSecrets");
    return 1;
  }
  return 0;
}

// Receives {B}_i from the Client, and returns {e_0}_i and {e_1}_i, two vectors
// of encrypted secrets.
bool ServerDiffieHellmanReceiveBs(
    const bool,
    const bool is_black_box,
    const int num_threads,
    Socket* connection,
    const LargeInt& a,
    const RandomOracleParams& ro_params,
    const AesParams& enc_params,
    const GroupElement* A,
    const vector<ServerSecretPair>* secrets) {
  // Receive B's from Client.
  const bool is_cookie_socket =
      connection->GetSocketType() == SocketType::COOKIE;
  bool received_extra_bytes = false;
  if (is_cookie_socket) {
    ListenParams params = connection->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(int64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (connection->GetReceivedBytes().size() != 1)
      LOG_FATAL("Unexpected number of Servers");
    connection->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    uint64_t num_bytes = CharVectorToValue<uint64_t>(received_data);

    // Now, listen for all of the secrets.
    if (num_bytes > INT_MAX) {
      LOG_FATAL("Too many bytes to receive.");
    }
    params.receive_buffer_max_size_ = (int) num_bytes;
    connection->ResetForReceive();
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
    return_codes = connection->Listen();
    // NOTE: The underlying CookieSocket::recv() functionality *must* support
    // calling recv(N), and receiving *more than* N bytes, and when this happens,
    // it must save the extra bytes somewhere, such that the *next* time
    // CookieSocket::recv(M) is called, then the overflow/storage is first checked/
    // drained, and then if additional bytes are needed, then keep reading.
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    ListenParams params;
    params.receive_data_ = &ReceiveInt64Bytes;
    if (!is_black_box) connection->ResetForReceive();
    connection->SetListenParams(params);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      // If D-H OT is used as an underlying black box OT protocol, then it is
      // possible that the present connection received not only the Server's
      // secrets, but also the *next* communication from the Server (based on
      // whatever the parent OT protocol dictates the Server should send next,
      // after having sent the secrets). In this case, Client may have received
      // more bytes than expected.
      if (return_codes.size() == 1 &&
          *(return_codes.begin()) ==
              ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
        received_extra_bytes = true;
      } else {
        DLOG_ERROR(
            "Failed communication with Client. Socket Error "
            "Message:\n" +
            connection->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  }

  if (connection->GetReceivedBytes().size() != 1)
    LOG_FATAL("Unexpected number of Servers");
  vector<char> received_data;
  connection->SwapBuffer(0, &received_data);

  const uint64_t num_secrets = secrets->size();

  unique_ptr<GroupElement> a_times_negative_A(CreateGroupElementCopy(*A));
  a_times_negative_A->Invert();
  (*a_times_negative_A) *= a;

  vector<vector<unsigned char>> e_0(num_secrets);
  vector<vector<unsigned char>> e_1(num_secrets);

  uint64_t buffer_index = is_cookie_socket ? 0 : sizeof(uint64_t);
  vector<uint64_t> b_sizes(num_secrets);

  for (uint64_t i = 0; i < num_secrets; ++i) {
    b_sizes[i] = ByteStringToValue<uint64_t>(
        sizeof(uint64_t), (unsigned char*) received_data.data() + buffer_index);
    buffer_index += sizeof(uint64_t);
  }

  uint64_t num_outgoing_bytes = 0;
  if (num_threads > 1) {
    // Divy up the work of generating the ciphertexts by assigning
    //   (num_secrets / num_threads) computations to each thread.
    const uint64_t num_tasks_per_thread = num_secrets / num_threads;
    const uint64_t remainder = num_secrets % num_threads;

    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    // Keep a pointer to each thread, so they may be terminated.
    vector<unique_ptr<ThreadParams>> thread_ids;
    CreateVectorOfThreadParams(num_threads, &thread_ids);

    uint64_t current_index = 0;
    vector<ServerDiffieHellmanEncryptSecretsParams> params_holder(
        num_threads, ServerDiffieHellmanEncryptSecretsParams());
    for (int i = 0; i < num_threads; ++i) {
      const uint64_t num_tasks_for_thread_i =
          num_tasks_per_thread + ((uint64_t) i < remainder ? 1 : 0);

      ServerDiffieHellmanEncryptSecretsParams& server_params = params_holder[i];
      server_params.start_index_ = current_index;
      server_params.num_secrets_ = num_tasks_for_thread_i;
      server_params.a_ = a;
      server_params.a_times_negative_A_ = a_times_negative_A.get();
      server_params.ro_params_ = &ro_params;
      server_params.enc_params_ = &enc_params;
      server_params.b_sizes_ = &b_sizes;
      server_params.first_b_ptr_ =
          (unsigned char*) received_data.data() + buffer_index;
      server_params.secrets_ = secrets;

      server_params.e_0_ = &e_0;
      server_params.e_1_ = &e_1;

      for (uint64_t j = 0; j < num_tasks_for_thread_i; ++j) {
        buffer_index += b_sizes[current_index + j];
      }

      t->StartThread(
          (void*) &ServerDiffieHellmanEncryptSecretsCallback,
          &server_params,
          thread_ids[i].get());
      current_index += num_tasks_for_thread_i;
    }

    bool all_threads_successful = true;
    for (int i = 0; i < num_threads; ++i) {
      t->WaitForThread(thread_ids[i].get());
      if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
        all_threads_successful = false;
        DLOG_ERROR("Thread " + Itoa(i) + " was unsuccesful:\n");
      }
      num_outgoing_bytes += params_holder[i].num_outgoing_bytes_for_thread_;
    }
    if (!all_threads_successful) {
      return false;
    }
  } else {
    if (!ServerDiffieHellmanEncryptSecrets(
            0,
            num_secrets,
            a,
            a_times_negative_A.get(),
            &ro_params,
            &enc_params,
            (unsigned char*) received_data.data() + buffer_index,
            &b_sizes,
            secrets,
            &num_outgoing_bytes,
            &e_0,
            &e_1)) {
      return false;
    }
    for (uint64_t i = 0; i < num_secrets; i++) {
      buffer_index += b_sizes[i];
    }
  }

  // Reset connection.
  // Save any extra bytes (which represent the *next* part of the communication
  // between Sender and Receiver).
  const uint64_t num_extra_bytes = received_data.size() - buffer_index;
  if ((num_extra_bytes == 0) == received_extra_bytes) {
    LOG_ERROR("Detected extra bytes received, but none found.");
    return false;
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        received_data.data() + buffer_index,
        num_extra_bytes);
  }
  if (!connection->ResetForReceive(extra_bytes)) {
    LOG_ERROR("Unable to save extra bytes for the next communication.");
    return false;
  }

  // Send (e_0, e_1).
  vector<unsigned char> to_send(num_outgoing_bytes);
  unsigned char* inserter = to_send.data();
  for (uint64_t i = 0; i < num_secrets; ++i) {
    const uint64_t num_bytes_0 = e_0[i].size();
    memcpy(inserter, e_0[i].data(), num_bytes_0);
    inserter += num_bytes_0;
    const uint64_t num_bytes_1 = e_1[i].size();
    memcpy(inserter, e_1[i].data(), num_bytes_1);
    inserter += num_bytes_1;
  }

  // Send.
  if (!connection->SendDataNoFlush(
          (unsigned char*) &num_outgoing_bytes, sizeof(uint64_t)) ||
      SendReturnCode::SUCCESS !=
          connection->SendData(to_send.data(), num_outgoing_bytes)) {
    DLOG_ERROR("Failure in ServerDiffieHellmanReceiveBs(): Unable to "
               "SendData.");
    return false;
  }

  // Done communicating with Client. Close connnection.
  if (!is_black_box) connection->Reset();

  return true;
}

// A structure to hold all of the inputs and outputs necessary to run
// ClientDiffieHellmanDecryptCiphertextParams.
struct ClientDiffieHellmanDecryptCiphertextParams {
  // =============================== Inputs ====================================
  uint64_t start_index_;
  uint64_t num_secrets_;
  uint64_t num_ciphertext_bytes_;
  const unsigned char* first_ciphertext_ptr_;
  const AesParams* enc_params_;
  const vector<vector<unsigned char>>* keys_;

  // =============================== Output ====================================
  vector<ClientSelectionBitAndSecret>* secrets_;

  ClientDiffieHellmanDecryptCiphertextParams() {
    start_index_ = 0;
    num_secrets_ = 0;
    num_ciphertext_bytes_ = 0;
    first_ciphertext_ptr_ = nullptr;
    enc_params_ = nullptr;
    keys_ = nullptr;
    secrets_ = nullptr;
  }
};

// This function takes in the encrypted secrets sent by the Server and
// decrypts the half of them corresponding to the bit choices chosen
// by the Client.

//
// Inputs:
//
// 'start_index': The (index of the) first secret to process.
// 'num_secrets': how many secrets to read.
// 'num_ciphertext_bytes:' byte counter to track how many bytes have
// been processed.
// 'enc_params': Encryption parameters used to encrypt the secrets
// 'first_ciphertext_ptr': which slice of the buffer sent by the
// Server is to be read in and decrypted in this thread.
// 'keys': Vector of keys generated by Client to decrypt final
// messages.
//
// Outputs:
//
// 'secrets': Vector of pairs (bit, secrets), where the bit was chosen
// by the Client at the beginning of this protocol, and the secret is
// the corresponding decrypted secret computed in this function.
bool ClientDiffieHellmanDecryptAndStoreSecret(
    const uint64_t start_index,
    const uint64_t num_secrets,
    const uint64_t& num_ciphertext_bytes,
    const unsigned char* first_ciphertext_ptr,
    const AesParams* enc_params,
    const vector<vector<unsigned char>>* keys,
    vector<ClientSelectionBitAndSecret>* secrets) {
  for (uint64_t i = start_index; i < start_index + num_secrets; ++i) {
    const bool c_i = (*secrets)[i].b_;
    if (c_i) {
      first_ciphertext_ptr += num_ciphertext_bytes;
    }
    vector<unsigned char> ciphertext(num_ciphertext_bytes);
    memcpy(ciphertext.data(), first_ciphertext_ptr, num_ciphertext_bytes);
    if (!AesDecrypt(
            *enc_params, (*keys)[i], ciphertext, &((*secrets)[i].s_b_))) {
      return false;
    }
    if (c_i) {
      first_ciphertext_ptr += num_ciphertext_bytes;
    } else {
      first_ciphertext_ptr += num_ciphertext_bytes * 2;
    }
  }

  return true;
}

// Callback function to compute
// ClientDiffieHellmanDecryptAndStoreSecret in multi-threaded case.
unsigned ClientDiffieHellmanDecryptCiphertextCallback(void* args) {
  ClientDiffieHellmanDecryptCiphertextParams* client_decrypt_params =
      (ClientDiffieHellmanDecryptCiphertextParams*) args;
  if (!ClientDiffieHellmanDecryptAndStoreSecret(
          client_decrypt_params->start_index_,
          client_decrypt_params->num_secrets_,
          client_decrypt_params->num_ciphertext_bytes_,
          client_decrypt_params->first_ciphertext_ptr_,
          client_decrypt_params->enc_params_,
          client_decrypt_params->keys_,
          client_decrypt_params->secrets_)) {
    DLOG_ERROR("Failed to compute ClientDiffieHellmanDecrypt and Store "
               "Secret");
    return 1;
  }
  return 0;
}

// Receives {e_0}_i and {e_1}_i, two vectors of encrypted secrets from
// the Server, and computes the {(b, secret)}_i, where the i-th secret
// is from e_0 or e_1 depending on the value of the i-th bit.
bool ClientDiffieHellmanReceiveSecrets(
    const bool is_black_box,
    const int num_threads,
    Socket* connection,
    const AesParams& enc_params,
    const vector<vector<unsigned char>>& keys,
    vector<ClientSelectionBitAndSecret>* selection_bits) {
  const uint64_t num_secrets = selection_bits->size();
  const uint64_t num_ciphertext_bytes = keys[0].size();

  // Listen for encrypted secrets from Server.
  const bool is_cookie_socket =
      connection->GetSocketType() == SocketType::COOKIE;
  bool received_extra_bytes = false;
  if (is_cookie_socket) {
    ListenParams params = connection->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(int64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (connection->GetReceivedBytes().size() != 1)
      LOG_FATAL("Unexpected number of Servers");
    connection->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    uint64_t num_bytes = CharVectorToValue<uint64_t>(received_data);

    // Now, listen for all of the secrets.
    if (num_bytes > INT_MAX) {
      LOG_FATAL("Too many bytes to receive.");
    }
    params.receive_buffer_max_size_ = (int) num_bytes;
    connection->ResetForReceive();
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
    return_codes = connection->Listen();
    // NOTE: The underlying CookieSocket::recv() functionality *must* support
    // calling recv(N), and receiving *more than* N bytes, and when this happens,
    // it must save the extra bytes somewhere, such that the *next* time
    // CookieSocket::recv(M) is called, then the overflow/storage is first checked/
    // drained, and then if additional bytes are needed, then keep reading.
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    ListenParams params;
    params.receive_data_ = &ReceiveInt64Bytes;
    connection->SetListenParams(params);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      // If D-H OT is used as an underlying black box OT protocol, then it is
      // possible that the present connection received not only the Server's
      // secrets, but also the *next* communication from the Server (based on
      // whatever the parent OT protocol dictates the Server should send next,
      // after having sent the secrets). In this case, Client may have received
      // more bytes than expected.
      if (return_codes.size() == 1 && is_black_box &&
          *(return_codes.begin()) ==
              ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
        received_extra_bytes = true;
      } else {
        DLOG_ERROR(
            "Failed communication with Server. Socket Error "
            "Message:\n" +
            connection->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  }

  vector<char> received_data;
  if (connection->GetReceivedBytes().size() != 1)
    LOG_FATAL("Unexpected number of Servers");
  connection->SwapBuffer(0, &received_data);

  // Parse received bytes.
  uint64_t buffer_index = is_cookie_socket ? 0 : sizeof(uint64_t);

  if (num_threads > 1) {
    // Divy up the work of generating the ciphertexts by assigning
    //   (num_secrets / num_threads) computations to each thread.
    const uint64_t num_tasks_per_thread = num_secrets / num_threads;
    const uint64_t remainder = num_secrets % num_threads;

    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    // Keep a pointer to each thread, so they may be terminated.
    vector<unique_ptr<ThreadParams>> thread_ids;
    CreateVectorOfThreadParams(num_threads, &thread_ids);

    vector<ClientDiffieHellmanDecryptCiphertextParams> params_holder(
        num_threads, ClientDiffieHellmanDecryptCiphertextParams());

    uint64_t current_index = 0;
    for (int i = 0; i < num_threads; ++i) {
      const uint64_t num_tasks_for_thread_i =
          num_tasks_per_thread + ((uint64_t) i < remainder ? 1 : 0);

      ClientDiffieHellmanDecryptCiphertextParams& client_info = params_holder[i];
      // Add start and num_tasks_per_thread for vector of secrets.
      client_info.start_index_ = current_index;
      client_info.num_secrets_ = num_tasks_for_thread_i;
      client_info.num_ciphertext_bytes_ = num_ciphertext_bytes;
      client_info.first_ciphertext_ptr_ =
          ((unsigned char*) received_data.data()) + buffer_index;
      client_info.enc_params_ = &enc_params;
      client_info.keys_ = &keys;

      client_info.secrets_ = selection_bits;
      for (uint64_t j = 0; j < num_tasks_for_thread_i; ++j) {
        buffer_index += 2 * num_ciphertext_bytes;
      }

      t->StartThread(
          (void*) &ClientDiffieHellmanDecryptCiphertextCallback,
          &client_info,
          thread_ids[i].get());
      current_index += num_tasks_for_thread_i;
    }

    bool all_threads_successful = true;
    for (int i = 0; i < num_threads; ++i) {
      t->WaitForThread(thread_ids[i].get());
      if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
        all_threads_successful = false;
        DLOG_ERROR("Thread " + Itoa(i) + " was unsuccesful:\n");
      }
    }
    if (!all_threads_successful) {
      return false;
    }
  } else {
    if (!ClientDiffieHellmanDecryptAndStoreSecret(
            0,
            num_secrets,
            num_ciphertext_bytes,
            ((unsigned char*) received_data.data()) + buffer_index,
            &enc_params,
            &keys,
            selection_bits)) {
      return false;
    }
    buffer_index += 2 * num_ciphertext_bytes * num_secrets;
  }

  const uint64_t num_extra_bytes = received_data.size() - buffer_index;
  if ((num_extra_bytes == 0) == received_extra_bytes) {
    DLOG_ERROR(
        "Detected extra bytes received, but none found: " +
        Itoa(received_data.size()) + " received, " +
        Itoa(
            is_cookie_socket ? received_data.size() :
                               CharVectorToValue<uint64_t>(received_data)) +
        " predicted, " + Itoa(buffer_index) + " used.");
    return false;
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        received_data.data() + buffer_index,
        num_extra_bytes);
  }
  // Done communicating with Server. Close connnection.
  if (!is_black_box) {
    connection->Reset();
  } else if (!connection->ResetForReceive(extra_bytes)) {
    DLOG_ERROR("Unable to save extra bytes for the next communication.");
    return false;
  }

  return true;
}

// Receives and parses the ciphertexts {E(s_b)}, storing the result in
// params->selection_bits_and_output_secret_[i].s_b_.
bool ClientReceivePaillierSecrets(
    const bool is_black_box,
    const int num_threads,
    Socket* connection,
    const PlaintextType type,
    const int plaintext_size,
    PaillierSecretKey& secret_key,
    vector<ClientSelectionBitAndSecret>* selection_bits_and_output_secret) {
  if (selection_bits_and_output_secret->empty()) {
    if (!is_black_box) connection->Reset();
    return true;
  }

  uint64_t num_secrets = 0;
  bool received_extra_bytes = false;
  const bool is_cookie_socket =
      connection->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = connection->GetListenParams();
    uint64_t num_first_comm_bytes = 2 * sizeof(uint64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (connection->GetReceivedBytes().size() != 1)
      LOG_FATAL("Unexpected number of Servers");
    connection->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    num_secrets = CharVectorToValue<uint64_t>(received_data);
    const uint64_t total_size =
        CharVectorToValue<uint64_t>(sizeof(uint64_t), received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes = num_secrets * sizeof(int) + total_size;
    if (num_second_comm_bytes > INT_MAX) {
      LOG_FATAL("Too many bytes to receive.");
    }
    params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
    connection->ResetForReceive();
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_second_comm_bytes);
    return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    // Listen for encrypted selection bits from Client.
    ListenParams params;
    params.receive_data_ = &ReceivePaillierSecrets;
    connection->SetListenParams(params);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      // If Paillier OT is used as an underlying black box OT protocol (e.g. for
      // IKNP OT), then it is possible
      // that the present connection received not only the Server's secrets, but also
      // the *next* communication from the Server (based on whatever the parent OT
      // protocol dictates the Server should send next, after having sent the secrets).
      // In this case, Client may have received more bytes than expected.
      if (return_codes.size() == 1 && is_black_box &&
          *(return_codes.begin()) ==
              ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
        received_extra_bytes = true;
      } else {
        DLOG_ERROR(
            "Failed communication with Server. Socket Error "
            "Message:\n" +
            connection->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  }

  // Done communicating with Server; just need to process the received bytes.
  // Go ahead and close the connection, so that the ip/port can be used
  // while this processing is being done.
  // Before closing connection, need to swap data buffer into a local copy, as
  // Reset()ing the connection will clear the buffer; but note that
  // 'SwapBuffer' doesn't take time, since the underlying 'swap' doesn't
  // copy all elements, it just swaps pointers.
  vector<char> received_data;
  if (connection->GetReceivedBytes().size() != 1)
    LOG_FATAL("Unexpected number of Servers");
  connection->SwapBuffer(0, &received_data);

  // The first byte(s) of the received data represents the number of
  // ciphertexts that should be expected.
  if (!is_cookie_socket) {
    num_secrets = CharVectorToValue<uint64_t>(received_data);
    // The next bytes of the received data represents the total size of all
    // ciphertexts. We don't use that info here (it was only needed to know
    // when Client was done receiving all the secrets from the Server); just
    // skip over those bytes.
  }

  uint64_t buffer_index = is_cookie_socket ? 0 : 2 * sizeof(uint64_t);
  if (num_secrets != selection_bits_and_output_secret->size()) {
    DLOG_ERROR(
        "Failure in ClientReceivePaillierSecrets(): Mismatching sizes "
        "of num_secrets (" +
        Itoa(num_secrets) +
        ") vs. "
        "selection_bits_and_output_secret (" +
        Itoa(selection_bits_and_output_secret->size()) + ")");
    return false;
  }

  // The next bytes are the sizes of each of the 'num_secrets' ciphertexts.
  vector<int> ciphertext_sizes(num_secrets);
  for (uint64_t i = 0; i < num_secrets; ++i) {
    ciphertext_sizes[i] = CharVectorToValue<int>(buffer_index, received_data);
    buffer_index += sizeof(int);
  }

  // The next bytes are the ciphertexts. Multi-thread this, since Decryption
  // may take time.
  if (num_threads > 1) {
    // Divy up the work of generating the ciphertexts by assigning
    //   num_secrets / num_threads
    // computations to each thread.
    const uint64_t num_tasks_per_thread = num_secrets / num_threads;
    const uint64_t remainder = num_secrets % num_threads;

    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    // Keep a pointer to each thread, so they may be terminated.
    vector<unique_ptr<ThreadParams>> thread_ids;
    CreateVectorOfThreadParams(num_threads, &thread_ids);

    // Spawn each thread to perform its task of decrypting the ciphertext.
    uint64_t current_index = 0;
    vector<ClientDecryptPaillierCiphertextParams> all_params(num_threads);
    for (int i = 0; i < num_threads; ++i) {
      const uint64_t num_tasks_for_thread_i =
          num_tasks_per_thread + ((uint64_t) i < remainder ? 1 : 0);

      // Create a structure that will be passed to the function that actually
      // performs the ciphertext computation.
      ClientDecryptPaillierCiphertextParams& thread_params = all_params[i];
      thread_params.secret_index_first_ = (int64_t) current_index;
      thread_params.num_secrets_in_block_ = num_tasks_for_thread_i;
      thread_params.secret_key_ = &secret_key;
      thread_params.type_ = type;
      thread_params.plaintext_size_ = plaintext_size;
      thread_params.ciphertext_sizes_ = &ciphertext_sizes;
      thread_params.thread_index_ = i;
      thread_params.first_ciphertext_ptr_ =
          (unsigned char*) received_data.data() + buffer_index;
      thread_params.secrets_.resize(num_tasks_for_thread_i);
      for (uint64_t j = 0; j < num_tasks_for_thread_i; ++j) {
        thread_params.secrets_[j] =
            &((*selection_bits_and_output_secret)[current_index + j].s_b_);
        buffer_index += ciphertext_sizes[current_index + j];
      }

      t->StartThread(
          (void*) &ClientPaillierDecryptCiphertextCallback,
          &thread_params,
          thread_ids[i].get());
      current_index += num_tasks_for_thread_i;
    }

    // Halt main thread until all threads have finished.
    bool all_threads_successful = true;
    for (int i = 0; i < num_threads; ++i) {
      t->WaitForThread(thread_ids[i].get());
      if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
        all_threads_successful = false;
        DLOG_ERROR(
            "Thread " + Itoa(i) + " was unsuccesful:\n" +
            all_params[i].error_msg_);
      }
    }
    if (!all_threads_successful) {
      return false;
    }
  } else {
    for (size_t i = 0; i < num_secrets; ++i) {
      const int ciphertext_size = ciphertext_sizes[i];
      // Read ciphertext.
      if (!ClientPaillierDecryptAndStoreSecret(
              type,
              plaintext_size,
              secret_key,
              ciphertext_size,
              (unsigned char*) received_data.data() + buffer_index,
              &(*selection_bits_and_output_secret)[i].s_b_)) {
        return false;
      }

      buffer_index += ciphertext_size;
    }
  }

  // Save any extra bytes (which represent the *next* part of the communication
  // between Sender and Receiver).
  const uint64_t num_extra_bytes = received_data.size() - buffer_index;
  if ((num_extra_bytes == 0) == received_extra_bytes) {
    DLOG_ERROR("Detected extra bytes received, but none found.");
    return false;
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        received_data.data() + buffer_index,
        num_extra_bytes);
  }
  // Done communicating with Server. Close connnection.
  if (!is_black_box) connection->Reset();
  else if (!connection->ResetForReceive(extra_bytes)) {
    DLOG_ERROR("Unable to save extra bytes for the next communication.");
    return false;
  }

  return true;
}

// Sends to Client the XOR of the original secrets and prg(random secrets).
bool ServerSendPrgXoredSecrets(
    const bool is_black_box,
    const int num_threads,
    Socket* connection,
    const PseudoRandomGeneratorParams& prg_params,
    const vector<ServerSecretPair>& random_secrets,
    const vector<ServerSecretPair>& original_secrets) {
  if (random_secrets.size() != original_secrets.size()) {
    LOG_FATAL("Bad input to ServerSendPrgXoredSecrets().");
  }
  if (original_secrets.empty()) {
    return true;
  }

  const uint64_t num_secrets = original_secrets.size();
  const uint64_t m = prg_params.domain_bits_;
  const uint64_t m_bytes = m / CHAR_BIT + (m % CHAR_BIT == 0 ? 0 : 1);
  const uint64_t n = prg_params.range_bits_;
  const uint64_t n_bytes = n / CHAR_BIT + (n % CHAR_BIT == 0 ? 0 : 1);

  vector<ServerSecretPair> xored_secrets;
  if (num_threads > 1) {
    // Divy up the work of xor'ing the secrets by assigning
    //   num_secrets / num_threads
    // computations to each thread.
    const uint64_t num_tasks_per_thread = num_secrets / num_threads;
    const uint64_t remainder = num_secrets % num_threads;

    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    // Keep a pointer to each thread, so they may be terminated.
    vector<unique_ptr<ThreadParams>> thread_ids;
    CreateVectorOfThreadParams(num_threads, &thread_ids);

    // Spawn each thread to perform its task of computing the ciphertext.
    uint64_t current_index = 0;
    vector<vector<ServerSecretPair>> xored_storage(num_threads);
    vector<ServerXorPrgSecretsParams> params_holder(
        num_threads, ServerXorPrgSecretsParams());
    for (int i = 0; i < num_threads; ++i) {
      const uint64_t num_tasks_for_thread_i =
          num_tasks_per_thread + ((uint64_t) i < remainder ? 1 : 0);
      // Create a structure that will be passed to the function that actually
      // performs the ciphertext computation.
      ServerXorPrgSecretsParams& params_i = params_holder[i];
      params_i.secret_index_first_ = current_index;
      params_i.num_secrets_in_block_ = num_tasks_for_thread_i;
      params_i.m_bytes_ = m_bytes;
      params_i.n_bytes_ = n_bytes;
      params_i.prg_params_ = &prg_params;
      params_i.orig_secrets_ = &original_secrets;
      params_i.random_secrets_ = &random_secrets;
      params_i.thread_index_ = i;
      params_i.xored_secrets_ = &xored_storage[i];

      t->StartThread(
          (void*) &ServerXorPrgSecretsCallback, &params_i, thread_ids[i].get());
      current_index += num_tasks_for_thread_i;
    }

    // Halt main thread until all threads have finished.
    bool all_threads_successful = true;
    for (int i = 0; i < num_threads; ++i) {
      t->WaitForThread(thread_ids[i].get());
      if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
        all_threads_successful = false;
        DLOG_ERROR(
            "Thread " + Itoa(i) + " was unsuccesful:\n" +
            params_holder[i].error_msg_);
      }
    }
    if (!all_threads_successful) {
      return false;
    }
    // Combine response from each thread, store in xored_secrets.
    for (int i = 0; i < num_threads; ++i) {
      xored_secrets.insert(
          xored_secrets.end(),
          params_holder[i].xored_secrets_->begin(),
          params_holder[i].xored_secrets_->end());
    }
  } else if (!ServerApplyPrgAndXorSecrets(
                 m_bytes,
                 n_bytes,
                 0,
                 num_secrets,
                 prg_params,
                 random_secrets,
                 original_secrets,
                 &xored_secrets)) {
    DLOG_ERROR("Failure in ServerSendPrgXoredSecrets(): Failed to "
               "ServerApplyPrgAndXorSecrets.");
    return false;
  }

  // Send the number of secrets to expect.
  if (!connection->SendDataNoFlush(
          (unsigned char*) &num_secrets, sizeof(uint64_t))) {
    DLOG_ERROR("Failure in ServerSendPrgXoredSecrets(): Unable to SendData.");
    return false;
  }
  // Send the size of each secret.
  if (SendReturnCode::SUCCESS !=
      connection->SendData((unsigned char*) &n_bytes, sizeof(uint64_t))) {
    DLOG_ERROR("Failure in ServerSendPrgXoredSecrets(): Unable to SendData.");
    return false;
  }
  // Send xored_secrets to Client.
  // NOTE: At this point, I could loop through xored_secrets, and call
  // SendData() on each one. That would incur any extra overhead that each
  // individual call to SendData() has. Alternatively, I can pack all of the
  // xored_secrets into a single (vector<unsigned char>) container, and then
  // call SendData() once on that. The latter approach of course incurs the
  // extra cost (both in terms of time and memory) of constructing that container,
  // but my current believe is that this latter overhead is likely less than
  // the overhead of (many calls to) SendData(), so that is what is done.
  uint64_t num_total_bytes = n_bytes * 2 * xored_secrets.size();
  vector<unsigned char> buffer_all(num_total_bytes);
  uint64_t current_index = 0;
  for (const ServerSecretPair& current_pair : xored_secrets) {
    for (uint64_t j = 0; j < current_pair.s0_.size(); ++j) {
      buffer_all[current_index] = current_pair.s0_[j];
      ++current_index;
    }
    for (uint64_t j = 0; j < current_pair.s1_.size(); ++j) {
      buffer_all[current_index] = current_pair.s1_[j];
      ++current_index;
    }
  }

  // Now send all secrets.
  // If a large number of bytes (> 65kb) need to be sent, we send in blocks.
  // This is because some OS can only send so many bytes as a time (per datagram).
  const uint64_t max_datagram_size = 65536;
  if (num_total_bytes > max_datagram_size) {
    uint64_t num_bytes_sent = 0;
    // Because we're sending in batches, we need the Client to "accept" what we
    // send before sending the next batch. However, the Client may still be
    // processing stuff from it's previous step, and thus not parsing the
    // received bytes. This means that the Client's receive buffer can be filling
    // up, and if it gets too full, it will stop accepting/listening for new bytes.
    // Thus, the SendData() call below can fail.
    // We want to allow the Client time to catch up (as well as to process the
    // bytes being received), but we also want to distinguish this from the case
    // that the Client has left the protocol. Thus, we will allow SendData() to
    // fail sometimes, and have the Server wait/sleep for a bit, and then try again.
    // If he continues to fail, then we will ultimately abort, after an appropriate
    // amount of time.
    const int max_num_errors =
        1000;  // Make sure (max_num_errors * 1000 <= 1000000, as
    // usleep has issues when passed-in value is >= 1M).
    int num_errors = 0;
    const int ms_to_sleep = 10;  // 0.01s
    bool prev_failed = false;
    while (num_bytes_sent < num_total_bytes) {
      const uint64_t num_to_send =
          min(num_total_bytes - num_bytes_sent, max_datagram_size);
      const SendReturnCode result = connection->SendData(
          ((unsigned char*) buffer_all.data()) + num_bytes_sent,
          (prev_failed ? 0 : num_to_send));
      if (result != SendReturnCode::SUCCESS) {
        // We allow failure if Client hasn't processed the bytes already sent,
        // which happens iff result indicates a SEND_ERROR or SOCKET_NOT_READY.
        if (result != SendReturnCode::SEND_ERROR &&
            result != SendReturnCode::SOCKET_NOT_READY) {
          DLOG_ERROR(
              "Failure in ServerSendPrgXoredSecrets(): Unable to "
              "SendData: " +
              Itoa(static_cast<int>(result)));
          return false;
        }
        ++num_errors;
        prev_failed = true;
        if (num_errors >= max_num_errors) {
          DLOG_ERROR(
              "Failure in ServerSendPrgXoredSecrets(): Unable to "
              "SendData. "
              "So far, " +
              Itoa(num_bytes_sent) + " of a total of " + Itoa(num_total_bytes) +
              " bytes have been sent, in chunks of " + Itoa(max_datagram_size) +
              " bytes per batch.  "
              "Socket Error Message:\n" +
              connection->GetErrorMessage());
          return false;
        }
        // Sleep more and more time, the more times we've failed.
        usleep(ms_to_sleep * 1000 * num_errors);
      } else {
        num_errors = 0;
        prev_failed = false;
        num_bytes_sent += num_to_send;
      }
    }
  } else if (
      SendReturnCode::SUCCESS !=
      connection->SendData(
          (unsigned char*) buffer_all.data(), num_total_bytes)) {
    DLOG_ERROR("Failure in ServerSendPrgXoredSecrets(): Unable to SendData.");
    return false;
  }

  // Done communicating with Client. Close connection.
  if (!is_black_box) connection->Reset();

  return true;
}

// Receives from Server the original secrets XORed with prg(random secrets).
bool ClientReceivePrgXoredSecrets(
    const bool is_black_box,
    Socket* connection,
    vector<ServerSecretPair>* xored_secrets) {
  uint64_t num_secrets = 0;
  uint64_t n_bytes = 0;
  bool received_extra_bytes = false;
  const bool is_cookie_socket =
      connection->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = connection->GetListenParams();
    uint64_t num_first_comm_bytes = 2 * sizeof(uint64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (connection->GetReceivedBytes().size() != 1)
      LOG_FATAL("Unexpected number of Servers");
    connection->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    num_secrets = CharVectorToValue<uint64_t>(received_data);
    n_bytes = CharVectorToValue<uint64_t>(sizeof(uint64_t), received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes = num_secrets * n_bytes * 2;
    if (num_second_comm_bytes > INT_MAX) {
      LOG_FATAL("Too many bytes to receive.");
    }
    params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
    connection->ResetForReceive();
    connection->SetListenParams(params);
    connection->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_second_comm_bytes);
    return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      DLOG_ERROR(
          "Client failed to get Server's secret(s). Socket Error "
          "Message:\n" +
          connection->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    // Listen for xored secrets from Server.
    ListenParams params;
    params.receive_data_ = &ReceivePrgXoredSecrets;
    connection->SetListenParams(params);
    set<ListenReturnCode> return_codes = connection->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      // If PRG OT is used as an underlying black box OT protocol, then it is possible
      // that the present connection received not only the Server's secrets, but also
      // the *next* communication from the Server (based on whatever the parent OT
      // protocol dictates the Server should send next, after having sent the secrets).
      // In this case, Client may have received more bytes than expected.
      if (return_codes.size() == 1 && is_black_box &&
          *(return_codes.begin()) ==
              ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
        received_extra_bytes = true;
      } else {
        DLOG_ERROR(
            "Failed communication with Server. Socket Error "
            "Message:\n" +
            connection->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  }

  // Done communicating with Server; just need to process the received bytes.
  // Go ahead and close the connection, so that the ip/port can be used
  // while this processing is being done.
  // Before closing connection, need to swap data buffer into a local copy, as
  // Reset()ing the connection will clear the buffer; but note that
  // 'SwapBuffer' doesn't take time, since the underlying 'swap' doesn't
  // copy all elements, it just swaps pointers.
  vector<char> received_data;
  if (connection->GetReceivedBytes().size() != 1)
    LOG_FATAL("Unexpected number of Servers");
  connection->SwapBuffer(0, &received_data);

  // The first byte(s) of the received data represents the number of
  // secret pairs that should be expected.
  if (!is_cookie_socket) {
    num_secrets = CharVectorToValue<uint64_t>(received_data);
    // The next bytes of the received data represents the number of bytes in
    // each pair of xored_secrets.
    n_bytes = CharVectorToValue<uint64_t>(sizeof(uint64_t), received_data);
  }

  uint64_t buffer_index = is_cookie_socket ? 0 : 2 * sizeof(uint64_t);

  // The next bytes are the xored_secret pairs.
  // NOTE: Another option would have been to make it so that received_data was
  // exactly the desired vector<ServerSecretPair>; for example by using
  // different ListenParams() above (i.e. use stop_params_.num_received_bytes_,
  // which is set to 2 * num_secrets * n_bytes). Then instead of doing a copy
  // in the loop below, time could be saved by simply doing:
  //   xored_secrets->swap(static_cast<vector<ServerSecretPair>>(received_data));
  // This was not done here to keep code consistent with how other ListenParams()
  // are set in the other methods in this file, and since the cost of the
  // copy here is negligible in the overall run-time of OT.
  xored_secrets->resize(num_secrets, ServerSecretPair());
  for (uint64_t i = 0; i < num_secrets; ++i) {
    ServerSecretPair& xored_secret_i = (*xored_secrets)[i];
    xored_secret_i.s0_.insert(
        xored_secret_i.s0_.begin(),
        (unsigned char*) received_data.data() + buffer_index,
        (unsigned char*) received_data.data() + buffer_index + n_bytes);
    buffer_index += n_bytes;
    xored_secret_i.s1_.insert(
        xored_secret_i.s1_.begin(),
        (unsigned char*) received_data.data() + buffer_index,
        (unsigned char*) received_data.data() + buffer_index + n_bytes);
    buffer_index += n_bytes;
  }

  // Save any extra bytes (which represent the *next* part of the communication
  // between Sender and Receiver).
  const uint64_t num_extra_bytes = received_data.size() - buffer_index;
  if ((num_extra_bytes == 0) == received_extra_bytes) {
    DLOG_ERROR("Detected extra bytes received, but none found.");
    return false;
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        received_data.data() + buffer_index,
        num_extra_bytes);
  }
  // Done communicating with Server. Close connnection.
  if (!is_black_box) connection->Reset();
  else if (!connection->ResetForReceive(extra_bytes)) {
    DLOG_ERROR("Unable to save extra bytes for the next communication.");
    return false;
  }

  return true;
}

}  // namespace

// ======================== Constructors for OTParamsSetup =====================
OTParamsSetup::OTParamsSetup() {
  type_ = OTProtocolCombo::UNKNOWN;
  num_secrets_ = 0;
  num_bytes_per_secret_ = 1;
  num_threads_ = -1;
  connection_ = nullptr;
  selection_bits_ = nullptr;
  secrets_ = nullptr;
  paillier_n_file_ = "";
  paillier_g_file_ = "";
  paillier_lambda_file_ = "";
  paillier_mu_file_ = "";
  use_edwards_curve_ = false;
  diffie_hellman_exponent_ = nullptr;
  prg_domain_bytes_ = 0;
  iknp_ro_security_param_bytes_ = 0;
}

OTParamsSetup::OTParamsSetup(const OTProtocolCombo type) : OTParamsSetup() {
  type_ = type;
}

OTParamsSetup::OTParamsSetup(
    const OTProtocolCombo type,
    const uint64_t& num_secrets,
    const uint64_t& bytes_per_secret,
    const string& paillier_n_file,
    const string& paillier_g_file,
    const string& paillier_lambda_file,
    const string& paillier_mu_file,
    const bool use_edwards_curve,
    const LargeInt* diffie_hellman_exponent,
    const uint64_t& prg_domain_bytes,
    const uint64_t& iknp_sec_param_bytes,
    // (At least) one of the two parameters below should be NULL.
    vector<ServerSecretPair>* secrets,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    Socket* connection,
    const int num_threads) {
  type_ = type;
  num_secrets_ = num_secrets;
  num_bytes_per_secret_ = bytes_per_secret;
  num_threads_ = num_threads;
  connection_ = connection;
  selection_bits_ = selection_bits;
  secrets_ = secrets;
  paillier_n_file_ = paillier_n_file;
  paillier_g_file_ = paillier_g_file;
  paillier_lambda_file_ = paillier_lambda_file;
  paillier_mu_file_ = paillier_mu_file;
  use_edwards_curve_ = use_edwards_curve;
  diffie_hellman_exponent_ = diffie_hellman_exponent;
  prg_domain_bytes_ = prg_domain_bytes;
  iknp_ro_security_param_bytes_ = iknp_sec_param_bytes;
}

OTParamsSetup::OTParamsSetup(
    const OTProtocolCombo type,
    const string&,
    const uint64_t& num_secrets,
    const uint64_t& bytes_per_secret,
    const bool use_edwards_curve,
    const LargeInt* diffie_hellman_exponent,
    const uint64_t& prg_domain_bytes,
    const uint64_t& iknp_sec_param_bytes,
    // (At least) one of the two parameters below should be NULL.
    vector<ServerSecretPair>* secrets,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    Socket* connection,
    const int num_threads) {
  type_ = type;
  num_secrets_ = num_secrets;
  num_bytes_per_secret_ = bytes_per_secret;
  num_threads_ = num_threads;
  connection_ = connection;
  selection_bits_ = selection_bits;
  secrets_ = secrets;
  paillier_n_file_ = "";
  paillier_g_file_ = "";
  paillier_lambda_file_ = "";
  paillier_mu_file_ = "";
  use_edwards_curve_ = use_edwards_curve;
  diffie_hellman_exponent_ = diffie_hellman_exponent;
  prg_domain_bytes_ = prg_domain_bytes;
  iknp_ro_security_param_bytes_ = iknp_sec_param_bytes;
}

// ====================== END Constructors for OTParamsSetup ===================

// ======================== Set[Server,Client]XXXOTParams ======================
// TODO(paul): There is a ton of duplicate code below, mainly stemming from the
// fact that all of the "From..." has boilerplate code (based on the parent OT),
// and only the call to Set[Client,Server]XXXOTParams for the child OT differs.
// Thus, for each *parent ot*, have a single, separate function to set the
// parent OT params. Then have all of them call this, and then the only
// thing that differs (besides the API/input parameters) is the call to the
// appropriate child OT(s).
bool SetServerPaillierOTParams(
    const bool is_debug,
    const bool is_black_box,
    const int num_threads,
    const string&,
    const string&,
    Socket* connection,
    vector<ServerSecretPair>* secrets,
    ServerPaillierOTParams* params) {
  // Set the ServerOTParms fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_client_.reset(connection);
  }
  if (secrets != nullptr) {
    params->secrets_ = secrets;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::PAILLIER;

  return true;
}

bool SetClientPaillierOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const string& paillier_n_file,
    const string& paillier_g_file,
    const string& paillier_lambda_file,
    const string& paillier_mu_file,
    Socket* connection,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    ClientPaillierOTParams* params) {
  if (num_bytes_per_secret >= kPaillierCryptosystemBits) {
    LOG_FATAL(
        "Unable to use Paillier OT for secrets of size > " +
        Itoa(kPaillierCryptosystemBits) + " bytes (" +
        Itoa(num_bytes_per_secret) + ").");
  }
  // Load Paillier Key information, if filenames containing this info
  // was provided.
  PaillierParams& paillier_params = params->paillier_params_;
  // I'll read keys in now (if available), so set read_keys_from_file_
  // to false (for future code that may try to re-read the keys).
  paillier_params.read_keys_from_file_ = false;
  const bool all_filenames_present = !paillier_lambda_file.empty() &&
      !paillier_mu_file.empty() && !paillier_n_file.empty() &&
      !paillier_g_file.empty();
  if (all_filenames_present) {
    paillier_params.key_file_n_ = paillier_n_file;
    paillier_params.key_file_g_ = paillier_g_file;
    paillier_params.key_file_lambda_ = paillier_lambda_file;
    paillier_params.key_file_mu_ = paillier_mu_file;
    // This will be over-written below, if the files already exist.
    paillier_params.write_keys_to_file_ = true;
  }
  // Read in keys from files, if they exist.
  if (all_filenames_present &&
      ReadPaillierSecretKey(
          paillier_n_file,
          paillier_lambda_file,
          paillier_mu_file,
          &paillier_params.secret_key_) &&
      ReadPaillierPublicKey(
          paillier_n_file, paillier_g_file, &paillier_params.public_key_)) {
    params->is_key_setup_ = true;
    paillier_params.write_keys_to_file_ = false;
  } else {
    params->is_key_setup_ = false;
    // We divide modulus by 2, since we will generate two primes, and we just
    // require their product to have kPaillierCryptosystemBits bits.
    paillier_params.modulus_bits_ = kPaillierCryptosystemBits;
  }

  // NOTE: If desired, in the future we can update input 'num_bytes_per_secret'
  // to instead 'num_bits_per_secret', and update the PlaintextType to
  // BIT_STRING. We don't do that now, because secrets are anyways stored as
  // byte arrays; so (at least as code stands now) specifying granularity at
  // the bit level does not yield any efficiency improvments.
  paillier_params.type_ = PlaintextType::BYTE_STRING;
  if (num_bytes_per_secret > std::numeric_limits<uint64_t>::max()) {
    LOG_FATAL("Plaintext too big.");
  }
  paillier_params.plaintext_size_ = (uint32_t) num_bytes_per_secret;

  // Set the ClientOTParms fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_server_.reset(connection);
  }
  if (selection_bits != nullptr) {
    params->selection_bits_and_output_secret_ = selection_bits;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::PAILLIER;

  return true;
}

bool SetServerDiffieHellmanOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    // Currently, only groups supported are DH (Z_STAR_LARGE_P) and E-C (EDWARDS_CURVE)
    const bool is_edwards_curve_group,
    const LargeInt* secret_exponent,
    Socket* connection,
    vector<ServerSecretPair>* secrets,
    ServerDiffieHellmanOTParams* params) {
  if (num_bytes_per_secret >= 32) {
    LOG_FATAL(
        "Unable to use Diffie-Hellman OT for secrets of size > 32 "
        "bytes (" +
        Itoa(num_bytes_per_secret) + ").");
  }

  // Set the ServerOTParms fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_client_.reset(connection);
  }
  if (secrets != nullptr) {
    params->secrets_ = secrets;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }

  // Set the DiffieHellman-specific fields.
  if (secret_exponent == nullptr) {
    LargeInt dh_group_modulus = is_edwards_curve_group ?
        GetEdwardCurveSubgroupSize() :
        GetDiffieHellmanGroupFourteenSize();
    params->a_ = RandomInModulus(dh_group_modulus);
  } else {
    params->a_ = *secret_exponent;
  }
  RandomOracleParams& ro_params = params->ro_params_;
  ro_params.type_ = RandomOracleType::SHA_256;
  AesParams& aes_params = params->enc_params_;
  aes_params.use_type_ = UseType::ENC;
  aes_params.key_type_ = EncryptionKeyType::KEY;
  aes_params.platform_ = EncryptionPlatform::NETTLE;
  if (is_edwards_curve_group) {
    // Default Edwards Curve is ED15519, which has 256 bits (255 bits for 'y',
    // 1 'sign' bit for 'x').
    // Set modulus (= 2^255 - 19), 'a' (= -1), and 'd' (= -121665/121666) for ED15519.
    LargeInt modulus =
        pow(LargeInt(2), static_cast<uint32_t>(255)) - LargeInt(19);
    LargeInt a = LargeInt(-1) % modulus;
    LargeInt inv;
    InverseModN(LargeInt(121666), modulus, &inv);
    LargeInt d = (LargeInt(-121665) * inv) % modulus;
    // Set value of the generator (of a subgroup of ED15519, which has order
    // |G| / 8, where |G| is the order of the full group ED15519). This
    // generator is the point (x, y) such that y = 4/5, and x is the
    // corresponding positive root.
    LargeInt y;
    InverseModN(LargeInt(5), modulus, &y);
    y = (LargeInt(4) * y) % modulus;
    LargeInt x = GetXCoordinate(y, modulus, a, d, true);
    params->g_ = unique_ptr<EdwardsCurveGroupElement>(
        new EdwardsCurveGroupElement(modulus, a, d, make_pair(x, y)));
  } else {
    // D-H group is "RFC 3526: D-H Group #14", which needs 2048 bits.
    // Currently the only non EC group we support is group14, for
    // which 2 is a generator:
    //   https://tools.ietf.org/html/rfc3526#section-3
    // NOTE: The subgroup of order 'q', where q is a large factor of p-1,
    // where p-1 is the order of EC group 14, is not relevant here.
    LargeInt modulus = GetDiffieHellmanGroupFourteenSize();
    params->g_ = unique_ptr<MultiplicativeIntegersModLargePGroupElement>(
        new MultiplicativeIntegersModLargePGroupElement(modulus, LargeInt(2)));
  }

  params->protocol_ = OTProtocol::DIFFIE_HELLMAN;

  return true;
}

bool SetClientDiffieHellmanOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    // Currently, only groups supported are DH (Z_STAR_LARGE_P) and E-C (EDWARDS_CURVE)
    const bool is_edwards_curve_group,
    const LargeInt* secret_exponent,
    Socket* connection,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    ClientDiffieHellmanOTParams* params) {
  if (num_bytes_per_secret > 16) {
    LOG_FATAL(
        "Unable to use Diffie-Hellman OT for secrets of size > 16 "
        "bytes (" +
        Itoa(num_bytes_per_secret) + ").");
  }

  // Set the ClientOTParms fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_server_.reset(connection);
  }
  if (selection_bits != nullptr) {
    params->selection_bits_and_output_secret_ = selection_bits;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }

  // Set the DiffieHellman-specific fields.
  //   - b_
  params->b_.resize(num_secrets);
  if (secret_exponent == nullptr) {
    LargeInt dh_group_modulus = is_edwards_curve_group ?
        GetEdwardCurveSubgroupSize() :
        GetDiffieHellmanGroupFourteenSize();
    for (uint64_t i = 0; i < num_secrets; ++i) {
      params->b_[i] = RandomInModulus(dh_group_modulus);
    }
  } else {
    for (uint64_t i = 0; i < num_secrets; ++i) {
      params->b_[i] = secret_exponent[i];
    }
  }
  RandomOracleParams& ro_params = params->ro_params_;
  ro_params.type_ = RandomOracleType::SHA_256;
  AesParams& aes_params = params->enc_params_;
  aes_params.use_type_ = UseType::ENC;
  aes_params.key_type_ = EncryptionKeyType::KEY;
  aes_params.platform_ = EncryptionPlatform::NETTLE;
  if (is_edwards_curve_group) {
    // Default Edwards Curve is ED15519, which has 256 bits (255 bits for 'y',
    // 1 'sign' bit for 'x').
    // Set modulus (= 2^255 - 19), 'a' (= -1), and 'd' (= -121665/121666) for ED15519.
    LargeInt modulus =
        pow(LargeInt(2), static_cast<uint32_t>(255)) - LargeInt(19);
    LargeInt a = LargeInt(-1) % modulus;
    LargeInt inv;
    InverseModN(LargeInt(121666), modulus, &inv);
    LargeInt d = (LargeInt(-121665) * inv) % modulus;
    // Set value of the generator, which is the point (x, y) such that
    // y = 4/5, and x is the corresponding positive root.
    LargeInt y;
    InverseModN(LargeInt(5), modulus, &y);
    y = (LargeInt(4) * y) % modulus;
    LargeInt x = GetXCoordinate(y, modulus, a, d, true);
    params->g_ = unique_ptr<EdwardsCurveGroupElement>(
        new EdwardsCurveGroupElement(modulus, a, d, make_pair(x, y)));
  } else {
    // D-H group is "RFC 3526: D-H Group #14", which needs 2048 bits.
    // Currently the only non EC group we support is group14, for
    // which 2 is a generator:
    //   https://tools.ietf.org/html/rfc3526#section-3
    // NOTE: The subgroup of order 'q', where q is a large factor of p-1,
    // where p-1 is the order of EC group 14, is not relevant here.
    LargeInt modulus = GetDiffieHellmanGroupFourteenSize();
    params->g_ = unique_ptr<MultiplicativeIntegersModLargePGroupElement>(
        new MultiplicativeIntegersModLargePGroupElement(modulus, LargeInt(2)));
  }

  params->protocol_ = OTProtocol::DIFFIE_HELLMAN;
  return true;
}

bool SetServerPrgFromPaillierOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t&,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_prg_domain_bytes,
    const string& paillier_n_file,
    const string& paillier_g_file,
    Socket* connection,
    vector<ServerSecretPair>* secrets,
    ServerPrgOTExtensionParams* params) {
  // Set underlying PRG OT parameters.
  params->prg_.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  params->prg_.domain_bits_ = CHAR_BIT * num_prg_domain_bytes;
  params->prg_.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set the ServerOTParms fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_client_.reset(connection);
  }
  if (secrets != nullptr) {
    params->secrets_ = secrets;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::PRG_EXTENSION;

  // Set underlying Paillier OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ServerPaillierOTParams>(new ServerPaillierOTParams());
  return SetServerPaillierOTParams(
      is_debug,
      true,
      num_threads,
      paillier_n_file,
      paillier_g_file,
      nullptr,
      nullptr,
      (ServerPaillierOTParams*) params->black_box_ot_params_.get());
}

bool SetClientPrgFromPaillierOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t&,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_prg_domain_bytes,
    const string& paillier_n_file,
    const string& paillier_g_file,
    const string& paillier_lambda_file,
    const string& paillier_mu_file,
    Socket* connection,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    ClientPrgOTExtensionParams* params) {
  // Set underlying PRG OT parameters.
  params->prg_.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  params->prg_.domain_bits_ = CHAR_BIT * num_prg_domain_bytes;
  params->prg_.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set the ClientOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_server_.reset(connection);
  }
  if (selection_bits != nullptr) {
    params->selection_bits_and_output_secret_ = selection_bits;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::PRG_EXTENSION;

  // Set underlying Paillier OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ClientPaillierOTParams>(new ClientPaillierOTParams());
  return SetClientPaillierOTParams(
      is_debug,
      true,
      num_prg_domain_bytes,
      num_threads,
      paillier_n_file,
      paillier_g_file,
      paillier_lambda_file,
      paillier_mu_file,
      nullptr,
      nullptr,
      (ClientPaillierOTParams*) params->black_box_ot_params_.get());
}

bool SetServerPrgFromDiffieHellmanOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t&,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_prg_domain_bytes,
    const bool is_edwards_curve_group,
    const LargeInt* secret_exponent,
    Socket* connection,
    vector<ServerSecretPair>* secrets,
    ServerPrgOTExtensionParams* params) {
  // Set underlying PRG OT parameters.
  params->prg_.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  params->prg_.domain_bits_ = CHAR_BIT * num_prg_domain_bytes;
  params->prg_.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set the ServerOTParms fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_client_.reset(connection);
  }
  if (secrets != nullptr) {
    params->secrets_ = secrets;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::PRG_EXTENSION;

  // Set underlying DiffieHellman OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ServerDiffieHellmanOTParams>(new ServerDiffieHellmanOTParams());
  return SetServerDiffieHellmanOTParams(
      is_debug,
      true,
      num_prg_domain_bytes,
      num_threads,
      is_edwards_curve_group,
      secret_exponent,
      nullptr,
      nullptr,
      (ServerDiffieHellmanOTParams*) params->black_box_ot_params_.get());
}

bool SetClientPrgFromDiffieHellmanOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_prg_domain_bytes,
    const bool is_edwards_curve_group,
    const LargeInt* secret_exponent,
    Socket* connection,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    ClientPrgOTExtensionParams* params) {
  // Set underlying PRG OT parameters.
  params->prg_.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  params->prg_.domain_bits_ = CHAR_BIT * num_prg_domain_bytes;
  params->prg_.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set the ClientOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_server_.reset(connection);
  }
  if (selection_bits != nullptr) {
    params->selection_bits_and_output_secret_ = selection_bits;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::PRG_EXTENSION;

  // Set underlying DiffieHellman OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ClientDiffieHellmanOTParams>(new ClientDiffieHellmanOTParams());
  return SetClientDiffieHellmanOTParams(
      is_debug,
      true,
      num_secrets,
      num_prg_domain_bytes,
      num_threads,
      is_edwards_curve_group,
      secret_exponent,
      nullptr,
      nullptr,
      (ClientDiffieHellmanOTParams*) params->black_box_ot_params_.get());
}

bool SetServerIKNPFromPaillierOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_iknp_sec_param_bytes,
    const string& paillier_n_file,
    const string& paillier_g_file,
    const string& paillier_lambda_file,
    const string& paillier_mu_file,
    Socket* connection,
    vector<ServerSecretPair>* secrets,
    ServerIKNPOTExtensionParams* params) {
  // The IKNP OT Extension protocol uses a Random Oracle. Set it up.
  RandomOracleParams& ro_params = params->random_oracle_;
  ro_params.type_ = RandomOracleType::AES_ENCRYPT_PLUS_PRG;
  PseudoRandomGeneratorParams& prg_params = ro_params.prg_params_;
  prg_params.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  prg_params.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set k = security parameter (used for RO), and underlying OT.
  params->num_security_param_bytes_ = num_iknp_sec_param_bytes;

  // Set the ServerOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_client_.reset(connection);
  }
  if (secrets != nullptr) {
    params->secrets_ = secrets;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::IKNP_EXTENSION;

  // Set underlying Paillier OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ClientPaillierOTParams>(new ClientPaillierOTParams());
  return SetClientPaillierOTParams(
      is_debug,
      true,
      (num_secrets / CHAR_BIT + (num_secrets % CHAR_BIT == 0 ? 0 : 1)),
      num_threads,
      paillier_n_file,
      paillier_g_file,
      paillier_lambda_file,
      paillier_mu_file,
      nullptr,
      nullptr,
      (ClientPaillierOTParams*) params->black_box_ot_params_.get());
}

bool SetClientIKNPFromPaillierOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t&,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_iknp_sec_param_bytes,
    const string& paillier_n_file,
    const string& paillier_g_file,
    Socket* connection,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    ClientIKNPOTExtensionParams* params) {
  // The IKNP OT Extension protocol uses a Random Oracle. Set it up.
  RandomOracleParams& ro_params = params->random_oracle_;
  ro_params.type_ = RandomOracleType::AES_ENCRYPT_PLUS_PRG;
  PseudoRandomGeneratorParams& prg_params = ro_params.prg_params_;
  prg_params.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  prg_params.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set k = security parameter (used for RO), and underlying OT.
  params->num_security_param_bytes_ = num_iknp_sec_param_bytes;

  // Set the ClientOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_server_.reset(connection);
  }
  if (selection_bits != nullptr) {
    params->selection_bits_and_output_secret_ = selection_bits;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::IKNP_EXTENSION;

  // Set underlying Paillier OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ServerPaillierOTParams>(new ServerPaillierOTParams());
  return SetServerPaillierOTParams(
      is_debug,
      true,
      num_threads,
      paillier_n_file,
      paillier_g_file,
      nullptr,
      nullptr,
      (ServerPaillierOTParams*) params->black_box_ot_params_.get());
}

bool SetServerIKNPFromDiffieHellmanOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_iknp_sec_param_bytes,
    // Currently, only groups supported are DH (Z_STAR_LARGE_P) and E-C (EDWARDS_CURVE)
    const bool is_edwards_curve_group,
    const LargeInt* secret_exponent,
    Socket* connection,
    vector<ServerSecretPair>* secrets,
    ServerIKNPOTExtensionParams* params) {
  // The IKNP OT Extension protocol uses a Random Oracle. Set it up.
  RandomOracleParams& ro_params = params->random_oracle_;
  ro_params.type_ = RandomOracleType::AES_ENCRYPT_PLUS_PRG;
  PseudoRandomGeneratorParams& prg_params = ro_params.prg_params_;
  prg_params.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  prg_params.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set k = security parameter (used for RO), and underlying OT.
  params->num_security_param_bytes_ = num_iknp_sec_param_bytes;

  // Set the ServerOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_client_.reset(connection);
  }
  if (secrets != nullptr) {
    params->secrets_ = secrets;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::IKNP_EXTENSION;

  // Set underlying DiffieHellman OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ClientDiffieHellmanOTParams>(new ClientDiffieHellmanOTParams());
  return SetClientDiffieHellmanOTParams(
      is_debug,
      true,
      CHAR_BIT * num_iknp_sec_param_bytes,
      (num_secrets / CHAR_BIT + (num_secrets % CHAR_BIT == 0 ? 0 : 1)),
      num_threads,
      is_edwards_curve_group,
      secret_exponent,
      nullptr,
      nullptr,
      (ClientDiffieHellmanOTParams*) params->black_box_ot_params_.get());
}

bool SetClientIKNPFromDiffieHellmanOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_iknp_sec_param_bytes,
    // Currently, only groups supported are DH (Z_STAR_LARGE_P) and E-C (EDWARDS_CURVE)
    const bool is_edwards_curve_group,
    const LargeInt* secret_exponent,
    Socket* connection,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    ClientIKNPOTExtensionParams* params) {
  // The IKNP OT Extension protocol uses a Random Oracle. Set it up.
  RandomOracleParams& ro_params = params->random_oracle_;
  ro_params.type_ = RandomOracleType::AES_ENCRYPT_PLUS_PRG;
  PseudoRandomGeneratorParams& prg_params = ro_params.prg_params_;
  prg_params.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  prg_params.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set k = security parameter (used for RO), and underlying OT.
  params->num_security_param_bytes_ = num_iknp_sec_param_bytes;

  // Set the ClientOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_server_.reset(connection);
  }
  if (selection_bits != nullptr) {
    params->selection_bits_and_output_secret_ = selection_bits;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::IKNP_EXTENSION;

  // Set underlying DiffieHellman OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ServerDiffieHellmanOTParams>(new ServerDiffieHellmanOTParams());
  return SetServerDiffieHellmanOTParams(
      is_debug,
      true,
      (num_secrets / CHAR_BIT + (num_secrets % CHAR_BIT == 0 ? 0 : 1)),
      num_threads,
      is_edwards_curve_group,
      secret_exponent,
      nullptr,
      nullptr,
      (ServerDiffieHellmanOTParams*) params->black_box_ot_params_.get());
}


bool SetServerIKNPFromPrgFromPaillierOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_prg_domain_bytes,
    const uint64_t& num_iknp_sec_param_bytes,
    const string& paillier_n_file,
    const string& paillier_g_file,
    const string& paillier_lambda_file,
    const string& paillier_mu_file,
    Socket* connection,
    vector<ServerSecretPair>* secrets,
    ServerIKNPOTExtensionParams* params) {
  // The IKNP OT Extension protocol uses a Random Oracle. Set it up.
  RandomOracleParams& ro_params = params->random_oracle_;
  ro_params.type_ = RandomOracleType::AES_ENCRYPT_PLUS_PRG;
  PseudoRandomGeneratorParams& prg_params = ro_params.prg_params_;
  prg_params.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  prg_params.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set k = security parameter (used for RO), and underlying OT.
  params->num_security_param_bytes_ = num_iknp_sec_param_bytes;

  // Set the ServerOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_client_.reset(connection);
  }
  if (secrets != nullptr) {
    params->secrets_ = secrets;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::IKNP_EXTENSION;

  // Set underlying Paillier OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ClientPrgOTExtensionParams>(new ClientPrgOTExtensionParams());
  return SetClientPrgFromPaillierOTParams(
      is_debug,
      true,
      CHAR_BIT * num_iknp_sec_param_bytes,
      (num_secrets / CHAR_BIT + (num_secrets % CHAR_BIT == 0 ? 0 : 1)),
      num_threads,
      num_prg_domain_bytes,
      paillier_n_file,
      paillier_g_file,
      paillier_lambda_file,
      paillier_mu_file,
      nullptr,
      nullptr,
      (ClientPrgOTExtensionParams*) params->black_box_ot_params_.get());
}

bool SetClientIKNPFromPrgFromPaillierOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_prg_domain_bytes,
    const uint64_t& num_iknp_sec_param_bytes,
    const string& paillier_n_file,
    const string& paillier_g_file,
    Socket* connection,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    ClientIKNPOTExtensionParams* params) {
  // The IKNP OT Extension protocol uses a Random Oracle. Set it up.
  RandomOracleParams& ro_params = params->random_oracle_;
  ro_params.type_ = RandomOracleType::AES_ENCRYPT_PLUS_PRG;
  PseudoRandomGeneratorParams& prg_params = ro_params.prg_params_;
  prg_params.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  prg_params.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set k = security parameter (used for RO), and underlying OT.
  params->num_security_param_bytes_ = num_iknp_sec_param_bytes;

  // Set the ClientOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_server_.reset(connection);
  }
  if (selection_bits != nullptr) {
    params->selection_bits_and_output_secret_ = selection_bits;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::IKNP_EXTENSION;

  // Set underlying Paillier OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ServerPrgOTExtensionParams>(new ServerPrgOTExtensionParams());
  return SetServerPrgFromPaillierOTParams(
      is_debug,
      true,
      CHAR_BIT * num_iknp_sec_param_bytes,
      (num_secrets / CHAR_BIT + (num_secrets % CHAR_BIT == 0 ? 0 : 1)),
      num_threads,
      num_prg_domain_bytes,
      paillier_n_file,
      paillier_g_file,
      nullptr,
      nullptr,
      (ServerPrgOTExtensionParams*) params->black_box_ot_params_.get());
}

bool SetServerIKNPFromPrgFromDiffieHellmanOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_prg_domain_bytes,
    const uint64_t& num_iknp_sec_param_bytes,
    // Currently, only groups supported are DH (Z_STAR_LARGE_P) and E-C (EDWARDS_CURVE)
    const bool is_edwards_curve_group,
    const LargeInt* secret_exponent,
    Socket* connection,
    vector<ServerSecretPair>* secrets,
    ServerIKNPOTExtensionParams* params) {
  // The IKNP OT Extension protocol uses a Random Oracle. Set it up.
  RandomOracleParams& ro_params = params->random_oracle_;
  ro_params.type_ = RandomOracleType::AES_ENCRYPT_PLUS_PRG;
  PseudoRandomGeneratorParams& prg_params = ro_params.prg_params_;
  prg_params.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  prg_params.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set k = security parameter (used for RO), and underlying OT.
  params->num_security_param_bytes_ = num_iknp_sec_param_bytes;

  // Set the ServerOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_client_.reset(connection);
  }
  if (secrets != nullptr) {
    params->secrets_ = secrets;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::IKNP_EXTENSION;

  // Set underlying DiffieHellman OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ClientPrgOTExtensionParams>(new ClientPrgOTExtensionParams());
  return SetClientPrgFromDiffieHellmanOTParams(
      is_debug,
      true,
      CHAR_BIT * num_iknp_sec_param_bytes,
      (num_secrets / CHAR_BIT + (num_secrets % CHAR_BIT == 0 ? 0 : 1)),
      num_threads,
      num_prg_domain_bytes,
      is_edwards_curve_group,
      secret_exponent,
      nullptr,
      nullptr,
      (ClientPrgOTExtensionParams*) params->black_box_ot_params_.get());
}

bool SetClientIKNPFromPrgFromDiffieHellmanOTParams(
    const bool is_debug,
    const bool is_black_box,
    const uint64_t& num_secrets,
    const uint64_t& num_bytes_per_secret,
    const int num_threads,
    const uint64_t& num_prg_domain_bytes,
    const uint64_t& num_iknp_sec_param_bytes,
    // Currently, only groups supported are DH (Z_STAR_LARGE_P) and E-C (EDWARDS_CURVE)
    const bool is_edwards_curve_group,
    const LargeInt* secret_exponent,
    Socket* connection,
    vector<ClientSelectionBitAndSecret>* selection_bits,
    ClientIKNPOTExtensionParams* params) {
  // The IKNP OT Extension protocol uses a Random Oracle. Set it up.
  RandomOracleParams& ro_params = params->random_oracle_;
  ro_params.type_ = RandomOracleType::AES_ENCRYPT_PLUS_PRG;
  PseudoRandomGeneratorParams& prg_params = ro_params.prg_params_;
  prg_params.type_ = PseudoRandomGeneratorType::AES_W_INPUT_AS_KEY;
  prg_params.range_bits_ = CHAR_BIT * num_bytes_per_secret;

  // Set k = security parameter (used for RO), and underlying OT.
  params->num_security_param_bytes_ = num_iknp_sec_param_bytes;

  // Set the ClientOTParams fields.
  params->is_black_box_ = is_black_box;
  params->is_debug_ = is_debug;
  if (connection != nullptr) {
    params->connection_to_server_.reset(connection);
  }
  if (selection_bits != nullptr) {
    params->selection_bits_and_output_secret_ = selection_bits;
  }
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
  params->protocol_ = OTProtocol::IKNP_EXTENSION;

  // Set underlying DiffieHellman OT parameters.
  params->black_box_ot_params_ =
      unique_ptr<ServerPrgOTExtensionParams>(new ServerPrgOTExtensionParams());
  return SetServerPrgFromDiffieHellmanOTParams(
      is_debug,
      true,
      CHAR_BIT * num_iknp_sec_param_bytes,
      (num_secrets / CHAR_BIT + (num_secrets % CHAR_BIT == 0 ? 0 : 1)),
      num_threads,
      num_prg_domain_bytes,
      is_edwards_curve_group,
      secret_exponent,
      nullptr,
      nullptr,
      (ServerPrgOTExtensionParams*) params->black_box_ot_params_.get());
}

// =========================== END SetXXXOTParams ==============================

bool ServerPaillierOT(ServerPaillierOTParams* params) {
  Timer ot_time;
  if (params->is_debug_) StartTimer(&ot_time);
  if (params == nullptr || params->secrets_ == nullptr ||
      params->secrets_->size() <= 0 ||
      (*params->secrets_)[0].s0_.size() > kPaillierCryptosystemBits ||
      params->connection_to_client_ == nullptr) {
    LOG_FATAL("Null input to ServerPaillierOT().");
  }

  // Get Paillier (public) parameters from Client.
  if (!ServerSetupPaillierParameters(
          params->connection_to_client_.get(), &params->key_)) {
    params->error_msg_ +=
        "Failed to get Paillier public parameters from Client.";
    DLOG_ERROR("Failure in ServerPaillierOT(): "
               "Failed to get Paillier public parameters from Client.");
    params->connection_to_client_->Reset();
    return false;
  }

  // Receive {E(0), E(1)} from the Client. Note that for each OT to perform, the
  // Sender receives |s_i| pairs {E(0), E(1)}, where |s_i| is the number of bits
  // in the Sender's secrets (typically 1, but sometimes e.g. |slice|. The outer
  // vector has size equal to the number of OT's being performed.
  vector<pair<LargeInt, LargeInt>> client_ciphertexts;
  const string success = ServerReceivePaillierSelectionBits(
      params->connection_to_client_.get(), &client_ciphertexts);
  if (!success.empty()) {
    params->error_msg_ += success;
    DLOG_ERROR("Failure in ServerPaillierOT(): " + success);
    params->connection_to_client_->Reset();
    return false;
  }

  // Compute the ciphertexts {E(s_b)}.
  uint64_t total_ciphertexts_size;
  vector<LargeInt> ciphertexts_to_return;
  if (!ServerComputePaillierCiphertexts(
          params,
          client_ciphertexts,
          &total_ciphertexts_size,
          &ciphertexts_to_return)) {
    params->error_msg_ += "Wrong number of (encrypted) selection bits "
                          "received from Client.";
    DLOG_ERROR("Failure in ServerPaillierOT(): "
               "Wrong number of (encrypted) selection bits received "
               "from Client.");
    params->connection_to_client_->Reset();
    return false;
  }

  // Send ciphertexts to Client.
  if (!ServerSendPaillierSecrets(
          params->is_black_box_,
          params->connection_to_client_.get(),
          total_ciphertexts_size,
          ciphertexts_to_return)) {
    params->error_msg_ += "Unable to ServerSendPaillierSecrets().";
    DLOG_ERROR("Failure in ServerPaillierOT(): "
               "Unable to ServerSendPaillierSecrets().");
    params->connection_to_client_->Reset();
    return false;
  }

  if (params->is_debug_) {
    StopTimer(&ot_time);
    LOG_INFO("Server Paillier: " + FormatTime(GetElapsedTime(ot_time) / 1000));
  }
  return true;
}

bool ClientPaillierOT(ClientPaillierOTParams* params) {
  Timer ot_time;
  if (params->is_debug_) StartTimer(&ot_time);
  // Check if Paillier parameters have already been set. If not, set them up.
  if (!params->is_key_setup_ &&
      !GeneratePaillierParameters(&params->paillier_params_)) {
    params->error_msg_ += "Unable to Setup Paillier parameters.";
    DLOG_ERROR("Failure in ClientPaillierOT(): "
               "Unable to setup Paillier Parameters.");
    params->connection_to_server_->Reset();
    return false;
  }

  // Engage in a 2-party protocol to Send the Server Paillier (public) parameters.
  if (!ClientSendPaillierParameters(
          params->connection_to_server_.get(), params->paillier_params_)) {
    params->error_msg_ += "Unable to Send Paillier public key to Server.";
    DLOG_ERROR("Failure in ClientPaillierOT(): "
               "Unable to Send Paillier public key to Server.");
    params->connection_to_server_->Reset();
    return false;
  }

  // Send (encrypted) selection bits to Server.
  if (!ClientSendPaillierSelectionBits(
          params->num_threads_,
          params->connection_to_server_.get(),
          params->paillier_params_.public_key_,
          *params->selection_bits_and_output_secret_)) {
    params->error_msg_ += "Unable to ClientSendPaillierSelectionBits().";
    DLOG_ERROR("Failure in ClientPaillierOT(): "
               "Unable to ClientSendPaillierSelectionBits().");
    params->connection_to_server_->Reset();
    return false;
  }

  // Receive and parse ciphertexts {E(s_b)} from Server.
  if (!ClientReceivePaillierSecrets(
          params->is_black_box_,
          params->num_threads_,
          params->connection_to_server_.get(),
          params->paillier_params_.type_,
          params->paillier_params_.plaintext_size_,
          params->paillier_params_.secret_key_,
          params->selection_bits_and_output_secret_)) {
    params->error_msg_ += "Failed to receive Server's secrets via Paillier OT.";
    DLOG_ERROR("Failure in ClientPaillierOT(): "
               "Failed to receive Server's secrets via Paillier OT.");
    params->connection_to_server_->Reset();
    return false;
  }

  if (params->is_debug_) {
    StopTimer(&ot_time);
    LOG_INFO("Client Paillier: " + FormatTime(GetElapsedTime(ot_time) / 1000));
  }
  return true;
}

bool ServerDiffieHellmanOT(ServerDiffieHellmanOTParams* params) {
  Timer ot_time_server;
  if (params->is_debug_) StartTimer(&ot_time_server);
  if (params == nullptr || params->secrets_ == nullptr ||
      params->secrets_->size() <= 0 ||
      params->connection_to_client_ == nullptr) {
    LOG_FATAL("Null input to ServerDiffieHellmanOT().");
  }

  // Compute A = g^a.
  unique_ptr<GroupElement> A(CreateGroupElementCopy(*(params->g_.get())));
  (*A) *= params->a_;

  // Send A = g^a to Client.
  if (!ServerDiffieHellmanSendA(
          params->is_black_box_, params->connection_to_client_.get(), A.get())) {
    return false;
  }

  // Receive B's from Client, and then send encrypted secrets to Client.
  if (!ServerDiffieHellmanReceiveBs(
          params->is_debug_,
          params->is_black_box_,
          params->num_threads_,
          params->connection_to_client_.get(),
          params->a_,
          params->ro_params_,
          params->enc_params_,
          A.get(),
          params->secrets_)) {
    return false;
  }

  if (params->is_debug_) {
    StopTimer(&ot_time_server);
    LOG_INFO(
        "Server DiffieHellman: " +
        FormatTime(GetElapsedTime(ot_time_server) / 1000));
  }

  return true;
}

bool ClientDiffieHellmanOT(ClientDiffieHellmanOTParams* params) {
  Timer ot_time_client;
  if (params->is_debug_) StartTimer(&ot_time_client);

  vector<vector<unsigned char>> keys(params->b_.size(), vector<unsigned char>());

  // Receive Server's A = g^a, and then return B's to Server.
  if (!ClientDiffieHellmanReceiveA(
          params->is_debug_,
          params->is_black_box_,
          params->num_threads_,
          params->connection_to_server_.get(),
          params->g_.get(),
          params->b_,
          *params->selection_bits_and_output_secret_,
          params->ro_params_,
          &keys)) {
    return false;
  }

  // Receive Server's encrypted secrets.
  if (!ClientDiffieHellmanReceiveSecrets(
          params->is_black_box_,
          params->num_threads_,
          params->connection_to_server_.get(),
          params->enc_params_,
          keys,
          params->selection_bits_and_output_secret_)) {
    return false;
  }

  if (params->is_debug_) {
    StopTimer(&ot_time_client);
    LOG_INFO(
        "Client DiffieHellman: " +
        FormatTime(GetElapsedTime(ot_time_client) / 1000));
  }

  return true;
}

bool ServerPrgOTExtension(ServerPrgOTExtensionParams* params) {
  if (params->secrets_->empty()) {
    return true;
  }
  Timer ot_time;
  if (params->is_debug_) StartTimer(&ot_time);
  const uint64_t k = params->secrets_->size();
  const uint64_t m = params->prg_.domain_bits_;
  const uint64_t n = params->prg_.range_bits_ > 0 ?
      params->prg_.range_bits_ :
      CHAR_BIT * (*params->secrets_)[0].s0_.size();
  params->prg_.range_bits_ = n;
  const uint64_t m_bytes = m / CHAR_BIT + (m % CHAR_BIT == 0 ? 0 : 1);

  // Generate random secrets to be transfered to Client for the underlying
  // OT^k_m protocol.
  vector<ServerSecretPair> random_secrets(k, ServerSecretPair());
  for (size_t i = 0; i < k; ++i) {
    ServerSecretPair& current_secrets = random_secrets[i];
    RandomBytes(m_bytes, &current_secrets.s0_);
    RandomBytes(m_bytes, &current_secrets.s1_);
  }
  params->black_box_ot_params_->secrets_ = &random_secrets;

  // Copy any other fields from params to black_box_ot_params_.
  ServerOTParams* ot_params = params->black_box_ot_params_.get();
  if (ot_params->connection_to_client_ == nullptr) {
    ot_params->connection_to_client_.reset(
        params->connection_to_client_.release());
  }
  if (ot_params->num_threads_ < 0) {
    ot_params->num_threads_ = params->num_threads_;
  }

  // Run underlying OT^k_m protocol.
  if (!ServerOT(ot_params)) {
    DLOG_ERROR("Failed ServerPrgOTExtension(): Underlying OT^k_m "
               "protocol failed.");
    return false;
  }
  // Take back ownership of connection.
  if (params->connection_to_client_ == nullptr) {
    params->connection_to_client_.reset(
        ot_params->connection_to_client_.release());
  }

  // Send Client, in the clear, the k-pairs of m-bit strings:
  //   (s0 + prg(z0), s1 + prg(z1))
  // where '+' denotes XOR, (s0, s1) are the Server's secrets, and (z0, z1)
  // are the generated secrets in random_secrets.
  if (!ServerSendPrgXoredSecrets(
          params->is_black_box_,
          params->num_threads_,
          params->connection_to_client_.get(),
          params->prg_,
          random_secrets,
          *params->secrets_)) {
    DLOG_ERROR("Failed ServerPrgOTExtension(): Failed to send XOR'ed "
               "secrets.");
    params->connection_to_client_->Reset();
    return false;
  }

  if (params->is_debug_) {
    StopTimer(&ot_time);
    LOG_INFO("Server PRG: " + FormatTime(GetElapsedTime(ot_time) / 1000));
  }
  return true;
}

bool ClientPrgOTExtension(ClientPrgOTExtensionParams* params) {
  if (params->selection_bits_and_output_secret_->empty()) {
    return true;
  }
  Timer ot_time;
  if (params->is_debug_) StartTimer(&ot_time);
  const uint64_t k = params->selection_bits_and_output_secret_->size();
  const uint64_t n = params->prg_.range_bits_;
  const uint64_t n_bytes = n / CHAR_BIT + (n % CHAR_BIT == 0 ? 0 : 1);

  // Copy selection bits to underlying OT protocol, if necessary.
  ClientOTParams* ot_params = params->black_box_ot_params_.get();
  vector<ClientSelectionBitAndSecret> selection_bits_and_output_secret;
  if (ot_params->selection_bits_and_output_secret_ == nullptr) {
    ot_params->selection_bits_and_output_secret_ =
        &selection_bits_and_output_secret;
  }
  if (ot_params->selection_bits_and_output_secret_->empty()) {
    *ot_params->selection_bits_and_output_secret_ =
        *params->selection_bits_and_output_secret_;
  }

  // Copy any other fields from params to black_box_ot_params_.
  if (ot_params->connection_to_server_ == nullptr) {
    ot_params->connection_to_server_.reset(
        params->connection_to_server_.release());
  }
  if (ot_params->num_threads_ < 0) {
    ot_params->num_threads_ = params->num_threads_;
  }

  // Run underlying OT^k_m protocol, to get Server's (random) z_b.
  if (!ClientOT(ot_params)) {
    DLOG_ERROR("Failed ClientPrgOTExtension(): Underlying OT^k_m "
               "protocol failed.");
    return false;
  }
  if (ot_params->selection_bits_and_output_secret_->empty()) {
    LOG_FATAL("Failure in ClientPrgOTExtension(). This should never happen.");
  }
  // Take back ownership of connection.
  if (params->connection_to_server_ == nullptr) {
    params->connection_to_server_.reset(
        ot_params->connection_to_server_.release());
  }

  // Receive XOR'ed secrets from Server:
  //   (s0 + prg(z0), s1 + prg(z1))
  // where '+' denotes XOR, (s0, s1) are the Server's secrets, and (z0, z1)
  // are the generated secrets in random_secrets.
  vector<ServerSecretPair> xored_secrets;
  if (!ClientReceivePrgXoredSecrets(
          params->is_black_box_,
          params->connection_to_server_.get(),
          &xored_secrets)) {
    DLOG_ERROR("Failed ClientPrgOTExtension(): Failed to receive "
               "XOR'ed secrets.");
    params->connection_to_server_->Reset();
    return false;
  }

  // Apply PRG to results of underlying OT^k_m, and then XOR with the appropriate
  // s_b + prg(z_b), to obtain s_b.
  if (ot_params->selection_bits_and_output_secret_->size() != k ||
      params->selection_bits_and_output_secret_->size() != k ||
      xored_secrets.size() != k) {
    LOG_FATAL("Failure in ClientPrgOTExtension(). This should never happen.");
  }

  // Apply PRG. Multi-thread this for speed.
  vector<vector<unsigned char>> prg_z_values(k);
  const int num_threads = params->num_threads_;
  if (num_threads > 1) {
    // Divy up the work of xor'ing the secrets by assigning
    //   num_secrets / num_threads
    // computations to each thread.
    const uint64_t num_tasks_per_thread = k / num_threads;
    const uint64_t remainder = k % num_threads;

    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    // Keep a pointer to each thread, so they may be terminated.
    vector<unique_ptr<ThreadParams>> thread_ids;
    CreateVectorOfThreadParams(num_threads, &thread_ids);

    // Spawn each thread to perform its task of computing the ciphertext.
    uint64_t current_index = 0;
    vector<ClientApplyPrgParams> params_holder(
        num_threads, ClientApplyPrgParams());
    for (int i = 0; i < num_threads; ++i) {
      const uint64_t num_tasks_for_thread_i =
          num_tasks_per_thread + ((uint64_t) i < remainder ? 1 : 0);
      // Create a structure that will be passed to the function that actually
      // performs the ciphertext computation.
      ClientApplyPrgParams& params_i = params_holder[i];
      params_i.secret_index_first_ = current_index;
      params_i.num_secrets_in_block_ = num_tasks_for_thread_i;
      params_i.prg_params_ = &params->prg_;
      params_i.orig_secrets_ = ot_params->selection_bits_and_output_secret_;
      params_i.thread_index_ = i;
      params_i.prg_secrets_ = &prg_z_values;

      t->StartThread(
          (void*) &ClientApplyPrgCallback, &params_i, thread_ids[i].get());
      current_index += num_tasks_for_thread_i;
    }

    // Halt main thread until all threads have finished.
    bool all_threads_successful = true;
    for (int i = 0; i < num_threads; ++i) {
      t->WaitForThread(thread_ids[i].get());
      if (!thread_ids[i]->exit_code_set_ || thread_ids[i]->exit_code_ != 0) {
        all_threads_successful = false;
        DLOG_ERROR(
            "Thread " + Itoa(i) + " was unsuccesful:\n" +
            params_holder[i].error_msg_);
      }
    }
    if (!all_threads_successful) {
      return false;
    }
  } else {
    for (size_t i = 0; i < k; ++i) {
      if (!ClientApplyPrg(
              params->prg_,
              (*ot_params->selection_bits_and_output_secret_)[i].s_b_,
              &prg_z_values[i])) {
        DLOG_ERROR(
            "Failure in ClientPrgOTExtension(): Failed to "
            "ClientApplyPrg() for i = " +
            Itoa(i));
        return false;
      }
    }
  }

  for (size_t i = 0; i < k; ++i) {
    const vector<unsigned char>& prg_z_i = prg_z_values[i];
    // XOR the appropriate received bytes: (s_b + prg(z_b)) with prg(z_b).
    const ServerSecretPair& server_secrets_i = xored_secrets[i];
    const vector<unsigned char>& server_secrets_i_b =
        (*params->selection_bits_and_output_secret_)[i].b_ ?
        server_secrets_i.s1_ :
        server_secrets_i.s0_;
    if (prg_z_i.size() != n_bytes || server_secrets_i_b.size() != n_bytes) {
      DLOG_ERROR("Unexpected size mismatch in ClientPrgOTExtension().");
      return false;
    }
    (*params->selection_bits_and_output_secret_)[i].s_b_.resize(n_bytes);
    for (size_t j = 0; j < n_bytes; ++j) {
      (*params->selection_bits_and_output_secret_)[i].s_b_[j] =
          server_secrets_i_b[j] ^ prg_z_i[j];
    }
  }

  if (params->is_debug_) {
    StopTimer(&ot_time);
    LOG_INFO("Client PRG: " + FormatTime(GetElapsedTime(ot_time) / 1000));
  }
  return true;
}

bool ServerIKNPOTExtension(ServerIKNPOTExtensionParams* params) {
  if (params->secrets_->empty()) {
    return true;
  }
  Timer ot_time;
  if (params->is_debug_) StartTimer(&ot_time);

  // Do Step 1 of IKNP: Server initializes random vector s \in {0, 1}^k;
  // 's' will be stored as the b_ field of each
  // params->black_box_ot_params_->selection_bits_and_output_secret_
  ClientOTParams* ot_params = params->black_box_ot_params_.get();
  vector<ClientSelectionBitAndSecret> selection_bits_and_output_secret;
  ot_params->selection_bits_and_output_secret_ =
      &selection_bits_and_output_secret;
  const uint64_t k_bytes = params->num_security_param_bytes_;
  ot_params->selection_bits_and_output_secret_->resize(k_bytes * CHAR_BIT);
  for (uint64_t i = 0; i < k_bytes; ++i) {
    const unsigned char random_byte_i = RandomByte();
    for (int j = 0; j < CHAR_BIT; ++j) {
      const bool random_bit_ij =
          random_byte_i & (unsigned char) (1 << (CHAR_BIT - 1 - j));
      (*ot_params->selection_bits_and_output_secret_)[i * CHAR_BIT + j] =
          ClientSelectionBitAndSecret(random_bit_ij);
    }
  }

  // Do Step 2 of IKNP: Utilize underlying OT^k_m protocol, so Server gets Q.
  // First, copy relevant fields of params to params->black_box_ot_params_.
  if (ot_params->connection_to_server_ == nullptr) {
    ot_params->connection_to_server_.reset(
        params->connection_to_client_.release());
  }
  if (ot_params->num_threads_ < 0) {
    ot_params->num_threads_ = params->num_threads_;
  }
  if (!ClientOT(ot_params)) {
    DLOG_ERROR("Failed ServerIKNPOTExtension(): Underlying OT^k_m "
               "protocol failed.");
    return false;
  }
  // Take back ownership of connection.
  if (params->connection_to_client_ == nullptr) {
    params->connection_to_client_.reset(
        ot_params->connection_to_server_.release());
  }

  // Do Step 3 of IKNP: Compute pairs {(y_j0, y_j1)}. The following buffer
  // will have outer-vector size m, and each inner vector j (for j \in [1..m]
  // will have size equal to the number of bytes in y_j0 + y_j1.
  vector<vector<unsigned char>> buffer;
  if (!ServerIKNPStepThree(
          params->num_threads_ > 0 ? params->num_threads_ : 1,
          params->random_oracle_,
          *params->secrets_,
          *ot_params->selection_bits_and_output_secret_,
          &buffer)) {
    DLOG_ERROR("Failed Step 3 of ServerIKNPOTExtension().");
    params->connection_to_client_->Reset();
    return false;
  }
  // Do Step 3 of IKNP: Send {(y_j0, y_j1)} to Client.
  if (!ServerIKNPStepThreeSend(
          params->is_black_box_,
          params->connection_to_client_.get(),
          params->secrets_->size(),
          (*params->secrets_)[0].s0_.size(),
          buffer)) {
    DLOG_ERROR("Failed Sending Step 3 of ServerIKNPOTExtension().");
    params->connection_to_client_->Reset();
    return false;
  }

  if (params->is_debug_) {
    StopTimer(&ot_time);
    LOG_INFO("Server IKNP: " + FormatTime(GetElapsedTime(ot_time) / 1000));
  }
  return true;
}

bool ClientIKNPOTExtension(ClientIKNPOTExtensionParams* params) {
  Timer ot_time;
  if (params->is_debug_) StartTimer(&ot_time);

  const size_t m = params->selection_bits_and_output_secret_->size();
  const size_t m_bytes = m / CHAR_BIT + (m % CHAR_BIT == 0 ? 0 : 1);
  const int remainder_bits = (int) (m % CHAR_BIT);

  // Do Step 1 of IKNP: Client initializes random matrix T \in M_{m, k}.
  // Actually, since this matrix represents the secrets that will be used
  // in the underlying OT^k_m protocol, it will be stored as k m-bit
  // secrets; where each of the k secrets are packed into m' = m / 8
  // bytes, and stored in params->black_box_ot_params_->secrets_.
  ServerOTParams* black_box_params = params->black_box_ot_params_.get();
  vector<ServerSecretPair> secrets;
  black_box_params->secrets_ = &secrets;
  const uint64_t k = params->num_security_param_bytes_ * CHAR_BIT;
  black_box_params->secrets_->resize(k, ServerSecretPair());
  for (size_t i = 0; i < k; ++i) {
    // Generate randomness needed for t^i = i^th column vector of T (m-bits,
    // packed into m_bytes bytes).
    vector<unsigned char> temp_random_bytes;
    RandomBytes(m_bytes, &temp_random_bytes);
    // Zero-out the leading bits of the first byte of temp_random_bytes,
    // if these are extra randomness (i.e. if m is not divisible by 8).
    if (m % CHAR_BIT != 0) {
      temp_random_bytes[0] =
          (unsigned char) (temp_random_bytes[0] & ((~((unsigned char) 0)) >> (CHAR_BIT - remainder_bits)));
    }
    ServerSecretPair& secret_pair = (*black_box_params->secrets_)[i];
    secret_pair.s0_.resize(m_bytes);
    secret_pair.s1_.resize(m_bytes);
    int index_w_in_secret = 0;
    for (size_t j = 0; j < m_bytes; ++j) {
      const unsigned char& jth_byte = temp_random_bytes[j];
      // Set the j^th byte of the i^th column of T as a random byte, and
      // store this byte as the j^th byte of the i^th secret s0.
      secret_pair.s0_[j] = jth_byte;
      // Compute the j^th byte of 'r \xor t^i', and store it in the
      // j^th byte of the i^th secret s1.
      secret_pair.s1_[j] = (unsigned char) 0;
      unsigned char& s1_value = secret_pair.s1_[j];
      const int bits_to_use =
          (j == 0 && remainder_bits > 0) ? remainder_bits : CHAR_BIT;
      for (int l = 0; l < bits_to_use; ++l) {
        const bool t_ijl =
            jth_byte & (unsigned char) (1 << (bits_to_use - 1 - l));
        const bool r_j =
            (*params->selection_bits_and_output_secret_)[index_w_in_secret].b_;
        if (t_ijl != r_j) {
          s1_value = (unsigned char) (s1_value + (1 << (bits_to_use - 1 - l)));
        }
        index_w_in_secret++;
      }
    }
  }

  // Do Step 2 of IKNP: Utilize underlying OT^k_m protocol, so Client sends
  // Q (columns of T and columns of T + r, chosen according to s) to Server.
  // First, copy relevant fields of params to params->black_box_ot_params_.
  if (black_box_params->connection_to_client_ == nullptr) {
    black_box_params->connection_to_client_.reset(
        params->connection_to_server_.release());
  }
  if (black_box_params->num_threads_ < 0) {
    black_box_params->num_threads_ = params->num_threads_;
  }
  if (!ServerOT(black_box_params)) {
    DLOG_ERROR("Failed ClientIKNPOTExtension(): Underlying OT^k_m "
               "protocol failed.");
    return false;
  }
  // Take back ownership of connection.
  if (params->connection_to_server_ == nullptr) {
    params->connection_to_server_.reset(
        black_box_params->connection_to_client_.release());
  }

  // Do Step 3 of IKNP: Receive pairs {(y_j0, y_j1)} from Server.
  vector<vector<unsigned char>> y_0, y_1;
  if (!ClientIKNPStepThreeReceive(
          params->is_black_box_,
          params->connection_to_server_.get(),
          &y_0,
          &y_1)) {
    DLOG_ERROR("Failed Step 3 of ClientIKNPOTExtension().");
    params->connection_to_server_->Reset();
    return false;
  }

  // Do Step 4 of IKNP: Compute z_j (= x_jb) from pairs {(y_j0, y_j1)} by
  // xor'ing the appropriate y_jb (based on selection bit b = r_j)
  // with H(j, T_j).
  if (!ClientIKNPStepFour(
          params->num_threads_ > 0 ? params->num_threads_ : 1,
          params->random_oracle_,
          y_0,
          y_1,
          *black_box_params->secrets_,
          params->selection_bits_and_output_secret_)) {
    DLOG_ERROR("Failed Step 4 of ClientIKNPOTExtension().");
    params->connection_to_server_->Reset();
    return false;
  }

  if (params->is_debug_) {
    StopTimer(&ot_time);
    LOG_INFO("Client IKNP: " + FormatTime(GetElapsedTime(ot_time) / 1000));
  }
  return true;
}

bool SetServerOTParams(
    const bool is_debug,
    const bool is_ot_subroutine,
    OTParamsSetup setup_params,
    ServerOTParams* params) {
  switch (setup_params.type_) {
    case OTProtocolCombo::PAILLIER:
      return SetServerPaillierOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_threads_,
          setup_params.paillier_n_file_,
          setup_params.paillier_g_file_,
          setup_params.connection_,
          setup_params.secrets_,
          (ServerPaillierOTParams*) params);
    case OTProtocolCombo::DIFFIE_HELLMAN:
      return SetServerDiffieHellmanOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.use_edwards_curve_,
          setup_params.diffie_hellman_exponent_,
          setup_params.connection_,
          setup_params.secrets_,
          (ServerDiffieHellmanOTParams*) params);
    case OTProtocolCombo::PRG_FROM_PAILLIER:
      return SetServerPrgFromPaillierOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.prg_domain_bytes_,
          setup_params.paillier_n_file_,
          setup_params.paillier_g_file_,
          setup_params.connection_,
          setup_params.secrets_,
          (ServerPrgOTExtensionParams*) params);
    case OTProtocolCombo::PRG_FROM_DIFFIE_HELLMAN:
      return SetServerPrgFromDiffieHellmanOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.prg_domain_bytes_,
          setup_params.use_edwards_curve_,
          setup_params.diffie_hellman_exponent_,
          setup_params.connection_,
          setup_params.secrets_,
          (ServerPrgOTExtensionParams*) params);
    case OTProtocolCombo::IKNP_FROM_PAILLIER:
      return SetServerIKNPFromPaillierOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.iknp_ro_security_param_bytes_,
          setup_params.paillier_n_file_,
          setup_params.paillier_g_file_,
          setup_params.paillier_lambda_file_,
          setup_params.paillier_mu_file_,
          setup_params.connection_,
          setup_params.secrets_,
          (ServerIKNPOTExtensionParams*) params);
    case OTProtocolCombo::IKNP_FROM_DIFFIE_HELLMAN:
      return SetServerIKNPFromDiffieHellmanOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.iknp_ro_security_param_bytes_,
          setup_params.use_edwards_curve_,
          setup_params.diffie_hellman_exponent_,
          setup_params.connection_,
          setup_params.secrets_,
          (ServerIKNPOTExtensionParams*) params);
    case OTProtocolCombo::IKNP_FROM_PRG_FROM_PAILLIER:
      return SetServerIKNPFromPrgFromPaillierOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.prg_domain_bytes_,
          setup_params.iknp_ro_security_param_bytes_,
          setup_params.paillier_n_file_,
          setup_params.paillier_g_file_,
          setup_params.paillier_lambda_file_,
          setup_params.paillier_mu_file_,
          setup_params.connection_,
          setup_params.secrets_,
          (ServerIKNPOTExtensionParams*) params);
    case OTProtocolCombo::IKNP_FROM_PRG_FROM_DIFFIE_HELLMAN:
      return SetServerIKNPFromPrgFromDiffieHellmanOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.prg_domain_bytes_,
          setup_params.iknp_ro_security_param_bytes_,
          setup_params.use_edwards_curve_,
          setup_params.diffie_hellman_exponent_,
          setup_params.connection_,
          setup_params.secrets_,
          (ServerIKNPOTExtensionParams*) params);
    default: {
      DLOG_ERROR(
          "Failure in SetServerOTParams: Unsupported OT protocol "
          "combination specified: " +
          Itoa(static_cast<int>(setup_params.type_)));
      return false;
    }
  }

  return true;
}

bool SetClientOTParams(
    const bool is_debug,
    const bool is_ot_subroutine,
    OTParamsSetup setup_params,
    ClientOTParams* params) {
  switch (setup_params.type_) {
    case OTProtocolCombo::PAILLIER:
      return SetClientPaillierOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.paillier_n_file_,
          setup_params.paillier_g_file_,
          setup_params.paillier_lambda_file_,
          setup_params.paillier_mu_file_,
          setup_params.connection_,
          setup_params.selection_bits_,
          (ClientPaillierOTParams*) params);
    case OTProtocolCombo::DIFFIE_HELLMAN:
      return SetClientDiffieHellmanOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.use_edwards_curve_,
          setup_params.diffie_hellman_exponent_,
          setup_params.connection_,
          setup_params.selection_bits_,
          (ClientDiffieHellmanOTParams*) params);
    case OTProtocolCombo::PRG_FROM_PAILLIER:
      return SetClientPrgFromPaillierOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.prg_domain_bytes_,
          setup_params.paillier_n_file_,
          setup_params.paillier_g_file_,
          setup_params.paillier_lambda_file_,
          setup_params.paillier_mu_file_,
          setup_params.connection_,
          setup_params.selection_bits_,
          (ClientPrgOTExtensionParams*) params);
    case OTProtocolCombo::PRG_FROM_DIFFIE_HELLMAN:
      return SetClientPrgFromDiffieHellmanOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.prg_domain_bytes_,
          setup_params.use_edwards_curve_,
          setup_params.diffie_hellman_exponent_,
          setup_params.connection_,
          setup_params.selection_bits_,
          (ClientPrgOTExtensionParams*) params);
    case OTProtocolCombo::IKNP_FROM_PAILLIER:
      return SetClientIKNPFromPaillierOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.iknp_ro_security_param_bytes_,
          setup_params.paillier_n_file_,
          setup_params.paillier_g_file_,
          setup_params.connection_,
          setup_params.selection_bits_,
          (ClientIKNPOTExtensionParams*) params);
    case OTProtocolCombo::IKNP_FROM_DIFFIE_HELLMAN:
      return SetClientIKNPFromDiffieHellmanOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.iknp_ro_security_param_bytes_,
          setup_params.use_edwards_curve_,
          setup_params.diffie_hellman_exponent_,
          setup_params.connection_,
          setup_params.selection_bits_,
          (ClientIKNPOTExtensionParams*) params);
    case OTProtocolCombo::IKNP_FROM_PRG_FROM_PAILLIER:
      return SetClientIKNPFromPrgFromPaillierOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.prg_domain_bytes_,
          setup_params.iknp_ro_security_param_bytes_,
          setup_params.paillier_n_file_,
          setup_params.paillier_g_file_,
          setup_params.connection_,
          setup_params.selection_bits_,
          (ClientIKNPOTExtensionParams*) params);
    case OTProtocolCombo::IKNP_FROM_PRG_FROM_DIFFIE_HELLMAN:
      return SetClientIKNPFromPrgFromDiffieHellmanOTParams(
          is_debug,
          is_ot_subroutine,
          setup_params.num_secrets_,
          setup_params.num_bytes_per_secret_,
          setup_params.num_threads_,
          setup_params.prg_domain_bytes_,
          setup_params.iknp_ro_security_param_bytes_,
          setup_params.use_edwards_curve_,
          setup_params.diffie_hellman_exponent_,
          setup_params.connection_,
          setup_params.selection_bits_,
          (ClientIKNPOTExtensionParams*) params);
    default: {
      DLOG_ERROR(
          "Failure in SetClientOTParams: Unsupported OT protocol "
          "combination specified: " +
          Itoa(static_cast<int>(setup_params.type_)));
      return false;
    }
  }

  return true;
}

void SetServerOtNumThreads(const int num_threads, ServerOTParams* params) {
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
}

void SetClientOtNumThreads(const int num_threads, ClientOTParams* params) {
  // Default is to utilize all cores available on the machine (minus one
  // for the main thread).
  if (num_threads <= 0) {
    const int num_cores = GetNumCores();
    params->num_threads_ = num_cores > 2 ? num_cores - 1 : -1;
  } else {
    params->num_threads_ = num_threads;
  }
}

bool ServerOT(ServerOTParams* params) {
  const OTProtocol protocol_to_use = params->protocol_;
  if (protocol_to_use == OTProtocol::NONE) {
    DLOG_ERROR("Failure in ServerOT: No OT protocol specified.");
    return false;
  }

  switch (protocol_to_use) {
    case OTProtocol::PAILLIER:
      return ServerPaillierOT((ServerPaillierOTParams*) params);
    case OTProtocol::DIFFIE_HELLMAN:
      return ServerDiffieHellmanOT((ServerDiffieHellmanOTParams*) params);
    case OTProtocol::PRG_EXTENSION:
      return ServerPrgOTExtension((ServerPrgOTExtensionParams*) params);
    case OTProtocol::IKNP_EXTENSION:
      return ServerIKNPOTExtension((ServerIKNPOTExtensionParams*) params);
    default: {
      DLOG_ERROR(
          "Failure in ServerOT: Unsupported OT protocol specified: " +
          Itoa(static_cast<int>(protocol_to_use)));
      return false;
    }
  }

  return true;
}

bool ClientOT(ClientOTParams* params) {
  const OTProtocol protocol_to_use = params->protocol_;
  if (protocol_to_use == OTProtocol::NONE) {
    DLOG_ERROR("Failure in ClientOT: No OT protocol specified.");
    return false;
  }

  switch (protocol_to_use) {
    case OTProtocol::PAILLIER:
      return ClientPaillierOT((ClientPaillierOTParams*) params);
    case OTProtocol::DIFFIE_HELLMAN:
      return ClientDiffieHellmanOT((ClientDiffieHellmanOTParams*) params);
    case OTProtocol::PRG_EXTENSION:
      return ClientPrgOTExtension((ClientPrgOTExtensionParams*) params);
    case OTProtocol::IKNP_EXTENSION:
      return ClientIKNPOTExtension((ClientIKNPOTExtensionParams*) params);
    default: {
      DLOG_ERROR(
          "Failure in ClientOT: Unsupported OT protocol specified: " +
          Itoa(static_cast<int>(protocol_to_use)));
      return false;
    }
  }

  return true;
}

}  // namespace crypto
