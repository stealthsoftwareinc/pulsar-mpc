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

#include "large_int.h"

#include "Crypto/RandomNumberGeneration/random_utils.h"  // For RandomBytes().
#include "GenericUtils/mutex.h"  // For Mutex.
#include "global_utils.h"

#include <cmath>
#include <cstring>  // For memset().
#include <vector>

using namespace string_utils;
using namespace std;

namespace math_utils {

// TODO(PHB): Implement all functions for mpir, and any other underlying base class.

namespace {

// The tommath library uses the Miller-Rabin algorithm to find primes.
// This algorithm proceeds in 'rounds'; this variable limits the number rounds.
static const unsigned int kNumRoundsToGeneratePrime = 20;

// The tommath library uses the Miller-Rabin algorithm to find the next prime
// (from a given starting point). This algorithm proceeds in 'rounds'; this
// variable limits the number rounds.
// NOTE: We may want to set this value to be higher than
// kNumRoundsToGeneratePrime above because in the code below, the former will
// be used to generate a first guess at a prime (which will actually then be
// used as a baseline), and then the code will loop  through calling 'next prime'
// until a prime is found; so it is more important that the 'next prime'
// algorithm actually finds a prime.
static const unsigned int kNumRoundsToGenerateNextPrime = 20;

// The tommath and GPN libraries uses Miller-Rabin algorithm to test whether a given
// number is prime. This algorithm proceeds for a certain number of rounds,
// and then returns whether it thinks the number is prime. The more rounds
// used, the greater probability Miller-Rabin will detect a composite number.
// Probability of classifying a composite as prime ~ 2^-kNumRoundsToTestPrime.
static const unsigned int kNumRoundsToTestPrime = 20;

// GMP requires a random state variable. Create a single (global) one, and
// initialize it once.
#ifdef LARGE_INT_GMP
static gmp_randstate_t kGmpRandomState;
#endif
#ifdef LARGE_INT_MP_INT
// The callback to be used by tommath's mp_prime_random_ex() function. It
// generates 'size' random bytes, and stores them in 'buffer'.
int RandomCallback(unsigned char* buffer, int size, void* unused) {
  crypto::random_number::RandomBytes(size, buffer);
  return size;
}
#endif

}  // namespace

LargeInt::LargeInt(const LargeInt& other) {
  Init();
#ifdef LARGE_INT_MP_INT
  mp_copy(((MpIntType*) other.x_)->value_, ((MpIntType*) x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_set(((GmpType*) x_)->value_, ((GmpType*) other.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt::LargeInt(const LargeIntType& other) {
  Init();
#ifdef LARGE_INT_MP_INT
  ((MpIntType*) x_)->CopyFrom((const MpIntType&) other);
#endif
#ifdef LARGE_INT_GMP
  ((GmpType*) x_)->CopyFrom((const GmpType&) other);
#endif
#ifdef LARGE_INT_MPIR
  ((MpirType*) x_)->CopyFrom((const MpirType&) other);
#endif
}

LargeInt::LargeInt(const int32_t other) {
  Init();
#ifdef LARGE_INT_MP_INT
  mp_set_long(((MpIntType*) x_)->value_, std::abs(other));
  if (other < 0) {
    mp_neg(((MpIntType*) x_)->value_, ((MpIntType*) x_)->value_);
  }
#endif
#ifdef LARGE_INT_GMP
  mpz_set_si(((GmpType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt::LargeInt(const uint32_t other) {
  Init();
#ifdef LARGE_INT_MP_INT
  mp_set_long(((MpIntType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_GMP
  mpz_set_ui(((GmpType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt::LargeInt(const int64_t& other) {
  Init();
#ifdef LARGE_INT_MP_INT
  mp_set_long_long(((MpIntType*) x_)->value_, std::abs(other));
  if (other < 0) {
    mp_neg(((MpIntType*) x_)->value_, ((MpIntType*) x_)->value_);
  }
#endif
#ifdef LARGE_INT_GMP
  // GMP has a convenient method for intializing via [u]int32_t
  // (namely, mpz_set_[u | s]i()), but not via [u]int64_t.
  // Instead, we cast 'other' as string, and initialize from that.
  mpz_set_str(((GmpType*) x_)->value_, Itoa(other).c_str(), 10);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt::LargeInt(const uint64_t& other) {
  Init();
#ifdef LARGE_INT_MP_INT
  mp_set_long_long(((MpIntType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_GMP
  // GMP has a convenient method for intializing via [u]int32_t
  // (namely, mpz_set_[u | s]i()), but not via [u]int64_t.
  // Instead, we cast 'other' as string, and initialize from that.
  mpz_set_str(((GmpType*) x_)->value_, Itoa(other).c_str(), 10);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt::LargeInt(LargeInt&& other) noexcept {
#ifdef LARGE_INT_MP_INT
  x_ = (MpIntType*) other.x_;
#endif
#ifdef LARGE_INT_GMP
  x_ = (GmpType*) other.x_;
#endif
#ifdef LARGE_INT_MPIR
  x_ = (MpirType*) other.x_;
#endif
  // No need to call other.Clear(): The move constructor 'steals' the
  // allocated resources of 'other', so we need not call Init()
  // for 'this', nor do we need to call Clear() for 'other'.
  other.x_ = nullptr;
}

LargeInt& LargeInt::operator=(const LargeInt& other) {
  LargeInt temp(other);  // Re-use copy-constructor.
  *this = move(temp);  // Re-use move-assignment.
  return *this;
}

LargeInt& LargeInt::operator=(const int32_t other) {
  LargeInt temp(other);  // Re-use copy-constructor.
  *this = move(temp);  // Re-use move-assignment.
  return *this;
}

LargeInt& LargeInt::operator=(const uint32_t other) {
  LargeInt temp(other);  // Re-use copy-constructor.
  *this = move(temp);  // Re-use move-assignment.
  return *this;
}

LargeInt& LargeInt::operator=(const int64_t& other) {
  LargeInt temp(other);  // Re-use copy-constructor.
  *this = move(temp);  // Re-use move-assignment.
  return *this;
}

LargeInt& LargeInt::operator=(const uint64_t& other) {
  LargeInt temp(other);  // Re-use copy-constructor.
  *this = move(temp);  // Re-use move-assignment.
  return *this;
}

LargeInt& LargeInt::operator=(LargeInt&& other) noexcept {
  if (this != &other) {
    Clear();
#ifdef LARGE_INT_MP_INT
    x_ = (MpIntType*) other.x_;
#endif
#ifdef LARGE_INT_GMP
    x_ = (GmpType*) other.x_;
#endif
#ifdef LARGE_INT_MPIR
    x_ = (MpirType*) other.x_;
#endif
    other.x_ = nullptr;
  }
  return *this;
}

bool LargeInt::random_seed_is_set_ = false;
std::unique_ptr<Mutex> LargeInt::random_seed_mutex_ =
    std::unique_ptr<Mutex>(CreateNewMutex());

void LargeInt::Init() {
#ifdef LARGE_INT_MP_INT
  x_ = new MpIntType();
#endif
#ifdef LARGE_INT_GMP
  x_ = new GmpType();
#endif
#ifdef LARGE_INT_MPIR
  x_ = new MpirType();
#endif
}

void LargeInt::Clear() {
  if (x_ == nullptr) return;
#ifdef LARGE_INT_MP_INT
  delete ((MpIntType*) x_);
#endif
#ifdef LARGE_INT_GMP
  delete ((GmpType*) x_);
#endif
#ifdef LARGE_INT_MPIR
  delete ((MpirType*) x_);
#endif
}

bool LargeInt::IsZero() const {
#ifdef LARGE_INT_MP_INT
  return mp_iszero(((MpIntType*) x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  return mpz_size(((GmpType*) x_)->value_) == 0;
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt LargeInt::Zero() {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  MpIntType* mp_int_holder = (MpIntType*) to_return.x_;
  mp_zero(mp_int_holder->value_);
#endif
#ifdef LARGE_INT_GMP
  // Nothing to do (default constructor sets value_ to '0').
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

LargeInt LargeInt::One() {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  MpIntType* mp_int_holder = (MpIntType*) to_return.x_;
  mp_set_int(mp_int_holder->value_, 1);
#endif
#ifdef LARGE_INT_GMP
  GmpType* as_gmp = (GmpType*) to_return.x_;
  mpz_set_ui(as_gmp->value_, 1);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

bool LargeInt::operator==(const LargeInt& other) const {
#ifdef LARGE_INT_MP_INT
  return (
      MP_EQ ==
      mp_cmp(((MpIntType*) x_)->value_, ((MpIntType*) other.x_)->value_));
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) other.x_)->value_) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator==(const int32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_si(((GmpType*) x_)->value_, other) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator==(const uint32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_ui(((GmpType*) x_)->value_, other) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator==(const int64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) temp.x_)->value_) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator==(const uint64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) temp.x_)->value_) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator==(const int32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_si(((GmpType*) two.x_)->value_, one) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator==(const uint32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_ui(((GmpType*) two.x_)->value_, one) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator==(const int64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(one);
  return (
      mpz_cmp(((GmpType*) two.x_)->value_, ((GmpType*) temp.x_)->value_) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator==(const uint64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(one);
  return (
      mpz_cmp(((GmpType*) two.x_)->value_, ((GmpType*) temp.x_)->value_) == 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator!=(const LargeInt& other) const {
#ifdef LARGE_INT_MP_INT
  return MP_EQ !=
      mp_cmp(((MpIntType*) x_)->value_, ((MpIntType*) other.x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  return !(*this == other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this == other);
#endif
}

bool LargeInt::operator!=(const int32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result != MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return !(*this == other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this == other);
#endif
}

bool LargeInt::operator!=(const uint32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result != MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return !(*this == other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this == other);
#endif
}

bool LargeInt::operator!=(const int64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result != MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return !(*this == other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this == other);
#endif
}

bool LargeInt::operator!=(const uint64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result != MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return !(*this == other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this == other);
#endif
}

bool operator!=(const int32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result != MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return !(one == two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one == two);
#endif
}

bool operator!=(const uint32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result != MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return !(one == two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one == two);
#endif
}

bool operator!=(const int64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result != MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return !(one == two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one == two);
#endif
}

bool operator!=(const uint64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result != MP_EQ;
#endif
#ifdef LARGE_INT_GMP
  return !(one == two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one == two);
#endif
}

bool LargeInt::operator>(const LargeInt& other) const {
#ifdef LARGE_INT_MP_INT
  return (
      MP_GT ==
      mp_cmp(((MpIntType*) x_)->value_, ((MpIntType*) other.x_)->value_));
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) other.x_)->value_) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator>(const int32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_GT;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_si(((GmpType*) x_)->value_, other) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator>(const uint32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_GT;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_ui(((GmpType*) x_)->value_, other) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator>(const int64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_GT;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) temp.x_)->value_) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator>(const uint64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_GT;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) temp.x_)->value_) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator>(const int32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_LT;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_si(((GmpType*) two.x_)->value_, one) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator>(const uint32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_LT;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_ui(((GmpType*) two.x_)->value_, one) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator>(const int64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_LT;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(one);
  return (
      mpz_cmp(((GmpType*) two.x_)->value_, ((GmpType*) temp.x_)->value_) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator>(const uint64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_LT;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(one);
  return (
      mpz_cmp(((GmpType*) two.x_)->value_, ((GmpType*) temp.x_)->value_) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator<(const LargeInt& other) const {
#ifdef LARGE_INT_MP_INT
  return (
      MP_LT ==
      mp_cmp(((MpIntType*) x_)->value_, ((MpIntType*) other.x_)->value_));
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) other.x_)->value_) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator<(const int32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_LT;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_si(((GmpType*) x_)->value_, other) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator<(const uint32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_LT;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_ui(((GmpType*) x_)->value_, other) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator<(const int64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_LT;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) temp.x_)->value_) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator<(const uint64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_LT;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  return (mpz_cmp(((GmpType*) x_)->value_, ((GmpType*) temp.x_)->value_) < 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator<(const int32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_GT;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_si(((GmpType*) two.x_)->value_, one) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator<(const uint32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_GT;
#endif
#ifdef LARGE_INT_GMP
  return (mpz_cmp_ui(((GmpType*) two.x_)->value_, one) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator<(const int64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_GT;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(one);
  return (
      mpz_cmp(((GmpType*) two.x_)->value_, ((GmpType*) temp.x_)->value_) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool operator<(const uint64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return result == MP_GT;
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(one);
  return (
      mpz_cmp(((GmpType*) two.x_)->value_, ((GmpType*) temp.x_)->value_) > 0);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

bool LargeInt::operator>=(const LargeInt& other) const {
#ifdef LARGE_INT_MP_INT
  const int result =
      mp_cmp(((MpIntType*) x_)->value_, ((MpIntType*) other.x_)->value_);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this < other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this < other);
#endif
}

bool LargeInt::operator>=(const int32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this < other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this < other);
#endif
}

bool LargeInt::operator>=(const uint32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this < other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this < other);
#endif
}

bool LargeInt::operator>=(const int64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this < other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this < other);
#endif
}

bool LargeInt::operator>=(const uint64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this < other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this < other);
#endif
}

bool operator>=(const int32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(one < two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one < two);
#endif
}

bool operator>=(const uint32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(one < two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one < two);
#endif
}

bool operator>=(const int64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(one < two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one < two);
#endif
}

bool operator>=(const uint64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(one < two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one < two);
#endif
}

bool LargeInt::operator<=(const LargeInt& other) const {
#ifdef LARGE_INT_MP_INT
  const int result =
      mp_cmp(((MpIntType*) x_)->value_, ((MpIntType*) other.x_)->value_);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this > other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this > other);
#endif
}

bool LargeInt::operator<=(const int32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this > other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this > other);
#endif
}

bool LargeInt::operator<=(const uint32_t other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this > other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this > other);
#endif
}

bool LargeInt::operator<=(const int64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this > other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this > other);
#endif
}

bool LargeInt::operator<=(const uint64_t& other) const {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  int result = mp_cmp(((MpIntType*) x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_LT);
#endif
#ifdef LARGE_INT_GMP
  return !(*this > other);
#endif
#ifdef LARGE_INT_MPIR
  return !(*this > other);
#endif
}

bool operator<=(const int32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(one > two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one > two);
#endif
}

bool operator<=(const uint32_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(one > two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one > two);
#endif
}

bool operator<=(const int64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(one));
  if (one < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(one > two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one > two);
#endif
}

bool operator<=(const uint64_t one, const LargeInt& two) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, one);
  int result = mp_cmp(((MpIntType*) two.x_)->value_, &temp);
  mp_clear(&temp);
  return (result == MP_EQ || result == MP_GT);
#endif
#ifdef LARGE_INT_GMP
  return !(one > two);
#endif
#ifdef LARGE_INT_MPIR
  return !(one > two);
#endif
}

LargeInt& LargeInt::operator+=(const LargeInt& other) {
#ifdef LARGE_INT_MP_INT
  mp_add(
      ((MpIntType*) x_)->value_,
      ((MpIntType*) other.x_)->value_,
      ((MpIntType*) x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_add(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) other.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator+=(const int32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_add(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_add(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator+=(const uint32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  mp_add(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  mpz_add_ui(((GmpType*) x_)->value_, ((GmpType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator+=(const int64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_add(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_add(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator+=(const uint64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  mp_add(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_add(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator-=(const LargeInt& other) {
#ifdef LARGE_INT_MP_INT
  mp_sub(
      ((MpIntType*) x_)->value_,
      ((MpIntType*) other.x_)->value_,
      ((MpIntType*) x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_sub(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) other.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator-=(const int32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_sub(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_sub(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator-=(const uint32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  mp_sub(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  mpz_sub_ui(((GmpType*) x_)->value_, ((GmpType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator-=(const int64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_sub(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_sub(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator-=(const uint64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  mp_sub(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_sub(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator*=(const LargeInt& other) {
#ifdef LARGE_INT_MP_INT
  mp_mul(
      ((MpIntType*) x_)->value_,
      ((MpIntType*) other.x_)->value_,
      ((MpIntType*) x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_mul(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) other.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator*=(const int32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_mul(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  mpz_mul_si(((GmpType*) x_)->value_, ((GmpType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator*=(const uint32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  mp_mul(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  mpz_mul_ui(((GmpType*) x_)->value_, ((GmpType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator*=(const int64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_mul(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_mul(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator*=(const uint64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  mp_mul(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_mul(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator/=(const LargeInt& other) {
#ifdef LARGE_INT_MP_INT
  mp_int remainder;
  mp_init(&remainder);
  mp_div(
      ((MpIntType*) x_)->value_,
      ((MpIntType*) other.x_)->value_,
      ((MpIntType*) x_)->value_,
      &remainder);
  mp_clear(&remainder);
#endif
#ifdef LARGE_INT_GMP
  mpz_tdiv_q(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) other.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator/=(const int32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int remainder;
  mp_init(&remainder);
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_div(
      ((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_, &remainder);
  mp_clear(&temp);
  mp_clear(&remainder);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_tdiv_q(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator/=(const uint32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int remainder;
  mp_init(&remainder);
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  mp_div(
      ((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_, &remainder);
  mp_clear(&temp);
  mp_clear(&remainder);
#endif
#ifdef LARGE_INT_GMP
  mpz_tdiv_q_ui(((GmpType*) x_)->value_, ((GmpType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator/=(const int64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int remainder;
  mp_init(&remainder);
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_div(
      ((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_, &remainder);
  mp_clear(&temp);
  mp_clear(&remainder);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_tdiv_q(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator/=(const uint64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int remainder;
  mp_init(&remainder);
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  mp_div(
      ((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_, &remainder);
  mp_clear(&temp);
  mp_clear(&remainder);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_tdiv_q(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator%=(const LargeInt& other) {
#ifdef LARGE_INT_MP_INT
  mp_mod(
      ((MpIntType*) x_)->value_,
      ((MpIntType*) other.x_)->value_,
      ((MpIntType*) x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_tdiv_r(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator%=(const int32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_mod(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_tdiv_r(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator%=(const uint32_t other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long(&temp, other);
  mp_mod(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  mpz_tdiv_r_ui(((GmpType*) x_)->value_, ((GmpType*) x_)->value_, other);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator%=(const int64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, std::abs(other));
  if (other < 0) {
    mp_int neg_one;
    mp_init(&neg_one);
    mp_set_int(&neg_one, 1);
    mp_neg(&neg_one, &neg_one);
    mp_mul(&temp, &neg_one, &temp);
    mp_clear(&neg_one);
  }
  mp_mod(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_tdiv_r(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt& LargeInt::operator%=(const uint64_t& other) {
#ifdef LARGE_INT_MP_INT
  mp_int temp;
  mp_init(&temp);
  mp_set_long_long(&temp, other);
  mp_mod(((MpIntType*) x_)->value_, &temp, ((MpIntType*) x_)->value_);
  mp_clear(&temp);
#endif
#ifdef LARGE_INT_GMP
  LargeInt temp(other);
  mpz_tdiv_r(
      ((GmpType*) x_)->value_,
      ((GmpType*) x_)->value_,
      ((GmpType*) temp.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return *this;
}

LargeInt operator+(const LargeInt& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator+(const LargeInt& one, const int32_t two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator+(const LargeInt& one, const uint32_t two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator+(const LargeInt& one, const int64_t& two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator+(const LargeInt& one, const uint64_t& two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator+(const int32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator+(const uint32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator+(const int64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator+(const uint64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator-(const LargeInt& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator-(const LargeInt& one, const int32_t two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator-(const LargeInt& one, const uint32_t two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator-(const LargeInt& one, const int64_t& two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator-(const LargeInt& one, const uint64_t& two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator-(const int32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator-(const uint32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator-(const int64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator-(const uint64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return -= two;
  return to_return;
}

LargeInt operator*(const LargeInt& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return *= two;
  return to_return;
}

LargeInt operator*(const LargeInt& one, const int32_t two) {
  LargeInt to_return(one);
  to_return *= two;
  return to_return;
}

LargeInt operator*(const LargeInt& one, const uint32_t two) {
  LargeInt to_return(one);
  to_return *= two;
  return to_return;
}

LargeInt operator*(const LargeInt& one, const int64_t& two) {
  LargeInt to_return(one);
  to_return += two;
  return to_return;
}

LargeInt operator*(const LargeInt& one, const uint64_t& two) {
  LargeInt to_return(one);
  to_return *= two;
  return to_return;
}

LargeInt operator*(const int32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return *= two;
  return to_return;
}

LargeInt operator*(const uint32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return *= two;
  return to_return;
}

LargeInt operator*(const int64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return *= two;
  return to_return;
}

LargeInt operator*(const uint64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return *= two;
  return to_return;
}

LargeInt operator/(const LargeInt& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator/(const LargeInt& one, const int32_t two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator/(const LargeInt& one, const uint32_t two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator/(const LargeInt& one, const int64_t& two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator/(const LargeInt& one, const uint64_t& two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator/(const int32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator/(const uint32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator/(const int64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator/(const uint64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return /= two;
  return to_return;
}

LargeInt operator%(const LargeInt& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator%(const LargeInt& one, const int32_t two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator%(const LargeInt& one, const uint32_t two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator%(const LargeInt& one, const int64_t& two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator%(const LargeInt& one, const uint64_t& two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator%(const int32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator%(const uint32_t one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator%(const int64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator%(const uint64_t& one, const LargeInt& two) {
  LargeInt to_return(one);
  to_return %= two;
  return to_return;
}

LargeInt operator-(const LargeInt& input) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  mp_neg(((MpIntType*) input.x_)->value_, ((MpIntType*) to_return.x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_neg(((GmpType*) to_return.x_)->value_, ((GmpType*) input.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

LargeInt abs(const LargeInt& input) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  mp_abs(((MpIntType*) input.x_)->value_, ((MpIntType*) to_return.x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_abs(((GmpType*) to_return.x_)->value_, ((GmpType*) input.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

LargeInt lcm(const LargeInt& one, const LargeInt& two) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  mp_lcm(
      ((MpIntType*) one.x_)->value_,
      ((MpIntType*) two.x_)->value_,
      ((MpIntType*) to_return.x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_lcm(
      ((GmpType*) to_return.x_)->value_,
      ((GmpType*) one.x_)->value_,
      ((GmpType*) two.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

LargeInt gcd(const LargeInt& one, const LargeInt& two) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  mp_gcd(
      ((MpIntType*) one.x_)->value_,
      ((MpIntType*) two.x_)->value_,
      ((MpIntType*) to_return.x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_gcd(
      ((GmpType*) to_return.x_)->value_,
      ((GmpType*) one.x_)->value_,
      ((GmpType*) two.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

LargeInt pow(const uint32_t& base, const uint32_t& exp) {
  return pow(LargeInt(base), exp);
}

LargeInt pow(const LargeInt& base, const uint32_t& exp) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  if (sizeof(mp_digit) != 4 && sizeof(mp_digit) != 8 && sizeof(mp_digit) != 16) {
    LOG_FATAL(
        "Unable to do pow(" + base.x_->Print() + ", " + Itoa(exp) +
        "): Unexpected mp_digit size: " + Itoa(sizeof(mp_digit)));
  }
  mp_digit exp_as_digit = (mp_digit) exp;
  mp_expt_d(
      ((MpIntType*) base.x_)->value_,
      exp_as_digit,
      ((MpIntType*) to_return.x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  mpz_pow_ui(
      ((GmpType*) to_return.x_)->value_, ((GmpType*) base.x_)->value_, exp);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

LargeInt pow(const LargeInt& base, const uint64_t& exp) {
#ifdef LARGE_INT_MP_INT
  LargeInt to_return;
  if (sizeof(mp_digit) != 4 && sizeof(mp_digit) != 8 && sizeof(mp_digit) != 16) {
    LOG_FATAL(
        "Unable to do pow(" + base.x_->Print() + ", " + Itoa(exp) +
        "): Unexpected mp_digit size: " + Itoa(sizeof(mp_digit)));
  } else if (sizeof(mp_digit) == 4 && exp > numeric_limits<uint32_t>::max()) {
    LOG_FATAL(
        "Unable to do pow(" + base.x_->Print() + ", " + Itoa(exp) +
        "): exp too big (can be at most 2^32 - 1)");
  }
  mp_digit exp_as_digit = (mp_digit) exp;
  mp_expt_d(
      ((MpIntType*) base.x_)->value_,
      exp_as_digit,
      ((MpIntType*) to_return.x_)->value_);
  return to_return;
#endif
#ifdef LARGE_INT_GMP
  // Gmp does not allow exponents to be more than 32-bits. Make
  // sure this is the case.
  if (exp > std::numeric_limits<uint32_t>::max())
    LOG_FATAL("Exponent too large");
  return pow(base, (uint32_t) exp);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt pow(const LargeInt& base, const LargeInt& exp) {
#ifdef LARGE_INT_MP_INT
  // Make sure exp can be converted to an appropriately small number.
  int result = 0;
  if (sizeof(unsigned long) < sizeof(uint32_t) ||
      sizeof(unsigned long long) < sizeof(uint64_t)) {
    LOG_FATAL(
        "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
        "): Unexpected size of unsigned long: " + Itoa(sizeof(unsigned long)) +
        "or unsigned long long: " + Itoa(sizeof(unsigned long long)));
  } else if (sizeof(mp_digit) <= 32) {
    mp_int temp;
    mp_init(&temp);
    mp_set_long(&temp, (unsigned long) numeric_limits<uint32_t>::max());
    if (MP_GT == mp_cmp(((MpIntType*) exp.x_)->value_, &temp)) {
      mp_clear(&temp);
      LOG_FATAL(
          "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
          "): exp too big.");
    }
    mp_clear(&temp);
  } else if (sizeof(mp_digit) <= 64) {
    mp_int temp;
    mp_init(&temp);
    mp_set_long_long(
        &temp, (unsigned long long) numeric_limits<uint64_t>::max());
    if (MP_GT == mp_cmp(((MpIntType*) exp.x_)->value_, &temp)) {
      mp_clear(&temp);
      LOG_FATAL(
          "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
          "): exp too big.");
    }
    mp_clear(&temp);
  } else {
    LOG_FATAL(
        "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
        "): Unexpected mp_digit size: " + Itoa(sizeof(mp_digit)));
  }

  // Libtommath doesn't have a generic pow() function; it only
  // let's you do it for exponent an "mp_digit", which is an
  // 8-bit unsigned int (so up to 255).
  if (sizeof(mp_digit) < sizeof(uint8_t)) {
    LOG_FATAL(
        "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
        "): Unexpected mp_digit size: " + Itoa(sizeof(mp_digit)));
  } else if (sizeof(mp_digit) == sizeof(uint8_t)) {
    const unsigned long exp_value = mp_get_int(((MpIntType*) exp.x_)->value_);
    if (exp_value > 255) {
      LOG_FATAL(
          "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
          "): exp too big (can be at most 255 (uint8_t)).");
    }
    return pow(base, (uint32_t) exp_value);
  } else if (sizeof(mp_digit) == sizeof(uint16_t)) {
    const unsigned long exp_value = mp_get_int(((MpIntType*) exp.x_)->value_);
    if (exp_value > 65535) {
      LOG_FATAL(
          "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
          "): exp too big (can be at most 65535 (uint16_t)).");
    }
    return pow(base, (uint32_t) exp_value);
  } else if (sizeof(mp_digit) == sizeof(uint32_t)) {
    const unsigned long exp_value = mp_get_long(((MpIntType*) exp.x_)->value_);
    if (exp_value > 4294967295) {
      LOG_FATAL(
          "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
          "): exp too big (can be at most 4294967295 (uint32_t)).");
    }
    return pow(base, (uint32_t) exp_value);
  } else if (sizeof(mp_digit) == sizeof(uint64_t)) {
    const unsigned long long exp_value =
        mp_get_long_long(((MpIntType*) exp.x_)->value_);
    if (exp_value >= std::pow(2, 64)) {
      LOG_FATAL(
          "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
          "): exp too big (can be at most 2^64 - 1 (uint64_t)).");
    }
    return pow(base, exp_value);
  } else {
    LOG_FATAL(
        "Unable to do pow(" + base.x_->Print() + ", " + exp.x_->Print() +
        "): Unexpected mp_digit size: " + Itoa(sizeof(mp_digit)));
  }
#endif
#ifdef LARGE_INT_GMP
  // Gmp does not allow exponents to be more than 32-bits. Make
  // sure this is the case.
  // NOTE: Could replace comparison against ULONG_MAX below with GMP
  // build-in function 'mpz_fits_ulong_p().
  if (exp > std::numeric_limits<uint32_t>::max())
    LOG_FATAL("Exponent too large");
  return pow(base, (uint32_t) mpz_get_ui(((GmpType*) exp.x_)->value_));
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt pow(
    const LargeInt& base, const LargeInt& exp, const LargeInt& modulus) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  mp_exptmod(
      ((MpIntType*) base.x_)->value_,
      ((MpIntType*) exp.x_)->value_,
      ((MpIntType*) modulus.x_)->value_,
      ((MpIntType*) to_return.x_)->value_);
#endif
#ifdef LARGE_INT_GMP
  // TODO(PHB): See GMP documentation about mpz_powm vs. mpz_powm_sec,
  // and consider using the latter instead (which may be more suitable
  // for cryptographic applications, i.e. resilient to side-channel attacks).
  mpz_powm(
      ((GmpType*) to_return.x_)->value_,
      ((GmpType*) base.x_)->value_,
      ((GmpType*) exp.x_)->value_,
      ((GmpType*) modulus.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

LargeInt pow(
    const LargeInt& base, const uint32_t& exp, const LargeInt& modulus) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  mp_int exp_int;
  mp_init(&exp_int);
  mp_set_long(&exp_int, exp);
  mp_exptmod(
      ((MpIntType*) base.x_)->value_,
      &exp_int,
      ((MpIntType*) modulus.x_)->value_,
      ((MpIntType*) to_return.x_)->value_);
  mp_clear(&exp_int);
#endif
#ifdef LARGE_INT_GMP
  // TODO(PHB): See GMP documentation about mpz_powm_ui vs. mpz_powm_sec,
  // and consider using the latter instead (which may be more suitable
  // for cryptographic applications, i.e. resilient to side-channel attacks).
  mpz_powm_ui(
      ((GmpType*) to_return.x_)->value_,
      ((GmpType*) base.x_)->value_,
      exp,
      ((GmpType*) modulus.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

bool InverseModN(
    const LargeInt& input, const LargeInt& modulus, LargeInt* inverse) {
#ifdef LARGE_INT_MP_INT
  return (
      MP_OKAY ==
      mp_invmod(
          ((MpIntType*) input.x_)->value_,
          ((MpIntType*) modulus.x_)->value_,
          ((MpIntType*) inverse->x_)->value_));
#endif
#ifdef LARGE_INT_GMP
  return 0 !=
      mpz_invert(
             ((GmpType*) inverse->x_)->value_,
             ((GmpType*) input.x_)->value_,
             ((GmpType*) modulus.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt RandomInModulus(const LargeInt& modulus) {
  if (modulus <= 0) return LargeInt::Zero();
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  // DISCUSSION:
  // Tommath has an mp_rand() function that I don't use here, for two
  // reasons:
  //   1) It only allows specification of a given number of digits,
  //      as opposed to granularity to specify a specific value
  //   2) I couldn't figure out to use it right, in particular, how
  //      to set the second argument 'digits' properly, based on the
  //      desired modulus size.
  // Even for use-cases where (1) is not a problem (e.g. where we just
  // want to generate a sufficiently large random value), (2) was still
  // a big problem, as I couldn't make sense of what exactly digits does:
  // it appears to be roughly what it says (i.e. passing in N digits will
  // generate an N-digit random value), but the relationship isn't precise,
  // or at least, using mp_unsigned_bin_size of the passed-in modulus does
  // not return expected results (close, but no clear relationship to
  // any of log_2, log_8, or log_10). Below is the attempted code:
  /*
    int num_digits =
        mp_unsigned_bin_size(((MpIntType*) modulus.x_)->value_);
    mp_rand(((MpIntType*) to_return.x_)->value_, num_digits);
    */
  // See further dicsucssion in comment above the BasicEncryptTest() in
  // paillier_test.cpp (you'll need to go to a Snapshot version of this file,
  // since it was updated on 6/22/2017), where encryption of a large value is done.
  if (modulus <= std::numeric_limits<uint64_t>::max()) {
    // Use RandomInModulus if modulus is small enough.
    mp_set_long_long(
        ((MpIntType*) to_return.x_)->value_,
        (unsigned long long) crypto::random_number::RandomInModulus(
            modulus.GetValue()->GetUInt64()));
  } else {
    // Use RandomBytes, then cast to random value.
    const uint32_t num_bits = log2(modulus);
    const uint32_t num_bytes =
        (num_bits / CHAR_BIT) + (num_bits % CHAR_BIT == 0 ? 0 : 1);
    vector<unsigned char> random_bytes;
    crypto::random_number::RandomBytes(num_bytes, &random_bytes);
    LargeInt temp = LargeInt::ByteStringToLargeInt(random_bytes);
    to_return = temp % modulus;
    // TODO(paul): The above code doesn't work, as it won't properly sample
    // uniformly in [0..modulus-1]. There should be some sort of protection
    // for a skewed selection, as in crypto::random_number::RandomInModulus().
    // However, since use of LibTom is deprecated, I don't bother with the
    // fix now. Just log fatal. [If we ever want to use LibTom again, will
    // need to update the fix then.]
    LOG_FATAL("This not properly supported.");
  }
#endif
#ifdef LARGE_INT_GMP
  // NOTE: Ordinarilly LargeInt::random_seed_is_set_ should be inside the lock,
  // but since it's a boolean (and hence setting it is an atomic operation),
  // and to save time of *not* needing to grab the lock before checking its
  // state, we save time by checking its value without the lock.
  if (!LargeInt::random_seed_is_set_) {
    // Grab lock.
    LargeInt::random_seed_mutex_->GrabLock();

    // Re-check if another thread already did this.
    if (!LargeInt::random_seed_is_set_) {
      // Set random seed.
      gmp_randinit_mt(kGmpRandomState);
      const uint32_t random_seed = crypto::random_number::RandomInModulus(
          std::numeric_limits<uint32_t>::max());
      gmp_randseed_ui(kGmpRandomState, random_seed);

      // Indicate to all that seed has been initialized.
      LargeInt::random_seed_is_set_ = true;
    }
    // Release lock.
    LargeInt::random_seed_mutex_->ReleaseLock();
  }
  mpz_urandomm(
      ((GmpType*) to_return.x_)->value_,
      kGmpRandomState,
      ((GmpType*) modulus.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

unsigned long LargeInt::RandomInModulus(
    void*, /* not used */
    const unsigned char* modulus,
    size_t num_bytes_in_modulus,
    unsigned char* output,
    size_t num_outputs) {
  LargeInt mod_as_int =
      ByteStringToLargeInt(modulus, (int) num_bytes_in_modulus);
  LargeInt rand;
  size_t current_index = 0;
  for (size_t i = 0; i < num_outputs; ++i) {
    rand = math_utils::RandomInModulus(mod_as_int);
    vector<unsigned char> tmp;
    rand.GetValue()->ToByteString(&tmp);
    if (tmp.size() > num_bytes_in_modulus) LOG_FATAL("Bad number generated.");
    if (tmp.size() < num_bytes_in_modulus) {
      memset(output + current_index, 0, num_bytes_in_modulus - tmp.size());
      current_index += num_bytes_in_modulus - tmp.size();
    }
    memcpy(output + current_index, tmp.data(), tmp.size());
    current_index += tmp.size();
  }

  return 0;
}

LargeInt LargeInt::RandomPrime(const uint32_t& modulus_bits) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  // Generate a random prime of size modulus_bits. Requires a function
  // (callback) with appropriate input/output parameters to generate random bytes.
  mp_prime_random_ex(
      ((MpIntType*) to_return.x_)->value_,
      kNumRoundsToGeneratePrime,
      modulus_bits,
      0 /* No special flags */,
      &RandomCallback,
      nullptr);
#endif
#ifdef LARGE_INT_GMP
  // First, generate a random value that will server as the baseline
  // for our random prime: i.e. the random value will just be uniform
  // random (not necessarily a prime), and then we'll take the next prime
  // bigger than this.
  // NOTE: Ordinarilly LargeInt::random_seed_is_set_ should be inside the lock,
  // but since it's a boolean (and hence setting it is an atomic operation),
  // and to save time of *not* needing to grab the lock before checking its
  // state, we save time by checking its value without the lock.
  if (!LargeInt::random_seed_is_set_) {
    // Grab lock.
    LargeInt::random_seed_mutex_->GrabLock();

    // Re-check if another thread already did this.
    if (!LargeInt::random_seed_is_set_) {
      // Set random seed.
      gmp_randinit_mt(kGmpRandomState);
      const uint32_t random_seed = crypto::random_number::RandomInModulus(
          std::numeric_limits<uint32_t>::max());
      gmp_randseed_ui(kGmpRandomState, random_seed);

      // Indicate to all that seed has been initialized.
      LargeInt::random_seed_is_set_ = true;
    }
    // Release lock.
    LargeInt::random_seed_mutex_->ReleaseLock();
  }
  mpz_t baseline, minimum;
  mpz_init(baseline);
  mpz_init(minimum);
  mpz_urandomb(baseline, kGmpRandomState, ((mp_bitcnt_t) modulus_bits));
  mpz_ui_pow_ui(minimum, 2, (modulus_bits / 2));
  // Sanity-check baseline is not too small.
  if (mpz_cmp(baseline, minimum) < 0) {
    LOG_FATAL("Oops, randomly sampled a prime that is too small");
  }
  GmpType temp;
  mpz_set(temp.value_, baseline);
  to_return = NextPrime(LargeInt(temp));
  mpz_clear(baseline);
  mpz_clear(minimum);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

LargeInt NextPrime(const LargeInt& input) {
  LargeInt to_return;
#ifdef LARGE_INT_MP_INT
  to_return = input;
  mp_prime_next_prime(
      ((MpIntType*) to_return.x_)->value_,
      kNumRoundsToGenerateNextPrime,
      0 /* No special flags */);
#endif
#ifdef LARGE_INT_GMP
  mpz_nextprime(
      ((GmpType*) to_return.x_)->value_, ((GmpType*) input.x_)->value_);
#endif
#ifdef LARGE_INT_MPIR
#endif
  return to_return;
}

int LargeInt::NumBytes() const {
#ifdef LARGE_INT_MP_INT
  const int to_return = mp_unsigned_bin_size(((MpIntType*) x_)->value_);
  // Special logic to avoid returning '0', which mp_unsigned_bin_size()
  // (annoyingly!) returns if value_ is zero.
  return to_return == 0 ? 1 : to_return;
#endif
#ifdef LARGE_INT_GMP
  const int num_bits = (int) mpz_sizeinbase(((GmpType*) x_)->value_, 2);
  return num_bits / CHAR_BIT + (num_bits % CHAR_BIT == 0 ? 0 : 1);
#endif
#ifdef LARGE_INT_MPIR
#endif
}

LargeInt LargeInt::BinaryStringToLargeInt(const string& input) {
  LargeInt to_return;
  to_return.x_->FromBinaryString(input);
  return to_return;
}

LargeInt LargeInt::TwosComplementStringToLargeInt(const string& input) {
  LargeInt to_return;
  to_return.x_->FromTwosComplementString(input);
  return to_return;
}

LargeInt LargeInt::ByteStringToLargeInt(
    const std::vector<unsigned char>& input) {
  LargeInt to_return;
  to_return.x_->FromByteString(input);
  return to_return;
}

LargeInt LargeInt::ByteStringToLargeInt(const std::vector<char>& input) {
  LargeInt to_return;
  to_return.x_->FromByteString(input);
  return to_return;
}

LargeInt LargeInt::ByteStringToLargeInt(
    const unsigned char* input, const int num_bytes) {
  LargeInt to_return;
  to_return.x_->FromByteString(input, num_bytes);
  return to_return;
}

LargeInt LargeInt::ByteStringToLargeInt(
    const unsigned char* input, const int num_bytes, const int endian) {
  LargeInt to_return;
  to_return.x_->FromByteString(input, num_bytes, endian);
  return to_return;
}

LargeInt LargeInt::ByteStringToLargeInt(const char* input, const int num_bytes) {
  LargeInt to_return;
  to_return.x_->FromByteString(input, num_bytes);
  return to_return;
}

LargeInt LargeInt::TwosComplementStringToLargeInt(
    const std::vector<unsigned char>& input) {
  LargeInt to_return;
  to_return.x_->FromTwosComplementByteString(input);
  return to_return;
}

LargeInt LargeInt::TwosComplementStringToLargeInt(
    const std::vector<char>& input) {
  LargeInt to_return;
  to_return.x_->FromTwosComplementByteString(input);
  return to_return;
}

void LargeIntToByteString(
    const LargeInt& input, std::vector<unsigned char>* output) {
  input.x_->ToByteString(output);
}

void LargeIntToByteString(
    const int endian,
    const LargeInt& input,
    std::vector<unsigned char>* output) {
  input.x_->ToByteString(endian, output);
}

void LargeIntToTwosComplementString(
    const LargeInt& input, std::vector<unsigned char>* output) {
  input.x_->ToTwosComplementByteString(output);
}

uint32_t log2(const LargeInt& input) {
  if (input <= 1) return 0;
  uint32_t lower_bound = 0;
  uint32_t upper_bound = numeric_limits<uint32_t>::max();
  bool found_upper_end = false;
  uint32_t range = upper_bound;
  uint32_t current = 1;
  LargeInt holder;
  // The last condition, that current > 0, is just to protect the case that
  // input >= 2^(2^32).
  while (lower_bound < upper_bound && range > 0 && current > 0) {
    holder = pow((uint32_t) 2, current);
    if (holder < input) {
      lower_bound = current;
      if (found_upper_end) {
        range /= 2;
        current += range;
      } else {
        current *= 2;
      }
    } else if (holder > input) {
      upper_bound = current;
      if (!found_upper_end) {
        found_upper_end = true;
        range = current - lower_bound;
        current = lower_bound + range / 2;
      } else {
        range /= 2;
        current -= range;
      }
    } else {
      return current;
    }
  }

  return lower_bound;
}

bool IsPrime(const LargeInt& input) {
#ifdef LARGE_INT_MP_INT
  int result = 0;
  mp_prime_is_prime(
      ((const MpIntType*) input.GetValue())->value_,
      kNumRoundsToTestPrime,
      &result);
  return result != 0;
#endif
#ifdef LARGE_INT_GMP
  return (
      0 <
      mpz_probab_prime_p(
          ((const GmpType*) input.GetValue())->value_, kNumRoundsToTestPrime));
#endif
#ifdef LARGE_INT_MPIR
#endif
}

}  // namespace math_utils
