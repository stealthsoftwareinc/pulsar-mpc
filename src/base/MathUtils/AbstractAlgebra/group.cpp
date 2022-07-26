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

#include "group.h"

#include <math.h>  // For pow()

#include <cstdint>  // For int64_t
#include <memory>  // For unique_ptr
#include <vector>

#include "Crypto/RandomNumberGeneration/random_utils.h"  // For RandomXXX.
#include "GenericUtils/char_casting_utils.h"  // For ValueToByteString().
#include "MathUtils/large_int.h"
#include "StringUtils/string_utils.h"

// NOTE: We don't just include namespace std, as this causes confusion between
// std math functions (e.g. pow, max, etc.) and LargeInt and/or GroupElement
// functions of the same name.
using std::unique_ptr;
using string_utils::Itoa;

namespace math_utils {

// Big-endian encoding of the prime number l = |G| / 8, where |G| is the
// oreder of Edwards Curve group ED25519:
//   l = 2^252 + 27742317777372353535851937790883648493
const uint32_t kEDBasePointOrderHex[] = {
    0x10UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL,
    0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL,
    0x14UL, 0xdeUL, 0xf9UL, 0xdeUL, 0xa2UL, 0xf7UL, 0x9cUL, 0xd6UL,
    0x58UL, 0x12UL, 0x63UL, 0x1aUL, 0x5cUL, 0xf5UL, 0xd3UL, 0xedUL};
// This large prime p used to generate a group (Z_STAR_LARGE_P)
// is derived from https://tools.ietf.org/html/rfc3526#section-3
const uint32_t kDiffieHellmanGroup[] = {
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xC90FDAA2UL, 0x2168C234UL, 0xC4C6628BUL,
    0x80DC1CD1UL, 0x29024E08UL, 0x8A67CC74UL, 0x020BBEA6UL, 0x3B139B22UL,
    0x514A0879UL, 0x8E3404DDUL, 0xEF9519B3UL, 0xCD3A431BUL, 0x302B0A6DUL,
    0xF25F1437UL, 0x4FE1356DUL, 0x6D51C245UL, 0xE485B576UL, 0x625E7EC6UL,
    0xF44C42E9UL, 0xA637ED6BUL, 0x0BFF5CB6UL, 0xF406B7EDUL, 0xEE386BFBUL,
    0x5A899FA5UL, 0xAE9F2411UL, 0x7C4B1FE6UL, 0x49286651UL, 0xECE45B3DUL,
    0xC2007CB8UL, 0xA163BF05UL, 0x98DA4836UL, 0x1C55D39AUL, 0x69163FA8UL,
    0xFD24CF5FUL, 0x83655D23UL, 0xDCA3AD96UL, 0x1C62F356UL, 0x208552BBUL,
    0x9ED52907UL, 0x7096966DUL, 0x670C354EUL, 0x4ABC9804UL, 0xF1746C08UL,
    0xCA18217CUL, 0x32905E46UL, 0x2E36CE3BUL, 0xE39E772CUL, 0x180E8603UL,
    0x9B2783A2UL, 0xEC07A28FUL, 0xB5C55DF0UL, 0x6F4C52C9UL, 0xDE2BCBF6UL,
    0x95581718UL, 0x3995497CUL, 0xEA956AE5UL, 0x15D22618UL, 0x98FA0510UL,
    0x15728E5AUL, 0x8AACAA68UL, 0xFFFFFFFFUL, 0xFFFFFFFFUL};

// Unlike all the other functions in GroupElement, which are defined to be
// purely abstract (via the '= 0' at the end), the pure virtual destructor
// must be defined.
GroupElement::~GroupElement() noexcept {}

GroupElement* CreateIdentityGroupElement(const GroupProperties& properties) {
  switch (properties.type_) {
    case GroupType::Z: {
      return new IntegerGroupElement();
    }
    case GroupType::LARGE_Z: {
      return new LargeIntegerGroupElement();
    }
    case GroupType::Z_TWO: {
      return new IntegerModTwoGroupElement();
    }
    case GroupType::EDWARDS_CURVE: {
      return new EdwardsCurveGroupElement(
          ((const EdwardsCurveGroupProperties&) properties).modulus_,
          ((const EdwardsCurveGroupProperties&) properties).a_,
          ((const EdwardsCurveGroupProperties&) properties).d_);
    }
    case GroupType::Z_N: {
      return new IntegerModNGroupElement(
          ((const ModulusGroupProperties&) properties).modulus_);
    }
    case GroupType::Z_LARGE_N: {
      return new IntegerModLargeNGroupElement(
          ((const LargeModulusGroupProperties&) properties).modulus_);
    }
    case GroupType::Z_STAR_P: {
      return new MultiplicativeIntegersModPGroupElement(
          ((const ModulusGroupProperties&) properties).modulus_);
    }
    case GroupType::Z_STAR_LARGE_P: {
      return new MultiplicativeIntegersModLargePGroupElement(
          ((const LargeModulusGroupProperties&) properties).modulus_);
    }
    case GroupType::DIRECT_PRODUCT: {
      return new DirectProductGroupElement(
          *(((const DirectProductGroupProperties&) properties).subgroup_one_),
          *(((const DirectProductGroupProperties&) properties).subgroup_two_));
    }
    default: {
      LOG_FATAL(
          "Unable to construct a GroupElement Copy of unsupported GroupType: " +
          Itoa(static_cast<int>(properties.type_)));
    }
  }
  return nullptr;
}

GroupElement* CreateGroupElementCopy(const GroupElement& element) {
  const GroupType type = element.GetGroupType();
  switch (type) {
    case GroupType::Z: {
      return new IntegerGroupElement(*((const IntegerGroupElement*) &element));
    }
    case GroupType::LARGE_Z: {
      return new LargeIntegerGroupElement(
          *((const LargeIntegerGroupElement*) &element));
    }
    case GroupType::Z_TWO: {
      return new IntegerModTwoGroupElement(
          *((const IntegerModTwoGroupElement*) &element));
    }
    case GroupType::EDWARDS_CURVE: {
      return new EdwardsCurveGroupElement(
          *((const EdwardsCurveGroupElement*) &element));
    }
    case GroupType::Z_N: {
      return new IntegerModNGroupElement(
          *((const IntegerModNGroupElement*) &element));
    }
    case GroupType::Z_LARGE_N: {
      return new IntegerModLargeNGroupElement(
          *((const IntegerModLargeNGroupElement*) &element));
    }
    case GroupType::Z_STAR_P: {
      return new MultiplicativeIntegersModPGroupElement(
          *((const MultiplicativeIntegersModPGroupElement*) &element));
    }
    case GroupType::Z_STAR_LARGE_P: {
      return new MultiplicativeIntegersModLargePGroupElement(
          *((const MultiplicativeIntegersModLargePGroupElement*) &element));
    }
    case GroupType::DIRECT_PRODUCT: {
      return new DirectProductGroupElement(
          *((const DirectProductGroupElement*) &element));
    }
    default: {
      LOG_FATAL(
          "Unable to construct a GroupElement Copy of unsupported GroupType: " +
          Itoa(static_cast<int>(type)));
    }
  }
  return nullptr;
}

void GroupElement::SetGroupProperties(const GroupProperties& properties) {
  properties_.reset(CreateNewCopy(&properties));
}

// ============================ GroupType = Z (Integers) =======================
GroupElement& IntegerGroupElement::operator+=(const GroupElement& other) {
  const IntegerGroupElement* other_cast = (IntegerGroupElement*) &other;
  value_ += other_cast->GetValue();
  return *this;
}

GroupElement& IntegerGroupElement::operator+=(GroupOperationHolder other) {
  IntegerGroupElement* other_cast = (IntegerGroupElement*) other.element_;
  value_ += other_cast->GetValue();
  delete other.element_;
  return *this;
}

GroupElement& IntegerGroupElement::operator-=(const GroupElement& other) {
  const IntegerGroupElement* other_cast = (IntegerGroupElement*) &other;
  value_ -= other_cast->GetValue();
  return *this;
}

GroupElement& IntegerGroupElement::operator-=(GroupOperationHolder other) {
  const IntegerGroupElement* other_cast = (IntegerGroupElement*) other.element_;
  value_ -= other_cast->GetValue();
  delete other.element_;
  return *this;
}

GroupElement& IntegerGroupElement::operator*=(const int32_t n) {
  value_ *= n;
  return *this;
}

GroupElement& IntegerGroupElement::operator*=(const uint32_t n) {
  value_ *= n;
  return *this;
}

GroupElement& IntegerGroupElement::operator*=(const int64_t& n) {
  value_ *= n;
  return *this;
}

GroupElement& IntegerGroupElement::operator*=(const uint64_t& n) {
  value_ *= n;
  return *this;
}

GroupElement& IntegerGroupElement::operator*=(const LargeInt& n) {
  if (n > std::numeric_limits<uint64_t>::max()) {
    LOG_FATAL("Cannot multiply by value larger than 64-bits.");
  }
  uint64_t n_cast = n.GetValue()->GetUInt64();
  value_ *= n_cast;
  return *this;
}

void IntegerGroupElement::Add(const GroupElement& a, const GroupElement& b) {
  const IntegerGroupElement* a_cast = (IntegerGroupElement*) &a;
  const IntegerGroupElement* b_cast = (IntegerGroupElement*) &b;
  value_ = a_cast->GetValue() + b_cast->GetValue();
}

void IntegerGroupElement::Subtract(
    const GroupElement& a, const GroupElement& b) {
  const IntegerGroupElement* a_cast = (IntegerGroupElement*) &a;
  const IntegerGroupElement* b_cast = (IntegerGroupElement*) &b;
  value_ = a_cast->GetValue() - b_cast->GetValue();
}

void IntegerGroupElement::Multiply(const int32_t a, const GroupElement& b) {
  const IntegerGroupElement* b_cast = (IntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void IntegerGroupElement::Multiply(const uint32_t a, const GroupElement& b) {
  const IntegerGroupElement* b_cast = (IntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void IntegerGroupElement::Multiply(const int64_t& a, const GroupElement& b) {
  const IntegerGroupElement* b_cast = (IntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void IntegerGroupElement::Multiply(const uint64_t& a, const GroupElement& b) {
  const IntegerGroupElement* b_cast = (IntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void IntegerGroupElement::Invert() { value_ = -1 * value_; }

bool IntegerGroupElement::Encode(
    uint64_t* num_bytes, unsigned char** output) const {
  *output = (unsigned char*) malloc(sizeof(uint64_t));
  memcpy(*output, (unsigned char*) &value_, sizeof(uint64_t));
  *num_bytes = sizeof(uint64_t);
  return true;
}

bool IntegerGroupElement::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  if (num_bytes != sizeof(uint64_t)) return false;
  memcpy((unsigned char*) &value_, input, num_bytes);
  return true;
}

IntegerGroupElement IntegerGroupElement::Inverse() const {
  return IntegerGroupElement(-1 * value_);
}

// ====================== GroupType = LARGE_Z (Large Integers) =================
GroupElement& LargeIntegerGroupElement::operator+=(const GroupElement& other) {
  const LargeIntegerGroupElement* other_cast =
      (LargeIntegerGroupElement*) &other;
  value_ += other_cast->GetValue();
  return *this;
}

GroupElement& LargeIntegerGroupElement::operator+=(GroupOperationHolder other) {
  const LargeIntegerGroupElement* other_cast =
      (LargeIntegerGroupElement*) other.element_;
  value_ += other_cast->GetValue();
  delete other.element_;
  return *this;
}

GroupElement& LargeIntegerGroupElement::operator-=(const GroupElement& other) {
  const LargeIntegerGroupElement* other_cast =
      (LargeIntegerGroupElement*) &other;
  value_ -= other_cast->GetValue();
  return *this;
}

GroupElement& LargeIntegerGroupElement::operator-=(GroupOperationHolder other) {
  const LargeIntegerGroupElement* other_cast =
      (LargeIntegerGroupElement*) other.element_;
  value_ -= other_cast->GetValue();
  delete other.element_;
  return *this;
}

GroupElement& LargeIntegerGroupElement::operator*=(const int32_t n) {
  value_ *= n;
  return *this;
}

GroupElement& LargeIntegerGroupElement::operator*=(const uint32_t n) {
  value_ *= n;
  return *this;
}

GroupElement& LargeIntegerGroupElement::operator*=(const int64_t& n) {
  value_ *= n;
  return *this;
}

GroupElement& LargeIntegerGroupElement::operator*=(const uint64_t& n) {
  value_ *= n;
  return *this;
}

GroupElement& LargeIntegerGroupElement::operator*=(const LargeInt& n) {
  value_ *= n;
  return *this;
}

void LargeIntegerGroupElement::Add(
    const GroupElement& a, const GroupElement& b) {
  const LargeIntegerGroupElement* a_cast = (LargeIntegerGroupElement*) &a;
  const LargeIntegerGroupElement* b_cast = (LargeIntegerGroupElement*) &b;
  value_ = a_cast->GetValue() + b_cast->GetValue();
}

void LargeIntegerGroupElement::Subtract(
    const GroupElement& a, const GroupElement& b) {
  const LargeIntegerGroupElement* a_cast = (LargeIntegerGroupElement*) &a;
  const LargeIntegerGroupElement* b_cast = (LargeIntegerGroupElement*) &b;
  value_ = a_cast->GetValue() - b_cast->GetValue();
}

void LargeIntegerGroupElement::Multiply(const int32_t a, const GroupElement& b) {
  const LargeIntegerGroupElement* b_cast = (LargeIntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void LargeIntegerGroupElement::Multiply(
    const uint32_t a, const GroupElement& b) {
  const LargeIntegerGroupElement* b_cast = (LargeIntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void LargeIntegerGroupElement::Multiply(
    const int64_t& a, const GroupElement& b) {
  const LargeIntegerGroupElement* b_cast = (LargeIntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void LargeIntegerGroupElement::Multiply(
    const uint64_t& a, const GroupElement& b) {
  const LargeIntegerGroupElement* b_cast = (LargeIntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void LargeIntegerGroupElement::Multiply(
    const LargeInt& a, const GroupElement& b) {
  const LargeIntegerGroupElement* b_cast = (LargeIntegerGroupElement*) &b;
  value_ = a * b_cast->GetValue();
}

void LargeIntegerGroupElement::Invert() { value_ = -1 * value_; }

bool LargeIntegerGroupElement::Encode(
    uint64_t* num_bytes, unsigned char** output) const {
  std::vector<unsigned char> tmp;
  LargeIntToByteString(value_, &tmp);
  *output = (unsigned char*) malloc(tmp.size());
  if (!*output) return false;
  std::memcpy(*output, tmp.data(), tmp.size());
  *num_bytes = tmp.size();
  return true;
}

bool LargeIntegerGroupElement::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  value_ = LargeInt::ByteStringToLargeInt(input, (int) num_bytes);
  return true;
}

LargeIntegerGroupElement LargeIntegerGroupElement::Inverse() const {
  return LargeIntegerGroupElement(-1 * value_);
}

// ============================= GroupType = Z_TWO =============================
GroupElement& IntegerModTwoGroupElement::operator+=(const GroupElement& other) {
  const IntegerModTwoGroupElement* other_cast =
      (IntegerModTwoGroupElement*) &other;
  value_ = other_cast->GetValue() ^ value_;
  return *this;
}

GroupElement& IntegerModTwoGroupElement::operator+=(GroupOperationHolder other) {
  const IntegerModTwoGroupElement* other_cast =
      (IntegerModTwoGroupElement*) other.element_;
  value_ = other_cast->GetValue() ^ value_;
  delete other.element_;
  return *this;
}

GroupElement& IntegerModTwoGroupElement::operator-=(const GroupElement& other) {
  const IntegerModTwoGroupElement* other_cast =
      (IntegerModTwoGroupElement*) &other;
  value_ = other_cast->GetValue() ^ value_;
  return *this;
}

GroupElement& IntegerModTwoGroupElement::operator-=(GroupOperationHolder other) {
  const IntegerModTwoGroupElement* other_cast =
      (IntegerModTwoGroupElement*) other.element_;
  value_ = other_cast->GetValue() ^ value_;
  delete other.element_;
  return *this;
}

GroupElement& IntegerModTwoGroupElement::operator*=(const int32_t n) {
  value_ = value_ ? (n >= 0 ? (n % 2) : (abs(n) % 2)) : false;
  return *this;
}

GroupElement& IntegerModTwoGroupElement::operator*=(const uint32_t n) {
  value_ = value_ ? (n % 2) : false;
  return *this;
}

GroupElement& IntegerModTwoGroupElement::operator*=(const int64_t& n) {
  value_ = value_ ? (n >= 0 ? (n % 2) : ((n * -1) % 2)) : false;
  return *this;
}

GroupElement& IntegerModTwoGroupElement::operator*=(const uint64_t& n) {
  value_ = value_ ? (n % 2) : false;
  return *this;
}

GroupElement& IntegerModTwoGroupElement::operator*=(const LargeInt& n) {
  LargeInt copy(n);
  copy %= 2;
  uint64_t n_cast = copy.GetValue()->GetUInt64();
  if (value_ && n_cast == 0) value_ = 0;
  return *this;
}

void IntegerModTwoGroupElement::Add(
    const GroupElement& a, const GroupElement& b) {
  const IntegerModTwoGroupElement* a_cast = (IntegerModTwoGroupElement*) &a;
  const IntegerModTwoGroupElement* b_cast = (IntegerModTwoGroupElement*) &b;
  value_ = a_cast->GetValue() ^ b_cast->GetValue();
}

void IntegerModTwoGroupElement::Subtract(
    const GroupElement& a, const GroupElement& b) {
  const IntegerModTwoGroupElement* a_cast = (IntegerModTwoGroupElement*) &a;
  const IntegerModTwoGroupElement* b_cast = (IntegerModTwoGroupElement*) &b;
  value_ = a_cast->GetValue() ^ b_cast->GetValue();
}

void IntegerModTwoGroupElement::Multiply(
    const int32_t a, const GroupElement& b) {
  const IntegerModTwoGroupElement* b_cast = (IntegerModTwoGroupElement*) &b;
  value_ = b_cast->GetValue() ? (a >= 0 ? (a % 2) : (abs(a) % 2)) : false;
}

void IntegerModTwoGroupElement::Multiply(
    const uint32_t a, const GroupElement& b) {
  const IntegerModTwoGroupElement* b_cast = (IntegerModTwoGroupElement*) &b;
  value_ = b_cast->GetValue() ? (a % 2) : false;
}

void IntegerModTwoGroupElement::Multiply(
    const int64_t& a, const GroupElement& b) {
  const IntegerModTwoGroupElement* b_cast = (IntegerModTwoGroupElement*) &b;
  value_ = b_cast->GetValue() ? (a >= 0 ? (a % 2) : ((a * -1) % 2)) : false;
}

void IntegerModTwoGroupElement::Multiply(
    const uint64_t& a, const GroupElement& b) {
  const IntegerModTwoGroupElement* b_cast = (IntegerModTwoGroupElement*) &b;
  value_ = b_cast->GetValue() ? (a % 2) : false;
}

void IntegerModTwoGroupElement::Invert() {
  // Nothing to do (both 0 and 1 are their own inverses).
}

bool IntegerModTwoGroupElement::Encode(
    uint64_t* num_bytes, unsigned char** output) const {
  *output = (unsigned char*) malloc(1);
  (*output)[0] = value_;
  *num_bytes = 1;
  return true;
}

bool IntegerModTwoGroupElement::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  if (num_bytes != 1) return false;
  value_ = input[0];
  return true;
}

IntegerModTwoGroupElement IntegerModTwoGroupElement::Inverse() const {
  // An element is its own inverse in Z_2.
  return IntegerModTwoGroupElement(value_);
}

IntegerModTwoGroupElement IntegerModTwoGroupElement::Random() const {
  if (crypto::random_number::RandomBit()) {
    return IntegerModTwoGroupElement(0);
  } else {
    return IntegerModTwoGroupElement(1);
  }
}

// ============================= GroupType = EdwardsCurve ====================
GroupElement& EdwardsCurveGroupElement::operator+=(const GroupElement& other) {
  const EdwardsCurveGroupElement* other_cast =
      (EdwardsCurveGroupElement*) &other;

  std::pair<LargeInt, LargeInt> other_value = other_cast->GetValue();
  value_ = EdwardsAddition(
      GetModulus(), GetA(), GetD(), value_, other_cast->GetValue());
  return *this;
}

GroupElement& EdwardsCurveGroupElement::operator+=(GroupOperationHolder other) {
  const EdwardsCurveGroupElement* other_cast =
      (EdwardsCurveGroupElement*) other.element_;

  value_ = EdwardsAddition(
      GetModulus(), GetA(), GetD(), value_, other_cast->GetValue());
  delete other.element_;
  return *this;
}

GroupElement& EdwardsCurveGroupElement::operator-=(const GroupElement& other) {
  const EdwardsCurveGroupElement* other_cast =
      (EdwardsCurveGroupElement*) &other;

  value_ = EdwardsAddition(
      GetModulus(),
      GetA(),
      GetD(),
      value_,
      EdwardsInverse(other_cast->GetModulus(), other_cast->GetValue()));
  return *this;
}

GroupElement& EdwardsCurveGroupElement::operator-=(GroupOperationHolder other) {
  const EdwardsCurveGroupElement* other_cast =
      (EdwardsCurveGroupElement*) other.element_;

  value_ = EdwardsAddition(
      GetModulus(),
      GetA(),
      GetD(),
      value_,
      EdwardsInverse(other_cast->GetModulus(), other_cast->GetValue()));
  delete other.element_;
  return *this;
}

GroupElement& EdwardsCurveGroupElement::operator*=(const int32_t n) {
  value_ = EdwardsScaling(GetModulus(), GetA(), GetD(), LargeInt(n), value_);
  return *this;
}

GroupElement& EdwardsCurveGroupElement::operator*=(const uint32_t n) {
  value_ = EdwardsScaling(GetModulus(), GetA(), GetD(), LargeInt(n), value_);

  return *this;
}

GroupElement& EdwardsCurveGroupElement::operator*=(const int64_t& n) {
  value_ = EdwardsScaling(GetModulus(), GetA(), GetD(), LargeInt(n), value_);
  return *this;
}

GroupElement& EdwardsCurveGroupElement::operator*=(const uint64_t& n) {
  value_ = EdwardsScaling(GetModulus(), GetA(), GetD(), LargeInt(n), value_);
  return *this;
}

GroupElement& EdwardsCurveGroupElement::operator*=(const LargeInt& n) {
  value_ = EdwardsScaling(GetModulus(), GetA(), GetD(), n, value_);
  return *this;
}

void EdwardsCurveGroupElement::Add(
    const GroupElement& a, const GroupElement& b) {
  const EdwardsCurveGroupElement* a_cast = (EdwardsCurveGroupElement*) &a;
  const EdwardsCurveGroupElement* b_cast = (EdwardsCurveGroupElement*) &b;

  value_ = EdwardsAddition(
      GetModulus(), GetA(), GetD(), a_cast->GetValue(), b_cast->GetValue());
}

void EdwardsCurveGroupElement::Subtract(
    const GroupElement& a, const GroupElement& b) {
  const EdwardsCurveGroupElement* a_cast = (EdwardsCurveGroupElement*) &a;
  const EdwardsCurveGroupElement* b_cast = (EdwardsCurveGroupElement*) &b;

  value_ = EdwardsAddition(
      GetModulus(),
      GetA(),
      GetD(),
      a_cast->GetValue(),
      EdwardsInverse(b_cast->GetModulus(), b_cast->GetValue()));
}

void EdwardsCurveGroupElement::Multiply(const int32_t a, const GroupElement& b) {
  const EdwardsCurveGroupElement* b_cast = (EdwardsCurveGroupElement*) &b;
  value_ = EdwardsScaling(
      GetModulus(), GetA(), GetD(), LargeInt(a), b_cast->GetValue());
}

void EdwardsCurveGroupElement::Multiply(
    const uint32_t a, const GroupElement& b) {
  const EdwardsCurveGroupElement* b_cast = (EdwardsCurveGroupElement*) &b;
  value_ = EdwardsScaling(
      GetModulus(), GetA(), GetD(), LargeInt(a), b_cast->GetValue());
}

void EdwardsCurveGroupElement::Multiply(
    const int64_t& a, const GroupElement& b) {
  const EdwardsCurveGroupElement* b_cast = (EdwardsCurveGroupElement*) &b;
  value_ = EdwardsScaling(
      GetModulus(), GetA(), GetD(), LargeInt(a), b_cast->GetValue());
}

void EdwardsCurveGroupElement::Multiply(
    const uint64_t& a, const GroupElement& b) {
  const EdwardsCurveGroupElement* b_cast = (EdwardsCurveGroupElement*) &b;
  value_ = EdwardsScaling(
      GetModulus(), GetA(), GetD(), LargeInt(a), b_cast->GetValue());
}

void EdwardsCurveGroupElement::Multiply(
    const LargeInt& a, const GroupElement& b) {
  const EdwardsCurveGroupElement* b_cast = (EdwardsCurveGroupElement*) &b;
  value_ = EdwardsScaling(GetModulus(), GetA(), GetD(), a, b_cast->GetValue());
}

void EdwardsCurveGroupElement::Invert() {
  value_ = EdwardsInverse(GetModulus(), value_);
}

bool EdwardsCurveGroupElement::Encode(
    uint64_t* num_bytes, unsigned char** output) const {
  LargeInt inv;
  InverseModN(LargeInt(121666), GetModulus(), &inv);
  if ((GetModulus() != pow(2, 255) - LargeInt(19)) ||
      (GetA() != (LargeInt(-1) % GetModulus())) ||
      (GetD() != ((LargeInt(-121665) * inv) % GetModulus()))) {
    LOG_FATAL("Currently we only support ED25519");
  }

  std::vector<unsigned char> tmp;
  LargeInt y = GetValue().second;
  //  As per the specification in https://cr.yp.to/papers.html#ed25519, we use
  //  the little endian encoding of y as a 255-bit.
  LargeIntToByteString(-1 /* little endian */, y, &tmp);

  const int num_bytes_in_edwards_curve_group = 256 / CHAR_BIT;
  if ((tmp.size() > num_bytes_in_edwards_curve_group) ||
      ((tmp.size() == num_bytes_in_edwards_curve_group) && (tmp.back() & 128))) {
    return false;
  } else {
    tmp.resize(num_bytes_in_edwards_curve_group, 0);
  }
  //  Use the remaining bit (only 255 bits used for y above) to denote the
  //  sign of x, using '1' iff x is "negative" (i.e. x is odd).
  if ((GetValue().first % 2) != LargeInt::Zero()) {
    tmp.back() |= 128;
  }

  *output = (unsigned char*) malloc(tmp.size());
  if (!(*output)) {
    return false;
  }

  std::memcpy(*output, tmp.data(), tmp.size());
  *num_bytes = tmp.size();
  return true;
}

bool EdwardsCurveGroupElement::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  LargeInt inv;
  InverseModN(LargeInt(121666), GetModulus(), &inv);
  if ((GetModulus() != pow(2, 255) - LargeInt(19)) ||
      (GetA() != (LargeInt(-1) % GetModulus())) ||
      (GetD() != ((LargeInt(-121665) * inv) % GetModulus()))) {
    LOG_FATAL("Currently we only support ED25519 ");
  }

  //  As per the specification in https://cr.yp.to/papers.html#ed25519, we
  //  assume the input is a 256-bit encoded number. We decode the first 255 bits
  //  (using the little endian encoding) to recover the value of y, and then set
  //  x = \pm sqrt((y^2 - 1)(dy^2 - a)), where the sign of x is negative iff the
  //  last bit from input equals 1.
  int endian = -1;

  //  Recover the last bit, and copy input to tmp where we explicitly set the
  //  last bit in tmp to zero.
  int last_bit = (input[num_bytes - 1] >> (CHAR_BIT - 1)) & 1;
  std::vector<unsigned char> tmp(num_bytes);
  std::memcpy(tmp.data(), input, tmp.size());
  tmp.back() &= 127;

  LargeInt y =
      LargeInt::ByteStringToLargeInt(tmp.data(), (int) num_bytes, endian);
  LargeInt x = GetXCoordinate(y, GetModulus(), GetA(), GetD(), last_bit != 1);

  SetValue(GroupValueType(std::make_pair(x, y)));
  return true;
}

EdwardsCurveGroupElement EdwardsCurveGroupElement::Inverse() const {
  return EdwardsCurveGroupElement(
      GetModulus(), GetA(), GetD(), EdwardsInverse(GetModulus(), value_));
}

// ============================ GroupType = Z_N ================================
GroupElement& IntegerModNGroupElement::operator+=(const GroupElement& other) {
  const IntegerModNGroupElement* other_cast = (IntegerModNGroupElement*) &other;
  value_ += other_cast->GetValue();
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& IntegerModNGroupElement::operator+=(GroupOperationHolder other) {
  const IntegerModNGroupElement* other_cast =
      (IntegerModNGroupElement*) other.element_;
  value_ += other_cast->GetValue();
  value_ = value_ % GetModulus();
  delete other.element_;
  return *this;
}

GroupElement& IntegerModNGroupElement::operator-=(const GroupElement& other) {
  const IntegerModNGroupElement* other_cast = (IntegerModNGroupElement*) &other;
  const uint64_t other_value = other_cast->GetValue();
  if (value_ >= other_value) {
    value_ -= other_cast->GetValue();
  } else {
    value_ += GetModulus() - other_value;
  }
  return *this;
}

GroupElement& IntegerModNGroupElement::operator-=(GroupOperationHolder other) {
  const IntegerModNGroupElement* other_cast =
      (IntegerModNGroupElement*) other.element_;
  const uint64_t other_value = other_cast->GetValue();
  if (value_ >= other_value) {
    value_ -= other_cast->GetValue();
  } else {
    value_ += GetModulus() - other_value;
  }
  delete other.element_;
  return *this;
}

GroupElement& IntegerModNGroupElement::operator*=(const int32_t n) {
  value_ *= n >= 0 ? n : abs(n);
  value_ = value_ % GetModulus();
  if (n < 0) value_ = GetModulus() - value_;
  return *this;
}

GroupElement& IntegerModNGroupElement::operator*=(const uint32_t n) {
  value_ *= n;
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& IntegerModNGroupElement::operator*=(const int64_t& n) {
  value_ *= n >= 0 ? n : (n * -1);
  value_ = value_ % GetModulus();
  if (n < 0) value_ = GetModulus() - value_;
  return *this;
}

GroupElement& IntegerModNGroupElement::operator*=(const uint64_t& n) {
  value_ *= n;
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& IntegerModNGroupElement::operator*=(const LargeInt& n) {
  LargeInt copy(n);
  copy %= GetModulus();
  uint64_t n_cast = copy.GetValue()->GetUInt64();
  value_ *= n_cast;
  value_ = value_ % GetModulus();
  return *this;
}

void IntegerModNGroupElement::Add(const GroupElement& a, const GroupElement& b) {
  const IntegerModNGroupElement* a_cast = (IntegerModNGroupElement*) &a;
  const IntegerModNGroupElement* b_cast = (IntegerModNGroupElement*) &b;
  value_ = a_cast->GetValue() + b_cast->GetValue();
  value_ = value_ % GetModulus();
}

void IntegerModNGroupElement::Subtract(
    const GroupElement& a, const GroupElement& b) {
  const IntegerModNGroupElement* a_cast = (IntegerModNGroupElement*) &a;
  const IntegerModNGroupElement* b_cast = (IntegerModNGroupElement*) &b;
  const uint64_t a_value = a_cast->GetValue();
  const uint64_t b_value = b_cast->GetValue();
  if (a_value >= b_value) {
    value_ = a_cast->GetValue() - b_cast->GetValue();
  } else {
    value_ = (GetModulus() - b_value) + a_value;
  }
}

void IntegerModNGroupElement::Multiply(const int32_t a, const GroupElement& b) {
  const IntegerModNGroupElement* b_cast = (IntegerModNGroupElement*) &b;
  value_ = b_cast->GetValue() * (a >= 0 ? a : abs(a));
  value_ = value_ % GetModulus();
  if (a < 0) value_ = GetModulus() - value_;
}

void IntegerModNGroupElement::Multiply(const uint32_t a, const GroupElement& b) {
  const IntegerModNGroupElement* b_cast = (IntegerModNGroupElement*) &b;
  value_ = b_cast->GetValue() * a;
  value_ = value_ % GetModulus();
}

void IntegerModNGroupElement::Multiply(const int64_t& a, const GroupElement& b) {
  const IntegerModNGroupElement* b_cast = (IntegerModNGroupElement*) &b;
  value_ = b_cast->GetValue() * (a >= 0 ? a : (a * -1));
  value_ = value_ % GetModulus();
  if (a < 0) value_ = GetModulus() - value_;
}

void IntegerModNGroupElement::Multiply(
    const uint64_t& a, const GroupElement& b) {
  const IntegerModNGroupElement* b_cast = (IntegerModNGroupElement*) &b;
  value_ = b_cast->GetValue() * a;
  value_ = value_ % GetModulus();
}

void IntegerModNGroupElement::Invert() {
  if (value_ != 0) value_ = GetModulus() - value_;
}

bool IntegerModNGroupElement::Encode(
    uint64_t* num_bytes, unsigned char** output) const {
  // First cast value_ as a (8-byte) byte string (big-endian).
  std::vector<unsigned char> as_byte_string;
  if (!ValueToByteString(false, value_, &as_byte_string)) return false;
  // Compute how many bytes are actually needed.
  const int num_bits = log2(GetModulus());
  *num_bytes = num_bits / CHAR_BIT + ((num_bits % CHAR_BIT == 0) ? 0 : 1);
  const int offset = (int) (sizeof(uint64_t) - *num_bytes);
  *output = (unsigned char*) malloc(sizeof(*num_bytes));
  memcpy(*output, as_byte_string.data() + offset, *num_bytes);
  return true;
}

bool IntegerModNGroupElement::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  const unsigned int num_bits = log2(GetModulus());
  const unsigned int num_expected_bytes =
      num_bits / CHAR_BIT + ((num_bits % CHAR_BIT == 0) ? 0 : 1);
  if (num_bytes != num_expected_bytes) return false;
  const int offset = (int) (sizeof(uint64_t) - num_bytes);
  std::vector<unsigned char> padded_input(sizeof(uint64_t));
  memcpy(padded_input.data() + offset, input, num_bytes);
  value_ = ByteStringToValue<uint64_t>(padded_input);
  return true;
}

IntegerModNGroupElement IntegerModNGroupElement::Inverse() const {
  if (value_ == 0) return IntegerModNGroupElement(GetModulus());
  return IntegerModNGroupElement(GetModulus(), GetModulus() - value_);
}

IntegerModNGroupElement IntegerModNGroupElement::Random() const {
  return IntegerModNGroupElement(
      GetModulus(), crypto::random_number::RandomInModulus(GetModulus()));
}

// ============================ GroupType = Z_LARGE_N ==========================
GroupElement& IntegerModLargeNGroupElement::operator+=(
    const GroupElement& other) {
  const IntegerModLargeNGroupElement* other_cast =
      (IntegerModLargeNGroupElement*) &other;
  value_ += other_cast->GetValue();
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& IntegerModLargeNGroupElement::operator+=(
    GroupOperationHolder other) {
  const IntegerModLargeNGroupElement* other_cast =
      (IntegerModLargeNGroupElement*) other.element_;
  value_ += other_cast->GetValue();
  value_ = value_ % GetModulus();
  delete other.element_;
  return *this;
}

GroupElement& IntegerModLargeNGroupElement::operator-=(
    const GroupElement& other) {
  const IntegerModLargeNGroupElement* other_cast =
      (IntegerModLargeNGroupElement*) &other;
  value_ -= other_cast->GetValue();
  value_ = value_ < 0 ? value_ + GetModulus() : value_ % GetModulus();
  return *this;
}

GroupElement& IntegerModLargeNGroupElement::operator-=(
    GroupOperationHolder other) {
  const IntegerModLargeNGroupElement* other_cast =
      (IntegerModLargeNGroupElement*) other.element_;
  value_ -= other_cast->GetValue();
  value_ = value_ < 0 ? value_ + GetModulus() : value_ % GetModulus();
  delete other.element_;
  return *this;
}

GroupElement& IntegerModLargeNGroupElement::operator*=(const int32_t n) {
  value_ *= n >= 0 ? n : abs(n);
  value_ = value_ % GetModulus();
  if (n < 0) value_ = GetModulus() - value_;
  return *this;
}

GroupElement& IntegerModLargeNGroupElement::operator*=(const uint32_t n) {
  value_ *= n;
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& IntegerModLargeNGroupElement::operator*=(const int64_t& n) {
  value_ *= n >= 0 ? n : (n * -1);
  value_ = value_ % GetModulus();
  if (n < 0) value_ = GetModulus() - value_;
  return *this;
}

GroupElement& IntegerModLargeNGroupElement::operator*=(const uint64_t& n) {
  value_ *= n;
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& IntegerModLargeNGroupElement::operator*=(const LargeInt& n) {
  value_ *= n >= 0 ? n : abs(n);
  value_ = value_ % GetModulus();
  if (n < 0) value_ = GetModulus() - value_;
  return *this;
}

void IntegerModLargeNGroupElement::Add(
    const GroupElement& a, const GroupElement& b) {
  const IntegerModLargeNGroupElement* a_cast =
      (IntegerModLargeNGroupElement*) &a;
  const IntegerModLargeNGroupElement* b_cast =
      (IntegerModLargeNGroupElement*) &b;
  value_ = a_cast->GetValue() + b_cast->GetValue();
  value_ = value_ % GetModulus();
}

void IntegerModLargeNGroupElement::Subtract(
    const GroupElement& a, const GroupElement& b) {
  const IntegerModLargeNGroupElement* a_cast =
      (IntegerModLargeNGroupElement*) &a;
  const IntegerModLargeNGroupElement* b_cast =
      (IntegerModLargeNGroupElement*) &b;
  value_ = a_cast->GetValue() - b_cast->GetValue();
  value_ = value_ < 0 ? value_ + GetModulus() : value_ % GetModulus();
}

void IntegerModLargeNGroupElement::Multiply(
    const int32_t a, const GroupElement& b) {
  const IntegerModLargeNGroupElement* b_cast =
      (IntegerModLargeNGroupElement*) &b;
  value_ = b_cast->GetValue() * (a >= 0 ? a : abs(a));
  value_ = value_ % GetModulus();
  if (a < 0) value_ = GetModulus() - value_;
}

void IntegerModLargeNGroupElement::Multiply(
    const uint32_t a, const GroupElement& b) {
  const IntegerModLargeNGroupElement* b_cast =
      (IntegerModLargeNGroupElement*) &b;
  value_ = b_cast->GetValue() * a;
  value_ = value_ % GetModulus();
}

void IntegerModLargeNGroupElement::Multiply(
    const int64_t& a, const GroupElement& b) {
  const IntegerModLargeNGroupElement* b_cast =
      (IntegerModLargeNGroupElement*) &b;
  value_ = b_cast->GetValue() * (a >= 0 ? a : (a * -1));
  value_ = value_ % GetModulus();
  if (a < 0) value_ = GetModulus() - value_;
}

void IntegerModLargeNGroupElement::Multiply(
    const uint64_t& a, const GroupElement& b) {
  const IntegerModLargeNGroupElement* b_cast =
      (IntegerModLargeNGroupElement*) &b;
  value_ = b_cast->GetValue() * a;
  value_ = value_ % GetModulus();
}

void IntegerModLargeNGroupElement::Multiply(
    const LargeInt& a, const GroupElement& b) {
  const IntegerModLargeNGroupElement* b_cast =
      (IntegerModLargeNGroupElement*) &b;
  value_ = b_cast->GetValue() * (a >= 0 ? a : abs(a));
  value_ = value_ % GetModulus();
  if (a < 0) value_ = GetModulus() - value_;
}

void IntegerModLargeNGroupElement::Invert() {
  if (!value_.IsZero()) value_ = GetModulus() - value_;
}

bool IntegerModLargeNGroupElement::Encode(
    uint64_t* num_bytes, unsigned char** output) const {
  std::vector<unsigned char> tmp;
  LargeIntToByteString(value_, &tmp);
  *output = (unsigned char*) malloc(tmp.size());
  if (!*output) return false;
  std::memcpy(*output, tmp.data(), tmp.size());
  *num_bytes = tmp.size();
  return true;
}

bool IntegerModLargeNGroupElement::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  value_ = LargeInt::ByteStringToLargeInt(input, (int) num_bytes);
  return true;
}

IntegerModLargeNGroupElement IntegerModLargeNGroupElement::Inverse() const {
  if (value_.IsZero()) {
    return IntegerModLargeNGroupElement(GetModulus(), LargeInt::Zero());
  }
  return IntegerModLargeNGroupElement(GetModulus(), GetModulus() - value_);
}

IntegerModLargeNGroupElement IntegerModLargeNGroupElement::Random() const {
  return IntegerModLargeNGroupElement(
      GetModulus(), RandomInModulus(GetModulus()));
}

// ============================ GroupType = Z*_p ===============================
GroupElement& MultiplicativeIntegersModPGroupElement::operator+=(
    const GroupElement& other) {
  const MultiplicativeIntegersModPGroupElement* other_cast =
      (MultiplicativeIntegersModPGroupElement*) &other;
  value_ *= other_cast->GetValue();
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& MultiplicativeIntegersModPGroupElement::operator+=(
    GroupOperationHolder other) {
  const MultiplicativeIntegersModPGroupElement* other_cast =
      (MultiplicativeIntegersModPGroupElement*) other.element_;
  value_ *= other_cast->GetValue();
  value_ = value_ % GetModulus();
  delete other.element_;
  return *this;
}

GroupElement& MultiplicativeIntegersModPGroupElement::operator-=(
    const GroupElement& other) {
  const MultiplicativeIntegersModPGroupElement* other_cast =
      (MultiplicativeIntegersModPGroupElement*) &other;
  value_ *= other_cast->Inverse().GetValue();
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& MultiplicativeIntegersModPGroupElement::operator-=(
    GroupOperationHolder other) {
  const MultiplicativeIntegersModPGroupElement* other_cast =
      (MultiplicativeIntegersModPGroupElement*) other.element_;
  value_ *= other_cast->Inverse().GetValue();
  value_ = value_ % GetModulus();
  delete other.element_;
  return *this;
}

GroupElement& MultiplicativeIntegersModPGroupElement::operator*=(
    const int32_t n) {
  if (n < 0) Invert();
  value_ = Pow(value_, (uint64_t) abs(n));
  return *this;
}

GroupElement& MultiplicativeIntegersModPGroupElement::operator*=(
    const uint32_t n) {
  value_ = Pow(value_, (uint64_t) n);
  return *this;
}

GroupElement& MultiplicativeIntegersModPGroupElement::operator*=(
    const int64_t& n) {
  if (n < 0) {
    Invert();
    value_ = Pow(value_, (uint64_t) (n * -1));
  } else {
    value_ = Pow(value_, (uint64_t) n);
  }
  return *this;
}

GroupElement& MultiplicativeIntegersModPGroupElement::operator*=(
    const uint64_t& n) {
  value_ = Pow(value_, n);
  return *this;
}

GroupElement& MultiplicativeIntegersModPGroupElement::operator*=(
    const LargeInt& n) {
  LargeInt copy(n);
  copy %= GetModulus();
  uint64_t n_cast = copy.GetValue()->GetUInt64();
  value_ = Pow(value_, n_cast);
  return *this;
}

void MultiplicativeIntegersModPGroupElement::Add(
    const GroupElement& a, const GroupElement& b) {
  const MultiplicativeIntegersModPGroupElement* a_cast =
      (MultiplicativeIntegersModPGroupElement*) &a;
  const MultiplicativeIntegersModPGroupElement* b_cast =
      (MultiplicativeIntegersModPGroupElement*) &b;
  value_ = (a_cast->GetValue() * b_cast->GetValue()) % GetModulus();
}

void MultiplicativeIntegersModPGroupElement::Subtract(
    const GroupElement& a, const GroupElement& b) {
  const MultiplicativeIntegersModPGroupElement* a_cast =
      (MultiplicativeIntegersModPGroupElement*) &a;
  const MultiplicativeIntegersModPGroupElement* b_cast =
      (MultiplicativeIntegersModPGroupElement*) &b;
  value_ = (a_cast->GetValue() * (b_cast->Inverse().GetValue())) % GetModulus();
}

void MultiplicativeIntegersModPGroupElement::Multiply(
    const int32_t a, const GroupElement& b) {
  const MultiplicativeIntegersModPGroupElement* b_cast =
      (MultiplicativeIntegersModPGroupElement*) &b;
  const uint64_t b_value =
      a < 0 ? b_cast->Inverse().GetValue() : b_cast->GetValue();
  value_ = Pow(b_value, (uint64_t) abs(a));
}

void MultiplicativeIntegersModPGroupElement::Multiply(
    const uint32_t a, const GroupElement& b) {
  const MultiplicativeIntegersModPGroupElement* b_cast =
      (MultiplicativeIntegersModPGroupElement*) &b;
  value_ = Pow(b_cast->GetValue(), (uint64_t) a);
}

void MultiplicativeIntegersModPGroupElement::Multiply(
    const int64_t& a, const GroupElement& b) {
  const MultiplicativeIntegersModPGroupElement* b_cast =
      (MultiplicativeIntegersModPGroupElement*) &b;
  const uint64_t b_value =
      a < 0 ? b_cast->Inverse().GetValue() : b_cast->GetValue();
  if (a < 0) {
    value_ = Pow(b_value, (uint64_t) (a * -1));
  } else {
    value_ = Pow(b_value, (uint64_t) a);
  }
}

void MultiplicativeIntegersModPGroupElement::Multiply(
    const uint64_t& a, const GroupElement& b) {
  const MultiplicativeIntegersModPGroupElement* b_cast =
      (MultiplicativeIntegersModPGroupElement*) &b;
  value_ = Pow(b_cast->GetValue(), a);
}

void MultiplicativeIntegersModPGroupElement::Invert() {
  // Use Fermats Little Theorem: For prime p and any element g \in Z*_p:
  //   g^{-1} = g^{p-2} (mod p)
  if (value_ == 1) return;
  if (GetModulus() == 2) return;  // Z*_2 = {1}, so value_ is always 1.
  value_ = Pow(value_, GetModulus() - 2);
}

bool MultiplicativeIntegersModPGroupElement::Encode(
    uint64_t* num_bytes, unsigned char** output) const {
  // First cast value_ as a (8-byte) byte string (big-endian).
  std::vector<unsigned char> as_byte_string;
  if (!ValueToByteString(false, value_, &as_byte_string)) return false;
  // Compute how many bytes are actually needed.
  const int num_bits = log2(GetModulus());
  *num_bytes = num_bits / CHAR_BIT + ((num_bits % CHAR_BIT == 0) ? 0 : 1);
  const int offset = (int) (sizeof(uint64_t) - *num_bytes);
  *output = (unsigned char*) malloc(sizeof(*num_bytes));
  memcpy(*output, as_byte_string.data() + offset, *num_bytes);
  return true;
}

bool MultiplicativeIntegersModPGroupElement::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  const unsigned int num_bits = log2(GetModulus());
  const unsigned int num_expected_bytes =
      num_bits / CHAR_BIT + ((num_bits % CHAR_BIT == 0) ? 0 : 1);
  if (num_bytes != num_expected_bytes) return false;
  const int offset = (int) (sizeof(uint64_t) - num_bytes);
  std::vector<unsigned char> padded_input(sizeof(uint64_t));
  memcpy(padded_input.data() + offset, input, num_bytes);
  value_ = ByteStringToValue<uint64_t>(padded_input);
  return true;
}

MultiplicativeIntegersModPGroupElement
MultiplicativeIntegersModPGroupElement::Inverse() const {
  if (value_ == 1 || GetModulus() == 2) {
    return MultiplicativeIntegersModPGroupElement(GetModulus());
  }
  return MultiplicativeIntegersModPGroupElement(
      GetModulus(), Pow(value_, GetModulus() - 2));
}

MultiplicativeIntegersModPGroupElement
MultiplicativeIntegersModPGroupElement::Random() const {
  return MultiplicativeIntegersModPGroupElement(
      GetModulus(),
      1 + crypto::random_number::RandomInModulus(GetModulus() - 1));
}

uint64_t MultiplicativeIntegersModPGroupElement::Pow(
    const uint64_t& base, const int64_t& exp) const {
  // Use LargeInt's built-in pow() function.
  LargeInt large_base(base);
  LargeInt large_exp(exp);
  LargeInt large_mod(GetModulus());
  LargeInt result = pow(large_base, large_exp, large_mod);
  // Now cast back to uint64_t.
  return result.GetValue()->GetUInt64();
}

uint64_t MultiplicativeIntegersModPGroupElement::Pow(
    const uint64_t& base, const uint64_t& exp) const {
  // Use LargeInt's built-in pow() function.
  LargeInt large_base(base);
  LargeInt large_exp(exp);
  LargeInt large_mod(GetModulus());
  LargeInt result = pow(large_base, large_exp, large_mod);
  // Now cast back to uint64_t.
  return result.GetValue()->GetUInt64();
}

// ================ GroupType = Z*_LARGE_p (Z*_p for LargeInt p) ===============
typedef MultiplicativeIntegersModLargePGroupElement ZStarModLargeP;
GroupElement& ZStarModLargeP::operator+=(const GroupElement& other) {
  const ZStarModLargeP* other_cast = (ZStarModLargeP*) &other;
  value_ *= other_cast->GetValue();
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& ZStarModLargeP::operator+=(GroupOperationHolder other) {
  const ZStarModLargeP* other_cast = (ZStarModLargeP*) other.element_;
  value_ *= other_cast->GetValue();
  value_ = value_ % GetModulus();
  delete other.element_;
  return *this;
}

GroupElement& ZStarModLargeP::operator-=(const GroupElement& other) {
  const ZStarModLargeP* other_cast = (ZStarModLargeP*) &other;
  value_ *= other_cast->Inverse().GetValue();
  value_ = value_ % GetModulus();
  return *this;
}

GroupElement& ZStarModLargeP::operator-=(GroupOperationHolder other) {
  const ZStarModLargeP* other_cast = (ZStarModLargeP*) other.element_;
  value_ *= other_cast->Inverse().GetValue();
  value_ = value_ % GetModulus();
  delete other.element_;
  return *this;
}

GroupElement& ZStarModLargeP::operator*=(const int32_t n) {
  if (n < 0) Invert();
  value_ = pow(value_, LargeInt(abs(n)), GetModulus());
  return *this;
}

GroupElement& ZStarModLargeP::operator*=(const uint32_t n) {
  value_ = pow(value_, LargeInt(n), GetModulus());
  return *this;
}

GroupElement& ZStarModLargeP::operator*=(const int64_t& n) {
  if (n < 0) {
    Invert();
    value_ = pow(value_, LargeInt((n * -1)), GetModulus());
  } else {
    value_ = pow(value_, LargeInt(n), GetModulus());
  }
  return *this;
}

GroupElement& ZStarModLargeP::operator*=(const uint64_t& n) {
  value_ = pow(value_, LargeInt(n), GetModulus());
  return *this;
}

GroupElement& ZStarModLargeP::operator*=(const LargeInt& n) {
  value_ = pow(value_, LargeInt(n), GetModulus());
  return *this;
}

void ZStarModLargeP::Add(const GroupElement& a, const GroupElement& b) {
  const ZStarModLargeP* a_cast = (ZStarModLargeP*) &a;
  const ZStarModLargeP* b_cast = (ZStarModLargeP*) &b;
  value_ = (a_cast->GetValue() * b_cast->GetValue()) % GetModulus();
}

void ZStarModLargeP::Subtract(const GroupElement& a, const GroupElement& b) {
  const ZStarModLargeP* a_cast = (ZStarModLargeP*) &a;
  const ZStarModLargeP* b_cast = (ZStarModLargeP*) &b;
  value_ = (a_cast->GetValue() * (b_cast->Inverse().GetValue())) % GetModulus();
}

void ZStarModLargeP::Multiply(const int32_t a, const GroupElement& b) {
  const ZStarModLargeP* b_cast = (ZStarModLargeP*) &b;
  const LargeInt b_value =
      a < 0 ? b_cast->Inverse().GetValue() : b_cast->GetValue();
  value_ = pow(b_value, LargeInt(abs(a)), GetModulus());
}

void ZStarModLargeP::Multiply(const uint32_t a, const GroupElement& b) {
  const ZStarModLargeP* b_cast = (ZStarModLargeP*) &b;
  value_ = pow(b_cast->GetValue(), LargeInt(a), GetModulus());
}

void ZStarModLargeP::Multiply(const int64_t& a, const GroupElement& b) {
  const ZStarModLargeP* b_cast = (ZStarModLargeP*) &b;
  const LargeInt b_value =
      a < 0 ? b_cast->Inverse().GetValue() : b_cast->GetValue();
  if (a < 0) {
    value_ = pow(b_value, LargeInt((a * -1)), GetModulus());
  } else {
    value_ = pow(b_value, LargeInt(a), GetModulus());
  }
}

void ZStarModLargeP::Multiply(const uint64_t& a, const GroupElement& b) {
  const ZStarModLargeP* b_cast = (ZStarModLargeP*) &b;
  value_ = pow(b_cast->GetValue(), LargeInt(a), GetModulus());
}

void ZStarModLargeP::Multiply(const LargeInt& a, const GroupElement& b) {
  const ZStarModLargeP* b_cast = (ZStarModLargeP*) &b;
  value_ = pow(b_cast->GetValue(), LargeInt(a), GetModulus());
}

void ZStarModLargeP::Invert() {
  // Use Fermats Little Theorem: For prime p and any element g \in Z*_p:
  //   g^{-1} = g^{p-2} (mod p)
  if (value_ == 1) return;
  if (GetModulus() == 2) return;  // Z*_2 = {1}, so value_ is always 1.
  value_ = pow(value_, GetModulus() - 2, GetModulus());
}

bool ZStarModLargeP::Encode(uint64_t* num_bytes, unsigned char** output) const {
  std::vector<unsigned char> tmp;
  LargeIntToByteString(value_, &tmp);
  *output = (unsigned char*) malloc(tmp.size());
  if (!*output) return false;
  std::memcpy(*output, tmp.data(), tmp.size());
  *num_bytes = tmp.size();
  return true;
}

bool ZStarModLargeP::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  value_ = LargeInt::ByteStringToLargeInt(input, (int) num_bytes);
  return true;
}

ZStarModLargeP ZStarModLargeP::Inverse() const {
  if (value_ == 1 || GetModulus() == 2) {
    return MultiplicativeIntegersModLargePGroupElement(GetModulus());
  }
  return MultiplicativeIntegersModLargePGroupElement(
      GetModulus(), pow(value_, GetModulus() - 2, GetModulus()));
}

ZStarModLargeP ZStarModLargeP::Random() const {
  return ZStarModLargeP(GetModulus(), 1 + RandomInModulus(GetModulus() - 1));
}

// ============================ GroupType = G x H (Direct Product) =============
GroupElement* DirectProductGroupElement::CreateDirectProductSubgroup(
    const GroupProperties& properties) const {
  switch (properties.type_) {
    case GroupType::Z: {
      return new IntegerGroupElement();
    }
    case GroupType::LARGE_Z: {
      return new LargeIntegerGroupElement();
    }
    case GroupType::Z_TWO: {
      return new IntegerModTwoGroupElement();
    }
    case GroupType::EDWARDS_CURVE: {
      return new EdwardsCurveGroupElement(
          ((const EdwardsCurveGroupProperties&) properties).modulus_,
          ((const EdwardsCurveGroupProperties&) properties).a_,
          ((const EdwardsCurveGroupProperties&) properties).d_);
    }
    case GroupType::Z_N: {
      return new IntegerModNGroupElement(
          ((const ModulusGroupProperties&) properties).modulus_);
    }
    case GroupType::Z_LARGE_N: {
      return new IntegerModLargeNGroupElement(
          ((const LargeModulusGroupProperties&) properties).modulus_);
    }
    case GroupType::Z_STAR_P: {
      return new MultiplicativeIntegersModPGroupElement(
          ((const ModulusGroupProperties&) properties).modulus_);
    }
    case GroupType::Z_STAR_LARGE_P: {
      return new MultiplicativeIntegersModLargePGroupElement(
          ((const LargeModulusGroupProperties&) properties).modulus_);
    }
    case GroupType::DIRECT_PRODUCT: {
      return new DirectProductGroupElement(
          *(((const DirectProductGroupProperties&) properties).subgroup_one_),
          *(((const DirectProductGroupProperties&) properties).subgroup_two_));
    }
    default: {
      // Currently, the above GroupTypes are the only ones that can be
      // constructed without any other arguments (other than the GroupType).
      LOG_FATAL(
          "Unable to use this API for CreateDirectProductSubgroup "
          "to construct a GroupElement of GroupType: " +
          Itoa(static_cast<int>(properties.type_)));
    }
  }
  return nullptr;
}

GroupElement& DirectProductGroupElement::operator+=(const GroupElement& other) {
  const DirectProductGroupElement* other_cast =
      (DirectProductGroupElement*) &other;
  SetFirstValue(*GetFirstValue() + *other_cast->GetFirstValue());
  SetSecondValue(*GetSecondValue() + *other_cast->GetSecondValue());
  return *this;
}

GroupElement& DirectProductGroupElement::operator+=(GroupOperationHolder other) {
  const DirectProductGroupElement* other_cast =
      (DirectProductGroupElement*) other.element_;
  SetFirstValue(*GetFirstValue() + *other_cast->GetFirstValue());
  SetSecondValue(*GetSecondValue() + *other_cast->GetSecondValue());
  delete other.element_;
  return *this;
}

GroupElement& DirectProductGroupElement::operator-=(const GroupElement& other) {
  const DirectProductGroupElement* other_cast =
      (DirectProductGroupElement*) &other;
  SetFirstValue(*GetFirstValue() - *other_cast->GetFirstValue());
  SetSecondValue(*GetSecondValue() - *other_cast->GetSecondValue());
  return *this;
}

GroupElement& DirectProductGroupElement::operator-=(GroupOperationHolder other) {
  const DirectProductGroupElement* other_cast =
      (DirectProductGroupElement*) other.element_;
  SetFirstValue(*GetFirstValue() - *other_cast->GetFirstValue());
  SetSecondValue(*GetSecondValue() - *other_cast->GetSecondValue());
  delete other.element_;
  return *this;
}

GroupElement& DirectProductGroupElement::operator*=(const int32_t n) {
  SetFirstValue(n * (*GetFirstValue()));
  SetSecondValue(n * (*GetSecondValue()));
  return *this;
}

GroupElement& DirectProductGroupElement::operator*=(const uint32_t n) {
  SetFirstValue(n * (*GetFirstValue()));
  SetSecondValue(n * (*GetSecondValue()));
  return *this;
}

GroupElement& DirectProductGroupElement::operator*=(const int64_t& n) {
  SetFirstValue(n * (*GetFirstValue()));
  SetSecondValue(n * (*GetSecondValue()));
  return *this;
}

GroupElement& DirectProductGroupElement::operator*=(const uint64_t& n) {
  SetFirstValue(n * (*GetFirstValue()));
  SetSecondValue(n * (*GetSecondValue()));
  return *this;
}

GroupElement& DirectProductGroupElement::operator*=(const LargeInt& n) {
  SetFirstValue(n * (*GetFirstValue()));
  SetSecondValue(n * (*GetSecondValue()));
  return *this;
}

void DirectProductGroupElement::Add(
    const GroupElement& a, const GroupElement& b) {
  const DirectProductGroupElement* a_cast = (DirectProductGroupElement*) &a;
  const DirectProductGroupElement* b_cast = (DirectProductGroupElement*) &b;
  SetFirstValue(*(a_cast->GetFirstValue()) + *(b_cast->GetFirstValue()));
  SetSecondValue(*(a_cast->GetSecondValue()) + *(b_cast->GetSecondValue()));
}

void DirectProductGroupElement::Subtract(
    const GroupElement& a, const GroupElement& b) {
  const DirectProductGroupElement* a_cast = (DirectProductGroupElement*) &a;
  const DirectProductGroupElement* b_cast = (DirectProductGroupElement*) &b;
  SetFirstValue(*(a_cast->GetFirstValue()) - *(b_cast->GetFirstValue()));
  SetSecondValue(*(a_cast->GetSecondValue()) - *(b_cast->GetSecondValue()));
}

void DirectProductGroupElement::Multiply(
    const int32_t a, const GroupElement& b) {
  const DirectProductGroupElement* b_cast = (DirectProductGroupElement*) &b;
  SetFirstValue(a * *(b_cast->GetFirstValue()));
  SetSecondValue(a * *(b_cast->GetSecondValue()));
}

void DirectProductGroupElement::Multiply(
    const uint32_t a, const GroupElement& b) {
  const DirectProductGroupElement* b_cast = (DirectProductGroupElement*) &b;
  SetFirstValue(a * *(b_cast->GetFirstValue()));
  SetSecondValue(a * *(b_cast->GetSecondValue()));
}

void DirectProductGroupElement::Multiply(
    const int64_t& a, const GroupElement& b) {
  const DirectProductGroupElement* b_cast = (DirectProductGroupElement*) &b;
  SetFirstValue(a * *(b_cast->GetFirstValue()));
  SetSecondValue(a * *(b_cast->GetSecondValue()));
}

void DirectProductGroupElement::Multiply(
    const uint64_t& a, const GroupElement& b) {
  const DirectProductGroupElement* b_cast = (DirectProductGroupElement*) &b;
  SetFirstValue(a * *(b_cast->GetFirstValue()));
  SetSecondValue(a * *(b_cast->GetSecondValue()));
}

void DirectProductGroupElement::Multiply(
    const LargeInt& a, const GroupElement& b) {
  const DirectProductGroupElement* b_cast = (DirectProductGroupElement*) &b;
  SetFirstValue(a * *(b_cast->GetFirstValue()));
  SetSecondValue(a * *(b_cast->GetSecondValue()));
}

void DirectProductGroupElement::Invert() {
  GetFirstValue()->Invert();
  GetSecondValue()->Invert();
}

bool DirectProductGroupElement::Encode(
    uint64_t* num_bytes, unsigned char** output) const {
  unsigned char* one = nullptr;
  uint64_t num_bytes_one = 0;
  unsigned char* two = nullptr;
  uint64_t num_bytes_two = 0;
  if (!value_one_->Encode(&num_bytes_one, &one) ||
      !value_two_->Encode(&num_bytes_two, &two)) {
    return false;
  }
  *output = (unsigned char*) malloc(
      num_bytes_one + num_bytes_two + 2 * sizeof(uint64_t));
  *num_bytes = num_bytes_one + num_bytes_two + 2 * sizeof(uint64_t);
  memcpy(*output, (unsigned char*) &num_bytes_one, sizeof(uint64_t));
  memcpy(*output, (unsigned char*) &num_bytes_two, sizeof(uint64_t));
  memcpy(*output + 2 * sizeof(uint64_t), one, num_bytes_one);
  memcpy(*output + num_bytes_one + 2 * sizeof(uint64_t), two, num_bytes_two);

  // Clean-up.
  free(one);
  free(two);

  return true;
}

bool DirectProductGroupElement::Decode(
    const uint64_t& num_bytes, const unsigned char* input) {
  if (num_bytes < 2 * sizeof(uint64_t)) return false;
  uint64_t num_bytes_one, num_bytes_two;
  memcpy((unsigned char*) &num_bytes_one, input, sizeof(uint64_t));
  memcpy(
      (unsigned char*) &num_bytes_two,
      input + sizeof(uint64_t),
      sizeof(uint64_t));
  value_one_->Decode(num_bytes_one, input + 2 * sizeof(uint64_t));
  value_two_->Decode(
      num_bytes_two, input + 2 * sizeof(uint64_t) + num_bytes_one);
  return true;
}

DirectProductGroupElement DirectProductGroupElement::Inverse() const {
  unique_ptr<GroupElement> first_inverse, second_inverse;

  switch (GetFirstGroupType()) {
    case GroupType::Z: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const IntegerGroupElement*) GetFirstValue())->Inverse()));
      break;
    }
    case GroupType::LARGE_Z: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const LargeIntegerGroupElement*) GetFirstValue())->Inverse()));
      break;
    }
    case GroupType::Z_TWO: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const IntegerModTwoGroupElement*) GetFirstValue())->Inverse()));
      break;
    }
    case GroupType::EDWARDS_CURVE: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const EdwardsCurveGroupElement*) GetFirstValue())->Inverse()));
      break;
    }
    case GroupType::Z_N: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const IntegerModNGroupElement*) GetFirstValue())->Inverse()));
      break;
    }
    case GroupType::Z_LARGE_N: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const IntegerModLargeNGroupElement*) GetFirstValue())->Inverse()));
      break;
    }
    case GroupType::Z_STAR_P: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const MultiplicativeIntegersModPGroupElement*) GetFirstValue())
              ->Inverse()));
      break;
    }
    case GroupType::Z_STAR_LARGE_P: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const MultiplicativeIntegersModLargePGroupElement*) GetFirstValue())
              ->Inverse()));
      break;
    }
    case GroupType::DIRECT_PRODUCT: {
      first_inverse.reset(CreateGroupElementCopy(
          ((const DirectProductGroupElement*) GetFirstValue())->Inverse()));
      break;
    }
    default: {
      LOG_FATAL(
          "Unable to get inverse for first Group of unsupported GroupType: " +
          Itoa(static_cast<int>(GetFirstGroupType())));
    }
  }

  switch (GetSecondGroupType()) {
    case GroupType::Z: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const IntegerGroupElement*) GetSecondValue())->Inverse()));
      break;
    }
    case GroupType::LARGE_Z: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const LargeIntegerGroupElement*) GetSecondValue())->Inverse()));
      break;
    }
    case GroupType::Z_TWO: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const IntegerModTwoGroupElement*) GetSecondValue())->Inverse()));
      break;
    }
    case GroupType::EDWARDS_CURVE: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const EdwardsCurveGroupElement*) GetSecondValue())->Inverse()));
      break;
    }
    case GroupType::Z_N: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const IntegerModNGroupElement*) GetSecondValue())->Inverse()));
      break;
    }
    case GroupType::Z_LARGE_N: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const IntegerModLargeNGroupElement*) GetSecondValue())->Inverse()));
      break;
    }
    case GroupType::Z_STAR_P: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const MultiplicativeIntegersModPGroupElement*) GetSecondValue())
              ->Inverse()));
      break;
    }
    case GroupType::Z_STAR_LARGE_P: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const MultiplicativeIntegersModLargePGroupElement*) GetSecondValue())
              ->Inverse()));
      break;
    }
    case GroupType::DIRECT_PRODUCT: {
      second_inverse.reset(CreateGroupElementCopy(
          ((const DirectProductGroupElement*) GetSecondValue())->Inverse()));
      break;
    }
    default: {
      LOG_FATAL(
          "Unable to get inverse for second Group of unsupported GroupType: " +
          Itoa(static_cast<int>(GetSecondGroupType())));
    }
  }

  return DirectProductGroupElement(*first_inverse, *second_inverse);
}

GroupProperties* CreateNewCopy(const GroupProperties* orig) {
  GroupProperties* to_return = nullptr;
  if (orig->type_ == GroupType::DIRECT_PRODUCT) {
    to_return = new DirectProductGroupProperties(
        *((const DirectProductGroupProperties*) orig));
  } else if (
      orig->type_ == GroupType::Z_N || orig->type_ == GroupType::Z_STAR_P) {
    to_return =
        new ModulusGroupProperties(*((const ModulusGroupProperties*) orig));
  } else if (
      orig->type_ == GroupType::Z_LARGE_N ||
      orig->type_ == GroupType::Z_STAR_LARGE_P) {
    to_return = new LargeModulusGroupProperties(
        *((const LargeModulusGroupProperties*) orig));
  } else if (orig->type_ == GroupType::EDWARDS_CURVE) {
    to_return = new EdwardsCurveGroupProperties(
        *((const EdwardsCurveGroupProperties*) orig));
  } else {
    to_return = new GroupProperties(*orig);
  }
  return to_return;
}

std::pair<LargeInt, LargeInt> EdwardsAddition(
    const LargeInt& modulus,
    const LargeInt& a,
    const LargeInt& d,
    const std::pair<LargeInt, LargeInt>& p,
    const std::pair<LargeInt, LargeInt>& q) {
  const LargeInt& x1 = p.first;
  const LargeInt& y1 = p.second;
  const LargeInt& x2 = q.first;
  const LargeInt& y2 = q.second;
  LargeInt w1;
  LargeInt w2;

  InverseModN(1 + d * x1 * x2 * y1 * y2, modulus, &w1);
  InverseModN(1 - d * x1 * x2 * y1 * y2, modulus, &w2);

  return std::make_pair(
      ((x1 * y2 + x2 * y1) * w1) % modulus,
      ((y1 * y2 - a * x1 * x2) * w2) % modulus);
}

std::pair<LargeInt, LargeInt> EdwardsInverse(
    const LargeInt& modulus, const std::pair<LargeInt, LargeInt>& p) {
  return std::make_pair(modulus - p.first, p.second);
}

std::pair<LargeInt, LargeInt> EdwardsScaling(
    const LargeInt& modulus,
    const LargeInt& a,
    const LargeInt& d,
    const LargeInt& n,
    const std::pair<LargeInt, LargeInt>& p) {
  if (n < 0) {
    return EdwardsInverse(modulus, EdwardsScaling(modulus, a, d, -n, p));
  }

  LargeInt num_remaining = n;
  std::pair<LargeInt, LargeInt> to_return =
      std::make_pair(LargeInt::Zero(), LargeInt::One());
  std::pair<LargeInt, LargeInt> power_of_two = p;
  while (num_remaining > 0) {
    if (num_remaining % 2 == 1) {
      to_return = EdwardsAddition(modulus, a, d, power_of_two, to_return);
    }
    power_of_two = EdwardsAddition(modulus, a, d, power_of_two, power_of_two);
    num_remaining /= 2;
  }

  return to_return;
}

LargeInt GetXCoordinate(
    const LargeInt& y,
    const LargeInt& modulus,
    const LargeInt& a,
    const LargeInt& d,
    const bool positive) {
  /*
   * quadratic residue calculation.
   * https://en.wikipedia.org/wiki/Quadratic_residue
   * https://en.wikipedia.org/wiki/Quartic_reciprocity
   * P = 8K+5
   * I = 2^((p-1)/ 4) is a primitive 4th root of unity (quartic reciprocity).
   * If a = x^2 then x = a^((p+3) / 8) OR x = I*a^((p+3) / 8)
   */

  const LargeInt sqrt_neg_one = pow(2, (modulus - 1) / 4, modulus);
  LargeInt tmp;
  InverseModN(d * y * y - a, modulus, &tmp);
  tmp = tmp * (y * y - 1);
  LargeInt x = pow(tmp, (modulus + 3) / 8, modulus);
  if ((x * x - tmp) % modulus != 0) {
    x = (x * sqrt_neg_one) % modulus;
  }
  if ((positive && (x % 2 != 0)) || (!positive && (x % 2 == 0))) {
    x = modulus - x;
  }
  return x;
}

LargeInt GetEdwardCurveSubgroupSize() {
  LargeInt p = LargeInt::Zero();
  for (int i = 0; i < 32; ++i) {
    p += LargeInt(kEDBasePointOrderHex[i]) *
        pow(LargeInt(2), static_cast<uint32_t>(8 * (31 - i)));
  }
  return p;
}

LargeInt GetDiffieHellmanGroupFourteenSize() {
  LargeInt p = LargeInt::Zero();
  for (int i = 0; i < 64; ++i) {
    p += LargeInt(kDiffieHellmanGroup[i]) *
        pow(LargeInt(2), static_cast<uint32_t>(32 * (63 - i)));
  }
  return p;
}

}  // namespace math_utils
