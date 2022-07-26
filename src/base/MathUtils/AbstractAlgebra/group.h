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
//   Provides a base (virtual) class to represent an arbitrary
//   (Algebraic) Group, along with serveral concrete instantiations.
//   There are 3 API's available for applying the group operation:
//     1) "c = a OP b", where:
//           - OP is +,-,*
//           - a and b have same GroupType as c (or, in the case of OP is *, then
//             a should have an integer type).
//        Example:
//          void foo(const GroupElement& a, const GroupElement& b, GroupElement* c) {
//            *c = a + b;
//          }
//     1*) "a = -b". Same result as: a = -1 * b.
//     2) "a OP= b", where:
//           - OP is +,-,*
//           - a has same GroupType as c (or, in the case of OP is *, then
//             a should have an integer type).
//        Example:
//          void foo(const GroupElement& b, GroupElement& a) {
//            a += b;
//          }
//     2*) "a OP= -b". Same result as: a OP= -1 * b.
//     3) "c OP1= a OP2 b", where:
//           - OP1, OP2 is +,-,*
//           - a and b have same GroupType as c (or, in the case of OP1 is *, then
//             a and b should have an integer type, or if OP2 is * (but OP1 is + or -),
//             then a should have an integer type).
//        Example:
//          void foo(const GroupElement& b, GroupElement& a, GroupElement* c) {
//            *c += a - b;
//          }
//   In addition, each group provides the following API's:
//     1) Identity(): (Static). Returns a GroupElement representing the group's
//                    identity element.
//          Example: IntegerGroupElement foo = IntegerGroupElement::Identity();
//     2) Invert(): Inverts the group element.
//          Example: a.Invert();
//     3) Inverse(): Returns a GroupElement that is the inverse of the object being
//        operated on.
//          Example: IntegerGroupElement foo = bar.Inverse();
//        Note: Inverse() is *not* a member function of GroupElement, so if
//        you need to use a generic version of Inverse() (e.g. if you're inside
//        a function in which you were passed generic GroupElements as the
//        parameters), then instead use the overloaded "-" operator, which *is*
//        defined for generic GroupElement.
//          Example: IntegerGroupElement foo = -bar;
//     4) [Get | Set]GroupType(): Returns/Sets the appropriate GroupType.
//     5) [Get | Set]Value(): Returns/Sets the appropriate GroupElement.
//   Finally, there are various ways to create GroupElements:
//     1) Via one of the constructors.
//          Example: IntegerGroupElement foo;
//          Example: IntegerGroupElement foo(1);
//          Example: IntegerGroupElement bar(foo);
//          Example: IntegerGroupElement bar = foo;
//     2) Copy Existing GroupElement.
//          Example: unique_ptr<IntegerGroupElement> foo(
//                        (IntegerGroupElement*) CreateGroupElementCopy(bar));
//          Example: IntegerGroupElement foo =
//                       *((IntegerGroupElement*) CreateGroupElementCopy(bar));

#ifndef GROUP_H
#define GROUP_H

#include <string>

#include <cstdint>  // For int64_t
#include <cstring>  // for memcpy
#include <memory>  // For unique_ptr

#include "MathUtils/large_int.h"  // For LargeInt.
#include "global_utils.h"  // For LOG_FATAL.

namespace math_utils {

// Big-endian encoding of the prime number l = |G| / 8, where |G| is the
// order of Edwards Curve group ED25519:
//   l = 2^252 + 27742317777372353535851937790883648493
extern const uint32_t kEDBasePointOrderHex[];
// This large prime p used to generate a group (Z_STAR_LARGE_P)
// is derived from https://tools.ietf.org/html/rfc3526#section-3
extern const uint32_t kDiffieHellmanGroup[];

// A list of the Groups currently supported.
enum class GroupType {
  UNKNOWN,
  Z,  // Integers. Instantiated by IntegerGroupElement.
  LARGE_Z,  // Large Integers. Instantiated by LargeIntegerGroupElement.
  Z_TWO,  // Integers mod 2. Instantiated by IntegerModTwoGroupElement.
  EDWARDS_CURVE,  // Edwards Curve
  Z_N,  // Integers mod N, for N of type uint64_t.
  // Instantiated by IntegerModNGroupElement.
  // The modulus 'N' will be stored in the modulus_ field.
  Z_LARGE_N,  // Integers mod N, for N of type LargeInt.
  // Instantiated by IntegerModLargeNGroupElement.
  // The modulus 'N' will be stored in the modulus_ field.
  Z_STAR_P,  // Multiplicate group Z*_P, for P of type uint64_t.
  // Instantiated by MultiplicativeIntegersModPGroupElement.
  // The prime modulus 'P' is stored in the modulus_ field
  Z_STAR_LARGE_P,  // Same as above, but for P of type LargeInt.
  // Instantiated by MultiplicativeIntegersModLargePGroupElement.
  // The prime modulus 'P' is stored in the modulus_ field
  DIRECT_PRODUCT,  // G x H, where G and H each have their own Group Types.
  // Instantiated by DirectProductGroupElement.
  // Note that G^n can be instantiated by n-1 DIRECT_PRODUCT
  // groups, e.g. G x (G x (G x (... x G) ... ))
  // TODO(PHB): Implement the following Groups:
  // RATIONALS  // Model an element by a int64_t numerator_ and denominator_
  // LARGE_RATIONALS  // Same as above for LargeInt instead of [u]int64_t.
  // IRRATIONALS
  // REALS
  // COMPLEX
  // S_N  // Symmetric group (permutations)
  // MATRIX // Matrices (fields for num rows, num columns, underlying GroupType
  //                     of entries, and a GroupElement for each entry)
};

// A Wrapper object to store the underlying values of each GroupType.
// Used for generic API's, so that all GroupTypes can have a common function
// that takes in a parameter of this type.
// TODO(PHB): It is expensive/wasteful (memory) to store all possible data types.
// Consider having a single field here, e.g. (a unique pointer to) a struct
// 'GenericGroupValueType', which itself has multiple instantiating children,
// each of which instantiates it for the desired data type (bool, int64, LargeInt,
// and two pointers for the DIRECT_PRODCUT case); then have a templated
// 'GetValue()' helper function that returns the appropriate (data type) value;
// see GenericDataType and GetValue() in data_structures.h as a template for
// how this could be done.
// UPDATE: Note that savings here are likely just for memory (e.g. not computation
// or even run-time), as updating GenericValue in the above described manner
// did not have any noticeable impact on run-time of the various unit tests
// (e.g. standard_circuit_test.exe and gmw_circuit_test.exe); so this change
// is likely only relevant if there is a use-case where memory becomes an issue...
struct GroupValueType {
  bool bool_value_;  // For GroupType::Z_TWO
  int64_t int64_value_;  // For GroupType::Z
  uint64_t uint64_value_;  // For GroupType::Z_N, Z_STAR_P
  LargeInt large_int_value_;  // For GroupType::Z_LARGE_N, Z_STAR_LARGE_P
  std::pair<LargeInt, LargeInt> ell_value_;  // For GroupType::EDWARDS_CURVE
  std::unique_ptr<GroupValueType>
      left_group_value_;  // For GroupType::DIRECT_PRODUCT
  std::unique_ptr<GroupValueType>
      right_group_value_;  // For GroupType::DIRECT_PRODUCT

  GroupValueType() {
    bool_value_ = false;
    int64_value_ = 0;
    uint64_value_ = 0;
    ell_value_ = std::make_pair(LargeInt::Zero(), LargeInt::One());
    large_int_value_ = LargeInt::Zero();
    left_group_value_ = nullptr;
    right_group_value_ = nullptr;
  }

  // Copy-Constructor.
  GroupValueType(const GroupValueType& other) {
    bool_value_ = other.bool_value_;
    int64_value_ = other.int64_value_;
    uint64_value_ = other.uint64_value_;
    ell_value_ = other.ell_value_;
    large_int_value_ = other.large_int_value_;
    if (other.left_group_value_ != nullptr) {
      left_group_value_.reset(new GroupValueType(*(other.left_group_value_)));
    }
    if (other.right_group_value_ != nullptr) {
      right_group_value_.reset(new GroupValueType(*(other.right_group_value_)));
    }
  }

  // Move-Constructor.
  GroupValueType(GroupValueType&& other) :
      left_group_value_(std::move(other.left_group_value_)),
      right_group_value_(std::move(other.right_group_value_)) {
    bool_value_ = other.bool_value_;
    int64_value_ = other.int64_value_;
    uint64_value_ = other.uint64_value_;
    ell_value_ = other.ell_value_;
    large_int_value_ = other.large_int_value_;
  }

  // Destructor.
  ~GroupValueType() noexcept {}

  // Copy-Assignment.
  GroupValueType& operator=(const GroupValueType& other) {
    GroupValueType temp(other);  // Re-use copy constructor.
    *this = std::move(temp);  // Re-use Move-Assignment.
    return *this;
  }

  // Move-Assignment.
  GroupValueType& operator=(GroupValueType&& other) {
    bool_value_ = other.bool_value_;
    int64_value_ = other.int64_value_;
    uint64_value_ = other.uint64_value_;
    ell_value_ = other.ell_value_;
    large_int_value_ = other.large_int_value_;
    if (other.left_group_value_ != nullptr) {
      left_group_value_ = std::move(other.left_group_value_);
    }
    if (other.right_group_value_ != nullptr) {
      right_group_value_ = std::move(other.left_group_value_);
    }
    return *this;
  }

  explicit GroupValueType(const bool value) {
    bool_value_ = value;
    int64_value_ = 0;
    uint64_value_ = 0;
    ell_value_ = std::make_pair(LargeInt::Zero(), LargeInt::One());
    large_int_value_ = LargeInt::Zero();
    left_group_value_ = nullptr;
    right_group_value_ = nullptr;
  }

  explicit GroupValueType(const int64_t& value) {
    bool_value_ = false;
    int64_value_ = value;
    uint64_value_ = 0;
    ell_value_ = std::make_pair(LargeInt::Zero(), LargeInt::One());
    large_int_value_ = LargeInt::Zero();
    left_group_value_ = nullptr;
    right_group_value_ = nullptr;
  }

  explicit GroupValueType(const uint64_t& value) {
    bool_value_ = false;
    int64_value_ = 0;
    uint64_value_ = value;
    ell_value_ = std::make_pair(LargeInt::Zero(), LargeInt::One());
    large_int_value_ = LargeInt::Zero();
    left_group_value_ = nullptr;
    right_group_value_ = nullptr;
  }

  explicit GroupValueType(const std::pair<LargeInt, LargeInt>& value) {
    bool_value_ = false;
    int64_value_ = 0;
    uint64_value_ = 0;
    ell_value_ = value;
    large_int_value_ = LargeInt::Zero();
    left_group_value_ = nullptr;
    right_group_value_ = nullptr;
  }

  explicit GroupValueType(const LargeInt& value) {
    bool_value_ = false;
    int64_value_ = 0;
    uint64_value_ = 0;
    ell_value_ = std::make_pair(LargeInt::Zero(), LargeInt::One());
    large_int_value_ = value;
    left_group_value_ = nullptr;
    right_group_value_ = nullptr;
  }

  explicit GroupValueType(
      const GroupValueType& left, const GroupValueType& right) {
    bool_value_ = false;
    int64_value_ = 0;
    uint64_value_ = 0;
    ell_value_ = std::make_pair(LargeInt::Zero(), LargeInt::One());
    large_int_value_ = LargeInt::Zero();
    left_group_value_.reset(new GroupValueType(left));
    right_group_value_.reset(new GroupValueType(right));
  }
};

// The fields needed to create an empty/default group element. For some of
// the above GroupTypes, this just specifies the GroupType; while for those
// needing a modulus, it also stores the modulus (in the appropriate type).
struct GroupProperties {
  // All GroupProperties objects should have the following field.
  GroupType type_;

  GroupProperties() { type_ = GroupType::UNKNOWN; }
  explicit GroupProperties(const GroupType type) { type_ = type; }

  // Copy-Constructor.
  GroupProperties(const GroupProperties& other) { type_ = other.type_; }

  // Move constructor.
  GroupProperties(GroupProperties&& other) noexcept { type_ = other.type_; }

  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~GroupProperties() noexcept {}

  // Copy-Assignment.
  GroupProperties& operator=(const GroupProperties& other) {
    GroupProperties temp(other);  // Re-use Copy-Constructor.
    *this = std::move(temp);  // Re-use Move-Assignment.
    return *this;
  }

  // Move-Assignment.
  GroupProperties& operator=(GroupProperties&& other) noexcept {
    type_ = other.type_;
    return *this;
  }

  // Print.
  std::string Print() { return Print(""); }
  std::string Print(const std::string& indent) {
    std::string to_return = indent + "{\n" + indent + "  type_: ";
    to_return += string_utils::Itoa(static_cast<int>(type_)) + "\n";
    to_return += indent + "}\n";
    return to_return;
  }
};

// Returns a new (on the heap) pointer to a copy of the passed-in GroupProperties
// object. In particular, if 'orig' is of an inherited class
// (e.g. ModulusGroupProperties), then the returned pointer will also be that class.
extern GroupProperties* CreateNewCopy(const GroupProperties* orig);

struct ModulusGroupProperties : public GroupProperties {
  // GroupTypes Z_N and Z_STAR_P should have the following field.
  uint64_t modulus_;

  ModulusGroupProperties() : GroupProperties() { modulus_ = 0; }
  explicit ModulusGroupProperties(const uint64_t& modulus) {
    type_ = GroupType::UNKNOWN;
    modulus_ = modulus;
  }
  // Constructor with Type (e.g. GroupTypes Z_N or Z_STAR_P).
  ModulusGroupProperties(const GroupType type, const uint64_t& modulus) {
    type_ = type;
    modulus_ = modulus;
  }

  // Copy-Constructor.
  ModulusGroupProperties(const ModulusGroupProperties& other) :
      GroupProperties() {
    type_ = other.type_;
    modulus_ = other.modulus_;
  }

  // Move constructor.
  ModulusGroupProperties(ModulusGroupProperties&& other) noexcept {
    type_ = other.type_;
    modulus_ = other.modulus_;
  }

  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~ModulusGroupProperties() noexcept {}

  // Copy-Assignment.
  ModulusGroupProperties& operator=(const ModulusGroupProperties& other) {
    ModulusGroupProperties temp(other);  // Re-use Copy-Constructor.
    *this = std::move(temp);  // Re-use Move-Assignment.
    return *this;
  }

  // Move-Assignment.
  ModulusGroupProperties& operator=(ModulusGroupProperties&& other) noexcept {
    type_ = other.type_;
    modulus_ = other.modulus_;
    return *this;
  }

  // Print.
  std::string Print() { return Print(""); }
  std::string Print(const std::string& indent) {
    std::string to_return = indent + "{\n" + indent + "  type_: ";
    to_return += string_utils::Itoa(static_cast<int>(type_)) + "\n";
    to_return += indent + "  modulus_: ";
    to_return += string_utils::Itoa(modulus_) + "\n";
    to_return += indent + "}\n";
    return to_return;
  }
};

struct LargeModulusGroupProperties : public GroupProperties {
  // GroupTypes Z_LARGE_N and Z_STAR_LARGE_P should have the following field.
  LargeInt modulus_;

  LargeModulusGroupProperties() : GroupProperties() {
    modulus_ = LargeInt::Zero();
  }
  explicit LargeModulusGroupProperties(const LargeInt& modulus) {
    type_ = GroupType::UNKNOWN;
    modulus_ = modulus;
  }
  // Constructor with Type (e.g. GroupTypes Z_LARGE_N or Z_STAR_LARGE_P).
  LargeModulusGroupProperties(const GroupType type, const LargeInt& modulus) {
    type_ = type;
    modulus_ = modulus;
  }

  // Copy-Constructor.
  LargeModulusGroupProperties(const LargeModulusGroupProperties& other) :
      GroupProperties() {
    type_ = other.type_;
    modulus_ = other.modulus_;
  }

  // Move constructor.
  LargeModulusGroupProperties(LargeModulusGroupProperties&& other) noexcept {
    type_ = other.type_;
    modulus_ = other.modulus_;
  }

  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~LargeModulusGroupProperties() noexcept {}

  // Copy-Assignment.
  LargeModulusGroupProperties& operator=(
      const LargeModulusGroupProperties& other) {
    LargeModulusGroupProperties temp(other);  // Re-use Copy-Constructor.
    *this = std::move(temp);  // Re-use Move-Assignment.
    return *this;
  }

  // Move-Assignment.
  LargeModulusGroupProperties& operator=(
      LargeModulusGroupProperties&& other) noexcept {
    type_ = other.type_;
    modulus_ = other.modulus_;
    return *this;
  }

  // Print.
  std::string Print() { return Print(""); }
  std::string Print(const std::string& indent) {
    std::string to_return = indent + "{\n" + indent + "  type_: ";
    to_return += string_utils::Itoa(static_cast<int>(type_)) + "\n";
    to_return += indent + "  modulus_: ";
    to_return += modulus_.Print() + "\n";
    to_return += indent + "}\n";
    return to_return;
  }
};

struct EdwardsCurveGroupProperties : public GroupProperties {
  // GroupType EdwardsCurve should have the following fields.
  LargeInt modulus_;
  LargeInt a_;
  LargeInt d_;
  // TODO(mark): Consider supporting these in the future.
  //LargeInt group_order_;
  //LargeInt cyclic_subgroup_order_;

  /** TODO(mark): What is a good default value for modulus and
   *   for d \notin {0, 1}?
   **/
  EdwardsCurveGroupProperties() : GroupProperties() {
    type_ = GroupType::EDWARDS_CURVE;
    modulus_ = LargeInt(5);
    a_ = LargeInt::One();
    d_ = LargeInt(2);
  }

  // TODO(mark): Add check to see if discriminant of curve is non-zero
  EdwardsCurveGroupProperties(
      const LargeInt& modulus, const LargeInt& a, const LargeInt& d) {
    type_ = GroupType::EDWARDS_CURVE;
    modulus_ = modulus;
    a_ = a % modulus;
    d_ = d % modulus;
  }

  // Copy-Constructor.
  explicit EdwardsCurveGroupProperties(
      const EdwardsCurveGroupProperties& other) :
      GroupProperties() {
    type_ = other.type_;
    modulus_ = other.modulus_;
    a_ = other.a_;
    d_ = other.d_;
  }

  // Move constructor.
  explicit EdwardsCurveGroupProperties(
      EdwardsCurveGroupProperties&& other) noexcept {
    type_ = other.type_;
    modulus_ = other.modulus_;
    a_ = other.a_;
    d_ = other.d_;
  }

  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~EdwardsCurveGroupProperties() noexcept {}

  // Copy-Assignment.
  EdwardsCurveGroupProperties& operator=(
      const EdwardsCurveGroupProperties& other) {
    EdwardsCurveGroupProperties temp(other);  // Re-use Copy-Constructor.
    *this = std::move(temp);  // Re-use Move-Assignment.
    return *this;
  }

  // Move-Assignment.
  EdwardsCurveGroupProperties& operator=(
      EdwardsCurveGroupProperties&& other) noexcept {
    type_ = other.type_;
    modulus_ = other.modulus_;
    a_ = other.a_;
    d_ = other.d_;
    return *this;
  }

  // Print.
  std::string Print() { return Print(""); }
  std::string Print(const std::string& indent) {
    std::string to_return = indent + "{\n" + indent + "  type_: ";
    to_return += string_utils::Itoa(static_cast<int>(type_)) + "\n";
    to_return += indent + "  modulus_: ";
    to_return += modulus_.Print() + "\n";
    to_return += indent + "  Curve Parameters: (a, d) = (";
    to_return += a_.Print() + ", " + d_.Print() + ")";
    to_return += indent + "}\n";
    return to_return;
  }
};

struct DirectProductGroupProperties : public GroupProperties {
  // GroupType DIRECT_PRODUCT should have the following two fields.
  std::unique_ptr<GroupProperties> subgroup_one_;
  std::unique_ptr<GroupProperties> subgroup_two_;

  DirectProductGroupProperties() : GroupProperties() {
    subgroup_one_ = nullptr;
    subgroup_two_ = nullptr;
  }

  // Copy-Constructor.
  DirectProductGroupProperties(const DirectProductGroupProperties& other) :
      GroupProperties() {
    type_ = other.type_;
    if (other.subgroup_one_ != nullptr) {
      subgroup_one_.reset(CreateNewCopy(other.subgroup_one_.get()));
    }
    if (other.subgroup_two_ != nullptr) {
      subgroup_two_.reset(CreateNewCopy(other.subgroup_two_.get()));
    }
  }

  // Move constructor.
  DirectProductGroupProperties(DirectProductGroupProperties&& other) noexcept {
    type_ = other.type_;
    if (other.subgroup_one_ != nullptr) {
      subgroup_one_.reset(other.subgroup_one_.release());
    }
    if (other.subgroup_two_ != nullptr) {
      subgroup_two_.reset(other.subgroup_two_.release());
    }
  }

  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~DirectProductGroupProperties() noexcept {}

  // Copy-Assignment.
  DirectProductGroupProperties& operator=(
      const DirectProductGroupProperties& other) {
    DirectProductGroupProperties temp(other);  // Re-use Copy-Constructor.
    *this = std::move(temp);  // Re-use Move-Assignment.
    return *this;
  }

  // Move-Assignment.
  DirectProductGroupProperties& operator=(
      DirectProductGroupProperties&& other) noexcept {
    type_ = other.type_;
    if (other.subgroup_one_ != nullptr) {
      subgroup_one_.reset(other.subgroup_one_.release());
    } else {
      subgroup_one_ = nullptr;
    }
    if (other.subgroup_two_ != nullptr) {
      subgroup_two_.reset(other.subgroup_two_.release());
    } else {
      subgroup_two_ = nullptr;
    }
    return *this;
  }

  // Constructor for GroupType DIRECT_PRODUCT.
  DirectProductGroupProperties(
      const GroupProperties& subgroup_one, const GroupProperties& subgroup_two) {
    type_ = GroupType::DIRECT_PRODUCT;
    subgroup_one_.reset(CreateNewCopy(&subgroup_one));
    subgroup_two_.reset(CreateNewCopy(&subgroup_two));
  }

  // Print.
  std::string Print() { return Print(""); }
  std::string Print(const std::string& indent) {
    std::string to_return = indent + "{\n" + indent + "  type_: ";
    to_return += string_utils::Itoa(static_cast<int>(type_)) + "\n";
    if (subgroup_one_ != nullptr) {
      to_return += indent + "  subgroup_one_:\n";
      to_return += subgroup_one_->Print(indent + "  ");
    }
    if (subgroup_two_ != nullptr) {
      to_return += indent + "  subgroup_two_:\n";
      to_return += subgroup_two_->Print(indent + "  ");
    }
    to_return += indent + "}\n";
    return to_return;
  }
};

// Forward declare GroupElement, so it can be used as a field of GroupOperationHolder.
class GroupElement;
// This is the return type for +,-,* operators. It is a temporary storage container,
// used until the object gets assigned to a GroupElement.
// The 'element_' field is a pointer to dynamic memory (on the heap), and as such,
// when this object is used, this memory should be deleted.
struct GroupOperationHolder {
  GroupElement* element_;

  GroupOperationHolder() { element_ = nullptr; }
};

// Virtual base class for all group elements.
// All functions are purely virtual, so this is an abstract base class (i.e.
// a specific instantiation via one of the inheriting classes must be created
// in order to actually use anything).
// NOTE: I considered making this a templated class, so that I could have
// "T value_" as a member variable of the abstract base class, and then each
// instantiating class sets T appropriately. However, I couldn't get this to
// work, as the desired API of being able to do:
//   void foo(const GroupElement& a, ...) { ... }
// doesn't work, as it will complain that GroupElement's type cannot be deduced
// (C++ allows deducing template types for functions, but not Classes).
class GroupElement {
public:
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~GroupElement() noexcept = 0;

  // Overload '+=' operator.
  // For API (2) to add one group element to another (see discussion at top).
  virtual GroupElement& operator+=(const GroupElement& other) = 0;
  // For API (2), where RHS is an expression involving adding/subtracting/multiplying
  // GroupElements (and in particular, one or more of the overloaded +,-,* operators
  // at the end of this file are called).
  // The other->element_ field should be deleted within all instantiating functions.
  virtual GroupElement& operator+=(GroupOperationHolder other) = 0;
  // Overload '-=' operator.
  // For API (2) to subtract one group element from another (see discussion at top).
  virtual GroupElement& operator-=(const GroupElement& other) = 0;
  // For API (2), where RHS is an expression involving adding/subtracting/multiplying
  // GroupElements (and in particular, one or more of the overloaded +,-,* operators
  // at the end of this file are called).
  // The other->element_ field should be deleted within all instantiating functions.
  virtual GroupElement& operator-=(GroupOperationHolder other) = 0;
  // Overload '*=' operator.
  // For API (2) to apply the group operation to itself n = RHS times (see discussion at top).
  virtual GroupElement& operator*=(const int32_t n) = 0;
  virtual GroupElement& operator*=(const uint32_t n) = 0;
  virtual GroupElement& operator*=(const int64_t& n) = 0;
  virtual GroupElement& operator*=(const uint64_t& n) = 0;
  virtual GroupElement& operator*=(const LargeInt& n) = 0;

  // We overload '=' operator in order to get '+' working correctly, so that:
  //   *c = a + b
  // works. See the lengthy discussion above the operator+ function at the
  // bottom of this file.
  // Note that the rule of 5 need not be followed here, as the function below is
  // not an overload of the ordinary '=' operator, since the input argument is a
  // *pointer* to a GroupElement, as opposed to a GroupElement or GroupElement&
  // (plus, the Rule of 5 can't be followed here anyway, since we want to make
  // this class abstract, but c++ forbids virtual Constructors).
  virtual GroupElement& operator=(GroupOperationHolder other) = 0;

  // Note: We cannot overload the standard 'GroupElement::operator+', which takes in a
  // single argument (the thing to add to 'this') for the following reasons
  // (this is why we overload the non-member function operator+, which has two
  // arguments; see the definition of this function at the bottom of the file):
  //   1) Desired API:
  //        virtual GroupElement operator+(const GroupElement& other) = 0;
  //      will fail, because the return value must either be by reference
  //      (GroupElement&) or a pointer (GroupElement*), because the
  //      GroupElement class is pure virtual (abstract). Of course, I could
  //      make this class non-abstract (by not using '= 0' for the
  //      '+=' overload and the Add() function below), but this not only has
  //      the drawback of not releflecting what GroupElement is supposed to
  //      be (namely, an abstract class, not meant to be an instantiation on
  //      its own); but more importantly, it doesn't solve the larger problem:
  //      what GroupElement should be returned? See point 3 below.
  //   2) Trying to make the overload of '+' a non-member function, e.g. via:
  //        friend GroupElement operator+(GroupElement a, const GroupElement& b)
  //      won't work, again because GroupElement is pure virtual. Trying to
  //      hack around this by modifying the API above could be done by making
  //      the returned GroupElement, as well as the first GroupElement input 'a',
  //      as either pointers or references to existing GroupElement objects. But
  //      in either case, we still are faced with the issue in point 3 below.
  //   3) The main problem here lies in what gets returned by '+'. We cannot
  //      create an object of the appropriate instatiating class, because: a) we
  //      don't know which GroupType to instantiate to; and b) even if we did, we
  //      haven't yet defined any instantiating classes. Note that issue (a)
  //      could be solved by toggling what GroupType object gets creating by
  //      switching based on type_, and (b) could be overcome by not using a
  //      member function here, but instead defining a utility, non-member function
  //      at the bottom of the file (after all instantiating classes have been
  //      defined); ultimately, this is what is done.
  //      Two further points: First, making GroupElement non-abstract, and returning a
  //      GroupElement object from '+' overload is not what we want, since the
  //      caller will have no way to reconstruct an instance of the actual class;
  //      i.e. it won't be possible to cast that object as the appropriate type.
  //      Second, another alternative to creating the GroupElement that gets
  //      returned by '+' operator would be to use something that was passed-in,
  //      and then we can use the fact that the passed-in object already has
  //      the correct type. But regardless of how this is done (via pointer or
  //      passing by reference), the passed-in object will be modified, and then
  //      we might as well use the += API above. In other words, this approach
  //      wouldn't really be implementing the desired '+' overload.
  // Side Note: See http://en.cppreference.com/w/cpp/language/operators for a
  // decent discussion on overloading operators.

  // Sets this->value_ to: a + b.
  virtual void Add(const GroupElement& a, const GroupElement& b) = 0;
  // Sets this->value_ to: a - b.
  virtual void Subtract(const GroupElement& a, const GroupElement& b) = 0;
  // Sets this->value_ to: a * b.
  virtual void Multiply(const int32_t a, const GroupElement& b) = 0;
  virtual void Multiply(const uint32_t a, const GroupElement& b) = 0;
  virtual void Multiply(const int64_t& a, const GroupElement& b) = 0;
  virtual void Multiply(const uint64_t& a, const GroupElement& b) = 0;
  // Needed only for the groups supporting LargeInt.
  // We don't make it pure- virtual, so that the Group types that don't
  // need to support it don't have to.
  virtual void Multiply(const LargeInt& a, const GroupElement& b) = 0;
  // Sets this->value_ to: -(this->value_) (i.e. the inverse group element).
  virtual void Invert() = 0;

  virtual void SetValue(const GroupValueType& value) = 0;
  virtual GroupValueType GetValueType() const = 0;

  GroupType GetGroupType() const { return properties_->type_; }
  void SetGroupType(const GroupType type) { properties_->type_ = type; }
  void SetGroupProperties(const GroupProperties& properties);
  virtual const GroupProperties* GetConstProperties() const {
    return properties_.get();
  }

  // 'Encode' transforms value_ into a byte array. Memory is allocated to 'output'
  // within the function, so caller is responsible to free memory when done
  // (the number of bytes allocated/represented by value_ is stored in 'num_bytes').
  virtual bool Encode(uint64_t* num_bytes, unsigned char** output) const = 0;

  // value_ is updated to be the value represented by 'input'.
  // Here, 'represented by' refers to the appropriate Encoding type, i.e.
  // Decode(Encode(x)) = x.
  virtual bool Decode(const uint64_t& num_bytes, const unsigned char* input) = 0;

protected:
  // Instantiations of GroupElement may want to have additional properties than
  // those that are available in the default GroupProperties struct (which just
  // has 'type'); e.g. the modulus N for Z_N. For such instantiations, I would
  // actually want the 'properties_' member variable to have a different type,
  // e.g. the type of another struct (which e.g. includes both a type_ as well
  // as a modulus_ field). Unfortunately, overloading the type of a member
  // variable is not possible in C++. This leaves four options:
  //   1) Have GroupProperties include *all* fields that are ever used by *all*
  //      instantiating classes of GroupElement
  //   2) Have 'properties_' be a pointer to GroupProperties (and then
  //      instantiating classes can have the pointer point to an extended/child
  //      struct of GroupProperties)
  //   3) Make GroupElement a templated class, and the 'properties_' field
  //      takes template parameter T.
  //   4) For the instantiations that require more member variables than
  //      'properties_' provides, they can "hide" the parent's properties_
  //      field and just define their own.
  // Option (1) is how the code originally worked, but this doesn't scale well
  // and is wasteful, plus it feels like bad design. Likewise, Option (4) is
  // not good design either (as well as be marginally wasteful). Option (3)
  // is probably naturally the best design, but having a purely virtual base
  // class that is templated is not ideal, and makes code messier to read/write.
  // Thus, we settled on Option (2).
  std::unique_ptr<GroupProperties> properties_;
  // Allow overridable access to properties_, so that inheriting types can
  // override properties_ with an extended type (e.g. ModulusGroupProperties).
  virtual GroupProperties* GetProperties() { return properties_.get(); }
};

// Constructs a (new) GroupElement (on the heap) that is the Identity element
// (of the appropriate GroupType).
// Caller takes ownership of the returned pointer.
// NOTE: Use this constructor with a smart pointer to avoid having to deal with
// memory maintainence.
extern GroupElement* CreateIdentityGroupElement(
    const GroupProperties& properties);
// Constructs a (new) GroupElement (on the heap) that is a copy of the input element.
// Caller takes ownership of the returned pointer.
// NOTE: Use this constructor with a smart pointer to avoid having to deal with
// memory maintainence.
extern GroupElement* CreateGroupElementCopy(const GroupElement& element);

// ============================ GroupType = Z (Integers) =======================
class IntegerGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  // Default Constructor.
  IntegerGroupElement() {
    value_ = 0;
    properties_.reset(new GroupProperties(GroupType::Z));
  }
  // Constructor specific to IntegerGroupElement.
  explicit IntegerGroupElement(const int64_t& value) {
    value_ = value;
    properties_.reset(new GroupProperties(GroupType::Z));
  }
  // Copy Constructor.
  IntegerGroupElement(const IntegerGroupElement& other) {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::Z));
  }
  // Copy Constructor (supports e.g.: IntegerGroupElement foo = a + b).
  IntegerGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((IntegerGroupElement*) other.element_)->GetValue();
    properties_.reset(new GroupProperties(GroupType::Z));
    delete other.element_;
  }
  // Move Constructor.
  IntegerGroupElement(IntegerGroupElement&& other) noexcept {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::Z));
  }
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~IntegerGroupElement() noexcept {}
  // Copy Assignement Operator.
  IntegerGroupElement& operator=(const IntegerGroupElement& other) {
    IntegerGroupElement temp(other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }
  // Move-Assignement Operator.
  IntegerGroupElement& operator=(IntegerGroupElement&& other) {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::Z));
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((IntegerGroupElement*) other.element_)->GetValue();
    properties_.reset(new GroupProperties(GroupType::Z));
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt&, const GroupElement&) {
    LOG_FATAL("Repeating group operation a LargeInt number of times is not "
              "supported for Group Integers.");
  }
  // Overload of GroupElement's Invert().
  void Invert();
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static IntegerGroupElement Identity() { return IntegerGroupElement(); }
  int64_t GetValue() const { return value_; }
  GroupValueType GetValueType() const { return GroupValueType(value_); }
  void SetValue(const int64_t& value) { value_ = value; }
  void SetValue(const GroupValueType& value) { value_ = value.int64_value_; }
  IntegerGroupElement Inverse() const;
  // ======================= END Generic Group Functions =======================

private:
  int64_t value_;
};

// ====================== GroupType = LARGE_Z (Large Integers) =================
class LargeIntegerGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  // Default Constructor.
  LargeIntegerGroupElement() {
    value_ = LargeInt::Zero();
    properties_.reset(new GroupProperties(GroupType::LARGE_Z));
  }
  // Constructor specific to LargeIntegerGroupElement.
  explicit LargeIntegerGroupElement(const LargeInt& value) {
    value_ = value;
    properties_.reset(new GroupProperties(GroupType::LARGE_Z));
  }
  // Copy Constructor.
  LargeIntegerGroupElement(const LargeIntegerGroupElement& other) {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::LARGE_Z));
  }
  // Copy Constructor (supports e.g.: LargeIntegerGroupElement foo = a + b).
  LargeIntegerGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::LARGE_Z) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((LargeIntegerGroupElement*) other.element_)->GetValue();
    properties_.reset(new GroupProperties(GroupType::LARGE_Z));
    delete other.element_;
  }
  // Move Constructor.
  LargeIntegerGroupElement(LargeIntegerGroupElement&& other) noexcept {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::LARGE_Z));
  }
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~LargeIntegerGroupElement() noexcept {}
  // Copy Assignement Operator.
  LargeIntegerGroupElement& operator=(const LargeIntegerGroupElement& other) {
    LargeIntegerGroupElement temp(other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }
  // Move-Assignement Operator.
  LargeIntegerGroupElement& operator=(LargeIntegerGroupElement&& other) {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::LARGE_Z));
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::LARGE_Z) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((LargeIntegerGroupElement*) other.element_)->GetValue();
    properties_.reset(new GroupProperties(GroupType::LARGE_Z));
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt& a, const GroupElement& b);
  // Overload of GroupElement's Invert().
  void Invert();
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static LargeIntegerGroupElement Identity() {
    return LargeIntegerGroupElement();
  }
  LargeInt GetValue() const { return value_; }
  GroupValueType GetValueType() const { return GroupValueType(value_); }
  void SetValue(const LargeInt& value) { value_ = value; }
  void SetValue(const GroupValueType& value) { value_ = value.large_int_value_; }
  LargeIntegerGroupElement Inverse() const;
  // ======================= END Generic Group Functions =======================

private:
  LargeInt value_;
};

// ================================ GroupType = Z_TWO ============================
class IntegerModTwoGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  // Default Constructor.
  IntegerModTwoGroupElement() {
    value_ = false;
    properties_.reset(new GroupProperties(GroupType::Z_TWO));
  }
  // Constructor specific to IntegerModTwoGroupElement.
  explicit IntegerModTwoGroupElement(const bool value) {
    value_ = value;
    properties_.reset(new GroupProperties(GroupType::Z_TWO));
  }
  // Copy Constructor.
  IntegerModTwoGroupElement(const IntegerModTwoGroupElement& other) {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::Z_TWO));
  }
  // Copy Constructor (supports e.g.: IntegerModTwoGroupElement foo = a + b).
  IntegerModTwoGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_TWO) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((IntegerModTwoGroupElement*) other.element_)->GetValue();
    properties_.reset(new GroupProperties(GroupType::Z_TWO));
    delete other.element_;
  }
  // Move Constructor.
  IntegerModTwoGroupElement(IntegerModTwoGroupElement&& other) noexcept {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::Z_TWO));
  }
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~IntegerModTwoGroupElement() noexcept {}
  // Copy Assignement Operator.
  IntegerModTwoGroupElement& operator=(const IntegerModTwoGroupElement& other) {
    IntegerModTwoGroupElement temp(other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }
  // Move-Assignement Operator.
  IntegerModTwoGroupElement& operator=(IntegerModTwoGroupElement&& other) {
    value_ = other.GetValue();
    properties_.reset(new GroupProperties(GroupType::Z_TWO));
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_TWO) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((IntegerModTwoGroupElement*) other.element_)->GetValue();
    properties_.reset(new GroupProperties(GroupType::Z_TWO));
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt&, const GroupElement&) {
    LOG_FATAL("Repeating group operation a LargeInt number of times is not "
              "supported for Group Integers Mod Two.");
  }
  // Overload of GroupElement's Invert().
  void Invert();
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static IntegerModTwoGroupElement Identity() {
    return IntegerModTwoGroupElement();
  }
  IntegerModTwoGroupElement Inverse() const;
  bool GetValue() const { return value_; }
  GroupValueType GetValueType() const { return GroupValueType(value_); }
  void SetValue(const bool value) { value_ = value; }
  void SetValue(const GroupValueType& value) { value_ = value.bool_value_; }
  // ======================= END Generic Group Functions =======================

  // =================== Z_2 specific functions ================================
  IntegerModTwoGroupElement Random() const;

private:
  bool value_;
};

// ================================ GroupType = Edwards Curve ==================

class EdwardsCurveGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  /**
   * The elements of the Curve are represented by pairs (x, y) in
   * (F_modulus)^2 satisfying a*x^2 + y^2 = 1 + d*x^2*y^2, where a, d
   * are elements of the field F_modulus. We currently do not support
   * the case where the base field is a prime power (i.e modulus = p^n
   * for some prime p and n > 1) or the case where modulus = 2 or 3.
   **/

  EdwardsCurveGroupElement(
      const LargeInt& modulus,
      const LargeInt& a,
      const LargeInt& d,
      const std::pair<LargeInt, LargeInt>& value) {
    if (!IsPrime(modulus)) {
      LOG_FATAL("Base modulus must be a prime.");
    }
    if ((modulus == LargeInt(2)) || (modulus == LargeInt(3))) {
      LOG_FATAL("Group implementation does not support a base field of "
                "characteristic equal to 2 or 3.");
    }
    // TODO(mark) replace this with extern function call
    if ((a * (value.first) * (value.first) + value.second * value.second - 1 -
         d * value.first * value.first * value.second * value.second) %
            modulus !=
        0) {
      LOG_FATAL("not a valid point");
    }
    EdwardsCurveGroupProperties to_copy;
    to_copy.modulus_ = modulus;
    to_copy.a_ = a;
    to_copy.d_ = d;
    SetGroupProperties(to_copy);
    value_ = value;
  }

  EdwardsCurveGroupElement(
      const LargeInt& modulus, const LargeInt& a, const LargeInt& d) :
      EdwardsCurveGroupElement(
          modulus, a, d, std::make_pair(LargeInt::Zero(), LargeInt::One())) {}

  // Default Constructor.
  // TODO(mblunk): What are good default values of a & d?
  explicit EdwardsCurveGroupElement(const LargeInt& modulus) :
      EdwardsCurveGroupElement(
          modulus,
          LargeInt::One(),
          LargeInt(2),
          std::make_pair(LargeInt::Zero(), LargeInt::One())) {}

  // Copy Constructor.
  explicit EdwardsCurveGroupElement(const EdwardsCurveGroupElement& other) {
    value_ = other.GetValue();
    SetGroupProperties(*other.GetConstProperties());
  }

  // Copy Constructor (supports e.g.: EdwardsCurveGroupElement foo = a + b).
  EdwardsCurveGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::EDWARDS_CURVE) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((EdwardsCurveGroupElement*) other.element_)->GetValue();
    SetGroupProperties(
        *(((EdwardsCurveGroupElement*) other.element_)->GetConstProperties()));
    delete other.element_;
  }

  // Move Constructor.
  EdwardsCurveGroupElement(EdwardsCurveGroupElement&& other) noexcept {
    value_ = other.GetValue();
    SetGroupProperties(*other.GetConstProperties());
  }

  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~EdwardsCurveGroupElement() noexcept {}
  // Copy Assignement Operator.
  EdwardsCurveGroupElement& operator=(const EdwardsCurveGroupElement& other) {
    EdwardsCurveGroupElement temp(other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }

  // Move-Assignement Operator.
  EdwardsCurveGroupElement& operator=(EdwardsCurveGroupElement&& other) {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::EDWARDS_CURVE) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((EdwardsCurveGroupElement*) other.element_)->GetValue();
    SetGroupProperties(
        *((EdwardsCurveGroupElement*) other.element_)->GetConstProperties());
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt& a, const GroupElement& b);

  // Overload of GroupElement's Invert().
  void Invert();
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static EdwardsCurveGroupElement Identity(
      const LargeInt& modulus, const LargeInt& a, const LargeInt& d) {
    return EdwardsCurveGroupElement(modulus, a, d);
  }

  EdwardsCurveGroupElement Inverse() const;
  std::pair<LargeInt, LargeInt> GetValue() const { return value_; }
  GroupValueType GetValueType() const { return GroupValueType(value_); }
  void SetValue(const std::pair<LargeInt, LargeInt> value) { value_ = value; }
  void SetValue(const GroupValueType& value) { value_ = value.ell_value_; }

  // ======================= END Generic Group Functions =======================

  // =================== Edwards Curve specific functions ======================

  /**
   * Return the order of the underlying Field F_p (i.e. p) of the Edwards Curve.
   */
  LargeInt GetModulus() const {
    return ((const EdwardsCurveGroupProperties*) GetConstProperties())->modulus_;
  }

  LargeInt GetA() const {
    return ((const EdwardsCurveGroupProperties*) GetConstProperties())->a_;
  }

  LargeInt GetD() const {
    return ((const EdwardsCurveGroupProperties*) GetConstProperties())->d_;
  }

private:
  std::pair<LargeInt, LargeInt> value_;
};

// ============================ GroupType = Z_N ================================
class IntegerModNGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  // Default Constructor.
  explicit IntegerModNGroupElement(const uint64_t& modulus) {
    ModulusGroupProperties to_copy;
    to_copy.type_ = GroupType::Z_N;
    to_copy.modulus_ = modulus;
    SetGroupProperties(to_copy);
    value_ = 0;
  }
  // Constructor specific to IntegerModNGroupElement.
  IntegerModNGroupElement(const uint64_t& modulus, const uint64_t& value) {
    ModulusGroupProperties to_copy;
    to_copy.type_ = GroupType::Z_N;
    to_copy.modulus_ = modulus;
    SetGroupProperties(to_copy);
    value_ = value % modulus;
  }
  // Copy Constructor.
  IntegerModNGroupElement(const IntegerModNGroupElement& other) {
    value_ = other.GetValue();
    SetGroupProperties(*other.GetConstProperties());
  }
  // Copy Constructor (supports e.g.: IntegerModNGroupElement foo = a + b).
  IntegerModNGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_N) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((IntegerModNGroupElement*) other.element_)->GetValue();
    SetGroupProperties(
        *(((IntegerModNGroupElement*) other.element_)->GetConstProperties()));
    delete other.element_;
  }
  // Move Constructor.
  IntegerModNGroupElement(IntegerModNGroupElement&& other) noexcept {
    value_ = other.GetValue();
    SetGroupProperties(*other.GetConstProperties());
  }
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~IntegerModNGroupElement() noexcept {}
  // Copy Assignement Operator.
  IntegerModNGroupElement& operator=(const IntegerModNGroupElement& other) {
    IntegerModNGroupElement temp(other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }
  // Move-Assignement Operator.
  IntegerModNGroupElement& operator=(IntegerModNGroupElement&& other) {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_N) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((IntegerModNGroupElement*) other.element_)->GetValue();
    SetGroupProperties(
        *((IntegerModNGroupElement*) other.element_)->GetConstProperties());
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt&, const GroupElement&) {
    LOG_FATAL("Repeating group operation a LargeInt number of times is not "
              "supported for Group Integers Mod N.");
  }
  // Overload of GroupElement's Invert().
  void Invert();
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static IntegerModNGroupElement Identity(const uint64_t& modulus) {
    return IntegerModNGroupElement(modulus);
  }
  IntegerModNGroupElement Inverse() const;
  uint64_t GetValue() const { return value_; }
  GroupValueType GetValueType() const { return GroupValueType(value_); }
  void SetValue(const uint64_t& value) { value_ = value % GetModulus(); }
  void SetValue(const GroupValueType& value) {
    value_ = value.uint64_value_ % GetModulus();
  }
  // ======================= END Generic Group Functions =======================

  void SetModulus(const uint64_t& modulus) {
    ((ModulusGroupProperties*) GetProperties())->modulus_ = modulus;
  }
  uint64_t GetModulus() const {
    return ((const ModulusGroupProperties*) GetConstProperties())->modulus_;
  }
  IntegerModNGroupElement Random() const;

private:
  uint64_t value_;
};

// ================== GroupType = Z_LARGE_N (Z_N for N = LargeInt) =============
class IntegerModLargeNGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  // Default Constructor.
  explicit IntegerModLargeNGroupElement(const LargeInt& modulus) {
    LargeModulusGroupProperties to_copy;
    to_copy.type_ = GroupType::Z_LARGE_N;
    to_copy.modulus_ = modulus;
    SetGroupProperties(to_copy);
    value_ = LargeInt::Zero();
  }
  // Constructor specific to IntegerModLargeNGroupElement.
  IntegerModLargeNGroupElement(const LargeInt& modulus, const LargeInt& value) {
    LargeModulusGroupProperties to_copy;
    to_copy.type_ = GroupType::Z_LARGE_N;
    to_copy.modulus_ = modulus;
    SetGroupProperties(to_copy);
    value_ = value >= 0 ? value % modulus : abs(value) % modulus;
    if (value < 0) value_ = modulus - value_;
  }
  // Copy Constructor.
  IntegerModLargeNGroupElement(const IntegerModLargeNGroupElement& other) {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
  }
  // Copy Constructor (supports e.g.: IntegerModLargeNGroupElement foo = a + b).
  IntegerModLargeNGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_LARGE_N) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((IntegerModLargeNGroupElement*) other.element_)->GetValue();
    SetGroupProperties(
        *((IntegerModLargeNGroupElement*) other.element_)->GetConstProperties());
    delete other.element_;
  }
  // Move Constructor.
  IntegerModLargeNGroupElement(IntegerModLargeNGroupElement&& other) noexcept {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
  }
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~IntegerModLargeNGroupElement() noexcept {}
  // Copy Assignement Operator.
  IntegerModLargeNGroupElement& operator=(
      const IntegerModLargeNGroupElement& other) {
    IntegerModLargeNGroupElement temp(other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }
  // Move-Assignement Operator.
  IntegerModLargeNGroupElement& operator=(IntegerModLargeNGroupElement&& other) {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_LARGE_N) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((IntegerModLargeNGroupElement*) other.element_)->GetValue();
    SetGroupProperties(
        *((IntegerModLargeNGroupElement*) other.element_)->GetConstProperties());
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt& a, const GroupElement& b);
  // Overload of GroupElement's Invert().
  void Invert();
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static IntegerModLargeNGroupElement Identity(const LargeInt& modulus) {
    return IntegerModLargeNGroupElement(modulus);
  }
  IntegerModLargeNGroupElement Inverse() const;
  LargeInt GetValue() const { return value_; }
  GroupValueType GetValueType() const { return GroupValueType(value_); }
  void SetValue(const LargeInt& value) {
    value_ = value >= 0 ? value % GetModulus() : abs(value) % GetModulus();
    if (value < 0) value_ = GetModulus() - value_;
  }
  void SetValue(const GroupValueType& value) {
    value_ = value.large_int_value_ >= 0 ?
        value.large_int_value_ % GetModulus() :
        abs(value.large_int_value_) % GetModulus();
    if (value.large_int_value_ < 0) value_ = GetModulus() - value_;
  }
  // ======================= END Generic Group Functions =======================

  void SetModulus(const LargeInt& modulus) {
    ((LargeModulusGroupProperties*) GetProperties())->modulus_ = modulus;
  }
  LargeInt GetModulus() const {
    return ((const LargeModulusGroupProperties*) GetConstProperties())->modulus_;
  }
  IntegerModLargeNGroupElement Random() const;

private:
  LargeInt value_;
};

// ============================ GroupType = Z*_p ===============================
class MultiplicativeIntegersModPGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  // Default Constructor.
  explicit MultiplicativeIntegersModPGroupElement(const uint64_t& modulus) {
    // Check modulus is prime.
    if (!IsPrime(LargeInt(modulus))) {
      LOG_FATAL(
          "Unable to create Z*_p for non-prime p: " +
          string_utils::Itoa(modulus));
    }
    ModulusGroupProperties to_copy;
    to_copy.type_ = GroupType::Z_STAR_P;
    to_copy.modulus_ = modulus;
    SetGroupProperties(to_copy);
    value_ = 1;
  }
  // Constructor specific to MultiplicativeIntegersModPGroupElement.
  MultiplicativeIntegersModPGroupElement(
      const uint64_t& modulus, const uint64_t& value) {
    // Check modulus is prime.
    if (!IsPrime(LargeInt(modulus))) {
      LOG_FATAL(
          "Unable to create Z*_p for non-prime p: " +
          string_utils::Itoa(modulus));
    }
    ModulusGroupProperties to_copy;
    to_copy.type_ = GroupType::Z_STAR_P;
    to_copy.modulus_ = modulus;
    SetGroupProperties(to_copy);
    value_ = value % modulus;
  }
  // Copy Constructor.
  MultiplicativeIntegersModPGroupElement(
      const MultiplicativeIntegersModPGroupElement& other) {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
  }
  // Copy Constructor (supports e.g.: MultiplicativeIntegersModPGroupElement foo = a + b).
  MultiplicativeIntegersModPGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_STAR_P) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ =
        ((MultiplicativeIntegersModPGroupElement*) other.element_)->GetValue();
    SetGroupProperties(
        *((MultiplicativeIntegersModPGroupElement*) other.element_)
             ->GetConstProperties());
    delete other.element_;
  }
  // Move Constructor.
  MultiplicativeIntegersModPGroupElement(
      MultiplicativeIntegersModPGroupElement&& other) noexcept {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
  }
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~MultiplicativeIntegersModPGroupElement() noexcept {}
  // Copy Assignement Operator.
  MultiplicativeIntegersModPGroupElement& operator=(
      const MultiplicativeIntegersModPGroupElement& other) {
    MultiplicativeIntegersModPGroupElement temp(other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }
  // Move-Assignement Operator.
  MultiplicativeIntegersModPGroupElement& operator=(
      MultiplicativeIntegersModPGroupElement&& other) {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_STAR_P) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ =
        ((MultiplicativeIntegersModPGroupElement*) other.element_)->GetValue();
    SetGroupProperties(
        *((MultiplicativeIntegersModPGroupElement*) other.element_)
             ->GetConstProperties());
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt&, const GroupElement&) {
    LOG_FATAL("Repeating group operation a LargeInt number of times is not "
              "supported for Group Multiplicative Integers.");
  }
  // Overload of GroupElement's Invert().
  void Invert();
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static MultiplicativeIntegersModPGroupElement Identity(
      const uint64_t& modulus) {
    return MultiplicativeIntegersModPGroupElement(modulus);
  }
  MultiplicativeIntegersModPGroupElement Inverse() const;
  uint64_t GetValue() const { return value_; }
  GroupValueType GetValueType() const { return GroupValueType(value_); }
  void SetValue(const uint64_t& value) { value_ = value % GetModulus(); }
  void SetValue(const GroupValueType& value) {
    value_ = value.uint64_value_ % GetModulus();
  }
  // ======================= END Generic Group Functions =======================
  void SetModulus(const uint64_t& modulus) {
    // Check modulus is prime.
    if (!IsPrime(LargeInt(modulus))) {
      LOG_FATAL(
          "Unable to create Z*_p for non-prime p: " +
          string_utils::Itoa(modulus));
    }
    ((ModulusGroupProperties*) GetProperties())->modulus_ = modulus;
  }
  uint64_t GetModulus() const {
    return ((const ModulusGroupProperties*) GetConstProperties())->modulus_;
  }
  // We cannot use 'pow()' in math.h, because exponent may be quite large (and
  // hence overflow [u]int64_t). Since this is exponent mod p, overflow should
  // be handled appropriately.
  uint64_t Pow(const uint64_t& base, const int64_t& exp) const;
  uint64_t Pow(const uint64_t& base, const uint64_t& exp) const;
  MultiplicativeIntegersModPGroupElement Random() const;

private:
  uint64_t value_;
};

// ================= GroupType = Z*_LARGE_p (Z*_p for p a LargeInt) ============
class MultiplicativeIntegersModLargePGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  // Default Constructor.
  explicit MultiplicativeIntegersModLargePGroupElement(const LargeInt& modulus) {
    // Check modulus is prime.
    if (!IsPrime(modulus)) {
      LOG_FATAL("Unable to create Z*_p for non-prime p: " + modulus.Print());
    }
    LargeModulusGroupProperties to_copy;
    to_copy.type_ = GroupType::Z_STAR_LARGE_P;
    to_copy.modulus_ = modulus;
    SetGroupProperties(to_copy);
    value_ = LargeInt::One();
  }
  // Constructor specific to MultiplicativeIntegersModLargePGroupElement.
  MultiplicativeIntegersModLargePGroupElement(
      const LargeInt& modulus, const LargeInt& value) {
    // Check modulus is prime.
    if (!IsPrime(modulus)) {
      LOG_FATAL("Unable to create Z*_p for non-prime p: " + modulus.Print());
    }
    LargeModulusGroupProperties to_copy;
    to_copy.type_ = GroupType::Z_STAR_LARGE_P;
    to_copy.modulus_ = modulus;
    SetGroupProperties(to_copy);
    value_ = value >= 0 ? value % modulus : abs(value) % modulus;
    if (value < 0) value_ = modulus - value_;
  }
  // Copy Constructor.
  MultiplicativeIntegersModLargePGroupElement(
      const MultiplicativeIntegersModLargePGroupElement& other) {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
  }
  // Copy Constructor; supports e.g.:
  //   MultiplicativeIntegersModLargePGroupElement foo = a + b
  MultiplicativeIntegersModLargePGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_STAR_LARGE_P) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((MultiplicativeIntegersModLargePGroupElement*) other.element_)
                 ->GetValue();
    SetGroupProperties(
        *((MultiplicativeIntegersModLargePGroupElement*) other.element_)
             ->GetConstProperties());
    delete other.element_;
  }
  // Move Constructor.
  MultiplicativeIntegersModLargePGroupElement(
      MultiplicativeIntegersModLargePGroupElement&& other) noexcept {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
  }
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~MultiplicativeIntegersModLargePGroupElement() noexcept {}
  // Copy Assignement Operator.
  MultiplicativeIntegersModLargePGroupElement& operator=(
      const MultiplicativeIntegersModLargePGroupElement& other) {
    MultiplicativeIntegersModLargePGroupElement temp(
        other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }
  // Move-Assignement Operator.
  MultiplicativeIntegersModLargePGroupElement& operator=(
      MultiplicativeIntegersModLargePGroupElement&& other) {
    SetGroupProperties(*other.GetConstProperties());
    value_ = other.GetValue();
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::Z_STAR_LARGE_P) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_ = ((MultiplicativeIntegersModLargePGroupElement*) other.element_)
                 ->GetValue();
    SetGroupProperties(
        *((MultiplicativeIntegersModLargePGroupElement*) other.element_)
             ->GetConstProperties());
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt& a, const GroupElement& b);
  // Overload of GroupElement's Invert().
  void Invert();
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static MultiplicativeIntegersModLargePGroupElement Identity(
      const LargeInt& modulus) {
    return MultiplicativeIntegersModLargePGroupElement(modulus);
  }
  MultiplicativeIntegersModLargePGroupElement Inverse() const;
  LargeInt GetValue() const { return value_; }
  GroupValueType GetValueType() const { return GroupValueType(value_); }
  void SetValue(const LargeInt& value) {
    value_ = value >= 0 ? value % GetModulus() : abs(value) % GetModulus();
    if (value < 0) value_ = GetModulus() - value_;
  }
  void SetValue(const GroupValueType& value) {
    value_ = value.large_int_value_ >= 0 ?
        value.large_int_value_ % GetModulus() :
        abs(value.large_int_value_) % GetModulus();
    if (value.large_int_value_ < 0) value_ = GetModulus() - value_;
  }
  // ======================= END Generic Group Functions =======================

  void SetModulus(const LargeInt& modulus) {
    // Check modulus is prime.
    if (!IsPrime(modulus)) {
      LOG_FATAL("Unable to create Z*_p for non-prime p: " + modulus.Print());
    }
    ((LargeModulusGroupProperties*) GetProperties())->modulus_ = modulus;
  }
  LargeInt GetModulus() const {
    return ((const LargeModulusGroupProperties*) GetConstProperties())->modulus_;
  }
  MultiplicativeIntegersModLargePGroupElement Random() const;

private:
  LargeInt value_;
};

// ============================ GroupType = G x H (Direct Product) =============
class DirectProductGroupElement : public GroupElement {
public:
  // =================== Constructor and Rule of 5 Functions ===================
  // Default Constructor.
  DirectProductGroupElement(
      const GroupProperties& group_one, const GroupProperties& group_two) :
      value_one_(CreateDirectProductSubgroup(group_one)),
      value_two_(CreateDirectProductSubgroup(group_two)) {
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(&group_one);
    SetSecondGroupProperties(&group_two);
  }
  // Similar to above, but one group will be created from scratch (default),
  // one group via a copy of an existing GroupElement.
  DirectProductGroupElement(
      const GroupElement& value_one, const GroupProperties& group_two) :
      value_one_(CreateGroupElementCopy(value_one)),
      value_two_(CreateDirectProductSubgroup(group_two)) {
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(value_one.GetConstProperties());
    SetSecondGroupProperties(&group_two);
  }
  // Same as above, vice-versa for which parameter is which.
  DirectProductGroupElement(
      const GroupProperties& group_one, const GroupElement& value_two) :
      value_one_(CreateDirectProductSubgroup(group_one)),
      value_two_(CreateGroupElementCopy(value_two)) {
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(&group_one);
    SetSecondGroupProperties(value_two.GetConstProperties());
  }
  // Similar to above, this time both are from a copy of existing GroupElements.
  DirectProductGroupElement(
      const GroupElement& value_one, const GroupElement& value_two) :
      value_one_(CreateGroupElementCopy(value_one)),
      value_two_(CreateGroupElementCopy(value_two)) {
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(value_one.GetConstProperties());
    SetSecondGroupProperties(value_two.GetConstProperties());
  }
  // Copy Constructor.
  DirectProductGroupElement(const DirectProductGroupElement& other) :
      value_one_(CreateGroupElementCopy(*(other.GetFirstValue()))),
      value_two_(CreateGroupElementCopy(*(other.GetSecondValue()))) {
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(other.GetFirstGroupProperties());
    SetSecondGroupProperties(other.GetSecondGroupProperties());
  }
  // Copy Constructor (supports e.g.: DirectProductGroupElement foo = a + b).
  DirectProductGroupElement(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::DIRECT_PRODUCT) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    value_one_.reset(
        ((DirectProductGroupElement*) other.element_)->ReleaseFirstValue());
    value_two_.reset(
        ((DirectProductGroupElement*) other.element_)->ReleaseSecondValue());
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(((DirectProductGroupElement*) other.element_)
                                ->GetFirstGroupProperties());
    SetSecondGroupProperties(((DirectProductGroupElement*) other.element_)
                                 ->GetSecondGroupProperties());
    delete other.element_;
  }
  // Move Constructor.
  DirectProductGroupElement(DirectProductGroupElement&& other) noexcept :
      value_one_(other.ReleaseFirstValue()),
      value_two_(other.ReleaseSecondValue()) {
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(other.GetFirstGroupProperties());
    SetSecondGroupProperties(other.GetSecondGroupProperties());
  }
  // Destructor (made virtual, so all derived class' destructors get called).
  virtual ~DirectProductGroupElement() noexcept {}
  // Copy Assignement Operator.
  DirectProductGroupElement& operator=(const DirectProductGroupElement& other) {
    DirectProductGroupElement temp(other);  // Use Copy Constructor.
    *this = std::move(temp);  // Use Move-Assignment Operator.
    return *this;
  }
  // Move-Assignement Operator.
  DirectProductGroupElement& operator=(DirectProductGroupElement&& other) {
    value_one_.reset(other.ReleaseFirstValue());
    value_two_.reset(other.ReleaseSecondValue());
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(other.GetFirstGroupProperties());
    SetSecondGroupProperties(other.GetSecondGroupProperties());
    return *this;
  }
  // ================= END Constructor and Rule of 5 Functions =================

  // ========================= GroupElement Overloads ==========================
  // Overload of GroupElement's '=' overload.
  GroupElement& operator=(GroupOperationHolder other) {
    if (other.element_ == nullptr) {
      LOG_FATAL("Unable to copy NULL GroupElement.");
    }
    if (other.element_->GetGroupType() != GroupType::DIRECT_PRODUCT) {
      LOG_FATAL("Unable to copy GroupElement of non-matching type.");
    }
    DirectProductGroupElement* other_cast =
        (DirectProductGroupElement*) other.element_;
    value_one_.reset(CreateGroupElementCopy(*other_cast->GetFirstValue()));
    value_two_.reset(CreateGroupElementCopy(*other_cast->GetSecondValue()));
    DirectProductGroupProperties to_copy;
    to_copy.type_ = GroupType::DIRECT_PRODUCT;
    SetGroupProperties(to_copy);
    SetFirstGroupProperties(other_cast->GetFirstGroupProperties());
    SetSecondGroupProperties(other_cast->GetSecondGroupProperties());
    delete other.element_;
    return *this;
  }
  // Overload of GroupElement's '+=' overload.
  GroupElement& operator+=(const GroupElement& other);
  GroupElement& operator+=(GroupOperationHolder other);
  // Overload of GroupElement's '-=' overload.
  GroupElement& operator-=(const GroupElement& other);
  GroupElement& operator-=(GroupOperationHolder other);
  // Overload '*=' operator.
  GroupElement& operator*=(const int32_t n);
  GroupElement& operator*=(const uint32_t n);
  GroupElement& operator*=(const int64_t& n);
  GroupElement& operator*=(const uint64_t& n);
  GroupElement& operator*=(const LargeInt& n);
  // Overload of GroupElement's Add().
  void Add(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Subtract().
  void Subtract(const GroupElement& a, const GroupElement& b);
  // Overload of GroupElement's Multiply().
  void Multiply(const int32_t a, const GroupElement& b);
  void Multiply(const uint32_t a, const GroupElement& b);
  void Multiply(const int64_t& a, const GroupElement& b);
  void Multiply(const uint64_t& a, const GroupElement& b);
  void Multiply(const LargeInt& a, const GroupElement& b);
  // Overload of GroupElement's Invert().
  void Invert();
  // Overload Encode/Decode.
  // NOTE: These API's don't make sense for DirectProduct, as the single
  // value for num_bytes makes it impossible to e.g. Decode using the
  // two subgroups' Decode() methods (since we don't have a breakdown
  // of how many bytes per each of the subgroups). Some options:
  //   1) Don't implement these for DirectProduct (so e.g. crash, since
  //      we need to implement them due to GroupElement being purely virutal)
  //   2) Offer an alternative API for Encode/Decode, that takes in *two*
  //      'num_bytes' parameters
  //   3) Hack the API to do what we want. For example, ignore 'num_bytes',
  //      and store all the 'num_byte' info we need inside of input/output.
  //   4) Have num_bytes denote the total, and force the num_bytes encoding
  //      for each subgroup to be exactly half of this.
  //   5) Change the first parameter of Decode to a pointer (const uint64_t*),
  //      and then overload num_bytes to actually be an array of uint64_t,
  //      based on how many different values are needed.
  // Note that (1) and (2) could be combined.
  // Also note (2) actually only solves things at one level of abstraction,
  // since e.g. if a DirectProduct subgroup is itself a DirectProduct, we're
  // in trouble again. Option (4) could work, but it's not ideal, especially
  // if one Subgroup's encoding is much larger than the other (then we lose
  // much efficiency).
  // We implemented option (3).
  bool Encode(uint64_t* num_bytes, unsigned char** output) const;
  bool Decode(const uint64_t& num_bytes, const unsigned char* input);
  // ======================= END GroupElement Overloads ========================

  // ========================= Generic Group Functions =========================
  static DirectProductGroupElement Identity(
      const GroupProperties& group_one, const GroupProperties& group_two) {
    return DirectProductGroupElement(group_one, group_two);
  }
  DirectProductGroupElement Inverse() const;
  GroupElement* GetFirstValue() const { return value_one_.get(); }
  GroupElement* GetSecondValue() const { return value_two_.get(); }
  GroupValueType GetValueType() const {
    return GroupValueType(
        value_one_->GetValueType(), value_two_->GetValueType());
  }
  void SetValue(const GroupValueType& value) {
    value_one_->SetValue(*value.left_group_value_);
    value_two_->SetValue(*value.right_group_value_);
  }
  void SetFirstValue(const GroupElement& value) {
    value_one_.reset(CreateGroupElementCopy(value));
  }
  void SetSecondValue(const GroupElement& value) {
    value_two_.reset(CreateGroupElementCopy(value));
  }
  // ======================= END Generic Group Functions =======================
  const GroupProperties* GetFirstGroupProperties() const {
    return ((const DirectProductGroupProperties*) GetConstProperties())
        ->subgroup_one_.get();
  }
  const GroupProperties* GetSecondGroupProperties() const {
    return ((const DirectProductGroupProperties*) GetConstProperties())
        ->subgroup_two_.get();
  }
  GroupType GetFirstGroupType() const {
    return GetFirstGroupProperties()->type_;
  }
  GroupType GetSecondGroupType() const {
    return GetSecondGroupProperties()->type_;
  }
  void SetFirstGroupProperties(const GroupProperties* properties) {
    ((DirectProductGroupProperties*) GetProperties())
        ->subgroup_one_.reset(CreateNewCopy(properties));
  }
  void SetSecondGroupProperties(const GroupProperties* properties) {
    ((DirectProductGroupProperties*) GetProperties())
        ->subgroup_two_.reset(CreateNewCopy(properties));
  }
  void SetFirstGroupType(const GroupType type) {
    ((DirectProductGroupProperties*) GetProperties())->subgroup_one_->type_ =
        type;
  }
  void SetSecondGroupType(const GroupType type) {
    ((DirectProductGroupProperties*) GetProperties())->subgroup_two_->type_ =
        type;
  }

protected:
  GroupElement* ReleaseFirstValue() { return value_one_.release(); }
  GroupElement* ReleaseSecondValue() { return value_two_.release(); }
  // In case the argument to Set[First | Second]Value is the result of a sum,
  // difference, or multiplication, the API overloads of these operators (at
  // the bottom of this file) will be applied, which return a pointer to a
  // new GroupElement() which should subsequently be destroyed here.
  // Thus, the passed in pointer will be destroyed. If you're using this API
  // in a context *other than* having just applied a +,-,* operation, then
  // be sure you're aware that this function may not behave as you would
  // otherwise expect.
  void SetFirstValue(GroupOperationHolder value) {
    value_one_.reset(CreateGroupElementCopy(*value.element_));
    delete value.element_;
  }
  void SetSecondValue(GroupOperationHolder value) {
    value_two_.reset(CreateGroupElementCopy(*value.element_));
    delete value.element_;
  }

private:
  std::unique_ptr<GroupElement> value_one_;
  std::unique_ptr<GroupElement> value_two_;

  // Helper function for DirectProductGroupElement Constructor: Creates one of
  // the direct-product groups.
  GroupElement* CreateDirectProductSubgroup(
      const GroupProperties& properties) const;
};

// What should the operator+ overload return?:
//   1) GroupElement
//   2) GroupElement&
//   3) GroupElement*
//   4) Something else...
// We'd like to do (1), as the other options require allocating memory on the
// heap (why? keep readin...), which is not desirable. However, (1) is not possible:
//   a) GroupElement is abstract. Code will not compile if you attempt to
//      return (by value) an abstract object; but making it non-abstract also
//      won't work (see (b) below)
//   b) Make GroupElement non-abstract. Besides violating our desire to make
//      the GroupElement base class abstract, this won't work anyway: the code will
//      compile now, but GroupElement's copy constructor will be called upon
//      the return, and since Constructors cannot be made virtual, the
//      element returned will actually be of type GroupElement, as opposed
//      to the desired instantiated type (i.e. even if we did:
//        return IntegerGroupElement();
//      The copy constructor for GroupElement (and *not* for IntegerGroupElement) will
//      be called when returning.
// So Option (1) is out.
// Regarding Options (3) and (4): These APIs are not really desirable, because the
// expected use-case for '+' is:
//   *c = a + b
// and hence we would want 'a + b' to return a GroupElement, not a pointer to one
// (or in the case of Option (4), something else entirely).  However, we can still
// support the desired use-case even if we do Option (3) or (4), by also
// overloading GroupElement's '=' operator, so that it takes in a GroupElement*
// (or in the case of Option (4), it takes in the 'Something else') instead of
// a GroupElement or GroupElement&. This is what we ended up doing, see more
// discussion below for why...
// Regarding Option (2): What value (object) should be returned?
// We can't really return 'a' or 'b', as those elements are 'const', and thus
// we can't modify them to make one of them represent the sum (besides, even if
// we made one of them non-const, as we can do, we might as well just use the
// supported '+=" overload in this case, since we'd be modifying one of the summands).
// Thus, the only thing we can return is a reference to a new GroupElement object,
// and the only way this reference survives beyone the scope of the '+' overload
// function is to create the variable on the heap. This approach can work, the
// issue I had was trying to make sure the memory was freed when the object is
// no longer needed (which is right away, since any use of '+' will immediately
// be followed by assignment '='; e.g. c = a + b). I tried using smart pointers
// so that the memory was freed automatically, but had a problem with them not
// being smart enough; for example, under the expected usage:
//   *c = a + b;
// Then the compiler recognizes that the object created by 'a + b' is not
// referenced anywhere, and therefore IT IS DESTROYED BEFORE c's ASSIGNMENT
// OPERATOR '=' IS CALLED; so the attempt to overload operator= will fail,
// as the passed-in 'other' will already have been destroyed.
// There is probably a way to postpone the destruction, but I couldn't figure
// it out and I gave up after several failed attempts.
// I also tried just creating a raw pointer to a 'new' heap object, and returning
// a reference to that; but the only reference I would have to this object
// (at least in the expected use-case: "c = a + b") is in c's overloaded '='
// operator function; thus, that would be the only place to delete/free the
// memory. While this can work, it means that the overload of the '=' operator
// must take a non-const reference to the input GroupElement&, which was
// discouraged by at least one site: http://www.cplusplus.com/articles/y8hv0pDG/
//
// So Option (2) is possible, but not desirable. Instead, I pursued Option (3)
// (NOTE: Option (4) is also possible, but since it would look very similar to
// Option (3), and Option (3) is more intuitive/straightforward, Option (4) is
// not worth it).
//
// WARNING: Using this function in any use-case EXCEPT the following is NOT recommended:
//   DEFAULT: *c = a + b
// where c is a GroupElement* (or a pointer to one of the instantiating classes
// of GroupElement). For example, the following code would compile:
//   RISKY1: GroupElement* foo = a + b;
//   RISKY2: GroupElement* foo(a + b);
//   RISKY3: GroupElement& foo = *(a + b);
// but they are not recommended, as they have the potential of creating a memory
// leak, since the only code that automatically deallocates the 'new' object
// returned by the below operator+ function is the code in the function:
//   GroupElement::operator=(GroupElement* other)
// and since the above RISKY examples won't call the overloaded '=' function,
// the caller must manually delete/free the returned object 'foo'.
// If the 'RISKY' use-case is desired, be sure to manually call 'delete foo'
// when you are done with it.
// See group_test.cpp for examples.
// For: c = a + b.
inline GroupOperationHolder operator+(
    const GroupElement& a, const GroupElement& b) {
  if (a.GetGroupType() != b.GetGroupType()) {
    LOG_FATAL("Unable to add two GroupElements of different GroupType.");
  }

  GroupOperationHolder to_return;
  switch (a.GetGroupType()) {
    case GroupType::Z: {
      to_return.element_ = new IntegerGroupElement();
      break;
    }
    case GroupType::LARGE_Z: {
      to_return.element_ = new LargeIntegerGroupElement();
      break;
    }
    case GroupType::Z_TWO: {
      to_return.element_ = new IntegerModTwoGroupElement();
      break;
    }
    case GroupType::EDWARDS_CURVE: {
      const EdwardsCurveGroupElement* a_cast =
          (const EdwardsCurveGroupElement*) &a;
      const EdwardsCurveGroupElement* b_cast =
          (const EdwardsCurveGroupElement*) &b;
      if ((a_cast->GetModulus() != b_cast->GetModulus()) ||
          (a_cast->GetA() != b_cast->GetA()) ||
          (a_cast->GetD() != b_cast->GetD())) {
        LOG_FATAL("Unable to add two GroupElements of different modulus N.");
      }
      to_return.element_ = new EdwardsCurveGroupElement(
          a_cast->GetModulus(), a_cast->GetA(), a_cast->GetD());
      break;
    }
    case GroupType::Z_N: {
      const IntegerModNGroupElement* a_cast =
          (const IntegerModNGroupElement*) &a;
      const IntegerModNGroupElement* b_cast =
          (const IntegerModNGroupElement*) &b;
      if (a_cast->GetModulus() != b_cast->GetModulus()) {
        LOG_FATAL("Unable to add two GroupElements of different modulus N.");
      }
      to_return.element_ = new IntegerModNGroupElement(a_cast->GetModulus());
      break;
    }
    case GroupType::Z_LARGE_N: {
      const IntegerModLargeNGroupElement* a_cast =
          (const IntegerModLargeNGroupElement*) &a;
      const IntegerModLargeNGroupElement* b_cast =
          (const IntegerModLargeNGroupElement*) &b;
      if (a_cast->GetModulus() != b_cast->GetModulus()) {
        LOG_FATAL(
            "Unable to add two GroupElements of different modulus N: " +
            a_cast->GetModulus().Print() + ", " + b_cast->GetModulus().Print());
      }
      to_return.element_ =
          new IntegerModLargeNGroupElement(a_cast->GetModulus());
      break;
    }
    case GroupType::Z_STAR_P: {
      const MultiplicativeIntegersModPGroupElement* a_cast =
          (const MultiplicativeIntegersModPGroupElement*) &a;
      const MultiplicativeIntegersModPGroupElement* b_cast =
          (const MultiplicativeIntegersModPGroupElement*) &b;
      if (a_cast->GetModulus() != b_cast->GetModulus()) {
        LOG_FATAL("Unable to add two GroupElements of different modulus N.");
      }
      to_return.element_ =
          new MultiplicativeIntegersModPGroupElement(a_cast->GetModulus());
      break;
    }
    case GroupType::Z_STAR_LARGE_P: {
      const MultiplicativeIntegersModLargePGroupElement* a_cast =
          (const MultiplicativeIntegersModLargePGroupElement*) &a;
      const MultiplicativeIntegersModLargePGroupElement* b_cast =
          (const MultiplicativeIntegersModLargePGroupElement*) &b;
      if (a_cast->GetModulus() != b_cast->GetModulus()) {
        LOG_FATAL("Unable to add two GroupElements of different modulus N.");
      }
      to_return.element_ =
          new MultiplicativeIntegersModLargePGroupElement(a_cast->GetModulus());
      break;
    }
    case GroupType::DIRECT_PRODUCT: {
      const DirectProductGroupElement* a_cast =
          (const DirectProductGroupElement*) &a;
      const DirectProductGroupElement* b_cast =
          (const DirectProductGroupElement*) &b;
      if (a_cast->GetFirstGroupType() != b_cast->GetFirstGroupType() ||
          a_cast->GetSecondGroupType() != b_cast->GetSecondGroupType()) {
        LOG_FATAL("Unable to add two GroupElements of different Group Types.");
      }
      to_return.element_ = new DirectProductGroupElement(
          *(a_cast->GetFirstGroupProperties()),
          *(b_cast->GetSecondGroupProperties()));
      break;
    }
    default: {
      LOG_FATAL(
          "Unable to add GroupElements of unsupported GroupType: " +
          string_utils::Itoa(static_cast<int>(a.GetGroupType())));
    }
  }

  if (to_return.element_ == nullptr) {
    LOG_FATAL("Bad code flow through '+' overload: to_return not set.");
  }
  to_return.element_->Add(a, b);
  return to_return;
}
// Same as above, but for supporting chaining of operations, e.g.: c = (a + b) + d
inline GroupOperationHolder operator+(
    GroupOperationHolder a, const GroupElement& b) {
  if (a.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  GroupOperationHolder to_return = (*a.element_) + b;
  delete a.element_;
  return to_return;
}
// Same as above, but for supporting chaining of operations, e.g.: c = a + (b + d)
inline GroupOperationHolder operator+(
    const GroupElement& a, GroupOperationHolder b) {
  if (b.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  GroupOperationHolder to_return = a + (*b.element_);
  delete b.element_;
  return to_return;
}
// Same as above, but for supporting chaining of operations, e.g.: c = (a + b) + (d + e)
inline GroupOperationHolder operator+(
    GroupOperationHolder a, GroupOperationHolder b) {
  if (a.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  if (b.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  GroupOperationHolder to_return = (*a.element_) + (*b.element_);
  delete a.element_;
  delete b.element_;
  return to_return;
}

// For: c = -a.
inline GroupOperationHolder operator-(const GroupElement& a) {
  GroupOperationHolder to_return;
  switch (a.GetGroupType()) {
    case GroupType::Z: {
      to_return.element_ =
          new IntegerGroupElement(((const IntegerGroupElement*) &a)->Inverse());
      break;
    }
    case GroupType::LARGE_Z: {
      to_return.element_ = new LargeIntegerGroupElement(
          ((const LargeIntegerGroupElement*) &a)->Inverse());
      break;
    }
    case GroupType::Z_TWO: {
      to_return.element_ = new IntegerModTwoGroupElement(
          ((const IntegerModTwoGroupElement*) &a)->Inverse());
      break;
    }
    case GroupType::EDWARDS_CURVE: {
      to_return.element_ = new EdwardsCurveGroupElement(
          ((const EdwardsCurveGroupElement*) &a)->Inverse());
      break;
    }
    case GroupType::Z_N: {
      to_return.element_ = new IntegerModNGroupElement(
          ((const IntegerModNGroupElement*) &a)->Inverse());
      break;
    }
    case GroupType::Z_LARGE_N: {
      to_return.element_ = new IntegerModLargeNGroupElement(
          ((const IntegerModLargeNGroupElement*) &a)->Inverse());
      break;
    }
    case GroupType::Z_STAR_P: {
      to_return.element_ = new MultiplicativeIntegersModPGroupElement(
          ((const MultiplicativeIntegersModPGroupElement*) &a)->Inverse());
      break;
    }
    case GroupType::Z_STAR_LARGE_P: {
      to_return.element_ = new MultiplicativeIntegersModLargePGroupElement(
          ((const MultiplicativeIntegersModLargePGroupElement*) &a)->Inverse());
      break;
    }
    case GroupType::DIRECT_PRODUCT: {
      to_return.element_ = new DirectProductGroupElement(
          ((const DirectProductGroupElement*) &a)->Inverse());
      break;
    }
    default: {
      LOG_FATAL(
          "Unable to add GroupElements of unsupported GroupType: " +
          string_utils::Itoa(static_cast<int>(a.GetGroupType())));
    }
  }

  if (to_return.element_ == nullptr) {
    LOG_FATAL("Bad code flow through '+' overload: to_return not set.");
  }
  return to_return;
}
// Same as above, but for supporting chaining of operations, e.g.: c = -(a + b)
inline GroupOperationHolder operator-(GroupOperationHolder a) {
  if (a.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  GroupOperationHolder to_return = -(*a.element_);
  delete a.element_;
  return to_return;
}

// For: c = a - b.
// I implement this twice below, once doing:
//   c = a - b
// and in particular, this utilizes the Subtract() function; and the other way doing:
//   c = a + (-b)
// and in particular, this utilizes one call to Inverse() and one to Add().
/*
// Implementation 1: c = a - b.
// NOTE: If I uncomment this out, I'll need to update the switch statement with
// implementations for all possible GroupTypes.
inline GroupOperationHolder operator-(const GroupElement& a, const GroupElement& b) {
  if (a.GetGroupType() != b.GetGroupType()) {
    LOG_FATAL("Unable to add two GroupElements of different GroupType.");
  }

  GroupOperationHolder to_return;
  switch (a.GetGroupType()) {
    case GroupType::Z: {
      to_return.element_ = new IntegerGroupElement();
      break;
    }
    default: {
      LOG_FATAL("Unable to add GroupElements of unsupported GroupType: " +
                string_utils::Itoa(static_cast<int>(a.GetGroupType())));
    }
  }

  if (to_return.element_ == nullptr) {
      LOG_FATAL("Bad code flow through '+' overload: to_return not set.");
    }
  to_return.element_->Subtract(a, b);
  return to_return;
}
*/
// Implementation 2: c = a + (-b).
inline GroupOperationHolder operator-(
    const GroupElement& a, const GroupElement& b) {
  GroupOperationHolder b_inverse = -b;
  GroupOperationHolder to_return = a + (*b_inverse.element_);
  delete b_inverse.element_;
  return to_return;
}
// Same as above, but for supporting chaining of operations, e.g.: c = (a + b) - d
inline GroupOperationHolder operator-(
    GroupOperationHolder a, const GroupElement& b) {
  if (a.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  GroupOperationHolder to_return = (*a.element_) - b;
  delete a.element_;
  return to_return;
}
// Same as above, but for supporting chaining of operations, e.g.: c = a - (b + d)
inline GroupOperationHolder operator-(
    const GroupElement& a, GroupOperationHolder b) {
  if (b.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  GroupOperationHolder to_return = a - (*b.element_);
  delete b.element_;
  return to_return;
}
// Same as above, but for supporting chaining of operations, e.g.: c = (a + b) - (d + e)
inline GroupOperationHolder operator-(
    GroupOperationHolder a, GroupOperationHolder b) {
  if (a.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  if (b.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  GroupOperationHolder to_return = (*a.element_) - (*b.element_);
  delete a.element_;
  delete b.element_;
  return to_return;
}

// For: c = a * b, where a is an integer.
template<typename value_t>
inline GroupOperationHolder operator*(const value_t a, const GroupElement& b) {
  GroupOperationHolder to_return;
  switch (b.GetGroupType()) {
    case GroupType::Z: {
      to_return.element_ = new IntegerGroupElement();
      break;
    }
    case GroupType::LARGE_Z: {
      to_return.element_ = new LargeIntegerGroupElement();
      break;
    }
    case GroupType::Z_TWO: {
      to_return.element_ = new IntegerModTwoGroupElement();
      break;
    }
    case GroupType::EDWARDS_CURVE: {
      to_return.element_ = new EdwardsCurveGroupElement(
          ((const EdwardsCurveGroupElement*) &b)->GetModulus(),
          ((const EdwardsCurveGroupElement*) &b)->GetA(),
          ((const EdwardsCurveGroupElement*) &b)->GetD());
      break;
    }
    case GroupType::Z_N: {
      to_return.element_ = new IntegerModNGroupElement(
          ((const IntegerModNGroupElement*) &b)->GetModulus());
      break;
    }
    case GroupType::Z_LARGE_N: {
      to_return.element_ = new IntegerModLargeNGroupElement(
          ((const IntegerModLargeNGroupElement*) &b)->GetModulus());
      break;
    }
    case GroupType::Z_STAR_P: {
      to_return.element_ = new MultiplicativeIntegersModPGroupElement(
          ((const MultiplicativeIntegersModPGroupElement*) &b)->GetModulus());
      break;
    }
    case GroupType::Z_STAR_LARGE_P: {
      to_return.element_ = new MultiplicativeIntegersModLargePGroupElement(
          ((const MultiplicativeIntegersModLargePGroupElement*) &b)
              ->GetModulus());
      break;
    }
    case GroupType::DIRECT_PRODUCT: {
      const DirectProductGroupElement* b_cast =
          (const DirectProductGroupElement*) &b;
      to_return.element_ = new DirectProductGroupElement(*b_cast);
      break;
    }
    default: {
      LOG_FATAL(
          "Unable to add GroupElements of unsupported GroupType: " +
          string_utils::Itoa(static_cast<int>(b.GetGroupType())));
    }
  }

  if (to_return.element_ == nullptr) {
    LOG_FATAL("Bad code flow through '+' overload: to_return not set.");
  }
  to_return.element_->Multiply(a, b);
  return to_return;
}
// Same as above, but for supporting chaining of operations, e.g.: c = a * (b + d)
template<typename value_t>
inline GroupOperationHolder operator*(const value_t a, GroupOperationHolder b) {
  if (b.element_ == nullptr) LOG_FATAL("Bad input to + operator");
  GroupOperationHolder to_return = a * (*b.element_);
  delete b.element_;
  return to_return;
}

/**
 * Adds two points x and y on an Edwards Curve: a*x^2 + y^2 = 1 + d*x^2*y^2
 * defined over (F_modulus)^2.
 **/
extern std::pair<LargeInt, LargeInt> EdwardsAddition(
    const LargeInt& modulus,
    const LargeInt& a,
    const LargeInt& d,
    const std::pair<LargeInt, LargeInt>& p,
    const std::pair<LargeInt, LargeInt>& q);

/**
 * Returns the inverse of a point on the Edwards Curve: a*x^2 + y^2 = 1 + d*x^2*y^2
 * defined over (F_modulus)^2. Note that the inverse definition does not depend
 * on the coefficients a or d.
 **/
extern std::pair<LargeInt, LargeInt> EdwardsInverse(
    const LargeInt& modulus, const std::pair<LargeInt, LargeInt>& p);

/**
 * Returns the result of adding a point a on the Edwards Curve:
 * a*x^2 + y^2 = 1 + d*x^2y^2 defined over (F_p)^2 to itself n times.
 **/
extern std::pair<LargeInt, LargeInt> EdwardsScaling(
    const LargeInt& modulus,
    const LargeInt& a,
    const LargeInt& d,
    const LargeInt& n,
    const std::pair<LargeInt, LargeInt>& p);

/*
 * Given a y-coordinate, compute the x-coordinate of a point (x,y) on
 * the curve. Edwards Curve: a*x^2 + y^2 = 1 + d*x^2*y^2 defined over
 * (F_modulus)^2. Used to compute generator B of a large subgroup.  If
 * the field positive is set to true, then return the positive root,
 * where 'positive' is defined as: We use the encoding of F_modulus to
 * define some field elements as being negative: specifically, x in
 * F_modulus is negative if the (b−1)-bit encoding of x (here modulus
 * < 2^(b-1) so there is a b-1 bit encoding of F_modulus) is
 * lexicographically larger than the (b − 1)-bit encoding of −x. More
 * concretely, if modulus is an odd prime and the encoding is the
 * little-endian representation of {0, 1, ... , modulus − 1} then
 * the positive elements of F_modulus are the even numbers between 0
 * and modulus - 1 (see
 * https://link.springer.com/chapter/10.1007/978-3-642-23951-9_9).
 */
extern LargeInt GetXCoordinate(
    const LargeInt& y,
    const LargeInt& modulus,
    const LargeInt& a,
    const LargeInt& d,
    const bool positive);
// Edwards Curve group ED25519 has subgroup of (prime) order:
//   l = 2^252 + 27742317777372353535851937790883648493
// This returns the LargeInt representing this prime value 'l'.
extern LargeInt GetEdwardCurveSubgroupSize();
// Diffie-Hellman Group #14 has size represented as a hex-string as per
// kDiffieHellmanGroup above (and alternatively represented as:
//   2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
// This function returns this group size (which is a prime).
extern LargeInt GetDiffieHellmanGroupFourteenSize();

}  // namespace math_utils

#endif
