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
//   A wrapper class for doing large integer math, e.g. finding large primes,
//   doing arithmetic in Z_n (for large n), etc.
//
//   Use functions provided in the base class rather than the implementing
//   classes, so that implentation details (i.e. the actual underlying
//   library used) are abstracted away, and in particular all usage point
//   to the base/wrapper class, with a single switch to control which
//   implementing Class (i.e. underlying library) is used; this will allow
//   quick/easy toggling of which library gets used, so I can easily switch
//   based on application and/or as better libraries are developed.
//
//   NOTE: Determining which underlying type is used is controlled by a
//   global macro, and testing which macro is defined. So you should
//   compile with exactly one of the following MACROs defined:
//     - LARGE_INT_MP_INT
//     - LARGE_INT_GMP
//     - LARGE_INT_MPIR
//   If compiling via build_reader.sh, the macro is automatically added,
//   the current default is to use 'LARGE_INT_GMP'; this can be
//   overridden either by explicitly defining a differen macro
//   (e.g. specifying '-D LARGE_INT_MPIR' on the command line), or by
//   editing the hard-coded value LARGE_INT_DEFAULT in build_reader.sh.
//
//   We design this as a non- virtual class (as opposed to a purely virtual base
//   class from which all instantiating classes are based) for ease of code
//   implementation: since most of the use-cases will be general operations on
//   LargeInt objects, it will be easier to overload operators, etc. within a
//   single class (contrast this to group.h, where I took the opposite approach).
//
//   Current possible instantiations of this Class are:
//     - mp_int (tommath library)
//     - gmp (GMP)
//     - mpir (Not yet implemented)

// TODO(PHB): Implement the MPIR instantiation.

#ifndef LARGE_INT_H
#define LARGE_INT_H

#include "GenericUtils/mutex.h"
#include "LoggingUtils/logging_utils.h"

#include <memory>  // For unique_ptr

#ifdef LARGE_INT_MP_INT
#include "MathUtils/mp_int_utils.h"
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
#include "LibTom/libtommath-1.0/tommath.h"  // For mp_int
#else
#include "LibTomLinux/libtommath-1.0/tommath.h"  // For mp_int
#endif
#endif
#ifdef LARGE_INT_GMP
#include "gmp.h"
#endif
#ifdef LARGE_INT_MPIR
// TODO: include whatever libraries are needed for mpir.
#endif

#include <climits>  // For CHAR_BIT
#include <iostream>
#include <string>
#include <vector>

namespace math_utils {

// A purely virtual structure, whose inherited sub-structs will have a single
// member variable representing the LargeInt value, using the appropriate type
// for the value (based on the Library used to implement LargeInt).
struct LargeIntType {
  // Virtual destructor (to ensure destructors of derived classes below get called).
  virtual ~LargeIntType() {}

  // Convert LargeInt to a standard type (in case it is actually small).
  // These conversions are done by the underlying library, and thus
  // behavior (e.g. for when the underlying value is too big for that
  // datatype) will depend on the underlying library (some will 'LOG_FATAL',
  // others will silently force the cast, e.g. by ignoring higher bits).
  // User is thus responsible for ensuring these will succeed.
  virtual int32_t GetInt32() const = 0;
  virtual uint32_t GetUInt32() const = 0;
  virtual int64_t GetInt64() const = 0;
  virtual uint64_t GetUInt64() const = 0;

  virtual std::string Print() const = 0;

  // ===================== LargeIntType <-> String ======================
  // Conversion to/from string representation. Base specifies binary (2),
  // decimal (10), or hex (16).
  virtual void FromString(const std::string& input, const char base) = 0;
  virtual std::string ToString(const char base) const = 0;

  // ===================== LargeIntType <-> Binary String ======================
  // Interprets the input string as an (unsigned) binary representation of a value;
  // Updates the underlying value_ field with this value.
  virtual void FromBinaryString(const std::string& as_binary) = 0;
  // Returns the (binary) string representation of this value. Should only
  // be used for non-negative values (use ToTwosComplementString() for
  // values that may be negative).
  virtual std::string ToBinaryString() const = 0;
  // Same as above, for signed values (leading bit is 2's complement bit).
  virtual void FromTwosComplementString(const std::string& as_binary) = 0;
  // Same as above, but the returned string should be interpretted as 2's complement.
  virtual std::string ToTwosComplementString() const = 0;

  // ===================== LargeIntType <-> Byte Stream ========================
  // Inteprets the input char array as a binary string, and sets value_ its value.
  virtual void FromByteString(const std::vector<unsigned char>& byte_string) = 0;
  // Same as above, different API.
  virtual void FromByteString(
      const unsigned char* byte_string, const int num_bytes) = 0;

  // Same as above, with endian-ness specified.
  virtual void FromByteString(
      const unsigned char* byte_string,
      const int num_bytes,
      const int endian) = 0;

  // Same as above, for (signed) char array.
  // NOTE: Even though char array is signed, like above, this cast all input
  // arrays as a positive value.
  virtual void FromByteString(const std::vector<char>& byte_string) = 0;
  // Same as above, different API.
  virtual void FromByteString(const char* byte_string, const int num_bytes) = 0;
  // Converts value_ to a byte string.
  // NOTE: Appends to output, if non-empty on input.
  virtual void ToByteString(std::vector<unsigned char>* output) const = 0;
  // Same as above, but you can set the field endian to specify little/big endian.
  virtual void ToByteString(
      const int endian, std::vector<unsigned char>* output) const = 0;
  // Same as above, different API.
  // NOTE: *output should be NULL, and then this will allocate 'num_bytes'
  // bytes to *output via malloc(); caller is responsible to free these bytes when done.
  virtual void ToByteString(
      const int endian, int* num_bytes, unsigned char** output) const = 0;
  // Same as above, for potentially negative values.
  virtual void FromTwosComplementByteString(
      const std::vector<unsigned char>& byte_string) = 0;
  // Same as above, for (signed) char array.
  virtual void FromTwosComplementByteString(
      const std::vector<char>& byte_string) = 0;
  // Same as above, for values that may be negative.
  virtual void ToTwosComplementByteString(
      std::vector<unsigned char>* output) const = 0;
};
#ifdef LARGE_INT_MP_INT
// mp_int (from tommath library) data type.
// TODO(paul): All of the functions in MathUtils/mp_int_utils.h,cpp are
// out-of-date, and really the whole thing should be re-written, or better,
// deleted (and then replaced all code that calls that file with the
// corresponding direct call to the appropriate function in LibTom).
// However, the effort to do this is not worth it, since LibTom is never
// acutally used; if we ever go back to LibTom, then address this TODO.
struct MpIntType : public LargeIntType {
  // It will be easier to store value_ as a pointer, rather than a pure
  // mp_int object, so that value_ can be modified even if the
  // underlying MpIntType container is const (as will be the case
  // for many of the member functions).
  mp_int* value_;

  MpIntType() {
    mp_init(value_);
    mp_set_int(value_, 0);
  }

  virtual ~MpIntType() {
    mp_clear(value_);
    delete value_;
  }

  // NOTE: All functions below don't override the corresponding ones in
  // LargeIntType, because they are non-const. They are non-const because
  // Libtommath takes only non-const (pointers to) mp_int arguments, even
  // when they should be const (e.g. mp_add(a, b, c) treats all 'a', 'b',
  // and 'c' as non-const, even though only 'c' should need to be mutable).
  void CopyFrom(const MpIntType& other) { mp_copy(other.value_, value_); }

  int32_t GetInt32() const {
    int32_t to_return;
    // First, make sure value_ is small enough to be in range.
    if (!MpIntToInt32(value_, &to_return)) {
      printf(
          "FATAL ERROR: Unable to cast '" + Print() + "' as int32 (too big).");
      exit(EXIT_FAILURE);
    }
    return to_return;
  }
  uint32_t GetUInt32() const {
    uint32_t to_return;
    // First, make sure value_ is small enough to be in range.
    if (!MpIntToUInt32(value_, &to_return)) {
      printf(
          "FATAL ERROR: Unable to cast '" + Print() + "' as uint32 (too big).");
      exit(EXIT_FAILURE);
    }
    return to_return;
  }
  int64_t GetInt64() const {
    int64_t to_return;
    // First, make sure value_ is small enough to be in range.
    if (!MpIntToInt64(value_, &to_return)) {
      printf(
          "FATAL ERROR: Unable to cast '" + Print() + "' as int64 (too big).");
      exit(EXIT_FAILURE);
    }
    return to_return;
  }
  uint64_t GetUInt64() const {
    uint64_t to_return;
    // First, make sure value_ is small enough to be in range.
    if (!MpIntToUInt64(value_, &to_return)) {
      printf(
          "FATAL ERROR: Unable to cast '" + Print() + "' as uint64 (too big).");
      exit(EXIT_FAILURE);
    }
    return to_return;
  }

  std::string Print() const {
    std::string to_return = "";
    if (!MpIntToString(value_, &to_return)) return "";
    return to_return;
  }

  void FromString(const std::string& input, const char base) {
    if (base == 2 || base == 10 || base == 16) {
      mp_read_radix(&value_, input.c_str(), base);
    } else {
      LOG_FATAL("Unsupported base.");
    }
  }

  void FromBinaryString(const std::string& as_binary) {
    MpIntFromBinaryString(as_binary, value_);
  }

  std::string ToString(const char base) const {
    if (base != 2 && base != 10 && base != 16) LOG_FATAL("Unsupported base.");

    // Special handling for '0', because mp_radix_size() may report 0 for this.
    const int mp_int_size = mp_unsigned_bin_size(&value_);
    if (mp_int_size == 0) return "0";

    // Get number of 'digits'.
    int mp_size;
    if (mp_radix_size(&value_, base, &mp_size) != MP_OKAY) {
      LOG_FATAL("Unable to get mp_radix_size().");
    }
    if (mp_size == 0) return "0";

    vector<char> buffer(mp_size);
    mp_toradix(&value_, buffer.data(), base);
    if (buffer[mp_size - 1] != 0) {
      LOG_WARNING("Weird behavior of mp_toradix; this should never happen.");
      buffer.push_back(0);
    }
    return string(buffer.data());
  }

  std::string ToBinaryString() const {
    std::string to_return = "";
    if (!MpIntToBinaryString(value_, &to_return)) return "";
    return to_return;
  }

  void FromTwosComplementString(const std::string& as_binary) {
    if (as_binary.empty()) {
      mp_set_int(value_, 0);
      return;
    }

    // If leading bit is '0', then this is a positive value, and 2's Complement
    // string is identical to Binary String, so just call the former.
    if (as_binary.at(0) == '0') {
      FromBinaryString(as_binary);
      return;
    }

    // Leading bit is '1', signifying a negative value. We will use the
    // relationship noted above in ToTwosComplementString(): We can flip
    // all bits, add 1, and then flip sign.
    std::string flip_bits = "";
    for (size_t i = 0; i < as_binary.length(); ++i) {
      if (as_binary.at(i) == '1') flip_bits += "0";
      else flip_bits += "1";
    }
    FromBinaryString(flip_bits);

    // Update from |x - 1| to |x| by adding '1'.
    mp_int one;
    mp_init(&one);
    mp_set_int(&one, 1);
    mp_add(value_, &one, value_);
    mp_clear(&one);

    // Update from |x| to x.
    mp_neg(value_, value_);
  }

  std::string ToTwosComplementString() const {
    // For positive values, just use ToBinaryString().
    mp_int zero;
    mp_init_set_int(&zero, 0);
    if (mp_cmp(value_, &zero) != MP_LT) {
      mp_clear(&zero);
      const std::string to_return = ToBinaryString();
      // If leading bit is a '1', we need to prepend an extra byte of 0's, so that
      // when viewed as a 2's complement byte string, it won't indicate a negative value.
      if (to_return.at(0) == '1') return "0" + to_return;
      return to_return;
    }
    mp_clear(&zero);

    // We get the 2's complement string of a negative value by noting that
    //   2sComplement(-x) = ~BinaryString(x - 1),
    // where the '~' denotes NOT (i.e., flip all bits).
    mp_int temp, one;
    mp_init(&temp);
    mp_init(&one);
    mp_set_int(&one, 1);
    mp_abs(value_, &temp);
    mp_sub(&temp, &one, &temp);
    std::string bits_flipped;
    if (!MpIntToBinaryString(&temp, &bits_flipped)) return "";
    mp_clear(&temp);
    mp_clear(&one);
    // Add the sign (2's complement) bit, if the leading bit (of the absolute
    // value) is '1'.
    std::string to_return = bits_flipped.at(0) == '1' ? "1" : "";
    for (size_t i = 0; i < bits_flipped.length(); ++i) {
      if (bits_flipped.at(i) == '1') to_return += "0";
      else to_return += "1";
    }
    return to_return;
  }

  void FromByteString(const std::vector<unsigned char>& byte_string) {
    CharVectorToMpInt(byte_string, value_);
  }
  void FromByteString(const unsigned char* byte_string, const int num_bytes) {
    CharVectorToMpInt(byte_string, num_bytes, value_);
  }
  void FromByteString(const std::vector<char>& byte_string) {
    CharVectorToMpInt(byte_string, value_);
  }
  void FromByteString(const char* byte_string, const int num_bytes) {
    CharVectorToMpInt(byte_string, num_bytes, value_);
  }

  void FromByteString(
      const char* byte_string, const int num_bytes, const int endian) {
    // could skip this and go straight to mp_import like in the GMP definition below.
    CharVectorToMpInt(byte_string, num_bytes, endian, value_);
  }
  void ToByteString(std::vector<unsigned char>* output) const {
    MpIntToCharVector(value_, output);
  }

  void ToByteString(const int endian, std::vector<unsigned char>* output) const {
    MpIntToCharVector(endian, value_, output) :
  }

  void ToByteString(
      const int endian, int* num_bytes, unsigned char** output) const {
    // TODO(paul): Wasteful. Better to either:
    //   a) Update mp_int_utils.h,cpp to have an API to MpIntToCharVector()
    //      that takes in unsigned char* instead of vector
    //   b) Just call LibTom functions directly (e.g. copy-paste the current
    //      code in MpIntToCharVector(), with obvious changes, to here.
    vector<unsigned char> foo;
    ToByteString(endian, &foo);
    *num_bytes = foo.size();
    *output = (unsigned char*) malloc(*num_bytes);
    memcpy(*output, foo.data(), *num_bytes);
  }

  void FromTwosComplementByteString(
      const std::vector<unsigned char>& byte_string) {
    // For positive values, just use FromByteString.
    if (!((byte_string[0] >> (CHAR_BIT - 1)) & 1)) {
      FromByteString(byte_string);
      return;
    }

    // The fact that we reached here means that byte_string represents a negative
    // value. Construct the byte string that would correspond to |x - 1|, by
    // noting that this is simply the NOT of the input byte string.
    std::vector<unsigned char> abs_value(byte_string.size());
    for (size_t i = 0; i < byte_string.size(); ++i) {
      abs_value[i] = ~(byte_string[i]);
    }

    // Set value_ to be |x - 1|.
    FromByteString(abs_value);

    // Add 1 to get |x|.
    mp_int one;
    mp_init(&one);
    mp_set_int(&one, 1);
    mp_add(value_, &one, value_);
    mp_clear(&one);

    // Multiply by -1, to get x.
    mp_neg(value_, value_);
  }

  void FromTwosComplementByteString(const std::vector<char>& byte_string) {
    // For positive values, just use FromByteString.
    if (!((byte_string[0] >> (CHAR_BIT - 1)) & 1)) {
      FromByteString(byte_string);
      return;
    }

    // The fact that we reached here means that byte_string represents a negative
    // value. Construct the byte string that would correspond to |x - 1|, by
    // noting that this is simply the NOT of the input byte string.
    std::vector<char> abs_value(byte_string.size());
    for (size_t i = 0; i < byte_string.size(); ++i) {
      abs_value[i] = ~(byte_string[i]);
    }

    // Set value_ to be |x - 1|.
    FromByteString(abs_value);

    // Add 1 to get |x|.
    mp_int one;
    mp_init(&one);
    mp_set_int(&one, 1);
    mp_add(value_, &one, value_);
    mp_clear(&one);

    // Multiply by -1, to get x.
    mp_neg(value_, value_);
  }

  void ToTwosComplementByteString(std::vector<unsigned char>* output) const {
    // For positive values, just use ToByteString.
    mp_int zero;
    mp_init_set_int(&zero, 0);
    if (mp_cmp(value_, &zero) != MP_LT) {
      mp_clear(&zero);
      ToByteString(output);
      // If leading bit is a '1', we need to prepend a '0' byte, so that this
      // value is not interpretted as a negative value (since user called
      // ToTwosComplement() instead of just ToBinary())
      if (((*output)[0] >> (CHAR_BIT - 1)) & 1) {
        const int orig_size = (int) output->size();
        output->push_back(0);
        for (int i = orig_size - 1; i >= 0; --i) {
          (*output)[i + 1] = (*output)[i];
        }
        (*output)[0] = 0;
      }
      return;
    }

    // This is a negative value. MP_INT does not do conversion to 2's complement
    // (byte or bit) strings. Instead, get the byte string of |x - 1|, and
    // manually construct the 2's complement byte string from that.
    mp_clear(&zero);
    mp_int one, abs_minus_one;
    mp_init(&abs_minus_one);
    mp_init(&one);
    mp_set_int(&one, 1);
    mp_abs(value_, &abs_minus_one);
    mp_sub(&abs_minus_one, &one, &abs_minus_one);
    std::vector<unsigned char> abs_value;
    MpIntToCharVector(&abs_minus_one, &abs_value);
    mp_clear(&abs_minus_one);
    mp_clear(&one);

    // Now flip all bits.
    // NOTE: We need to handle the special case that the leading bit (of the
    // leading byte) of |x - 1| is '1', since in this case, we need to update
    // the byte string representation of |x - 1| by prepending a byte of 0's.
    const size_t num_bytes = abs_value.size();
    const bool leading_bit_is_one = (abs_value[0] >> (CHAR_BIT - 1)) & 1;
    const size_t orig_size = output->size();
    output->resize(orig_size + num_bytes + (leading_bit_is_one ? 1 : 0));
    if (leading_bit_is_one) {
      (*output)[orig_size] = ~((unsigned char) 0);
    }
    const size_t start_byte = leading_bit_is_one ? 1 : 0;
    for (size_t i = 0; i < num_bytes; ++i) {
      (*output)[orig_size + start_byte + i] = ~(abs_value[i]);
    }
  }
};
#endif
#ifdef LARGE_INT_GMP
// Gmp (from GMP library) data type.
struct GmpType : public LargeIntType {
  mpz_t value_;

  GmpType() {
    mpz_init(value_);
    mpz_set_ui(value_, 0);
  }

  virtual ~GmpType() { mpz_clear(value_); }

  void CopyFrom(const GmpType& other) { mpz_set(value_, other.value_); }

  int32_t GetInt32() const { return (int32_t) mpz_get_si(value_); }
  uint32_t GetUInt32() const { return (uint32_t) mpz_get_ui(value_); }
  // NOTE: GMP does not offer conversion to Int64 (long long) types.
  // The below will return [u]int64_t, but in reality they are casting
  // this from [u]int32_t, so overflow will be a problem if the value
  // returned would have been more than 32 bits.
  int64_t GetInt64() const {
    return (mpz_getlimbn(value_, 0) * (mpz_sgn(value_) == -1 ? -1 : 1));
  }
  uint64_t GetUInt64() const { return mpz_getlimbn(value_, 0); }

  std::string Print() const {
    return std::string(mpz_get_str(nullptr, 10, value_));
  }

  void FromString(const std::string& input, const char base) {
    if (base == 2 || base == 10 || base == 16) {
      mpz_set_str(value_, input.c_str(), base);
    } else {
      LOG_FATAL("Unsupported base.");
    }
  }

  std::string ToString(const char base) const {
    if (base != 2 && base != 10 && base != 16) LOG_FATAL("Unsupported base.");
    return std::string(mpz_get_str(nullptr, base, value_));
  }

  void FromBinaryString(const std::string& as_binary) {
    mpz_set_str(value_, as_binary.c_str(), 2);
  }

  std::string ToBinaryString() const {
    return std::string(mpz_get_str(nullptr, 2, value_));
  }

  void FromTwosComplementString(const std::string& as_binary) {
    if (as_binary.empty()) {
      mpz_set_ui(value_, 0);
      return;
    }

    // If leading bit is '0', then this is a positive value, and 2's Complement
    // string is identical to Binary String, so just call the former.
    if (as_binary.at(0) == '0') {
      FromBinaryString(as_binary);
      return;
    }

    // Leading bit is '1', signifying a negative value. We will use the
    // relationship noted above in ToTwosComplementString(): We can flip
    // all bits, add 1, and then flip sign.
    std::string flip_bits = "";
    for (size_t i = 0; i < as_binary.length(); ++i) {
      if (as_binary.at(i) == '1') flip_bits += "0";
      else flip_bits += "1";
    }
    FromBinaryString(flip_bits);

    // Add 1, to get |x|.
    mpz_add_ui(value_, value_, 1);

    // Flip sign, to get x.
    mpz_neg(value_, value_);
  }

  std::string ToTwosComplementString() const {
    // For positive values, just use the mpz_get_str().
    if (mpz_cmp_ui(value_, 0) >= 0) {
      const std::string to_return = std::string(mpz_get_str(nullptr, 2, value_));
      // If leading bit is a '1', we need to prepend an extra '0' so that when
      // viewed as a 2's complement byte string, it won't indicate a negative value.
      if (to_return.at(0) == '1') return "0" + to_return;
      return to_return;
    }

    // We get the 2's complement string of a negative value by noting that
    //   2sComplement(-x) = ~BinaryString(x - 1),
    // where the '~' denotes NOT (i.e., flip all bits).
    mpz_t temp;
    mpz_init(temp);
    mpz_abs(temp, value_);
    mpz_sub_ui(temp, temp, 1);
    const std::string bits_flipped = std::string(mpz_get_str(nullptr, 2, temp));
    mpz_clear(temp);
    // Add the sign (2's complement) bit, if the leading bit (of the absolute
    // value) is '1'.
    std::string to_return = bits_flipped.at(0) == '1' ? "1" : "";
    for (size_t i = 0; i < bits_flipped.length(); ++i) {
      if (bits_flipped.at(i) == '1') to_return += "0";
      else to_return += "1";
    }
    return to_return;
  }

  void FromByteString(const std::vector<unsigned char>& byte_string) {
    mpz_import(value_, 1, 1, byte_string.size(), 1, 0, byte_string.data());
  }

  void FromByteString(const unsigned char* byte_string, const int num_bytes) {
    mpz_import(value_, 1, 1, num_bytes, 1, 0, byte_string);
  }

  void FromByteString(
      const unsigned char* byte_string, const int num_bytes, const int endian) {
    mpz_import(value_, 1, 1, num_bytes, endian, 0, byte_string);
  }

  void FromByteString(const std::vector<char>& byte_string) {
    mpz_import(value_, 1, 1, byte_string.size(), 1, 0, byte_string.data());
  }
  void FromByteString(const char* byte_string, const int num_bytes) {
    mpz_import(value_, 1, 1, num_bytes, 1, 0, byte_string);
  }

  void ToByteString(const int endian, std::vector<unsigned char>* output) const {
    const size_t num_bits = mpz_sizeinbase(value_, 2);
    const size_t num_bytes =
        num_bits / CHAR_BIT + (num_bits % CHAR_BIT == 0 ? 0 : 1);
    const size_t orig_size = output->size();
    output->resize(orig_size + num_bytes);
    mpz_export(
        output->data() + orig_size, nullptr, 1, num_bytes, endian, 0, value_);
  }

  void ToByteString(std::vector<unsigned char>* output) const {
    ToByteString(1, output);
  }

  void ToByteString(
      const int endian, int* num_bytes, unsigned char** output) const {
    const size_t num_bits = mpz_sizeinbase(value_, 2);
    *num_bytes =
        (int) (num_bits / CHAR_BIT + (num_bits % CHAR_BIT == 0 ? 0 : 1));
    *output = (unsigned char*) malloc(*num_bytes);
    mpz_export(*output, nullptr, 1, *num_bytes, endian, 0, value_);
  }

  void FromTwosComplementByteString(
      const std::vector<unsigned char>& byte_string) {
    // For positive values, just use FromByteString.
    if (!((byte_string[0] >> (CHAR_BIT - 1)) & 1)) {
      FromByteString(byte_string);
      return;
    }

    // The fact that we reached here means that byte_string represents a negative
    // value. Construct the byte string that would correspond to |x - 1|, by
    // noting that this is simply the NOT of the input byte string.
    std::vector<unsigned char> abs_value(byte_string.size());
    for (size_t i = 0; i < byte_string.size(); ++i) {
      abs_value[i] = UCHAR_MAX ^ byte_string[i];
    }

    // Set value_ to be |x - 1|.
    FromByteString(abs_value);

    // Add 1 to get |x|.
    mpz_add_ui(value_, value_, 1);

    // Multiply by -1, to get x.
    mpz_neg(value_, value_);
  }

  void FromTwosComplementByteString(const std::vector<char>& byte_string) {
    // For positive values, just use FromByteString.
    if (!((byte_string[0] >> (CHAR_BIT - 1)) & 1)) {
      FromByteString(byte_string);
      return;
    }

    // The fact that we reached here means that byte_string represents a negative
    // value. Construct the byte string that would correspond to |x - 1|, by
    // noting that this is simply the NOT of the input byte string.
    std::vector<char> abs_value(byte_string.size());
    for (size_t i = 0; i < byte_string.size(); ++i) {
      abs_value[i] = (char) (UCHAR_MAX ^ (unsigned char) byte_string[i]);
    }

    // Set value_ to be |x - 1|.
    FromByteString(abs_value);

    // Add 1 to get |x|.
    mpz_add_ui(value_, value_, 1);

    // Multiply by -1, to get x.
    mpz_neg(value_, value_);
  }

  void ToTwosComplementByteString(std::vector<unsigned char>* output) const {
    // For positive values, just use ToByteString.
    if (mpz_cmp_ui(value_, 0) >= 0) {
      ToByteString(output);
      // If leading bit is a '1', we need to prepend a '0' byte, so that this
      // value is not interpretted as a negative value (since user called
      // ToTwosComplement() instead of just ToBinary())
      if (((*output)[0] >> (CHAR_BIT - 1)) & 1) {
        const int orig_size = (int) output->size();
        output->push_back(0);
        for (int i = orig_size - 1; i >= 0; --i) {
          (*output)[i + 1] = (*output)[i];
        }
        (*output)[0] = 0;
      }
      return;
    }

    // This is a negative value. GMP does not do conversion to 2's complement
    // (byte or bit) strings. Instead, get the byte string of |x - 1|, and
    // manually construct the 2's complement byte string from that.
    mpz_t abs_minus_one;
    mpz_init(abs_minus_one);
    mpz_abs(abs_minus_one, value_);
    mpz_sub_ui(abs_minus_one, abs_minus_one, 1);
    const size_t num_bits = mpz_sizeinbase(abs_minus_one, 2);
    const size_t num_bytes =
        num_bits / CHAR_BIT + (num_bits % CHAR_BIT == 0 ? 0 : 1);
    std::vector<unsigned char> abs_value(num_bytes);
    mpz_export(abs_value.data(), nullptr, 1, num_bytes, 1, 0, abs_minus_one);
    mpz_clear(abs_minus_one);

    // Now flip all bits.
    // NOTE: We need to handle the special case that the leading bit (of the
    // leading byte) of |x - 1| is '1', since in this case, we need to update
    // the byte string representation of |x - 1| by prepending a byte of 0's.
    const bool leading_bit_is_one = (abs_value[0] >> (CHAR_BIT - 1)) & 1;
    const size_t orig_size = output->size();
    output->resize(orig_size + num_bytes + (leading_bit_is_one ? 1 : 0));
    if (leading_bit_is_one) {
      (*output)[orig_size] = ~((unsigned char) 0);
    }
    const size_t start_byte = leading_bit_is_one ? 1 : 0;
    for (size_t i = 0; i < num_bytes; ++i) {
      (*output)[orig_size + start_byte + i] = UCHAR_MAX ^ abs_value[i];
    }
  }
};
#endif
#ifdef LARGE_INT_MPIR
// mpir (from mpir library) data type.
struct MpirType : public LargeIntType {
  // TODO: Fill in field 'value_' that has appropriate (MPIR) data type, e.g.:
  //mpir value_

  // TODO: Fill-in all of the functions below.
  MpirType() {}

  virtual ~MpirType() {}

  void CopyFrom(const MpirType& other) {}

  int32_t GetInt32() const { return 0; }
  uint32_t GetUInt32() const { return 0; }
  int64_t GetInt64() const { return 0; }
  uint64_t GetUInt64() const { return 0; }

  std::string Print() const { return ""; }

  void FromString(const std::string& input, const char base) {}
  std::string ToString(const char base) const { return ""; }
  void FromBinaryString(const std::string& as_binary) {}
  std::string ToBinaryString() const { return ""; }

  void FromTwosComplementString(const std::string& as_binary) {}
  std::string ToTwosComplementString() const { return ""; }

  void FromByteString(const std::vector<unsigned char>& byte_string) {}
  void FromByteString(const unsigned char* byte_string, const int num_bytes) {}
  void FromByteString(
      const unsigned char* byte_string, const int num_bytes, const int endian) {}
  void FromByteString(const std::vector<char>& byte_string) {}
  void FromByteString(const char* byte_string, const int num_bytes) {}
  void ToByteString(std::vector<unsigned char>* output) const {}
  void ToByteString(const int endian, std::vector<unsigned char>* output) const {
  }
  void ToByteString(
      const int endian, int* num_bytes, unsigned char** output) const {}
  void FromTwosComplementByteString(
      const std::vector<unsigned char>& byte_string) {}
  void FromTwosComplementByteString(const std::vector<char>& byte_string) {}
  void ToTwosComplementByteString(std::vector<unsigned char>* output) const {}
};
#endif

class LargeInt {
public:
  // ================================== Constructors ==========================-
  LargeInt() { Init(); }
  LargeInt(const int32_t value);
  LargeInt(const uint32_t value);
  LargeInt(const int64_t& value);
  LargeInt(const uint64_t& value);
  LargeInt(const LargeIntType& other);
  // Destructor.
  virtual ~LargeInt() noexcept { Clear(); }

  // ========================== Rule of 5 Functions ============================
  // Copy Constructor.
  LargeInt(const LargeInt& other);
  // Move Constructor.
  LargeInt(LargeInt&& other) noexcept;
  // Copy-Assignment.
  LargeInt& operator=(const LargeInt& other);
  LargeInt& operator=(const int32_t other);
  LargeInt& operator=(const uint32_t other);
  LargeInt& operator=(const int64_t& other);
  LargeInt& operator=(const uint64_t& other);
  // Move-Assignment.
  LargeInt& operator=(LargeInt&& other) noexcept;
  // ======================== END Rule of 5 Functions ==========================

  // ============================== Basic Functions ============================
  // Initialize (e.g. allocate memory) for this LargeInt.
  void Init();

  // Delete/free memory allocated for this LargeInt.
  void Clear();

  // Returns (a pointer to) the value represented by the LargeInt.
  const LargeIntType* GetValue() const { return x_; }

  std::string Print() const { return x_->Print(); }
  std::string PrintBinaryString() const { return x_->ToBinaryString(); }

  bool IsZero() const;
  static LargeInt Zero();
  static LargeInt One();
  // Convert a LargeInt <-> String representation.
  // Supported only for base = {2, 10, 16}, where '2' is binary representation
  // (always big endian), 10 is standard decimal representation, and 16 is hex
  // (when converting from, can handle leading '0x' or not, and is case-
  // insenstive; when outputting, will output *without* '0x', and all caps).
  static LargeInt FromString(const std::string& input, const char base) {
    LargeInt to_return;
    to_return.FromString(input, base);
    return to_return;
  }
  std::string ToString(const char base) const { return x_->ToString(base); }
  // =========================== END Basic Functions ===========================

  // ========================== Operator overloads =============================
  // Comparison.
  bool operator==(const LargeInt& other) const;
  bool operator==(const int32_t other) const;
  bool operator==(const uint32_t other) const;
  bool operator==(const int64_t& other) const;
  bool operator==(const uint64_t& other) const;
  friend bool operator==(const int32_t one, const LargeInt& two);
  friend bool operator==(const uint32_t one, const LargeInt& two);
  friend bool operator==(const int64_t one, const LargeInt& two);
  friend bool operator==(const uint64_t one, const LargeInt& two);
  bool operator!=(const LargeInt& other) const;
  bool operator!=(const int32_t other) const;
  bool operator!=(const uint32_t other) const;
  bool operator!=(const int64_t& other) const;
  bool operator!=(const uint64_t& other) const;
  friend bool operator!=(const int32_t one, const LargeInt& two);
  friend bool operator!=(const uint32_t one, const LargeInt& two);
  friend bool operator!=(const int64_t one, const LargeInt& two);
  friend bool operator!=(const uint64_t one, const LargeInt& two);
  bool operator>(const LargeInt& other) const;
  bool operator>(const int32_t other) const;
  bool operator>(const uint32_t other) const;
  bool operator>(const int64_t& other) const;
  bool operator>(const uint64_t& other) const;
  friend bool operator>(const int32_t one, const LargeInt& two);
  friend bool operator>(const uint32_t one, const LargeInt& two);
  friend bool operator>(const int64_t one, const LargeInt& two);
  friend bool operator>(const uint64_t one, const LargeInt& two);
  bool operator>=(const LargeInt& other) const;
  bool operator>=(const int32_t other) const;
  bool operator>=(const uint32_t other) const;
  bool operator>=(const int64_t& other) const;
  bool operator>=(const uint64_t& other) const;
  friend bool operator>=(const int32_t one, const LargeInt& two);
  friend bool operator>=(const uint32_t one, const LargeInt& two);
  friend bool operator>=(const int64_t one, const LargeInt& two);
  friend bool operator>=(const uint64_t one, const LargeInt& two);
  bool operator<(const LargeInt& other) const;
  bool operator<(const int32_t other) const;
  bool operator<(const uint32_t other) const;
  bool operator<(const int64_t& other) const;
  bool operator<(const uint64_t& other) const;
  friend bool operator<(const int32_t one, const LargeInt& two);
  friend bool operator<(const uint32_t one, const LargeInt& two);
  friend bool operator<(const int64_t one, const LargeInt& two);
  friend bool operator<(const uint64_t one, const LargeInt& two);
  bool operator<=(const LargeInt& other) const;
  bool operator<=(const int32_t other) const;
  bool operator<=(const uint32_t other) const;
  bool operator<=(const int64_t& other) const;
  bool operator<=(const uint64_t& other) const;
  friend bool operator<=(const int32_t one, const LargeInt& two);
  friend bool operator<=(const uint32_t one, const LargeInt& two);
  friend bool operator<=(const int64_t one, const LargeInt& two);
  friend bool operator<=(const uint64_t one, const LargeInt& two);
  // Arithmetic self-modifiers
  LargeInt& operator+=(const LargeInt& other);
  LargeInt& operator+=(const int32_t other);
  LargeInt& operator+=(const uint32_t other);
  LargeInt& operator+=(const int64_t& other);
  LargeInt& operator+=(const uint64_t& other);
  LargeInt& operator-=(const LargeInt& other);
  LargeInt& operator-=(const int32_t other);
  LargeInt& operator-=(const uint32_t other);
  LargeInt& operator-=(const int64_t& other);
  LargeInt& operator-=(const uint64_t& other);
  LargeInt& operator*=(const LargeInt& other);
  LargeInt& operator*=(const int32_t other);
  LargeInt& operator*=(const uint32_t other);
  LargeInt& operator*=(const int64_t& other);
  LargeInt& operator*=(const uint64_t& other);
  LargeInt& operator/=(const LargeInt& other);
  LargeInt& operator/=(const int32_t other);
  LargeInt& operator/=(const uint32_t other);
  LargeInt& operator/=(const int64_t& other);
  LargeInt& operator/=(const uint64_t& other);
  LargeInt& operator%=(const LargeInt& other);
  LargeInt& operator%=(const int32_t other);
  LargeInt& operator%=(const uint32_t other);
  LargeInt& operator%=(const int64_t& other);
  LargeInt& operator%=(const uint64_t& other);
  // Arithmetic with two arguments.
  // NOTE: We do this as non-member friend functions, as suggested by:
  // http://www.learncpp.com/cpp-tutorial/94-overloading-operators-using-member-functions/
  friend LargeInt operator+(const LargeInt& one, const LargeInt& two);
  friend LargeInt operator+(const LargeInt& one, const int32_t two);
  friend LargeInt operator+(const LargeInt& one, const uint32_t two);
  friend LargeInt operator+(const LargeInt& one, const int64_t& two);
  friend LargeInt operator+(const LargeInt& one, const uint64_t& two);
  friend LargeInt operator+(const int32_t two, const LargeInt& one);
  friend LargeInt operator+(const uint32_t two, const LargeInt& one);
  friend LargeInt operator+(const int64_t& two, const LargeInt& one);
  friend LargeInt operator+(const uint64_t& two, const LargeInt& one);
  friend LargeInt operator-(const LargeInt& one, const LargeInt& two);
  friend LargeInt operator-(const LargeInt& one, const int32_t two);
  friend LargeInt operator-(const LargeInt& one, const uint32_t two);
  friend LargeInt operator-(const LargeInt& one, const int64_t& two);
  friend LargeInt operator-(const LargeInt& one, const uint64_t& two);
  friend LargeInt operator-(const int32_t two, const LargeInt& one);
  friend LargeInt operator-(const uint32_t two, const LargeInt& one);
  friend LargeInt operator-(const int64_t& two, const LargeInt& one);
  friend LargeInt operator-(const uint64_t& two, const LargeInt& one);
  friend LargeInt operator*(const LargeInt& one, const LargeInt& two);
  friend LargeInt operator*(const LargeInt& one, const int32_t two);
  friend LargeInt operator*(const LargeInt& one, const uint32_t two);
  friend LargeInt operator*(const LargeInt& one, const int64_t& two);
  friend LargeInt operator*(const LargeInt& one, const uint64_t& two);
  friend LargeInt operator*(const int32_t two, const LargeInt& one);
  friend LargeInt operator*(const uint32_t two, const LargeInt& one);
  friend LargeInt operator*(const int64_t& two, const LargeInt& one);
  friend LargeInt operator*(const uint64_t& two, const LargeInt& one);
  friend LargeInt operator/(const LargeInt& one, const LargeInt& two);
  friend LargeInt operator/(const LargeInt& one, const int32_t two);
  friend LargeInt operator/(const LargeInt& one, const uint32_t two);
  friend LargeInt operator/(const LargeInt& one, const int64_t& two);
  friend LargeInt operator/(const LargeInt& one, const uint64_t& two);
  friend LargeInt operator/(const int32_t two, const LargeInt& one);
  friend LargeInt operator/(const uint32_t two, const LargeInt& one);
  friend LargeInt operator/(const int64_t& two, const LargeInt& one);
  friend LargeInt operator/(const uint64_t& two, const LargeInt& one);
  friend LargeInt operator%(const LargeInt& one, const LargeInt& two);
  friend LargeInt operator%(const LargeInt& one, const int32_t two);
  friend LargeInt operator%(const LargeInt& one, const uint32_t two);
  friend LargeInt operator%(const LargeInt& one, const int64_t& two);
  friend LargeInt operator%(const LargeInt& one, const uint64_t& two);
  friend LargeInt operator%(const int32_t two, const LargeInt& one);
  friend LargeInt operator%(const uint32_t two, const LargeInt& one);
  friend LargeInt operator%(const int64_t& two, const LargeInt& one);
  friend LargeInt operator%(const uint64_t& two, const LargeInt& one);

  // Negative (flip sign).
  friend LargeInt operator-(const LargeInt& input);

  // Absolute Value.
  friend LargeInt abs(const LargeInt& input);

  // GCD.
  friend LargeInt gcd(const LargeInt& one, const LargeInt& two);

  // LCM.
  friend LargeInt lcm(const LargeInt& one, const LargeInt& two);
  // ======================== END Operator overloads ===========================

  // =============================== Power =====================================
  // Exponent.
  friend LargeInt pow(const LargeInt& base, const uint32_t& exp);
  friend LargeInt pow(const LargeInt& base, const uint64_t& exp);
  friend LargeInt pow(const LargeInt& base, const LargeInt& exp);
  // The following is defined as an 'extern' function below (outside of this class):
  //   1) Attempting to define it here doesn't work, possibly because 'friend'
  //      functions require one of the arguments to be an object of that class.
  //   2) Instead, we just make this an ordinary function with no special access
  //      to LargeInt private variables/functions, and then in the implementation
  //      it calls one of the above APIs.
  //friend LargeInt pow(const uint32_t& base, const uint32_t& exp);

  // Exponent mod N.
  friend LargeInt pow(
      const LargeInt& base, const LargeInt& exp, const LargeInt& modulus);
  friend LargeInt pow(
      const LargeInt& base, const uint32_t& exp, const LargeInt& modulus);

  // (Multiplicative) Inverse mod N. Returns true if the inverse exists
  // (and populates 'inverse'); otherwise returns false.
  friend bool InverseModN(
      const LargeInt& input, const LargeInt& modulus, LargeInt* inverse);
  // ============================= END Power ===================================

  // ========================== Primes, Random  ================================
  // Returns a random value in [0..modulus).
  friend LargeInt RandomInModulus(const LargeInt& modulus);
  // Similar to above, alternate API (for compatibility with Stealth's OT library).
  // The 'num_outputs' argument specifies how many random values to generate.
  // 'output' should be pre-allocated exactly (num_outputs * num_bytes_in_modulus) bytes.
  // Also not that compatibility with Stealth OT library requires normal API rules to
  // be violated (e.g. not doing const size_t& for the two size_t args, and
  // order of args does not respect convention).
  static unsigned long RandomInModulus(
      void* cookie, /* not used */
      const unsigned char* modulus,
      size_t num_bytes_in_modulus,
      unsigned char* output,
      size_t num_outputs);

  // Returns a random prime with at most N = 'modulus_bits' bits. More precisely,
  // prime will be chosen uniformly randomly in: [a, b), where b = 2^N,
  // and a = 2^(N / 2). Note that having a minimum requirement on minimum
  // size of the prime chosen is necessary for cryptographic purposes: we don't
  // want to pick primes that are too small. However, choosing a random prime
  // between [0, b) will overwhelmingly also lie in [a, b), since the probability
  // of lying in [0, a) is a / b, which is 1 / 2^(N / 2).
  static LargeInt RandomPrime(const uint32_t& modulus_bits);

  // Returns the *next* prime larger than input.
  friend LargeInt NextPrime(const LargeInt& input);
  // ======================== END Primes, Random  ==============================

  // ====================== LargeInt <-> Byte Array  ===========================
  // Returns the number of bytes required to represent this value, i.e. the size
  // of the resulting vector if 'LargeIntToByteString' were to be called.
  int NumBytes() const;
  static LargeInt BinaryStringToLargeInt(const std::string& input);
  // Similar to above, for 2's complement representation.
  static LargeInt TwosComplementStringToLargeInt(const std::string& input);
  // NOTE: It is assumed that the byte (bit) stream represents the number directly
  // in binary format. In particular, casting a numeric type (e.g. uint64_t) as
  // a character array and then applying ByteStringToLargeInt() to it may not work
  // (depending on system ENDIANESS), since the cast character array may NOT
  // be the binary string representation (high/low order bits swapped).
  static LargeInt ByteStringToLargeInt(const std::vector<unsigned char>& input);
  // Same as above, for char vector.
  static LargeInt ByteStringToLargeInt(const std::vector<char>& input);
  // Same as above, alternate API.
  static LargeInt ByteStringToLargeInt(
      const unsigned char* input, const int num_bytes);

  // Same as above, but with endian-ness specified
  static LargeInt ByteStringToLargeInt(
      const unsigned char* input, const int num_bytes, const int endian);

  // Same as above, for char*.
  static LargeInt ByteStringToLargeInt(const char* input, const int num_bytes);
  // Similar to above, for 2's complement representation.
  static LargeInt TwosComplementStringToLargeInt(
      const std::vector<unsigned char>& input);
  // Same as above, for char vector.
  static LargeInt TwosComplementStringToLargeInt(const std::vector<char>& input);
  // Similar to above, in the other direction.
  // If output vector is non-empty, appends to the end.
  friend void LargeIntToByteString(
      const LargeInt& input, std::vector<unsigned char>* output);

  // same as above, but specify little or big endian
  friend void LargeIntToByteString(
      const int endian,
      const LargeInt& input,
      std::vector<unsigned char>* output);

  // Similar to above, for 2's complement representation.
  friend void LargeIntToTwosComplementString(
      const LargeInt& input, std::vector<unsigned char>* output);
  // ==================== END LargeInt <-> Byte Array  =========================
private:
  // Member variables.
  //   - Actual value of this LargeInt.
  LargeIntType* x_;

  // Static member variables (for thread safety).
  static std::unique_ptr<Mutex> random_seed_mutex_;
  static bool random_seed_is_set_;

  // Overload 'print' operator.
  friend std::ostream& operator<<(std::ostream& os, const LargeInt& input) {
    os << input.x_->Print();
    return os;
  }
};

// ====================== LargeInt Utility Functions ===========================

// Returns whether the input is prime (with high probability).
extern bool IsPrime(const LargeInt& input);

// Log_2. We return uint32_t (as opposed to LargeInt) because having an exponent
// larger than 2^32 is unreasonable, and is likely a bug anyway.
extern uint32_t log2(const LargeInt& input);

// Raises base^exp. This is the same as the 'friend' functions (defined within
// the LargeInt class above), but is placed here because the API (which doesn't
// include a LargeInt input parameter) doesn't allow it to be a friend function.
extern LargeInt pow(const uint32_t& base, const uint32_t& exp);
}  // namespace math_utils

#endif
