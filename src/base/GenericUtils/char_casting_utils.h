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
//   Utility functions for going back and forth between untyped bytes
//   (i.e. [unsigned] characters) and typed objects.
//
// Discussion:
// For any unsigned (numeric) type (see TODO inside ByteStringToValue() below
// why we restrict functionality to *unsigned* buffers), we can imagine two ways
// of casting to a vector of bytes:
//   1) As a byte-string (= Big Endian), so that viewing a byte as 8-bits,
//      then reading the vector (of bytes) from left-to-right would give the
//      binary string representation of the value. In other words, vector[0]
//      will be the 8 most significant bits of value, and vector.back() will
//      be the 8 least significant bits of the value.
//   2) Consistent with how the system actually stores the value (as a
//      contiguous block of bytes in memory)
// (Actually, a third way would be to write the number as a string, so that
// the vector of bytes is the character/string representation of the number;
// this case is not covered in this file, use string_utils::Stoi for this.)
// Note that (1) and (2) are equivalent iff the system stores values in
// BIG-ENDIAN format. Doing (2) is trivial: just cast the value as a
// char vector (see examples below); however, we provide functions for these for
// clarity (so the caller can be assured of behavior):
//   CharVectorToValue[Vector]: Does (2) for vector<unsigned char> -> value_t
//   Value[Vector]ToCharVector: Does (2) for value_t -> vector<unsigned char>
// If you desire interpretation (1), so you always interpret a vector of bytes
// as the byte-string representation of a value (i.e. Big-Endian), use:
//   ByteStringToValue[Vector]: Does (1) for vector<unsigned char> -> value_t
//   Value[Vector]ToByteString: Does (1) for value_t -> vector<unsigned char>
//
// As mentioned above, the functions provided that do (2) are not necessary.
// For example, suppose a function takes in a char array and its size (in bytes):
//   Foo(char* input, size_t num_bytes_in_input),
// and I have a slice "bar" that I want to give it. Then I can do:
//   Foo((char*) &bar, sizeof(slice));
// Or with a vector<slice> "bar":
//   Foo((char*) bar.data(), sizeof(slice) * bar.size());
#ifndef CHAR_CASTING_UTILS_H
#define CHAR_CASTING_UTILS_H

#include "MathUtils/constants.h"  // For slice
#include "global_utils.h"  // For LOG_FATAL and GetEndianness

#include <climits>  // For CHAR_BIT
#include <vector>

// =========== Usage (1) ByteString -> Value (see Discussion at top) ===========

// Interpret the characters between [from, to) (note the 'from' is inclusive,
// while 'to' is exclusive) as a numeric value of the appropriate type.
template<typename value_t>
inline value_t ByteStringToValue(
    const uint64_t& from,
    const uint64_t& to,
    const std::vector<unsigned char>& buffer) {
  if (buffer.size() <= from) {
    LOG_FATAL(
        "Start index (" + string_utils::Itoa(from) + ") exceeds buffer size (" +
        string_utils::Itoa(buffer.size()) + ").");
  }
  const size_t value_t_bytes = sizeof(value_t);
  if (to <= from || to != from + value_t_bytes) {
    LOG_FATAL(
        "Cannot cast a buffer of size " +
        string_utils::Itoa((uint64_t) to - from) +
        " as the indicated numeric type of " +
        string_utils::Itoa(value_t_bytes) + " bytes (wrong number of bytes).");
  }

  // Check if there are value_t_bytes bytes to use in buffer; otherwise, we
  // just use the bytes we have (and treat missing bytes as leading '0's).
  const size_t stop_byte =
      to <= buffer.size() ? value_t_bytes : buffer.size() - from;

  value_t to_return = 0;
  for (size_t i = 0; i < stop_byte; ++i) {
    // We need to cast buffer[] as 'value_t', as for numeric types that are
    // greater than 32 bits (e.g. int64_t), element buffer[i] will be cast
    // as an int (32 bits), and then when j >= 4, we'll shift past 32 bits,
    // and end up with zero.
    to_return = static_cast<value_t>(
        to_return +
        ((value_t) buffer[i + from] << (stop_byte - 1 - i) * CHAR_BIT));
    // TODO: WARNING: The above line casts buffer[x] as datatype value_t.
    // This cast is safe/consistent across different OS's because buffer
    // entries are *unsigned*.  If one were to implement this function
    // for *signed* char buffers, then the cast to value_t may cause
    // inconsistent behavior across different OS's.  For example, linux
    // will sign-extend leading 1's for a negative (twos-complement) value.
    // For example, casting a negative char value (say -1 = 11111111) as an
    // unsigned integer (e.g. uint16_t) may become 255 = 00000000 11111111
    // or UINT16_MAX = 11111111 11111111, depending on the OS. One
    // potential way to avoid this is to bitwise AND the casted buffer
    // value with UCHAR_MAX to force 0-padding; but this may or may not
    // be the desired behavior.
    // This is why we do not support an API that takes as input a
    // *signed* buffer, since the desired/appropriate behavior is
    // not well-defined, as is the OS's manner of filling leading bits.
  }

  return to_return;
}
// Same as above, but only take in a start position (end position will be
// determined by sizeof(value_t)).
template<typename value_t>
inline value_t ByteStringToValue(
    const uint64_t& from, const std::vector<unsigned char>& buffer) {
  return ByteStringToValue<value_t>(from, from + sizeof(value_t), buffer);
}
// Same as above, but with from = 0.
template<typename value_t>
inline value_t ByteStringToValue(const std::vector<unsigned char>& buffer) {
  return ByteStringToValue<value_t>(0, buffer);
}
// Same as above, for unsigned char array (instead of vector).
template<typename value_t>
inline value_t ByteStringToValue(
    const uint64_t& num_bytes, const unsigned char* const buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  if (num_bytes > value_t_bytes) {
    LOG_FATAL(
        "Cannot cast a buffer of size " + string_utils::Itoa(num_bytes) +
        " as the indicated numeric type of " +
        string_utils::Itoa(value_t_bytes) + " bytes (wrong number of bytes).");
  }

  value_t to_return = 0;
  for (size_t i = 0; i < num_bytes; ++i) {
    // We need to cast buffer[] as 'value_t', as for numeric types that are
    // greater than 32 bits (e.g. int64_t), element buffer[i] will be cast
    // as an int (32 bits), and then when j >= 4, we'll shift past 32 bits,
    // and end up with zero.
    to_return = static_cast<value_t>(
        to_return + ((value_t) buffer[i] << (num_bytes - 1 - i) * CHAR_BIT));
  }

  return to_return;
}

// Same as above, but interpret as a vector of values.
template<typename value_t>
inline std::vector<value_t> ByteStringToValueVector(
    const uint64_t& from,
    const uint64_t& to,
    const std::vector<unsigned char>& buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  uint64_t num_elements = (to - from) / value_t_bytes;

  // Make sure buffer is an integer multiple of value_t_bytes.
  if (to <= from || to != from + num_elements * value_t_bytes) {
    LOG_FATAL(
        "Cannot cast a buffer of size " +
        string_utils::Itoa((uint64_t) to - from) +
        " as a vector of the indicated numeric type (wrong number of bytes).");
  }

  std::vector<value_t> to_return(num_elements, value_t());
  for (uint64_t i = 0; i < num_elements; ++i) {
    value_t& current_value = to_return[i];
    current_value = 0;  // Should be default to value_t(), but just in case...
    for (size_t j = 0; j < value_t_bytes; ++j) {
      // We need to cast buffer[] as 'value_t', as for numeric types that are
      // greater than 32 bits (e.g. int64_t), element buffer[i] will be cast
      // as an int (32 bits), and then when j >= 4, we'll shift past 32 bits,
      // and end up with zero.
      current_value = static_cast<value_t>(
          current_value +
          ((value_t) buffer[from + value_t_bytes * i + j]
           << (value_t_bytes - 1 - j) * CHAR_BIT));
    }
  }

  return to_return;
}
// Same as above, but only input 'from' (and read the remainder of buffer).
template<typename value_t>
inline std::vector<value_t> ByteStringToValueVector(
    const uint64_t& from, const std::vector<unsigned char>& buffer) {
  return ByteStringToValueVector<value_t>(from, buffer.size(), buffer);
}
// Same as above, but use the entire buffer.
template<typename value_t>
inline std::vector<value_t> ByteStringToValueVector(
    const std::vector<unsigned char>& buffer) {
  return ByteStringToValueVector<value_t>(0, buffer.size(), buffer);
}

// Same as above, but alternate API (char* instead of vector).
template<typename value_t>
inline std::vector<value_t> ByteStringToValueVector(
    const uint64_t& from,
    const uint64_t& to,
    const unsigned char* const buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  uint64_t num_elements = (to - from) / value_t_bytes;

  // Make sure buffer is an integer multiple of value_t_bytes.
  if (to <= from || to != from + num_elements * value_t_bytes) {
    LOG_FATAL(
        "Cannot cast a buffer of size " +
        string_utils::Itoa((uint64_t) to - from) +
        " as a vector of the indicated numeric type (wrong number of bytes).");
  }

  std::vector<value_t> to_return(num_elements, value_t());
  for (uint64_t i = 0; i < num_elements; ++i) {
    value_t& current_value = to_return[i];
    current_value = 0;  // Should be default to value_t(), but just in case...
    for (size_t j = 0; j < value_t_bytes; ++j) {
      // We need to cast buffer[] as 'value_t', as for numeric types that are
      // greater than 32 bits (e.g. int64_t), element buffer[i] will be cast
      // as an int (32 bits), and then when j >= 4, we'll shift past 32 bits,
      // and end up with zero.
      current_value = static_cast<value_t>(
          current_value +
          ((value_t) buffer[from + value_t_bytes * i + j]
           << (value_t_bytes - 1 - j) * CHAR_BIT));
    }
  }

  return to_return;
}
// Same as above, but start from the beginning ('from' = 0).
template<typename value_t>
inline std::vector<value_t> ByteStringToValueVector(
    const uint64_t& num_bytes, const unsigned char* const buffer) {
  return ByteStringToValueVector<value_t>(0, num_bytes, buffer);
}
// ========= END Usage (1) ByteString -> Value (see Discussion at top) =========

// =========== Usage (1) Value -> ByteString (see Discussion at top) ===========
// Cast the numeric value as byte string.
// NOTES:
//  1) This will resize the vector to have the appropriate size, which is:
//      - num_bytes: If append is 'false'
//      - num_bytes + orig_size: If append is 'true'
//  2) The provided 'num_bytes' should be <= sizeof(value_t). For strict
//     inequality (if num_bytes < sizeof(value_t)), if the input value is
//     larger than 'num_bytes', only the *trailing* 'num_bytes' bytes
//     will be copied.
template<typename value_t>
inline bool ValueToByteString(
    const bool append,
    const size_t num_bytes,
    const value_t& input,
    std::vector<unsigned char>* buffer) {
  const size_t orig_size = buffer->size();
  const size_t start_index = append ? orig_size : 0;
  if (append) {
    buffer->resize(orig_size + num_bytes);
  } else if (orig_size < num_bytes) {
    buffer->resize(num_bytes);
  }
  const value_t char_mask = (value_t) UCHAR_MAX;
  for (size_t i = 0; i < num_bytes; ++i) {
    (*buffer)[start_index + i] =
        (unsigned char) ((input >> ((num_bytes - 1 - i) * CHAR_BIT)) & char_mask);
  }

  return true;
}
// Same as above, default 'num_bytes' to sizeof(value_t).
template<typename value_t>
inline bool ValueToByteString(
    const bool append,
    const value_t& input,
    std::vector<unsigned char>* buffer) {
  return ValueToByteString<value_t>(append, sizeof(value_t), input, buffer);
}
// Same as above, but defaults to 'append = true'.
template<typename value_t>
inline bool ValueToByteString(
    const value_t& input, std::vector<unsigned char>* buffer) {
  return ValueToByteString<value_t>(true, input, buffer);
}

// Same as above with output an unsigned char* instead of a vector.
template<typename value_t>
inline bool ValueToByteString(
    const size_t num_bytes, const value_t& input, unsigned char* buffer) {
  const value_t char_mask = UCHAR_MAX;
  for (size_t i = 0; i < num_bytes; ++i) {
    *(buffer + i) =
        (unsigned char) ((input >> ((num_bytes - 1 - i) * CHAR_BIT)) & char_mask);
  }
  return true;
}
// Same as above, default to setting num_bytes to sizeof(value_t).
template<typename value_t>
inline bool ValueToByteString(const value_t& input, unsigned char* buffer) {
  return ValueToByteString<value_t>(sizeof(value_t), input, buffer);
}

// Cast the vector of numeric values as a vector<unsigned char>
template<typename value_t>
inline bool ValueVectorToByteString(
    const std::vector<value_t>& input, std::vector<unsigned char>* buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  const size_t orig_buffer_size = buffer->size();
  const size_t num_new_bytes = input.size() * value_t_bytes;
  buffer->resize(orig_buffer_size + num_new_bytes);
  for (size_t i = 0; i < input.size(); ++i) {
    const value_t& value = input[i];
    for (size_t j = 0; j < value_t_bytes; ++j) {
      (*buffer)[orig_buffer_size + i * value_t_bytes + j] =
          (unsigned char) ((value >> (value_t_bytes - 1 - j) * CHAR_BIT) & ~0);
    }
  }

  return true;
}
// ========= END Usage (1) Value -> ByteString (see Discussion at top) =========

// ============= Usage (2) Bytes -> Value (see Discussion at top) ==============
// Interpret the characters between [from, to) (note the 'from' is inclusive,
// while 'to' is exclusive) as a numeric value of the appropriate type.
template<typename value_t>
inline value_t CharVectorToValue(
    const uint64_t& from,
    const uint64_t& to,
    const std::vector<unsigned char>& buffer) {
  if (buffer.size() <= from) LOG_FATAL("Start index exceeds buffer size.");
  const size_t value_t_bytes = sizeof(value_t);
  if (to <= from || to != from + value_t_bytes) {
    LOG_FATAL(
        "Cannot cast a buffer of size " +
        string_utils::Itoa((uint64_t) to - from) +
        " as the indicated numeric type of " +
        string_utils::Itoa(value_t_bytes) + " bytes (wrong number of bytes).");
  }

  // Check if there are value_t_bytes bytes to use in buffer, in which case
  // can just cast the input vector as the appropriate type.
  if (to <= buffer.size()) return *((value_t*) (buffer.data() + from));
  // Not enough bytes in input vector: treat missing bytes as leading '0's.
  const size_t stop_byte = buffer.size() - from;
  value_t to_return = 0;
  for (size_t i = 0; i < stop_byte; ++i) {
    // Cast buffer[] as 'value_t' so that we don't overflow when bit-shifting below.
    if (GetEndianness() == SYSTEM_ENDIAN::BIG) {
      to_return = static_cast<value_t>(
          to_return +
          ((value_t) buffer[i + from] << (stop_byte - 1 - i) * CHAR_BIT));
    } else {
      to_return = static_cast<value_t>(
          to_return + ((value_t) buffer[i + from] << (CHAR_BIT * i)));
    }
  }

  return to_return;
}
// Same as above, but only take in a start position (end position will be
// determined by sizeof(value_t)).
template<typename value_t>
inline value_t CharVectorToValue(
    const uint64_t& from, const std::vector<unsigned char>& buffer) {
  return CharVectorToValue<value_t>(from, from + sizeof(value_t), buffer);
}
// Same as above, but with from = 0.
template<typename value_t>
inline value_t CharVectorToValue(const std::vector<unsigned char>& buffer) {
  return CharVectorToValue<value_t>(0, buffer);
}
// Same as above, for unsigned char array (instead of vector).
// The 'num_bytes' here is the number of bytes of 'buffer' to copy.
// We require:
//   (i) buffer has size at least num_bytes
//  (ii) num_bytes <= sizeof(value_t)
// If num_bytes < sizeof(value_t), then we pretend that buffer simply
// had leading zeros.
template<typename value_t>
inline value_t CharVectorToValue(
    const uint64_t& num_bytes, const unsigned char* const buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  if (num_bytes > value_t_bytes) {
    LOG_FATAL(
        "Cannot cast a buffer of size " + string_utils::Itoa(num_bytes) +
        " as the indicated numeric type of " +
        string_utils::Itoa(value_t_bytes) + " bytes (wrong number of bytes).");
  }

  // Check if there are value_t_bytes bytes to use in buffer, in which case
  // can just cast the input vector as the appropriate type.
  if (num_bytes == value_t_bytes) return *((value_t*) buffer);
  // Not enough bytes in input vector: treat missing bytes as leading '0's.
  value_t to_return = 0;
  for (size_t i = 0; i < num_bytes; ++i) {
    // Cast buffer[] as 'value_t' so that we don't overflow when bit-shifting below.
    if (GetEndianness() == SYSTEM_ENDIAN::BIG) {
      to_return = static_cast<value_t>(
          to_return + ((value_t) buffer[i] << (num_bytes - 1 - i) * CHAR_BIT));
    } else {
      to_return = static_cast<value_t>(
          to_return + ((value_t) buffer[i] << (CHAR_BIT * i)));
    }
  }

  return to_return;
}
// Same as above, assume buffer has at least sizeof(value_t) bytes.
template<typename value_t>
inline value_t CharVectorToValue(const unsigned char* buffer) {
  return CharVectorToValue<value_t>(sizeof(value_t), buffer);
}
// Same as above, but interpret as a vector of values.
template<typename value_t>
inline std::vector<value_t> CharVectorToValueVector(
    const uint64_t& from,
    const uint64_t& to,
    const std::vector<unsigned char>& buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  uint64_t num_elements = (to - from) / value_t_bytes;

  // Make sure buffer is an integer multiple of value_t_bytes.
  if (to <= from || to != from + num_elements * value_t_bytes) {
    LOG_FATAL(
        "Cannot cast a buffer of size " +
        string_utils::Itoa((uint64_t) to - from) +
        " as a vector of the indicated numeric type (wrong number of bytes).");
  }

  std::vector<value_t> to_return(num_elements, value_t());
  for (uint64_t i = 0; i < num_elements; ++i) {
    to_return[i] =
        static_cast<value_t>(*(((value_t*) (buffer.data() + from)) + i));
  }

  return to_return;
}
// Same as above, but only input 'from' (and read the remainder of buffer).
template<typename value_t>
inline std::vector<value_t> CharVectorToValueVector(
    const uint64_t& from, const std::vector<unsigned char>& buffer) {
  return CharVectorToValueVector<value_t>(from, buffer.size(), buffer);
}
// Same as above, but use the entire buffer.
template<typename value_t>
inline std::vector<value_t> CharVectorToValueVector(
    const std::vector<unsigned char>& buffer) {
  return CharVectorToValueVector<value_t>(0, buffer.size(), buffer);
}
// Same as above, but alternate API (char* instead of vector).
template<typename value_t>
inline std::vector<value_t> CharVectorToValueVector(
    const uint64_t& from,
    const uint64_t& to,
    const unsigned char* const buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  uint64_t num_elements = (to - from) / value_t_bytes;

  // Make sure buffer is an integer multiple of value_t_bytes.
  if (to <= from || to != from + num_elements * value_t_bytes) {
    LOG_FATAL(
        "Cannot cast a buffer of size " +
        string_utils::Itoa((uint64_t) to - from) +
        " as a vector of the indicated numeric type (wrong number of "
        "bytes).");
  }

  std::vector<value_t> to_return(num_elements, value_t());
  for (uint64_t i = 0; i < num_elements; ++i) {
    to_return[i] = static_cast<value_t>(*(((value_t*) (buffer + from)) + i));
  }

  return to_return;
}
// Same as above, but start from the beginning ('from' = 0).
template<typename value_t>
inline std::vector<value_t> CharVectorToValueVector(
    const uint64_t& num_bytes, const unsigned char* const buffer) {
  return CharVectorToValueVector<value_t>(0, num_bytes, buffer);
}
// =========== END Usage (2) Bytes -> Value (see Discussion at top) ============

// ============= Usage (2) Value -> Bytes (see Discussion at top) ==============
// Cast the numeric value as a vector<unsigned char>.
// NOTE: Appends value to buffer (as opposed to clearing buffer first).
template<typename value_t>
inline bool ValueToCharVector(
    const bool append,
    const value_t& input,
    std::vector<unsigned char>* buffer) {
  const size_t orig_size = buffer->size();
  const size_t value_t_bytes = sizeof(value_t);
  const size_t start_index = append ? orig_size : 0;
  if (append) {
    buffer->resize(orig_size + value_t_bytes);
  } else if (orig_size < value_t_bytes) {
    buffer->resize(value_t_bytes);
  }
  value_t* inserter = (value_t*) (buffer->data() + start_index);
  *inserter = input;

  return true;
}

// Same as above, but defaults to 'append = true'.
template<typename value_t>
inline bool ValueToCharVector(
    const value_t& input, std::vector<unsigned char>* buffer) {
  return ValueToCharVector<value_t>(true, input, buffer);
}

// Same as above with output an unsigned char* instead of a vector.
// Caller should already have allocated sizeof(value_t) bytes to 'buffer'.
template<typename value_t>
inline bool ValueToCharVector(const value_t& input, unsigned char* buffer) {
  value_t* inserter = (value_t*) buffer;
  *inserter = input;
  return true;
}

// Cast the vector of numeric values as a vector<unsigned char>
template<typename value_t>
inline bool ValueVectorToCharVector(
    const std::vector<value_t>& input, std::vector<unsigned char>* buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  const size_t orig_buffer_size = buffer->size();
  const size_t num_new_bytes = input.size() * value_t_bytes;
  buffer->resize(orig_buffer_size + num_new_bytes);
  for (size_t i = 0; i < input.size(); ++i) {
    const value_t& value_i = input[i];
    value_t* inserter =
        (value_t*) (buffer->data() + (orig_buffer_size + i * value_t_bytes));
    *inserter = value_i;
  }

  return true;
}
// =========== END Usage (2) Value -> Bytes (see Discussion at top) ============

// ============= The remaining functions all do Usage (2)  =====================
// ======= They match the functionality above, but for specified value_t =======

// Unsigned Char <-> Bool
// WARNING: If you're using a vector<bool>, you're probably doing something wrong.
// C++ handles these in a funky way. Consider using std::bitset instead, or
// by having the user cast the vector<bool> to a vector<unsigned char> in a
// way that is consistent with their needs.
extern bool CharVectorToBool(const std::vector<unsigned char>& buffer);
extern std::vector<bool> CharVectorToBoolVector(
    const std::vector<unsigned char>& buffer);
extern bool BoolToCharVector(
    const bool input, std::vector<unsigned char>* buffer);
extern bool BoolVectorToCharVector(
    const std::vector<bool>& input, std::vector<unsigned char>* buffer);

// Unsigned Char <-> int32_t
extern int32_t CharVectorToInt32(const std::vector<unsigned char>& buffer);
extern std::vector<int32_t> CharVectorToInt32Vector(
    const std::vector<unsigned char>& buffer);
extern bool Int32ToCharVector(
    const int32_t input, std::vector<unsigned char>* buffer);
extern bool Int32VectorToCharVector(
    const std::vector<int32_t>& input, std::vector<unsigned char>* buffer);

// Unsigned Char <-> uint32_t
extern uint32_t CharVectorToUint32(const std::vector<unsigned char>& buffer);
extern std::vector<uint32_t> CharVectorToUint32Vector(
    const std::vector<unsigned char>& buffer);
extern bool Uint32ToCharVector(
    const uint32_t input, std::vector<unsigned char>* buffer);
extern bool Uint32VectorToCharVector(
    const std::vector<uint32_t>& input, std::vector<unsigned char>* buffer);

// Unsigned Char <-> int64_t
extern int64_t CharVectorToInt64(const std::vector<unsigned char>& buffer);
extern std::vector<int64_t> CharVectorToInt64Vector(
    const std::vector<unsigned char>& buffer);
extern bool Int64ToCharVector(
    const int64_t& input, std::vector<unsigned char>* buffer);
extern bool Int64VectorToCharVector(
    const std::vector<int64_t>& input, std::vector<unsigned char>* buffer);

// Unsigned Char <-> uint64_t
extern uint64_t CharVectorToUint64(const std::vector<unsigned char>& buffer);
extern std::vector<uint64_t> CharVectorToUint64Vector(
    const std::vector<unsigned char>& buffer);
extern bool Uint64ToCharVector(
    const uint64_t& input, std::vector<unsigned char>* buffer);
extern bool Uint64VectorToCharVector(
    const std::vector<uint64_t>& input, std::vector<unsigned char>* buffer);

// Unsigned Char <-> slice
extern math_utils::slice CharVectorToSlice(
    const std::vector<unsigned char>& buffer);
extern std::vector<math_utils::slice> CharVectorToSliceVector(
    const std::vector<unsigned char>& buffer);
extern bool SliceToCharVector(
    const math_utils::slice& input, std::vector<unsigned char>* buffer);
extern bool SliceVectorToCharVector(
    const std::vector<math_utils::slice>& input,
    std::vector<unsigned char>* buffer);
// Unsigned Char <-> SlicePair
extern std::pair<math_utils::slice, math_utils::slice> CharVectorToSlicePair(
    const uint64_t& from,
    const uint64_t& to,
    const std::vector<unsigned char>& buffer);
extern std::pair<math_utils::slice, math_utils::slice> CharVectorToSlicePair(
    const uint64_t& from, const std::vector<unsigned char>& buffer);
extern std::pair<math_utils::slice, math_utils::slice> CharVectorToSlicePair(
    const std::vector<unsigned char>& buffer);
extern std::vector<std::pair<math_utils::slice, math_utils::slice>>
CharVectorToSlicePairVector(
    const uint64_t& from,
    const uint64_t& to,
    const std::vector<unsigned char>& buffer);
extern std::vector<std::pair<math_utils::slice, math_utils::slice>>
CharVectorToSlicePairVector(
    const uint64_t& from, const std::vector<unsigned char>& buffer);
extern std::vector<std::pair<math_utils::slice, math_utils::slice>>
CharVectorToSlicePairVector(const std::vector<unsigned char>& buffer);
extern bool SlicePairToCharVector(
    const std::pair<math_utils::slice, math_utils::slice>& input,
    std::vector<unsigned char>* buffer);
extern bool SlicePairVectorToCharVector(
    const std::vector<std::pair<math_utils::slice, math_utils::slice>>& input,
    std::vector<unsigned char>* buffer);
// Unsigned Char <-> pair<SlicePair, SlicePair>
extern std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>
CharVectorToPairSlicePair(
    const uint64_t& from,
    const uint64_t& to,
    const std::vector<unsigned char>& buffer);
extern std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>
CharVectorToPairSlicePair(
    const uint64_t& from, const std::vector<unsigned char>& buffer);
extern std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>
CharVectorToPairSlicePair(const std::vector<unsigned char>& buffer);
extern std::vector<std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>>
CharVectorToPairSlicePairVector(
    const uint64_t& from,
    const uint64_t& to,
    const std::vector<unsigned char>& buffer);
extern std::vector<std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>>
CharVectorToPairSlicePairVector(
    const uint64_t& from, const std::vector<unsigned char>& buffer);
extern std::vector<std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>>
CharVectorToPairSlicePairVector(const std::vector<unsigned char>& buffer);
extern bool PairSlicePairToCharVector(
    const std::pair<
        std::pair<math_utils::slice, math_utils::slice>,
        std::pair<math_utils::slice, math_utils::slice>>& input,
    std::vector<unsigned char>* buffer);
extern bool PairSlicePairVectorToCharVector(
    const std::vector<std::pair<
        std::pair<math_utils::slice, math_utils::slice>,
        std::pair<math_utils::slice, math_utils::slice>>>& input,
    std::vector<unsigned char>* buffer);

// Unsigned Char <-> double
extern double CharVectorToDouble(const std::vector<unsigned char>& buffer);
extern std::vector<double> CharVectorToDoubleVector(
    const std::vector<unsigned char>& buffer);
extern bool DoubleToCharVector(
    const double& input, std::vector<unsigned char>* buffer);
extern bool DoubleVectorToCharVector(
    const std::vector<double>& input, std::vector<unsigned char>* buffer);

// ===================================== Char ==================================
// NOTE: The remainder of this file is identical to the above, with everything in
// terms of 'char' instead of 'unsigned char' (ugh, why does C++ even allow both?!)
// Note that one change that has to be made is to cast each std::vector<char> buffer
// as a vector of unsigned chars (it is assumed that any code path that
// creates such a buffer did so using unsigned chars, so we must do it this way).

// ============= Usage (2) Bytes -> Value (see Discussion at top) ==============
// Interpret the characters between [from, to) (note the 'from' is inclusive,
// while 'to' is exclusive) as a numeric value of the appropriate type.
template<typename value_t>
inline value_t CharVectorToValue(
    const uint64_t& from, const uint64_t& to, const std::vector<char>& buffer) {
  if (to < from || buffer.size() < to) {
    LOG_FATAL("Bad target range of bytes to copy.");
  }
  return CharVectorToValue<value_t>(
      to - from, (const unsigned char* const) (buffer.data() + from));
}
// Same as above, but only take in a start position (end position will be
// determined by sizeof(value_t)).
template<typename value_t>
inline value_t CharVectorToValue(
    const uint64_t& from, const std::vector<char>& buffer) {
  return CharVectorToValue<value_t>(from, from + sizeof(value_t), buffer);
}
// Same as above, but with from = 0.
template<typename value_t>
inline value_t CharVectorToValue(const std::vector<char>& buffer) {
  return CharVectorToValue<value_t>(0, buffer);
}

// Same as above, but interpret as a vector of values.
template<typename value_t>
inline std::vector<value_t> CharVectorToValueVector(
    const uint64_t& from, const uint64_t& to, const std::vector<char>& buffer) {
  return CharVectorToValueVector<value_t>(
      from, to, (const unsigned char* const) buffer.data());
}
// Same as above, but only input 'from' (and read the remainder of buffer).
template<typename value_t>
inline std::vector<value_t> CharVectorToValueVector(
    const uint64_t& from, const std::vector<char>& buffer) {
  return CharVectorToValueVector<value_t>(from, buffer.size(), buffer);
}
// Same as above, but use the entire buffer.
template<typename value_t>
inline std::vector<value_t> CharVectorToValueVector(
    const std::vector<char>& buffer) {
  return CharVectorToValueVector<value_t>(0, buffer.size(), buffer);
}

// ============= Usage (2) Value -> Bytes (see Discussion at top) ==============
// Cast the numeric value as a byte-string (vector<char>).
// NOTE: The resulting byte-string is always oriented big-endian, so that if
// we interpret each byte in the byte string as 8-bits, then the byte string
// is the binary string representation of the value.
template<typename value_t>
inline bool ValueToCharVector(
    const bool append, const value_t& input, std::vector<char>* buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  const size_t orig_buffer_size = buffer->size();
  size_t offset = 0;
  if (append) {
    buffer->resize(orig_buffer_size + value_t_bytes);
    offset = orig_buffer_size;
  } else if (orig_buffer_size < value_t_bytes) {
    buffer->resize(value_t_bytes);
  }

  return ValueToCharVector<value_t>(
      input, (unsigned char*) (buffer->data() + offset));
}
// Same as above, but defaults to 'append = true'.
template<typename value_t>
inline bool ValueToCharVector(const value_t& input, std::vector<char>* buffer) {
  return ValueToCharVector<value_t>(true, input, buffer);
}

// Cast the vector of numeric values as a vector<char>
template<typename value_t>
inline bool ValueVectorToCharVector(
    const std::vector<value_t>& input, std::vector<char>* buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  const size_t orig_buffer_size = buffer->size();
  const size_t num_new_bytes = input.size() * value_t_bytes;
  buffer->resize(orig_buffer_size + num_new_bytes);
  for (size_t i = 0; i < input.size(); ++i) {
    const value_t& value_i = input[i];
    value_t* inserter =
        (value_t*) (buffer->data() + (orig_buffer_size + i * value_t_bytes));
    *inserter = value_i;
  }

  return true;
}
// =========== Usage (1) ByteString -> Value (see Discussion at top) ===========
// Interpret the characters between [from, to) (note the 'from' is inclusive,
// while 'to' is exclusive) as a numeric value of the appropriate type.
template<typename value_t>
inline value_t ByteStringToValue(
    const uint64_t& from, const uint64_t& to, const std::vector<char>& buffer) {
  if (to < from || buffer.size() < to) {
    LOG_FATAL("Bad target range of bytes to copy.");
  }
  return ByteStringToValue<value_t>(
      to - from, (const unsigned char* const) (buffer.data() + from));
}
// Same as above, but only take in a start position (end position will be
// determined by sizeof(value_t)).
template<typename value_t>
inline value_t ByteStringToValue(
    const uint64_t& from, const std::vector<char>& buffer) {
  return ByteStringToValue<value_t>(from, from + sizeof(value_t), buffer);
}
// Same as above, but with from = 0.
template<typename value_t>
inline value_t ByteStringToValue(const std::vector<char>& buffer) {
  return ByteStringToValue<value_t>(0, buffer);
}

// Same as above, but interpret as a vector of values.
template<typename value_t>
inline std::vector<value_t> ByteStringToValueVector(
    const uint64_t& from, const uint64_t& to, const std::vector<char>& buffer) {
  return ByteStringToValueVector<value_t>(
      from, to, (const unsigned char* const) buffer.data());
}
// Same as above, but only input 'from' (and read the remainder of buffer).
template<typename value_t>
inline std::vector<value_t> ByteStringToValueVector(
    const uint64_t& from, const std::vector<char>& buffer) {
  return ByteStringToValueVector<value_t>(from, buffer.size(), buffer);
}
// Same as above, but use the entire buffer.
template<typename value_t>
inline std::vector<value_t> ByteStringToValueVector(
    const std::vector<char>& buffer) {
  return ByteStringToValueVector<value_t>(0, buffer.size(), buffer);
}

// =========== Usage (1) Value -> ByteString (see Discussion at top) ===========
template<typename value_t>
inline bool ValueToByteString(
    const bool append,
    const size_t num_bytes,
    const value_t& input,
    std::vector<char>* buffer) {
  const size_t orig_size = buffer->size();
  const size_t start_index = append ? orig_size : 0;
  if (append) {
    buffer->resize(orig_size + num_bytes);
  } else if (orig_size < num_bytes) {
    buffer->resize(num_bytes);
  }

  return ValueToByteString<value_t>(
      input, (unsigned char*) (buffer->data() + start_index));
}
// Same as above, default 'num_bytes' to sizeof(value_t).
template<typename value_t>
inline bool ValueToByteString(
    const bool append, const value_t& input, std::vector<char>* buffer) {
  return ValueToByteString<value_t>(append, sizeof(value_t), input, buffer);
}
// Same as above, but defaults to 'append = true'.
template<typename value_t>
inline bool ValueToByteString(const value_t& input, std::vector<char>* buffer) {
  return ValueToByteString<value_t>(true, input, buffer);
}

// Cast the vector of numeric values as a vector<unsigned char>
template<typename value_t>
inline bool ValueVectorToByteString(
    const std::vector<value_t>& input, std::vector<char>* buffer) {
  const size_t value_t_bytes = sizeof(value_t);
  const size_t orig_buffer_size = buffer->size();
  const size_t num_new_bytes = input.size() * value_t_bytes;
  buffer->resize(orig_buffer_size + num_new_bytes);
  for (size_t i = 0; i < input.size(); ++i) {
    const value_t& value = input[i];
    for (size_t j = 0; j < value_t_bytes; ++j) {
      (*buffer)[orig_buffer_size + i * value_t_bytes + j] =
          (char) ((value >> (value_t_bytes - 1 - j) * CHAR_BIT) & ~0);
    }
  }

  return true;
}

// ============= The remaining functions all do Usage (2)  =====================
// ======= They match the functionality above, but for specified value_t =======
// = They also match functionality above, but for 'char' (not 'unsigned char') =
// Char <-> Bool
// WARNING: If you're using a vector<bool>, you're probably doing something wrong.
// C++ handles these in a funky way. Consider using std::bitset instead, or
// by having the user cast the vector<bool> to a vector<char> in a
// way that is consistent with their needs.
extern bool CharVectorToBool(const std::vector<char>& buffer);
extern std::vector<bool> CharVectorToBoolVector(const std::vector<char>& buffer);
extern bool BoolToCharVector(const bool input, std::vector<char>* buffer);
extern bool BoolVectorToCharVector(
    const std::vector<bool>& input, std::vector<char>* buffer);

// Char <-> int32_t
extern int32_t CharVectorToInt32(const std::vector<char>& buffer);
extern std::vector<int32_t> CharVectorToInt32Vector(
    const std::vector<char>& buffer);
extern bool Int32ToCharVector(const int32_t input, std::vector<char>* buffer);
extern bool Int32VectorToCharVector(
    const std::vector<int32_t>& input, std::vector<char>* buffer);

// Char <-> uint32_t
extern uint32_t CharVectorToUint32(const std::vector<char>& buffer);
extern std::vector<uint32_t> CharVectorToUint32Vector(
    const std::vector<char>& buffer);
extern bool Uint32ToCharVector(const uint32_t input, std::vector<char>* buffer);
extern bool Uint32VectorToCharVector(
    const std::vector<uint32_t>& input, std::vector<char>* buffer);

// Char <-> int64_t
extern int64_t CharVectorToInt64(const std::vector<char>& buffer);
extern std::vector<int64_t> CharVectorToInt64Vector(
    const std::vector<char>& buffer);
extern bool Int64ToCharVector(const int64_t& input, std::vector<char>* buffer);
extern bool Int64VectorToCharVector(
    const std::vector<int64_t>& input, std::vector<char>* buffer);

// Char <-> uint64_t
extern uint64_t CharVectorToUint64(const std::vector<char>& buffer);
extern std::vector<uint64_t> CharVectorToUint64Vector(
    const std::vector<char>& buffer);
extern bool Uint64ToCharVector(const uint64_t& input, std::vector<char>* buffer);
extern bool Uint64VectorToCharVector(
    const std::vector<uint64_t>& input, std::vector<char>* buffer);

// Char <-> math_utils::slice
extern math_utils::slice CharVectorToSlice(const std::vector<char>& buffer);
extern std::vector<math_utils::slice> CharVectorToSliceVector(
    const std::vector<char>& buffer);
extern bool SliceToCharVector(
    const math_utils::slice& input, std::vector<char>* buffer);
extern bool SliceVectorToCharVector(
    const std::vector<math_utils::slice>& input, std::vector<char>* buffer);
// Char <-> SlicePair
extern std::pair<math_utils::slice, math_utils::slice> CharVectorToSlicePair(
    const uint64_t& from, const uint64_t& to, const std::vector<char>& buffer);
extern std::pair<math_utils::slice, math_utils::slice> CharVectorToSlicePair(
    const uint64_t& from, const std::vector<char>& buffer);
extern std::pair<math_utils::slice, math_utils::slice> CharVectorToSlicePair(
    const std::vector<char>& buffer);
extern std::vector<std::pair<math_utils::slice, math_utils::slice>>
CharVectorToSlicePairVector(
    const uint64_t& from, const uint64_t& to, const std::vector<char>& buffer);
extern std::vector<std::pair<math_utils::slice, math_utils::slice>>
CharVectorToSlicePairVector(
    const uint64_t& from, const std::vector<char>& buffer);
extern std::vector<std::pair<math_utils::slice, math_utils::slice>>
CharVectorToSlicePairVector(const std::vector<char>& buffer);
extern bool SlicePairToCharVector(
    const std::pair<math_utils::slice, math_utils::slice>& input,
    std::vector<char>* buffer);
extern bool SlicePairVectorToCharVector(
    const std::vector<std::pair<math_utils::slice, math_utils::slice>>& input,
    std::vector<char>* buffer);
// Char <-> pair<SlicePair, SlicePair>
extern std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>
CharVectorToPairSlicePair(
    const uint64_t& from, const uint64_t& to, const std::vector<char>& buffer);
extern std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>
CharVectorToPairSlicePair(const uint64_t& from, const std::vector<char>& buffer);
extern std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>
CharVectorToPairSlicePair(const std::vector<char>& buffer);
extern std::vector<std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>>
CharVectorToPairSlicePairVector(
    const uint64_t& from, const uint64_t& to, const std::vector<char>& buffer);
extern std::vector<std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>>
CharVectorToPairSlicePairVector(
    const uint64_t& from, const std::vector<char>& buffer);
extern std::vector<std::pair<
    std::pair<math_utils::slice, math_utils::slice>,
    std::pair<math_utils::slice, math_utils::slice>>>
CharVectorToPairSlicePairVector(const std::vector<char>& buffer);
extern bool PairSlicePairToCharVector(
    const std::pair<
        std::pair<math_utils::slice, math_utils::slice>,
        std::pair<math_utils::slice, math_utils::slice>>& input,
    std::vector<char>* buffer);
extern bool PairSlicePairVectorToCharVector(
    const std::vector<std::pair<
        std::pair<math_utils::slice, math_utils::slice>,
        std::pair<math_utils::slice, math_utils::slice>>>& input,
    std::vector<char>* buffer);

// Char <-> double
extern double CharVectorToDouble(const std::vector<char>& buffer);
extern std::vector<double> CharVectorToDoubleVector(
    const std::vector<char>& buffer);
extern bool DoubleToCharVector(const double& input, std::vector<char>* buffer);
extern bool DoubleVectorToCharVector(
    const std::vector<double>& input, std::vector<char>* buffer);

#endif
