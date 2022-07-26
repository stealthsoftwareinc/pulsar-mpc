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

// Description: Constants, plus a function for converting values to slices.

#ifndef NUMBER_CONVERSION_UTILS_H
#define NUMBER_CONVERSION_UTILS_H

#include <climits>  // For CHAR_BIT
#include <cstdint>  // For [u]int64_t
#include <string>
#include <vector>

namespace math_utils {

// Returns a string representation of the input value in binary.
// NOTE: This is OS-endianness independent, i.e. this is the true binary
// representation of the value, as opposed to (in the case of Little-Endian)
// the bit/byte sequence that represents this value as stored in memory.
template<typename value_t>
std::string ToBinaryString(const bool use_byte_separator, const value_t& input) {
  const size_t num_bytes = sizeof(value_t);

  std::string to_return = "";
  for (size_t i = 0; i < num_bytes; ++i) {
    const unsigned char byte_i = (unsigned char) (input >> (i * CHAR_BIT));
    // Now print out the bits, as they appear in byte_i.
    for (int j = 0; j < CHAR_BIT; ++j) {
      const std::string curr_bit = ((byte_i & (1 << j)) == 0) ? "0" : "1";
      to_return = curr_bit + to_return;
    }
    // Add a space between bytes.
    if (use_byte_separator && i != num_bytes - 1) to_return = " " + to_return;
  }

  return to_return;
}
// Same as above, but using default byte-separation set to 'true'.
template<typename value_t>
std::string ToBinaryString(const value_t& input) {
  return ToBinaryString<value_t>(true, input);
}

// Similar to above, but for a vector of values. The output is a concatenation
// of the binary string representations of each individual element.
template<typename value_t>
std::string VectorToBinaryString(
    const bool use_byte_separator,
    const bool separate_values,
    const std::vector<value_t>& input) {
  std::string to_return = "";
  for (size_t i = 0; i < input.size(); ++i) {
    const value_t& value = input[i];
    to_return += ToBinaryString<value_t>(use_byte_separator, value);
    if (separate_values && i != input.size() - 1) to_return += " | ";
  }
  return to_return;
}
// Same as above, but using default byte-separation set to 'true'.
template<typename value_t>
std::string VectorToBinaryString(
    const bool separate_values, const std::vector<value_t>& input) {
  return VectorToBinaryString<value_t>(true, separate_values, input);
}
// Same as above, with default byte-separation AND value-separation set to 'true'.
template<typename value_t>
std::string VectorToBinaryString(const std::vector<value_t>& input) {
  return VectorToBinaryString<value_t>(true, true, input);
}

template<typename value_t>
value_t FromBinaryString(const std::string& binary_string) {
  const uint64_t num_bits = binary_string.length();
  if (num_bits == 0 || num_bits > CHAR_BIT * sizeof(value_t)) {
    return 0;
  }

  value_t to_return = 0;
  for (size_t i = 0; i < num_bits; ++i) {
    if (binary_string.substr(num_bits - 1 - i, 1) == "1") {
      to_return = (value_t) (to_return + ((value_t) 1 << i));
    }
  }

  return to_return;
}

// Similar to above, but creates a vector of values.
template<typename value_t>
std::vector<value_t> VectorFromBinaryString(const std::string& binary_string) {
  const uint64_t num_bits = binary_string.length();
  const size_t bits_per_value_t = CHAR_BIT * sizeof(value_t);
  const bool has_overflow = num_bits % bits_per_value_t == 0;
  const uint32_t output_vector_size =
      num_bits / bits_per_value_t + (has_overflow ? 1 : 0);

  std::vector<value_t> to_return;
  for (uint32_t i = 0; i < output_vector_size; ++i) {
    const size_t string_segment_length =
        (i < output_vector_size - 1 || !has_overflow) ?
        bits_per_value_t :
        num_bits % bits_per_value_t;
    const std::string binary_string_segment =
        binary_string.substr(i * bits_per_value_t, string_segment_length);
    to_return.push_back(FromBinaryString<value_t>(binary_string_segment));
  }

  return to_return;
}

// A function used to bit-slice a (vector of) number(s). Suppose input is:
//   [a, b, c]
// where a, b, and c are (positive) integers (of type input_value_t) whose bit
// representations are:
//   a = (a_0, a_1, ..., a_N)
//   b = (b_0, b_1, ..., b_N)
//   c - (c_0, c_1, ..., c_N)
// Then the output would be a vector of size N = CHAR_BIT * sizeof(input_value_t)
// of integers of type output_value_t:
//   [x_0, x_1, x_2, ..., x_N]
// where the bit representations are:
//   x_0 = (a_0, b_0, c_0, 0, ..., 0)
//   x_1 = (a_1, b_1, c_1, 0, ..., 0)
//   ...
//   x_N = (a_N, b_N, c_N, 0, ..., 0)
// This function is useful for circuit evaluation: we wish to perform the same
// funciton on pairs of inputs; e.g. there is some function f that we wish to
// apply to input pairs: f(a, A), f(b, B), f(c, C), etc. (e.g. f() is "LT" function).
// Then we call PackSliceBits twice, once with input [a, b, c], which produces
// output [x_0, x_1, ..., x_N] and once with input [A, B, C] which produces output
// [y_0, y_1, ..., y_N], and then we pass to circuit f the inputs (x, y);
// the circuit of f will be applied (in parallel) to each of the bits of x and y,
// at no extra cost, so long as the gates can handle CHAR_BIT * sizeof(output_value_t)
// bits in parallel (typically, output_value_t is uint32_t or uint64_t).
// NOTE: Regarding Endianness: The representations e.g.:
//   a = (a_0, a_1, ..., a_N)
// and
//   x_0 = (a_0, b_0, c_0, 0, ..., 0)
// are meant to be Endian-independent; i.e. they are the actual binary
// representations of the values 'a' and 'x_0'. The code below will account for
// system-Endianness when it constructs these.
// NOTES:
//   - The number of inputs that can be packed into a single output value is
//       B := CHAR_BIT * sizeof(output_value_t)
//   - Each input value has L := CHAR_BIT * sizeof(input_value_t) bits. Each
//     such value will therefore be expanded into L inputs (one input for
//     each bit of the input).
//   - If input.size() is less than B, we will have a single "block" of values
//     in the output; i.e. output->size() = L. More generally:
//       output->size() = L * (input.size() / B)
template<typename input_value_t, typename output_value_t>
bool PackSliceBits(
    const bool reverse_bits,
    const std::vector<input_value_t>& input,
    std::vector<output_value_t>* output) {
  if (output == nullptr) return false;
  if (input.empty()) return true;

  // Set constants, based on input/output value types and sizes.
  const int bytes_per_input_value = (int) sizeof(input_value_t);
  const int num_packed_per_output_value = CHAR_BIT * sizeof(output_value_t);
  const int block_size = CHAR_BIT * bytes_per_input_value;
  const int num_remainder_inputs = input.size() % num_packed_per_output_value;
  const int num_blocks_needed =
      (int) input.size() / num_packed_per_output_value +
      (num_remainder_inputs == 0 ? 0 : 1);
  const uint64_t num_outputs = block_size * num_blocks_needed;
  // Initialize output as a vector of '0's, of appropriate size.
  output->resize(num_outputs, 0);

  // Partition input into 'blocks', where a block is the maximum number of
  // input values that can be packed together (i.e. evaluated in parallel),
  // which is 'num_packed_per_output_value'.
  for (int i = 0; i < num_blocks_needed; ++i) {
    std::vector<uint32_t> values_batch_i;
    // Process each of the num_packed_per_output_value inputs in this block.
    // If this is the last block, we may not be fully packing things, as
    // the number of values that can be packed may exceed the number of inputs.
    int num_inputs_in_block_i = num_packed_per_output_value;
    if (i == num_blocks_needed - 1 && num_remainder_inputs != 0) {
      num_inputs_in_block_i = num_remainder_inputs;
    }
    for (int j = 0; j < num_inputs_in_block_i; ++j) {
      const input_value_t& input_j = input[i * num_packed_per_output_value + j];
      // Go through each byte of the current input value, picking out its k^th bit,
      // and putting it in the appropriate place.
      for (int k = 0; k < bytes_per_input_value; ++k) {
        const unsigned char* input_j_byte_k = ((unsigned char*) &input_j) + k;
        for (int l = 0; l < CHAR_BIT; ++l) {
          const bool input_j_byte_k_bit_l =
              (*input_j_byte_k >> (CHAR_BIT - 1 - l)) & 1;
          if (input_j_byte_k_bit_l) {
            // The m^th = ((CHAR_BIT * k) + l) bit of input j is a '1'; update
            // the appropriate bit of output.
            const int output_index = reverse_bits ?
                (i * block_size +
                 (CHAR_BIT * bytes_per_input_value - 1 - l -
                  CHAR_BIT * (bytes_per_input_value - 1 - k))) :
                (i * block_size + l +
                 CHAR_BIT * (bytes_per_input_value - 1 - k));
            // We cast '1' do be type output_value_t to make sure we don't
            // overflow when shifting.
            (*output)[output_index] = (*output)[output_index] |
                (output_value_t) (((output_value_t) 1)
                                  << (num_packed_per_output_value - 1 - j));
          }
        }
      }
    }
  }

  return true;
}
// Same as above, but without the reverse_bits option (defaults to false).
template<typename input_value_t, typename output_value_t>
inline bool PackSliceBits(
    const std::vector<input_value_t>& input,
    std::vector<output_value_t>* output) {
  return PackSliceBits<input_value_t, output_value_t>(false, input, output);
}

// This is the inverse of PackSliceBits, so that calling the two in
// succession gets you back where you started. Viewing the binary
// representations as a Matrix, we see that both this function and its
// inverse PackSliceBits() are simply Matrix transpose; in particular,
// they are the same function.
// Expected usage: Apply this function to the outputs of a circuit, to
// see the actual output for each (original/unpacked) input.
// For example, suppose input is:
//   x_0 = (a_0, b_0, ..., n_0)
//   x_1 = (a_1, b_1, ..., n_1)
//   ...
//   x_N = (a_N, b_N, ..., n_N)
// Then outputs vector [a, b, c, ..., n], where:
//   a = (a_0, a_1, ..., a_N)
//   b = (b_0, b_1, ..., b_N)
//   ...
//   n = (n_0, n_1, ..., n_N)
// NOTES:
//   - sizeof(output_value_t) * CHAR_BIT must be >= input.size().
//   - output.size() = num bits in input values = CHAR_BIT * sizeof(input_value_t)
template<typename input_value_t, typename output_value_t>
inline bool UnpackSliceBits(
    const bool reverse_bits,
    const std::vector<input_value_t>& input,
    std::vector<output_value_t>* output) {
  return PackSliceBits<input_value_t, output_value_t>(
      reverse_bits, input, output);
}
// Same as above, but without the reverse_bits option (defaults to false).
template<typename input_value_t, typename output_value_t>
inline bool UnpackSliceBits(
    const std::vector<input_value_t>& input,
    std::vector<output_value_t>* output) {
  return PackSliceBits<input_value_t, output_value_t>(false, input, output);
}

}  // namespace math_utils

#endif
