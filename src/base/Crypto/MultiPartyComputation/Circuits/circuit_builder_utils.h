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
// Description: Defines structures and functions that build a circuit (file).
//
// There are two main approaches for building a circuit:
//   1) Manually construct subcircuits for a single operation applied to
//      two inputs, and then merge/join these subcircuits to form larger
//      subcircuits, etc.
//   2) Have a single (string) representation of the final function (circuit)
//      to be constructed, and construct this circuit all at once
// circuit_builder_main.cpp provides API's and examples for both use-cases above.
// In terms of use-case (2), the main data structure is the 'Formula' struct,
// which is the intermediate object that is used to transition from
// a string expression of a formula to a (Standard)Circuit.
//
// NOTE: Circuit (files) will handle signed vs. unsigned DataTypes as follows:
//   - Each DataType will have a fixed number of bits used to express it.
//     These bits will be loaded onto separate input (wires)
//   - The bits represent a value (of the appropriate DataType) either in
//     binary format, or in two's complement. In particular, all signed (INTXX)
//     DataTypes will be represented in 2's complement; all other DataTypes
//     (including STRINGXX) will be represented in binary
//   - Thus, for any ComparisonOperation, a circuit will need to either treat
//     the leading bit specially (in the 2's complement case) or not (in the
//     binary case). For example, a circuit representing a single
//     ComparisonOperation (e.g. COMP_GT) will look different if the specified
//     inputs are UINTXX vs. INTXX.
// A consequence of this approach is that subtraction for Unsigned DataTypes
// (UINTXX) will not behave as expected whenever the Difference would be a
// negative number (this is an expected/tolerable drawback, since user's
// should specify the input types as a signed type (i.e. INTXX) if a
// computation to be performed might ever result in a negative value).

// The reason we use 2's complement (for signed DataTypes) is to simplify
// Addition/Subtraction (when implemented in Boolean circuits), and to remove
// the necessity of having special circuit logic to handle the ambiguity of
// expressing '0' that exists if we were to use the strategy that leading bit
// denotes sign (i.e. 10000000 = 00000000).

// TODO(paul): I have not updated this file yet to reflect the changes to
// StandardCircuit; in particular, the fact that it is now templated.
// Instead, I just forced all code here to assume template type bool
// (Format 2). The proper thing to do is likely make all of the functions
// here templated, and then the code should probably work fine as-is.
#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"  // For OutputRecipient.
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"  // For StandardCircuit.
#include "LoggingUtils/logging_utils.h"
#include "MathUtils/constants.h"  // For slice.
#include "StringUtils/string_utils.h"

#include <climits>  // For ULLONG_MAX, etc.
#include <map>
#include <memory>  // For unique_ptr.
#include <set>
#include <string>
#include <tuple>  // For pair.
#include <typeinfo>  // For typeid, bad_cast
#include <vector>

#ifndef CIRCUIT_BUILDER_UTILS_H
#define CIRCUIT_BUILDER_UTILS_H

namespace crypto {
namespace multiparty_computation {

// Used for setting input/output DataTypes when they are unknown.
extern const math_utils::DataType kDefaultDataType;
extern const uint64_t kFirstTwentyFactorials[];

/* =============================== Functions ================================ */
// Turns on/off the flag that controls whether ReduceCircuit() does anything.
void SetAllowReduceCircuit(const bool should_allow);

// For Argmin/Argmax circuits, we return a characteristic vector with a '1'
// in the min/max position. In case of ties, we deterministically take
// the first (resp. last) coordinate that represents the min/max.
// The following sets if we should take the first or last (default is first).
extern void SetArgminBreakTiesPos(const bool use_first);

// Toggles kAdditionLookaheadBlocks, which is used to perform ``lookahead''
// addition (an optimization for minimizing circuit depth at the cost of extra
// circuit complexity (num gates); see discussion above this variable in
// circuit_builder_utils.cpp).
extern void SetAdditionNumberLookaheadBlocks(const int num_blocks);

// Simplifies the circuit by recrusively:
//   - Flatten: Make sure all gates are on their minimial level:
//       1 + min(left_wire level, right_wire_level)
//   - De-dup: If a gate has same type and input wires as another gate (perhaps with
//     flip-flopped which is left/right input wire), then condense these into
//     a single gate
//   - Constants: Remove gates where both input wires are constant values.
//   - IDENTITY and NOT: Remove IDENTITY and NOT gates (unless output wire is global output)
// Returns the number of reductions that were made (or -1 for failure).
extern int ReduceCircuit(const bool print_status, StandardCircuit<bool>* output);
inline int ReduceCircuit(StandardCircuit<bool>* output) {
  return ReduceCircuit(true, output);
}

// For each output wire of the input circuit, duplicates that output wire.
// Output wire that is originally output wire 'i' will turn into output
// wires 'i' and 'N + i', where N = Number of (original) output wires.
// More generally, we allow a duplication factor: each output wire will
// be duplicated this many times; so an original output wire of index 'i'
// will become output wires 'i', 'N + i', '2N + i', ..., 'd*N + i',
// where N = Number of (original) output wires and 'd' = duplication factor.
template<typename value_t>
extern bool DuplicateOutputs(
    const StandardCircuit<value_t>& input,
    const uint64_t& duplication_factor,
    StandardCircuit<value_t>* output);
// Same as above, for duplication factor = 2.
template<typename value_t>
inline bool DuplicateOutputs(
    const StandardCircuit<value_t>& input, StandardCircuit<value_t>* output) {
  return DuplicateOutputs<value_t>(input, 2, output);
}

// Constructs a circuit with one IDENTITY gate, that takes in input from
// the appropriate 'constant' input field (constant_slice_input_ or
// (Format 1) or constant_[zero | one]_input_ (Format 2)).
extern bool ConstructConstantCircuit(
    const math_utils::slice& value,
    const uint64_t& num_outputs,
    StandardCircuit<math_utils::slice>* output);
// Same as above, but for num_outputs input/output wires.
// NOTE: Format 2 circuits only.
extern bool ConstructConstantCircuit(
    const bool value,
    const uint64_t& num_outputs,
    StandardCircuit<bool>* output);
// Same as above, for a single input/output.
inline bool ConstructConstantCircuit(
    const math_utils::slice& value, StandardCircuit<math_utils::slice>* output) {
  return ConstructConstantCircuit(value, (uint64_t) 1, output);
}
inline bool ConstructConstantCircuit(
    const bool value, StandardCircuit<bool>* output) {
  return ConstructConstantCircuit(value, (uint64_t) 1, output);
}
// Similar to above, but allowing an arbitrary constant for Format 2:
// Specify how many bits you want to express the value as, and it will
// create this many output wires, with the appropriate bit of the input value.
extern bool ConstructConstantCircuit(
    const uint64_t& value, const int num_bits, StandardCircuit<bool>* output);
// Same as above, for negative values. Note that the only reason to this API as
// opposed to the above is if the constant value is negative. Therefore, the
// leading bit (defined as bit (num_bits - 1) as opposed to (64-1)) will
// be the sign (2's complement) bit and will be set to '1', independent of what
// 'value' is, and then the rest of the bits will be set according to the bits
// of |value|.
extern bool ConstructConstantCircuit(
    const int64_t& value, const int num_bits, StandardCircuit<bool>* output);

// Constructs a trivial (1-party) depth-1 circuit with a single (bit) input and
// a single (global) output wire, with a single IDENTITY gate.
extern bool ConstructSingleBitIdentityCircuit(
    const bool is_format_one, StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
extern bool ConstructSingleBitIdentityCircuit(
    const bool is_format_one,
    const int party_index,
    const uint64_t& input_index,
    StandardCircuit<bool>* output);

// Same as above, for multiple inputs (or multiple input bits). Then the created
// depth-1 circuit will be the identity circuit for each input (bit); so there
// will be num_inputs outputs, and the i^th output will be the i^th input (bit).
// NOTE: The output wires will be viewed as independent from each other, so
// that output->num_outputs_ will equal 'num_inputs', as opposed to e.g. equaling
// '1', where the wires are to be viewed as the bit-components of a larger
// DataType. We make this choice because there is no compelling use-case where
// you would need the identity circuit if the output wires are identical to
// the input wires. Note that this distinction is only important in terms of
// the metadata fields, i.e. it doesn't change the gates/wiring of the circuit,
// just the fields num_outputs_, output_designations_, and function_description_.
extern bool ConstructIdentityCircuit(
    const bool is_format_one,
    const bool is_signed_type,
    const uint64_t& num_inputs,
    StandardCircuit<bool>* output);
// Same as above, where num_inputs is determined by DatatType.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructIdentityCircuit(
    const math_utils::DataType type, StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
extern bool ConstructIdentityCircuit(
    const bool is_format_one,
    const bool is_signed_type,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& num_inputs,
    StandardCircuit<bool>* output);
// Same as above, where num_inputs is determined by DatatType.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructIdentityCircuit(
    const int party_index,
    const uint64_t& input_index,
    const math_utils::DataType type,
    StandardCircuit<bool>* output);

// Constructs a trivial (1-party) depth-1 circuit with a single (bit) input and
// a single (global) output wire, with a single NOT gate.
extern bool ConstructSingleBitNotCircuit(
    const bool is_format_one, StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
extern bool ConstructSingleBitNotCircuit(
    const bool is_format_one,
    const int party_index,
    const uint64_t& input_index,
    StandardCircuit<bool>* output);
// Same as above, with specification of bit index.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructSingleBitNotCircuit(
    const bool is_signed_type,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output);

// Same as above, for multiple inputs (or multiple input bits). Then the created
// depth-1 circuit will be the NOT circuit for each input (bit); so there will be
// num_inputs outputs, and the i^th output will be the negated i^th input (bit).
extern bool ConstructNotCircuit(
    const bool is_format_one,
    const bool is_signed_type,
    const uint64_t& num_inputs,
    StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
extern bool ConstructNotCircuit(
    const bool is_format_one,
    const bool is_signed_type,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& num_inputs,
    StandardCircuit<bool>* output);
// Same as above, where num_inputs is determined by DatatType.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructNotCircuit(
    const math_utils::DataType type, StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
extern bool ConstructNotCircuit(
    const int party_index,
    const uint64_t& input_index,
    const math_utils::DataType type,
    StandardCircuit<bool>* output);
// Same as above, for API where input is a Circuit. In particular,
// adds one level to the input circuit, and the number output gates equals
// number of original output gates, where every output wire has been negated.
extern bool ConstructNotCircuit(
    const StandardCircuit<bool>& input, StandardCircuit<bool>* output);

// Constructs a (1-party) depth-1 circuit that selects (outputs) the
// 'bit_index' bit of the 'input_index' input.
// NOTE 1: The circuit won't actually do anything with the other (bits of)
// input indices; so it doesn't really matter what input_index is, but we
// allow it as in input parameter so that this function can be chained with
// other ones, being called as a sub-routine to pick out a bit of one of the
// (global) inputs.
// NOTE 2: Only valid for Format 2 circuits.
extern bool ConstructSelectBitCircuit(
    const bool is_signed_type,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output);
// Same as above, but doesn't specify Party or input_index (default to Party 1's input '0').
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructSelectBitCircuit(
    const bool is_signed_type,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output);
// Similar to above, but allows specification of multiple bits to select (output).
// The ordering of the output wires is preserved, i.e. respects the ordering
// w.r.t. 'bit_indices'.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructSelectBitsCircuit(
    const bool is_signed_type,
    const int party_index,
    const std::vector<std::pair<uint64_t, uint64_t>>& bit_indices,
    StandardCircuit<bool>* output);
// Same as above, but doesn't specify Party or input_index (default to Party 1's input '0').
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructSelectBitsCircuit(
    const bool is_signed_type,
    const std::vector<uint64_t>& bit_indices,
    StandardCircuit<bool>* output);

// Constructs a circuit that takes as input:
//   - A bit b
//   - A boolean vector v of size n (this is viewed as n separate boolean inputs)
// and outputs a boolean vector of size n where each coordinate of v has
// been multiplied by b.
// NOTE: Format 2 circuits only.
extern bool ConstructScalarMultiplicationCircuit(
    const uint64_t& vector_size, StandardCircuit<bool>* output);
// Same as above, but vector b and coordinates of v can have arbitrary DataType.
extern bool ConstructScalarMultiplicationCircuit(
    const math_utils::DataType type,
    const uint64_t& vector_size,
    StandardCircuit<bool>* output);

// Constructs a circuit that takes two boolean vectors as input, and
// outputs the concatenation of these.
extern bool ConstructVectorConcatenationCircuit(
    const uint64_t& left_vector_size,
    const uint64_t& right_vector_size,
    StandardCircuit<bool>* output);
// Same as above, for vectors of arbitrary DataType.
extern bool ConstructVectorConcatenationCircuit(
    const math_utils::DataType type,
    const uint64_t& left_vector_size,
    const uint64_t& right_vector_size,
    StandardCircuit<bool>* output);

// Constructs a trivial (2-party) circuit with a single (bit) input (from each party)
// and a single (global) output wire, with a single gate of the indicated type.
extern bool ConstructBitComparisonCircuit(
    const bool is_format_one,
    const math_utils::BooleanOperation& op,
    StandardCircuit<bool>* output);
// Same as above, but the bit to be compared is the 'bit_index' bit of
// the 'input_index' input of each party.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructBitComparisonCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const uint64_t& one_input_index,
    const uint64_t& one_bit_index,
    const uint64_t& two_input_index,
    const uint64_t& two_bit_index,
    const math_utils::BooleanOperation& op,
    StandardCircuit<bool>* output);
// Same as above, defaults to setting each party's input_index to '0'.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructBitComparisonCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const uint64_t& one_bit_index,
    const uint64_t& two_bit_index,
    const math_utils::BooleanOperation& op,
    StandardCircuit<bool>* output);
// Same as above, but compares arbitrary bit of arbitrary input index of
// arbitrary Party.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructBitComparisonCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int bit_one_party_index,
    const int bit_two_party_index,
    const uint64_t& one_input_index,
    const uint64_t& one_bit_index,
    const uint64_t& two_input_index,
    const uint64_t& two_bit_index,
    const math_utils::BooleanOperation& op,
    StandardCircuit<bool>* output);

// Similar to the ConstructBitComparisonCircuit() functions above, but for
// arbitrary DataType (so will compare multiple bits; comparison is bit-wise).
// NOTE2: This will treat 'num_[one | two]_input_bits' as coming from
// separate inputs (i.e. treat all inputs from each party as boolean); if
// instead you want to treat the input bits as comprising a single input
// (i.e. an input whose DataType has 'num_input_bits'), use one of the
// API's below.
extern bool ConstructBooleanCircuit(
    const math_utils::BooleanOperation& op,
    const bool is_signed_type,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructBooleanCircuit(
    const math_utils::BooleanOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output);
// Same as above, where num_input_bits is determined by DatatType.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructBooleanCircuit(
    const math_utils::BooleanOperation& op,
    const math_utils::DataType input_type,
    StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructBooleanCircuit(
    const math_utils::BooleanOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const math_utils::DataType input_type,
    StandardCircuit<bool>* output);

// Same as above, for ComparisonOperator (instead of BooleanOperation).
// Constructs a (2-party) circuit that takes in a single input (of multiple bits)
// from each party and has a single (global) output value (which is obtained
// by merging the bits (values) on max(num_one_input_bits, num_two_input_bits)
// output wires, and constructs the circuit that will compare the appropriate
// input bits of each input to perform the indicated comparison.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructComparisonCircuit(
    const math_utils::ComparisonOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output);
// Same as above, without specification of 'is_twos_complement'; will set this
// to be true by default.
extern bool ConstructComparisonCircuit(
    const math_utils::ComparisonOperation& op,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructComparisonCircuit(
    const math_utils::ComparisonOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output);
// Same as above, without specification of 'is_twos_complement'; will set this
// to be true by default.
extern bool ConstructComparisonCircuit(
    const math_utils::ComparisonOperation& op,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output);
// Same as above, where num_input_bits is determined by DatatType.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructComparisonCircuit(
    const math_utils::ComparisonOperation& op,
    const math_utils::DataType input_one_type,
    const math_utils::DataType input_two_type,
    StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructComparisonCircuit(
    const math_utils::ComparisonOperation& op,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const math_utils::DataType input_one_type,
    const math_utils::DataType input_two_type,
    StandardCircuit<bool>* output);

// Similar to ConstructComparisonCircuit() functions above, but for ArithmeticOperations.
// Constructs a (2-party) circuit that takes in a single input (of multiple bits)
// from each party and has a single (global) output value (which is obtained
// by merging the bits (values) on max(num_one_input_bits, num_two_input_bits)
// output wires, and constructs the circuit that will compare the appropriate
// input bits of each input to perform the indicated comparison.
// NOTE 1: The 'as_boolean' field will determine if a boolean-style circuit is
// used to implement the indicated 'op', or if an Arithmetic circuit is used.
// NOTE 2: Only valid for Format 2 circuits.
extern bool ConstructArithmeticCircuit(
    const bool as_boolean,
    const math_utils::ArithmeticOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructArithmeticCircuit(
    const bool as_boolean,
    const math_utils::ArithmeticOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output);
// Same as above, where num_input_bits is determined by DatatType.
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructArithmeticCircuit(
    const bool as_boolean,
    const math_utils::ArithmeticOperation& op,
    const math_utils::DataType input_one_type,
    const math_utils::DataType input_two_type,
    StandardCircuit<bool>* output);
// Same as above, but allows specification of where the value comes from
// (i.e. which Party, and the input index of that party).
// NOTE: Only valid for Format 2 circuits.
extern bool ConstructArithmeticCircuit(
    const bool as_boolean,
    const math_utils::ArithmeticOperation& op,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const math_utils::DataType input_one_type,
    const math_utils::DataType input_two_type,
    StandardCircuit<bool>* output);

// Creates a single circuit, that "stacks" the two circuits. I.e. sets the
// output wires of the first circuit as the input wires of the second circuit,
// via the provided mapping, which maps:
//   output (wire) index -> (party_index, input index, input bit)
// where the output index is with respect to wires (bits), e.g. w.r.t
// outputs_as_bits_ (as opposed to outputs_as_generic_value_).
// NOTE 1: We allow partial connections:
//   - Not all output wires of circuit 'one' have to hook up to input wires
//     of circuit 'two'
//   - Not all input wires of circuit 'two' need to be connected to an output
//     wire of circuit 'one'
// For unmapped output wires of circuit 'one', they will continue to be output
// wires (with the same index) in the joined circuit. Then the indexing of
// the joined circuit's output wires that come from circuit 'two' will be
// offset by the number of unmapped output wires from circuit one.
// For unmapped input wires of circuit 'two', the original indexing of these
// wires is maintained, e.g. we do *NOT* use an offset (e.g. of the number of
// inputs to circuit 'one') to adjust the input indices of these inputs.
// NOTE 2: preserve_input_indexing controls what happens to the input wires
// of the bottom circuit 'two' that are not mapped to by the output wires of
// circuit 'one' (if there are any):
//   - If true, the indexing/labelling of these wires remains what it was
//   - If false, it will assume that these inputs should not overlap with
//     circuit 'one' inputs, and hence the input index of each such input
//     will be incremented by the number of inputs in circuit 'one'.
// NOTE 3: Only valid for Format 2 circuits.
extern bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const std::
        map<int64_t, std::set<std::pair<int, std::pair<uint64_t, uint64_t>>>>&
            output_to_input,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, with 'update_function_description' set to true.
inline bool JoinCircuits(
    const bool preserve_input_indexing,
    const std::
        map<int64_t, std::set<std::pair<int, std::pair<uint64_t, uint64_t>>>>&
            output_to_input,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return JoinCircuits(
      preserve_input_indexing, true, output_to_input, one, two, output);
}
// Same as above, with 'preserve_input_indexing' set to true.
inline bool JoinCircuits(
    const std::
        map<int64_t, std::set<std::pair<int, std::pair<uint64_t, uint64_t>>>>&
            output_to_input,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return JoinCircuits(true, output_to_input, one, two, output);
}
// Same as above, for Format 1 circuits. Here, the providing mapping is:
//   output index -> (party_index, input index)
// NOTE: Only valid for Format 1 circuits.
extern bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const std::map<int64_t, std::set<std::pair<int, uint64_t>>>& output_to_input,
    const StandardCircuit<math_utils::slice>& one,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output);
// Same as above, with 'update_function_description' set to true.
inline bool JoinCircuits(
    const bool preserve_input_indexing,
    const std::map<int64_t, std::set<std::pair<int, uint64_t>>>& output_to_input,
    const StandardCircuit<math_utils::slice>& one,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output) {
  return JoinCircuits(
      preserve_input_indexing, true, output_to_input, one, two, output);
}
// Same as above, with 'preserve_input_indexing' set to true.
inline bool JoinCircuits(
    const std::map<int64_t, std::set<std::pair<int, uint64_t>>>& output_to_input,
    const StandardCircuit<math_utils::slice>& one,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output) {
  return JoinCircuits(true, output_to_input, one, two, output);
}
// Same as the above two functions, but without an output->input mapping.
// Instead, the outputs (ordered according to their output_index) are mapped
// to the inputs as the inputs are iterated through: first outputs get mapped
// to inputs_as_[slice | generic_value]_locations_[0], and next outputs get
// mapped to inputs_as_[slice | generic_value]_locations_[1], and so on.
// NOTE: This means partial connections are not tolerated for this API. I.e.,
// the number of output wires in 'one' must match the number of inputs of 'two':
//   one.num_outputs_ == \sum_i(two.inputs_as_[slice | generic_value]_locations_[i].size())
extern bool JoinCircuits(
    const StandardCircuit<math_utils::slice>& one,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output);
// Same as above, for Format 2.
extern bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, with 'update_function_description' set to true.
inline bool JoinCircuits(
    const bool preserve_input_indexing,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return JoinCircuits(preserve_input_indexing, true, one, two, output);
}
// Same as above, with 'preserve_input_indexing' set to true.
inline bool JoinCircuits(
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return JoinCircuits(true, true, one, two, output);
}

// Similar to above, where the 'lower' circuit takes inputs from two parties;
// and 'left' circuit denotes Party 1 (i.e. its outputs will be viewed
// as Party 1's inputs), and 'right' circuit denotes Party 2.
// NOTE 1: See NOTE 1 in the 2-circuit API of JoinCircuits above, regarding
// unmapped input/output wires. In the present context, we also allow unmapped
// input/output wires for *both* circuit 'left' and circuit 'right'.
// As above, indexing of unmapped input wires of circuit 'two' will remain the same.
// The indexing of the output wires of the joined circuit will be:
//   - Output wires from the (unmapped output wires) of the 'left' circuit
//     will maintain their original indexing;
//   - Output wires from the (unmapped output wires) of the 'right' circuit
//     will be offset by the number of (unmapped) output wires in the 'left' circuit
//   - Output wires from circuit 'two' circuit will be offset by the number
//     of (unmapped) output wires in the 'left' circuit plus the number of
//     (unmapped) output wires in the 'right' circuit.
// NOTE 2: Only valid for Format 2 circuits.
extern bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const std::map<int64_t, std::set<std::pair<uint64_t, uint64_t>>>&
        left_output_to_input,
    const std::map<int64_t, std::set<std::pair<uint64_t, uint64_t>>>&
        right_output_to_input,
    const StandardCircuit<bool>& left,
    const StandardCircuit<bool>& right,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, with 'update_function_description' set to true.
inline bool JoinCircuits(
    const bool preserve_input_indexing,
    const std::map<int64_t, std::set<std::pair<uint64_t, uint64_t>>>&
        left_output_to_input,
    const std::map<int64_t, std::set<std::pair<uint64_t, uint64_t>>>&
        right_output_to_input,
    const StandardCircuit<bool>& left,
    const StandardCircuit<bool>& right,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return JoinCircuits(
      preserve_input_indexing,
      true,
      left_output_to_input,
      right_output_to_input,
      left,
      right,
      two,
      output);
}
// Same as above, with 'preserve_input_indexing' set to true.
inline bool JoinCircuits(
    const std::map<int64_t, std::set<std::pair<uint64_t, uint64_t>>>&
        left_output_to_input,
    const std::map<int64_t, std::set<std::pair<uint64_t, uint64_t>>>&
        right_output_to_input,
    const StandardCircuit<bool>& left,
    const StandardCircuit<bool>& right,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return JoinCircuits(
      true,
      left_output_to_input,
      right_output_to_input,
      left,
      right,
      two,
      output);
}
// Same as above, for Format 1 circuits.
// NOTE: Only valid for Format 1 circuits.
extern bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const std::map<int64_t, std::set<uint64_t>>& left_output_to_input,
    const std::map<int64_t, std::set<uint64_t>>& right_output_to_input,
    const StandardCircuit<math_utils::slice>& left,
    const StandardCircuit<math_utils::slice>& right,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output);
// Same as above, with 'update_function_description' set to true.
inline bool JoinCircuits(
    const bool preserve_input_indexing,
    const std::map<int64_t, std::set<uint64_t>>& left_output_to_input,
    const std::map<int64_t, std::set<uint64_t>>& right_output_to_input,
    const StandardCircuit<math_utils::slice>& left,
    const StandardCircuit<math_utils::slice>& right,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output) {
  return JoinCircuits(
      preserve_input_indexing,
      true,
      left_output_to_input,
      right_output_to_input,
      left,
      right,
      two,
      output);
}
// Same as above, with 'preserve_input_indexing' set to true.
inline bool JoinCircuits(
    const std::map<int64_t, std::set<uint64_t>>& left_output_to_input,
    const std::map<int64_t, std::set<uint64_t>>& right_output_to_input,
    const StandardCircuit<math_utils::slice>& left,
    const StandardCircuit<math_utils::slice>& right,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output) {
  return JoinCircuits(
      true,
      left_output_to_input,
      right_output_to_input,
      left,
      right,
      two,
      output);
}
// Same as the above two functions, but without an output->input mapping.
// Instead, the outputs from circuit 'one' (ordered according to their output_index)
// are mapped to input_one_as_[slice | generic_value]_locations_, and the outputs
// from circuit 'two' are mapped to input_two_as_[slice | generic_value]_locations_.
// NOTE: This means partial connections are not tolerated for this API. I.e.,
// the number of output wires in 'left' and 'right' must match the number of
// inputs of 'two':
//   one.num_outputs_ == input_one_as_[slice | generic_value]_locations_.size();
//   two.num_outputs_ == input_two_as_[slice | generic_value]_locations_.size();
extern bool JoinCircuits(
    const StandardCircuit<math_utils::slice>& left,
    const StandardCircuit<math_utils::slice>& right,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output);
// Same as above, for Format 2.
extern bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const StandardCircuit<bool>& left,
    const StandardCircuit<bool>& right,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, with 'update_function_description' set to true.
inline bool JoinCircuits(
    const bool preserve_input_indexing,
    const StandardCircuit<bool>& left,
    const StandardCircuit<bool>& right,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return JoinCircuits(preserve_input_indexing, true, left, right, two, output);
}
// Same as above, with 'preserve_input_indexing' set to true.
inline bool JoinCircuits(
    const StandardCircuit<bool>& left,
    const StandardCircuit<bool>& right,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return JoinCircuits(true, left, right, two, output);
}

// Constructs a circuit that combines two input circuits, with the same number
// of ouputs, and merges their outputs via 'op'.
// NOTE 1: This function can also be used to merge two circuits by NOT combining
// their outputs via 'op', but rather, by keeping all original outputs (and
// just keeping track of indexing of the outputs, so that the outputs from
// circuit two are re-indexed by offset = one.num_outputs_). In other words,
// in this special use-case, this function takes two circuits and places them
// "side-by-side".
// The special use-case is triggered by op == IDENTITY, and in this case, we
// don't have the requirement that the number of outputs of the two circuits match.
// NOTE 2: There are two options for the labelling of input wires on circuit two:
//   1) Preserve the original labelling (which merges inputs that have same (Party, Index))
//   2) Update all (global/circuit) input indices by incrementing by the number
//      of (global/circuit) inputs (from the appropriate party) in circuit one.
// For example, suppose circuits have inputs:
//   Circuit 'one':       Circuit 'two':
//   P0: (UINT2) x        P0: (INT2) x
//   P1: [None]               (BOOL) x2
//   P2: (BOOL) z         P1: (BOOL) y
// Then if 'preserve_input_indexing' is true, the final circuit inputs are:
//   P0: (INT2) x
//       (BOOL) x2
//   P1: (BOOL) y
//   P2: (BOOL) z
// Notice that the only 'overlapping' input, i.e. the only (Party, Index) that
// is a common to both circuits is (P0, 0), and this input has been 'merged'
// in the final circuit's inputs. In order to successfully merge these inputs,
// we demand that the variable names of any overlapping inputs must match
// (in the above example, since the only overlapping input is the 0th input
// from P0, it must be that both inputs have the same name, in this case 'x'),
// and the DataType selected for this input will be the larger of the two,
// or if they are the same size and yet different DataTypes (i.e. one is signed
// and the other unsigned), then default to the signed DataType (which is
// why the 0th input of P0 has final DataType INT2).
// Meanwhile, if 'preserve_input_indexing' is false, the final circuit inputs are:
//   P0: (UINT2) x
//       (INT2) x
//       (BOOL) x2
//   P1: (BOOL) y
//   P2: (BOOL) z
template<typename value_t>
extern bool MergeCircuitsInternal(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const math_utils::BooleanOperation& op,
    const StandardCircuit<value_t>& one,
    const StandardCircuit<value_t>& two,
    StandardCircuit<value_t>* output);
// Same as above, with 'update_function_description' set to true as default.
template<typename value_t>
inline bool MergeCircuitsInternal(
    const bool preserve_input_indexing,
    const math_utils::BooleanOperation& op,
    const StandardCircuit<value_t>& one,
    const StandardCircuit<value_t>& two,
    StandardCircuit<value_t>* output) {
  return MergeCircuitsInternal<value_t>(
      preserve_input_indexing, true, op, one, two, output);
}
inline bool MergeCircuits(
    const bool preserve_input_indexing,
    const math_utils::BooleanOperation& op,
    const StandardCircuit<math_utils::slice>& one,
    const StandardCircuit<math_utils::slice>& two,
    StandardCircuit<math_utils::slice>* output) {
  return MergeCircuitsInternal<math_utils::slice>(
      preserve_input_indexing, op, one, two, output);
}
// Same as above, for Format 2 circuits.
inline bool MergeCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const math_utils::BooleanOperation& op,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return MergeCircuitsInternal<bool>(
      preserve_input_indexing,
      update_function_description,
      op,
      one,
      two,
      output);
}
// Same as above, with 'update_function_description' set to true as default.
inline bool MergeCircuits(
    const bool preserve_input_indexing,
    const math_utils::BooleanOperation& op,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return MergeCircuitsInternal<bool>(
      preserve_input_indexing, true, op, one, two, output);
}
// Same as above, for a ComparisonOperation. In particular, if either input
// circuit has multiple outputs, these outputs are treated as (ordered) bits of
// a single value, and these values are then compared via 'op'; thus, this
// function produces a circuit with a single output wire, regardless of the
// number of output wires of the input circuits.
// NOTE: Only valid for Format 2 circuits.
extern bool MergeCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const math_utils::ComparisonOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, with 'update_function_description' set to true as default.
inline bool MergeCircuits(
    const bool preserve_input_indexing,
    const math_utils::ComparisonOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return MergeCircuits(
      preserve_input_indexing,
      true,
      op,
      one_is_twos_complement,
      two_is_twos_complement,
      one,
      two,
      output);
}
// Same as above, for an arithmetic operation.
// NOTE: Only valid for Format 2 circuits.
extern bool MergeCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const math_utils::ArithmeticOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, with 'update_function_description' set to true as default.
inline bool MergeCircuits(
    const bool preserve_input_indexing,
    const math_utils::ArithmeticOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return MergeCircuits(
      preserve_input_indexing,
      true,
      op,
      one_is_twos_complement,
      two_is_twos_complement,
      one,
      two,
      output);
}
// A generic wrapper for the three functions above; will just call the
// appropriate one (based on op_holder.type_).
// NOTE: Only valid for Format 2 circuits.
extern bool MergeCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const math_utils::OperationHolder& op_holder,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, with 'update_function_description' set to true as default.
inline bool MergeCircuits(
    const bool preserve_input_indexing,
    const math_utils::OperationHolder& op_holder,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  return MergeCircuits(
      preserve_input_indexing,
      true,
      op_holder,
      one_is_twos_complement,
      two_is_twos_complement,
      one,
      two,
      output);
}

// Same as above, but allows specification of which output wires from each
// circuit that should have 'op' applied to. In particular, the vectors should
// have equal lengths equal to the number of bits in the indicated DataType,
// and the vectors should be viewed a the binary/2's complement representation;
// for example, UINTX DataTypes will be binary, while STRING and INTX DataTypes
// will be 2's complement (so one_ouput_indices[0] is the most significant bit
// (resp. the -2^n bit), and one_ouput_indices.back() is the least significant bit.
// NOT SUPPORTED. I never needed to use this API, so I didn't implement it.
// I'll leave the template in place, in case a future use-case wants it
// (at which point I'd need to actually implement it).
/*
extern bool MergeCircuits(
    const bool preserve_input_indexing,
    const math_utils::OperationHolder& op_holder,
    const DataType& type,
    const std::vector<int64_t>& one_ouput_indices,
    const std::vector<int64_t>& two_ouput_indices,
    const StandardCircuit<bool>& one, const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, for merging muliptle outputs via multiple operations:
// The size of 'ops' and 'types' should match the size of the outer vectors of
// one_ouput_indices and two_ouput_indices, and each inner-vector of
// one_ouput_indices and two_ouput_indices should have length equal to the
// number of bits of the corresponding DataType in types.
extern bool MergeCircuits(
    const bool preserve_input_indexing,
    const std::vector<math_utils::OperationHolder>& ops,
    const std::vector<math_utils::DataType>& types,
    const std::vector<std::vector<int64_t>>& one_ouput_indices,
    const std::vector<std::vector<int64_t>>& two_ouput_indices,
    const StandardCircuit<bool>& one, const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// NOT SUPPORTED. While the below functions may be useful, they will require non-
// trivial work to implement, and anyway they are not necessary, since equivalent
// functionality can be achieved by chaining together appropriate calls of the
// MergeCircuits() APIs above.
// More flexibility than above: Input to describe which output wires
// to apply a set of operations to. The 'ops' input has Key:
//   (output_index_1, output_index_2)
// and applies the indicated operation to those output wires.
// The output circuit's output(s) will be in the order the 'ops' input
// is processed (i.e. based on Keys, and then index within each Value).
extern bool MergeCircuits(
    const std::map<std::pair<uint64_t, uint64_t>, std::vector<math_utils::BooleanOperation>>& ops,
    const StandardCircuit<bool>& one, const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, for an comparison operation. Notice the API is different, since
// ComparisonOperations (can) operate on multiple-bit values. Therefore, the Keys
// for 'ops' have format:
//   (output_indices_1, output_indices_2),
// where output_indices_[1 | 2] is a vector of output indices. This vector is
// to be interpreted as a binary-string representation; thus, the *LAST* element
// of each vector represents the least significant bit, etc.
extern bool MergeCircuits(
    const std::map<std::pair<vector<uint64_t>, vector<uint64_t>>,
                   std::vector<math_utils::ComparisonOperation>>& ops,
    const StandardCircuit<bool>& one, const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, for an arithmetic operation.
extern bool MergeCircuits(
    const std::map<std::pair<vector<uint64_t>, vector<uint64_t>>,
                   std::vector<math_utils::ArithmeticOperation>>& ops,
    const StandardCircuit<bool>& one, const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
// Same as above, for a combination of gate/comparison/arithmetic operations.
// This is a generic wrapper for the three functions above; it will just call the
// appropriate one (based on op_holder.type_). 
// Note that for an element 'op' in 'ops' that has type_ == BOOLEAN, the corresponding
// Key must be a pair of vectors of length 1, since the API of MergeCircuits that
// acts on BooleanOperation requires Keys that are a pair of uint64_t.
extern bool MergeCircuits(
    const std::map<std::pair<vector<uint64_t>, vector<uint64_t>>,
                   std::vector<math_utils::OperationHolder>>& ops,
    const StandardCircuit<bool>& one, const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output);
*/

// Inputs:
//   - input_types: May be empty. If so, all variables are assumed
//     to have DataType kDefaultDataType (INT64).
//   - output_designations: May be empty. If so, BOTH will be the default for
//     the OutputRecipient, and output DataTypes will be the smallest (signed)
//     numeric value that can hold the corresponding output value.
extern bool CircuitFromFunction(
    const bool print_reductions,
    const std::vector<std::vector<std::pair<std::string, math_utils::DataType>>>&
        input_types,
    const std::vector<std::pair<OutputRecipient, math_utils::DataType>>&
        output_designations,
    const std::vector<math_utils::Formula>& output_formulas,
    StandardCircuit<bool>* output);
// Same as above, with just the function description as input. The function string
// should have format:
//    f(x1, x2, ..., xn; y1, y2, ..., ym) = (FORMULA_1; ... FORMULA_i)
// where spacing (including line breaks) is ignored. Before each FORMULA, there
// may optionally be output information (OutputRecipient and DataType), in format:
//   (DataType)[OutputRecipient]:
// In particular:
//   - OutputRecipients and DataTypes: This can either be included/specified
//     in the input function string, or if not present, default is to use BOTH
//     as the output recipients and output DataTypes will be the smallest (signed)
//     numeric value that can hold the corresponding output value.
//   - Input DataTypes: Since these are not provided, circuit will treat all
//     inputs/variables as kDefaultDataType (INT64) DataType.
// WARNING: This function should be used with extreme caution, and probably
// not at all (prefer the API for CircuitFromFunction above), as it is easy
// to screw it up. For example, it is sensitive to the variable name values
// (input ordering will be chosen lexicographically based on the variable
// names, which may not be how they are specified in function LHS nor how
// the user anticipated when loading input values), and is also sensitive
// to input/output DataTypes (for example, function:
//   f(x1, x2; y1) = (x1 < y1) AND x2
// would fail to build, because the default is to treat all inputs/outputs
// as kDefaultDataType (INT64), and then the subcircuit (x1 < y1) will
// correctly dictate the output is BOOL (all ComparisonCircuits output
// BOOL), and then the 'AND' with x2 would fail, since 'AND' only works
// for matching DataTypes, which we don't have here (BOOL vs INT64).
extern bool CircuitFromFunction(
    const bool print_reductions,
    const std::string& function,
    StandardCircuit<bool>* output);
// Same as above, with 'print_reductions' set to false.
inline bool CircuitFromFunction(
    const std::string& function, StandardCircuit<bool>* output) {
  return CircuitFromFunction(false, function, output);
}
/* ============================= END Functions ============================== */

}  // namespace multiparty_computation
}  // namespace crypto
#endif
