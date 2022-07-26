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
// Description: MPC Tool 1: Circuit Builder.
// Provides a mechanism to construct (boolean, arithematic) circuits.
//
// Usage:
// There are several ways to use this tool (build a circuit). The output
// is always the same: a circuit file (that can be loaded by
// [Gmw]StandardCircuit::LoadCircuit()).
//
// NOTE: Can toggle between StandardCircuit and StandardCircuitByGate formats
// of the output by specifying one of the flags (default is circuit_by_gate):
//   --[circuit_]by_gate    --[circuit_]by_level
//
// NOTE: StandardCircuit has one of two formats (see DISCUSSION in
// standard_circuit.h); this executable currently only supports Format 2.
//
// For all use-cases below that specify --op, the "OP" should be one of:
//   A BooleanOperation:
//     {IDENTITY, NOT, AND, NAND, OR, NOR, XOR, EQ, GT, GTE, LT, LTE}
//   A ComparisonOperation:
//     {COMP_EQ, COMP_NEQ, COMP_GT, COMP_GTE, COMP_LT, COMP_LTE}
//   An ArithmeticOperation:
//     {ABS, FACTORIAL, SQRT, ADD, SUB, MULT, DIV, POW}
//
// For all use-cases below that specify --value_type, the "TYPE" should be one of:
//  {BIT, BOOL, [U]INT2, [U]INT4, [U]INT8, [U]INT16, [U]INT32, [U]INT64, DOUBLE, SLICE, STRING}
// where 'BIT' and 'BOOL' are treated identically. Alternatively, (since value_type
// is only used to determine the number of bits), you can specify a (positive) integer.
//
// There are several possible use-cases:
//   0) Flatten Circuit:
//        ./circuit_builder_main.exe --circuit FILE
//   1) Join Two Existing Circuits: Set Output Wires of 1st To Input Wires of 2nd:
//        ./circuit_builder_main.exe --circuit_one FILENAME --circuit_two FILENAME
//      NOTE: the mapping of output wires to input wires will be according to indexing
//      of output wires (for circuit one) and input_one_as_[slice | generic_value]_locations_
//      (for circuit two). In particular, the i^th output wire will map to the i^th
//      input wire, where the i^th input wire is defined as the i^th item while
//      iterating through the input_one_as_[slice | generic_value]_locations_ map.
//   2) Join Three Existing Circuits: Set Output Wires of 1st To "X" Input Wires of 2nd,
//                                    and Output Wires of 2nd To "Y" Input Wires of 2nd:
//       ./circuit_builder_main.exe --left_circuit FILE --right_circuit FILE --circuit_two FILE
//      See NOTE in (1) above about how the mapping is done.
//   3) Merge Two Existing Circuit (Files) via an Operation:
//        ./circuit_builder_main.exe --circuit_one FILENAME --circuit_two FILENAME --op OP
//      NOTE: The (global/circuit) input indices of the first circuit will remain
//      constant. The (global/circuit) input indices of the second circuit can
//      either be kept the same, or can be incremented (by number of input indices
//      in the first circuit). For example, if we want to achieve the global circuit:
//         (x1 > y1)  &&  (x1 > y2)
//      by combining (with AND) the circuits:
//        circuit_one: x1 > y1    circuit_two: x1 > y2
//      then because x1 appears in both circuits, we want to preserve the indexing
//      (in this case, circuit 2 should have been built by specifying that
//      the 2nd Party's input index was "1" (which represents 'y2' since input
//      indices are 0-based), even though this circuit only has a single input
//      from Party 2).
//      The default is to increment Party 2's input indices; if you want to preserve
//      them, specify command-line option:
//        --preserve_input_indexing
//   4) Merge Existing Circuit (File) With a Value via an Operation:
//        ./circuit_builder_main.exe --circuit FILENAME --value_type TYPE --op OP
//      NOTE: As was the case with use-case (3) above, there are two scenarios
//      user may wish in terms of indexing the input index of the vlaue that
//      corresponds to 'value_type': Either use the next input index (i.e. one
//      higher than the highest circuit_one input index), or specify an index.
//      The default is to use the next input index; if you want to specify the
//      index, specify command-line option:
//        --[one | two]_input_index INDEX
//      where {one, two} refers to the Party, and INDEX is the (0-based) input index.
//   5) Combine Two Values via an Operation:
//        ./circuit_builder_main.exe --value_type_one TYPE --value_type_two TYPE --op OP
//      NOTE: As with use-case (4) above, there are two scenarios for how the
//      circuit input wires are labelled: the default is to label value_type_one
//      as the 0^th input from Party 1, and value_type_two as the 0^th input
//      from Party 2. If you want different labelling, specify command-line options:
//        --[one | two]_value_one_input_index INDEX
//        --[one | two]_value_two_input_index INDEX
//   6) Parse a Formula Expression:
//        ./circuit_builder_main.exe --formula FORMULA [--types_k TYPES]
//      where FORMULA should have format: LHS = RHS, where LHS looks like:
//        f(x1, x2, ..., xn; y1, y2, ..., ym; ...)
//      and RHS is enclosed in parentheses and is a semi-colon separated list
//      of formulas involving {x1, ..., xn, y1, ..., yn} and constants;
//      and where TYPES should be a (comma-separated) list of DataTypes
//      for the inputs corresponding to Party k, where the order of this list
//      coincides with the order these inputs
//      were specified in LHS of FORMULA, for example TYPES may be:
//        "BOOL, INT32, UINT64"
//      NOTE: Originally, I also allowed the user to (optionally) specify:
//        [--constant_types CONSTANT_TYPES],
//      which would allow them to dictate the DataTypes of any constant terms
//      appearing in the formula. However, this option is now DEPRECATED, and
//      DataTypes for any constants appearing in the formula are automatically
//      determined (picks the minimal [U]INTXXX that can hold the value, and
//      uses Unsigned for positive values).
//   7) Parse a Formula File:
//        ./circuit_builder_main.exe --function_file FILENAME
//
// There are additional command-line options that can be included for any of the
// above use-cases:
//   --output OR
//   --output_file: Specify the name of the output circuit file that gets created.
//                  Default writes to: CircuitFiles/circuit_builder_output.circuit
//   --outputs: A (semi-colon-separated list of) output DataTypes:OutputRecipient, e.g:
//                --outputs "STRING:A;UINT64:N;BOOL:0,1;BOOL:1"
//   --by_gate: Output format is for StandardCircuitByGate
//   --by_level: Output format is for StandardCircuit
//   --add_lookahead N: Sets the number of ``lookahead'' addition blocks
//                      (kAdditionLookaheadBlocks), which trades-off circuit
//                      size (num gates) vs. circuit depth (default is to
//                      use no lookahead (N == 1), which minimizes circuit
//                      size at the cost of more circuit depth.
//   --depend_on_all: Only relevant if output format is StandardCircuitByGate
//                    (i.e. --by_gate is specified). This sets kForceDependsOnAll
//                    to true, which in turn means that all gates will have
//                    depends_on_ equal all parties.
//
// Examples: There are a bunch of practical examples that can be found in:
//           TestFiles/CircuitFiles/OldCircuitFiles/Notes.txt
//   0) Reduce Circuit.
//        ./circuit_builder_main.exe
//        --circuit TestFiles/CircuitFiles/OldCircuitFiles/big1k.circuit
//   1) Join 2 Existing Circuits.
//        ./circuit_builder_main.exe --circuit_one stack.circuit --circuit_two stack.circuit
//   2) Join 3 Existing Circuits.
//        ./circuit_builder_main.exe --left_circuit lt.circuit --right_circuit eq.circuit
//        --circuit_two stack.circuit
//   3) Merge 2 Existing Circuits (both are 8-bit greater than) with a (boolean) operator:
//      ./circuit_builder_main.exe
//      --circuit_one CircuitFiles/OldCircuitFiles/8_bit_lt.circuit_v2
//      --circuit_two CircuitFiles/OldCircuitFiles/8_bit_lt.circuit_v2 --op OR
//  4a) Merge an Existing Circuit with a Value, via an Operation.
//      The Operation can be any of the Boolean, Comparison, or Arithmetic operators
//      that were specified above. Example:
//      ./circuit_builder_main.exe
//      --circuit CircuitFiles/OldCircuitFiles/8_bit_lt.circuit_v2
//      --value_type BOOL --op AND
//  4b) Same as above, but specify that the value being AND'ed comes from Party 2:
//      ./circuit_builder_main.exe
//      --circuit CircuitFiles/OldCircuitFiles/8_bit_lt.circuit_v2
//      --value_type BOOL --op AND --two_input_index 1
//      NOTE: The fact that the value input comes from Party 2 is dictated by the
//      use of '--two_input_index' (as opposed to '--one_input_index'), and the
//      value specified is "1" because the circuit (file) being merged with has
//      exactly one input from Party 2, and hence the boolean value being combined
//      is Party 2's second input (or, input index = '1', since doing 0-based indexing).
//   5) Comparison of two values.
//        ./circuit_builder_main.exe --value_type_one UINT4 --value_type_two UINT4 --op EQ
//      NOTE: The comparison can be a Boolean operator:
//        {AND, NAND, OR, NOR, XOR, EQ, GT, GTE, LT, LTE}
//      or a Comparison operator:
//        {COMP_EQ, COMP_NEQ, COMP_LT, COMP_GT, COMP_LTE, COMP_GTE}
//      or an "Arithmetic" operator:
//        {+, -, *, /, || (absolute value), MIN, MAX}
//      This will construct a circuit that applies the specified operation to
//      the two values. Example:
//        ./circuit_builder_main.exe --value_type_one BOOL --value_type_two BIT --op EQ
//      NOTE: Even though they look similar, the Boolean Operators generate different
//      circuits than their Comparison Operator counterparts (e.g. EQ vs. COMP_EQ):
//      the former is applied bit-wise, the latter in aggregate. So e.g. given
//      two DataTypes UINT4, operator EQ would generate a circuit that on inputs
//        1011, 1101
//      would output: 1001 (since the first and last bits of the inputs match), while
//      COMP_EQ would generate output 0000 (since 11 \neq 13).
//   6) Circuit from Formula (string).
//        ./circuit_builder_main.exe --formula "f(x; y) = x + y"
//   7) Circuit from Function File.
//        ./circuit_builder_main.exe --function_file TestFiles/FunctionFiles/sum.function

#include "circuit_builder_utils.h"

// Needed for use-case (7), when desired format is .circuit_by_gate, then first
// a .circuit format is constructed, and then circuit_converter_utils::ConvertCircuit()
// converts this to .circuit_by_gate.
#include "Crypto/MultiPartyComputation/Circuits/circuit_converter_utils.h"
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"
#include "MathUtils/data_structures.h"  // For DataType
#include "MathUtils/formula_utils.h"  // For Formula
#include "global_utils.h"

#include <fstream>
#include <map>
#include <string>

using namespace crypto::multiparty_computation;
using namespace math_utils;
using namespace string_utils;
using namespace std;

// When this .exe is called by the Excel MPC tool/plugin, we want a specific
// output message upon success.
static bool kIsExcelUsage = false;

// Toggle whether the final output is a .circuit or .circuit_by_gate.
// This is controlled via the --by_gate and --by_level flags.
static bool kCircuitByGate = true;
// For .circuit_by_gate format, we can force all gates to have depends_on_ indicate
// that all gates depend on all parties; this is useful for use-cases when all
// inputs are (already) secret-shared amongst all parties.
// The default is to set this to false; it can be overridden via --depend_on_all flag.
static bool kForceDependsOnAll = false;

const char kDefaultOutputFilename[] =
    "CircuitFiles/circuit_builder_output.circuit";
const char kDefaultByGateOutputFilename[] =
    "CircuitFiles/circuit_builder_output.circuit_by_gate";

struct ArgHolder {
  bool is_debug_;
  bool preserve_input_indexing_;
  string circuit_one_;
  string circuit_two_;
  string left_circuit_;
  string right_circuit_;
  string formula_;
  string formula_file_;
  string output_file_;
  DataType value_type_one_;
  DataType value_type_two_;
  uint64_t value_bits_one_;
  uint64_t value_bits_two_;
  int64_t party_one_value_one_input_index_;
  int64_t party_two_value_one_input_index_;
  int64_t party_one_value_two_input_index_;
  int64_t party_two_value_two_input_index_;
  int add_lookahead_;
  vector<vector<DataType>> var_types_;
  map<uint64_t, DataType> unsigned_constant_types_;
  map<int64_t, DataType> signed_constant_types_;
  OperationHolder op_holder_;
  vector<pair<OutputRecipient, DataType>> output_targets_;

  ArgHolder() {
    is_debug_ = false;
    preserve_input_indexing_ = false;
    circuit_one_ = "";
    circuit_two_ = "";
    left_circuit_ = "";
    right_circuit_ = "";
    formula_ = "";
    formula_file_ = "";
    output_file_ = string(kDefaultOutputFilename);
    party_one_value_one_input_index_ = -1;
    party_two_value_one_input_index_ = -1;
    party_one_value_two_input_index_ = -1;
    party_two_value_two_input_index_ = -1;
    add_lookahead_ = 1;
    value_type_one_ = DataType::UNKNOWN;
    value_type_two_ = DataType::UNKNOWN;
    value_bits_one_ = 0;
    value_bits_two_ = 0;
  }
};

bool ParseDataType(const string& input, uint64_t* num_bits, DataType* type) {
  // First try to parse input as an (unsigned) int.
  // Need to make sure none of the DataTypes that end in a numeric value
  // are specified, since Stoi will happily return true for these.
  if (!HasPrefixString(input, "STRING") && !HasPrefixString(input, "INT") &&
      !HasPrefixString(input, "UINT") && !HasPrefixString(input, "BIT") &&
      !HasPrefixString(input, "BOOL") && !HasPrefixString(input, "SLICE") &&
      !HasPrefixString(input, "DOUBLE") && !HasPrefixString(input, "UNKNOWN") &&
      Stoi(input, num_bits)) {
    return true;
  }

  // 'input' is not an (unsigned) int. Try to parse as a DataType.
  if (HasPrefixString(input, "STRING")) {
    const string num_bytes_str = StripPrefixString(input, "STRING");
    uint32_t num_bytes;
    if (!Stoi(num_bytes_str, &num_bytes)) return false;
    if (num_bytes == 8) {
      *num_bits = GetValueNumBits(DataType::STRING8);
      *type = DataType::STRING8;
    } else if (num_bytes == 16) {
      *num_bits = GetValueNumBits(DataType::STRING16);
      *type = DataType::STRING16;
    } else if (num_bytes == 24) {
      *num_bits = GetValueNumBits(DataType::STRING24);
      *type = DataType::STRING24;
    } else if (num_bytes == 32) {
      *num_bits = GetValueNumBits(DataType::STRING32);
      *type = DataType::STRING32;
    } else if (num_bytes == 64) {
      *num_bits = GetValueNumBits(DataType::STRING64);
      *type = DataType::STRING64;
    } else if (num_bytes == 128) {
      *num_bits = GetValueNumBits(DataType::STRING128);
      *type = DataType::STRING128;
    } else {
      return false;
    }
    return true;
    LOG_FATAL("STRING DataType not ready yet.");
  } else if (input == "BOOL" || input == "BIT") {
    *num_bits = GetValueNumBits(DataType::BOOL);
    *type = DataType::BOOL;
    return true;
  } else if (input == "INT2") {
    *num_bits = GetValueNumBits(DataType::INT2);
    *type = DataType::INT2;
    return true;
  } else if (input == "UINT2") {
    *num_bits = GetValueNumBits(DataType::UINT2);
    *type = DataType::UINT2;
    return true;
  } else if (input == "INT4") {
    *num_bits = GetValueNumBits(DataType::INT4);
    *type = DataType::INT4;
    return true;
  } else if (input == "UINT4") {
    *num_bits = GetValueNumBits(DataType::UINT4);
    *type = DataType::UINT4;
    return true;
  } else if (input == "INT8") {
    *num_bits = GetValueNumBits(DataType::INT8);
    *type = DataType::INT8;
    return true;
  } else if (input == "UINT8") {
    *num_bits = GetValueNumBits(DataType::UINT8);
    *type = DataType::UINT8;
    return true;
  } else if (input == "INT16") {
    *num_bits = GetValueNumBits(DataType::INT16);
    *type = DataType::INT16;
    return true;
  } else if (input == "UINT16") {
    *num_bits = GetValueNumBits(DataType::UINT16);
    *type = DataType::UINT16;
    return true;
  } else if (input == "INT32") {
    *num_bits = GetValueNumBits(DataType::INT32);
    *type = DataType::INT32;
    return true;
  } else if (input == "UINT32") {
    *num_bits = GetValueNumBits(DataType::UINT32);
    *type = DataType::UINT32;
    return true;
  } else if (input == "INT64") {
    *num_bits = GetValueNumBits(DataType::INT64);
    *type = DataType::INT64;
    return true;
  } else if (input == "UINT64") {
    *num_bits = GetValueNumBits(DataType::UINT64);
    *type = DataType::UINT64;
    return true;
  } else if (input == "SLICE") {
    *num_bits = GetValueNumBits(DataType::SLICE);
    *type = DataType::SLICE;
    return true;
  } else if (input == "DOUBLE") {
    *num_bits = GetValueNumBits(DataType::DOUBLE);
    *type = DataType::DOUBLE;
    return true;
  }

  return false;
}

bool ParseArgs(int argc, char* argv[], ArgHolder* args) {
  // Special handling, for external/production API:
  //   ./circuit_builder_main.exe FUNCTION_FILE
  if (argc == 2) {
    args->formula_file_ = StripQuotes(argv[1]);
    return true;
  }

  // Start loop at '1' (argument 0 is the executable itself).
  for (int i = 1; i < argc; ++i) {
    string arg = argv[i];
    if (ToLowerCase(arg) == "--circuit_one") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--circuit_one'.");
        return false;
      }
      ++i;
      args->circuit_one_ = StripAllEnclosingPunctuationAndWhitespace(argv[i]);
    } else if (ToLowerCase(arg) == "--from_excel") {
      kIsExcelUsage = true;
    } else if (ToLowerCase(arg) == "--add_lookahead") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--add_lookahead'.");
        return false;
      }
      ++i;
      if (!Stoi(
              StripAllEnclosingPunctuationAndWhitespace(argv[i]),
              &args->add_lookahead_) ||
          args->add_lookahead_ <= 0) {
        LOG_ERROR(
            "Unable to parse add_lookahead '" + string(argv[i]) +
            "' as a positive integer.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--depend_on_all") {
      kForceDependsOnAll = true;
    } else if (
        ToLowerCase(arg) == "--circuit_by_gate" ||
        ToLowerCase(arg) == "--by_gate") {
      kCircuitByGate = true;
      args->output_file_ = string(kDefaultByGateOutputFilename);
    } else if (
        ToLowerCase(arg) == "--circuit_by_level" ||
        ToLowerCase(arg) == "--by_level") {
      kCircuitByGate = false;
      args->output_file_ = string(kDefaultOutputFilename);
    } else if (ToLowerCase(arg) == "--circuit") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--circuit'.");
        return false;
      }
      ++i;
      args->circuit_one_ = StripAllEnclosingPunctuationAndWhitespace(argv[i]);
    } else if (ToLowerCase(arg) == "--circuit_two") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--circuit_two'.");
        return false;
      }
      ++i;
      args->circuit_two_ = StripAllEnclosingPunctuationAndWhitespace(argv[i]);
    } else if (ToLowerCase(arg) == "--left_circuit") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--left_circuit'.");
        return false;
      }
      ++i;
      args->left_circuit_ = StripAllEnclosingPunctuationAndWhitespace(argv[i]);
    } else if (ToLowerCase(arg) == "--right_circuit") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--right_circuit'.");
        return false;
      }
      ++i;
      args->right_circuit_ = StripAllEnclosingPunctuationAndWhitespace(argv[i]);
    } else if (
        ToLowerCase(arg) == "--output_file" || ToLowerCase(arg) == "--output") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--output_file'.");
        return false;
      }
      ++i;
      args->output_file_ = StripQuotes(argv[i]);
    } else if (ToLowerCase(arg) == "--formula") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--formula'.");
        return false;
      }
      ++i;
      args->formula_ =
          ToLowerCase(StripAllEnclosingPunctuationAndWhitespace(argv[i]));
    } else if (
        ToLowerCase(arg) == "--formula_file" ||
        ToLowerCase(arg) == "--function_file") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--function_file'.");
        return false;
      }
      ++i;
      args->formula_file_ = StripQuotes(argv[i]);
    } else if (ToLowerCase(arg) == "--debug") {
      args->is_debug_ = true;
    } else if (ToLowerCase(arg) == "--preserve_input_indexing") {
      args->preserve_input_indexing_ = true;
    } else if (HasPrefixString("--types_", ToLowerCase(arg))) {
      // Parse 'k'.
      const string suffix = StripPrefixString("--types_", ToLowerCase(arg));
      int k;
      if (!Stoi(suffix, &k) || k < 0) {
        LOG_ERROR("Unable to parse party index: '" + suffix + "'");
        return false;
      }
      if ((int) args->var_types_.size() <= k) {
        args->var_types_.resize(k + 1);
      }
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--types_k'.");
        return false;
      }
      ++i;
      vector<string> value_types;
      CHECK(Split(
          StripAllEnclosingPunctuationAndWhitespace(argv[i]),
          ",",
          &value_types));
      args->var_types_[k].reserve(value_types.size());
      for (const string& value_type : value_types) {
        uint64_t num_bits;  // Not used.
        DataType type;
        if (!ParseDataType(value_type, &num_bits, &type)) {
          LOG_ERROR("Unable to parse --one_types arg: '" + value_type + "'");
          return false;
        }
        args->var_types_[k].push_back(type);
      }
    } else if (ToLowerCase(arg) == "--constant_types") {
      LOG_WARNING("The --constant_types option is no longer supported; this "
                  "argument will be ignored.");
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--constant_types'.");
        return false;
      }
      ++i;
      vector<string> value_types;
      CHECK(Split(
          StripAllEnclosingPunctuationAndWhitespace(argv[i]),
          ",",
          &value_types));
      for (const string& value_type : value_types) {
        // Split around ":" (terms have form: VALUE:DATATYPE).
        vector<string> parts;
        Split(value_type, ":", &parts);
        if (parts.size() != 2) {
          LOG_ERROR("Unable to parse --constant_types: '" + value_type + "'");
          return false;
        }
        // Parse Value.
        const bool is_negative = HasPrefixString(parts[0], "-");
        const string value_str = is_negative ? parts[0].substr(1) : parts[0];
        uint64_t u_value;
        int64_t value;
        if (is_negative && !Stoi(value_str, &value)) {
          LOG_ERROR("Unable to parse --constant_types: '" + value_type + "'");
          return false;
        } else if (!is_negative && !Stoi(value_str, &u_value)) {
          LOG_ERROR("Unable to parse --constant_types: '" + value_type + "'");
          return false;
        }
        // Parse DataType.
        uint64_t num_bits;  // Not used.
        DataType type;
        if (!ParseDataType(parts[1], &num_bits, &type)) {
          LOG_ERROR(
              "Unable to parse --constant_types arg: '" + value_type + "'");
          return false;
        }
        if (is_negative) {
          args->signed_constant_types_.insert(make_pair(value, type));
        } else {
          args->unsigned_constant_types_.insert(make_pair(u_value, type));
        }
      }
    } else if (ToLowerCase(arg) == "--value_type") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--value_type'.");
        return false;
      }
      ++i;
      const string data_type =
          StripAllEnclosingPunctuationAndWhitespace(argv[i]);
      if (!ParseDataType(
              data_type, &args->value_bits_one_, &args->value_type_one_)) {
        LOG_ERROR(
            "Unable to parse value_type '" + string(argv[i]) +
            "' as a DataType.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--value_type_one") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--value_type_one'.");
        return false;
      }
      ++i;
      const string data_type =
          StripAllEnclosingPunctuationAndWhitespace(argv[i]);
      if (!ParseDataType(
              data_type, &args->value_bits_one_, &args->value_type_one_)) {
        LOG_ERROR(
            "Unable to parse value_type_one '" + string(argv[i]) +
            "' as a DataType.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--value_type_two") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--value_type_two'.");
        return false;
      }
      ++i;
      const string data_type =
          StripAllEnclosingPunctuationAndWhitespace(argv[i]);
      if (!ParseDataType(
              data_type, &args->value_bits_two_, &args->value_type_two_)) {
        LOG_ERROR(
            "Unable to parse value_type_two '" + string(argv[i]) +
            "' as a DataType.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--outputs") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--outputs'.");
        return false;
      }
      ++i;
      vector<string> outputs;
      CHECK(Split(
          StripAllEnclosingPunctuationAndWhitespace(argv[i]), ";", &outputs));
      args->output_targets_.resize(outputs.size());
      for (int i = 0; i < (int) outputs.size(); ++i) {
        vector<string> output_i_parts;
        Split(outputs[i], ":", &output_i_parts);
        if (output_i_parts.size() != 2) {
          LOG_ERROR(
              "Unable to parse output target " + Itoa(i) + ": " + outputs[i]);
          return false;
        }
        args->output_targets_[i].second = StringToDataType(output_i_parts[0]);
        if (args->output_targets_[i].second == DataType::UNKNOWN) {
          LOG_ERROR(
              "Unable to parse output target " + Itoa(i) + ": " + outputs[i]);
          return false;
        }
        vector<string> to;
        Split(output_i_parts[1], ",", &to);
        bool is_first = true;
        for (const string& output_i : to) {
          if (output_i == "A") {
            args->output_targets_[i].first = OutputRecipient(true, false);
          } else if (output_i == "N") {
            args->output_targets_[i].first = OutputRecipient(false, true);
          } else {
            int index;
            if (!Stoi(output_i, &index)) {
              LOG_ERROR(
                  "Unable to parse output " + Itoa(i + 1) +
                  " as one of: "
                  "{A, N, 0, 1, ...}");
              return false;
            }
            if (is_first)
              args->output_targets_[i].first = OutputRecipient(index);
            else args->output_targets_[i].first.to_.insert(index);
          }
          is_first = false;
        }
      }
    } else if (ToLowerCase(arg) == "--op") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--op'.");
        return false;
      }
      ++i;
      const string op_str = StripAllEnclosingPunctuationAndWhitespace(argv[i]);
      if (op_str == "IDENTITY") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::IDENTITY;
      } else if (op_str == "NOT") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::NOT;
      } else if (op_str == "OR") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::OR;
      } else if (op_str == "NOR") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::NOR;
      } else if (op_str == "XOR") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::XOR;
      } else if (op_str == "AND") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::AND;
      } else if (op_str == "NAND") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::NAND;
      } else if (op_str == "EQ") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::EQ;
      } else if (op_str == "GT") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::GT;
      } else if (op_str == "GTE") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::GTE;
      } else if (op_str == "LT") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::LT;
      } else if (op_str == "LTE") {
        args->op_holder_.type_ = OperationType::BOOLEAN;
        args->op_holder_.gate_op_ = BooleanOperation::LTE;
      } else if (op_str == "COMP_EQ") {
        args->op_holder_.type_ = OperationType::COMPARISON;
        args->op_holder_.comparison_op_ = ComparisonOperation::COMP_EQ;
      } else if (op_str == "COMP_NEQ") {
        args->op_holder_.type_ = OperationType::COMPARISON;
        args->op_holder_.comparison_op_ = ComparisonOperation::COMP_NEQ;
      } else if (op_str == "COMP_GT") {
        args->op_holder_.type_ = OperationType::COMPARISON;
        args->op_holder_.comparison_op_ = ComparisonOperation::COMP_GT;
      } else if (op_str == "COMP_GTE") {
        args->op_holder_.type_ = OperationType::COMPARISON;
        args->op_holder_.comparison_op_ = ComparisonOperation::COMP_GTE;
      } else if (op_str == "COMP_LT") {
        args->op_holder_.type_ = OperationType::COMPARISON;
        args->op_holder_.comparison_op_ = ComparisonOperation::COMP_LT;
      } else if (op_str == "COMP_LTE") {
        args->op_holder_.type_ = OperationType::COMPARISON;
        args->op_holder_.comparison_op_ = ComparisonOperation::COMP_LTE;
      } else if (op_str == "ABS") {
        args->op_holder_.type_ = OperationType::ARITHMETIC;
        args->op_holder_.arithmetic_op_ = ArithmeticOperation::ABS;
      } else if (op_str == "FACTORIAL") {
        args->op_holder_.type_ = OperationType::ARITHMETIC;
        args->op_holder_.arithmetic_op_ = ArithmeticOperation::FACTORIAL;
      } else if (op_str == "SQRT") {
        args->op_holder_.type_ = OperationType::ARITHMETIC;
        args->op_holder_.arithmetic_op_ = ArithmeticOperation::SQRT;
      } else if (op_str == "ADD") {
        args->op_holder_.type_ = OperationType::ARITHMETIC;
        args->op_holder_.arithmetic_op_ = ArithmeticOperation::ADD;
      } else if (op_str == "SUB") {
        args->op_holder_.type_ = OperationType::ARITHMETIC;
        args->op_holder_.arithmetic_op_ = ArithmeticOperation::SUB;
      } else if (op_str == "MULT") {
        args->op_holder_.type_ = OperationType::ARITHMETIC;
        args->op_holder_.arithmetic_op_ = ArithmeticOperation::MULT;
      } else if (op_str == "DIV") {
        args->op_holder_.type_ = OperationType::ARITHMETIC;
        args->op_holder_.arithmetic_op_ = ArithmeticOperation::DIV;
      } else if (op_str == "POW") {
        args->op_holder_.type_ = OperationType::ARITHMETIC;
        args->op_holder_.arithmetic_op_ = ArithmeticOperation::POW;
      } else {
        LOG_ERROR(
            "Unable to parse op '" + string(argv[i]) +
            "' as a BooleanOperation, ComparisonOperator, or "
            "ArithmeticOperator.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--one_input_index") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--one_input_index'.");
        return false;
      }
      ++i;
      args->preserve_input_indexing_ = true;
      if (!Stoi(
              StripAllEnclosingPunctuationAndWhitespace(argv[i]),
              &args->party_one_value_one_input_index_) ||
          args->party_one_value_one_input_index_ < 0) {
        LOG_ERROR(
            "Unable to parse one_input_index '" + string(argv[i]) +
            "' as a non-negative integer.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--two_input_index") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--two_input_index'.");
        return false;
      }
      ++i;
      args->preserve_input_indexing_ = true;
      if (!Stoi(
              StripAllEnclosingPunctuationAndWhitespace(argv[i]),
              &args->party_two_value_one_input_index_) ||
          args->party_two_value_one_input_index_ < 0) {
        LOG_ERROR(
            "Unable to parse two_input_index '" + string(argv[i]) +
            "' as a non-negative integer.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--one_value_one_input_index") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--one_value_one_input_index'.");
        return false;
      }
      ++i;
      args->preserve_input_indexing_ = true;
      if (!Stoi(
              StripAllEnclosingPunctuationAndWhitespace(argv[i]),
              &args->party_one_value_one_input_index_) ||
          args->party_one_value_one_input_index_ < 0) {
        LOG_ERROR(
            "Unable to parse one_value_one_input_index '" + string(argv[i]) +
            "' as a non-negative integer.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--two_value_one_input_index") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--two_value_one_input_index'.");
        return false;
      }
      ++i;
      args->preserve_input_indexing_ = true;
      if (!Stoi(
              StripAllEnclosingPunctuationAndWhitespace(argv[i]),
              &args->party_two_value_one_input_index_) ||
          args->party_two_value_one_input_index_ < 0) {
        LOG_ERROR(
            "Unable to parse two_value_one_input_index '" + string(argv[i]) +
            "' as a non-negative integer.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--one_value_two_input_index") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--one_value_two_input_index'.");
        return false;
      }
      ++i;
      args->preserve_input_indexing_ = true;
      if (!Stoi(
              StripAllEnclosingPunctuationAndWhitespace(argv[i]),
              &args->party_one_value_two_input_index_) ||
          args->party_one_value_two_input_index_ < 0) {
        LOG_ERROR(
            "Unable to parse one_value_two_input_index '" + string(argv[i]) +
            "' as a non-negative integer.");
        return false;
      }
    } else if (ToLowerCase(arg) == "--two_value_two_input_index") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--two_value_two_input_index'.");
        return false;
      }
      ++i;
      args->preserve_input_indexing_ = true;
      if (!Stoi(
              StripAllEnclosingPunctuationAndWhitespace(argv[i]),
              &args->party_two_value_two_input_index_) ||
          args->party_two_value_two_input_index_ < 0) {
        LOG_ERROR(
            "Unable to parse two_value_two_input_index '" + string(argv[i]) +
            "' as a non-negative integer.");
        return false;
      }
    } else if (!HasPrefixString(arg, "--")) {
      // Treat flag-prefixed argument as the formula file.
      if (!args->formula_file_.empty()) {
        LOG_ERROR("Unexpected command-line argument '" + arg + "'");
        return false;
      }
      args->formula_file_ = StripQuotes(argv[i]);
    } else {
      LOG_ERROR("Unexpected command-line argument '" + arg + "'");
      return false;
    }
  }

  return true;
}

bool UpdateOutputs(
    const vector<pair<OutputRecipient, DataType>>& output_targets,
    StandardCircuit<bool>* circuit) {
  if (output_targets.empty()) return true;
  if (output_targets.size() != circuit->output_designations_.size()) {
    LOG_ERROR("Mismatching number of outputs.");
    return false;
  }
  for (int i = 0; i < (int) output_targets.size(); ++i) {
    circuit->output_designations_[i] = output_targets[i];
  }
  return true;
}

// Run use-case (0).
bool SimplifyCircuit(ArgHolder& args) {
  StandardCircuit<bool> circuit;
  circuit.load_function_description_ = true;
  CHECK(circuit.LoadCircuit(args.circuit_one_));
  const int num_changes_made = ReduceCircuit(&circuit);
  if (num_changes_made < 0) {
    LOG_ERROR("Failed to ReduceCircuit.");
    return false;
  } else if (num_changes_made > 0) {
    circuit.WriteCircuitFile(args.output_file_);
    LOG_LINE();
    TLOG_INFO("Made " + Itoa(num_changes_made) + " reductions!");
  } else {
    TLOG_INFO(
        "Circuit in " + args.circuit_one_ +
        " is already reduced; nothing done.");
  }

  return true;
}

// Run use-case (1).
bool JoinTwoCircuits(ArgHolder& args) {
  // Read the two circuits from file.
  StandardCircuit<bool> circuit_one, circuit_two;
  circuit_one.load_function_description_ = true;
  circuit_two.load_function_description_ = true;
  if (args.is_debug_)
    TLOG_INFO("Loading circuits (into memory) from .circuit files...");
  CHECK(
      circuit_one.LoadCircuit(args.circuit_one_) &&
      circuit_two.LoadCircuit(args.circuit_two_));

  // Join the circuits.
  StandardCircuit<bool> output;
  if (args.is_debug_) TLOG_INFO("Joining circuits...");
  CHECK(JoinCircuits(circuit_one, circuit_two, &output));

  // Reduce circuit.
  if (args.is_debug_) TLOG_INFO("Reducing circuit...");
  CHECK(ReduceCircuit(&output) >= 0);

  // Print joined circuit to file.
  if (args.is_debug_) TLOG_INFO("Done building circuit. Printing to file...");
  if (!UpdateOutputs(args.output_targets_, &output)) return false;
  output.WriteCircuitFile(args.output_file_);
  return true;
}

// Run use-case (2).
bool JoinThreeCircuits(ArgHolder& args) {
  // Read the three circuits from file.
  StandardCircuit<bool> left_circuit, right_circuit, circuit_two;
  left_circuit.load_function_description_ = true;
  right_circuit.load_function_description_ = true;
  circuit_two.load_function_description_ = true;
  if (args.is_debug_)
    TLOG_INFO("Loading circuits (into memory) from .circuit files...");
  CHECK(
      left_circuit.LoadCircuit(args.left_circuit_) &&
      right_circuit.LoadCircuit(args.right_circuit_) &&
      circuit_two.LoadCircuit(args.circuit_two_));

  // Join the circuits.
  StandardCircuit<bool> output;
  if (args.is_debug_) TLOG_INFO("Joining circuits...");
  CHECK(JoinCircuits(left_circuit, right_circuit, circuit_two, &output));

  // Reduce circuit.
  if (args.is_debug_) TLOG_INFO("Reducing circuit...");
  CHECK(ReduceCircuit(&output) >= 0);

  // Print joined circuit to file.
  if (args.is_debug_) TLOG_INFO("Done building circuit. Printing to file...");
  if (!UpdateOutputs(args.output_targets_, &output)) return false;
  output.WriteCircuitFile(args.output_file_);
  return true;
}

// Run use-case (3).
bool MergeTwoCircuits(ArgHolder& args) {
  // Read the two circuits from file.
  StandardCircuit<bool> circuit_one, circuit_two;
  circuit_one.load_function_description_ = true;
  circuit_two.load_function_description_ = true;
  if (args.is_debug_)
    TLOG_INFO("Loading circuits (into memory) from .circuit files...");
  CHECK(
      circuit_one.LoadCircuit(args.circuit_one_) &&
      circuit_two.LoadCircuit(args.circuit_two_));

  // Merging two circuits via an operation (other than IDENTITY, which
  // has a special meaning) is not possible unless the outputs of the
  // circuits each represent a single value.
  bool one_is_twos_complement = false;
  bool two_is_twos_complement = false;
  if (args.op_holder_.type_ != OperationType::BOOLEAN ||
      args.op_holder_.gate_op_ != BooleanOperation::IDENTITY) {
    if (circuit_one.output_designations_.size() != 1 ||
        circuit_two.output_designations_.size() != 1) {
      LOG_ERROR("Cannot merge two circuits with non-trivial operation "
                "unless the two circuits each output a single value.");
      return false;
    }
    one_is_twos_complement =
        IsDataTypeTwosComplement(circuit_one.output_designations_[0].second);
    two_is_twos_complement =
        IsDataTypeTwosComplement(circuit_two.output_designations_[0].second);
  }

  // Merge the circuits.
  StandardCircuit<bool> output;
  if (args.is_debug_) TLOG_INFO("Merging circuits...");
  if (args.op_holder_.type_ == OperationType::BOOLEAN) {
    CHECK(MergeCircuitsInternal(
        args.preserve_input_indexing_,
        args.op_holder_.gate_op_,
        circuit_one,
        circuit_two,
        &output));
  } else if (args.op_holder_.type_ == OperationType::COMPARISON) {
    CHECK(MergeCircuits(
        args.preserve_input_indexing_,
        args.op_holder_.comparison_op_,
        one_is_twos_complement,
        two_is_twos_complement,
        circuit_one,
        circuit_two,
        &output));
  } else {
    if (args.add_lookahead_ > 1)
      SetAdditionNumberLookaheadBlocks(args.add_lookahead_);
    CHECK(MergeCircuits(
        args.preserve_input_indexing_,
        args.op_holder_.arithmetic_op_,
        one_is_twos_complement,
        two_is_twos_complement,
        circuit_one,
        circuit_two,
        &output));
  }

  // Reduce circuit.
  if (args.is_debug_) TLOG_INFO("Reducing circuit...");
  CHECK(ReduceCircuit(&output) >= 0);

  // Print merged circuit to file.
  if (args.is_debug_) TLOG_INFO("Done building circuit. Printing to file...");
  if (!UpdateOutputs(args.output_targets_, &output)) return false;
  output.WriteCircuitFile(args.output_file_);
  return true;
}

// Run use-case (4).
bool MergeCircuitAndValue(ArgHolder& args) {
  // Read the first circuit from file.
  StandardCircuit<bool> circuit_one;
  circuit_one.load_function_description_ = true;
  if (args.is_debug_)
    TLOG_INFO("Loading circuit (into memory) from .circuit file...");
  CHECK(circuit_one.LoadCircuit(args.circuit_one_));

  // Merging a circuits with an operation is not possible unless the outputs of
  // the circuit represents a single value.
  bool one_is_twos_complement;
  if (circuit_one.output_designations_.size() != 1) {
    LOG_ERROR("Cannot merge a circuit and a value unless the "
              "circuit outputs a single value.");
    return false;
  }
  one_is_twos_complement =
      IsDataTypeTwosComplement(circuit_one.output_designations_[0].second);

  // Create a (identity) circuit for the Value.
  const bool two_is_twos_complement =
      (args.value_type_one_ == DataType::UNKNOWN) ?
      IsDataTypeTwosComplement(kDefaultDataType) :
      IsDataTypeTwosComplement(args.value_type_one_);
  StandardCircuit<bool> circuit_two;
  if (args.preserve_input_indexing_) {
    if (args.party_two_value_one_input_index_ == -1) {
      if (args.value_type_one_ == DataType::UNKNOWN) {
        CHECK(ConstructIdentityCircuit(
            false,
            true,
            two_is_twos_complement,
            args.party_one_value_one_input_index_,
            args.value_bits_one_,
            &circuit_two));
      } else {
        CHECK(ConstructIdentityCircuit(
            true,
            args.party_one_value_one_input_index_,
            args.value_type_one_,
            &circuit_two));
      }
    } else {
      if (args.value_type_one_ == DataType::UNKNOWN) {
        CHECK(ConstructIdentityCircuit(
            false,
            false,
            two_is_twos_complement,
            args.party_two_value_one_input_index_,
            args.value_bits_one_,
            &circuit_two));
      } else {
        CHECK(ConstructIdentityCircuit(
            false,
            args.party_two_value_one_input_index_,
            args.value_type_one_,
            &circuit_two));
      }
    }
  } else {
    if (args.value_type_one_ == DataType::UNKNOWN) {
      CHECK(ConstructIdentityCircuit(
          false, two_is_twos_complement, args.value_bits_one_, &circuit_two));
    } else {
      CHECK(ConstructIdentityCircuit(args.value_type_one_, &circuit_two));
    }
  }

  // Merge the circuits.
  if (args.is_debug_) TLOG_INFO("Merging circuits...");
  StandardCircuit<bool> output;
  if (args.op_holder_.type_ == OperationType::BOOLEAN) {
    CHECK(MergeCircuitsInternal(
        args.preserve_input_indexing_,
        args.op_holder_.gate_op_,
        circuit_one,
        circuit_two,
        &output));
  } else if (args.op_holder_.type_ == OperationType::COMPARISON) {
    CHECK(MergeCircuits(
        args.preserve_input_indexing_,
        args.op_holder_.comparison_op_,
        one_is_twos_complement,
        two_is_twos_complement,
        circuit_one,
        circuit_two,
        &output));
  } else {
    if (args.add_lookahead_ > 1)
      SetAdditionNumberLookaheadBlocks(args.add_lookahead_);
    CHECK(MergeCircuits(
        args.preserve_input_indexing_,
        args.op_holder_.arithmetic_op_,
        one_is_twos_complement,
        two_is_twos_complement,
        circuit_one,
        circuit_two,
        &output));
  }

  // Reduce circuit.
  if (args.is_debug_) TLOG_INFO("Reducing circuits...");
  CHECK(ReduceCircuit(&output) >= 0);

  // Print merged circuit to file.
  if (args.is_debug_) TLOG_INFO("Done building circuit. Printing to file...");
  if (!UpdateOutputs(args.output_targets_, &output)) return false;
  output.WriteCircuitFile(args.output_file_);
  return true;
}

// Run use-case (5).
bool CombineTwoValues(ArgHolder& args) {
  // Set input indices.
  bool value_one_is_party_one = true;
  bool value_two_is_party_one = false;
  uint64_t value_one_input_index = 0;
  uint64_t value_two_input_index = 0;
  if (args.preserve_input_indexing_) {
    if (args.party_two_value_one_input_index_ == -1) {
      value_one_input_index = args.party_one_value_one_input_index_;
    } else {
      value_one_is_party_one = false;
      value_one_input_index = args.party_two_value_one_input_index_;
    }
    if (args.party_two_value_two_input_index_ == -1) {
      value_two_input_index = args.party_one_value_two_input_index_;
    } else {
      value_two_is_party_one = false;
      value_two_input_index = args.party_two_value_two_input_index_;
    }
  }

  if (args.op_holder_.type_ == OperationType::BOOLEAN &&
      args.value_bits_one_ != args.value_bits_two_) {
    LOG_ERROR("Unable to combine values with different number of bits");
    return false;
  }

  const bool one_is_twos_complement =
      (args.value_type_one_ == DataType::UNKNOWN) ?
      IsDataTypeTwosComplement(kDefaultDataType) :
      IsDataTypeTwosComplement(args.value_type_one_);
  const bool two_is_twos_complement =
      (args.value_type_two_ == DataType::UNKNOWN) ?
      IsDataTypeTwosComplement(kDefaultDataType) :
      IsDataTypeTwosComplement(args.value_type_two_);

  // Construct circuit, using appropriate API based on op type.
  StandardCircuit<bool> output;
  if (args.op_holder_.type_ == OperationType::BOOLEAN) {
    if (args.value_type_one_ == DataType::UNKNOWN ||
        args.value_type_two_ == DataType::UNKNOWN) {
      CHECK(ConstructBooleanCircuit(
          args.op_holder_.gate_op_,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_is_party_one,
          value_one_input_index,
          value_two_is_party_one,
          value_two_input_index,
          args.value_bits_one_,
          &output));
    } else {
      CHECK(ConstructBooleanCircuit(
          args.op_holder_.gate_op_,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_is_party_one,
          value_one_input_index,
          value_two_is_party_one,
          value_two_input_index,
          args.value_type_one_,
          &output));
    }
  } else if (args.op_holder_.type_ == OperationType::COMPARISON) {
    if (args.value_type_one_ == DataType::UNKNOWN ||
        args.value_type_two_ == DataType::UNKNOWN) {
      CHECK(ConstructComparisonCircuit(
          args.op_holder_.comparison_op_,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_is_party_one,
          value_one_input_index,
          value_two_is_party_one,
          value_two_input_index,
          args.value_bits_one_,
          args.value_bits_two_,
          &output));
    } else {
      CHECK(ConstructComparisonCircuit(
          args.op_holder_.comparison_op_,
          value_one_is_party_one,
          value_one_input_index,
          value_two_is_party_one,
          value_two_input_index,
          args.value_type_one_,
          args.value_type_two_,
          &output));
    }
  } else {
    if (args.add_lookahead_ > 1)
      SetAdditionNumberLookaheadBlocks(args.add_lookahead_);
    if (args.value_type_one_ == DataType::UNKNOWN ||
        args.value_type_two_ == DataType::UNKNOWN) {
      CHECK(ConstructArithmeticCircuit(
          true,
          args.op_holder_.arithmetic_op_,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_is_party_one,
          value_one_input_index,
          value_two_is_party_one,
          value_two_input_index,
          args.value_bits_one_,
          args.value_bits_two_,
          &output));
    } else {
      CHECK(ConstructArithmeticCircuit(
          true,
          args.op_holder_.arithmetic_op_,
          value_one_is_party_one,
          value_one_input_index,
          value_two_is_party_one,
          value_two_input_index,
          args.value_type_one_,
          args.value_type_two_,
          &output));
    }
  }

  // Reduce circuit.
  if (args.is_debug_) TLOG_INFO("Reducing circuits...");
  CHECK(ReduceCircuit(&output) >= 0);

  // Print merged circuit to file.
  if (args.is_debug_) TLOG_INFO("Done building circuit. Printing to file...");
  if (!UpdateOutputs(args.output_targets_, &output)) return false;
  output.WriteCircuitFile(args.output_file_);
  return true;
}

// Run use-case (6).
bool ParseFormula(ArgHolder& args) {
  // Parse args.formula_.
  bool output_designation_present = false;
  vector<pair<OutputRecipient, DataType>> output_designations;
  vector<vector<string>> input_names;
  vector<Formula> output_formulas;
  if (args.is_debug_) TLOG_INFO("Parsing function...");
  if (!ParseFunctionString(
          args.formula_,
          &output_designation_present,
          &input_names,
          &output_formulas,
          &output_designations)) {
    LOG_ERROR("Unable to parse function string:\n" + args.formula_);
    return false;
  }

  // Add variable names with default DataType kDefaultDataType (INT64)
  // to expected input types.
  const int num_parties = (int) input_names.size();
  vector<vector<pair<string, DataType>>> input_types(num_parties);
  for (int party = 0; party < num_parties; ++party) {
    input_types[party].resize(input_names[party].size());
    if ((int) args.var_types_.size() <= party ||
        args.var_types_[party].empty()) {
      int i = 0;
      for (const string& var_name : input_names[party]) {
        input_types[party][i] = make_pair(var_name, kDefaultDataType);
        ++i;
      }
    } else {
      if (args.var_types_[party].size() != input_names[party].size()) {
        LOG_ERROR("Mismatching size of number of inputs found");
        return false;
      }
      for (int i = 0; i < (int) input_names[party].size(); ++i) {
        input_types[party][i] =
            make_pair(input_names[party][i], args.var_types_[party][i]);
      }
    }
  }

  StandardCircuit<bool> output;
  if (args.is_debug_) TLOG_INFO("Building circuit...");
  if (args.add_lookahead_ > 1)
    SetAdditionNumberLookaheadBlocks(args.add_lookahead_);
  if (!CircuitFromFunction(
          args.is_debug_,
          input_types,
          output_designations,
          output_formulas,
          &output)) {
    LOG_ERROR("Failed to generate CircuitFromFunction");
    return false;
  }

  // Print circuit to file.
  if (args.is_debug_) TLOG_INFO("Done building circuit. Printing to file...");
  if (!UpdateOutputs(args.output_targets_, &output)) return false;
  output.WriteCircuitFile(args.output_file_);

  return true;
}

// Run use-case (7).
bool ParseFormulaFile(ArgHolder& args) {
  // Parse function file.
  const string orig_output_name = args.output_file_;
  string& output_circuit_filename = args.output_file_;
  vector<Formula> function;
  vector<vector<GenericValue>> input_values;
  vector<vector<pair<string, DataType>>> input_var_types;
  vector<pair<OutputRecipient, DataType>> output_types;
  if (args.is_debug_) TLOG_INFO("Reading .function file...");
  if (!ReadFunctionFile(
          false,
          args.formula_file_,
          &output_circuit_filename,
          &function,
          &input_values,
          &input_var_types,
          &output_types)) {
    LOG_ERROR("Failed to process function file: '" + args.formula_file_ + "'");
    return false;
  }

  // Sanity-check that the output filename in the .function file is consistent
  // with the command-line arg --output specified by the user.
  if (orig_output_name != output_circuit_filename &&
      orig_output_name != kDefaultOutputFilename &&
      orig_output_name != kDefaultByGateOutputFilename) {
    if (!kIsExcelUsage) {
      TLOG_WARNING(
          "Output file name specified in the .function file '" +
          args.formula_file_ + "' (" + output_circuit_filename +
          ") does not match the name specified in the --output "
          "command-line argument (" +
          orig_output_name + "). The latter name is used.");
    }
    args.output_file_ = orig_output_name;
  }

  // Build Circuit.
  StandardCircuit<bool> output;
  if (args.is_debug_)
    TLOG_INFO("Parsing function and inputs from .function file...");
  if (args.add_lookahead_ > 1)
    SetAdditionNumberLookaheadBlocks(args.add_lookahead_);
  if (!CircuitFromFunction(
          args.is_debug_, input_var_types, output_types, function, &output)) {
    LOG_ERROR("Failed to construct circuit.");
    return false;
  }

  // Print circuit to file.
  if (args.is_debug_) TLOG_INFO("Done building circuit. Printing to file...");
  if (!UpdateOutputs(args.output_targets_, &output)) return false;

  if (kCircuitByGate) {
    if (kForceDependsOnAll) SetDependsOnAll(true);
    CircuitByGate output_by_gate;
    if (!ConvertCircuit(&output, &output_by_gate)) {
      LOG_ERROR("Unable to convert circuit from by-level to by-gate.");
      return false;
    }
    return output_by_gate.WriteCircuitFile(args.output_file_);
  } else {
    return output.WriteCircuitFile(args.output_file_);
  }
}

// Determines the use-case (based on the user-specified command-line arguments
// in 'args'), and makes sure all appropriate command-line arguments are
// consistent with this use-case (i.e. all necessary arguments provided, and
// no extra ones provided). Populates 'use_case_function_ptr' with the
// appropriate use-case function to run.
typedef bool (*use_case_function_ptr)(ArgHolder&);
bool DetermineUseCase(const ArgHolder& args, use_case_function_ptr* fn_ptr) {
  // Check for use-case (7).
  if (!args.formula_file_.empty()) {
    if (!args.circuit_one_.empty() || !args.circuit_two_.empty() ||
        !args.left_circuit_.empty() || !args.right_circuit_.empty() ||
        !args.formula_.empty() || args.value_bits_one_ != 0 ||
        args.value_bits_two_ != 0 ||
        args.party_one_value_one_input_index_ >= 0 ||
        args.party_two_value_one_input_index_ >= 0 ||
        args.party_one_value_two_input_index_ >= 0 ||
        args.party_two_value_two_input_index_ >= 0 ||
        args.preserve_input_indexing_ || args.op_holder_.IsValid()) {
      LOG_ERROR("Invalid use-case (7) parameters.");
      return false;
    }
    *fn_ptr = &ParseFormulaFile;
    return true;
  }

  // Check for use-case (6).
  if (!args.formula_.empty()) {
    if (!args.circuit_one_.empty() || !args.circuit_two_.empty() ||
        !args.left_circuit_.empty() || !args.right_circuit_.empty() ||
        !args.formula_file_.empty() || args.value_bits_one_ != 0 ||
        args.value_bits_two_ != 0 ||
        args.party_one_value_one_input_index_ >= 0 ||
        args.party_two_value_one_input_index_ >= 0 ||
        args.party_one_value_two_input_index_ >= 0 ||
        args.party_two_value_two_input_index_ >= 0 ||
        args.preserve_input_indexing_ || args.op_holder_.IsValid()) {
      LOG_ERROR("Invalid use-case (6) parameters.");
      return false;
    }
    *fn_ptr = &ParseFormula;
    return true;
  }

  // Check for use-case (5).
  if (args.value_bits_one_ != 0 && args.value_bits_two_ != 0) {
    if (!args.circuit_one_.empty() || !args.circuit_two_.empty() ||
        !args.left_circuit_.empty() || !args.right_circuit_.empty() ||
        !args.formula_.empty() || !args.formula_file_.empty() ||
        !args.op_holder_.IsValid()) {
      LOG_ERROR("Invalid use-case (5) parameters.");
      return false;
    }
    *fn_ptr = &CombineTwoValues;
    return true;
  }

  // Check for use-case (4).
  if (args.value_bits_one_ != 0) {
    if (!args.circuit_two_.empty() || !args.left_circuit_.empty() ||
        !args.right_circuit_.empty() || !args.formula_.empty() ||
        !args.formula_file_.empty() || args.value_bits_two_ != 0 ||
        args.party_one_value_two_input_index_ >= 0 ||
        args.party_two_value_two_input_index_ >= 0 ||
        !args.op_holder_.IsValid()) {
      LOG_ERROR("Invalid use-case (4) parameters.");
      return false;
    }
    *fn_ptr = &MergeCircuitAndValue;
    return true;
  }

  // Check for use-case (3).
  if (args.op_holder_.IsValid()) {
    if (args.circuit_one_.empty() || args.circuit_two_.empty() ||
        !args.left_circuit_.empty() || !args.right_circuit_.empty() ||
        !args.formula_.empty() || !args.formula_file_.empty() ||
        args.value_bits_one_ != 0 || args.value_bits_two_ != 0 ||
        args.party_one_value_one_input_index_ >= 0 ||
        args.party_two_value_one_input_index_ >= 0 ||
        args.party_one_value_two_input_index_ >= 0 ||
        args.party_two_value_two_input_index_ >= 0) {
      LOG_ERROR("Invalid use-case (3) parameters.");
      return false;
    }
    *fn_ptr = &MergeTwoCircuits;
    return true;
  }

  // Check for use-case (2).
  if (!args.left_circuit_.empty() && !args.right_circuit_.empty()) {
    if (!args.circuit_one_.empty() || args.circuit_two_.empty() ||
        !args.formula_.empty() || !args.formula_file_.empty() ||
        args.value_bits_one_ != 0 || args.value_bits_two_ != 0 ||
        args.party_one_value_one_input_index_ >= 0 ||
        args.party_two_value_one_input_index_ >= 0 ||
        args.party_one_value_two_input_index_ >= 0 ||
        args.party_two_value_two_input_index_ >= 0 ||
        args.preserve_input_indexing_ || args.op_holder_.IsValid()) {
      LOG_ERROR("Invalid use-case (2) parameters.");
      return false;
    }
    *fn_ptr = &JoinThreeCircuits;
    return true;
  }

  // Check for use-case (1).
  if (!args.circuit_one_.empty() && !args.circuit_two_.empty()) {
    if (!args.left_circuit_.empty() || !args.right_circuit_.empty() ||
        !args.formula_.empty() || !args.formula_file_.empty() ||
        args.value_bits_one_ != 0 || args.value_bits_two_ != 0 ||
        args.party_one_value_one_input_index_ >= 0 ||
        args.party_two_value_one_input_index_ >= 0 ||
        args.party_one_value_two_input_index_ >= 0 ||
        args.party_two_value_two_input_index_ >= 0 ||
        args.preserve_input_indexing_ || args.op_holder_.IsValid()) {
      LOG_ERROR("Invalid use-case (1) parameters.");
      return false;
    }
    *fn_ptr = &JoinTwoCircuits;
    return true;
  }

  // Check for use-case (0).
  if (!args.circuit_one_.empty()) {
    if (!args.circuit_two_.empty() || !args.left_circuit_.empty() ||
        !args.right_circuit_.empty() || !args.formula_.empty() ||
        !args.formula_file_.empty() || args.value_bits_one_ != 0 ||
        args.value_bits_two_ != 0 ||
        args.party_one_value_one_input_index_ >= 0 ||
        args.party_two_value_one_input_index_ >= 0 ||
        args.party_one_value_two_input_index_ >= 0 ||
        args.party_two_value_two_input_index_ >= 0 ||
        args.preserve_input_indexing_ || args.op_holder_.IsValid()) {
      LOG_ERROR("Invalid use-case (0) parameters.");
      return false;
    }
    *fn_ptr = &SimplifyCircuit;
    return true;
  }

  LOG_ERROR("Unable to run circuit_builder_main.exe with the provided "
            "parameters. Be sure command-line arguments are consistent "
            "with one of the use-case examples listed in the USAGE section.");
  return false;
}

int main(int argc, char* argv[]) {
  InitMain();

  ArgHolder args;
  if (!ParseArgs(argc, argv, &args)) {
    LOG_ERROR("Unable to run circuit_builder_main.exe with the provided "
              "parameters. Be sure command-line arguments are consistent "
              "with one of the use-case examples listed in the USAGE section.");
    return -1;
  }
  SetUseLogColors(!kIsExcelUsage);

  // Determine which use-case is desired based on command-line args.
  use_case_function_ptr fn_ptr;
  if (!DetermineUseCase(args, &fn_ptr)) {
    LOG_ERROR("Unable to run circuit_builder_main.exe with the provided "
              "parameters. Be sure command-line arguments are consistent "
              "with one of the use-case examples listed in the USAGE section.");
    return -1;
  }

  // Run the appropriate use-case.
  if (!(*fn_ptr)(args)) {
    return -1;
  }

  if (!kIsExcelUsage) {
    LOG_LINE();
    TLOG_INFO("Success! Circuit can be found in: '" + args.output_file_ + "'");
  }

  return 0;
}
