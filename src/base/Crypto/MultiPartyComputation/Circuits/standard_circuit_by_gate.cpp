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

#include "standard_circuit_by_gate.h"

#include "FileReaderUtils/read_file_utils.h"
#include "GenericUtils/thread.h"
#include "GenericUtils/thread_utils.h"
#include "MapUtils/map_utils.h"  // For FindOrNull()
#include "MathUtils/constants.h"  // For slice
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "MathUtils/formula_utils.h"  // For Formula.
#include "circuit_utils.h"  // For OutputRecipient.
#include "global_utils.h"
#include "gmw_circuit_by_gate.h"  // For GmwByGate.
#include "standard_circuit.h"  // For PrintFunction() and ParseFunctionString().

#include <cctype>  // For isspace().
#include <fstream>
#include <map>
#include <string>
#include <unistd.h>  // For usleep().
#include <vector>

using namespace math_utils;
using namespace map_utils;
using namespace file_reader_utils;
using namespace string_utils;
using namespace std;

namespace crypto {
namespace multiparty_computation {

namespace {

static const bool kPrintGateEvalInfo = false;
static const char kCircuitFileDir[] = "CircuitByGateFiles/";

// Read Circuit File constants.
static const int64_t kMaxReadFileBlockBytes = 256 * 1024 * 1024;  // 256Mb
static const string kNumGatesKeyword = "Num_Gates:";
static const string kNumNonLocalBoolKeyword = "Num_Non_Local_Boolean_Gates:";
static const string kNumNonLocalBoolKeywordOld = "-Local_Boolean_Gates:";
static const string kNumGatesPerLevelKeyword = "Num_Gates_Per_Level:";
static const string kNumNonLocalArithKeyword = "Num_Non_Local_Arithmetic_Gates:";
static const string kNumNonLocalArithKeywordOld = "-Local_Arithmetic_Gates:";
static const string kNumOutputsKeyword = "Num_Outputs:";
static const string kArithGatesFromBoolGatesKeyword =
    "Arithmetic_Gates_with_Inputs_from_Boolean_Gates:";
static const string kPartyInputsKeyword = "Party_Inputs";
static const string kConstantGatesKeyword = "Constant_Inputs:";
static const string kGateInfoKeyword = "Gate_Info:";
static const int kNumDigitsInGateIndexDataType = 10;
static const int kNumDigitsIn64BitInt = 20;
static const int kNumDigitsIn8BitInt = 3;
static const map<DataType, string> kDataTypeToString = {
    {DataType::STRING8, "S8"},   {DataType::STRING16, "S16"},
    {DataType::STRING24, "S24"}, {DataType::STRING32, "S32"},
    {DataType::STRING64, "S64"}, {DataType::STRING128, "S128"},
    {DataType::BOOL, "B"},       {DataType::INT2, "I2"},
    {DataType::UINT2, "U2"},     {DataType::INT4, "I4"},
    {DataType::UINT4, "U4"},     {DataType::INT8, "I8"},
    {DataType::UINT8, "U8"},     {DataType::INT16, "I16"},
    {DataType::UINT16, "U16"},   {DataType::INT32, "I32"},
    {DataType::UINT32, "U32"},   {DataType::INT64, "I64"},
    {DataType::UINT64, "U64"},   {DataType::SLICE, "L"},
    {DataType::DOUBLE, "D"},     {DataType::VECTOR, "V"},
};

// Extracts the byte at index 'current_byte_index' out of memblock.
// If this byte is a space (\s, \t, \r, \n), increments current_byte_index
// and extracts the next byte (and so on). If at any point current_byte_index
// exceeds current_block_size, returns the null char (\0).
char GetByte(
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index) {
  while ((int64_t) *current_byte_index < current_block_size) {
    char to_return = memblock[*current_byte_index];
    if (isspace(to_return)) {
      ++(*current_byte_index);
    } else {
      return to_return;
    }
  }

  // Failed to extract byte (all bytes were whitespace).
  return '\0';
}

// Searches memblock for 'keyword', starting at position 'current_byte_index'.
// If 'keyword' is *not* the first (non-whitespace) char found, returns false,
// and also if 'reset' is true, then makes sure input parameters (current_byte_index
// and the pointer within memblock) are reset to their initial values.
// Otherwise, current_byte_index is advanced to the next character after the
// end of 'keyword'.
bool AdvanceCurrentByteIndex(
    const bool reset,
    const string& keyword,
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index) {
  uint64_t orig_byte_index = *current_byte_index;
  for (size_t i = 0; i < keyword.length(); ++i) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == '\0' || current_byte != keyword.at(i)) {
      if (reset) *current_byte_index = orig_byte_index;
      return false;
    }
    ++(*current_byte_index);
  }

  return true;
}
// Same as above, with 'reset' set to false.
bool AdvanceCurrentByteIndex(
    const string& keyword,
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index) {
  return AdvanceCurrentByteIndex(
      false, keyword, current_block_size, memblock, current_byte_index);
}
// Similar to above, but does not demand that 'keyword' is the *first*
// non-whitespace character.
bool AdvanceCurrentByteIndexToKeyword(
    const string& keyword,
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index) {
  const size_t word_length = keyword.length();
  if (word_length == 0) {
    return false;
  }
  size_t num_matches_so_far = 0;

  while ((int64_t) *current_byte_index < current_block_size) {
    const uint64_t orig_byte_index = *current_byte_index;
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == '\0') {
      return false;
    }
    if (orig_byte_index != *current_byte_index) {
      // Whitespace skipped over. Reset search.
      num_matches_so_far = 0;
    }
    const char target_char = keyword.at(num_matches_so_far);
    if (current_byte == target_char) {
      ++num_matches_so_far;
      if (num_matches_so_far == word_length) {
        ++(*current_byte_index);
        return true;
      }
      // Failed to match char at 'num_matches_so_far', but also check first char.
    } else if (num_matches_so_far > 0 && current_byte == keyword.at(0)) {
      num_matches_so_far = 1;
    } else {
      num_matches_so_far = 0;
    }
    ++(*current_byte_index);
  }

  return false;
}

// Parses the bit_index_ field of input, which has encoded (into an unsigned
// char) both the location of the bit_index, as well as a bool for whether
// this OutputWireLocation uses a bit index.
// Returns -1 if the first (leading) bit of bit_index_ is zero (indicating
// bit_index should be ignored).
int GetBitIndex(const OutputWireLocation& input) {
  if (!(input.bit_index_ & kBitIndexMask)) {
    return -1;
  }
  return input.bit_index_ & ~(kBitIndexMask);
}

// DEPRECATED: Not used.
/*
// Decodes 'depends_on_' vector to determine if the gate is a constant gate,
// i.e. it doesn't depend on any players, which happens iff input is all 0's.
bool IsConstantGate(const vector<char> & input) {
  if (input.empty()) {
    return false;
  }
  bool to_return = true;
  for (const char byte_i : input) {
    to_return &= (byte_i == 0);
  }
  return to_return;
}
*/

bool IsInputWiresSet(
    const GenericValue& left,
    const GenericValue& right,
    const CircuitOperation op) {
  const bool is_left_wire_set = left.type_ != DataType::UNKNOWN;
  const bool is_right_wire_set = right.type_ != DataType::UNKNOWN;
  if (IsSingleInputOperation(op)) {
    return (is_left_wire_set != is_right_wire_set);
  }
  return (is_left_wire_set && is_right_wire_set);
}

// NOTE: For single argument operators (NOT, IDENTITY), assumes it is the
// *left* wire that represents the wire to use.
bool EvaluateBooleanGate(
    const CircuitOperation op,
    const bool& left,
    const bool& right,
    bool* output) {
  switch (op) {
    case CircuitOperation::IDENTITY: {
      *output = left;
      return true;
    }
    case CircuitOperation::NOT: {
      *output = !left;
      return true;
    }
    case CircuitOperation::AND: {
      *output = left && right;
      return true;
    }
    case CircuitOperation::NAND: {
      *output = !(left && right);
      return true;
    }
    case CircuitOperation::OR: {
      *output = left || right;
      return true;
    }
    case CircuitOperation::NOR: {
      *output = !(left || right);
      return true;
    }
    case CircuitOperation::XOR: {
      *output = left != right;
      return true;
    }
    case CircuitOperation::EQ: {
      *output = left == right;
      return true;
    }
    case CircuitOperation::GT: {
      *output = left && (!right);
      return true;
    }
    case CircuitOperation::GTE: {
      *output = left || (!right);
      return true;
    }
    case CircuitOperation::LT: {
      *output = (!left) && right;
      return true;
    }
    case CircuitOperation::LTE: {
      *output = (!left) || right;
      return true;
    }
    default: {
      LOG_ERROR(
          "Unsupported gate operation in EvaluateBooleanGate(): " +
          GetOpString(op));
      return false;
    }
  }

  return true;
}

bool EvaluateArithmeticGate(
    const CircuitOperation op,
    const GenericValue& left,
    const GenericValue& right,
    GenericValue* output) {
  if (op == CircuitOperation::UNKNOWN) {
    LOG_ERROR("UNKNOWN gate operation.");
    return false;
  }
  const bool is_left_set = left.type_ != DataType::UNKNOWN;
  const bool is_right_set = right.type_ != DataType::UNKNOWN;
  // Split-out single-input operations from double-input operations.
  if (op == CircuitOperation::IDENTITY || op == CircuitOperation::NOT ||
      op == CircuitOperation::SELF || op == CircuitOperation::ABS ||
      op == CircuitOperation::FLIP_SIGN || op == CircuitOperation::SQRT ||
      op == CircuitOperation::FACTORIAL) {
    if (is_left_set == is_right_set) {
      LOG_ERROR("Gate has wrong number of input wires set.");
      return false;
    }
    if (is_left_set) {
      return ApplyOperator(op, left, output);
    } else {
      return ApplyOperator(op, right, output);
    }
  }

  // 2-term operator. Use MergeValuesViaOperator().
  if (!is_left_set || !is_right_set) {
    LOG_ERROR("Gate has wrong number of input wires set.");
    return false;
  }
  return MergeValuesViaOperator(op, left, right, output);
}

struct ReadCircuitFileCallbackParams {
  bool* is_done_;
  CircuitByGate* circuit_;

  ReadCircuitFileCallbackParams() {
    is_done_ = nullptr;
    circuit_ = nullptr;
  }
  ReadCircuitFileCallbackParams(bool* is_done, CircuitByGate* circuit) {
    is_done_ = is_done;
    circuit_ = circuit;
  }
};
unsigned ReadCircuitFileCallback(void* args) {
  ReadCircuitFileCallbackParams* params = (ReadCircuitFileCallbackParams*) args;
  if (params == nullptr || params->circuit_ == nullptr) {
    return 1;
  }
  if (!params->circuit_->ReadCircuitFile(params->is_done_)) {
    return 1;
  }

  return 0;
}

struct EvaluateCircuitCallbackParams {
  bool* is_done_;
  CircuitByGate* circuit_;

  EvaluateCircuitCallbackParams() {
    is_done_ = nullptr;
    circuit_ = nullptr;
  }
  EvaluateCircuitCallbackParams(bool* is_done, CircuitByGate* circuit) {
    is_done_ = is_done;
    circuit_ = circuit;
  }
};
unsigned EvaluateCircuitCallback(void* args) {
  EvaluateCircuitCallbackParams* params = (EvaluateCircuitCallbackParams*) args;
  if (params == nullptr || params->circuit_ == nullptr) {
    return 1;
  }
  if (!params->circuit_->EvaluateCircuit(params->is_done_)) {
    return 1;
  }

  return 0;
}

bool EvaluateGate(
    const CircuitOperation op,
    const GenericValue& left,
    const GenericValue& right,
    GenericValue* output) {
  // Sanity-check left and right values are set and compatible with op.
  if (op == CircuitOperation::UNKNOWN) {
    LOG_ERROR("Unknown gate type in EvaluateGate().");
    return false;
  }
  if (!IsInputWiresSet(left, right, op)) {
    LOG_ERROR("Unable to EvaluateGate.");
    return false;
  }

  // Handle single-argument Boolean operators separately.
  if (op == CircuitOperation::IDENTITY || op == CircuitOperation::NOT) {
    const bool is_left_set = left.type_ != DataType::UNKNOWN;
    if (op == CircuitOperation::IDENTITY) {
      *output = is_left_set ? left : right;
      return true;
    }
    // Operation is NOT.
    const bool value = is_left_set ?
        GetValue<bool>(*((const BoolDataType*) left.value_.get())) :
        GetValue<bool>(*((const BoolDataType*) right.value_.get()));
    output->type_ = DataType::BOOL;
    output->value_.reset(new BoolDataType((bool) !value));
    return true;
  }

  if (IsBooleanOperation(op)) {
    bool temp;
    if (!EvaluateBooleanGate(
            op,
            GetValue<bool>(*((const BoolDataType*) left.value_.get())),
            GetValue<bool>(*((const BoolDataType*) right.value_.get())),
            &temp)) {
      return false;
    }
    *output = GenericValue(temp);
    return true;
  } else {
    return EvaluateArithmeticGate(op, left, right, output);
  }
}

// Same as CircuitByGate::ParseFunctionDescription, but for non-member
// (static) use.
bool ParseFunctionDescription(
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index,
    vector<vector<string>>* function_var_names,
    vector<Formula>* function_description,
    vector<pair<OutputRecipient, DataType>>* output_designations) {
  vector<char> value_holder;
  vector<char> end_function_holder(
      kNumGatesKeyword.begin(), kNumGatesKeyword.end());
  size_t end_function_index = 0;
  while ((int64_t) *current_byte_index < current_block_size) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == end_function_holder[end_function_index]) {
      ++end_function_index;
      if (end_function_index == kNumGatesKeyword.size()) {
        const string function_str(value_holder.begin(), value_holder.end());
        bool expect_output_designation = true;
        *current_byte_index -= end_function_index;
        if (!ParseFunctionString(
                function_str,
                &expect_output_designation,
                function_var_names,
                function_description,
                output_designations)) {
          return false;
        }
        return true;
      }
    } else {
      // If end_function_index > 0, this means some bytes were not recorded in
      // value_holder, as we thought we were reading kNumGatesKeyword.
      // Copy those bytes over now.
      for (size_t i = 0; i < end_function_index; ++i) {
        value_holder.push_back(end_function_holder[i]);
      }
      end_function_index = 0;
      value_holder.push_back(current_byte);
    }
    ++(*current_byte_index);
  }

  LOG_ERROR("Reached end of parsing function description without "
            "finding next block(s) to read (e.g. Party input info).");
  return false;
}

// Same as CircuitByGate::ParseInputs, but for non-member (static) use.
// (Also, doesn't populate [left | right]_input_wire_to_party_index_
// like the non-static version does).
bool ParseInputs(
    const uint64_t& num_parties,
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index,
    vector<GlobalInputInfo>* inputs) {
  // Handle corner-case: First party(ies) don't have any inputs. Then
  // advance to next party.
  int current_party_index = 0;
  char temp_curr_byte =
      GetByte(current_block_size, memblock, current_byte_index);
  while (temp_curr_byte == ';') {
    ++(*current_byte_index);
    if (current_party_index == (int) num_parties - 1) {
      return true;
    }
    ++current_party_index;
    // Advance current_byte_index to the end of kPartyInputsKeyword.
    const string keyword =
        string(kPartyInputsKeyword) + "(" + Itoa(current_party_index) + "):";
    if (!AdvanceCurrentByteIndex(
            keyword, current_block_size, memblock, current_byte_index)) {
      LOG_ERROR("Expected Keyword '" + keyword + "' not found.");
      return false;
    }
    temp_curr_byte = GetByte(current_block_size, memblock, current_byte_index);
  }

  vector<char> value_holder;
  value_holder.reserve(kNumDigitsInGateIndexDataType);
  GenericValue constant_value;
  DataType type;
  GateIndexDataType gate_index;
  bool is_left = false;
  bool keep_going = true;
  bool expect_data_type = true;
  bool expect_left_right = false;
  bool expect_bit_index = false;
  while (keep_going && (int64_t) *current_byte_index < current_block_size) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == '(') {
      if (!expect_data_type) {
        LOG_ERROR(
            "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
            ": '" + current_byte + "'");
        return false;
      }
      ++(*current_byte_index);
      if (!CircuitByGate::ParseInputDataType(
              current_block_size, memblock, &type, current_byte_index)) {
        return false;
      }
      inputs->push_back(GlobalInputInfo(type));
      expect_data_type = false;
      expect_left_right = true;
    } else if (expect_data_type) {
      LOG_ERROR(
          "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
          ": '" + current_byte + "'");
      return false;
    } else if (current_byte == 'L' || current_byte == 'R') {
      if (!expect_left_right) {
        LOG_ERROR(
            "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
            ": '" + current_byte + "'");
        return false;
      }
      expect_left_right = false;
      if (current_byte == 'L') is_left = true;
      else is_left = false;
      ++(*current_byte_index);
    } else if (expect_left_right) {
      LOG_ERROR(
          "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
          ": '" + current_byte + "'");
      return false;
    } else if (current_byte == ':') {
      if (value_holder.empty()) {
        LOG_ERROR("Missing output gate index or bit index.");
        return false;
      }
      if (!Stoi(value_holder, &gate_index)) {
        LOG_ERROR(
            "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
            ": '" + current_byte + "'");
        return false;
      }
      value_holder.clear();
      value_holder.reserve(kNumDigitsInGateIndexDataType);
      expect_bit_index = true;
      ++(*current_byte_index);
    } else if (current_byte == ',' || current_byte == ';') {
      if (value_holder.size() > kNumDigitsInGateIndexDataType)
        LOG_FATAL("Bad circuit file.");
      GateIndexDataType index;
      if (!Stoi(value_holder, &index)) {
        LOG_ERROR(
            "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
            ": '" + current_byte + "'");
        return false;
      }
      value_holder.clear();
      value_holder.reserve(kNumDigitsInGateIndexDataType);
      OutputWireLocation target;
      if (expect_bit_index) {
        expect_bit_index = false;
        target = OutputWireLocation(
            InputWireLocation(is_left, gate_index), (unsigned char) index);
      } else {
        target = OutputWireLocation(InputWireLocation(is_left, index));
      }
      inputs->back().to_.insert(target);
      // Grab index of next (non-whitespace) byte.
      ++(*current_byte_index);
      char next_char = GetByte(current_block_size, memblock, current_byte_index);
      // Reset current_byte_index back to previous byte.
      --(*current_byte_index);
      if (current_byte == ',') {
        expect_left_right = true;
        ++(*current_byte_index);
      } else if (next_char == '(') {
        // Present party has another input. Process it.
        expect_data_type = true;
      } else {
        // No more inputs for the present party. Skip to info for next party,
        // or return if all Parties' inputs have been processed.
        char curr_byte = ';';
        while (curr_byte == ';') {
          ++(*current_byte_index);
          if (current_party_index == (int) num_parties - 1) {
            return true;
          }
          ++current_party_index;
          // Advance current_byte_index to the end of kPartyInputsKeyword.
          const string keyword = string(kPartyInputsKeyword) + "(" +
              Itoa(current_party_index) + "):";
          if (!AdvanceCurrentByteIndex(
                  keyword, current_block_size, memblock, current_byte_index)) {
            LOG_ERROR("Expected Keyword '" + keyword + "' not found.");
            return false;
          }
          curr_byte = GetByte(current_block_size, memblock, current_byte_index);
        }
        expect_data_type = true;
      }
    } else {
      value_holder.push_back(current_byte);
      ++(*current_byte_index);
    }
  }

  LOG_ERROR("Reached end of parsing Party inputs in circuit file, without "
            "finding next block(s) to read (e.g. Gate info).");
  return false;
}

// Same as CircuitByGate::ParseNumberOfGates, but for non-member (static) use.
bool ParseNumberOfGates(
    const int num_parties,
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index,
    GateIndexDataType* num_levels,
    GateIndexDataType* num_gates,
    GateIndexDataType* num_outputs,
    map<GateIndexDataType, DataType>* datatypes_of_arith_from_bool_gates,
    vector<GateIndexDataType>* num_non_local_boolean_gates_per_party_pairs,
    vector<GateIndexDataType>* num_gates_per_level,
    vector<GateIndexDataType>* num_non_local_arithmetic_gates_per_party_pairs) {
  // First, advance current_byte_index to the end of kNumGatesKeyword.
  if (!AdvanceCurrentByteIndex(
          kNumGatesKeyword, current_block_size, memblock, current_byte_index)) {
    LOG_ERROR("Expected Keyword '" + kNumGatesKeyword + "' not found.");
    return false;
  }

  // Reserve space for num_[arithmetic | boolean]_gates_per_party_pairs.
  if (num_parties > 0) {
    if (num_non_local_boolean_gates_per_party_pairs != nullptr) {
      num_non_local_boolean_gates_per_party_pairs->reserve(
          (num_parties * (num_parties - 1)) / 2);
    }
    if (num_non_local_arithmetic_gates_per_party_pairs != nullptr) {
      num_non_local_arithmetic_gates_per_party_pairs->reserve(
          (num_parties * (num_parties - 1)) / 2);
    }
  }

  // Now read through relevant parts of the metadata.
  vector<char> value_holder;
  value_holder.reserve(kNumDigitsIn64BitInt);
  bool parsed_num_gates = false;
  bool parsed_num_boolean_gates = false;
  bool parsed_num_arithmetic_gates = false;
  bool parsed_num_gates_per_level = false;
  bool parsed_num_outputs = false;
  bool parsed_arith_from_bool_types = false;
  bool expect_data_type = false;
  GateIndexDataType arith_from_bool_index;
  while ((int64_t) *current_byte_index < current_block_size) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == ';' || current_byte == ',') {
      // Comma-separated lists expected for:
      //   - Num non-local boolean/arithmetic gates
      //   - Arithmetic Gates with Inputs from Boolean Gates
      // Make sure we're currently processing one of those, if ',' is encountered.
      if (current_byte == ',' &&
          (!parsed_num_gates ||
           (parsed_num_arithmetic_gates && !parsed_num_outputs))) {
        LOG_ERROR("Bad format of circuit file.");
        return false;
      }
      GateIndexDataType value;
      if (!value_holder.empty() && !Stoi(value_holder, &value)) {
        LOG_ERROR("Bad format of circuit file.");
        return false;
      }
      if (!parsed_num_gates) {
        *num_gates = value;
        value_holder.clear();
        value_holder.reserve(kNumDigitsIn64BitInt);
        parsed_num_gates = true;
        ++(*current_byte_index);
        if (!AdvanceCurrentByteIndex(
                kNumNonLocalBoolKeyword,
                current_block_size,
                memblock,
                current_byte_index) &&
            !AdvanceCurrentByteIndex(
                kNumNonLocalBoolKeywordOld,
                current_block_size,
                memblock,
                current_byte_index)) {
          LOG_ERROR(
              "Expected Keyword '" + kNumNonLocalBoolKeyword + "' not found.");
          return false;
        }
      } else if (!parsed_num_boolean_gates) {
        if (num_non_local_boolean_gates_per_party_pairs != nullptr) {
          num_non_local_boolean_gates_per_party_pairs->push_back(value);
        }
        value_holder.clear();
        value_holder.reserve(kNumDigitsIn64BitInt);
        if (current_byte == ';') {
          ++(*current_byte_index);
          // Sanity-check that the expected number of partner pairs were found.
          if (num_non_local_boolean_gates_per_party_pairs != nullptr &&
              (int) num_non_local_boolean_gates_per_party_pairs->size() !=
                  (num_parties * (num_parties - 1)) / 2) {
            LOG_ERROR(
                "Bad circuit file: only " +
                Itoa(num_non_local_boolean_gates_per_party_pairs->size()) +
                " pairs of partners found (" +
                Itoa((num_parties * (num_parties - 1)) / 2) +
                " pairs of partners expected, for " + Itoa(num_parties) +
                " total parties).");
            return false;
          }
          parsed_num_boolean_gates = true;
          if (!AdvanceCurrentByteIndex(
                  kNumGatesPerLevelKeyword,
                  current_block_size,
                  memblock,
                  current_byte_index)) {
            // Perhaps this is an old circuit file that hasn't been updated
            // yet with the num GMW gates per level; keep parsing.
            parsed_num_gates_per_level = true;
            if (!AdvanceCurrentByteIndex(
                    kNumNonLocalArithKeyword,
                    current_block_size,
                    memblock,
                    current_byte_index) &&
                !AdvanceCurrentByteIndex(
                    kNumNonLocalArithKeywordOld,
                    current_block_size,
                    memblock,
                    current_byte_index)) {
              LOG_ERROR(
                  "Expected Keyword '" + kNumNonLocalArithKeyword +
                  "' not found.");
              return false;
            }
          }
        }
      } else if (!parsed_num_gates_per_level) {
        if (num_gates_per_level != nullptr) {
          num_gates_per_level->push_back(value);
        }
        value_holder.clear();
        value_holder.reserve(kNumDigitsIn64BitInt);
        if (current_byte == ';') {
          if (num_levels != nullptr && num_gates_per_level != nullptr) {
            *num_levels = (GateIndexDataType) num_gates_per_level->size();
          }
          ++(*current_byte_index);
          parsed_num_gates_per_level = true;
          if (!AdvanceCurrentByteIndex(
                  kNumNonLocalArithKeyword,
                  current_block_size,
                  memblock,
                  current_byte_index) &&
              !AdvanceCurrentByteIndex(
                  kNumNonLocalArithKeywordOld,
                  current_block_size,
                  memblock,
                  current_byte_index)) {
            LOG_ERROR(
                "Expected Keyword '" + kNumNonLocalArithKeyword +
                "' not found.");
            return false;
          }
        }
      } else if (!parsed_num_arithmetic_gates) {
        if (num_non_local_arithmetic_gates_per_party_pairs != nullptr) {
          num_non_local_arithmetic_gates_per_party_pairs->push_back(value);
        }
        value_holder.clear();
        value_holder.reserve(kNumDigitsIn64BitInt);
        if (current_byte == ';') {
          ++(*current_byte_index);
          // Sanity-check that the expected number of partner pairs were found.
          if (num_non_local_arithmetic_gates_per_party_pairs != nullptr &&
              (int) num_non_local_arithmetic_gates_per_party_pairs->size() !=
                  (num_parties * (num_parties - 1)) / 2) {
            LOG_ERROR(
                "Bad circuit file: only " +
                Itoa(num_non_local_arithmetic_gates_per_party_pairs->size()) +
                " pairs of partners found (" +
                Itoa((num_parties * (num_parties - 1)) / 2) +
                " pairs of partners expected, for " + Itoa(num_parties) +
                " total parties).");
            return false;
          }
          parsed_num_arithmetic_gates = true;
          if (!AdvanceCurrentByteIndex(
                  kNumOutputsKeyword,
                  current_block_size,
                  memblock,
                  current_byte_index)) {
            LOG_ERROR(
                "Expected Keyword '" + kNumOutputsKeyword + "' not found.");
            return false;
          }
        }
      } else if (!parsed_num_outputs) {
        *num_outputs = value;
        value_holder.clear();
        value_holder.reserve(kNumDigitsInGateIndexDataType);
        parsed_num_outputs = true;
        ++(*current_byte_index);
        if (!AdvanceCurrentByteIndex(
                kArithGatesFromBoolGatesKeyword,
                current_block_size,
                memblock,
                current_byte_index)) {
          LOG_ERROR(
              "Expected Keyword '" + kArithGatesFromBoolGatesKeyword +
              "' not found.");
          return false;
        }
      } else if (!parsed_arith_from_bool_types) {
        if (!expect_data_type && !value_holder.empty()) {
          LOG_ERROR("Bad format of circuit file.");
          return false;
        }
        if (!value_holder.empty() &&
            datatypes_of_arith_from_bool_gates != nullptr) {
          datatypes_of_arith_from_bool_gates->insert(
              make_pair(arith_from_bool_index, static_cast<DataType>(value)));
        }
        if (current_byte == ',') {
          expect_data_type = false;
          value_holder.clear();
          value_holder.reserve(kNumDigitsInGateIndexDataType);
        } else {
          parsed_arith_from_bool_types = true;
          ++(*current_byte_index);
          break;
        }
      }
    } else if (current_byte == ':') {
      if (!parsed_num_outputs || expect_data_type ||
          !Stoi(value_holder, &arith_from_bool_index)) {
        LOG_ERROR("Bad format of circuit file.");
        return false;
      }
      expect_data_type = true;
      value_holder.clear();
      value_holder.reserve(kNumDigitsInGateIndexDataType);
    } else if (
        current_byte == '\0' &&
        (int64_t) *current_byte_index == current_block_size) {
      --(*current_byte_index);
    } else {
      value_holder.push_back(current_byte);
    }
    ++(*current_byte_index);
  }

  return true;
}

// Same as CircuitByGate::ParseGates, but for non-member (static) use.
bool ParseGates(
    const int num_parties,
    const GateIndexDataType& num_gates,
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index,
    ReadWriteQueue<Gate>* gates) {
  // First, advance current_byte_index to the end of kGateInfoKeyword.
  if (!AdvanceCurrentByteIndexToKeyword(
          kGateInfoKeyword, current_block_size, memblock, current_byte_index)) {
    LOG_ERROR("Expected Keyword '" + kGateInfoKeyword + "' not found.");
    return false;
  }

  // Reserve space for all gates.
  gates->reserve(num_gates);

  // Compute size of depends_on_ (= Num Parties / 8).
  const int depends_on_size =
      num_parties / CHAR_BIT + ((num_parties % CHAR_BIT == 0) ? 0 : 1);
  const unsigned char depends_on_all_byte = -1;  // 11111111
  const unsigned char depends_on_all_last_byte =
      (unsigned char) ((num_parties % CHAR_BIT == 0) ? depends_on_all_byte : (depends_on_all_byte ^ (depends_on_all_byte >> (num_parties % CHAR_BIT))));

  // Parse Gate info:
  //   - Gate Op (1 byte)
  //   - Depends On (N / 8 bytes)
  //   - Left Output Wire(s) (comma-separated list)
  //   - Right Output Wire(s) (comma-separated list)
  //   - Global Output Wire(s) (comma-separated list)
  Gate current_gate;
  OutputWireLocation current_output_wire;
  vector<char> value_holder;
  value_holder.reserve(kNumDigitsInGateIndexDataType);
  bool expect_op = true;
  int expect_depends_on = -1;
  bool depends_on_all_parties = true;
  bool expect_left_outputs = false;
  bool expect_right_outputs = false;
  bool expect_global_outputs = false;
  bool expect_bit_index = false;
  while ((int64_t) *current_byte_index < current_block_size) {
    // Read current byte.
    // NOTE: We ignore (skip-over) whitespace, UNLESS we are reading the
    // depends_on_ field, in which case all 256 characters are valid, i.e.
    // whitespace should be interpretted as the corresponding numeric value.
    const char current_byte = expect_depends_on >= 0 ?
        memblock[*current_byte_index] :
        GetByte(current_block_size, memblock, current_byte_index);
    if (expect_op) {
      if (current_byte == ';') {
        if (value_holder.empty()) {
          LOG_ERROR("Missing Gate op.");
          return false;
        }
        unsigned char op_index;
        if (!Stoi(value_holder, &op_index)) {
          LOG_ERROR(
              "Unable to parse Op index: '" +
              string(value_holder.begin(), value_holder.end()) + "'");
          return false;
        }
        current_gate.op_ = static_cast<CircuitOperation>(op_index);
        value_holder.clear();
        value_holder.reserve(kNumDigitsInGateIndexDataType);
        expect_op = false;
        expect_depends_on = 0;
        depends_on_all_parties = true;
      } else if (current_byte == '\0') {
        if (!value_holder.empty() ||
            (int64_t) *current_byte_index < current_block_size) {
          LOG_ERROR("Bad format of circuit file.");
          return false;
        }
        return true;
      } else {
        value_holder.push_back(current_byte);
      }
      ++(*current_byte_index);
    } else if (expect_depends_on >= 0) {
      if (expect_depends_on == 0) {
        current_gate.depends_on_.resize(depends_on_size, 0);
        current_gate.depends_on_[0] = current_byte;
        depends_on_all_parties &= ((unsigned char) current_byte) ==
            (depends_on_size == 1 ? depends_on_all_last_byte :
                                    depends_on_all_byte);
      } else if (expect_depends_on == depends_on_size) {
        if (current_byte != ';') {
          LOG_ERROR("Bad depends_on_ at Gate " + Itoa(gates->size()));
          return false;
        }
        if (depends_on_all_parties) current_gate.depends_on_.clear();
        expect_depends_on = -2;
        expect_left_outputs = true;
      } else {
        current_gate.depends_on_[expect_depends_on] = current_byte;
        depends_on_all_parties &= ((unsigned char) current_byte) ==
            ((depends_on_size == expect_depends_on + 1) ?
                 depends_on_all_last_byte :
                 depends_on_all_byte);
      }
      ++expect_depends_on;
      ++(*current_byte_index);
    } else if (expect_left_outputs || expect_right_outputs) {
      if (current_byte == ':') {
        if (value_holder.empty()) {
          LOG_ERROR("Missing output gate index or bit index.");
          return false;
        }
        GateIndexDataType gate_index;
        if (!Stoi(value_holder, &gate_index)) {
          LOG_ERROR(
              "Unable to parse gate index: '" +
              string(value_holder.begin(), value_holder.end()) + "'");
          return false;
        }
        current_output_wire.loc_.index_ = gate_index;
        value_holder.clear();
        value_holder.reserve(kNumDigitsInGateIndexDataType);
        expect_bit_index = true;
      } else if (current_byte == ',' || current_byte == ';') {
        if (value_holder.empty() && (current_byte == ',' || expect_bit_index)) {
          LOG_ERROR("Missing Left Output gate info");
          return false;
        }
        if (!value_holder.empty()) {
          GateIndexDataType index;
          if (!Stoi(value_holder, &index)) {
            LOG_ERROR(
                "Unable to parse bit index: '" +
                string(value_holder.begin(), value_holder.end()) + "'");
            return false;
          }
          if (expect_bit_index) {
            if (index >= kBitIndexMask) {
              LOG_ERROR(
                  "Unable to parse bit index: '" +
                  string(value_holder.begin(), value_holder.end()) + "'");
              return false;
            }
            current_output_wire.bit_index_ =
                (unsigned char) (index + kBitIndexMask);
          } else {
            current_output_wire.loc_.index_ = index;
          }
          current_output_wire.loc_.is_left_ = expect_left_outputs;
          current_gate.output_wires_.push_back(current_output_wire);
          // current_output_wire will get used for the *next* gate also; the
          // loc_ field will necessarily be overwritten (so no need to clear
          // it here), but the bit_index_ field may not be; clear it now.
          current_output_wire.bit_index_ = 0;
          value_holder.clear();
          value_holder.reserve(kNumDigitsInGateIndexDataType);
        }
        expect_bit_index = false;

        // Handle case this is the end of the left/right output gate info for this gate.
        if (current_byte == ';') {
          expect_global_outputs = expect_right_outputs ? true : false;
          expect_right_outputs = expect_left_outputs ? true : false;
          expect_left_outputs = false;
        }
      } else {
        value_holder.push_back(current_byte);
      }
      ++(*current_byte_index);
    } else if (expect_global_outputs) {
      if (current_byte == ':') {
        if (value_holder.empty()) {
          LOG_ERROR("Missing global output gate index or bit index.");
          return false;
        }
        GateIndexDataType gate_index;
        if (!Stoi(value_holder, &gate_index)) {
          LOG_ERROR(
              "Unable to parse bit index: '" +
              string(value_holder.begin(), value_holder.end()) + "'");
          return false;
        }
        current_output_wire.loc_.index_ = gate_index + num_gates;
        value_holder.clear();
        value_holder.reserve(kNumDigitsInGateIndexDataType);
        expect_bit_index = true;
      } else if (current_byte == ',' || current_byte == '|') {
        // Parse the (current) global output gate
        if (value_holder.empty() && (current_byte == ',' || expect_bit_index)) {
          LOG_ERROR("Missing global output gate index or bit index.");
          return false;
        } else if (!value_holder.empty()) {
          GateIndexDataType index;
          if (!Stoi(value_holder, &index)) {
            LOG_ERROR(
                "Unable to parse bit index: '" +
                string(value_holder.begin(), value_holder.end()) + "'");
            return false;
          }
          if (expect_bit_index) {
            if (index >= kBitIndexMask) {
              LOG_ERROR("Unable to parse bit index: " + Itoa(index));
              return false;
            }
            current_output_wire.bit_index_ =
                (unsigned char) (index + kBitIndexMask);
          } else {
            current_output_wire.loc_.index_ = index + num_gates;
          }
          // Convention is to mark global outputs as the 'Left' wire.
          current_output_wire.loc_.is_left_ = true;
          current_gate.output_wires_.push_back(current_output_wire);
          // current_output_wire will get used for the *next* gate also; the
          // loc_ field will necessarily be overwritten (so no need to clear
          // it here), but the bit_index_ field may not be; clear it now.
          current_output_wire.bit_index_ = 0;
          value_holder.clear();
          value_holder.reserve(kNumDigitsInGateIndexDataType);
        }
        expect_bit_index = false;

        // Handle case this is the end of the gate info for this gate.
        if (current_byte == '|') {
          expect_global_outputs = false;
          expect_op = true;
          gates->Push(current_gate);
          // 'current_gate' will be reused for the next gate. Clear the fields
          // that won't be reset.
          current_gate.output_wires_.clear();
          ++(*current_byte_index);
          // Reset current_byte_index back to previous byte.
          --(*current_byte_index);
        }
      } else {
        value_holder.push_back(current_byte);
      }
      ++(*current_byte_index);
    } else {
      LOG_FATAL("Should never reach here.");
    }
  }

  return true;
}

}  // namespace

// Same as CircuitByGate::ReadCircuitFile, but for non-member (static) use.
bool ReadCircuitFile(
    const string& filename,
    vector<vector<string>>* function_var_names,
    vector<Formula>* function_description,
    vector<pair<OutputRecipient, DataType>>* output_designations,
    GateIndexDataType* num_levels,
    GateIndexDataType* num_gates,
    GateIndexDataType* num_outputs,
    map<GateIndexDataType, DataType>* datatypes_of_arith_from_bool_gates,
    vector<GateIndexDataType>* num_non_local_boolean_gates_per_party_pairs,
    vector<GateIndexDataType>* num_gates_per_level,
    vector<GateIndexDataType>* num_non_local_arithmetic_gates_per_party_pairs,
    vector<GlobalInputInfo>* inputs,
    ReadWriteQueue<Gate>* gates) {
  ifstream file(filename, ios::in | ios::binary | ios::ate);
  if (!file.is_open()) {
    LOG_ERROR("Unable to open circuit file: '" + filename + "'");
    return false;
  }
  const int64_t num_circuit_file_bytes = file.tellg();
  file.seekg(0, ios::beg);

  // Allocate memory to read in (a block of) the circuit file.
  const int64_t block_size = min(kMaxReadFileBlockBytes, num_circuit_file_bytes);

  char* memblock = new char[block_size];
  if (!memblock) {
    LOG_ERROR(
        "Unable to allocate enough memory (" + Itoa(block_size) +
        " bytes) for the circuit file");
    file.close();
    return false;
  }

  // Loop through circuit file, extracting info.
  bool is_circuit_file_function_read = false;
  bool is_circuit_file_num_gates_read = false;
  bool is_circuit_file_inputs_read = false;
  int64_t circuit_reader_thread_current_byte = 0;
  vector<char> remainder_bytes;
  char* temp;
  while (circuit_reader_thread_current_byte < num_circuit_file_bytes) {
    // Resize memblock, if this is the final block and there are fewer
    // than block_size bytes left.
    const int64_t remaining_bytes =
        num_circuit_file_bytes - circuit_reader_thread_current_byte;
    int64_t current_block_size = min(remaining_bytes, block_size);
    if (current_block_size < block_size) {
      // See Discussion in corresponding place of the member function
      // StandardCircuitByGate::ReadCircuitFile() for why temp is used.
      temp = (char*) realloc(memblock, current_block_size);
      memblock = temp;
    }

    // Store 'remainder_bytes' into the first bytes of memblock.
    for (size_t i = 0; i < remainder_bytes.size(); ++i) {
      memblock[i] = remainder_bytes[i];
    }

    // Read block.
    file.read(memblock + remainder_bytes.size(), current_block_size);
    int64_t last_circuit_file_block_break_byte = 0;
    uint64_t current_byte_index = 0;
    while ((int64_t) current_byte_index < current_block_size) {
      // Read function description, if haven't already.
      if (!is_circuit_file_function_read) {
        if (!ParseFunctionDescription(
                current_block_size,
                memblock,
                &current_byte_index,
                function_var_names,
                function_description,
                output_designations)) {
          delete[] memblock;
          return false;
        }
        is_circuit_file_function_read = true;
        // Read Number of gates, if haven't already.
      } else if (!is_circuit_file_num_gates_read) {
        if (!ParseNumberOfGates(
                (int) function_var_names->size(),
                current_block_size,
                memblock,
                &current_byte_index,
                num_levels,
                num_gates,
                num_outputs,
                datatypes_of_arith_from_bool_gates,
                num_non_local_boolean_gates_per_party_pairs,
                num_gates_per_level,
                num_non_local_arithmetic_gates_per_party_pairs)) {
          delete[] memblock;
          return false;
        }
        is_circuit_file_num_gates_read = true;
        // Read Global inputs (of each party, and constants), if haven't already.
      } else if (!is_circuit_file_inputs_read && inputs != nullptr) {
        if (!ParseInputs(
                function_var_names->size(),
                current_block_size,
                memblock,
                &current_byte_index,
                inputs)) {
          delete[] memblock;
          return false;
        }
        is_circuit_file_inputs_read = true;
        // All metadata has been read; abort if appropriate.
      } else if (gates == nullptr) {
        delete[] memblock;
        return true;
        // Read Gate info.
      } else {
        if (!ParseGates(
                (int) function_var_names->size(),
                *num_gates,
                current_block_size,
                memblock,
                &current_byte_index,
                gates)) {
          delete[] memblock;
          return false;
        }
      }
    }

    // Before proceeding to next block, check if current block ended at a
    // good spot to break (likely it didn't). If not, (temporarily) store
    // the bytes between the last good break point and the current byte,
    // and update other variables that will aide processing the next block.
    if (last_circuit_file_block_break_byte != current_block_size) {
      circuit_reader_thread_current_byte += last_circuit_file_block_break_byte;
      // Since file.read() will continue from the last byte read, we need
      // to store the bytes between last_circuit_file_block_break_byte and
      // the end of memblock, as these bytes won't be re-read (even though
      // circuit_reader_thread_current_byte points to the proper place).
      const size_t num_remainder_bytes =
          current_block_size - last_circuit_file_block_break_byte;
      remainder_bytes.resize(num_remainder_bytes);
      for (size_t i = 0; i < num_remainder_bytes; ++i) {
        remainder_bytes[i] = memblock[circuit_reader_thread_current_byte + i];
      }
    } else {
      circuit_reader_thread_current_byte += current_block_size;
    }
  }

  delete[] memblock;
  return true;
}

bool GateDependsOn(const int party_index, const vector<char>& depends_on) {
  if (depends_on.empty()) {
    return true;
  }
  const int byte_index = party_index / CHAR_BIT;
  if (byte_index >= (int) depends_on.size()) LOG_FATAL("Bad party index");
  const int bit_index = party_index % CHAR_BIT;
  return depends_on[byte_index] & (1 << (CHAR_BIT - 1 - bit_index));
}

int GetLowestDependentPartyIndex(const vector<char>& depends_on) {
  if (depends_on.empty()) {
    return 0;
  }
  for (int byte = 0; byte < (int) depends_on.size(); ++byte) {
    const char byte_i = depends_on[byte];
    for (int bit = 0; bit < CHAR_BIT; ++bit) {
      if (byte_i & (1 << (CHAR_BIT - 1 - bit))) {
        return (byte * CHAR_BIT) + bit;
      }
    }
  }
  return -1;
}

int GetHighestDependentPartyIndex(const vector<char>& depends_on) {
  if (depends_on.empty()) {
    return -1;
  }
  for (int byte = (int) depends_on.size() - 1; byte >= 0; --byte) {
    const char byte_i = depends_on[byte];
    for (int bit = CHAR_BIT - 1; bit >= 0; --bit) {
      if (byte_i & (1 << (CHAR_BIT - 1 - bit))) {
        return (byte * CHAR_BIT) + bit;
      }
    }
  }
  return -1;
}

int NumDependentParties(const vector<char>& depends_on) {
  int to_return = 0;
  for (int byte = 0; byte < (int) depends_on.size(); ++byte) {
    const char byte_i = depends_on[byte];
    for (int bit = 0; bit < CHAR_BIT; ++bit) {
      if (byte_i & (1 << (CHAR_BIT - 1 - bit))) {
        ++to_return;
      }
    }
  }
  return to_return;
}

bool ReadCircuitByGateMetadata(
    const string& filename,
    vector<Formula>* function,
    vector<vector<pair<string, DataType>>>* input_var_types,
    vector<pair<OutputRecipient, DataType>>* output_types) {
  // Open circuit file.
  ifstream file(filename, ios::in | ios::binary | ios::ate);
  if (!file.is_open()) {
    LOG_ERROR("Unable to open circuit file: '" + filename + "'");
    return false;
  }

  // Grab total circuit size.
  const int64_t num_circuit_file_bytes = file.tellg();
  file.seekg(0, ios::beg);

  // Allocate memory to read in (a block of) the circuit file.
  const int64_t block_size = min(kMaxReadFileBlockBytes, num_circuit_file_bytes);
  char* memblock = new char[block_size];
  if (!memblock) {
    LOG_ERROR(
        "Unable to allocate enough memory (" + Itoa(block_size) +
        " bytes) for the circuit file");
    file.close();
    return false;
  }

  // Read block.
  file.read(memblock, block_size);
  uint64_t current_byte_index = 0;
  // Read function description.
  vector<vector<string>> function_var_names;
  if (!ParseFunctionDescription(
          block_size,
          memblock,
          &current_byte_index,
          &function_var_names,
          function,
          output_types)) {
    delete[] memblock;
    return false;
  }
  // Skip over next block of metadata (Num Gates, etc.).
  if (!AdvanceCurrentByteIndexToKeyword(
          kPartyInputsKeyword, block_size, memblock, &current_byte_index)) {
    LOG_ERROR("Expected Keyword '" + kPartyInputsKeyword + "' not found.");
    return false;
  }
  // Next couple of bytes should be: ' (0):'. Verify, and skip over them.
  char temp = memblock[current_byte_index];
  bool failure = false;
  if (!isspace(temp)) failure = true;
  ++current_byte_index;
  temp = memblock[current_byte_index];
  if (temp != '(') failure = true;
  ++current_byte_index;
  temp = memblock[current_byte_index];
  if (temp != '0') failure = true;
  ++current_byte_index;
  temp = memblock[current_byte_index];
  if (temp != ')') failure = true;
  ++current_byte_index;
  temp = memblock[current_byte_index];
  if (temp != ':') failure = true;
  if (failure) {
    LOG_ERROR("Expected Keyword '" + kPartyInputsKeyword + "(0):' not found.");
    return false;
  }
  ++current_byte_index;
  // Read Global inputs (of each party, and constants).
  vector<GlobalInputInfo> global_input_info;
  if (input_var_types != nullptr &&
      !ParseInputs(
          function_var_names.size(),
          block_size,
          memblock,
          &current_byte_index,
          &global_input_info)) {
    delete[] memblock;
    return false;
  }
  delete[] memblock;

  // Combine varibale name info. with variable DataType info.
  if (input_var_types != nullptr) {
    input_var_types->resize(function_var_names.size());
    uint64_t global_input_index = 0;
    for (size_t i = 0; i < function_var_names.size(); ++i) {
      (*input_var_types)[i].resize(function_var_names[i].size());
      for (size_t j = 0; j < function_var_names[i].size(); ++j) {
        pair<string, DataType>& target = (*input_var_types)[i][j];
        target.first = function_var_names[i][j];
        if (global_input_index >= global_input_info.size()) {
          LOG_ERROR("Insufficient DataType info for variables");
          return false;
        }
        target.second = global_input_info[global_input_index].type_;
        ++global_input_index;
      }
    }
  }

  return true;
}

void CircuitByGate::SetThreadStatus(
    const CircuitByGateTask task, const ThreadStatus status) {
  InsertOrReplace(thread_status_, task, status);
}

ThreadStatus CircuitByGate::GetThreadStatus(const CircuitByGateTask task) {
  ThreadStatus* to_return = FindOrNull(task, thread_status_);
  if (to_return == nullptr) {
    return ThreadStatus::UNKNOWN;
  }
  return *to_return;
}

bool CircuitByGate::IsProgressBeingMade(
    const SleepReason reason,
    const ThreadStatus circuit_reading_status,
    const ThreadStatus parse_inputs_status,
    const ThreadStatus eval_gates_status,
    int* num_sleeps,
    int* num_sleeps_two) {
  switch (reason) {
    case SleepReason::READ_GATE_INFO_FOR_EVAL: {
      if (eval_gates_status == ThreadStatus::UNSTARTED ||
          eval_gates_status == ThreadStatus::ACTIVE ||
          parse_inputs_status == ThreadStatus::UNSTARTED ||
          parse_inputs_status == ThreadStatus::ACTIVE) {
        return true;
      } else if (
          eval_gates_status != ThreadStatus::ASLEEP &&
          eval_gates_status != ThreadStatus::PAUSED) {
        return false;
      }
      // The Evaluate Gates thread, which we require to be making progress in
      // order for Circuit Reading thread to stop sleeping, is asleep.
      // There are funny timing circumstances where this can happen.
      // Check for such a funny timing, and if that is possible, give it one
      // more chance; otherwise, return false.
      if (num_sleeps == nullptr || num_sleeps_two == nullptr) {
        return false;
      }
      if (*num_sleeps < 0) {
        *num_sleeps = evaluate_gates_sleep_.GetNumFailures();
        return true;
      }
      if (*num_sleeps_two < 0) {
        *num_sleeps_two = read_inputs_sleep_.GetNumFailures();
        return true;
      }
      return (
          evaluate_gates_sleep_.GetNumFailures() <= *num_sleeps ||
          read_inputs_sleep_.GetNumFailures() <= *num_sleeps_two);
    }
    case SleepReason::PARSE_INPUTS_FOR_INPUT_INFO: {
      return (
          circuit_reading_status == ThreadStatus::ACTIVE ||
          circuit_reading_status == ThreadStatus::UNSTARTED);
    }
    case SleepReason::EVAL_FOR_INPUT_INFO: {
      if (circuit_reading_status == ThreadStatus::UNKNOWN) {
        // Passing in 'UNKNOWN' is a hack for indicating that the current
        // function was called when 'parent' (from calling code) is non-null;
        // this in turn means that EvaluateCircuit() is being called
        // as a sub-routine for GMW gate evaluation, where necessarily
        // all inputs should have been parsed before EvaluateCircuit()
        // is called; so this is always an error.
        // NOTE: This check is unnecessary, since we would have returned false
        // below anyway; but we keep it here for code readibility.
        return false;
      }
      return (
          circuit_reading_status == ThreadStatus::UNSTARTED ||
          circuit_reading_status == ThreadStatus::ACTIVE);
    }
    case SleepReason::EVAL_FOR_GATE_INFO: {
      if (circuit_reading_status == ThreadStatus::ACTIVE ||
          circuit_reading_status == ThreadStatus::UNSTARTED) {
        return true;
      } else if (circuit_reading_status != ThreadStatus::ASLEEP) {
        return false;
      }
      // The Evaluate Gates thread is hanging waiting for gates_ to be non-empty,
      // namely it needs the Circuit Reading thread to read more of the Gate block.
      // There are funny timing circumstances where this can happen.
      // Check for such a funny timing, and if that is possible, give it one
      // more chance; otherwise, return false.
      if (num_sleeps == nullptr) {
        return false;
      }
      if (*num_sleeps < 0) {
        *num_sleeps = read_gates_sleep_.GetNumFailures();
        return true;
      }
      return read_gates_sleep_.GetNumFailures() <= *num_sleeps;
    }
    case SleepReason::EVAL_FOR_INPUT_PARSING: {
      if (parse_inputs_status == ThreadStatus::UNSTARTED ||
          parse_inputs_status == ThreadStatus::ACTIVE) {
        return true;
      } else if (
          parse_inputs_status != ThreadStatus::ASLEEP &&
          parse_inputs_status != ThreadStatus::PAUSED) {
        return false;
      }

      // The Parse Inputs thread, which we require to be making progress in
      // order for Eval Gates thread to stop sleeping, is asleep.
      // There are funny timing circumstances where this can happen.
      // Check for such a funny timing, and if that is possible, give it one
      // more chance; otherwise, return false.
      if (num_sleeps == nullptr) {
        return false;
      }
      if (*num_sleeps < 0) {
        *num_sleeps = read_inputs_sleep_.GetNumFailures();
        return true;
      }
      return read_inputs_sleep_.GetNumFailures() <= *num_sleeps;
    }
    default: {
      LOG_FATAL("Unsupported reason: " + Itoa(static_cast<int>(reason)));
      return false;
    }
  }

  // Code should never reach here.
  return false;
}

bool CircuitByGate::IsProgressBeingMade(
    const SleepReason reason,
    const ThreadStatus circuit_reading_status,
    const ThreadStatus parse_inputs_status,
    const ThreadStatus eval_gates_status,
    int* num_sleeps) {
  return IsProgressBeingMade(
      reason,
      circuit_reading_status,
      parse_inputs_status,
      eval_gates_status,
      num_sleeps,
      nullptr);
}

bool CircuitByGate::ParseNumberOfGates(
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index) {
  // First, advance current_byte_index to the end of kNumGatesKeyword.
  if (!AdvanceCurrentByteIndex(
          kNumGatesKeyword, current_block_size, memblock, current_byte_index)) {
    LOG_ERROR("Expected Keyword '" + kNumGatesKeyword + "' not found.");
    return false;
  }

  // Reserve space for num_[arithmetic | boolean]_gates_per_party_pairs_.
  const int num_parties = (int) function_var_names_.size();
  if (num_parties > 0) {
    num_non_local_boolean_gates_per_party_pairs_.reserve(
        (num_parties * (num_parties - 1)) / 2);
    num_non_local_arithmetic_gates_per_party_pairs_.reserve(
        (num_parties * (num_parties - 1)) / 2);
  }

  // Now read through relevant parts of the metadata.
  vector<char> value_holder;
  value_holder.reserve(kNumDigitsIn64BitInt);
  bool parsed_num_gates = false;
  bool parsed_num_boolean_gates = false;
  bool parsed_num_gates_per_level = false;
  bool parsed_num_arithmetic_gates = false;
  bool parsed_num_outputs = false;
  bool parsed_arith_from_bool_types = false;
  bool expect_data_type = false;
  GateIndexDataType arith_from_bool_index;
  while ((int64_t) *current_byte_index < current_block_size) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == ';' || current_byte == ',') {
      // Comma-separated lists expected for:
      //   - Num non-local boolean/arithmetic gates
      //   - Arithmetic Gates with Inputs from Boolean Gates
      // Make sure we're currently processing one of those, if ',' is encountered.
      if (current_byte == ',' &&
          (!parsed_num_gates ||
           (parsed_num_arithmetic_gates && !parsed_num_outputs))) {
        LOG_ERROR("Bad format of circuit file.");
        return false;
      }
      GateIndexDataType value;
      if (!value_holder.empty() && !Stoi(value_holder, &value)) {
        LOG_ERROR("Bad format of circuit file.");
        return false;
      }
      if (!parsed_num_gates) {
        num_gates_ = value;
        value_holder.clear();
        value_holder.reserve(kNumDigitsIn64BitInt);
        parsed_num_gates = true;
        ++(*current_byte_index);
        if (!AdvanceCurrentByteIndex(
                kNumNonLocalBoolKeyword,
                current_block_size,
                memblock,
                current_byte_index) &&
            !AdvanceCurrentByteIndex(
                kNumNonLocalBoolKeywordOld,
                current_block_size,
                memblock,
                current_byte_index)) {
          LOG_ERROR(
              "Expected Keyword '" + kNumNonLocalBoolKeyword + "' not found.");
          return false;
        }
      } else if (!parsed_num_boolean_gates) {
        num_non_local_boolean_gates_per_party_pairs_.push_back(value);
        value_holder.clear();
        value_holder.reserve(kNumDigitsIn64BitInt);
        if (current_byte == ';') {
          ++(*current_byte_index);
          // Sanity-check that the expected number of partner pairs were found.
          if ((int) num_non_local_boolean_gates_per_party_pairs_.size() !=
              (num_parties * (num_parties - 1)) / 2) {
            LOG_ERROR(
                "Bad circuit file: only " +
                Itoa(num_non_local_boolean_gates_per_party_pairs_.size()) +
                " pairs of partners found (" +
                Itoa((num_parties * (num_parties - 1)) / 2) +
                " pairs of partners expected, for " + Itoa(num_parties) +
                " total parties).");
            return false;
          }
          parsed_num_boolean_gates = true;
          if (!AdvanceCurrentByteIndex(
                  true,
                  kNumGatesPerLevelKeyword,
                  current_block_size,
                  memblock,
                  current_byte_index)) {
            // Perhaps this is an old circuit file that hasn't been updated
            // yet with the num GMW gates per level; keep parsing.
            parsed_num_gates_per_level = true;
            if (!AdvanceCurrentByteIndex(
                    kNumNonLocalArithKeyword,
                    current_block_size,
                    memblock,
                    current_byte_index) &&
                !AdvanceCurrentByteIndex(
                    kNumNonLocalArithKeywordOld,
                    current_block_size,
                    memblock,
                    current_byte_index)) {
              LOG_ERROR(
                  "Expected Keyword '" + kNumNonLocalArithKeyword +
                  "' not found.");
              return false;
            }
          }
        }
      } else if (!parsed_num_gates_per_level) {
        num_gates_per_level_.push_back(value);
        value_holder.clear();
        value_holder.reserve(kNumDigitsIn64BitInt);
        if (current_byte == ';') {
          ++(*current_byte_index);
          num_levels_ = (GateIndexDataType) num_gates_per_level_.size();
          parsed_num_gates_per_level = true;
          if (!AdvanceCurrentByteIndex(
                  kNumNonLocalArithKeyword,
                  current_block_size,
                  memblock,
                  current_byte_index) &&
              !AdvanceCurrentByteIndex(
                  kNumNonLocalArithKeywordOld,
                  current_block_size,
                  memblock,
                  current_byte_index)) {
            LOG_ERROR(
                "Expected Keyword '" + kNumNonLocalArithKeyword +
                "' not found.");
            return false;
          }
        }
      } else if (!parsed_num_arithmetic_gates) {
        num_non_local_arithmetic_gates_per_party_pairs_.push_back(value);
        value_holder.clear();
        value_holder.reserve(kNumDigitsIn64BitInt);
        if (current_byte == ';') {
          ++(*current_byte_index);
          // Sanity-check that the expected number of partner pairs were found.
          if ((int) num_non_local_arithmetic_gates_per_party_pairs_.size() !=
              (num_parties * (num_parties - 1)) / 2) {
            LOG_ERROR(
                "Bad circuit file: only " +
                Itoa(num_non_local_arithmetic_gates_per_party_pairs_.size()) +
                " pairs of partners found (" +
                Itoa((num_parties * (num_parties - 1)) / 2) +
                " pairs of partners expected, for " + Itoa(num_parties) +
                " total parties).");
            return false;
          }
          parsed_num_arithmetic_gates = true;
          if (!AdvanceCurrentByteIndex(
                  kNumOutputsKeyword,
                  current_block_size,
                  memblock,
                  current_byte_index)) {
            LOG_ERROR(
                "Expected Keyword '" + kNumOutputsKeyword + "' not found.");
            return false;
          }
        }
      } else if (!parsed_num_outputs) {
        num_outputs_ = value;
        // Update max_gates_in_queue_ to equal the maximum number of gates
        // needed (based on number of gates in the circuit and global outputs).
        if (max_gates_in_queue_ > num_gates_ + num_outputs_) {
          max_gates_in_queue_ = num_gates_ + num_outputs_;
        }
        // Update [read | eval]_gates_thread_num_tasks_until_context_switch_
        // to be max_gates_in_queue_, if appropriate.
        if (read_gates_thread_num_tasks_until_context_switch_ >= 0 &&
            read_gates_thread_num_tasks_until_context_switch_ >
                max_gates_in_queue_) {
          read_gates_thread_num_tasks_until_context_switch_ =
              max_gates_in_queue_;
        }
        if (eval_gates_thread_num_tasks_until_context_switch_ >= 0 &&
            eval_gates_thread_num_tasks_until_context_switch_ >
                max_gates_in_queue_) {
          eval_gates_thread_num_tasks_until_context_switch_ =
              max_gates_in_queue_;
        }
        value_holder.clear();
        value_holder.reserve(kNumDigitsInGateIndexDataType);
        parsed_num_outputs = true;
        ++(*current_byte_index);
        if (!AdvanceCurrentByteIndex(
                kArithGatesFromBoolGatesKeyword,
                current_block_size,
                memblock,
                current_byte_index)) {
          LOG_ERROR(
              "Expected Keyword '" + kArithGatesFromBoolGatesKeyword +
              "' not found.");
          return false;
        }
      } else if (!parsed_arith_from_bool_types) {
        if (!expect_data_type && !value_holder.empty()) {
          LOG_ERROR("Bad format of circuit file.");
          return false;
        }
        if (!value_holder.empty()) {
          datatypes_of_arith_from_bool_gates_.insert(
              make_pair(arith_from_bool_index, static_cast<DataType>(value)));
        }
        if (current_byte == ',') {
          expect_data_type = false;
          value_holder.clear();
          value_holder.reserve(kNumDigitsInGateIndexDataType);
        } else {
          parsed_arith_from_bool_types = true;
          is_circuit_file_num_gates_read_ = true;
          ++(*current_byte_index);
          break;
        }
      }
    } else if (current_byte == ':') {
      if (!parsed_num_outputs || expect_data_type ||
          !Stoi(value_holder, &arith_from_bool_index)) {
        LOG_ERROR("Bad format of circuit file.");
        return false;
      }
      expect_data_type = true;
      value_holder.clear();
      value_holder.reserve(kNumDigitsInGateIndexDataType);
    } else if (
        current_byte == '\0' &&
        (int64_t) *current_byte_index == current_block_size) {
      --(*current_byte_index);
    } else {
      value_holder.push_back(current_byte);
    }
    ++(*current_byte_index);
  }

  return true;
}

bool CircuitByGate::ParseFunctionDescription(
    const bool parse_function_formula,
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index) {
  vector<char> value_holder;
  vector<char> end_function_holder(
      kNumGatesKeyword.begin(), kNumGatesKeyword.end());
  size_t end_function_index = 0;
  while ((int64_t) *current_byte_index < current_block_size) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == end_function_holder[end_function_index]) {
      ++end_function_index;
      if (end_function_index == kNumGatesKeyword.size()) {
        const string function_str(value_holder.begin(), value_holder.end());
        bool expect_output_designation = true;
        *current_byte_index -= end_function_index;
        if (!ParseFunctionString(
                function_str,
                &expect_output_designation,
                &function_var_names_,
                (parse_function_formula ? &function_description_ : nullptr),
                &output_designations_)) {
          return false;
        }
        is_circuit_file_function_read_ = true;
        return true;
      }
    } else {
      // If end_function_index > 0, this means some bytes were not recorded in
      // value_holder, as we thought we were reading kNumGatesKeyword.
      // Copy those bytes over now.
      for (size_t i = 0; i < end_function_index; ++i) {
        value_holder.push_back(end_function_holder[i]);
      }
      end_function_index = 0;
      value_holder.push_back(current_byte);
    }
    ++(*current_byte_index);
  }

  LOG_ERROR("Reached end of parsing function description without "
            "finding next block(s) to read (e.g. Party input info).");
  return false;
}

// NOTE: The logic below should be kept consistent with how we map DataType
// to a succinct string, which is described via the kDataTypeToString map.
bool CircuitByGate::ParseInputDataType(
    const int64_t& current_block_size,
    const char* memblock,
    DataType* type,
    uint64_t* current_byte_index) {
  // Parse the first character, which describes the underlying type
  // (string vs. integer, etc.).
  bool is_string = false;
  bool is_int = false;
  bool is_uint = false;
  const char type_byte =
      GetByte(current_block_size, memblock, current_byte_index);
  ++(*current_byte_index);
  if (type_byte == 'S') {
    is_string = true;
  } else if (type_byte == 'B') {
    const char next_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (next_byte != ')') {
      LOG_ERROR("Bad format of circuit file.");
      return false;
    }
    *type = DataType::BOOL;
    ++(*current_byte_index);
    return true;
  } else if (type_byte == 'I') {
    is_int = true;
  } else if (type_byte == 'U') {
    is_uint = true;
  } else if (
      type_byte ==
      'L') {  // 'L' denotes 'Slice', since 'S' already taken (STRING)
    const char next_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (next_byte != ')') {
      LOG_ERROR("Bad format of circuit file.");
      return false;
    }
    *type = DataType::SLICE;
    ++(*current_byte_index);
    return true;
  } else if (type_byte == 'D') {
    const char next_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (next_byte != ')') {
      LOG_ERROR("Bad format of circuit file.");
      return false;
    }
    *type = DataType::DOUBLE;
    ++(*current_byte_index);
    return true;
  } else if (type_byte == 'V') {
    const char next_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (next_byte != ')') {
      LOG_ERROR("Bad format of circuit file.");
      return false;
    }
    *type = DataType::VECTOR;
    ++(*current_byte_index);
    return true;
  } else {
    LOG_ERROR("Unrecognized DataType: " + Itoa(type_byte));
    return false;
  }

  // The fact that we reached here means data type requires a number
  // (specifying number of bits). Parse this.
  vector<char> num_bits_as_string;
  // The maximum number of characters needed to express the number of bits
  // (in human readable format) is 3 (for 128).
  const int kMaxNumCharsInNumBits = 3;
  num_bits_as_string.reserve(kMaxNumCharsInNumBits);
  while ((int64_t) *current_byte_index < current_block_size &&
         num_bits_as_string.size() < kMaxNumCharsInNumBits) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == ')') break;
    num_bits_as_string.push_back(current_byte);
    ++(*current_byte_index);
  }

  if ((int64_t) *current_byte_index >= current_block_size ||
      memblock[*current_byte_index] != ')') {
    LOG_ERROR("Bad format of circuit file.");
    return false;
  }

  unsigned int num_bits;
  if (num_bits_as_string.empty() || !Stoi(num_bits_as_string, &num_bits)) {
    LOG_ERROR("Bad format of circuit file.");
    return false;
  }

  if (is_string) {
    if (num_bits == 8) *type = DataType::STRING8;
    else if (num_bits == 16) *type = DataType::STRING16;
    else if (num_bits == 24) *type = DataType::STRING24;
    else if (num_bits == 32) *type = DataType::STRING32;
    else if (num_bits == 64) *type = DataType::STRING64;
    else if (num_bits == 128) *type = DataType::STRING128;
    else {
      LOG_ERROR(
          "Unsupported number of bits in STRING DataType: " + Itoa(num_bits));
      return false;
    }
  } else if (is_int) {
    if (num_bits == 2) *type = DataType::INT2;
    else if (num_bits == 4) *type = DataType::INT4;
    else if (num_bits == 8) *type = DataType::INT8;
    else if (num_bits == 16) *type = DataType::INT16;
    else if (num_bits == 32) *type = DataType::INT32;
    else if (num_bits == 64) *type = DataType::INT64;
    else {
      LOG_ERROR("Unsupported number of bits in INT DataType: " + Itoa(num_bits));
      return false;
    }
  } else if (is_uint) {
    if (num_bits == 2) *type = DataType::UINT2;
    else if (num_bits == 4) *type = DataType::UINT4;
    else if (num_bits == 8) *type = DataType::UINT8;
    else if (num_bits == 16) *type = DataType::UINT16;
    else if (num_bits == 32) *type = DataType::UINT32;
    else if (num_bits == 64) *type = DataType::UINT64;
    else {
      LOG_ERROR(
          "Unsupported number of bits in UINT DataType: " + Itoa(num_bits));
      return false;
    }
  } else {
    LOG_ERROR("Unrecognized first character.");
    return false;
  }

  ++(*current_byte_index);
  return true;
}

bool CircuitByGate::ParseConstantInput(
    const int64_t& current_block_size,
    const char* memblock,
    GenericValue* value,
    uint64_t* current_byte_index) {
  vector<char> constant_holder;
  // The maximum number of bytes we'll need to express constant inputs (values)
  // is the number of bytes in uint64_t (no bigger constant values supported).
  constant_holder.reserve(kNumDigitsIn64BitInt);
  bool has_negative_sign = false;
  while ((int64_t) *current_byte_index < current_block_size &&
         constant_holder.size() < kNumDigitsIn64BitInt) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == 'L' || current_byte == 'R') break;
    if (current_byte == '-') {
      if (!constant_holder.empty() || has_negative_sign) {
        LOG_ERROR("Bad format of circuit file.");
        return false;
      }
      has_negative_sign = true;
    } else {
      constant_holder.push_back(current_byte);
    }
    ++(*current_byte_index);
  }

  const char next_byte =
      GetByte(current_block_size, memblock, current_byte_index);
  if (next_byte != 'L' && next_byte != 'R') {
    LOG_ERROR("Bad format of circuit file.");
    return false;
  }

  int64_t neg_value;
  uint64_t pos_value;
  if (has_negative_sign) {
    if (!Stoi(constant_holder, &neg_value)) {
      LOG_ERROR("Bad format of circuit file.");
      return false;
    }
    *value = GenericValue(neg_value * -1);
  } else {
    if (!Stoi(constant_holder, &pos_value)) {
      LOG_ERROR("Bad format of circuit file.");
      return false;
    }
    *value = GenericValue(pos_value);
  }

  return true;
}

bool CircuitByGate::ParseInputs(
    const int64_t& current_block_size,
    const char* memblock,
    uint64_t* current_byte_index) {
  // First, advance current_byte_index to the end of kPartyInputsKeyword.
  if (!AdvanceCurrentByteIndex(
          kPartyInputsKeyword + "(0):",
          current_block_size,
          memblock,
          current_byte_index)) {
    LOG_ERROR("Expected Keyword '" + kPartyInputsKeyword + "(0)' not found.");
    return false;
  }
  // Handle corner-case: First party(ies) don't have any inputs. Then
  // advance to next party.
  int current_party_index = 0;
  bool is_constant_block = false;
  char temp_curr_byte =
      GetByte(current_block_size, memblock, current_byte_index);
  while (temp_curr_byte == ';') {
    ++(*current_byte_index);
    if (current_party_index == (int) function_var_names_.size()) {
      is_circuit_file_inputs_read_ = true;
      return true;
    } else if (current_party_index == (int) function_var_names_.size() - 1) {
      is_constant_block = true;
    }
    ++current_party_index;
    // Advance current_byte_index to the end of kPartyInputsKeyword.
    const string keyword = is_constant_block ?
        kConstantGatesKeyword :
        (string(kPartyInputsKeyword) + "(" + Itoa(current_party_index) + "):");
    if (!AdvanceCurrentByteIndex(
            keyword, current_block_size, memblock, current_byte_index)) {
      LOG_ERROR("Expected Keyword '" + keyword + "' not found.");
      return false;
    }
    temp_curr_byte = GetByte(current_block_size, memblock, current_byte_index);
  }

  vector<char> value_holder;
  value_holder.reserve(kNumDigitsInGateIndexDataType);
  GenericValue constant_value;
  DataType type;
  GateIndexDataType gate_index;
  bool is_left = false;
  bool keep_going = true;
  bool expect_data_type = true;
  bool expect_left_right = false;
  bool expect_constant_value = false;
  bool expect_bit_index = false;
  int current_input_index = 0;
  while (keep_going && (int64_t) *current_byte_index < current_block_size) {
    const char current_byte =
        GetByte(current_block_size, memblock, current_byte_index);
    if (current_byte == '(') {
      if (!expect_data_type) {
        LOG_ERROR(
            "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
            ": '" + current_byte + "'");
        return false;
      }
      ++(*current_byte_index);
      if (!ParseInputDataType(
              current_block_size, memblock, &type, current_byte_index)) {
        return false;
      }
      if (!is_constant_block) {
        inputs_.push_back(GlobalInputInfo(type));
      }
      expect_data_type = false;
      if (!is_constant_block) {
        expect_left_right = true;
      } else {
        expect_constant_value = true;
      }
    } else if (expect_data_type) {
      LOG_ERROR(
          "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
          ": '" + current_byte + "'");
      return false;
    } else if (expect_constant_value) {
      if (!ParseConstantInput(
              current_block_size,
              memblock,
              &constant_value,
              current_byte_index)) {
        return false;
      }
      expect_left_right = true;
      expect_constant_value = false;
    } else if (current_byte == 'L' || current_byte == 'R') {
      if (!expect_left_right) {
        LOG_ERROR(
            "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
            ": '" + current_byte + "'");
        return false;
      }
      expect_left_right = false;
      if (current_byte == 'L') is_left = true;
      else is_left = false;
      ++(*current_byte_index);
    } else if (expect_left_right) {
      LOG_ERROR(
          "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
          ": '" + current_byte + "'");
      return false;
    } else if (current_byte == ':') {
      if (value_holder.empty()) {
        LOG_ERROR("Missing output gate index or bit index.");
        return false;
      }
      if (!Stoi(value_holder, &gate_index)) {
        LOG_ERROR(
            "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
            ": '" + current_byte + "'");
        return false;
      }
      value_holder.clear();
      value_holder.reserve(kNumDigitsInGateIndexDataType);
      expect_bit_index = true;
      ++(*current_byte_index);
    } else if (current_byte == ',' || current_byte == ';') {
      if (value_holder.size() > kNumDigitsInGateIndexDataType)
        LOG_FATAL("Bad circuit file.");
      GateIndexDataType index;
      if (!Stoi(value_holder, &index)) {
        LOG_ERROR(
            "Bad format of circuit file at byte " + Itoa(*current_byte_index) +
            ": '" + current_byte + "'");
        return false;
      }
      value_holder.clear();
      value_holder.reserve(kNumDigitsInGateIndexDataType);
      OutputWireLocation target;
      if (expect_bit_index) {
        target = OutputWireLocation(
            InputWireLocation(is_left, gate_index), (unsigned char) index);
      } else {
        target = OutputWireLocation(InputWireLocation(is_left, index));
      }
      if (!is_constant_block) {
        inputs_.back().to_.insert(target);
        set<tuple<int, int, int>>* input_loc;
        if (is_left) {
          input_loc = FindOrInsert(
              target.loc_.index_,
              left_input_wire_to_party_index_,
              set<tuple<int, int, int>>());
        } else {
          input_loc = FindOrInsert(
              target.loc_.index_,
              right_input_wire_to_party_index_,
              set<tuple<int, int, int>>());
        }
        input_loc->insert(make_tuple(
            current_party_index,
            current_input_index,
            expect_bit_index ? (int) index : -1));
      } else {
        if (target.loc_.is_left_) {
          left_constant_input_.insert(
              make_pair(target.loc_.index_, constant_value));
        } else {
          right_constant_input_.insert(
              make_pair(target.loc_.index_, constant_value));
        }
      }
      expect_bit_index = false;
      // Grab index of next (non-whitespace) byte.
      ++(*current_byte_index);
      char next_char = GetByte(current_block_size, memblock, current_byte_index);
      last_circuit_file_block_break_byte_ = (*current_byte_index);
      // Reset current_byte_index back to previous byte.
      --(*current_byte_index);
      if (current_byte == ',') {
        expect_left_right = true;
        ++(*current_byte_index);
      } else if (next_char == '(') {
        // Present party has another input. Process it.
        expect_data_type = true;
        ++current_input_index;
      } else {
        // No more inputs for the present party. Skip to info for next party,
        // or return if all Parties' inputs have been processed.
        char curr_byte = ';';
        while (curr_byte == ';') {
          ++(*current_byte_index);
          if (current_party_index == (int) function_var_names_.size()) {
            is_circuit_file_inputs_read_ = true;
            return true;
          } else if (
              current_party_index == (int) function_var_names_.size() - 1) {
            is_constant_block = true;
          }
          ++current_party_index;
          current_input_index = 0;
          // Advance current_byte_index to the end of kPartyInputsKeyword.
          const string keyword = is_constant_block ?
              kConstantGatesKeyword :
              (string(kPartyInputsKeyword) + "(" + Itoa(current_party_index) +
               "):");
          if (!AdvanceCurrentByteIndex(
                  keyword, current_block_size, memblock, current_byte_index)) {
            LOG_ERROR("Expected Keyword '" + keyword + "' not found.");
            return false;
          }
          curr_byte = GetByte(current_block_size, memblock, current_byte_index);
        }
        expect_data_type = true;
      }
    } else {
      value_holder.push_back(current_byte);
      ++(*current_byte_index);
    }
  }

  LOG_ERROR("Reached end of parsing Party inputs in circuit file, without "
            "finding next block(s) to read (e.g. Gate info).");
  return false;
}

// Discussion:
// There are three reasons the parsing of the Gates section of the circuit file
// can be interrupted (which additionally means that when entering this block,
// we may be entering it for the first time, or after an interruption):
//   1) (Memory) If num_threads_ = 1 and read_gates_thread_num_tasks_until_context_switch_
//      gates have been read, Pause (context switch) to process these gates so
//      we can keep memory footprint lower.
//   2) (Memory) If gates_.size() reaches max_gates_in_queue_, Sleep until
//      gates_ has more space.
//      NOTE: This case can only happen if num_threads_ > 1, since otherwise
//      max_gates_in_queue_ >= read_gates_thread_num_tasks_until_context_switch_,
//      and hence in the single thread case we should have done a context switch
//      before threatening to exceed max_gates_in_queue_ items in gates_.
//      will interrupt after this many gates have been read
//   3) (Code Design) If 'current_block_size' is not big enough to read all the
//      circuit file, (temporarilly) return and fetch the next block of bytes.
// Need to handle all three cases, both in determining when to interrupt, as well
// as handling a return here after an interruption.
bool CircuitByGate::ParseGates(
    const bool started_parsing_gates,
    const bool wait_when_gates_is_full,
    const int64_t& current_block_size,
    const char* memblock,
    GmwByGate* parent,
    uint64_t* current_byte_index) {
  // First, advance current_byte_index to the end of kGateInfoKeyword.
  if (!started_parsing_gates &&
      !AdvanceCurrentByteIndex(
          kGateInfoKeyword, current_block_size, memblock, current_byte_index)) {
    LOG_ERROR("Expected Keyword '" + kGateInfoKeyword + "' not found.");
    return false;
  }

  // Reserve space for all gates (or as many as allowed by kDefaultMaxGates).
  const GateIndexDataType queue_size =
      read_gates_thread_num_tasks_until_context_switch_ > 0 ?
      min(max_gates_in_queue_,
          (GateIndexDataType)
              read_gates_thread_num_tasks_until_context_switch_) :
      max_gates_in_queue_;
  if (gates_.size() < queue_size) {
    gates_.reserve(queue_size);
    left_values_.reserve(queue_size);
    right_values_.reserve(queue_size);
  }

  // Compute size of depends_on_ (= Num Parties / 8).
  const int num_parties = (int) function_var_names_.size();
  const int depends_on_size =
      num_parties / CHAR_BIT + ((num_parties % CHAR_BIT == 0) ? 0 : 1);
  const unsigned char depends_on_all_byte = -1;  // 11111111
  const unsigned char depends_on_all_last_byte =
      (unsigned char) ((num_parties % CHAR_BIT == 0) ? depends_on_all_byte : (depends_on_all_byte ^ (depends_on_all_byte >> (num_parties % CHAR_BIT))));

  // Parse Gate info:
  //   - Gate Op (1 byte)
  //   - Depends On (N / 8 bytes)
  //   - Left Output Wire(s) (comma-separated list)
  //   - Right Output Wire(s) (comma-separated list)
  //   - Global Output Wire(s) (comma-separated list)
  Gate current_gate;
  OutputWireLocation current_output_wire;
  vector<char> value_holder;
  value_holder.reserve(kNumDigitsInGateIndexDataType);
  bool expect_op = true;
  int expect_depends_on = -1;
  bool depends_on_all_parties = true;
  bool expect_left_outputs = false;
  bool expect_right_outputs = false;
  bool expect_global_outputs = false;
  bool expect_bit_index = false;
  while ((int64_t) *current_byte_index < current_block_size) {
    // Read current byte.
    // NOTE: We ignore (skip-over) whitespace, UNLESS we are reading the
    // depends_on_ field, in which case all 256 characters are valid, i.e.
    // whitespace should be interpretted as the corresponding numeric value.
    const char current_byte = expect_depends_on >= 0 ?
        memblock[*current_byte_index] :
        GetByte(current_block_size, memblock, current_byte_index);
    if (expect_op) {
      if (current_byte == ';') {
        if (value_holder.empty()) {
          LOG_ERROR("Missing Gate op.");
          return false;
        }
        unsigned char op_index;
        if (!Stoi(value_holder, &op_index)) {
          LOG_ERROR(
              "Unable to parse Op index: '" +
              string(value_holder.begin(), value_holder.end()) + "'");
          return false;
        }
        current_gate.op_ = static_cast<CircuitOperation>(op_index);
        value_holder.clear();
        value_holder.reserve(kNumDigitsInGateIndexDataType);
        expect_op = false;
        expect_depends_on = 0;
        depends_on_all_parties = true;
      } else if (current_byte == '\0') {
        if (!value_holder.empty() ||
            (int64_t) *current_byte_index < current_block_size) {
          LOG_ERROR("Bad format of circuit file.");
          return false;
        }
        return true;
      } else {
        value_holder.push_back(current_byte);
      }
      ++(*current_byte_index);
    } else if (expect_depends_on >= 0) {
      if (expect_depends_on == 0) {
        current_gate.depends_on_.resize(depends_on_size, 0);
        current_gate.depends_on_[0] = current_byte;
        depends_on_all_parties &= ((unsigned char) current_byte) ==
            (depends_on_size == 1 ? depends_on_all_last_byte :
                                    depends_on_all_byte);
      } else if (expect_depends_on == depends_on_size) {
        if (current_byte != ';') {
          LOG_ERROR("Bad depends_on_ at Gate " + Itoa(gates_.size()));
          return false;
        }
        if (depends_on_all_parties) current_gate.depends_on_.clear();
        expect_depends_on = -2;
        expect_left_outputs = true;
      } else {
        current_gate.depends_on_[expect_depends_on] = current_byte;
        depends_on_all_parties &= ((unsigned char) current_byte) ==
            ((depends_on_size == expect_depends_on + 1) ?
                 depends_on_all_last_byte :
                 depends_on_all_byte);
      }
      ++expect_depends_on;
      ++(*current_byte_index);
    } else if (expect_left_outputs || expect_right_outputs) {
      if (current_byte == ':') {
        if (value_holder.empty()) {
          LOG_ERROR("Missing output gate index or bit index.");
          return false;
        }
        GateIndexDataType gate_index;
        if (!Stoi(value_holder, &gate_index)) {
          LOG_ERROR(
              "Unable to parse gate index: '" +
              string(value_holder.begin(), value_holder.end()) + "'");
          return false;
        }
        current_output_wire.loc_.index_ = gate_index;
        value_holder.clear();
        value_holder.reserve(kNumDigitsInGateIndexDataType);
        expect_bit_index = true;
      } else if (current_byte == ',' || current_byte == ';') {
        if (value_holder.empty() && (current_byte == ',' || expect_bit_index)) {
          LOG_ERROR("Missing Left Output gate info");
          return false;
        }
        if (!value_holder.empty()) {
          GateIndexDataType index;
          if (!Stoi(value_holder, &index)) {
            LOG_ERROR(
                "Unable to parse bit index: '" +
                string(value_holder.begin(), value_holder.end()) + "'");
            return false;
          }
          if (expect_bit_index) {
            if (index >= kBitIndexMask) {
              LOG_ERROR(
                  "Unable to parse bit index: '" +
                  string(value_holder.begin(), value_holder.end()) + "'");
              return false;
            }
            current_output_wire.bit_index_ =
                (unsigned char) (index + kBitIndexMask);
          } else {
            current_output_wire.loc_.index_ = index;
          }
          current_output_wire.loc_.is_left_ = expect_left_outputs;
          current_gate.output_wires_.push_back(current_output_wire);
          // current_output_wire will get used for the *next* gate also; the
          // loc_ field will necessarily be overwritten (so no need to clear
          // it here), but the bit_index_ field may not be; clear it now.
          current_output_wire.bit_index_ = 0;
          value_holder.clear();
          value_holder.reserve(kNumDigitsInGateIndexDataType);
        }
        expect_bit_index = false;

        // Handle case this is the end of the left/right output gate info for this gate.
        if (current_byte == ';') {
          expect_global_outputs = expect_right_outputs ? true : false;
          expect_right_outputs = expect_left_outputs ? true : false;
          expect_left_outputs = false;
        }
      } else {
        value_holder.push_back(current_byte);
      }
      ++(*current_byte_index);
    } else if (expect_global_outputs) {
      if (current_byte == ':') {
        if (value_holder.empty()) {
          LOG_ERROR("Missing global output gate index or bit index.");
          return false;
        }
        GateIndexDataType gate_index;
        if (!Stoi(value_holder, &gate_index)) {
          LOG_ERROR(
              "Unable to parse bit index: '" +
              string(value_holder.begin(), value_holder.end()) + "'");
          return false;
        }
        current_output_wire.loc_.index_ = gate_index + num_gates_;
        value_holder.clear();
        value_holder.reserve(kNumDigitsInGateIndexDataType);
        expect_bit_index = true;
      } else if (current_byte == ',' || current_byte == '|') {
        // Parse the (current) global output gate
        if (value_holder.empty() && (current_byte == ',' || expect_bit_index)) {
          LOG_ERROR("Missing global output gate index or bit index.");
          return false;
        } else if (!value_holder.empty()) {
          GateIndexDataType index;
          if (!Stoi(value_holder, &index)) {
            LOG_ERROR(
                "Unable to parse bit index: '" +
                string(value_holder.begin(), value_holder.end()) + "'");
            return false;
          }
          if (expect_bit_index) {
            if (index >= kBitIndexMask) {
              LOG_ERROR("Unable to parse bit index: " + Itoa(index));
              return false;
            }
            current_output_wire.bit_index_ =
                (unsigned char) (index + kBitIndexMask);
          } else {
            current_output_wire.loc_.index_ = index + num_gates_;
          }
          // Convention is to mark global outputs as the 'Left' wire.
          current_output_wire.loc_.is_left_ = true;
          current_gate.output_wires_.push_back(current_output_wire);
          // current_output_wire will get used for the *next* gate also; the
          // loc_ field will necessarily be overwritten (so no need to clear
          // it here), but the bit_index_ field may not be; clear it now.
          current_output_wire.bit_index_ = 0;
          value_holder.clear();
          value_holder.reserve(kNumDigitsInGateIndexDataType);
        }
        expect_bit_index = false;

        // Handle case this is the end of the gate info for this gate.
        if (current_byte == '|') {
          expect_global_outputs = false;
          expect_op = true;
          // To keep gates_ in sync with [left | right]_values_, we call Push()
          // at the same time, even though we can't actually fill the latter
          // with meaningful values at this point. And actually, we call Push()
          // on these before calling it on gates_, for concurrency reasons:
          // If we were to gates_ first, there is the (very small) chance that
          // the current thread hangs between calling Push() on gates_ and Push()
          // on left/right_values_, and then if the EvaluateCircuit() thread is
          // flying, it may go to evaluate the corresponding gate *before* Push()
          // was called on left/right_values_, which would cause a hiccup in
          // the EvaluateCircuit() code. However, doing things this way won't
          // be a problem, since we'll never attempt to read an entry of the
          // left/right_values_ Queue before reading the corresponding value
          // in gates_.
          left_values_.Push(GenericValue());
          right_values_.Push(GenericValue());
          gates_.Push(current_gate);
          // 'current_gate' will be reused for the next gate. Clear the fields
          // that won't be reset.
          current_gate.output_wires_.clear();
          ++(*current_byte_index);
          last_circuit_file_block_break_byte_ = (*current_byte_index);
          // Reset current_byte_index back to previous byte.
          --(*current_byte_index);

          // Check for early abort (based on Concurrency/Memory constraints):
          //   If read_gates_thread_num_tasks_until_context_switch_ indicates a
          //   context switch should happen when gates_ reaches its present size
          if (read_gates_thread_num_tasks_until_context_switch_ > 0 &&
              (int64_t) gates_.size() >=
                  read_gates_thread_num_tasks_until_context_switch_) {
            ++(*current_byte_index);
            return true;
          }
          if (gates_.size() >= max_gates_in_queue_) {
            // If we're on the last byte of the file, then gates_.size() will equal
            // max_gates_in_queue_, but we should just return.
            // Also, if wait_when_gates_is_full is false, just return.
            if (!wait_when_gates_is_full ||
                (int64_t) (*current_byte_index) + 1 == current_block_size) {
              ++(*current_byte_index);
              return true;
            }
          }

          int num_eval_thread_sleeps = -1;
          int num_parse_inputs_thread_sleeps = -1;
          while (gates_.size() >= max_gates_in_queue_ ||
                 left_values_.size() >= max_gates_in_queue_ ||
                 right_values_.size() >= max_gates_in_queue_) {
            // The fact that we reached here means that there is a separate thread
            // processing (Pop()ing) items from gates_, and so the current thread
            // just needs to wait (sleep) for a bit, giving the other thread a
            // chance to clear space in gates_ so that the present thread can fill
            // it again. There are a couple of items to consider here:
            //   1) Need to sanity-check that the Evaluate Gates thread is making
            //      progress
            //   2) How much space to clear in gates_ (i.e. how many gates the
            //      other thread should process) before the present thread wakes
            // Item (1) is handled by IsProgressBeingMade().
            // For Item (2), we could wake up as soon as just one gate has been
            // processed, since this will allow one gate to be Push()ed. However,
            // there is a concurrency issue here: If we wake up and Push() that
            // gate before the Evaluate Gates thread has Pop()ed a *second* gate,
            // then we'll just need to pause (sleep) the present thread again.
            // This can lead to inefficiency of constantly going to sleep and
            // waking up; and possibly worse. Nevertheless, this is what we do,
            // as the alternative(s) (of sleeping until gates_ has X free slots)
            // will likely, in most cases, take longer.
            if (!IsProgressBeingMade(
                    SleepReason::READ_GATE_INFO_FOR_EVAL,
                    ThreadStatus::UNKNOWN, /* Not Used */
                    (parent == nullptr ?
                         GetThreadStatus(CircuitByGateTask::PARSE_INPUTS) :
                         parent->GetThreadStatus(
                             CircuitByGateTask::PARSE_INPUTS)),
                    (parent == nullptr ?
                         GetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT) :
                         parent->GetThreadStatus(
                             CircuitByGateTask::EVALUATE_CIRCUIT)),
                    &num_eval_thread_sleeps,
                    &num_parse_inputs_thread_sleeps)) {
              // Re-check gates_.size() vs. max_gates_in_queue_, on the off-
              // chance this has changed since the check in the while loop condition.
              if (gates_.size() < max_gates_in_queue_ &&
                  left_values_.size() < max_gates_in_queue_ &&
                  right_values_.size() < max_gates_in_queue_) {
                break;
              }
              LOG_ERROR(
                  "Gate Evaluation is not active: " +
                  Itoa(static_cast<int>(
                      GetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT))));
              return false;
            }
            uint64_t sleep_time;
            if (!read_gates_sleep_.GetSleepTime(&sleep_time) ||
                // usleep throws error is sleeping more than 1 second
                sleep_time > 1000000) {
              if (sleep_time > 1000000) {
                LOG_ERROR(
                    "Already slept too long (" +
                    Itoa(read_gates_sleep_.GetTotalSleptTime()) +
                    "microseconds), aborting.");
              }
              return false;
            }
            SetThreadStatus(
                CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::ASLEEP);
            max_gates_sleep_time_ += sleep_time;
            usleep((useconds_t) sleep_time);
            SetThreadStatus(
                CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::ACTIVE);
          }
          read_gates_sleep_.Reset();
        }
      } else {
        value_holder.push_back(current_byte);
      }
      ++(*current_byte_index);
    } else {
      LOG_FATAL("Should never reach here.");
    }
  }

  return true;
}

bool CircuitByGate::ReadCircuitFile(
    const bool parse_function_formula,
    ifstream& file,
    const int64_t block_size,
    GmwByGate* parent,
    bool* is_done) {
  const bool abort_after_reading_metadata =
      (!is_circuit_file_inputs_read_ && is_done != nullptr && num_threads_ == 1);
  char* memblock = new char[block_size];
  if (!memblock) {
    LOG_ERROR(
        "Unable to allocate enough memory (" + Itoa(block_size) +
        " bytes) for the circuit file");
    file.close();
    if (parent == nullptr) {
      SetThreadStatus(
          CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::FAILED);
    } else {
      parent->SetThreadStatus(
          CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::FAILED);
    }
    return false;
  }

  // Loop through circuit file, extracting info.
  vector<char> remainder_bytes;
  char* temp;
  bool started_parsing_gates = gates_.size() > 0 || num_gates_processed_ > 0;
  while (circuit_reader_thread_current_byte_ < num_circuit_file_bytes_) {
    // Resize memblock, if this is the final block and there are fewer
    // than block_size bytes left.
    const int64_t remaining_bytes =
        num_circuit_file_bytes_ - circuit_reader_thread_current_byte_;
    int64_t current_block_size = min(remaining_bytes, block_size);
    if (current_block_size < block_size) {
      // Dicussion: Originally, memblock was passed-in to the present function
      // as an arg, and then the calling function called delete[] on memblock
      // when the present function returned. However, this was causing a
      // crash (only sometimes!), presumably because temp is a local variable,
      // and so reassigning memblock to temp (as is done below) means that
      // the call to (now deleted 'temp') delete[] memblock had undefined
      // behavior, hence the crash.
      // I redesigned so that memblock is now also a local variable, and that
      // seems to have resolved the crash. However, since the crash was only
      // occassional, it's possible that the code below is still problematic.
      // More generally, options are:
      //   - Leave as is
      //   - Just delete[] memblock, and then call memblock = new char[]
      //   - Don't reallocate at all (just leave memblock having extra space)
      //   - Figure out how to properly reallocate, so that the needed bytes
      //     of memblock stay allocated, and the rest goes free.
      temp = (char*) realloc(memblock, current_block_size);
      memblock = temp;
    }

    // Store 'remainder_bytes' into the first bytes of memblock.
    for (size_t i = 0; i < remainder_bytes.size(); ++i) {
      memblock[i] = remainder_bytes[i];
    }

    // Read block.
    file.read(memblock + remainder_bytes.size(), current_block_size);
    last_circuit_file_block_break_byte_ = 0;
    uint64_t current_byte_index = 0;

    while ((int64_t) current_byte_index < current_block_size) {
      // Read function description, if haven't already.
      if (!is_circuit_file_function_read_) {
        if (!ParseFunctionDescription(
                parse_function_formula,
                current_block_size,
                memblock,
                &current_byte_index)) {
          delete[] memblock;
          return false;
        }
        // Read Number of gates, if haven't already.
      } else if (!is_circuit_file_num_gates_read_) {
        if (!ParseNumberOfGates(
                current_block_size, memblock, &current_byte_index)) {
          delete[] memblock;
          return false;
        }
        // Read Global inputs (of each party, and constants), if haven't already.
      } else if (!is_circuit_file_inputs_read_) {
        if (!ParseInputs(current_block_size, memblock, &current_byte_index)) {
          delete[] memblock;
          return false;
        }
        // All metadata has been read; abort if appropriate.
      } else if (abort_after_reading_metadata) {
        circuit_reader_thread_current_byte_ += (int64_t) current_byte_index;
        if (parent == nullptr) {
          SetThreadStatus(
              CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::PAUSED);
        } else {
          parent->SetThreadStatus(
              CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::PAUSED);
        }
        delete[] memblock;
        return true;
        // Read Gate info.
      } else {
        if (!ParseGates(
                started_parsing_gates,
                is_done == nullptr,
                current_block_size,
                memblock,
                parent,
                &current_byte_index)) {
          delete[] memblock;
          return false;
        }
        started_parsing_gates = true;
        // Hard break here: ParseGates() will either proceed until
        // current_byte_index equals current_block_size (in which case the
        // hard break isn't necessary, but is harmless anyway), or it
        // will stop when it reaches an early abort condition, which signals
        // that we are (temporarily) done reading this block.
        break;
      }
    }

    // Done parsing the block. Determine what to do next:
    // First check for early abort, which necessarily means ParseGates() was
    // not finished due to:
    //   1) max_gates_in_queue_ gates were read; OR
    //   2) There is only one thread and:
    //       a) read_gates_thread_num_tasks_until_context_switch_ gates were read; OR
    //       b) done_global_inputs_file_ is false (need to read global inputs first)
    if ((int64_t) current_byte_index < current_block_size) {
      circuit_reader_thread_current_byte_ += last_circuit_file_block_break_byte_;
      if (is_done != nullptr) {
        if (parent == nullptr) {
          SetThreadStatus(
              CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::PAUSED);
        } else {
          parent->SetThreadStatus(
              CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::PAUSED);
        }
        *is_done = false;
      } else {
        LOG_ERROR("Early abort reading circuit file.");
      }
      delete[] memblock;
      return is_done != nullptr;
    }

    // No early abort, which means we made it through the end of the block.
    // Before proceeding to next block, check if current block ended at a
    // good spot to break (likely it didn't). If not, (temporarily) store
    // the bytes between the last good break point and the current byte,
    // and update other variables that will aide processing the next block.
    if ((int64_t) last_circuit_file_block_break_byte_ != current_block_size) {
      circuit_reader_thread_current_byte_ += last_circuit_file_block_break_byte_;
      // Since file.read() will continue from the last byte read, we need
      // to store the bytes between last_circuit_file_block_break_byte_ and
      // the end of memblock, as these bytes won't be re-read (even though
      // circuit_reader_thread_current_byte_ points to the proper place).
      const size_t num_remainder_bytes =
          current_block_size - last_circuit_file_block_break_byte_;
      remainder_bytes.resize(num_remainder_bytes);
      for (size_t i = 0; i < num_remainder_bytes; ++i) {
        remainder_bytes[i] = memblock[circuit_reader_thread_current_byte_ + i];
      }
    } else {
      circuit_reader_thread_current_byte_ += current_block_size;
    }
  }

  if (parent == nullptr) {
    SetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::DONE);
  } else {
    parent->SetThreadStatus(
        CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::DONE);
  }
  if (is_done != nullptr) *is_done = true;
  delete[] memblock;
  return true;
}

bool CircuitByGate::ReadCircuitFile(
    const bool parse_function_formula, GmwByGate* parent, bool* is_done) {
  // Return if already done.
  if (done_circuit_file_) {
    if (parent == nullptr) {
      SetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::DONE);
    } else {
      parent->SetThreadStatus(
          CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::DONE);
    }
    if (is_done != nullptr) *is_done = true;
    return true;
  }
  if (parent == nullptr) {
    SetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::ACTIVE);
  } else {
    parent->SetThreadStatus(
        CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::ACTIVE);
  }
  if (debug_) StartTimer(&read_circuit_file_timer_);

  // Open circuit file.
  const bool has_started_reading = num_circuit_file_bytes_ >= 0;
  const ios_base::openmode open_flags = has_started_reading ?
      (ios::in | ios::binary) :
      (ios::in | ios::binary | ios::ate);
  ifstream file(circuit_filename_, open_flags);
  if (!file.is_open()) {
    if (parent == nullptr) {
      SetThreadStatus(
          CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::FAILED);
    } else {
      parent->SetThreadStatus(
          CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::FAILED);
    }
    if (debug_) StopTimer(&read_circuit_file_timer_);
    LOG_ERROR("Unable to open circuit file: '" + circuit_filename_ + "'");
    return false;
  }

  // Check if we already started reading the circuit file.
  // Grab total circuit size, if not read yet.
  if (!has_started_reading) {
    num_circuit_file_bytes_ = file.tellg();
    file.seekg(0, ios::beg);
  } else {
    file.seekg(circuit_reader_thread_current_byte_, ios::beg);
  }
  // Allocate memory to read in (a block of) the circuit file.
  const int64_t block_size =
      min(kMaxReadFileBlockBytes, num_circuit_file_bytes_);
  const bool return_value =
      ReadCircuitFile(parse_function_formula, file, block_size, parent, is_done);
  // Clean-up: Deallocate memory and close file.
  file.close();
  if (!return_value) {
    if (parent == nullptr) {
      SetThreadStatus(
          CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::FAILED);
    } else {
      parent->SetThreadStatus(
          CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::FAILED);
    }
  }
  if (debug_) StopTimer(&read_circuit_file_timer_);

  return return_value;
}

bool CircuitByGate::ParseGlobalInputs(
    const string& filename, const vector<GenericValue>& inputs, bool* is_done) {
  // Return if already done.
  if (done_global_inputs_file_) {
    SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::DONE);
    if (is_done != nullptr) *is_done = true;
    return true;
  }
  SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::ACTIVE);

  // Make sure inputs are provided, either via 'inputs' or 'filename'.
  if (debug_) StartTimer(&parse_global_inputs_timer_);
  if (filename.empty() == inputs.empty()) {
    LOG_ERROR("Empty input.");
    SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
    if (debug_) StopTimer(&parse_global_inputs_timer_);
    return false;
  }

  // Make sure global inputs file is ready to be read, i.e. that we know
  // DataTypes of all inputs (i.e. that Circuit File metadata has been read,
  // at least up through the Party Input info).
  while (!is_circuit_file_inputs_read_) {
    if (is_done != nullptr) {
      *is_done = false;
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::PAUSED);
      if (debug_) StopTimer(&parse_global_inputs_timer_);
      return true;
    } else {
      if (!IsProgressBeingMade(
              SleepReason::PARSE_INPUTS_FOR_INPUT_INFO,
              GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE),
              ThreadStatus::UNKNOWN, /* Not Used */
              ThreadStatus::UNKNOWN, /* Not Used */
              nullptr /* Not Used */)) {
        // Re-check is_circuit_file_inputs_read_, on the off-chance this
        // has been set to true since the check in the while loop condition.
        if (is_circuit_file_inputs_read_) break;
        LOG_ERROR(
            "Circuit File Reading thread is not active: " +
            Itoa(static_cast<int>(
                GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE))));
        SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
        if (debug_) StopTimer(&parse_global_inputs_timer_);
        return false;
      }
      uint64_t sleep_time;
      if (!read_inputs_sleep_.GetSleepTime(&sleep_time) ||
          // usleep throws error is sleeping more than 1 second
          sleep_time > 1000000) {
        if (sleep_time > 1000000) {
          LOG_ERROR(
              "Already slept too long (" +
              Itoa(read_inputs_sleep_.GetTotalSleptTime()) +
              "microseconds), aborting.");
        }
        SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
        if (debug_) StopTimer(&parse_global_inputs_timer_);
        return false;
      }
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::ASLEEP);
      read_metadata_for_inputs_sleep_time_ += sleep_time;
      usleep((useconds_t) sleep_time);
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::ACTIVE);
    }
  }
  read_inputs_sleep_.Reset();

  if (filename.empty()) {
    return ParseGlobalInputsInternal(inputs, is_done);
  }
  return ParseGlobalInputsInternal(filename, is_done);
}

bool CircuitByGate::ParseGlobalInput(
    const set<OutputWireLocation>& targets, const GenericValue& value) {
  // For BOOL inputs that have non-bool target gates, 'value' will be setting
  // a bit of the target input wire. We'll need to know if we should set that
  // bit to 0 or 1 (based on 'value'); since we may need to do this multiple
  // times, we'll go ahead and parse 'value' as a bit now, so that we don't
  // have to do this for every output target.
  bool value_is_one = false;
  if (value.type_ == DataType::BOOL) {
    value_is_one = GetValue<bool>(*((const BoolDataType*) value.value_.get()));
  }

  // Store value at all relevant wires.
  for (const OutputWireLocation& loc : targets) {
    const int bit_index = GetBitIndex(loc);
    if (bit_index >= 0) {
      if (bit_index >= (int) (sizeof(uint64_t) * CHAR_BIT)) {
        LOG_ERROR("Invalid bit index.");
        return false;
      }
      // Two cases when bit_index is set:
      //   a) The input is of type BOOL, and the target gate is type Arithmetic
      //   b) The input is non-BOOL, and target gate is Bool
      // Toggle based on this.
      if (value.type_ == DataType::BOOL) {
        // Case (a). Grab the DataType of the target gate.
        const DataType* target_gate_type =
            FindOrNull(loc.loc_.index_, datatypes_of_arith_from_bool_gates_);
        if (target_gate_type == nullptr) {
          LOG_ERROR("Unexpected BOOL input indicates non-bool target gate, "
                    "which is not in datatypes_of_arith_from_bool_gates_");
          return false;
        }

        // Now set a GenericValue, which has the appropriate type, and only
        // the 'bit_index' bit set.
        const GenericValue value_with_bit_i_set = !value_is_one ?
            GenericValue(*target_gate_type, (uint64_t) 0) :
            (IsSignedDataType(*target_gate_type) ?
                 GenericValue(
                     *target_gate_type,
                     (int64_t) (((uint64_t) 1) << bit_index)) :
                 GenericValue(*target_gate_type, ((uint64_t) 1) << bit_index));
        // If already an entry in [left | right]_input_values_,
        // update that value; otherwise add a new entry.
        map<GateIndexDataType, GenericValue>& input_value_map =
            loc.loc_.is_left_ ? left_input_values_ : right_input_values_;
        pair<map<GateIndexDataType, GenericValue>::iterator, bool> insert_info =
            input_value_map.insert(
                make_pair(loc.loc_.index_, value_with_bit_i_set));
        if (!insert_info.second) {
          // That gate (input wire) already had a bit set. Update value.
          insert_info.first->second += value_with_bit_i_set;
        }
      } else {
        // Case (b). Grab bit at bit_index.
        if (bit_index >= (int) GetValueNumBits(value)) {
          LOG_ERROR("Invalid bit index.");
          return false;
        }
        const GenericValue bit_i(GetBit(bit_index, value));
        if (loc.loc_.is_left_) {
          left_input_values_.insert(make_pair(loc.loc_.index_, bit_i));
        } else {
          right_input_values_.insert(make_pair(loc.loc_.index_, bit_i));
        }
      }
    } else {
      if (loc.loc_.is_left_) {
        left_input_values_.insert(make_pair(loc.loc_.index_, value));
      } else {
        right_input_values_.insert(make_pair(loc.loc_.index_, value));
      }
    }
  }

  return true;
}

bool CircuitByGate::ParseGlobalInputsInternal(
    const string& filename, bool* is_done) {
  ifstream input_file(filename.c_str());
  if (!input_file.is_open()) {
    SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
    if (debug_) StopTimer(&parse_global_inputs_timer_);
    LOG_ERROR("Unable to find input file '" + filename + "'.");
    return false;
  }

  int line_num = 0;
  size_t current_input_index = -1;
  int64_t num_new_inputs_parsed = 0;
  string orig_line, line;
  while (getline(input_file, orig_line)) {
    if (is_done != nullptr) {
      if (parse_inputs_thread_num_tasks_until_context_switch_ > 0 &&
          num_new_inputs_parsed >=
              2 * parse_inputs_thread_num_tasks_until_context_switch_) {
        SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::PAUSED);
        if (debug_) StopTimer(&parse_global_inputs_timer_);
        *is_done = false;
        return true;
      }
    }

    line_num++;
    RemoveWindowsTrailingCharacters(&orig_line);
    line = RemoveAllWhitespace(orig_line);
    if (line.empty() || HasPrefixString(line, "#")) continue;
    ++current_input_index;
    if (current_input_index < num_global_inputs_parsed_) continue;

    // Grab DataType of this input from inputs_.
    if (current_input_index >= inputs_.size()) {
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
      if (debug_) StopTimer(&parse_global_inputs_timer_);
      LOG_ERROR("Too many inputs.");
      return false;
    }
    const GlobalInputInfo& input_info = inputs_[current_input_index];

    // Parse line. Two possible formats:
    //   (DataType) Value
    //   Value
    DataType input_type = input_info.type_;
    GenericValue value;
    if (HasPrefixString(line, "(")) {
      // Split line into the DataType and Value parts.
      vector<string> parts;
      Split(line, ")", &parts);
      if (parts.size() != 2) {
        SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
        if (debug_) StopTimer(&parse_global_inputs_timer_);
        LOG_ERROR("Unable to parse input: '" + line + "'");
        return false;
      }
      // Parse DataType.
      input_type = StringToDataType(parts[0].substr(1));
      if (input_type == DataType::UNKNOWN) {
        LOG_ERROR(
            "Unable to parse '" + parts[0].substr(1) + "' as a valid DataType.");
      } else if (input_type != input_info.type_) {
        SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
        if (debug_) StopTimer(&parse_global_inputs_timer_);
        LOG_ERROR("Unexpected DataType of global input");
        return false;
      }
      // Parse Value.
      if (!ParseGenericValue(input_type, parts[1], &value)) {
        SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
        if (debug_) StopTimer(&parse_global_inputs_timer_);
        LOG_ERROR(
            "Unable to parse '" + parts[1] + "' as a " +
            GetDataTypeString(input_type));
        return false;
      }
    } else {
      // Parse Value.
      if (!ParseGenericValue(input_type, line, &value)) {
        SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
        if (debug_) StopTimer(&parse_global_inputs_timer_);
        LOG_ERROR(
            "Unable to parse '" + line + "' as a " +
            GetDataTypeString(input_type));
        return false;
      }
    }

    if (!ParseGlobalInput(input_info.to_, value)) {
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
      if (debug_) StopTimer(&parse_global_inputs_timer_);
      return false;
    }
    ++num_global_inputs_parsed_;
    ++num_new_inputs_parsed;
  }
  input_file.close();

  if (num_global_inputs_parsed_ != inputs_.size()) {
    LOG_ERROR(
        "Values for all inputs not found in input file: " +
        Itoa(num_global_inputs_parsed_) + " values found, " +
        Itoa(inputs_.size()) + " values expected.");
    SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
    if (debug_) StopTimer(&parse_global_inputs_timer_);
    return false;
  }

  done_global_inputs_file_ = true;
  SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::DONE);
  if (debug_) StopTimer(&parse_global_inputs_timer_);
  return true;
}

bool CircuitByGate::ParseGlobalInputsInternal(
    const vector<math_utils::GenericValue>& inputs, bool* is_done) {
  int64_t num_new_inputs_parsed = 0;
  for (size_t current_input_index = num_global_inputs_parsed_;
       current_input_index < inputs.size();
       ++current_input_index) {
    const GenericValue& value = inputs[current_input_index];
    if (is_done != nullptr) {
      if (parse_inputs_thread_num_tasks_until_context_switch_ > 0 &&
          num_new_inputs_parsed >=
              2 * parse_inputs_thread_num_tasks_until_context_switch_) {
        SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::PAUSED);
        if (debug_) StopTimer(&parse_global_inputs_timer_);
        *is_done = false;
        return true;
      }
    }

    // Grab DataType of this input from inputs_.
    if (current_input_index >= inputs_.size()) {
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
      if (debug_) StopTimer(&parse_global_inputs_timer_);
      LOG_ERROR("Too many inputs.");
      return false;
    }

    const GlobalInputInfo& input_info = inputs_[current_input_index];
    if (value.type_ != input_info.type_) {
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
      if (debug_) StopTimer(&parse_global_inputs_timer_);
      LOG_ERROR("Unexpected DataType of global input");
      return false;
    }

    if (!ParseGlobalInput(input_info.to_, value)) {
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
      if (debug_) StopTimer(&parse_global_inputs_timer_);
      return false;
    }
    ++num_global_inputs_parsed_;
    ++num_new_inputs_parsed;
  }

  if (num_global_inputs_parsed_ != inputs_.size()) {
    LOG_ERROR(
        "Values for all inputs not found in input file: " +
        Itoa(num_global_inputs_parsed_) + " values found, " +
        Itoa(inputs_.size()) + " values expected.");
    SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
    if (debug_) StopTimer(&parse_global_inputs_timer_);
    return false;
  }

  done_global_inputs_file_ = true;
  SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::DONE);
  if (debug_) StopTimer(&parse_global_inputs_timer_);
  return true;
}

bool CircuitByGate::StoreOutputValue(
    const bool is_boolean_value,
    const vector<OutputWireLocation>& output_wires,
    GenericValue& output_value) {
  for (const OutputWireLocation& loc : output_wires) {
    const int bit_index = GetBitIndex(loc);
    const bool child_has_opposite_type = bit_index >= 0;
    GenericValue* value_ptr = &output_value;
    GenericValue alternate_value;
    bool value_as_bit;
    if (child_has_opposite_type) {
      if (is_boolean_value) {
        value_as_bit =
            GetValue<bool>(*((const BoolDataType*) output_value.value_.get()));
      } else {
        if (bit_index >= (int) GetValueNumBits(output_value)) {
          return false;
        }
        alternate_value = GenericValue(GetBit(bit_index, output_value));
      }
      value_ptr = &alternate_value;
    }

    if (loc.loc_.is_left_) {
      if (child_has_opposite_type && is_boolean_value) {
        DataType* type_of_child =
            FindOrNull(loc.loc_.index_, datatypes_of_arith_from_bool_gates_);
        if (type_of_child == nullptr) LOG_FATAL("Incomplete gate info.");
        const int num_bits_in_data_type = (int) GetValueNumBits(*type_of_child);
        const int num_bytes_in_data_type =
            (int) GetValueNumBytes(*type_of_child);
        vector<unsigned char>* byte_string = FindOrInsert(
            loc.loc_.index_,
            left_bool_to_arith_values_,
            vector<unsigned char>());
        if (byte_string->empty()) {
          byte_string->resize(num_bytes_in_data_type, 0);
        }
        if (value_as_bit) {
          const int byte_index =
              num_bytes_in_data_type - 1 - bit_index / CHAR_BIT;
          const int pos_within_byte = bit_index % CHAR_BIT;
          (*byte_string)[byte_index] =
              (unsigned char) ((*byte_string)[byte_index] ^ (1 << pos_within_byte));
          if (IsSignedDataType(*type_of_child) &&
              bit_index == (num_bits_in_data_type - 1)) {
            for (int high_bit = pos_within_byte + 1; high_bit < CHAR_BIT;
                 ++high_bit) {
              (*byte_string)[byte_index] =
                  (unsigned char) ((*byte_string)[byte_index] ^ (1 << high_bit));
            }
          }
        }
      } else {
        // Store value in left_values_, if possible.
        if (left_values_.NumPushed() > loc.loc_.index_) {
          left_values_[loc.loc_.index_ - left_values_.NumPopped()] = *value_ptr;
        } else {
          left_overflow_values_.insert(make_pair(loc.loc_.index_, *value_ptr));
        }
      }
    } else {
      if (child_has_opposite_type && is_boolean_value) {
        DataType* type_of_child =
            FindOrNull(loc.loc_.index_, datatypes_of_arith_from_bool_gates_);
        if (type_of_child == nullptr) LOG_FATAL("Incomplete gate info.");
        const int num_bits_in_data_type = (int) GetValueNumBits(*type_of_child);
        const int num_bytes_in_data_type =
            (int) GetValueNumBytes(*type_of_child);
        vector<unsigned char>* byte_string = FindOrInsert(
            loc.loc_.index_,
            right_bool_to_arith_values_,
            vector<unsigned char>());
        if (byte_string->empty()) {
          byte_string->resize(num_bytes_in_data_type, 0);
        }
        if (value_as_bit) {
          const int byte_index =
              num_bytes_in_data_type - 1 - bit_index / CHAR_BIT;
          const int pos_within_byte = bit_index % CHAR_BIT;
          (*byte_string)[byte_index] =
              (unsigned char) ((*byte_string)[byte_index] ^ (1 << pos_within_byte));
          if (IsSignedDataType(*type_of_child) &&
              bit_index == (num_bits_in_data_type - 1)) {
            for (int high_bit = pos_within_byte + 1; high_bit < CHAR_BIT;
                 ++high_bit) {
              (*byte_string)[byte_index] =
                  (unsigned char) ((*byte_string)[byte_index] ^ (1 << high_bit));
            }
          }
        }
      } else {
        // Store value in right_values_, if possible.
        if (right_values_.NumPushed() > loc.loc_.index_) {
          right_values_[loc.loc_.index_ - right_values_.NumPopped()] =
              *value_ptr;
        } else {
          right_overflow_values_.insert(make_pair(loc.loc_.index_, *value_ptr));
        }
      }
    }
  }
  return true;
}

bool CircuitByGate::EvaluateCircuit(
    const bool by_gate,
    const bool should_send,
    const bool should_receive,
    GmwByGate* parent,
    bool (*eval_gate_fn_ptr)(
        GmwByGate*,
        const bool,
        const bool,
        const bool,
        const CircuitOperation,
        const vector<char>&,
        const GenericValue&,
        const GenericValue&,
        bool*,
        GenericValue*),
    bool (*eval_level_fn_ptr)(GmwByGate*, const bool, const bool, const bool),
    bool* is_done) {
  if (debug_) StartTimer(&evaluate_gates_timer_);
  if (parent == nullptr) {
    // Return if already done (NOTE: We do this check *inside* the parent == nullptr
    // check, as for the case EvaluateCircuit() is called with parent != nullptr,
    // the calling code should have already checked this.
    if (num_gates_ > 0 && num_gates_ == num_gates_processed_) {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::DONE);
      if (is_done != nullptr) *is_done = true;
      if (debug_) StopTimer(&evaluate_gates_timer_);
      return true;
    }
    SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);

    // First check things that need to happen before evaluation starts
    // (Number of Gates, Global Input Mappings, Global Input Values) are done.
    while (!is_circuit_file_inputs_read_) {
      if (is_done != nullptr) {
        *is_done = false;
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::PAUSED);
        if (debug_) StopTimer(&evaluate_gates_timer_);
        return true;
      }
      // Sanity-check progress is being made on the things not yet done that
      // we are waiting for.
      if (!IsProgressBeingMade(
              SleepReason::EVAL_FOR_INPUT_INFO,
              GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE),
              ThreadStatus::UNKNOWN, /* Not Used */
              ThreadStatus::UNKNOWN, /* Not Used */
              nullptr /* Not Used */)) {
        // Re-check is_circuit_file_inputs_read_, on the off-chance this
        // has been set to true since the check in the while loop condition.
        if (is_circuit_file_inputs_read_) break;
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        if (debug_) StopTimer(&evaluate_gates_timer_);
        LOG_ERROR(
            "Circuit File reading thread is not active: " +
            Itoa(static_cast<int>(
                GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE))));
        return false;
      }
      uint64_t sleep_time;
      if (!evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
          // usleep throws error is sleeping more than 1 second
          sleep_time > 1000000) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        if (debug_) StopTimer(&evaluate_gates_timer_);
        if (sleep_time > 1000000) {
          LOG_ERROR(
              "Already slept too long (" +
              Itoa(evaluate_gates_sleep_.GetTotalSleptTime()) +
              "microseconds), aborting.");
        }
        return false;
      }
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
      read_metadata_for_eval_sleep_time_ += sleep_time;
      usleep((useconds_t) sleep_time);
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
    }
    // Now check that all global inputs have been read.
    // NOTE: Circuit evaluation does not require that *all* global inputs have been
    // read, only that *enough* have been read to evaluate the gates that depend
    // on them. For example, I used to have the following check that enough
    // inputs had been processed in order to guarantee gates could be evaluated:
    //   if (eval_gates_thread_num_tasks_until_context_switch_ > 0 &&
    //       2 * eval_gates_thread_num_tasks_until_context_switch_ <=
    //           left_input_values_.size() + right_input_values_.size() +
    //           left_constant_input_.size() + right_constant_input_.size())
    // However, if we allow both ParseGlobalInputs() AND EvaluateCircuit()
    // to access/modify [left | right]_input_values_ at the same time, then there
    // are concurrency hiccups (e.g. C++ reallocates space and copies over the
    // map(s) as more items are added, which de-legitimizes an existing pointer
    // to a value that EvaluateCircuit() has just looked up). Turns out, these
    // concurrency issues can happen with non-negligible probability; so go
    // ahead and wait for all inputs to be read before proceeding with gate evaluation.
    while (!done_global_inputs_file_) {
      if (is_done != nullptr) {
        *is_done = false;
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::PAUSED);
        if (debug_) StopTimer(&evaluate_gates_timer_);
        return true;
      }
      // Sanity-check progress is being made on the things not yet done that
      // we are waiting for.
      int num_parse_inputs_sleeps = -1;
      if (!IsProgressBeingMade(
              SleepReason::EVAL_FOR_INPUT_PARSING,
              ThreadStatus::UNKNOWN, /* Not Used */
              GetThreadStatus(CircuitByGateTask::PARSE_INPUTS),
              ThreadStatus::UNKNOWN, /* Not Used */
              &num_parse_inputs_sleeps)) {
        // Re-check is_circuit_file_inputs_read_, on the off-chance this
        // has been set to true since the check in the while loop condition.
        if (done_global_inputs_file_) break;
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        if (debug_) StopTimer(&evaluate_gates_timer_);
        LOG_ERROR(
            "Input parsing thread is not active: " +
            Itoa(static_cast<int>(
                GetThreadStatus(CircuitByGateTask::PARSE_INPUTS))));
        return false;
      }
      uint64_t sleep_time;
      if (!evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
          // usleep throws error is sleeping more than 1 second
          sleep_time > 1000000) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        if (debug_) StopTimer(&evaluate_gates_timer_);
        if (sleep_time > 1000000) {
          LOG_ERROR(
              "Already slept too long (" +
              Itoa(evaluate_gates_sleep_.GetTotalSleptTime()) +
              "microseconds), aborting.");
        }
        return false;
      }
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
      read_inputs_for_eval_sleep_time_ += sleep_time;
      usleep((useconds_t) sleep_time);
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
    }
  } else if (eval_gate_fn_ptr == nullptr) {
    if (debug_) StopTimer(&evaluate_gates_timer_);
    LOG_ERROR("Bad usage: If calling from GMW, function pointer to "
              "Gmw::EvaluateGate() must be non-null.");
    return false;
  }

  evaluate_gates_sleep_.Reset();

  if (by_gate) {
    return EvaluateCircuitByGate(
        should_send, should_receive, parent, eval_gate_fn_ptr, is_done);
  } else {
    return EvaluateCircuitByLevel(
        should_send,
        should_receive,
        parent,
        eval_gate_fn_ptr,
        eval_level_fn_ptr,
        is_done);
  }
}

bool CircuitByGate::EvaluateCircuitByGate(
    const bool should_send,
    const bool should_receive,
    GmwByGate* parent,
    bool (*eval_gate_fn_ptr)(
        GmwByGate*,
        const bool,
        const bool,
        const bool,
        const CircuitOperation,
        const vector<char>&,
        const GenericValue&,
        const GenericValue&,
        bool*,
        GenericValue*),
    bool* is_done) {
  // Evaluate Gates. Evaluation should proceed until:
  //   a) (Done) All gates have been evaluated; OR
  //   b) (Memory) eval_gates_thread_num_tasks_until_context_switch_ gates have been
  //      evaluated (since the last context switch); OR
  //   c) (Concurrency) Unable to evaluate more gates due to not enough
  //      global inputs having been read
  GateIndexDataType current_batch_num_gates_evaluated = 0;
  Gate current_gate;
  while (num_gates_processed_ < num_gates_) {
    // Check stopping condition (b).
    if (current_batch_num_gates_evaluated ==
        eval_gates_thread_num_tasks_until_context_switch_) {
      if (is_done != nullptr) {
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::PAUSED);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::PAUSED);
        }
        *is_done = false;
      } else {
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        }
        LOG_ERROR("Flags indicate to stop parsing gates, but not done yet.");
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      return is_done != nullptr;
    }

    // Evaluate Gate:
    //   1) Extract Gate Info (gate op and whether it can be computed locally)
    //      from gates_
    //   2) Read Input wire values:
    //       a) First check values in the evaluated gates queue: [left | right]_values_
    //       b) Next check global inputs: [left | right]_[constant_]input_[values_]
    //       c) Next check overflow: [left | right]_overflow_values_
    //   3) Evaluate Gate.
    //   4) Store output value at all appropriate places.
    //   5) Update counters.
    // Do (1).
    if (num_threads_ > 1 ||
        (parent != nullptr && parent->GetNumThreads() >= 3)) {
      // Grab gate info from gates_. Note that since we are in the case of multiple
      // threads, it is possible to reach here before the gate info has been
      // added to gates_. Rather than call the ReadWriteQueue's PopOrSleep(), we
      // manually check if the Pop() is successful, and if not, determine what to
      // do based on the progress that other threads are (or aren't) making.
      int num_read_circuit_file_sleeps = -1;
      while (!gates_.Pop(&current_gate)) {
        const ThreadStatus status = parent == nullptr ?
            GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE) :
            parent->GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE);
        if (!IsProgressBeingMade(
                SleepReason::EVAL_FOR_GATE_INFO,
                status,
                ThreadStatus::UNKNOWN, /* Not Used */
                ThreadStatus::UNKNOWN, /* Not Used */
                &num_read_circuit_file_sleeps)) {
          // Check once more that there aren't any gates in gates_.
          if (gates_.Pop(&current_gate)) break;
          if (parent != nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          } else {
            SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          }
          if (debug_) StopTimer(&evaluate_gates_timer_);
          LOG_ERROR(
              "No gates ready to be evaluated, and thread reading gate "
              "info has status: " +
              Itoa(static_cast<int>(status)));
          return false;
        }
        uint64_t sleep_time;
        if (!evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          if (parent != nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          } else {
            SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          }
          if (debug_) StopTimer(&evaluate_gates_timer_);
          if (sleep_time > 1000000) {
            LOG_ERROR(
                "Already slept too long (" +
                Itoa(evaluate_gates_sleep_.GetTotalSleptTime()) +
                "microseconds), aborting.");
          }
          return false;
        }
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        }
        read_gates_for_eval_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
        }
      }
      evaluate_gates_sleep_.Reset();
    } else if (!gates_.Pop(&current_gate)) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR(
          "Gate " + Itoa(num_gates_processed_) + " not ready to be evaluated.");
      return false;
    }
    evaluate_gates_sleep_.Reset();
    // Do (2).
    GenericValue left_value, right_value;
    bool is_mult_by_const = false;
    // Do (2a): First check evaluated gates queues for values.
    if (!left_values_.Pop(&left_value) || !right_values_.Pop(&right_value)) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR(
          "Unable to get input wire values during gate evaluation of "
          "gate " +
          Itoa(num_gates_processed_) + ". This should never happen.");
      return false;
    }
    // Do (2b) and (2c) for left wire, if necessary.
    if (left_value.type_ == DataType::UNKNOWN) {
      GenericValue* left_value_ptr =
          FindOrNull(num_gates_processed_, left_input_values_);
      if (left_value_ptr != nullptr) {
        left_value = *left_value_ptr;
        left_input_values_.erase(num_gates_processed_);
        // In order to respect GMW invariant of values on input wires (namely,
        // that values on input wires are shared *between parties involved
        // in computation of the gate*, we may need to readjust the input
        // value for the party whose input this is.
        if (parent != nullptr && !current_gate.depends_on_.empty()) {
          set<tuple<int, int, int>>* input_locations =
              FindOrNull(num_gates_processed_, left_input_wire_to_party_index_);
          if (input_locations == nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
            if (debug_) StopTimer(&evaluate_gates_timer_);
            LOG_ERROR(
                "Unable to get party index of input wire of gate " +
                Itoa(num_gates_processed_) + ". This should never happen.");
            return false;
          }
          for (const tuple<int, int, int>& input_loc : *input_locations) {
            if (get<0>(input_loc) == parent->GetSelfPartyIndex()) {
              parent->AdjustInputValue(
                  get<1>(input_loc),
                  get<2>(input_loc),
                  current_gate.depends_on_,
                  &left_value);
            }
          }
        }
      } else {
        left_value_ptr = FindOrNull(num_gates_processed_, left_constant_input_);
        if (left_value_ptr != nullptr) {
          left_value = *left_value_ptr;
          left_constant_input_.erase(num_gates_processed_);
          // Left-input wire is constant. For GMW applications, we may need
          // to update the constant value being used, as per convention
          // (see discussion item (2) at top of gmw_circuit.h).
          if (parent != nullptr) {
            const int party_index = parent->GetSelfPartyIndex();
            if (current_gate.op_ == CircuitOperation::IDENTITY) {
              // Handle the special case that the gate is IDENTITY (which by
              // convention, since the gate wasn't removed during circuit
              // building/reduction, means all output wires of this gate are
              // global outputs). In this case, all Parties except Party 0
              // should use input value '0', and Party 0 should use value '1'.
              if (party_index > 0)
                left_value = GenericValue(left_value.type_, (uint64_t) 0);
            } else if (current_gate.op_ == CircuitOperation::MULT) {
              is_mult_by_const = true;
              // For MULT, all parties involved in the gate computation get
              // the constant value, all other parties get '0'.
              if (!GateDependsOn(party_index, current_gate.depends_on_)) {
                left_value = GenericValue(left_value.type_, (uint64_t) 0);
              }
            } else {
              // For all other gate types, the lowest party index gets the
              // constant value, all other parties get '0'.
              if (party_index !=
                  GetLowestDependentPartyIndex(current_gate.depends_on_)) {
                left_value = GenericValue(left_value.type_, (uint64_t) 0);
              }
            }
          }
        } else {
          if ((left_overflow_values_.empty() ||
               left_overflow_values_.begin()->first != num_gates_processed_) &&
              (left_bool_to_arith_values_.empty() ||
               left_bool_to_arith_values_.begin()->first !=
                   num_gates_processed_)) {
            // No value available for the left input wire. This could be an
            // error, or it could happen in case multi-threading separated
            // tasks of reading global inputs and evaulating gates, and the
            // former thread is slower than the latter.
            int num_parse_inputs_sleeps = -1;
            while (!done_global_inputs_file_ && left_value_ptr == nullptr) {
              if (!IsProgressBeingMade(
                      SleepReason::EVAL_FOR_INPUT_PARSING,
                      ThreadStatus::UNKNOWN, /* Not Used */
                      (parent == nullptr ?
                           GetThreadStatus(CircuitByGateTask::PARSE_INPUTS) :
                           ThreadStatus::UNKNOWN),
                      ThreadStatus::UNKNOWN, /* Not Used */
                      &num_parse_inputs_sleeps)) {
                // Re-check done_global_inputs_file_)
                if (done_global_inputs_file_) continue;
                if (parent != nullptr) {
                  parent->SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                } else {
                  SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                }
                if (debug_) StopTimer(&evaluate_gates_timer_);
                LOG_ERROR(
                    "Input parsing thread is not active: " +
                    Itoa(static_cast<int>(
                        GetThreadStatus(CircuitByGateTask::PARSE_INPUTS))));
                return false;
              }
              uint64_t sleep_time;
              if (!evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
                  // usleep throws error is sleeping more than 1 second
                  sleep_time > 1000000) {
                if (parent != nullptr) {
                  parent->SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                } else {
                  SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                }
                if (debug_) StopTimer(&evaluate_gates_timer_);
                if (sleep_time > 1000000) {
                  LOG_ERROR(
                      "Already slept too long (" +
                      Itoa(evaluate_gates_sleep_.GetTotalSleptTime()) +
                      "microseconds), aborting.");
                }
                return false;
              }
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
              }
              read_inputs_for_eval_sleep_time_ += sleep_time;
              usleep((useconds_t) sleep_time);
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
              }
              left_value_ptr =
                  FindOrNull(num_gates_processed_, left_input_values_);
            }
            evaluate_gates_sleep_.Reset();
            if (left_value_ptr == nullptr) {
              // It is possible that the above while loop was abandoned because
              // done_global_inputs_file_, and left_value_ptr was not updated.
              // Give it one more chance to find it.
              if (done_global_inputs_file_) {
                left_value_ptr =
                    FindOrNull(num_gates_processed_, left_input_values_);
              }
            }
            if (left_value_ptr == nullptr) {
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              }
              if (debug_) StopTimer(&evaluate_gates_timer_);
              LOG_ERROR(
                  "Unable to find a value for left input wire during "
                  "gate evaluation at gate index: " +
                  Itoa(num_gates_processed_));
              return false;
            }
            left_value = *left_value_ptr;
            left_input_values_.erase(num_gates_processed_);
            evaluate_gates_sleep_.Reset();
          } else if (
              left_overflow_values_.empty() ||
              left_overflow_values_.begin()->first != num_gates_processed_) {
            DataType* gate_data_type = FindOrNull(
                num_gates_processed_, datatypes_of_arith_from_bool_gates_);
            if (gate_data_type == nullptr ||
                !ParseGenericValueFromTwosComplementString(
                    *gate_data_type,
                    left_bool_to_arith_values_.begin()->second,
                    &left_value)) {
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              }
              if (debug_) StopTimer(&evaluate_gates_timer_);
              LOG_ERROR("Unable to parse bool to arith value.");
              return false;
            }
            left_bool_to_arith_values_.erase(left_bool_to_arith_values_.begin());
          } else {
            left_value = left_overflow_values_.begin()->second;
            left_overflow_values_.erase(left_overflow_values_.begin());
          }
        }
      }
    }
    // Do (2b) and (2c) for right wire, if necessary.
    if (!IsSingleInputOperation(current_gate.op_) &&
        right_value.type_ == DataType::UNKNOWN) {
      GenericValue* right_value_ptr =
          FindOrNull(num_gates_processed_, right_input_values_);
      if (right_value_ptr != nullptr) {
        right_value = *right_value_ptr;
        right_input_values_.erase(num_gates_processed_);
        // In order to respect GMW invariant of values on input wires (namely,
        // that values on input wires are shared *between parties involved
        // in computation of the gate*, we may need to readjust the input
        // value for the party whose input this is.
        if (parent != nullptr && !current_gate.depends_on_.empty()) {
          set<tuple<int, int, int>>* input_locations =
              FindOrNull(num_gates_processed_, right_input_wire_to_party_index_);
          if (input_locations == nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
            if (debug_) StopTimer(&evaluate_gates_timer_);
            LOG_ERROR(
                "Unable to get party index of input wire of gate " +
                Itoa(num_gates_processed_) + ". This should never happen.");
            return false;
          }
          for (const tuple<int, int, int>& input_loc : *input_locations) {
            if (get<0>(input_loc) == parent->GetSelfPartyIndex()) {
              parent->AdjustInputValue(
                  get<1>(input_loc),
                  get<2>(input_loc),
                  current_gate.depends_on_,
                  &right_value);
            }
          }
        }
      } else {
        right_value_ptr =
            FindOrNull(num_gates_processed_, right_constant_input_);
        if (right_value_ptr != nullptr) {
          right_value = *right_value_ptr;
          right_constant_input_.erase(num_gates_processed_);
          // Right-input wire is constant. For GMW applications, we may need
          // to update the constant value being used, as per convention
          // (see discussion item (2) at top of gmw_circuit.h).
          if (parent != nullptr) {
            const int party_index = parent->GetSelfPartyIndex();
            if (current_gate.op_ == CircuitOperation::MULT) {
              is_mult_by_const = true;
              // For MULT, all parties involved in the gate computation get
              // the constant value, all other parties get '0'.
              if (!GateDependsOn(party_index, current_gate.depends_on_)) {
                right_value = GenericValue(right_value.type_, (uint64_t) 0);
              }
            } else {
              // For all other gate types, the lowest party index gets the
              // constant value, all other parties get '0'.
              if (party_index !=
                  GetLowestDependentPartyIndex(current_gate.depends_on_)) {
                right_value = GenericValue(right_value.type_, (uint64_t) 0);
              }
            }
          }
        } else {
          if ((right_overflow_values_.empty() ||
               right_overflow_values_.begin()->first != num_gates_processed_) &&
              (right_bool_to_arith_values_.empty() ||
               right_bool_to_arith_values_.begin()->first !=
                   num_gates_processed_)) {
            // No value available for the right input wire. This could be an
            // error, or it could happen in case multi-threading separated
            // tasks of reading global inputs and evaulating gates, and the
            // former thread is slower than the latter.
            int num_parse_inputs_sleeps = -1;
            while (!done_global_inputs_file_ && right_value_ptr == nullptr) {
              if (!IsProgressBeingMade(
                      SleepReason::EVAL_FOR_INPUT_PARSING,
                      ThreadStatus::UNKNOWN, /* Not Used */
                      (parent == nullptr ?
                           GetThreadStatus(CircuitByGateTask::PARSE_INPUTS) :
                           ThreadStatus::UNKNOWN),
                      ThreadStatus::UNKNOWN, /* Not Used */
                      &num_parse_inputs_sleeps)) {
                // Re-check done_global_inputs_file_)
                if (done_global_inputs_file_) continue;
                if (parent != nullptr) {
                  parent->SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                } else {
                  SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                }
                if (debug_) StopTimer(&evaluate_gates_timer_);
                LOG_ERROR(
                    "Input parsing thread is not active: " +
                    Itoa(static_cast<int>(
                        GetThreadStatus(CircuitByGateTask::PARSE_INPUTS))));
                return false;
              }
              uint64_t sleep_time;
              if (!evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
                  // usleep throws error is sleeping more than 1 second
                  sleep_time > 1000000) {
                if (parent != nullptr) {
                  parent->SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                } else {
                  SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                }
                if (debug_) StopTimer(&evaluate_gates_timer_);
                if (sleep_time > 1000000) {
                  LOG_ERROR(
                      "Already slept too long (" +
                      Itoa(evaluate_gates_sleep_.GetTotalSleptTime()) +
                      "microseconds), aborting.");
                }
                return false;
              }
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
              }
              read_inputs_for_eval_sleep_time_ += sleep_time;
              usleep((useconds_t) sleep_time);
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
              }
              right_value_ptr =
                  FindOrNull(num_gates_processed_, right_input_values_);
            }
            evaluate_gates_sleep_.Reset();
            if (right_value_ptr == nullptr) {
              // It is possible that the above while loop was abandoned because
              // done_global_inputs_file_, and right_value_ptr was not updated.
              // Give it one more chance to find it.
              if (done_global_inputs_file_) {
                right_value_ptr =
                    FindOrNull(num_gates_processed_, right_input_values_);
              }
            }
            if (right_value_ptr == nullptr) {
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              }
              if (debug_) StopTimer(&evaluate_gates_timer_);
              LOG_ERROR(
                  "Unable to find a value for right input wire during "
                  "gate evaluation at gate index: " +
                  Itoa(num_gates_processed_));
              return false;
            }
            right_value = *right_value_ptr;
            right_input_values_.erase(num_gates_processed_);
            evaluate_gates_sleep_.Reset();
          } else if (
              right_overflow_values_.empty() ||
              right_overflow_values_.begin()->first != num_gates_processed_) {
            DataType* gate_data_type = FindOrNull(
                num_gates_processed_, datatypes_of_arith_from_bool_gates_);
            if (gate_data_type == nullptr ||
                !ParseGenericValueFromTwosComplementString(
                    *gate_data_type,
                    right_bool_to_arith_values_.begin()->second,
                    &right_value)) {
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              }
              if (debug_) StopTimer(&evaluate_gates_timer_);
              LOG_ERROR("Unable to parse bool to arith value.");
              return false;
            }
            right_bool_to_arith_values_.erase(
                right_bool_to_arith_values_.begin());
          } else {
            right_value = right_overflow_values_.begin()->second;
            right_overflow_values_.erase(right_overflow_values_.begin());
          }
        }
      }
    }
    // Do (3).
    GenericValue output_value;
    if (parent == nullptr &&
        !EvaluateGate(
            current_gate.op_, left_value, right_value, &output_value)) {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      if (debug_) StopTimer(&evaluate_gates_timer_);
      return false;
    } else if (parent != nullptr) {
      if (debug_) StopTimer(&evaluate_gates_timer_);
      const bool result = eval_gate_fn_ptr(
          parent,
          should_send,
          should_receive,
          is_mult_by_const,
          current_gate.op_,
          current_gate.depends_on_,
          left_value,
          right_value,
          nullptr,
          &output_value);
      if (!result) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        return false;
      }
      if (debug_) StartTimer(&evaluate_gates_timer_);
    }
    if (kPrintGateEvalInfo) {
      LOG_INFO(
          "Gate " + Itoa(num_gates_processed_) + ": " +
          GetGenericValueString(left_value) + " " +
          GetOpString(current_gate.op_) + " " +
          GetGenericValueString(right_value) + " = " +
          GetGenericValueString(output_value));
    }
    // Do (4).
    if (!StoreOutputValue(
            IsBooleanOperation(current_gate.op_),
            current_gate.output_wires_,
            output_value)) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR("Invalid bit index.");
    }
    // Do (5).
    ++num_gates_processed_;
    ++current_batch_num_gates_evaluated;
  }

  // The fact that we reached here means all gates have been evaluated
  // (as opposed to aborting early due to other stopping conditions; see
  // (b) and (c) above). Check that the number of unused values exactly
  // equals num_outputs_, and fill global_outputs_.
  global_outputs_.reserve(num_outputs_);
  GateIndexDataType num_outputs_found = 0;
  // First, grab values from left_values_.
  while (num_outputs_found < num_outputs_ && !left_values_.empty()) {
    GenericValue value;
    if (!left_values_.Pop(&value)) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR("Unable to pop value from non-empty queue. This should "
                "never happen");
      return false;
    }
    global_outputs_.push_back(value);
    ++num_outputs_found;
  }
  if (!left_values_.empty()) {
    if (parent != nullptr) {
      parent->SetThreadStatus(
          CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
    } else {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
    }
    if (debug_) StopTimer(&evaluate_gates_timer_);
    LOG_ERROR("Found too many outputs.");
    return false;
  }
  global_outputs_.resize(num_outputs_);
  // Next, grab outputs that may have been put into left_overflow_values_ and/or
  // left_bool_to_arith_values_ (necessary 'left', as global outputs are always
  // marked as 'left' wire).
  for (const pair<const GateIndexDataType, GenericValue>& itr :
       left_overflow_values_) {
    const GateIndexDataType output_index = itr.first - num_gates_;
    if (num_outputs_found >= num_outputs_ || output_index >= num_outputs_) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR("Found too many outputs.");
      return false;
    }
    global_outputs_[output_index] = itr.second;
    ++num_outputs_found;
  }
  for (const pair<const GateIndexDataType, vector<unsigned char>>& itr :
       left_bool_to_arith_values_) {
    const GateIndexDataType output_index = itr.first - num_gates_;
    DataType* output_type =
        FindOrNull(itr.first, datatypes_of_arith_from_bool_gates_);
    if (num_outputs_found >= num_outputs_ || output_index >= num_outputs_ ||
        output_type == nullptr ||
        !ParseGenericValueFromTwosComplementString(
            *output_type, itr.second, &(global_outputs_[output_index]))) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR("Found too many outputs.");
      return false;
    }
    ++num_outputs_found;
  }
  if (num_outputs_found != num_outputs_) {
    if (parent != nullptr) {
      parent->SetThreadStatus(
          CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
    } else {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
    }
    if (debug_) StopTimer(&evaluate_gates_timer_);
    LOG_ERROR(
        "Found too few outputs: " + Itoa(num_outputs_found) + " found, " +
        Itoa(num_outputs_) + " expected.");
    return false;
  }

  if (parent != nullptr) {
    parent->SetThreadStatus(
        CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::DONE);
  } else {
    SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::DONE);
  }
  if (debug_) StopTimer(&evaluate_gates_timer_);
  if (is_done != nullptr) *is_done = true;

  return true;
}

bool CircuitByGate::EvaluateCircuitByLevel(
    const bool should_send,
    const bool should_receive,
    GmwByGate* parent,
    bool (*eval_gate_fn_ptr)(
        GmwByGate*,
        const bool,
        const bool,
        const bool,
        const CircuitOperation,
        const vector<char>&,
        const GenericValue&,
        const GenericValue&,
        bool*,
        GenericValue*),
    bool (*eval_level_fn_ptr)(GmwByGate*, const bool, const bool, const bool),
    bool* is_done) {
  // Sanity-check level information is present.
  if (num_levels_ == 0 || num_levels_ != num_gates_per_level_.size()) {
    LOG_ERROR("Circuit file does not support by-level evaluation.");
    return false;
  }

  // Initialize (reserve space) for the data structure that will hold
  // preliminary gate information.
  if (parent != nullptr) {
    parent->InitializePrelimGateEvalDataHolder(num_levels_processed_);
  }

  // Evaluate Gates. Evaluation should proceed until:
  //   a) (Done) All gates have been evaluated; OR
  //   b) (Memory) eval_gates_thread_num_tasks_until_context_switch_ gates have been
  //      evaluated (since the last context switch); OR
  //   c) (Concurrency) Unable to evaluate more gates due to not enough
  //      global inputs having been read
  GateIndexDataType current_batch_num_gates_evaluated = 0;
  Gate current_gate;
  while (num_gates_processed_ < num_gates_) {
    // Check stopping condition (b).
    if (current_batch_num_gates_evaluated ==
        eval_gates_thread_num_tasks_until_context_switch_) {
      if (is_done != nullptr) {
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::PAUSED);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::PAUSED);
        }
        *is_done = false;
      } else {
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        }
        LOG_ERROR("Flags indicate to stop parsing gates, but not done yet.");
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      return is_done != nullptr;
    }

    // Evaluate Gate:
    //   1) Extract Gate Info (gate op and whether it can be computed locally)
    //      from gates_
    //   2) Read Input wire values:
    //       a) First check values in the evaluated gates queue: [left | right]_values_
    //       b) Next check global inputs: [left | right]_[constant_]input_[values_]
    //       c) Next check overflow: [left | right]_overflow_values_
    //   3) Evaluate Gate.
    //   4) Store output value at all appropriate places.
    //   5) Update counters.
    // Do (1).
    if (num_threads_ > 1 ||
        (parent != nullptr && parent->GetNumThreads() >= 3)) {
      // Grab gate info from gates_. Note that since we are in the case of multiple
      // threads, it is possible to reach here before the gate info has been
      // added to gates_. Rather than call the ReadWriteQueue's PopOrSleep(), we
      // manually check if the Pop() is successful, and if not, determine what to
      // do based on the progress that other threads are (or aren't) making.
      int num_read_circuit_file_sleeps = -1;
      while (!gates_.Pop(&current_gate)) {
        const ThreadStatus status = parent == nullptr ?
            GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE) :
            parent->GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE);
        if (!IsProgressBeingMade(
                SleepReason::EVAL_FOR_GATE_INFO,
                status,
                ThreadStatus::UNKNOWN, /* Not Used */
                ThreadStatus::UNKNOWN, /* Not Used */
                &num_read_circuit_file_sleeps)) {
          // Check once more that there aren't any gates in gates_.
          if (gates_.Pop(&current_gate)) break;
          if (parent != nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          } else {
            SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          }
          if (debug_) StopTimer(&evaluate_gates_timer_);
          LOG_ERROR(
              "No gates ready to be evaluated, and thread reading gate "
              "info has status: " +
              Itoa(static_cast<int>(status)));
          return false;
        }
        uint64_t sleep_time;
        if (!evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          if (parent != nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          } else {
            SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          }
          if (debug_) StopTimer(&evaluate_gates_timer_);
          if (sleep_time > 1000000) {
            LOG_ERROR(
                "Already slept too long (" +
                Itoa(evaluate_gates_sleep_.GetTotalSleptTime()) +
                "microseconds), aborting.");
          }
          return false;
        }
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        }
        read_gates_for_eval_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
        }
      }
      evaluate_gates_sleep_.Reset();
    } else if (!gates_.Pop(&current_gate)) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR(
          "Gate " + Itoa(num_gates_processed_) + " not ready to be evaluated.");
      return false;
    }
    evaluate_gates_sleep_.Reset();
    // Do (2).
    GenericValue left_value, right_value;
    bool is_mult_by_const = false;
    // Do (2a): First check evaluated gates queues for values.
    if (!left_values_.Pop(&left_value) || !right_values_.Pop(&right_value)) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR(
          "Unable to get input wire values during gate evaluation of "
          "gate " +
          Itoa(num_gates_processed_) + ". This should never happen.");
      return false;
    }
    // Do (2b) and (2c) for left wire, if necessary.
    if (left_value.type_ == DataType::UNKNOWN) {
      GenericValue* left_value_ptr =
          FindOrNull(num_gates_processed_, left_input_values_);
      if (left_value_ptr != nullptr) {
        left_value = *left_value_ptr;
        left_input_values_.erase(num_gates_processed_);
        // In order to respect GMW invariant of values on input wires (namely,
        // that values on input wires are shared *between parties involved
        // in computation of the gate*, we may need to readjust the input
        // value for the party whose input this is.
        if (parent != nullptr && !current_gate.depends_on_.empty()) {
          set<tuple<int, int, int>>* input_locations =
              FindOrNull(num_gates_processed_, left_input_wire_to_party_index_);
          if (input_locations == nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
            if (debug_) StopTimer(&evaluate_gates_timer_);
            LOG_ERROR(
                "Unable to get party index of input wire of gate " +
                Itoa(num_gates_processed_) + ". This should never happen.");
            return false;
          }
          for (const tuple<int, int, int>& input_loc : *input_locations) {
            if (get<0>(input_loc) == parent->GetSelfPartyIndex()) {
              parent->AdjustInputValue(
                  get<1>(input_loc),
                  get<2>(input_loc),
                  current_gate.depends_on_,
                  &left_value);
            }
          }
        }
      } else {
        left_value_ptr = FindOrNull(num_gates_processed_, left_constant_input_);
        if (left_value_ptr != nullptr) {
          left_value = *left_value_ptr;
          left_constant_input_.erase(num_gates_processed_);
          // Left-input wire is constant. For GMW applications, we may need
          // to update the constant value being used, as per convention
          // (see discussion item (2) at top of gmw_circuit.h).
          if (parent != nullptr) {
            const int party_index = parent->GetSelfPartyIndex();
            if (current_gate.op_ == CircuitOperation::IDENTITY) {
              // Handle the special case that the gate is IDENTITY (which by
              // convention, since the gate wasn't removed during circuit
              // building/reduction, means all output wires of this gate are
              // global outputs). In this case, all Parties except Party 0
              // should use input value '0', and Party 0 should use value '1'.
              if (party_index > 0)
                left_value = GenericValue(left_value.type_, (uint64_t) 0);
            } else if (current_gate.op_ == CircuitOperation::MULT) {
              is_mult_by_const = true;
              // For MULT, all parties involved in the gate computation get
              // the constant value, all other parties get '0'.
              if (!GateDependsOn(party_index, current_gate.depends_on_)) {
                left_value = GenericValue(left_value.type_, (uint64_t) 0);
              }
            } else {
              // For all other gate types, the lowest party index gets the
              // constant value, all other parties get '0'.
              if (party_index !=
                  GetLowestDependentPartyIndex(current_gate.depends_on_)) {
                left_value = GenericValue(left_value.type_, (uint64_t) 0);
              }
            }
          }
        } else {
          if ((left_overflow_values_.empty() ||
               left_overflow_values_.begin()->first != num_gates_processed_) &&
              (left_bool_to_arith_values_.empty() ||
               left_bool_to_arith_values_.begin()->first !=
                   num_gates_processed_)) {
            // No value available for the left input wire. This could be an
            // error, or it could happen in case multi-threading separated
            // tasks of reading global inputs and evaulating gates, and the
            // former thread is slower than the latter.
            int num_parse_inputs_sleeps = -1;
            while (!done_global_inputs_file_ && left_value_ptr == nullptr) {
              if (!IsProgressBeingMade(
                      SleepReason::EVAL_FOR_INPUT_PARSING,
                      ThreadStatus::UNKNOWN, /* Not Used */
                      (parent == nullptr ?
                           GetThreadStatus(CircuitByGateTask::PARSE_INPUTS) :
                           ThreadStatus::UNKNOWN),
                      ThreadStatus::UNKNOWN, /* Not Used */
                      &num_parse_inputs_sleeps)) {
                // Re-check done_global_inputs_file_)
                if (done_global_inputs_file_) continue;
                if (parent != nullptr) {
                  parent->SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                } else {
                  SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                }
                if (debug_) StopTimer(&evaluate_gates_timer_);
                LOG_ERROR(
                    "Input parsing thread is not active: " +
                    Itoa(static_cast<int>(
                        GetThreadStatus(CircuitByGateTask::PARSE_INPUTS))));
                return false;
              }
              uint64_t sleep_time;
              if (!evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
                  // usleep throws error is sleeping more than 1 second
                  sleep_time > 1000000) {
                if (parent != nullptr) {
                  parent->SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                } else {
                  SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                }
                if (debug_) StopTimer(&evaluate_gates_timer_);
                if (sleep_time > 1000000) {
                  LOG_ERROR(
                      "Already slept too long (" +
                      Itoa(evaluate_gates_sleep_.GetTotalSleptTime()) +
                      "microseconds), aborting.");
                }
                return false;
              }
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
              }
              read_inputs_for_eval_sleep_time_ += sleep_time;
              usleep((useconds_t) sleep_time);
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
              }
              left_value_ptr =
                  FindOrNull(num_gates_processed_, left_input_values_);
            }
            evaluate_gates_sleep_.Reset();
            if (left_value_ptr == nullptr) {
              // It is possible that the above while loop was abandoned because
              // done_global_inputs_file_, and left_value_ptr was not updated.
              // Give it one more chance to find it.
              if (done_global_inputs_file_) {
                left_value_ptr =
                    FindOrNull(num_gates_processed_, left_input_values_);
              }
            }
            if (left_value_ptr == nullptr) {
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              }
              if (debug_) StopTimer(&evaluate_gates_timer_);
              LOG_ERROR(
                  "Unable to find a value for left input wire during "
                  "gate evaluation at gate index: " +
                  Itoa(num_gates_processed_));
              return false;
            }
            left_value = *left_value_ptr;
            left_input_values_.erase(num_gates_processed_);
            evaluate_gates_sleep_.Reset();
          } else if (
              left_overflow_values_.empty() ||
              left_overflow_values_.begin()->first != num_gates_processed_) {
            DataType* gate_data_type = FindOrNull(
                num_gates_processed_, datatypes_of_arith_from_bool_gates_);
            if (gate_data_type == nullptr ||
                !ParseGenericValueFromTwosComplementString(
                    *gate_data_type,
                    left_bool_to_arith_values_.begin()->second,
                    &left_value)) {
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              }
              if (debug_) StopTimer(&evaluate_gates_timer_);
              LOG_ERROR("Unable to parse bool to arith value.");
              return false;
            }
            left_bool_to_arith_values_.erase(left_bool_to_arith_values_.begin());
          } else {
            left_value = left_overflow_values_.begin()->second;
            left_overflow_values_.erase(left_overflow_values_.begin());
          }
        }
      }
    }
    // Do (2b) and (2c) for right wire, if necessary.
    if (!IsSingleInputOperation(current_gate.op_) &&
        right_value.type_ == DataType::UNKNOWN) {
      GenericValue* right_value_ptr =
          FindOrNull(num_gates_processed_, right_input_values_);
      if (right_value_ptr != nullptr) {
        right_value = *right_value_ptr;
        right_input_values_.erase(num_gates_processed_);
        // In order to respect GMW invariant of values on input wires (namely,
        // that values on input wires are shared *between parties involved
        // in computation of the gate*, we may need to readjust the input
        // value for the party whose input this is.
        if (parent != nullptr && !current_gate.depends_on_.empty()) {
          set<tuple<int, int, int>>* input_locations =
              FindOrNull(num_gates_processed_, right_input_wire_to_party_index_);
          if (input_locations == nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
            if (debug_) StopTimer(&evaluate_gates_timer_);
            LOG_ERROR(
                "Unable to get party index of input wire of gate " +
                Itoa(num_gates_processed_) + ". This should never happen.");
            return false;
          }
          for (const tuple<int, int, int>& input_loc : *input_locations) {
            if (get<0>(input_loc) == parent->GetSelfPartyIndex()) {
              parent->AdjustInputValue(
                  get<1>(input_loc),
                  get<2>(input_loc),
                  current_gate.depends_on_,
                  &right_value);
            }
          }
        }
      } else {
        right_value_ptr =
            FindOrNull(num_gates_processed_, right_constant_input_);
        if (right_value_ptr != nullptr) {
          right_value = *right_value_ptr;
          right_constant_input_.erase(num_gates_processed_);
          // Right-input wire is constant. For GMW applications, we may need
          // to update the constant value being used, as per convention
          // (see discussion item (2) at top of gmw_circuit.h).
          if (parent != nullptr) {
            const int party_index = parent->GetSelfPartyIndex();
            if (current_gate.op_ == CircuitOperation::MULT) {
              is_mult_by_const = true;
              // For MULT, all parties involved in the gate computation get
              // the constant value, all other parties get '0'.
              if (!GateDependsOn(party_index, current_gate.depends_on_)) {
                right_value = GenericValue(right_value.type_, (uint64_t) 0);
              }
            } else {
              // For all other gate types, the lowest party index gets the
              // constant value, all other parties get '0'.
              if (party_index !=
                  GetLowestDependentPartyIndex(current_gate.depends_on_)) {
                right_value = GenericValue(right_value.type_, (uint64_t) 0);
              }
            }
          }
        } else {
          if ((right_overflow_values_.empty() ||
               right_overflow_values_.begin()->first != num_gates_processed_) &&
              (right_bool_to_arith_values_.empty() ||
               right_bool_to_arith_values_.begin()->first !=
                   num_gates_processed_)) {
            // No value available for the right input wire. This could be an
            // error, or it could happen in case multi-threading separated
            // tasks of reading global inputs and evaulating gates, and the
            // former thread is slower than the latter.
            int num_parse_inputs_sleeps = -1;
            while (!done_global_inputs_file_ && right_value_ptr == nullptr) {
              if (!IsProgressBeingMade(
                      SleepReason::EVAL_FOR_INPUT_PARSING,
                      ThreadStatus::UNKNOWN, /* Not Used */
                      (parent == nullptr ?
                           GetThreadStatus(CircuitByGateTask::PARSE_INPUTS) :
                           ThreadStatus::UNKNOWN),
                      ThreadStatus::UNKNOWN, /* Not Used */
                      &num_parse_inputs_sleeps)) {
                // Re-check done_global_inputs_file_)
                if (done_global_inputs_file_) continue;
                if (parent != nullptr) {
                  parent->SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                } else {
                  SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                }
                if (debug_) StopTimer(&evaluate_gates_timer_);
                LOG_ERROR(
                    "Input parsing thread is not active: " +
                    Itoa(static_cast<int>(
                        GetThreadStatus(CircuitByGateTask::PARSE_INPUTS))));
                return false;
              }
              uint64_t sleep_time;
              if (!evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
                  // usleep throws error is sleeping more than 1 second
                  sleep_time > 1000000) {
                if (parent != nullptr) {
                  parent->SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                } else {
                  SetThreadStatus(
                      CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
                }
                if (debug_) StopTimer(&evaluate_gates_timer_);
                if (sleep_time > 1000000) {
                  LOG_ERROR(
                      "Already slept too long (" +
                      Itoa(evaluate_gates_sleep_.GetTotalSleptTime()) +
                      "microseconds), aborting.");
                }
                return false;
              }
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
              }
              read_inputs_for_eval_sleep_time_ += sleep_time;
              usleep((useconds_t) sleep_time);
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
              }
              right_value_ptr =
                  FindOrNull(num_gates_processed_, right_input_values_);
            }
            evaluate_gates_sleep_.Reset();
            if (right_value_ptr == nullptr) {
              // It is possible that the above while loop was abandoned because
              // done_global_inputs_file_, and right_value_ptr was not updated.
              // Give it one more chance to find it.
              if (done_global_inputs_file_) {
                right_value_ptr =
                    FindOrNull(num_gates_processed_, right_input_values_);
              }
            }
            if (right_value_ptr == nullptr) {
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              }
              if (debug_) StopTimer(&evaluate_gates_timer_);
              LOG_ERROR(
                  "Unable to find a value for right input wire during "
                  "gate evaluation at gate index: " +
                  Itoa(num_gates_processed_));
              return false;
            }
            right_value = *right_value_ptr;
            right_input_values_.erase(num_gates_processed_);
            evaluate_gates_sleep_.Reset();
          } else if (
              right_overflow_values_.empty() ||
              right_overflow_values_.begin()->first != num_gates_processed_) {
            DataType* gate_data_type = FindOrNull(
                num_gates_processed_, datatypes_of_arith_from_bool_gates_);
            if (gate_data_type == nullptr ||
                !ParseGenericValueFromTwosComplementString(
                    *gate_data_type,
                    right_bool_to_arith_values_.begin()->second,
                    &right_value)) {
              if (parent != nullptr) {
                parent->SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              } else {
                SetThreadStatus(
                    CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
              }
              if (debug_) StopTimer(&evaluate_gates_timer_);
              LOG_ERROR("Unable to parse bool to arith value.");
              return false;
            }
            right_bool_to_arith_values_.erase(
                right_bool_to_arith_values_.begin());
          } else {
            right_value = right_overflow_values_.begin()->second;
            right_overflow_values_.erase(right_overflow_values_.begin());
          }
        }
      }
    }
    // Do (3).
    GenericValue output_value;
    bool store_result = true;
    if (parent == nullptr &&
        !EvaluateGate(
            current_gate.op_, left_value, right_value, &output_value)) {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      if (debug_) StopTimer(&evaluate_gates_timer_);
      return false;
    } else if (parent != nullptr) {
      if (debug_) StopTimer(&evaluate_gates_timer_);
      const bool eval_gate_result = eval_gate_fn_ptr(
          parent,
          should_send,
          should_receive,
          is_mult_by_const,
          current_gate.op_,
          current_gate.depends_on_,
          left_value,
          right_value,
          &store_result,
          &output_value);
      if (!eval_gate_result) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        return false;
      }
      if (debug_) StartTimer(&evaluate_gates_timer_);
    }
    if (kPrintGateEvalInfo) {
      LOG_INFO(
          "Gate " + Itoa(num_gates_processed_) + ": " +
          GetGenericValueString(left_value) + " " +
          GetOpString(current_gate.op_) + " " +
          GetGenericValueString(right_value) + " = " +
          GetGenericValueString(output_value));
    }
    // Do (4).
    if (parent == nullptr || store_result) {
      // The 'output_value' computed by EvaluateGate() above is the actual/
      // final output value; go ahead an store it on all output wires.
      if (!StoreOutputValue(
              IsBooleanOperation(current_gate.op_),
              current_gate.output_wires_,
              output_value)) {
        if (parent != nullptr) {
          parent->SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        } else {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        }
        if (debug_) StopTimer(&evaluate_gates_timer_);
        LOG_ERROR("Failed to store output value.");
        return false;
      }
    } else {
      parent->StorePrelimGateInfo(
          IsBooleanOperation(current_gate.op_),
          current_gate.output_wires_,
          output_value);
    }
    // EvalGate only did local stuff, as we're waiting to batch together
    // all communication. Check and see if we're done with the level.
    if (parent != nullptr &&
        num_curr_level_gates_processed_ + 1 ==
            num_gates_per_level_[num_levels_processed_]) {
      if (debug_) StopTimer(&evaluate_gates_timer_);
      const bool eval_level_result = eval_level_fn_ptr(
          parent,
          IsBooleanOperation(current_gate.op_),
          should_send,
          should_receive);
      if (!eval_level_result) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        return false;
      }
      if (debug_) StartTimer(&evaluate_gates_timer_);
      num_curr_level_gates_processed_ = 0;
      ++num_levels_processed_;
      if (num_levels_processed_ < num_levels_) {
        parent->InitializePrelimGateEvalDataHolder(num_levels_processed_);
      }
    } else {
      ++num_curr_level_gates_processed_;
    }
    // Do (5).
    ++num_gates_processed_;
    ++current_batch_num_gates_evaluated;
  }

  // TODO(paul): All code below is identical to the ByGate case. Merge them
  // (likely by not having EvalCircuit() return immediately after calling the
  // subroutine EvalCircuitBy[Level,Gate], but instead doing the post-
  // processing stuff below.
  //
  // The fact that we reached here means all gates have been evaluated
  // (as opposed to aborting early due to other stopping conditions; see
  // (b) and (c) above). Check that the number of unused values exactly
  // equals num_outputs_, and fill global_outputs_.
  global_outputs_.reserve(num_outputs_);
  GateIndexDataType num_outputs_found = 0;
  // First, grab values from left_values_.
  while (num_outputs_found < num_outputs_ && !left_values_.empty()) {
    GenericValue value;
    if (!left_values_.Pop(&value)) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR("Unable to pop value from non-empty queue. This should "
                "never happen");
      return false;
    }
    // Store value in global outputs.
    // NOTE: The stored datatype may NOT match the target (output) datatype.
    // This is ok, so long as the stored datatype can be cast as the desired
    // datatype (e.g. we're not trying to cast a value > 1 into a bool).
    const DataType output_type =
        output_designations_[global_outputs_.size()].second;
    if (value.type_ != output_type) {
      if (IsSignedDataType(value.type_)) {
        int64_t as_signed_int;
        if (!GetSignedIntegerValue(value, &as_signed_int)) {
          if (parent != nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          } else {
            SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          }
          if (debug_) StopTimer(&evaluate_gates_timer_);
          LOG_ERROR("Unable to cast output value as appropriate datatype.");
          return false;
        }
        global_outputs_.push_back(GenericValue(output_type, as_signed_int));
      } else {
        uint64_t as_unsigned_int;
        if (!GetUnsignedIntegerValue(value, &as_unsigned_int)) {
          if (parent != nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          } else {
            SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          }
          if (debug_) StopTimer(&evaluate_gates_timer_);
          LOG_ERROR("Unable to cast output value as appropriate datatype.");
          return false;
        }
        global_outputs_.push_back(GenericValue(output_type, as_unsigned_int));
      }
    } else {
      global_outputs_.push_back(value);
    }
    ++num_outputs_found;
  }
  if (!left_values_.empty()) {
    if (parent != nullptr) {
      parent->SetThreadStatus(
          CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
    } else {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
    }
    if (debug_) StopTimer(&evaluate_gates_timer_);
    LOG_ERROR("Found too many outputs.");
    return false;
  }
  global_outputs_.resize(num_outputs_);
  // Next, grab outputs that may have been put into left_overflow_values_ and/or
  // left_bool_to_arith_values_ (necessary 'left', as global outputs are always
  // marked as 'left' wire).
  for (const pair<const GateIndexDataType, GenericValue>& itr :
       left_overflow_values_) {
    const GateIndexDataType output_index = itr.first - num_gates_;
    if (num_outputs_found >= num_outputs_ || output_index >= num_outputs_) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR("Found too many outputs.");
      return false;
    }
    // Store value in global outputs.
    // NOTE: The stored datatype may NOT match the target (output) datatype.
    // This is ok, so long as the stored datatype can be cast as the desired
    // datatype (e.g. we're not trying to cast a value > 1 into a bool).
    const DataType output_type = output_designations_[output_index].second;
    const GenericValue& value = itr.second;
    if (value.type_ != output_type) {
      if (IsSignedDataType(value.type_)) {
        int64_t as_signed_int;
        if (!GetSignedIntegerValue(value, &as_signed_int)) {
          if (parent != nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          } else {
            SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          }
          if (debug_) StopTimer(&evaluate_gates_timer_);
          LOG_ERROR("Unable to cast output value as appropriate datatype.");
          return false;
        }
        global_outputs_[output_index] = GenericValue(output_type, as_signed_int);
      } else {
        uint64_t as_unsigned_int;
        if (!GetUnsignedIntegerValue(value, &as_unsigned_int)) {
          if (parent != nullptr) {
            parent->SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          } else {
            SetThreadStatus(
                CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          }
          if (debug_) StopTimer(&evaluate_gates_timer_);
          LOG_ERROR("Unable to cast output value as appropriate datatype.");
          return false;
        }
        global_outputs_[output_index] =
            GenericValue(output_type, as_unsigned_int);
      }
    } else {
      global_outputs_[output_index] = value;
    }
    ++num_outputs_found;
  }
  for (const pair<const GateIndexDataType, vector<unsigned char>>& itr :
       left_bool_to_arith_values_) {
    const GateIndexDataType output_index = itr.first - num_gates_;
    DataType* output_type =
        FindOrNull(itr.first, datatypes_of_arith_from_bool_gates_);
    if (num_outputs_found >= num_outputs_ || output_index >= num_outputs_ ||
        output_type == nullptr ||
        !ParseGenericValueFromTwosComplementString(
            *output_type, itr.second, &(global_outputs_[output_index]))) {
      if (parent != nullptr) {
        parent->SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      } else {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      }
      if (debug_) StopTimer(&evaluate_gates_timer_);
      LOG_ERROR("Found too many outputs.");
      return false;
    }
    ++num_outputs_found;
  }
  if (num_outputs_found != num_outputs_) {
    if (parent != nullptr) {
      parent->SetThreadStatus(
          CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
    } else {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
    }
    if (debug_) StopTimer(&evaluate_gates_timer_);
    LOG_ERROR(
        "Found too few outputs: " + Itoa(num_outputs_found) + " found, " +
        Itoa(num_outputs_) + " expected.");
    return false;
  }

  if (parent != nullptr) {
    parent->SetThreadStatus(
        CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::DONE);
  } else {
    SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::DONE);
  }
  if (debug_) StopTimer(&evaluate_gates_timer_);
  if (is_done != nullptr) *is_done = true;

  return true;
}

string CircuitByGate::PrintTimerInfo() const {
  string to_return = "";
  const int meaningful_ms = 10;
  const int64_t parse_global_inputs_time =
      GetElapsedTime(parse_global_inputs_timer_) / 1000;
  if (parse_global_inputs_time / 1000 > 0 ||
      parse_global_inputs_time % 1000 > meaningful_ms) {
    to_return += "  parse_global_inputs_timer_: " +
        test_utils::FormatTime(parse_global_inputs_time) + "\n";
  }
  const int64_t read_circuit_file_time =
      GetElapsedTime(read_circuit_file_timer_) / 1000;
  if (read_circuit_file_time / 1000 > 0 ||
      read_circuit_file_time % 1000 > meaningful_ms) {
    to_return += "  read_circuit_file_timer_: " +
        test_utils::FormatTime(read_circuit_file_time) + "\n";
  }
  const int64_t evaluate_gates_time =
      GetElapsedTime(evaluate_gates_timer_) / 1000;
  if (evaluate_gates_time / 1000 > 0 ||
      evaluate_gates_time % 1000 > meaningful_ms) {
    to_return += "  evaluate_gates_timer_: " +
        test_utils::FormatTime(evaluate_gates_time) + "\n";
  }

  // Print Sleep Timers.
  to_return += "  Sleep Times:\n";
  to_return += "    read_metadata_for_do_all_sleep_time_: " +
      test_utils::FormatTime(read_metadata_for_do_all_sleep_time_ / 1000) + "\n";
  to_return += "    read_metadata_for_inputs_sleep_time_: " +
      test_utils::FormatTime(read_metadata_for_inputs_sleep_time_ / 1000) + "\n";
  to_return += "    read_metadata_for_eval_sleep_time_: " +
      test_utils::FormatTime(read_metadata_for_eval_sleep_time_ / 1000) + "\n";
  to_return += "    read_inputs_for_eval_sleep_time_: " +
      test_utils::FormatTime(read_inputs_for_eval_sleep_time_ / 1000) + "\n";
  to_return += "    read_gates_for_eval_sleep_time_: " +
      test_utils::FormatTime(read_gates_for_eval_sleep_time_ / 1000) + "\n";
  to_return += "    max_gates_sleep_time_: " +
      test_utils::FormatTime(max_gates_sleep_time_) + "\n";

  if (to_return.empty()) {
    return "";
  }
  return "CircuitByGate Timers:\n" + to_return;
}

bool CircuitByGate::PrintOutputs(const string& filename) const {
  if (filename.empty()) {
    return false;
  }
  ofstream out;
  out.open(filename);
  if (!out.is_open()) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }
  for (const GenericValue& output_i : global_outputs_) {
    out << GetGenericValueString(output_i) << endl;
  }
  if (debug_) {
    out << "Timer Info:\n" << PrintTimerInfo() << endl;
  }
  out.close();

  return true;
}

bool CircuitByGate::WriteCircuitFile(const string& filename) const {
  if (filename.empty()) {
    return false;
  }
  // Open output file for writing.
  if (!CreateDir(GetDirectory(filename))) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }
  ofstream out;
  out.open(filename);
  if (!out.is_open()) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }

  // Write Circuit Metadata (Function Description, Num Gates, Input Mappings, etc.)
  //   - Item (a): Function Fingerprint.
  out << PrintFunction(
      false, function_var_names_, output_designations_, function_description_);
  out << endl << endl;
  //   - Items (b) - (d): Circuit size, num non-local (Bool, Arith) gates, num outputs.
  out << kNumGatesKeyword << " " << num_gates_ << ";" << endl;
  out << kNumNonLocalBoolKeyword << " "
      << JoinValues<GateIndexDataType>(
             num_non_local_boolean_gates_per_party_pairs_, ",")
      << ";" << endl;
  out << kNumGatesPerLevelKeyword << " "
      << JoinValues<GateIndexDataType>(num_gates_per_level_, ",") << ";" << endl;
  out << kNumNonLocalArithKeyword << " "
      << JoinValues<GateIndexDataType>(
             num_non_local_arithmetic_gates_per_party_pairs_, ",")
      << ";" << endl;
  out << kNumOutputsKeyword << " " << num_outputs_ << ";" << endl;
  //   - Item (e): List of Arith Gates that have a Bool input gate.
  out << kArithGatesFromBoolGatesKeyword << endl;
  bool is_first_output = true;
  for (const pair<const GateIndexDataType, DataType>& output_itr :
       datatypes_of_arith_from_bool_gates_) {
    if (!is_first_output) out << ",";
    is_first_output = false;
    out << output_itr.first << ":" << static_cast<int>(output_itr.second);
  }
  out << ";" << endl;
  //   - Item (f): Input mappings.
  // Since inputs_ stores things based on input index (as opposed to grouped
  // by party), we first run through it, and gather things by party.
  int party_input_index = 0;
  int current_party = 0;
  for (size_t i = 0; i < inputs_.size(); ++i) {
    if (i == 0) out << endl << kPartyInputsKeyword << " (0):" << endl;
    // Figure out if this is a new Party's input.
    if (current_party >= (int) function_var_names_.size()) {
      LOG_ERROR(
          "At input " + Itoa(i) + ", current party index (" +
          Itoa(current_party) + ") exceeds the number of expected parties (" +
          Itoa(function_var_names_.size()) + ")");
      return false;
    }
    int num_current_party_inputs =
        (int) function_var_names_[current_party].size();
    while (party_input_index >= num_current_party_inputs) {
      if (party_input_index == 0) out << ";" << endl;
      party_input_index = 0;
      ++current_party;
      if (current_party >= (int) function_var_names_.size()) {
        LOG_ERROR(
            "At input " + Itoa(i) + ", current party index (" +
            Itoa(current_party) + ") exceeds the number of expected parties (" +
            Itoa(function_var_names_.size()) + ")");
        return false;
      }
      num_current_party_inputs = (int) function_var_names_[current_party].size();
      out << endl
          << kPartyInputsKeyword << " (" << current_party << "):" << endl;
    }
    ++party_input_index;
    const GlobalInputInfo& input_info = inputs_[i];
    const string* data_type_string =
        FindOrNull(input_info.type_, kDataTypeToString);
    if (data_type_string == nullptr) {
      return false;
    }
    out << "(" << *data_type_string << ")";
    bool is_first = true;
    for (const OutputWireLocation& loc : input_info.to_) {
      if (!is_first) out << ",";
      is_first = false;
      out << (loc.loc_.is_left_ ? "L" : "R") << loc.loc_.index_;
      const int bit_index = GetBitIndex(loc);
      if (bit_index >= 0) {
        out << ":" << bit_index;
      }
    }
    out << ";" << endl;
  }
  // For corner-case that there are extra parties (who don't have any inputs),
  // write keyword for these parties' inputs (with empty lines below, indicating
  // no actual inputs).
  for (int i = current_party + 1; i < (int) function_var_names_.size(); ++i) {
    out << endl
        << kPartyInputsKeyword << " (" << i << "):" << endl
        << ";" << endl;
  }
  //   - Item (g): Constant global inputs.
  // A little work must be done for constant inputs, as they are stored in
  // a manner that is opposite to how we need to write them.
  map<GenericValue, set<InputWireLocation>> constants;
  for (const pair<const GateIndexDataType, GenericValue>& input :
       left_constant_input_) {
    set<InputWireLocation>* targets =
        FindOrInsert(input.second, constants, set<InputWireLocation>());
    targets->insert(InputWireLocation(true, input.first));
  }
  for (const pair<const GateIndexDataType, GenericValue>& input :
       right_constant_input_) {
    set<InputWireLocation>* targets =
        FindOrInsert(input.second, constants, set<InputWireLocation>());
    targets->insert(InputWireLocation(false, input.first));
  }
  out << endl << kConstantGatesKeyword << endl;
  bool is_first_constant = true;
  for (const pair<const GenericValue, set<InputWireLocation>>& targets :
       constants) {
    if (!is_first_constant) {
      out << ";" << endl;
    }
    is_first_constant = false;
    const string* data_type_string =
        FindOrNull(targets.first.type_, kDataTypeToString);
    if (data_type_string == nullptr) {
      return false;
    }
    out << "(" << *data_type_string << ")";
    out << GetGenericValueString(targets.first);
    bool is_first = true;
    for (const InputWireLocation& loc : targets.second) {
      if (!is_first) out << ",";
      is_first = false;
      out << (loc.is_left_ ? "L" : "R") << loc.index_;
    }
  }
  out << ";" << endl;

  // Write Gates Block (gate op and output wirings).
  out << endl << kGateInfoKeyword << endl;
  for (GateIndexDataType i = 0; i < gates_.size(); ++i) {
    const Gate& gate = gates_[i];

    // GATE_OP.
    out << static_cast<int>(gate.op_) << ";";

    // DEPENDS_ON.
    if (gate.depends_on_.empty()) {
      const int num_parties = (int) function_var_names_.size();
      const int depends_on_size =
          (int) (num_parties / CHAR_BIT + ((num_parties % CHAR_BIT == 0) ? 0 : 1));
      const unsigned char depends_on_all_byte = -1;  // 11111111
      const unsigned char depends_on_all_last_byte =
          (unsigned char) ((num_parties % CHAR_BIT == 0) ? depends_on_all_byte : (depends_on_all_byte ^ (depends_on_all_byte >> (num_parties % CHAR_BIT))));
      for (int i = 0; i < depends_on_size - 1; ++i) {
        out << depends_on_all_byte;
      }
      out << depends_on_all_last_byte;
    } else {
      for (const char depends_on_i : gate.depends_on_) {
        out << depends_on_i;
      }
    }
    out << ";";

    // (Left, Right, Global) Outputs.
    vector<pair<GateIndexDataType, unsigned char>> left_outputs;
    vector<pair<GateIndexDataType, unsigned char>> right_outputs;
    vector<pair<GateIndexDataType, unsigned char>> global_outputs;
    for (const OutputWireLocation& loc : gate.output_wires_) {
      if (loc.loc_.is_left_) {
        if (loc.loc_.index_ < num_gates_) {
          left_outputs.push_back(make_pair(loc.loc_.index_, loc.bit_index_));
        } else {
          global_outputs.push_back(
              make_pair(loc.loc_.index_ - num_gates_, loc.bit_index_));
        }
      } else {
        right_outputs.push_back(make_pair(loc.loc_.index_, loc.bit_index_));
      }
    }
    bool is_first = true;
    for (const pair<GateIndexDataType, unsigned char>& index : left_outputs) {
      if (!is_first) out << ",";
      is_first = false;
      out << index.first;
      if (index.second & kBitIndexMask) {
        out << ":" << (index.second & ~(kBitIndexMask));
      }
    }
    out << ";";
    is_first = true;
    for (const pair<GateIndexDataType, unsigned char>& index : right_outputs) {
      if (!is_first) out << ",";
      is_first = false;
      out << index.first;
      if (index.second & kBitIndexMask) {
        out << ":" << (index.second & ~(kBitIndexMask));
      }
    }
    out << ";";
    is_first = true;
    for (const pair<GateIndexDataType, unsigned char>& index : global_outputs) {
      if (!is_first) out << ",";
      is_first = false;
      out << index.first;
      if (index.second & kBitIndexMask) {
        out << ":" << (index.second & ~(kBitIndexMask));
      }
    }
    out << "|";
  }

  out.close();
  return true;
}

void CircuitByGate::SetCircuitFilename(const string& filename) {
  if (!FileExists(filename)) {
    circuit_filename_ = string(kCircuitFileDir) + filename;
  }

  // If it doesn't exist with the prefix either, just default to use what
  // was specified, and deal with error later.
  if (!FileExists(circuit_filename_)) {
    circuit_filename_ = filename;
  }
}

bool CircuitByGate::DoAll(
    const string& inputs_file,
    const vector<GenericValue>& inputs,
    const string& outputs_file) {
  bool read_inputs_is_done = false;
  bool read_circuit_file_is_done = false;
  bool evaluate_gates_is_done = false;

  // Parallelize based on number of threads available on the system.
  // TODO(paul): What if not all system threads are available (so NumCores()
  // reports too high a value), and/or a thread doing some task gets
  // prempted by system to start working on another task?
  if (num_threads_ == 1) {
    // Read Circuit File metadata.
    if (!ReadCircuitFile(&read_circuit_file_is_done)) {
      return false;
    }

    // Cycle through reading circuit file, reading global inputs, and evaluating gates.
    while (!read_circuit_file_is_done || !read_inputs_is_done ||
           !evaluate_gates_is_done) {
      if (!ReadCircuitFile(&read_circuit_file_is_done) ||
          !ParseGlobalInputs(inputs_file, inputs, &read_inputs_is_done) ||
          !EvaluateCircuit(&evaluate_gates_is_done)) {
        return false;
      }
    }
  } else if (num_threads_ == 2) {
    thread_status_.insert(make_pair(
        CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::UNSTARTED));
    thread_status_.insert(
        make_pair(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::UNSTARTED));
    thread_status_.insert(
        make_pair(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::UNSTARTED));
    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    unique_ptr<ThreadParams> read_circuit_thread(CreateThreadParams());
    // Start the thread for reading the circuit file.
    ReadCircuitFileCallbackParams params(nullptr, this);
    t->StartThread(
        (void*) &ReadCircuitFileCallback, &params, read_circuit_thread.get());

    // First, wait for circuit file reading thread to finish reading metadata.
    while (!is_circuit_file_inputs_read_) {
      if (!IsProgressBeingMade(
              SleepReason::PARSE_INPUTS_FOR_INPUT_INFO,
              GetThreadStatus(CircuitByGateTask::READ_CIRCUIT_FILE),
              ThreadStatus::UNKNOWN, /* Not Used */
              ThreadStatus::UNKNOWN, /* Not Used */
              nullptr /* Not Used */)) {
        // Re-check is_circuit_file_inputs_read_, on the off-chance this
        // has been set to true since the check in the while loop condition.
        if (is_circuit_file_inputs_read_) break;
        return false;
      }
      uint64_t sleep_time;
      if (!read_inputs_sleep_.GetSleepTime(&sleep_time) ||
          // usleep throws error is sleeping more than 1 second
          sleep_time > 1000000) {
        if (sleep_time > 1000000) {
          LOG_ERROR(
              "Already slept too long (" +
              Itoa(read_inputs_sleep_.GetTotalSleptTime()) +
              "microseconds), aborting.");
        }
        return false;
      }
      read_metadata_for_do_all_sleep_time_ += sleep_time;
      usleep((useconds_t) sleep_time);
    }
    read_inputs_sleep_.Reset();

    // Now, have the main thread cycle between parsing global inputs and evaluating gates.
    while (!read_inputs_is_done || !evaluate_gates_is_done) {
      if (!ParseGlobalInputs(inputs_file, inputs, &read_inputs_is_done) ||
          !EvaluateCircuit(&evaluate_gates_is_done)) {
        return false;
      }
    }
    // EvaluateCircuit(), done by the main thread, will necessarily be done
    // when code reaches here, which also means that ReadCircuitFile(),
    // which was done by the helper thread, is also necessarily done.
    // So this wait is extraneous, but we do it anyway for keeping true to
    // the thread standard: CreateThread, StartThread, WaitForThread.
    t->WaitForThread(read_circuit_thread.get());
    if (!read_circuit_thread->exit_code_set_ ||
        read_circuit_thread->exit_code_ != 0) {
      LOG_ERROR(
          "Thread for reading circuit file aborted with exit code: " +
          Itoa(read_circuit_thread->exit_code_));
      return false;
    }
  } else {
    thread_status_.insert(make_pair(
        CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::UNSTARTED));
    thread_status_.insert(
        make_pair(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::UNSTARTED));
    thread_status_.insert(
        make_pair(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::UNSTARTED));
    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    unique_ptr<ThreadParams> read_circuit_thread(CreateThreadParams());
    unique_ptr<ThreadParams> eval_circuit_thread(CreateThreadParams());
    // Start a thread for reading the circuit file.
    ReadCircuitFileCallbackParams read_params(nullptr, this);
    t->StartThread(
        (void*) &ReadCircuitFileCallback,
        &read_params,
        read_circuit_thread.get());
    // Start a thread for evaluating the circuit file.
    EvaluateCircuitCallbackParams eval_params(nullptr, this);
    t->StartThread(
        (void*) &EvaluateCircuitCallback,
        &eval_params,
        eval_circuit_thread.get());
    // Have the main thread parse the global inputs.
    if (!ParseGlobalInputs(inputs_file, inputs, nullptr)) {
      return false;
    }
    // Wait for the other tasks to complete.
    t->WaitForThread(read_circuit_thread.get());
    if (!read_circuit_thread->exit_code_set_ ||
        read_circuit_thread->exit_code_ != 0) {
      LOG_ERROR(
          "Thread for reading circuit file aborted with exit code: " +
          Itoa(read_circuit_thread->exit_code_));
      return false;
    }
    t->WaitForThread(eval_circuit_thread.get());
    if (!eval_circuit_thread->exit_code_set_ ||
        eval_circuit_thread->exit_code_ != 0) {
      LOG_ERROR(
          "Thread for reading circuit file aborted with exit code: " +
          Itoa(eval_circuit_thread->exit_code_));
      return false;
    }
  }

  if (!outputs_file.empty()) {
    return PrintOutputs(outputs_file);
  }
  return true;
}

}  // namespace multiparty_computation
}  // namespace crypto
