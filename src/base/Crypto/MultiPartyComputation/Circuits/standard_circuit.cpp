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

#include "standard_circuit.h"

#include "FileReaderUtils/read_file_utils.h"
#include "MapUtils/map_utils.h"  // For FindOrInsert()
#include "MathUtils/constants.h"  // For slice
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "MathUtils/formula_utils.h"  // For Formula.
#include "circuit_utils.h"  // For OutputRecipient.
#include "global_utils.h"

#include <fstream>
#include <map>

using namespace math_utils;
using namespace map_utils;
using namespace file_reader_utils;
using namespace string_utils;
using namespace std;

namespace crypto {
namespace multiparty_computation {

namespace {

static const char kCircuitMetadataFunction[] = "Circuit Function:";
static const char kCircuitMetadataCommonTerms[] = "Common Terms:";
static const char kCircuitMetadataPartyInputs[] = "Party Inputs";
static const char kCircuitMetadataOutputFilename[] = "Output:";

// Parses specification of an indexed variable:
//   {VARNAME}_START^FINISH
// where VARNAME is an arbitrary string and [START, END] give the indices
// this variable takes; e.g. {x}_1^5.
bool ParseVariableNameWithIndex(
    const string& input, int* start, int* end, string* var_base) {
  string temp;
  if (!StripPrefixString(input, "{", &temp)) {
    return false;
  }

  vector<string> parts;
  Split(temp, "}_", &parts);
  if (parts.size() != 2) {
    return false;
  }
  *var_base = parts[0];

  vector<string> rhs_parts;
  Split(parts[1], "^", &rhs_parts);
  if (rhs_parts.size() != 2 || !Stoi(rhs_parts[0], start) ||
      !Stoi(rhs_parts[1], end)) {
    return false;
  }
  if (*start < 0 || *end < *start) {
    return false;
  }

  return true;
}

// Subroutine of LoadCircuit: Parses a line of the .function or .circuit file
// that represents one of the party's inputs.
bool ParseInputLine(
    const string& line,
    vector<GenericValue>* input_values,
    vector<pair<string, DataType>>* input_var_types) {
  if (input_var_types == nullptr) {
    return true;
  }

  // Split out data values, if present.
  vector<string> value_parts;
  Split(line, ":", &value_parts);
  if (value_parts.empty() || value_parts.size() > 2) {
    LOG_ERROR("Unexpected Input line: '" + line + "'");
    return false;
  }
  if (!HasPrefixString(value_parts[0], "(")) {
    LOG_ERROR("Unexpected Input line: '" + line + "'");
    return false;
  }
  const string lhs = StripPrefixString(value_parts[0], "(");

  // Split out DataType and Variable Name.
  vector<string> parts;
  Split(lhs, ")", &parts);
  if (parts.size() != 2) {
    LOG_ERROR("Unexpected Input line: '" + line + "'");
    return false;
  }

  // Parse DataType.
  const DataType type = StringToDataType(parts[0]);
  if (type == DataType::UNKNOWN) {
    LOG_ERROR(
        "Unable to parse '" + parts[0] + "' as a DataType (from line: '" + line +
        "').");
    return false;
  }

  // Store variable name.
  // NOTE: We don't simply just use parts[1] here, as we need to support variable
  // indexing subscripts.
  vector<string> variables(1, parts[1]);
  if (HasPrefixString(parts[1], "{")) {
    int start_index, end_index;
    string var_base = "";
    if (!ParseVariableNameWithIndex(
            parts[1], &start_index, &end_index, &var_base)) {
      LOG_ERROR(
          "Unable to parse variable name with indexing subscript:\n" + parts[1]);
      return false;
    }
    variables.resize(1 + end_index - start_index);
    for (int index = start_index; index <= end_index; ++index) {
      variables[index - start_index] = var_base + Itoa(index);
    }
  }
  for (size_t i = 0; i < variables.size(); ++i) {
    input_var_types->push_back(make_pair(variables[i], type));
  }

  // Parse value, if present.
  if (value_parts.size() == 2) {
    if (input_values == nullptr) {
      LOG_ERROR("Found input value, but API indicated none was expected.");
      return false;
    }
    input_values->push_back(GenericValue());
    GenericValue& new_value = input_values->back();
    if (HasPrefixString(value_parts[1], "-")) {
      if (!ParseIfInteger(true, value_parts[1].substr(1), &new_value)) {
        LOG_ERROR("Unable to parse input value: '" + value_parts[1] + "'");
        return false;
      }
    } else if (!ParseIfInteger(false, value_parts[1], &new_value)) {
      LOG_ERROR("Unable to parse input value: '" + value_parts[1] + "'");
      return false;
    }
    // Sanity-check that the provided input value can be stored in the
    // specified DataType, and if so, make sure new_value equals this DataType.
    if (new_value.type_ != type) {
      if (!IsDataTypeSubType(new_value.type_, type)) {
        LOG_ERROR(
            "Input value " + GetGenericValueString(new_value) +
            " cannot fit in (or has wrong sign as) DataType " +
            GetDataTypeString(type));
      }
      // Found DataType can be stored in specified DataType. Convert new_value
      // to this type.
      if (HasPrefixString(value_parts[1], "-")) {
        int64_t value;
        if (!Stoi(value_parts[1].substr(1), &value)) {
          LOG_ERROR("Unable to parse input value: '" + value_parts[1] + "'");
          return false;
        }
        new_value = GenericValue(type, value);
      } else {
        uint64_t value;
        if (!Stoi(value_parts[1], &value)) {
          LOG_ERROR("Unable to parse input value: '" + value_parts[1] + "'");
          return false;
        }
        new_value = GenericValue(type, value);
      }
    }
  }

  return true;
}

// On input, fn_rhs should be everything on the RHS of the '=' sign, with all
// whitespace removed. Returns true if there are enclosing parentheses (which
// is slightly more complicated then just checking for leading and trailing
// parentheses, since e.g.:
//   (x) AND (y)
// ought to return 'false', even though the naive parentheses check is true.
bool FunctionRhsHasEnclosingParentheses(const string& fn_rhs) {
  if (!HasPrefixString(fn_rhs, "(") || !HasSuffixString(fn_rhs, ")")) {
    return false;
  }

  int num_unmatched = 0;
  return (
      CountOpenCloseParentheses(
          true,
          StripSuffixString(StripPrefixString(fn_rhs, "("), ")"),
          &num_unmatched) &&
      num_unmatched == 0);
}

}  // namespace

string GateLocation::Print() const {
  return "(" + Itoa(level_) + ", " + Itoa(index_) + ")";
}

string WireLocation::Print() const {
  const string side = is_left_ ? "left" : "right";
  return "(" + side + ", " + Itoa(loc_.level_) + ", " + Itoa(loc_.index_) + ")";
}

template<typename value_t>
void StandardGate<value_t>::CopyFrom(const StandardGate<value_t>& other) {
  loc_ = other.loc_;
  type_ = other.type_;
  left_input_ = other.left_input_;
  left_input_set_ = other.left_input_set_;
  right_input_ = other.right_input_;
  right_input_set_ = other.right_input_set_;
  depends_on_ = other.depends_on_;
  output_value_ = other.output_value_;
  output_wire_locations_ = other.output_wire_locations_;
}

template<typename value_t>
void StandardCircuitLevel<value_t>::CopyFrom(
    const StandardCircuitLevel<value_t>& other) {
  level_ = other.level_;
  num_gates_ = other.num_gates_;

  gates_.resize(other.gates_.size());
  for (uint64_t gate = 0; gate < other.gates_.size(); ++gate) {
    gates_[gate].CopyFrom(other.gates_[gate]);
  }
}

template<typename value_t>
bool StandardCircuitLevel<value_t>::EvaluateLevel() {
  for (size_t index = 0; index < gates_.size(); ++index) {
    if (!EvaluateGate(&gates_[index])) {
      LOG_ERROR("Failed to EvaluateLevel() at index " + Itoa(index));
      return false;
    }
  }

  return true;
}

template<typename value_t>
void StandardCircuit<value_t>::CopyFrom(const StandardCircuit<value_t>& other) {
  depth_ = other.depth_;
  size_ = other.size_;
  num_non_local_gates_ = other.num_non_local_gates_;
  num_outputs_ = other.num_outputs_;
  num_output_wires_ = other.num_output_wires_;
  outputs_as_bits_ = other.outputs_as_bits_;
  outputs_as_slice_ = other.outputs_as_slice_;
  outputs_as_generic_value_ = other.outputs_as_generic_value_;
  output_designations_ = other.output_designations_;
  function_description_.resize(other.function_description_.size());
  for (size_t i = 0; i < other.function_description_.size(); ++i) {
    const Formula& f = other.function_description_[i];
    function_description_[i] = f;
  }
  input_types_ = other.input_types_;
  inputs_as_slice_locations_ = other.inputs_as_slice_locations_;
  constant_slice_input_ = other.constant_slice_input_;
  inputs_as_generic_value_locations_ = other.inputs_as_generic_value_locations_;
  constant_zero_input_ = other.constant_zero_input_;
  constant_one_input_ = other.constant_one_input_;

  levels_.resize(other.levels_.size());
  for (uint64_t level = 0; level < other.levels_.size(); ++level) {
    const StandardCircuitLevel<value_t>& other_level = other.levels_[level];
    levels_[level].CopyFrom(other_level);
  }
}

template<typename value_t>
bool StandardCircuit<value_t>::ParseInputWire(
    const bool is_left,
    const string& line,
    const int64_t& current_level,
    const int64_t& current_gate_index,
    int* max_party_index) {
  const string prefix = is_left ? "left_wire:" : "right_wire:";
  vector<string> location_parts;
  Split(StripParentheses(StripPrefixString(line, prefix)), ",", &location_parts);
  if (location_parts.size() < 2 || location_parts.size() > 4) {
    return false;
  }

  // Parse level.
  int64_t level;
  bool is_format_two_input_wire = false;
  if (HasPrefixString(location_parts[0], "P")) {
    is_format_two_input_wire = true;
    int party_index;
    if (!Stoi(StripPrefixString(location_parts[0], "P"), &party_index)) {
      return false;
    }
    level = -2 - party_index;
  } else if (location_parts[0] == "c") {
    is_format_two_input_wire = true;
    level = -1;
  } else if (!Stoi(location_parts[0], &level)) {
    return false;
  }
  // Parse index (on level).
  int64_t index = 0;
  slice constant_slice = 0;
  if ((level == -1 && !Stoi(location_parts[1], &constant_slice)) ||
      (level != -1 && !Stoi(location_parts[1], &index))) {
    return false;
  }
  if (level >= current_level || (level != -1 && index < 0) ||
      (level >= 0 && index >= levels_[level].num_gates_)) {
    return false;
  }
  // Sanity-check the proper number of terms were found.
  const size_t num_expected_parts =
      (is_format_two_input_wire && level < -1) ? 3 : 2;
  if (location_parts.size() != num_expected_parts) {
    return false;
  }
  // Parse bit of index (if Format 2).
  uint64_t bit_index;
  if (is_format_two_input_wire && level != -1 &&
      !Stoi(location_parts[2], &bit_index)) {
    return false;
  }
  // Handle input wire.
  if (level < 0) {
    if (level == -1) {
      if (is_format_two_input_wire) {
        if (constant_slice != 0 && constant_slice != 1) {
          return false;
        } else if (constant_slice == 0) {
          constant_zero_input_.insert(
              WireLocation(current_level, current_gate_index, is_left));
        } else {
          constant_one_input_.insert(
              WireLocation(current_level, current_gate_index, is_left));
        }
      } else {
        set<WireLocation>* locations_for_this_slice_value = FindOrInsert(
            constant_slice, constant_slice_input_, set<WireLocation>());
        locations_for_this_slice_value->insert(
            WireLocation(current_level, current_gate_index, is_left));
      }
    } else {
      const int party_index = (int) (-2 - level);
      if (party_index > *max_party_index) {
        *max_party_index = party_index;
      }
      levels_[current_level].gates_[current_gate_index].depends_on_.insert(
          party_index);
      if (is_format_two_input_wire) {
        if (party_index >= 0 &&
            inputs_as_generic_value_locations_.size() <= (size_t) party_index) {
          inputs_as_generic_value_locations_.resize(1 + party_index);
        }
        if (index >=
            (int64_t) inputs_as_generic_value_locations_[party_index].size()) {
          inputs_as_generic_value_locations_[party_index].resize(
              index + 1, vector<set<WireLocation>>());
        }
        vector<set<WireLocation>>& locations_for_this_bit =
            inputs_as_generic_value_locations_[party_index][index];
        if (locations_for_this_bit.size() <= bit_index) {
          locations_for_this_bit.resize(bit_index + 1);
        }
        locations_for_this_bit[bit_index].insert(
            WireLocation(current_level, current_gate_index, is_left));
      } else {
        if (party_index >= 0 &&
            inputs_as_slice_locations_.size() <= (size_t) party_index) {
          inputs_as_slice_locations_.resize(1 + party_index);
        }
        if ((int64_t) inputs_as_slice_locations_[party_index].size() <= index) {
          inputs_as_slice_locations_[party_index].resize(index + 1);
        }
        inputs_as_slice_locations_[party_index][index].insert(
            WireLocation(current_level, current_gate_index, is_left));
      }
    }
  } else {
    StandardGate<value_t>& parent_gate = levels_[level].gates_[index];
    parent_gate.output_wire_locations_.insert(
        WireLocation(current_level, current_gate_index, is_left));
    for (const int k : parent_gate.depends_on_) {
      levels_[current_level].gates_[current_gate_index].depends_on_.insert(k);
    }
  }

  return true;
}

template<typename value_t>
bool StandardCircuit<value_t>::LoadCircuit(const string& filename) {
  if (filename.empty()) LOG_FATAL("Bad input to LoadCircuit().");

  // Open input file.
  ifstream input_file(filename.c_str());
  if (!input_file.is_open()) {
    LOG_ERROR("Bad input to LoadCircuit: Unable to find '" + filename + "'");
    return false;
  }

  // Clear circuit.
  Clear();

  // Load Metadata.
  if (!ReadCircuitFileMetadata(
          filename,
          (load_function_description_ ? &function_description_ : nullptr),
          (load_all_metadata_ ? &input_types_ : nullptr),
          &output_designations_)) {
    LOG_ERROR("Unable to parse circuit metadata for circuit: " + filename);
    return false;
  }

  // Read File.
  int line_num = 0;
  int max_party_index = -1;
  int64_t depth = 0;
  int64_t current_level = -1;
  int64_t current_gate_index = -1;
  int64_t num_output_gates = 0;
  string orig_line, line;
  map<int64_t, int64_t> num_gates_per_level;
  bool inside_circuit = false;
  bool inside_level = false;
  bool inside_gate = false;
  set<uint64_t> output_gates;
  while (getline(input_file, orig_line)) {
    line_num++;
    RemoveWindowsTrailingCharacters(&orig_line);
    line = RemoveAllWhitespace(orig_line);
    if (line.empty() || HasPrefixString(line, "#")) continue;

    // Determine what to do based on line.
    if (line == "}") {
      if (inside_gate) {
        if (!output_gates.empty()) {
          set<WireLocation>& output_wire_loc = levels_[current_level]
                                                   .gates_[current_gate_index]
                                                   .output_wire_locations_;
          levels_[current_level].gates_[current_gate_index].loc_ =
              GateLocation(current_level, current_gate_index);
          num_output_gates += output_gates.size();
          for (const uint64_t& output_index : output_gates) {
            // Level "-1" in output_wire_locations_ indicates a *Circuit* output.
            output_wire_loc.insert(WireLocation(-1, output_index));
          }
          output_gates.clear();
        }
        inside_gate = false;
      } else if (inside_level) {
        inside_level = false;
        current_gate_index = -1;
      } else if (inside_circuit) {
        inside_circuit = false;
        current_level = -1;
      } else {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename +
            "): Too many nested '}' (last one "
            "on line " +
            Itoa(line_num) + ").");
        return false;
      }
    } else if (line == "Circuit{" || line == "circuit{") {
      if (inside_circuit) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      inside_circuit = true;
    } else if (
        (HasPrefixString(line, "Level") || HasPrefixString(line, "level")) &&
        HasSuffixString(line, "{")) {
      string level_number_str = StripSuffixString(
          StripPrefixString(StripPrefixString(line, "Level"), "level"), "{");
      // Sanity check level specified in file is as expected.
      if (!level_number_str.empty()) {
        int64_t level_number;
        if (!IsNumeric(level_number_str) ||
            !Stoi(level_number_str, &level_number) ||
            level_number != current_level + 1) {
          LOG_ERROR(
              "Unable to LoadCircuit(" + filename + "): Unparsable line " +
              Itoa(line_num) + ":\n'" + orig_line + "'");
          return false;
        }
      }
      if (!inside_circuit || inside_level) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      inside_level = true;
      current_level++;
      depth++;
      levels_.push_back(StandardCircuitLevel<value_t>(current_level));
    } else if (
        (HasPrefixString(line, "Gate") || HasPrefixString(line, "gate")) &&
        HasSuffixString(line, "{")) {
      string gate_number_str = StripSuffixString(
          StripPrefixString(StripPrefixString(line, "Gate"), "gate"), "{");
      // Sanity check gate specified in file is as expected.
      if (!gate_number_str.empty()) {
        int64_t gate_number;
        if (!IsNumeric(gate_number_str) ||
            !Stoi(gate_number_str, &gate_number) ||
            gate_number != current_gate_index + 1) {
          LOG_ERROR(
              "Unable to LoadCircuit(" + filename + "): Unparsable line " +
              Itoa(line_num) + ":\n'" + orig_line + "'");
          return false;
        }
      }
      if (!inside_circuit || !inside_level || inside_gate) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      inside_gate = true;
      current_gate_index++;
      size_++;
      levels_[current_level].num_gates_++;
      levels_[current_level].gates_.push_back(
          StandardGate<value_t>(current_level, current_gate_index));
    } else if (HasPrefixString(line, "depth:")) {
      if (!inside_circuit || inside_level || depth_ != -1) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      const string suffix = StripPrefixString(line, "depth:");
      if (!Stoi(suffix, &depth_)) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
    } else if (HasPrefixString(line, "num_gates:")) {
      if (!inside_circuit || inside_gate) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      if (num_gates_per_level.find(current_level) != num_gates_per_level.end()) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename +
            "): Number of gates for level " + Itoa(current_level) +
            " was specified mulitple times.");
        return false;
      }
      const string suffix = StripPrefixString(line, "num_gates:");
      int64_t num_gates;
      if (!Stoi(suffix, &num_gates) || num_gates < 0) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      num_gates_per_level.insert(
          make_pair((inside_level ? current_level : -1), num_gates));
    } else if (HasPrefixString(line, "num_non_local_gates:")) {
      if (!inside_circuit || inside_gate || inside_level ||
          num_non_local_gates_ != 0) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      const string suffix = StripPrefixString(line, "num_non_local_gates:");
      int64_t num_gates;
      if (!Stoi(suffix, &num_gates) || num_gates < 0) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      num_non_local_gates_ = num_gates;
    } else if (HasPrefixString(line, "num_outputs:")) {
      if (!inside_circuit || inside_level || num_outputs_ != 0) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      const string suffix = StripPrefixString(line, "num_outputs:");
      if (!Stoi(suffix, &num_outputs_)) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
    } else if (HasPrefixString(line, "num_output_wires:")) {
      if (!inside_circuit || inside_level || num_output_wires_ != 0) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      const string suffix = StripPrefixString(line, "num_output_wires:");
      if (!Stoi(suffix, &num_output_wires_)) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
    } else if (HasPrefixString(line, "type:")) {
      if (!inside_gate) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      StandardGate<value_t>& current_gate =
          levels_[current_level].gates_[current_gate_index];
      current_gate.type_ = GetBooleanOperation(StripPrefixString(line, "type:"));
      if (current_gate.type_ == BooleanOperation::UNKNOWN) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename +
            "): Unrecognized Gate Operation '" +
            StripPrefixString(line, "type:") + "' on line " + Itoa(line_num) +
            ":\n'" + orig_line + "'");
        return false;
      }
    } else if (HasPrefixString(line, "left_wire:")) {
      if (!inside_gate) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      if (!ParseInputWire(
              true, line, current_level, current_gate_index, &max_party_index)) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
    } else if (HasPrefixString(line, "right_wire:")) {
      if (!inside_gate) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      if (!ParseInputWire(
              false,
              line,
              current_level,
              current_gate_index,
              &max_party_index)) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
    } else if (HasPrefixString(line, "output_gate:")) {
      if (!inside_gate) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      const string output_index_str = StripPrefixString(line, "output_gate:");
      uint64_t output_index;
      if (!Stoi(output_index_str, &output_index)) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Unparsable line " +
            Itoa(line_num) + ":\n'" + orig_line + "'");
        return false;
      }
      if (!output_gates.insert(output_index).second) {
        LOG_ERROR("Too many lines specify output index " + output_index_str);
        return false;
      }
    } else {
      LOG_ERROR(
          "Unable to LoadCircuit(" + filename + "): Unparsable line " +
          Itoa(line_num) + ":\n'" + orig_line + "'");
      return false;
    }
  }

  // Done reading circuit file. Now go back through accumlated information,
  // counting various things and updating fields.

  // Now that the input wires to all gates has been set, we can now identify
  // a gate as being locally computable or not (since this depends not only
  // on the gate's operation, but also 'constant' gates (whose input only
  // depends on at most one Party) are locally computable.
  // Also, while we're looping through all gates, sanity-check field
  // num_non_local_gates_.
  int64_t num_non_local_gates = 0;
  for (StandardCircuitLevel<value_t>& level : levels_) {
    for (StandardGate<value_t>& current_gate : level.gates_) {
      if (!current_gate.IsLocallyComputable()) {
        ++num_non_local_gates;
      }
    }
  }
  if (num_non_local_gates_ == 0) {
    num_non_local_gates_ = num_non_local_gates;
  } else if (num_non_local_gates_ != num_non_local_gates) {
    LOG_ERROR(
        "Unable to LoadCircuit(" + filename +
        "): mismatching number of non-local gates: " +
        Itoa(num_non_local_gates_) + " vs. " + Itoa(num_non_local_gates));
    return false;
  }

  // Set number of ouputs, and/or make sure it is consistent.
  if (num_outputs_ == 0) {
    num_outputs_ = (int64_t) output_designations_.size();
  } else if (num_outputs_ != (int64_t) output_designations_.size()) {
    LOG_FATAL(
        "Mismatching number of outputs: " + Itoa(num_outputs_) + " reported, " +
        Itoa(output_designations_.size()) + " found");
  }

  // Set number of output wires, and/or make sure it is consistent.
  if (num_output_wires_ == 0) {
    num_output_wires_ = num_output_gates;
  } else if (num_output_wires_ != num_output_gates) {
    LOG_FATAL(
        "Mismatching number of outputs: " + Itoa(num_output_wires_) +
        " reported, " + Itoa(num_output_gates) + " found");
  }

  // Set depth_, and/or make sure it is consistent.
  if (depth_ == -1) {
    depth_ = depth;
  } else if (depth_ != depth) {
    LOG_FATAL(
        "Mismatching depths: " + Itoa(depth_) + " reported, " + Itoa(depth) +
        " found");
  }

  // If num_gates was specified for either the whole circuit and/or for
  // the Level(s) of the circuit, sanity-check that the number of gates
  // found matches the value specified.
  for (const pair<const int64_t, int64_t>& gates_on_level :
       num_gates_per_level) {
    if (gates_on_level.first == -1) {
      // -1 was used as a dummy identifier to express this is the number
      // of gates in the whole circuit.
      if (size_ != gates_on_level.second) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Expected " +
            Itoa(gates_on_level.second) +
            " gates in the circuit ("
            "based on 'num_gates' being specified in the circuit file)"
            ", but read in " +
            Itoa(size_) + " gates.");
        return false;
      }
    } else {
      if (gates_on_level.first < 0 ||
          (size_t) gates_on_level.first >= levels_.size()) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename +
            "): Unexpected error: a negative "
            "circuit level was encountered. This should never happen.");
        return false;
      }
      if (levels_[gates_on_level.first].num_gates_ != gates_on_level.second) {
        LOG_ERROR(
            "Unable to LoadCircuit(" + filename + "): Expected " +
            Itoa(gates_on_level.second) + " gates on level " +
            Itoa(gates_on_level.first) +
            "(based on 'num_gates' being specified in the circuit file)"
            ", but read in " +
            Itoa(size_) + " gates.");
        return false;
      }
    }
  }

  return true;
}

template<typename value_t>
bool StandardCircuit<value_t>::WriteCircuitFile(const string& filename) const {
  // Open output file for writing.
  if (!CreateDir(GetDirectory(filename))) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }
  ofstream outfile;
  outfile.open(filename);
  if (!outfile.is_open()) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }

  // Write metadata.
  if (!function_description_.empty()) {
    outfile << "# Circuit Function:" << endl;
    outfile << PrintFunction(
        true, input_types_, output_designations_, function_description_);
    outfile << endl << endl;
  }
  for (size_t i = 0; i < input_types_.size(); ++i) {
    outfile << "# Party Inputs (" << i << "): " << endl;
    for (const pair<string, DataType>& input : input_types_[i]) {
      outfile << "# (" << GetDataTypeString(input.second) << ") " << input.first
              << endl;
    }
    outfile << endl;
  }

  // Sanity-check format of this circuit (Format 1 vs. Format 2) is well-
  // defined.
  const bool is_format_one = format_ == CircuitFormat::FORMAT_ONE;

  // The following is not strictly necessary, but will be useful as a
  // sanity-check, in making sure (circuit) input wires are properly identified.
  // They map a (global input) gate's location to the input index of the
  // relevant party that maps to that gate.
  map<GateLocation, pair<int, uint64_t>> left_input_by_party_as_slice_wires,
      right_input_by_party_as_slice_wires;
  map<GateLocation, slice> constant_left_input, constant_right_input;
  if (is_format_one) {
    // Go through each Party's inputs (as slice).
    for (size_t party = 0; party < inputs_as_slice_locations_.size(); ++party) {
      for (uint64_t i = 0; i < inputs_as_slice_locations_[party].size(); ++i) {
        const set<WireLocation>& party_inputs =
            inputs_as_slice_locations_[party][i];
        for (const WireLocation& wire_loc : party_inputs) {
          if (wire_loc.is_left_) {
            if (!left_input_by_party_as_slice_wires
                     .insert(make_pair(wire_loc.loc_, make_pair(party, i)))
                     .second) {
              LOG_FATAL("Duplicate input.");
            }
          } else {
            if (!right_input_by_party_as_slice_wires
                     .insert(make_pair(wire_loc.loc_, make_pair(party, i)))
                     .second) {
              LOG_FATAL("Duplicate input.");
            }
          }
        }
      }
    }
    // Go through constant inputs.
    for (const pair<const slice, set<WireLocation>>& constant_i :
         constant_slice_input_) {
      const set<WireLocation>& gates = constant_i.second;
      for (const WireLocation& loc_j : gates) {
        if (loc_j.is_left_) {
          constant_left_input.insert(make_pair(loc_j.loc_, constant_i.first));
        } else {
          constant_right_input.insert(make_pair(loc_j.loc_, constant_i.first));
        }
      }
    }
  }
  // Repeat above procedure, this time for inputs as generic value (Format 2).
  map<GateLocation, pair<int, pair<uint64_t, uint64_t>>>
      left_input_by_party_as_generic_value_wires,
      right_input_by_party_as_generic_value_wires;
  set<GateLocation> constant_zero_left_inputs, constant_one_left_inputs;
  set<GateLocation> constant_zero_right_inputs, constant_one_right_inputs;
  if (!is_format_one) {
    // Go through Party's inputs (as GenericValue).
    for (size_t party = 0; party < inputs_as_generic_value_locations_.size();
         ++party) {
      for (size_t one_input_index = 0;
           one_input_index < inputs_as_generic_value_locations_[party].size();
           ++one_input_index) {
        const vector<set<WireLocation>>& party_input_loc_to_output_loc =
            inputs_as_generic_value_locations_[party][one_input_index];
        for (uint64_t i = 0; i < party_input_loc_to_output_loc.size(); ++i) {
          for (const WireLocation& wire_loc : party_input_loc_to_output_loc[i]) {
            if (wire_loc.is_left_) {
              if (!left_input_by_party_as_generic_value_wires
                       .insert(make_pair(
                           wire_loc.loc_,
                           make_pair(party, make_pair(one_input_index, i))))
                       .second) {
                LOG_FATAL("Duplicate inputs.");
              }
            } else {
              if (!right_input_by_party_as_generic_value_wires
                       .insert(make_pair(
                           wire_loc.loc_,
                           make_pair(party, make_pair(one_input_index, i))))
                       .second) {
                LOG_FATAL("Duplicate inputs.");
              }
            }
          }
        }
      }
    }
    // Go through constant '0' inputs.
    for (const WireLocation& constant_gate : constant_zero_input_) {
      if (constant_gate.is_left_) {
        constant_zero_left_inputs.insert(GateLocation(constant_gate.loc_));
      } else {
        constant_zero_right_inputs.insert(GateLocation(constant_gate.loc_));
      }
    }
    // Go through constant '1' inputs.
    for (const WireLocation& constant_gate : constant_one_input_) {
      if (constant_gate.is_left_) {
        constant_one_left_inputs.insert(GateLocation(constant_gate.loc_));
      } else {
        constant_one_right_inputs.insert(GateLocation(constant_gate.loc_));
      }
    }
  }

  // Write Circuit "header".
  outfile << "Circuit {" << endl;
  outfile << "  depth : " << levels_.size() << endl;
  outfile << "  num_gates : " << size_ << endl;
  outfile << "  num_non_local_gates : " << num_non_local_gates_ << endl;
  outfile << "  num_outputs : " << num_outputs_ << endl;
  outfile << "  num_output_wires : " << num_output_wires_ << endl;

  // Now go through the gates of the StandardCircuit and from it (and the
  // other StandardCircuit fields), write the output file.
  // We'll need to keep track of the output wire locations of each gate,
  // since StandardCircuit stores the output wire locations (explicitly),
  // but not the input wire locations (which are implicit, based on
  // being the target of some other gate's output wire).
  map<GateLocation, GateLocation> gate_to_left_input;
  map<GateLocation, GateLocation> gate_to_right_input;
  for (size_t level_index = 0; level_index < levels_.size(); ++level_index) {
    const StandardCircuitLevel<value_t>& current_level = levels_[level_index];
    outfile << "  Level " << level_index << " {" << endl;
    outfile << "    num_gates : " << current_level.gates_.size() << endl;
    for (size_t gate_index = 0; gate_index < current_level.gates_.size();
         ++gate_index) {
      const StandardGate<value_t>& current_gate =
          current_level.gates_[gate_index];
      if (current_gate.loc_.level_ != (int64_t) level_index ||
          current_gate.loc_.index_ != (int64_t) gate_index) {
        LOG_FATAL("Bad location.");
      }
      outfile << "    Gate " << gate_index << " {" << endl;
      outfile << "      type : " << GetBooleanOperationString(current_gate.type_)
              << endl;

      // Get location of left input wire: This will either live in one of the
      // global/circuit inputs maps, or it will have been inserted into
      // one of the gate_to_left_input maps from a gate on a lower level.
      GateLocation* left_input =
          FindOrNull(current_gate.loc_, gate_to_left_input);
      bool no_left_input = left_input == nullptr;
      if (is_format_one) {
        pair<int, uint64_t>* party_global_left_input =
            FindOrNull(current_gate.loc_, left_input_by_party_as_slice_wires);
        const slice* constant_left_input_ptr =
            FindOrNull(current_gate.loc_, constant_left_input);
        const int num_non_null = (party_global_left_input == nullptr ? 0 : 1) +
            (constant_left_input_ptr == nullptr ? 0 : 1);
        if (num_non_null > 1) {
          LOG_FATAL("Double input.");
        }
        if (left_input == nullptr) {
          if (num_non_null == 0 &&
              current_gate.type_ != BooleanOperation::IDENTITY &&
              current_gate.type_ != BooleanOperation::NOT) {
            LOG_FATAL("No input.");
          } else if (num_non_null > 1) {
            LOG_FATAL(
                "Current gate: (" + Itoa(current_gate.loc_.level_) + ", " +
                Itoa(current_gate.loc_.index_) +
                "), num_non_null: " + Itoa(num_non_null) +
                ", gate op: " + GetOpString(current_gate.type_));
          }
          if (party_global_left_input != nullptr) {
            no_left_input = false;
            outfile << "      left_wire : (-"
                    << Itoa(2 + party_global_left_input->first) << ", "
                    << Itoa(party_global_left_input->second) << ")" << endl;
          } else {
            no_left_input = false;
            outfile << "      left_wire : (-1, "
                    << Itoa(*constant_left_input_ptr) << ")" << endl;
          }
        } else {
          if (num_non_null != 0) {
            LOG_FATAL("Double input.");
          }
          outfile << "      left_wire : (" << Itoa(left_input->level_) << ", "
                  << Itoa(left_input->index_) << ")" << endl;
        }
      } else {
        pair<int, pair<uint64_t, uint64_t>>* party_global_left_input =
            FindOrNull(
                current_gate.loc_, left_input_by_party_as_generic_value_wires);
        bool temp_true = true;
        bool temp_false = true;
        bool* constant_zero_left =
            constant_zero_left_inputs.find(current_gate.loc_) ==
                constant_zero_left_inputs.end() ?
            nullptr :
            &temp_false;
        bool* constant_one_left =
            constant_one_left_inputs.find(current_gate.loc_) ==
                constant_one_left_inputs.end() ?
            nullptr :
            &temp_true;
        const int num_non_null = (party_global_left_input == nullptr ? 0 : 1) +
            (constant_zero_left == nullptr ? 0 : 1) +
            (constant_one_left == nullptr ? 0 : 1);
        if (num_non_null > 1) {
          LOG_FATAL(
              "Current gate: (" + Itoa(current_gate.loc_.level_) + ", " +
              Itoa(current_gate.loc_.index_) + ")");
        }
        if (left_input == nullptr) {
          if (num_non_null == 0 &&
              current_gate.type_ != BooleanOperation::IDENTITY &&
              current_gate.type_ != BooleanOperation::NOT) {
            LOG_FATAL("Null first input.");
          } else if (num_non_null > 1) {
            LOG_FATAL(
                "Current gate: (" + Itoa(current_gate.loc_.level_) + ", " +
                Itoa(current_gate.loc_.index_) +
                "), num_non_null: " + Itoa(num_non_null) +
                ", gate op: " + GetOpString(current_gate.type_));
          }
          if (party_global_left_input != nullptr) {
            no_left_input = false;
            outfile << "      left_wire : (P"
                    << Itoa(party_global_left_input->first) << ", "
                    << Itoa(party_global_left_input->second.first) << ", "
                    << Itoa(party_global_left_input->second.second) << ")"
                    << endl;
          } else if (constant_zero_left != nullptr) {
            no_left_input = false;
            outfile << "      left_wire : (c, 0)" << endl;
          } else if (constant_one_left != nullptr) {
            no_left_input = false;
            outfile << "      left_wire : (c, 1)" << endl;
          }
        } else {
          if (num_non_null != 0) {
            LOG_FATAL("Double input.");
          }
          outfile << "      left_wire : (" << Itoa(left_input->level_) << ", "
                  << Itoa(left_input->index_) << ")" << endl;
        }
      }

      // Get location of right input wire: This will either live in one of the
      // global/circuit inputs maps, or it will have been inserted into
      // one of the gate_to_right_input maps from a gate on a lower level.
      GateLocation* right_input =
          FindOrNull(current_gate.loc_, gate_to_right_input);
      if (is_format_one) {
        pair<int, uint64_t>* party_global_right_input =
            FindOrNull(current_gate.loc_, right_input_by_party_as_slice_wires);
        slice* constant_right_input_ptr =
            FindOrNull(current_gate.loc_, constant_right_input);
        const int num_non_null = (party_global_right_input == nullptr ? 0 : 1) +
            (constant_right_input_ptr == nullptr ? 0 : 1);
        if (num_non_null > 1) {
          LOG_FATAL("Double input.");
        }
        if (right_input == nullptr) {
          // Special-handling of right-wire needed: some gates don't require/have
          // a right-input wire (e.g. IDENTITY, NOT gates).
          if (num_non_null == 0 &&
              (no_left_input ||
               (current_gate.type_ != BooleanOperation::IDENTITY &&
                current_gate.type_ != BooleanOperation::NOT))) {
            LOG_FATAL("Null second input.");
          }
          if (party_global_right_input != nullptr) {
            outfile << "      right_wire : (-"
                    << Itoa(2 + party_global_right_input->first) << ", "
                    << Itoa(party_global_right_input->second) << ")" << endl;
          } else if (constant_right_input_ptr != nullptr) {
            outfile << "      right_wire : (-1, "
                    << Itoa(*constant_right_input_ptr) << ")" << endl;
          }
        } else {
          if (num_non_null != 0) {
            LOG_FATAL("Double input.");
          }
          outfile << "      right_wire : (" << Itoa(right_input->level_) << ", "
                  << Itoa(right_input->index_) << ")" << endl;
        }
      } else {
        pair<int, pair<uint64_t, uint64_t>>* party_global_right_input =
            FindOrNull(
                current_gate.loc_, right_input_by_party_as_generic_value_wires);
        bool temp_true = true;
        bool temp_false = false;
        bool* constant_zero_right =
            constant_zero_right_inputs.find(current_gate.loc_) ==
                constant_zero_right_inputs.end() ?
            nullptr :
            &temp_false;
        bool* constant_one_right =
            constant_one_right_inputs.find(current_gate.loc_) ==
                constant_one_right_inputs.end() ?
            nullptr :
            &temp_true;
        const int num_non_null = (party_global_right_input == nullptr ? 0 : 1) +
            (constant_zero_right == nullptr ? 0 : 1) +
            (constant_one_right == nullptr ? 0 : 1);
        if (num_non_null > 1) {
          LOG_FATAL("Double input.");
        }
        if (right_input == nullptr) {
          // Special-handling of right-wire needed: some gates don't require/have
          // a right-input wire (e.g. IDENTITY, NOT gates).
          if (num_non_null == 0 &&
              (no_left_input ||
               (current_gate.type_ != BooleanOperation::IDENTITY &&
                current_gate.type_ != BooleanOperation::NOT))) {
            LOG_FATAL("Null second input.");
          } else if (num_non_null > 1) {
            LOG_FATAL(
                "Current gate: (" + Itoa(current_gate.loc_.level_) + ", " +
                Itoa(current_gate.loc_.index_) +
                "), num_non_null: " + Itoa(num_non_null) +
                ", gate op: " + GetOpString(current_gate.type_));
          }
          if (party_global_right_input != nullptr) {
            outfile << "      right_wire : (P"
                    << Itoa(party_global_right_input->first) << ", "
                    << Itoa(party_global_right_input->second.first) << ", "
                    << Itoa(party_global_right_input->second.second) << ")"
                    << endl;
          } else if (constant_zero_right != nullptr) {
            outfile << "      right_wire : (c, 0)" << endl;
          } else if (constant_one_right != nullptr) {
            outfile << "      right_wire : (c, 1)" << endl;
          }
        } else {
          if (num_non_null != 0) {
            LOG_FATAL("Double input.");
          }
          outfile << "      right_wire : (" << Itoa(right_input->level_) << ", "
                  << Itoa(right_input->index_) << ")" << endl;
        }
      }
      // Now go through all of the current_gate.output_wire_locations_, adding
      // each output wire either to gate_to_[left | right]_input, or mark it as
      // a global/circuit output.
      for (const WireLocation& output_wire :
           current_gate.output_wire_locations_) {
        if (output_wire.loc_.level_ == -1) {
          outfile << "      output_gate : " << output_wire.loc_.index_ << endl;
        } else if (output_wire.is_left_) {
          if (!gate_to_left_input
                   .insert(make_pair(output_wire.loc_, current_gate.loc_))
                   .second) {
            LOG_FATAL("Duplicate output.");
          }
        } else {
          if (!gate_to_right_input
                   .insert(make_pair(output_wire.loc_, current_gate.loc_))
                   .second) {
            LOG_FATAL("Duplicate output.");
          }
        }
      }
      outfile << "    }" << endl;
    }
    outfile << "  }" << endl;
  }

  // Write Circuit closing parentheses, and then close file.
  outfile << "}" << endl;
  outfile.close();

  return true;
}

template<typename value_t>
bool StandardCircuit<value_t>::IsValidGateLocation(
    const GateLocation& location) const {
  if (levels_.empty() || location.level_ < 0 || location.index_ < 0) {
    return false;
  }

  return (
      (int64_t) levels_.size() > location.level_ &&
      (int64_t) levels_[location.level_].gates_.size() > location.index_);
}

template<typename value_t>
bool StandardCircuit<value_t>::IsCircuitFormatOne() const {
  const bool is_format_one =
      !inputs_as_slice_locations_.empty() || !constant_slice_input_.empty();
  const bool is_format_two = !inputs_as_generic_value_locations_.empty() ||
      !constant_zero_input_.empty() || !constant_one_input_.empty();
  if (!(is_format_one || is_format_two) || (is_format_one == is_format_two)) {
    LOG_FATAL("Neither or both formats detected.");
  }
  return is_format_one;
}

template<typename value_t>
string StandardCircuit<value_t>::PrintTimers() const {
  string to_return = "StandardCircuit Timers:\n";
  const int meaningful_ms = 10;
  const int64_t evaluate_circuit_overall_time =
      GetElapsedTime(evaluate_circuit_overall_timer_) / 1000;
  if (evaluate_circuit_overall_time / 1000 > 0 ||
      evaluate_circuit_overall_time % 1000 > meaningful_ms) {
    to_return += "  evaluate_circuit_overall_timer_: " +
        test_utils::FormatTime(evaluate_circuit_overall_time) + "\n";
  }
  const int64_t server_generate_ot_secrets_time =
      GetElapsedTime(server_generate_ot_secrets_timer_) / 1000;
  if (server_generate_ot_secrets_time / 1000 > 0 ||
      server_generate_ot_secrets_time % 1000 > meaningful_ms) {
    to_return += "  server_generate_ot_secrets_timer_: " +
        test_utils::FormatTime(server_generate_ot_secrets_time) + "\n";
  }
  const int64_t server_generate_ot_masks_time =
      GetElapsedTime(server_generate_ot_masks_timer_) / 1000;
  if (server_generate_ot_masks_time / 1000 > 0 ||
      server_generate_ot_masks_time % 1000 > meaningful_ms) {
    to_return += "  server_generate_ot_masks_timer_: " +
        test_utils::FormatTime(server_generate_ot_masks_time) + "\n";
  }
  const int64_t client_generate_ot_selection_bits_time =
      GetElapsedTime(client_generate_ot_selection_bits_timer_) / 1000;
  if (client_generate_ot_selection_bits_time / 1000 > 0 ||
      client_generate_ot_selection_bits_time % 1000 > meaningful_ms) {
    to_return += "  client_generate_ot_selection_bits_timer_: " +
        test_utils::FormatTime(client_generate_ot_selection_bits_time) + "\n";
  }
  const int64_t load_ot_bits_time = GetElapsedTime(load_ot_bits_timer_) / 1000;
  if (load_ot_bits_time / 1000 > 0 || load_ot_bits_time % 1000 > meaningful_ms) {
    to_return +=
        "  load_ot_bits_timer_: " + test_utils::FormatTime(load_ot_bits_time) +
        "\n";
  }
  const int64_t ot_protocol_time = GetElapsedTime(ot_protocol_timer_) / 1000;
  if (ot_protocol_time / 1000 > 0 || ot_protocol_time % 1000 > meaningful_ms) {
    to_return +=
        "  ot_protocol_timer_: " + test_utils::FormatTime(ot_protocol_time) +
        "\n";
  }
  const int64_t write_ot_bits_time = GetElapsedTime(write_ot_bits_timer_) / 1000;
  if (write_ot_bits_time / 1000 > 0 ||
      write_ot_bits_time % 1000 > meaningful_ms) {
    to_return +=
        "  write_ot_bits_timer_: " + test_utils::FormatTime(write_ot_bits_time) +
        "\n";
  }
  const int64_t server_load_ot_bits_to_gate_masks_time =
      GetElapsedTime(server_load_ot_bits_to_gate_masks_timer_) / 1000;
  if (server_load_ot_bits_to_gate_masks_time / 1000 > 0 ||
      server_load_ot_bits_to_gate_masks_time % 1000 > meaningful_ms) {
    to_return += "  server_load_ot_bits_to_gate_masks_timer_: " +
        test_utils::FormatTime(server_load_ot_bits_to_gate_masks_time) + "\n";
  }
  const int64_t client_store_ot_bits_time =
      GetElapsedTime(client_store_ot_bits_timer_) / 1000;
  if (client_store_ot_bits_time / 1000 > 0 ||
      client_store_ot_bits_time % 1000 > meaningful_ms) {
    to_return += "  client_store_ot_bits_timer_: " +
        test_utils::FormatTime(client_store_ot_bits_time) + "\n";
  }
  const int64_t exchange_inputs_time =
      GetElapsedTime(exchange_inputs_timer_) / 1000;
  if (exchange_inputs_time / 1000 > 0 ||
      exchange_inputs_time % 1000 > meaningful_ms) {
    to_return += "  exchange_inputs_timer_: " +
        test_utils::FormatTime(exchange_inputs_time) + "\n";
  }
  const int64_t load_inputs_time = GetElapsedTime(load_inputs_timer_) / 1000;
  if (load_inputs_time / 1000 > 0 || load_inputs_time % 1000 > meaningful_ms) {
    to_return +=
        "  load_inputs_timer_: " + test_utils::FormatTime(load_inputs_time) +
        "\n";
  }
  const int64_t evaluate_circuit_only_time =
      GetElapsedTime(evaluate_circuit_only_timer_) / 1000;
  if (evaluate_circuit_only_time / 1000 > 0 ||
      evaluate_circuit_only_time % 1000 > meaningful_ms) {
    to_return += "  evaluate_circuit_only_timer_: " +
        test_utils::FormatTime(evaluate_circuit_only_time) + "\n";
  }
  const int64_t server_evaluate_level_time =
      GetElapsedTime(server_evaluate_level_timer_) / 1000;
  if (server_evaluate_level_time / 1000 > 0 ||
      server_evaluate_level_time % 1000 > meaningful_ms) {
    to_return += "  server_evaluate_level_timer_: " +
        test_utils::FormatTime(server_evaluate_level_time) + "\n";
  }
  const int64_t server_awaiting_selection_bits_time =
      GetElapsedTime(server_awaiting_selection_bits_timer_) / 1000;
  if (server_awaiting_selection_bits_time / 1000 > 0 ||
      server_awaiting_selection_bits_time % 1000 > meaningful_ms) {
    to_return += "  server_awaiting_selection_bits_timer_: " +
        test_utils::FormatTime(server_awaiting_selection_bits_time) + "\n";
  }
  const int64_t server_computing_gates_time =
      GetElapsedTime(server_computing_gates_timer_) / 1000;
  if (server_computing_gates_time / 1000 > 0 ||
      server_computing_gates_time % 1000 > meaningful_ms) {
    to_return += "  server_computing_gates_timer_: " +
        test_utils::FormatTime(server_computing_gates_time) + "\n";
  }
  const int64_t server_sending_server_mask_time =
      GetElapsedTime(server_sending_server_mask_timer_) / 1000;
  if (server_sending_server_mask_time / 1000 > 0 ||
      server_sending_server_mask_time % 1000 > meaningful_ms) {
    to_return += "  server_sending_server_mask_timer_: " +
        test_utils::FormatTime(server_sending_server_mask_time) + "\n";
  }
  const int64_t server_updating_output_wires_time =
      GetElapsedTime(server_updating_output_wires_timer_) / 1000;
  if (server_updating_output_wires_time / 1000 > 0 ||
      server_updating_output_wires_time % 1000 > meaningful_ms) {
    to_return += "  server_updating_output_wires_timer_: " +
        test_utils::FormatTime(server_updating_output_wires_time) + "\n";
  }
  const int64_t client_evaluate_level_time =
      GetElapsedTime(client_evaluate_level_timer_) / 1000;
  if (client_evaluate_level_time / 1000 > 0 ||
      client_evaluate_level_time % 1000 > meaningful_ms) {
    to_return += "  client_evaluate_level_timer_: " +
        test_utils::FormatTime(client_evaluate_level_time) + "\n";
  }
  const int64_t client_preparing_selection_bits_time =
      GetElapsedTime(client_preparing_selection_bits_timer_) / 1000;
  if (client_preparing_selection_bits_time / 1000 > 0 ||
      client_preparing_selection_bits_time % 1000 > meaningful_ms) {
    to_return += "  client_preparing_selection_bits_timer_: " +
        test_utils::FormatTime(client_preparing_selection_bits_time) + "\n";
  }
  const int64_t client_sending_selection_bits_time =
      GetElapsedTime(client_sending_selection_bits_timer_) / 1000;
  if (client_sending_selection_bits_time / 1000 > 0 ||
      client_sending_selection_bits_time % 1000 > meaningful_ms) {
    to_return += "  client_sending_selection_bits_timer_: " +
        test_utils::FormatTime(client_sending_selection_bits_time) + "\n";
  }
  const int64_t client_awaiting_server_mask_time =
      GetElapsedTime(client_awaiting_server_mask_timer_) / 1000;
  if (client_awaiting_server_mask_time / 1000 > 0 ||
      client_awaiting_server_mask_time % 1000 > meaningful_ms) {
    to_return += "  client_awaiting_server_mask_timer_: " +
        test_utils::FormatTime(client_awaiting_server_mask_time) + "\n";
  }
  const int64_t client_computing_gates_time =
      GetElapsedTime(client_computing_gates_timer_) / 1000;
  if (client_computing_gates_time / 1000 > 0 ||
      client_computing_gates_time % 1000 > meaningful_ms) {
    to_return += "  client_computing_gates_timer_: " +
        test_utils::FormatTime(client_computing_gates_time) + "\n";
  }
  const int64_t client_updating_output_wires_time =
      GetElapsedTime(client_updating_output_wires_timer_) / 1000;
  if (client_updating_output_wires_time / 1000 > 0 ||
      client_updating_output_wires_time % 1000 > meaningful_ms) {
    to_return += "  client_updating_output_wires_timer_: " +
        test_utils::FormatTime(client_updating_output_wires_time) + "\n";
  }
  const int64_t exchange_outputs_time =
      GetElapsedTime(exchange_outputs_timer_) / 1000;
  if (exchange_outputs_time / 1000 > 0 ||
      exchange_outputs_time % 1000 > meaningful_ms) {
    to_return += "  exchange_outputs_timer_: " +
        test_utils::FormatTime(exchange_outputs_time) + "\n";
  }
  const int64_t write_outputs_time = GetElapsedTime(write_outputs_timer_) / 1000;
  if (write_outputs_time / 1000 > 0 ||
      write_outputs_time % 1000 > meaningful_ms) {
    to_return +=
        "  write_outputs_timer_: " + test_utils::FormatTime(write_outputs_time) +
        "\n";
  }
  const int64_t initiate_connection_time =
      GetElapsedTime(initiate_connection_timer_) / 1000;
  if (initiate_connection_time / 1000 > 0 ||
      initiate_connection_time % 1000 > meaningful_ms) {
    to_return += "  initiate_connection_timer_: " +
        test_utils::FormatTime(initiate_connection_time) + "\n";
  }
  const int64_t close_connection_time =
      GetElapsedTime(close_connection_timer_) / 1000;
  if (close_connection_time / 1000 > 0 ||
      close_connection_time % 1000 > meaningful_ms) {
    to_return += "  close_connection_timer_: " +
        test_utils::FormatTime(close_connection_time) + "\n";
  }

  return to_return;
}

template<typename value_t>
string StandardCircuit<value_t>::PrintInputMappings() const {
  string to_return = "";
  if (!inputs_as_slice_locations_.empty()) {
    to_return += "\nSlice Inputs:";
    for (size_t party = 0; party < inputs_as_slice_locations_.size(); ++party) {
      to_return += "\n\tParty " + Itoa(party) + " Inputs:";
      for (size_t i = 0; i < inputs_as_slice_locations_[party].size(); ++i) {
        to_return += "\n\t\tInput " + Itoa(i) + ": ";
        bool is_first = true;
        for (const WireLocation& loc : inputs_as_slice_locations_[party][i]) {
          if (!is_first) to_return += ", ";
          is_first = false;
          to_return += loc.Print();
        }
      }
    }
  }
  if (!inputs_as_generic_value_locations_.empty()) {
    to_return += "\nGeneric Value Inputs:";
    for (size_t party = 0; party < inputs_as_generic_value_locations_.size();
         ++party) {
      to_return += "\n\tParty " + Itoa(party) + " Inputs:";
      for (size_t i = 0; i < inputs_as_generic_value_locations_[party].size();
           ++i) {
        to_return += "\n\t\tInput " + Itoa(i) + ": ";
        for (size_t bit = 0;
             bit < inputs_as_generic_value_locations_[party][i].size();
             ++bit) {
          to_return += "\n\t\t\tBit " + Itoa(bit) + ": ";
          bool is_first = true;
          for (const WireLocation& loc :
               inputs_as_generic_value_locations_[party][i][bit]) {
            if (!is_first) to_return += ", ";
            is_first = false;
            to_return += loc.Print();
          }
        }
      }
    }
  }
  return to_return;
}

// Returns true if both input wires to a gate have been set; or in
// the case the gate is NOT or IDENTITY, exactly one of the input
// wires have been set.
bool IsInputWiresSet(
    const bool is_left_wire_set,
    const bool is_right_wire_set,
    const BooleanOperation type) {
  if (type == BooleanOperation::NOT || type == BooleanOperation::IDENTITY) {
    return (is_left_wire_set != is_right_wire_set);
  }
  return (is_left_wire_set && is_right_wire_set);
}

bool GetOutputWireIndexToGenericValueIndex(
    const vector<pair<OutputRecipient, DataType>>& output_types,
    vector<pair<uint64_t, uint64_t>>* output_wire_to_output_index_and_bit) {
  output_wire_to_output_index_and_bit->clear();

  for (uint64_t output_index = 0; output_index < output_types.size();
       ++output_index) {
    const uint64_t num_bits_in_output_i =
        GetValueNumBits(output_types[output_index].second);
    for (uint64_t bit_index = 0; bit_index < num_bits_in_output_i; ++bit_index) {
      output_wire_to_output_index_and_bit->push_back(
          make_pair(output_index, bit_index));
    }
  }

  return true;
}

string PrintFunction(
    const bool print_comment_symbol,
    const vector<vector<string>>& var_input_names,
    const vector<pair<OutputRecipient, DataType>>& output_types,
    const vector<Formula>& function) {
  if (!output_types.empty() && !function.empty() &&
      output_types.size() != function.size()) {
    LOG_FATAL("Mismatching output types.");
  }
  string to_return = "";
  to_return += print_comment_symbol ? "# f(" : "f(";
  bool is_first = true;
  for (const vector<string>& party_i_inputs : var_input_names) {
    if (!is_first) to_return += "; ";
    is_first = false;
    to_return += Join(party_i_inputs, ", ");
  }
  to_return += ")";
  if (output_types.empty() && function.empty()) {
    return to_return;
  }

  to_return += " = (";
  const size_t num_outputs =
      function.empty() ? output_types.size() : function.size();
  for (size_t i = 0; i < num_outputs; ++i) {
    to_return += print_comment_symbol ? "\n# " : "\n";
    if (!output_types.empty()) {
      const OutputRecipient& who = output_types[i].first;
      const DataType type = output_types[i].second;
      to_return += "(" + GetDataTypeString(type) + ")[";
      if (who.all_) {
        to_return += "A";
      } else if (who.none_) {
        to_return += "N";
      } else if (who.to_.empty()) {
        LOG_FATAL("Unsupported OutputRecipient");
      } else {
        to_return += Join(who.to_, ",");
      }
      to_return += "]:";
    }
    if (!function.empty()) {
      to_return += "\t";
      to_return += GetFormulaString(function[i]);
      if (i != num_outputs - 1) to_return += ";";
    }
  }
  to_return += print_comment_symbol ? "\n# )" : "\n)";

  return to_return;
}

string PrintFunction(
    const bool print_comment_symbol,
    const vector<vector<pair<string, DataType>>>& input_types,
    const vector<pair<OutputRecipient, DataType>>& output_types,
    const vector<Formula>& function) {
  if (!output_types.empty() && !function.empty() &&
      output_types.size() != function.size()) {
    LOG_FATAL("Mismatching output types.");
  }
  string to_return = "";
  to_return += print_comment_symbol ? "# f(" : "f(";
  if (input_types.empty()) {
    to_return += ";";
  }
  for (size_t party = 0; party < input_types.size(); ++party) {
    if (party != 0) to_return += ";";
    for (size_t i = 0; i < input_types[party].size(); ++i) {
      const pair<string, DataType>& input_one_i = input_types[party][i];
      if (i != 0) to_return += ", ";
      to_return += input_one_i.first;
    }
  }
  to_return += ")";
  if (output_types.empty() && function.empty()) {
    return to_return;
  }

  to_return += " = (";
  const size_t num_outputs =
      function.empty() ? output_types.size() : function.size();
  for (size_t i = 0; i < num_outputs; ++i) {
    to_return += print_comment_symbol ? "\n# " : "\n";
    if (!output_types.empty()) {
      const OutputRecipient& who = output_types[i].first;
      const DataType type = output_types[i].second;
      to_return += "(" + GetDataTypeString(type) + ")[";
      if (who.all_) {
        to_return += "A";
      } else if (who.none_) {
        to_return += "N";
      } else if (who.to_.empty()) {
        LOG_FATAL("Unsupported OutputRecipient");
      } else {
        to_return += Join(who.to_, ",");
      }
      to_return += "]:";
    }
    if (!function.empty()) {
      to_return += "\t";
      to_return += GetFormulaString(function[i]);
      if (i != num_outputs - 1) to_return += ";";
    }
  }
  to_return += print_comment_symbol ? "\n# )" : "\n)";

  return to_return;
}

bool ParseFunctionString(
    const string& input,
    const vector<pair<string, string>>& common_terms,
    bool* output_designation_present,
    vector<vector<string>>* input_var_names,
    vector<Formula>* function,
    vector<pair<OutputRecipient, DataType>>* output_types) {
  // Clean function string (remove spaces, tabs, and line returns).
  string function_str = RemoveAllWhitespace(input);
  // Replace common-terms (temporary variables allowed in function description)
  // with the full expression. We iterate through 'common_terms' backwards,
  // due to the required format of the Common Terms block within the .function
  // file, which has later lines (stored as elements of 'common_terms') depending
  // on variables defined in earlier lines.
  for (int i = (int) common_terms.size() - 1; i >= 0; --i) {
    const pair<string, string>& common_term = common_terms[i];
    function_str =
        Replace(function_str, common_term.first, "(" + common_term.second + ")");
  }

  // Split function LHS and RHS.
  size_t eq_pos = function_str.find("=");
  if (eq_pos == string::npos) {
    LOG_ERROR("Unable to parse function, no '=' sign:\n" + function_str);
    return false;
  }

  // Extract the variable names from function LHS.
  set<string> var_names;
  if (function != nullptr || input_var_names != nullptr) {
    const string fn_lhs_orig = function_str.substr(0, eq_pos);
    if (!HasPrefixString(fn_lhs_orig, "f(") ||
        !HasSuffixString(fn_lhs_orig, ")")) {
      LOG_ERROR("Unable to parse function, bad LHS:\n" + function_str);
      return false;
    }
    const string fn_lhs =
        StripSuffixString(StripPrefixString(fn_lhs_orig, "f("), ")");
    vector<string> var_parts;
    Split(fn_lhs, ";", false, &var_parts);
    if (input_var_names != nullptr) {
      input_var_names->resize(var_parts.size());
    }
    for (size_t i = 0; i < var_parts.size(); ++i) {
      const string& var_part = var_parts[i];
      if (var_part.empty()) continue;
      vector<string> var_names_str;
      Split(var_part, ",", &var_names_str);
      if (input_var_names != nullptr) {
        (*input_var_names)[i].resize(var_names_str.size());
      }
      for (size_t j = 0; j < var_names_str.size(); ++j) {
        const string& var_name_orig = var_names_str[j];
        // Check for index-formatting (subscript) of variable.
        vector<string> var_name_explicit(1, var_name_orig);
        if (HasPrefixString(var_name_orig, "{")) {
          int start_index, end_index;
          string var_base = "";
          if (!ParseVariableNameWithIndex(
                  var_name_orig, &start_index, &end_index, &var_base)) {
            LOG_ERROR(
                "Unable to parse variable name with indexing "
                "subscript:\n" +
                var_name_orig);
            return false;
          }
          var_name_explicit.resize(1 + end_index - start_index);
          for (int index = start_index; index <= end_index; ++index) {
            var_name_explicit[index - start_index] = var_base + Itoa(index);
          }
        }

        // Add variable name.
        for (const string& var_name : var_name_explicit) {
          if (function != nullptr && !var_names.insert(var_name).second) {
            LOG_ERROR(
                "Unable to parse function, variable name '" + var_name +
                "' appears more than once on LHS:\n" + function_str);
            return false;
          }
          if (input_var_names != nullptr) (*input_var_names)[i][j] = var_name;
        }
      }
    }
  }

  // Now parse function RHS.
  string fn_rhs = function_str.substr(eq_pos + 1);

  // Strip enclosing parentheses.
  bool rhs_has_parentheses = FunctionRhsHasEnclosingParentheses(fn_rhs);
  if (rhs_has_parentheses) {
    fn_rhs = StripSuffixString(StripPrefixString(fn_rhs, "("), ")");
  }

  // Split out each output.
  vector<string> formulas;
  Split(fn_rhs, ";", &formulas);
  if (formulas.size() > 1 && !rhs_has_parentheses) {
    LOG_ERROR(
        "Unable to parse function: Multiple outputs detected, but RHS "
        "is not enclosed in parentheses.\n" +
        function_str);
    return false;
  }
  if (function != nullptr) function->resize(formulas.size());

  // Iterate through each output, parsing the formula.
  for (size_t i = 0; i < formulas.size(); ++i) {
    const string formula_i = formulas[i];

    // Split output designation and type from formula.
    vector<string> formula_parts;
    Split(formula_i, ":", &formula_parts);
    if (formula_parts.size() != 1 && formula_parts.size() != 2) {
      LOG_ERROR(
          "Unable to parse function, bad output line '" + formula_i +
          "' in function:\n" + function_str);
      return false;
    }

    // Make sure all output lines are consistent, in terms of
    // whether they have info on output designation and type.
    if (i > 0 &&
        ((formula_parts.size() == 1 && *output_designation_present) ||
         (formula_parts.size() == 2 && !*output_designation_present))) {
      LOG_ERROR("Either all function output lines must contain "
                "output recipient and data type, or none do.");
      return false;
    }

    // Parse output designation and type, if present.
    if (formula_parts.size() == 2) {
      *output_designation_present = true;
      if (output_types != nullptr) {
        output_types->resize(formulas.size());

        // Parse output designation and type.
        pair<OutputRecipient, DataType>& output_type_i = (*output_types)[i];
        if (!HasSuffixString(formula_parts[0], "]")) {
          LOG_ERROR("Function output line has bad format: '" + formula_i + "'");
          return false;
        }
        const string no_suffix = StripSuffixString(formula_parts[0], "]");
        vector<string> output_parts;
        Split(no_suffix, "[", &output_parts);
        if (output_parts.size() != 2) {
          LOG_ERROR("Function output line has bad format: '" + formula_i + "'");
          return false;
        }

        // Parse Output DataType.
        if (!HasPrefixString(output_parts[0], "(") ||
            !HasSuffixString(output_parts[0], ")")) {
          LOG_ERROR("Function output line has bad format: '" + formula_i + "'");
          return false;
        }
        const string type_str = StripParentheses(output_parts[0]);
        output_type_i.second = StringToDataType(type_str);
        if (output_type_i.second == DataType::UNKNOWN) {
          LOG_ERROR(
              "Function output line has unrecognizable DataType: '" + formula_i +
              "'");
          return false;
        }

        // Parse Output Recipient.
        vector<string> to;
        Split(output_parts[1], ",", &to);
        bool is_first = true;
        for (const string& output_i : to) {
          if (output_i == "A") {
            output_type_i.first = OutputRecipient(true, false);
          } else if (output_i == "N") {
            output_type_i.first = OutputRecipient(false, true);
          } else {
            int index;
            if (!Stoi(output_i, &index)) {
              LOG_ERROR(
                  "Function output line has unrecognizable "
                  "OutputRecipient: '" +
                  formula_i + "'");
              return false;
            }
            if (is_first) output_type_i.first = OutputRecipient(index);
            else output_type_i.first.to_.insert(index);
          }
          is_first = false;
        }
      }
    }

    // Parse Formula.
    if (function != nullptr) {
      const string output_i = formula_parts.back();
      string error_msg = "";
      if (!ParseFormula(
              true, output_i, true, var_names, &((*function)[i]), &error_msg)) {
        LOG_ERROR(
            "Unable to parse output formula:\n" + output_i + "\n" + error_msg);
        return false;
      }
    }
  }

  return true;
}

bool ReadFunctionFile(
    const bool is_circuit_file,
    const string& filename,
    string* output_circuit_filename,
    vector<Formula>* function,
    vector<vector<GenericValue>>* input_values,
    vector<vector<pair<string, DataType>>>* input_var_types,
    vector<pair<OutputRecipient, DataType>>* output_types) {
  if (filename.empty()) LOG_FATAL("Empty filename.");

  // Clear outputs.
  if (input_values != nullptr) input_values->clear();
  if (input_var_types != nullptr) input_var_types->clear();
  if (output_types != nullptr) output_types->clear();

  // Open input file.
  ifstream input_file(filename.c_str());
  if (!input_file.is_open()) {
    LOG_ERROR(
        "Bad input to ReadFunctionFile: Unable to find '" + filename + "'");
    return false;
  }

  // Parse .function file.
  // NOTE: The code below assumes the .function file is formatted into blocks,
  // with the following order:
  //   1) Circuit Function (identified by a line with kCircuitMetadataFunction)
  //   2) [Optional] Common Terms (identified by a line with kCircuitMetadataCommonTerms)
  //   3) Party i Inputs (identified by a line with kCircuitMetadataPartyInputs)
  //   4) Output filename (identified by a line with kCircuitMetadataOutputFilename)
  bool expect_function = false;
  bool inside_common_terms = false;
  int party_index = -1;
  bool inside_output_name = false;
  bool output_designation_present = false;
  bool done_reading_function_string = false;
  bool done_with_common_terms_block = false;
  string function_str = "";
  vector<pair<string, string>> common_terms;
  int line_num = 0;
  int num_fn_open_parentheses = 0;
  string orig_line, line;
  while (getline(input_file, orig_line)) {
    line_num++;
    // No need to keep going if we've already parsed the non-null inputs.
    if (done_reading_function_string && done_with_common_terms_block &&
        input_values == nullptr && input_var_types == nullptr) {
      break;
    }
    RemoveWindowsTrailingCharacters(&orig_line);
    line = RemoveAllWhitespace(orig_line);
    if (line.empty()) continue;
    if (is_circuit_file && !HasPrefixString(line, "#")) break;
    line = StripPrefixString(line, "#");
    // Skip empty lines, or comment lines (prefixed with double-'#').
    if (line.empty() || HasPrefixString(line, "#")) continue;

    // Determine what to do based on line.
    if (line == RemoveAllWhitespace(kCircuitMetadataFunction)) {
      expect_function = true;
    } else if (line == RemoveAllWhitespace(kCircuitMetadataCommonTerms)) {
      if (expect_function || !done_reading_function_string) {
        input_file.close();
        LOG_ERROR("Expected function description.");
        return false;
      }
      inside_common_terms = true;
      party_index = -1;
    } else if (HasPrefixString(
                   line, RemoveAllWhitespace(kCircuitMetadataPartyInputs))) {
      if (expect_function || !done_reading_function_string) {
        input_file.close();
        LOG_ERROR("Expected function description.");
        return false;
      }
      string suffix = StripPrefixString(
          line, RemoveAllWhitespace(kCircuitMetadataPartyInputs));
      if (!HasSuffixString(suffix, ":")) {
        input_file.close();
        LOG_ERROR("Expected end colon");
        return false;
      }
      suffix = StripParentheses(StripSuffixString(suffix, ":"));
      if (!Stoi(suffix, &party_index) || party_index < 0) {
        input_file.close();
        LOG_ERROR("Invalid party index: '" + suffix + "'");
        return false;
      }
      if (input_values != nullptr && party_index >= 0 &&
          input_values->size() <= (size_t) party_index) {
        input_values->resize(party_index + 1);
      }
      if (input_var_types != nullptr && party_index >= 0 &&
          input_var_types->size() <= (size_t) party_index) {
        input_var_types->resize(party_index + 1);
      }
      done_with_common_terms_block = true;
      inside_common_terms = false;
    } else if (line == RemoveAllWhitespace(kCircuitMetadataOutputFilename)) {
      if (is_circuit_file || output_circuit_filename == nullptr) {
        input_file.close();
        LOG_ERROR("Output filename not expected for circuit files.");
        return false;
      }
      if (expect_function || !done_reading_function_string) {
        input_file.close();
        LOG_ERROR("Expected function description.");
        return false;
      }
      done_with_common_terms_block = true;
      inside_common_terms = false;
      party_index = -1;
      inside_output_name = true;
    } else if (expect_function) {
      // If this is the first function line, which has the function
      // description (of format f(x1, ...; y1, ...) = ...), then we
      // only need to keep the function description if we're going to
      // populate the 'function' parameter, i.e. if it is non-null.
      // Otherwise, ignore this part of the function string (since it
      // can be quite long if there are lots of inputs, and then
      // ignoring the function description saves on load time).
      if (function_str.empty() && function == nullptr &&
          HasPrefixString(line, "f(") && HasSuffixString(line, ")=(")) {
        function_str += "f()=(";
      } else {
        function_str += line;
      }
      if (!CountOpenCloseParentheses(true, line, &num_fn_open_parentheses) ||
          num_fn_open_parentheses < 0) {
        input_file.close();
        LOG_ERROR(
            "Unparsable function (has too many closed "
            "parentheses):\n\t" +
            function_str);
        return false;
      }
      // Check if this is the last line of the function specification.
      if (num_fn_open_parentheses == 0) {
        // Even though function_str is now complete (and ready to be parsed),
        // we don't parse it yet (into 'function') because we may need to
        // first read 'Common Terms' block to map variable names appearing
        // there to the actual Parties' variable names.
        done_reading_function_string = true;
        expect_function = false;
      }
    } else if (inside_common_terms) {
      if (!HasSuffixString(line, ";")) {
        input_file.close();
        LOG_ERROR("Unexpected Common Term line: '" + line + "'");
        return false;
      }
      size_t eq_pos = line.find("=");
      if (eq_pos == string::npos || line.length() - eq_pos < 3) {
        input_file.close();
        LOG_ERROR("Unexpected Common Term line: '" + line + "'");
        return false;
      }
      common_terms.push_back(make_pair(
          line.substr(0, eq_pos),
          line.substr(eq_pos + 1, line.length() - eq_pos - 2)));
    } else if (party_index >= 0) {
      if (!ParseInputLine(
              line,
              (input_values == nullptr ? nullptr :
                                         &((*input_values)[party_index])),
              (input_var_types == nullptr ?
                   nullptr :
                   &((*input_var_types)[party_index])))) {
        input_file.close();
        LOG_ERROR("Unable to parse line " + Itoa(line_num));
        return false;
      }
    } else if (inside_output_name) {
      *output_circuit_filename =
          RemoveLeadingWhitespace(StripPrefixString(orig_line, "#"));
      break;
    } else {
      input_file.close();
      LOG_ERROR("Unexpected comment line at top of circuit file:\n" + line);
      return false;
    }
  }
  input_file.close();

  // We haven't yet parsed the function RHS, as even after parsing the full
  // string, we may have needed additional information from the Common Terms
  // block to properly parse the function. Now, since Common Terms block has
  // been read, we are guaranteed to have enough info to parse function RHS.
  if (!done_reading_function_string ||
      !ParseFunctionString(
          function_str,
          common_terms,
          &output_designation_present,
          nullptr,
          function,
          output_types)) {
    LOG_ERROR("Unable to parse function: \n\t" + function_str);
    return false;
  }

  return true;
}

template<typename value_t>
bool StandardGate<value_t>::IsLocalGate() const {
  return (
      type_ == BooleanOperation::IDENTITY || type_ == BooleanOperation::NOT ||
      type_ == BooleanOperation::XOR || type_ == BooleanOperation::EQ);
}

template<typename value_t>
bool StandardGate<value_t>::IsLocallyComputable() const {
  return (IsLocalGate() || depends_on_.size() < 2);
}

bool LoadInputsToCircuit(
    const vector<vector<slice>>& inputs, StandardCircuit<slice>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to LoadInputsToCircuit().");
  // We allow for inequality below since some parties may not contribute
  // any actual inputs, but they'll still be represented in 'inputs'.
  if (inputs.size() < circuit->inputs_as_slice_locations_.size()) {
    LOG_FATAL("Mismatching inputs to LoadInputsToCircuit().");
  }

  for (size_t party = 0; party < inputs.size(); ++party) {
    // Make sure we have an actual input everywhere it is needed
    // (we allow inequality here, to allow for unused inputs of the parties).
    if (circuit->inputs_as_slice_locations_[party].size() >
        inputs[party].size()) {
      LOG_FATAL("Mismatching inputs to LoadInputsToCircuit().");
    }

    // Update 'circuit' by setting values on the input wires, for inputs coming
    // this Party.
    for (size_t i = 0; i < circuit->inputs_as_slice_locations_[party].size();
         ++i) {
      const set<WireLocation>& wires =
          circuit->inputs_as_slice_locations_[party][i];
      const slice& input_value = inputs[party][i];
      for (const WireLocation& location : wires) {
        StandardGate<slice>& current_gate =
            circuit->levels_[location.loc_.level_].gates_[location.loc_.index_];
        if (location.is_left_) {
          if (current_gate.left_input_set_) {
            LOG_FATAL(
                "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                Itoa(location.loc_.index_) +
                " has had its left wire set "
                "multiple times.");
          }
          current_gate.left_input_ = input_value;
          current_gate.left_input_set_ = true;
        } else {
          if (current_gate.right_input_set_) {
            LOG_FATAL(
                "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                Itoa(location.loc_.index_) +
                " has had its right wire set "
                "multiple times.");
          }
          current_gate.right_input_ = input_value;
          current_gate.right_input_set_ = true;
        }
      }
    }
  }

  // Update 'circuit' by setting values on the input wires, for constant inputs.
  for (const pair<const slice, set<WireLocation>>& value_and_loc :
       circuit->constant_slice_input_) {
    const set<WireLocation>& wires = value_and_loc.second;
    const slice& input_value = value_and_loc.first;
    for (const WireLocation& location : wires) {
      StandardGate<slice>& current_gate =
          circuit->levels_[location.loc_.level_].gates_[location.loc_.index_];
      if (location.is_left_) {
        if (current_gate.left_input_set_) {
          LOG_FATAL(
              "Gate at level " + Itoa(location.loc_.level_) + " and index " +
              Itoa(location.loc_.index_) +
              " has had its left wire set "
              "multiple times.");
        }
        current_gate.left_input_ = input_value;
        current_gate.left_input_set_ = true;
      } else {
        if (current_gate.right_input_set_) {
          LOG_FATAL(
              "Gate at level " + Itoa(location.loc_.level_) + " and index " +
              Itoa(location.loc_.index_) +
              " has had its right wire set "
              "multiple times.");
        }
        current_gate.right_input_ = input_value;
        current_gate.right_input_set_ = true;
      }
    }
  }

  return true;
}

bool LoadInputsToCircuit(
    const vector<vector<GenericValue>>& inputs, StandardCircuit<bool>* circuit) {
  if (circuit == nullptr) {
    LOG_FATAL("Bad Input to LoadInputsToCircuit().");
  }
  // We allow for inequality below since some parties may not contribute
  // any actual inputs, but they'll still be represented in 'inputs'.
  if (inputs.size() < circuit->inputs_as_generic_value_locations_.size()) {
    LOG_FATAL("Mismatching inputs to LoadInputsToCircuit().");
  }

  for (size_t party = 0;
       party < circuit->inputs_as_generic_value_locations_.size();
       ++party) {
    // Make sure we have an actual input everywhere it is needed
    // (we allow inequality here, to allow for unused inputs of the parties).
    if (circuit->inputs_as_generic_value_locations_[party].size() >
        inputs[party].size()) {
      LOG_FATAL("Mismatching inputs to LoadInputsToCircuit().");
    }

    // Update 'circuit' by setting values on the input wires, for inputs coming
    // this Party.
    for (size_t one_input_index = 0; one_input_index <
         circuit->inputs_as_generic_value_locations_[party].size();
         ++one_input_index) {
      const vector<set<WireLocation>>& input_to_wires =
          circuit->inputs_as_generic_value_locations_[party][one_input_index];
      if (one_input_index >= inputs[party].size()) {
        LOG_FATAL(
            "Bad inputs: " + Itoa(one_input_index) + ", " +
            Itoa(inputs[party].size()));
      }
      const GenericValue& input_value = inputs[party][one_input_index];
      for (uint64_t bit_index = 0; bit_index < input_to_wires.size();
           ++bit_index) {
        const bool input_value_bit_i = GetBit(bit_index, input_value);
        const set<WireLocation>& wires = input_to_wires[bit_index];
        for (const WireLocation& location : wires) {
          StandardGate<bool>& current_gate =
              circuit->levels_[location.loc_.level_]
                  .gates_[location.loc_.index_];
          if (location.is_left_) {
            if (current_gate.left_input_set_) {
              LOG_FATAL(
                  "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                  Itoa(location.loc_.index_) +
                  " has had its left wire set "
                  "multiple times.");
            }
            current_gate.left_input_ = input_value_bit_i;
            current_gate.left_input_set_ = true;
          } else {
            if (current_gate.right_input_set_) {
              LOG_FATAL(
                  "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                  Itoa(location.loc_.index_) +
                  " has had its right wire set "
                  "multiple times.");
            }
            current_gate.right_input_ = input_value_bit_i;
            current_gate.right_input_set_ = true;
          }
        }
      }
    }
  }

  // Update 'circuit' by setting values on the input wires, for constant inputs.
  for (const WireLocation location : circuit->constant_zero_input_) {
    StandardGate<bool>& current_gate =
        circuit->levels_[location.loc_.level_].gates_[location.loc_.index_];
    if (location.is_left_) {
      if (current_gate.left_input_set_) {
        LOG_FATAL(
            "Gate at level " + Itoa(location.loc_.level_) + " and index " +
            Itoa(location.loc_.index_) +
            " has had its left wire set "
            "multiple times.");
      }
      current_gate.left_input_ = false;
      current_gate.left_input_set_ = true;
    } else {
      if (current_gate.right_input_set_) {
        LOG_FATAL(
            "Gate at level " + Itoa(location.loc_.level_) + " and index " +
            Itoa(location.loc_.index_) +
            " has had its right wire set "
            "multiple times.");
      }
      current_gate.right_input_ = false;
      current_gate.right_input_set_ = true;
    }
  }
  for (const WireLocation& location : circuit->constant_one_input_) {
    StandardGate<bool>& current_gate =
        circuit->levels_[location.loc_.level_].gates_[location.loc_.index_];
    if (location.is_left_) {
      if (current_gate.left_input_set_) {
        LOG_FATAL(
            "Gate at level " + Itoa(location.loc_.level_) + " and index " +
            Itoa(location.loc_.index_) +
            " has had its left wire set "
            "multiple times.");
      }
      current_gate.left_input_ = true;
      current_gate.left_input_set_ = true;
    } else {
      if (current_gate.right_input_set_) {
        LOG_FATAL(
            "Gate at level " + Itoa(location.loc_.level_) + " and index " +
            Itoa(location.loc_.index_) +
            " has had its right wire set "
            "multiple times.");
      }
      current_gate.right_input_ = true;
      current_gate.right_input_set_ = true;
    }
  }

  return true;
}

template<typename value_t>
void StandardCircuit<value_t>::ClearCircuitValues() {
  // Remove values on (global) output wires (all other wires are considered
  // 'input' wires, and will be cleared below when processing the gate that
  // they input into).
  outputs_as_bits_.clear();
  outputs_as_slice_.clear();
  outputs_as_generic_value_.clear();

  // Go through every gate, removing values on input wires.
  for (StandardCircuitLevel<value_t>& level : levels_) {
    for (StandardGate<value_t>& gate : level.gates_) {
      // Remove values on input wires. Actually, we just need to indicate
      // that each input wire hasn't been set, so that a future run will
      // know that the current values are invalid (and can be overwritten
      // when the Evaluating the circuit with new input).
      gate.left_input_set_ = false;
      gate.right_input_set_ = false;

      // Clear the truth table mask (ditto above about just flipping
      // the bit that indicates whether the mask has been set).
      gate.mask_set_ = false;
    }
  }
}

template<typename value_t>
uint64_t StandardCircuit<value_t>::GetNumberOutputBits() const {
  // This information is directly available as the number of output wires,
  // provided this field is populated (which is always should be...).
  if (num_output_wires_ > 0) {
    return num_output_wires_;
  }

  uint64_t to_return = 0;
  for (const pair<OutputRecipient, DataType>& output_i : output_designations_) {
    to_return += GetValueNumBits(output_i.second);
  }

  // The output_designations_ field is optional (it is populated via metadata
  // in the circuit file, which is *not* mandatory). When it is missing, it
  // is assumed all outputs are bits.
  if (to_return == 0) {
    LOG_FATAL("Number of output bits not available.");
  }

  return to_return;
}

template<typename value_t>
bool StandardCircuit<value_t>::ConvertOutputs() {
  // If output_designations_ field is empty, this means all output wires should
  // be interpretted to be actual output values (i.e. all output values are
  // interpreted as BOOL DataType).
  if (output_designations_.empty()) {
    if (num_output_wires_ != (int64_t) outputs_as_bits_.size()) {
      LOG_FATAL("Mismatching number of bits.");
    }
    outputs_as_generic_value_.clear();
    outputs_as_generic_value_.resize(num_output_wires_);
    for (uint64_t output_index = 0; output_index < outputs_as_bits_.size();
         ++output_index) {
      outputs_as_generic_value_[output_index] = GenericValue(
          (bool) (outputs_as_bits_[output_index] & (unsigned char) 1));
    }
    return true;
  }

  // Since we didn't return above, we have specficiation of the output DataTypes.
  // Combine congruous wires to form the DataType values they represent.
  // First, get a mapping from wire index to output value's (index, bit-index).
  vector<pair<uint64_t, uint64_t>> output_wire_to_output_index_and_bit;
  GetOutputWireIndexToGenericValueIndex(
      output_designations_, &output_wire_to_output_index_and_bit);

  // We will walk through output_wire_to_output_index_and_bit, setting one
  // bit of each output value at a time. Initialize each bit of each output
  // value to be zero.
  const uint64_t num_outputs = output_designations_.size();
  vector<string> outputs_as_twos_complement(num_outputs, "");
  for (uint64_t output_index = 0; output_index < num_outputs; ++output_index) {
    const DataType type_i = output_designations_[output_index].second;
    const uint64_t num_bits = GetValueNumBits(type_i);
    for (uint64_t bit_index = 0; bit_index < num_bits; ++bit_index) {
      outputs_as_twos_complement[output_index] += "0";
    }
  }

  // Go through the Output wires, converting the wire values (bits) to form
  // the corresponding output value (of the appropriate DataType).
  if (output_wire_to_output_index_and_bit.size() != outputs_as_bits_.size()) {
    LOG_FATAL("Mismatching number of bits.");
  }
  for (uint64_t i = 0; i < outputs_as_bits_.size(); ++i) {
    const unsigned char& output_i = outputs_as_bits_[i];
    const bool output_bit_i = (output_i & 1);
    if (!output_bit_i) continue;
    const pair<uint64_t, uint64_t>& output_indices =
        output_wire_to_output_index_and_bit[i];
    const size_t num_bits_in_output =
        outputs_as_twos_complement[output_indices.first].length();
    if (output_indices.first >= num_outputs ||
        output_indices.second >= num_bits_in_output) {
      LOG_FATAL("Mismatching number of bits.");
    }
    outputs_as_twos_complement[output_indices.first].replace(
        (num_bits_in_output - 1 - output_indices.second), 1, "1");
  }

  // Finally, convert the binary string representations of each output into
  // the value that it represents.
  outputs_as_generic_value_.clear();
  outputs_as_generic_value_.resize(num_outputs);
  for (uint64_t output_index = 0; output_index < num_outputs; ++output_index) {
    if (!ParseGenericValueFromTwosComplementString(
            output_designations_[output_index].second,
            outputs_as_twos_complement[output_index],
            &(outputs_as_generic_value_[output_index]))) {
      LOG_ERROR(
          "Unable to convert output " + Itoa(output_index) +
          " from binary string (from output wires) '" +
          outputs_as_twos_complement[output_index] + "' to a GenericValue.");
      return false;
    }
  }

  return true;
}

// Based on the current (input) gate location, finds the location of the
// next gate in the circuit (i.e. the next gate (index) on the same level,
// or if this is the last gate on the level, then the first gate on the
// next level). Returns false if the current (input) location is invalid,
// or if there is no next gate (current location is the final gate).
template<typename value_t>
bool StandardCircuit<value_t>::GetNextGateLocation(
    GateLocation* location) const {
  if (location == nullptr) LOG_FATAL("Bad input to GetNextGateLocation().");

  // Return false if circuit is empty.
  if (levels_.empty() || levels_[0].gates_.empty()) {
    return false;
  }

  // If level_ is negative, set next gate location to be the first gate.
  if (location->level_ < 0) {
    location->level_ = 0;
    location->index_ = 0;
    return true;
  }

  // Check that the input level is within the circuit.
  if (location->level_ >= (int64_t) levels_.size()) {
    return false;
  }

  // If index_ is negative, set next gate location to be the first gate
  // at the input level.
  if (location->index_ < 0) {
    location->index_ = 0;
    return true;
  }

  const StandardCircuitLevel<value_t>& level = levels_[location->level_];

  // Check that the input gate index is within the level.
  if (location->index_ >= (int64_t) level.gates_.size()) {
    return false;
  }

  // If this is *not* the last gate on this level, next gate is simply the
  // next gate on this level.
  if (location->index_ != (int64_t) level.gates_.size() - 1) {
    (location->index_)++;
    return true;
  }

  // Current location is last gate on level; so next gate is the first gate
  // on the next level, if such a gate exists.
  if (location->level_ == (int64_t) levels_.size() - 1) {
    return false;
  }

  // Set next gate location to be the first gate on the next level.
  (location->level_)++;
  location->index_ = 0;

  return true;
}

template<typename value_t>
bool StandardCircuit<value_t>::SetInputsForNextLevel(
    const int64_t& prev_level_index) {
  const StandardCircuitLevel<value_t>& previous_level =
      levels_[prev_level_index];
  const bool is_format_one = format_ == CircuitFormat::FORMAT_ONE;
  for (size_t gate_index = 0; gate_index < previous_level.gates_.size();
       ++gate_index) {
    const value_t& output_value =
        previous_level.gates_[gate_index].output_value_;
    for (const WireLocation& loc :
         previous_level.gates_[gate_index].output_wire_locations_) {
      const GateLocation& output_wire_loc = loc.loc_;

      // A negative level for the output wire either indicates that
      // this is a global output wire (in which case the location index
      // should be non-negative) or that the output wire location was
      // not set (an error).
      if (output_wire_loc.level_ < 0) {
        if (output_wire_loc.index_ < 0) {
          LOG_ERROR(
              "Unable to SetInputsForNextLevel(): Gate " + Itoa(gate_index) +
              " has not set the location of its output_wire_.");
          return false;
        }
        // This is a global output wire.
        // Resize outputs_as_[slice | bits]_ if necessary.
        if (is_format_one) {
          if ((int64_t) outputs_as_slice_.size() <= output_wire_loc.index_) {
            outputs_as_slice_.resize(output_wire_loc.index_ + 1);
          }
          outputs_as_slice_[output_wire_loc.index_] = (slice) output_value;
        } else {
          if ((int64_t) outputs_as_bits_.size() <= output_wire_loc.index_) {
            outputs_as_bits_.resize(output_wire_loc.index_ + 1);
          }
          outputs_as_bits_[output_wire_loc.index_] =
              (unsigned char) output_value;
        }
      } else {
        // This is an internal wire. Copy the output value to the appropriate
        // input wire.
        if ((int64_t) levels_.size() <= output_wire_loc.level_ ||
            (int64_t) levels_[output_wire_loc.level_].gates_.size() <=
                output_wire_loc.index_) {
          LOG_ERROR(
              "Unable to SetInputsForNextLevel(): Gate " + Itoa(gate_index) +
              " has an output_wire_ that does not index a valid gate "
              "(" +
              Itoa(output_wire_loc.level_) + ", " +
              Itoa(output_wire_loc.index_) + ").");
          return false;
        }
        if (loc.is_left_) {
          levels_[output_wire_loc.level_]
              .gates_[output_wire_loc.index_]
              .left_input_set_ = true;
          levels_[output_wire_loc.level_]
              .gates_[output_wire_loc.index_]
              .left_input_ = output_value;
        } else {
          levels_[output_wire_loc.level_]
              .gates_[output_wire_loc.index_]
              .right_input_set_ = true;
          levels_[output_wire_loc.level_]
              .gates_[output_wire_loc.index_]
              .right_input_ = output_value;
        }
      }
    }
  }

  return true;
}

template<typename value_t>
bool StandardCircuit<value_t>::EvaluateCircuit() {
  outputs_as_bits_.clear();
  outputs_as_slice_.clear();
  outputs_as_generic_value_.clear();

  const bool is_format_one = format_ == CircuitFormat::FORMAT_ONE;

  // Resize outputs_as_bits_ here (if we know ahead of time how many output
  // gates there are) to avoid having to resize() outputs_as_bits_ every
  // time a new output gate is encountered.
  if (num_output_wires_ > 0) {
    if (is_format_one) {
      outputs_as_slice_.resize(num_output_wires_);
    } else {
      outputs_as_bits_.resize(GetNumberOutputBits());
    }
  }
  if (num_outputs_ > 0 && !is_format_one) {
    outputs_as_generic_value_.resize(num_outputs_);
  }

  for (size_t level = 0; level < levels_.size(); ++level) {
    // Evaluate all gates on this level.
    if (!levels_[level].EvaluateLevel()) {
      LOG_ERROR("Failed to EvaluateCircuit() at level " + Itoa(level));
      return false;
    }
    // Copy values on output wires to the appropriate input wires
    // of the next level's gates.
    if (!SetInputsForNextLevel(level)) {
      LOG_ERROR("Failed to EvaluateCircuit() at level " + Itoa(level));
      return false;
    }
  }

  // If this is a Format 2 circuit, convert output wire values (which
  // are the bits of an actual GenericValue) to the actual output value.
  return (is_format_one || ConvertOutputs());
}

bool EvaluateCircuit(
    const map<WireLocation, slice>& inputs, StandardCircuit<slice>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to EvaluateCircuit().");

  // Update 'circuit' by setting values on the input wires.
  for (const pair<const WireLocation, slice>& loc_and_value : inputs) {
    if (loc_and_value.first.loc_.level_ < 0 ||
        (size_t) loc_and_value.first.loc_.level_ >= circuit->levels_.size() ||
        loc_and_value.first.loc_.index_ < 0 ||
        (size_t) loc_and_value.first.loc_.index_ >=
            circuit->levels_[loc_and_value.first.loc_.level_].gates_.size()) {
      LOG_FATAL(
          "Unable to EvaluateCircuit(): Bad level " +
          Itoa(loc_and_value.first.loc_.level_) + " or index " +
          Itoa(loc_and_value.first.loc_.index_) + " in inputs");
    }
    if (loc_and_value.first.is_left_) {
      circuit->levels_[loc_and_value.first.loc_.level_]
          .gates_[loc_and_value.first.loc_.index_]
          .left_input_set_ = true;
      circuit->levels_[loc_and_value.first.loc_.level_]
          .gates_[loc_and_value.first.loc_.index_]
          .left_input_ = loc_and_value.second;
    } else {
      circuit->levels_[loc_and_value.first.loc_.level_]
          .gates_[loc_and_value.first.loc_.index_]
          .right_input_set_ = true;
      circuit->levels_[loc_and_value.first.loc_.level_]
          .gates_[loc_and_value.first.loc_.index_]
          .right_input_ = loc_and_value.second;
    }
  }

  // Evaluate circuit.
  return circuit->EvaluateCircuit();
}

bool EvaluateCircuit(
    const map<WireLocation, bool>& inputs, StandardCircuit<bool>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to EvaluateCircuit().");

  // Update 'circuit' by setting values on the input wires.
  for (const pair<const WireLocation, bool>& loc_and_value : inputs) {
    if (loc_and_value.first.loc_.level_ < 0 ||
        (size_t) loc_and_value.first.loc_.level_ >= circuit->levels_.size() ||
        loc_and_value.first.loc_.index_ < 0 ||
        (size_t) loc_and_value.first.loc_.index_ >=
            circuit->levels_[loc_and_value.first.loc_.level_].gates_.size()) {
      LOG_FATAL(
          "Unable to EvaluateCircuit(): Bad level " +
          Itoa(loc_and_value.first.loc_.level_) + " or index " +
          Itoa(loc_and_value.first.loc_.index_) + " in inputs");
    }
    if (loc_and_value.first.is_left_) {
      circuit->levels_[loc_and_value.first.loc_.level_]
          .gates_[loc_and_value.first.loc_.index_]
          .left_input_set_ = true;
      circuit->levels_[loc_and_value.first.loc_.level_]
          .gates_[loc_and_value.first.loc_.index_]
          .left_input_ = loc_and_value.second;
    } else {
      circuit->levels_[loc_and_value.first.loc_.level_]
          .gates_[loc_and_value.first.loc_.index_]
          .right_input_set_ = true;
      circuit->levels_[loc_and_value.first.loc_.level_]
          .gates_[loc_and_value.first.loc_.index_]
          .right_input_ = loc_and_value.second;
    }
  }

  // Evaluate circuit.
  return circuit->EvaluateCircuit();
}

bool EvaluateCircuit(
    const map<GateLocation, slice>& left_inputs,
    const map<GateLocation, slice>& right_inputs,
    StandardCircuit<slice>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to EvaluateCircuit().");
  if (circuit->levels_.empty() ||
      // We allow inequality here, as some gates may be NOT or IDENTITY gates,
      // in which case only left_input needs to be set.
      left_inputs.size() < right_inputs.size()) {
    LOG_FATAL("Bad Input to EvaluateCircuit().");
  }

  // Update 'circuit' by setting values on the input wires.
  for (const pair<const GateLocation, slice>& loc_and_value : left_inputs) {
    if (loc_and_value.first.level_ < 0 ||
        (size_t) loc_and_value.first.level_ >= circuit->levels_.size() ||
        loc_and_value.first.index_ < 0 ||
        (size_t) loc_and_value.first.index_ >=
            circuit->levels_[loc_and_value.first.level_].gates_.size()) {
      LOG_FATAL(
          "Unable to EvaluateCircuit(): Bad level " +
          Itoa(loc_and_value.first.level_) + " or index " +
          Itoa(loc_and_value.first.index_) + " in inputs");
    }
    circuit->levels_[loc_and_value.first.level_]
        .gates_[loc_and_value.first.index_]
        .left_input_set_ = true;
    circuit->levels_[loc_and_value.first.level_]
        .gates_[loc_and_value.first.index_]
        .left_input_ = loc_and_value.second;
  }
  for (const pair<const GateLocation, slice>& loc_and_value : right_inputs) {
    if (loc_and_value.first.level_ < 0 ||
        (size_t) loc_and_value.first.level_ >= circuit->levels_.size() ||
        loc_and_value.first.index_ < 0 ||
        (size_t) loc_and_value.first.index_ >=
            circuit->levels_[loc_and_value.first.level_].gates_.size()) {
      LOG_FATAL(
          "Unable to EvaluateCircuit(): Bad level " +
          Itoa(loc_and_value.first.level_) + " or index " +
          Itoa(loc_and_value.first.index_) + " in inputs");
    }
    circuit->levels_[loc_and_value.first.level_]
        .gates_[loc_and_value.first.index_]
        .right_input_set_ = true;
    circuit->levels_[loc_and_value.first.level_]
        .gates_[loc_and_value.first.index_]
        .right_input_ = loc_and_value.second;
  }

  // Evaluate circuit.
  return circuit->EvaluateCircuit();
}

bool EvaluateCircuit(
    const map<GateLocation, bool>& left_inputs,
    const map<GateLocation, bool>& right_inputs,
    StandardCircuit<bool>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to EvaluateCircuit().");
  if (circuit->levels_.empty() ||
      // We allow inequality here, as some gates may be NOT or IDENTITY gates,
      // in which case only left_input needs to be set.
      left_inputs.size() < right_inputs.size()) {
    LOG_FATAL("Bad Input to EvaluateCircuit().");
  }

  // Update 'circuit' by setting values on the input wires.
  for (const pair<const GateLocation, bool>& loc_and_value : left_inputs) {
    if (loc_and_value.first.level_ < 0 ||
        (size_t) loc_and_value.first.level_ >= circuit->levels_.size() ||
        loc_and_value.first.index_ < 0 ||
        (size_t) loc_and_value.first.index_ >=
            circuit->levels_[loc_and_value.first.level_].gates_.size()) {
      LOG_FATAL(
          "Unable to EvaluateCircuit(): Bad level " +
          Itoa(loc_and_value.first.level_) + " or index " +
          Itoa(loc_and_value.first.index_) + " in inputs");
    }
    circuit->levels_[loc_and_value.first.level_]
        .gates_[loc_and_value.first.index_]
        .left_input_set_ = true;
    circuit->levels_[loc_and_value.first.level_]
        .gates_[loc_and_value.first.index_]
        .left_input_ = loc_and_value.second;
  }
  for (const pair<const GateLocation, bool>& loc_and_value : right_inputs) {
    if (loc_and_value.first.level_ < 0 ||
        (size_t) loc_and_value.first.level_ >= circuit->levels_.size() ||
        loc_and_value.first.index_ < 0 ||
        (size_t) loc_and_value.first.index_ >=
            circuit->levels_[loc_and_value.first.level_].gates_.size()) {
      LOG_FATAL(
          "Unable to EvaluateCircuit(): Bad level " +
          Itoa(loc_and_value.first.level_) + " or index " +
          Itoa(loc_and_value.first.index_) + " in inputs");
    }
    circuit->levels_[loc_and_value.first.level_]
        .gates_[loc_and_value.first.index_]
        .right_input_set_ = true;
    circuit->levels_[loc_and_value.first.level_]
        .gates_[loc_and_value.first.index_]
        .right_input_ = loc_and_value.second;
  }

  // Evaluate circuit.
  return circuit->EvaluateCircuit();
}

bool EvaluateCircuit(
    const vector<slice>& inputs, StandardCircuit<slice>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to EvaluateCircuit().");
  // Make sure we have an actual input everywhere it is needed
  // (we allow inequality here, to allow for unused inputs of the parties).
  if (circuit->inputs_as_slice_locations_.size() != 1 ||
      circuit->inputs_as_slice_locations_[0].size() > inputs.size()) {
    LOG_FATAL("Bad Input to EvaluateCircuit().");
  }

  // Update 'circuit' by setting values on the input wires.
  for (size_t i = 0; i < circuit->inputs_as_slice_locations_[0].size(); ++i) {
    const set<WireLocation>& wires = circuit->inputs_as_slice_locations_[0][i];
    const slice& input_value = inputs[i];
    for (const WireLocation& location : wires) {
      StandardGate<slice>& current_gate =
          circuit->levels_[location.loc_.level_].gates_[location.loc_.index_];
      if (location.is_left_) {
        if (current_gate.left_input_set_) {
          LOG_FATAL(
              "Gate at level " + Itoa(location.loc_.level_) + " and index " +
              Itoa(location.loc_.index_) +
              " has had its left wire set "
              "multiple times.");
        }
        current_gate.left_input_ = input_value;
        current_gate.left_input_set_ = true;
      } else {
        if (current_gate.right_input_set_) {
          LOG_FATAL(
              "Gate at level " + Itoa(location.loc_.level_) + " and index " +
              Itoa(location.loc_.index_) +
              " has had its right wire set "
              "multiple times.");
        }
        current_gate.right_input_ = input_value;
        current_gate.right_input_set_ = true;
      }
    }
  }

  // Evaluate circuit.
  return circuit->EvaluateCircuit();
}

bool EvaluateCircuit(
    const vector<GenericValue>& inputs, StandardCircuit<bool>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to EvaluateCircuit().");
  // Make sure we have an actual input everywhere it is needed
  // (we allow inequality here, to allow for unused inputs of the parties).
  if (circuit->inputs_as_generic_value_locations_.size() != 1 ||
      circuit->inputs_as_generic_value_locations_[0].size() > inputs.size()) {
    LOG_FATAL("Bad Input to EvaluateCircuit().");
  }

  // Update 'circuit' by setting values on the input wires.
  for (size_t one_input_index = 0;
       one_input_index < circuit->inputs_as_generic_value_locations_[0].size();
       ++one_input_index) {
    const vector<set<WireLocation>>& input_to_wires =
        circuit->inputs_as_generic_value_locations_[0][one_input_index];
    if (one_input_index >= inputs.size()) LOG_FATAL("Bad inputs.");
    const GenericValue& input_value = inputs[one_input_index];
    for (uint64_t bit_index = 0; bit_index < input_to_wires.size();
         ++bit_index) {
      const set<WireLocation>& wires = input_to_wires[bit_index];
      for (const WireLocation& location : wires) {
        StandardGate<bool>& current_gate =
            circuit->levels_[location.loc_.level_].gates_[location.loc_.index_];
        if (location.is_left_) {
          if (current_gate.left_input_set_) {
            LOG_FATAL(
                "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                Itoa(location.loc_.index_) +
                " has had its left wire set "
                "multiple times.");
          }
          current_gate.left_input_ = GetBit(bit_index, input_value);
          current_gate.left_input_set_ = true;
        } else {
          if (current_gate.right_input_set_) {
            LOG_FATAL(
                "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                Itoa(location.loc_.index_) +
                " has had its right wire set "
                "multiple times.");
          }
          current_gate.right_input_ = GetBit(bit_index, input_value);
          current_gate.right_input_set_ = true;
        }
      }
    }
  }

  // Evaluate circuit.
  return circuit->EvaluateCircuit();
}

bool EvaluateCircuit(
    const vector<vector<slice>>& inputs, StandardCircuit<slice>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to EvaluateCircuit().");

  if (!LoadInputsToCircuit(inputs, circuit)) {
    LOG_ERROR("Failed to EvaluateCircuit(): Unable to load inputs.");
    return false;
  }

  // Evaluate circuit.
  return circuit->EvaluateCircuit();
}

bool EvaluateCircuit(
    const vector<vector<GenericValue>>& inputs, StandardCircuit<bool>* circuit) {
  if (circuit == nullptr) LOG_FATAL("Bad Input to EvaluateCircuit().");

  if (!LoadInputsToCircuit(inputs, circuit)) {
    LOG_ERROR("Failed to EvaluateCircuit(): Unable to load inputs.");
    return false;
  }

  // Evaluate circuit.
  return circuit->EvaluateCircuit();
}

bool EvaluateGate(StandardGate<bool>* gate) {
  if (gate->type_ == BooleanOperation::UNKNOWN) {
    LOG_ERROR("Unknown gate type in EvaluateGate().");
    return false;
  }

  // Make sure input wires have been set.
  if (!IsInputWiresSet(
          gate->left_input_set_, gate->right_input_set_, gate->type_)) {
    LOG_ERROR(
        "Unable to EvaluateGate() at level " + Itoa(gate->loc_.level_) +
        " and gate index " + Itoa(gate->loc_.index_) +
        ": Input wire values not properly set (Left is set: " +
        Itoa(gate->left_input_set_) +
        ", Right is set: " + Itoa(gate->right_input_set_) +
        ", Gate Type:" + GetOpString(gate->type_) + ")");
    return false;
  }

  switch (gate->type_) {
    case BooleanOperation::IDENTITY: {
      gate->output_value_ =
          gate->left_input_set_ ? gate->left_input_ : gate->right_input_;
      break;
    }
    case BooleanOperation::NOT: {
      gate->output_value_ =
          gate->left_input_set_ ? !gate->left_input_ : !gate->right_input_;
      break;
    }
    case BooleanOperation::OR: {
      gate->output_value_ = gate->left_input_ || gate->right_input_;
      break;
    }
    case BooleanOperation::NOR: {
      gate->output_value_ = !(gate->left_input_ || gate->right_input_);
      break;
    }
    case BooleanOperation::XOR: {
      gate->output_value_ = gate->left_input_ != gate->right_input_;
      break;
    }
    case BooleanOperation::EQ: {
      gate->output_value_ = gate->left_input_ == gate->right_input_;
      break;
    }
    case BooleanOperation::AND: {
      gate->output_value_ = gate->left_input_ && gate->right_input_;
      break;
    }
    case BooleanOperation::NAND: {
      gate->output_value_ = !(gate->left_input_ && gate->right_input_);
      break;
    }
    case BooleanOperation::LT: {
      gate->output_value_ = (!gate->left_input_) && gate->right_input_;
      break;
    }
    case BooleanOperation::LTE: {
      gate->output_value_ = (!gate->left_input_) || gate->right_input_;
      break;
    }
    case BooleanOperation::GT: {
      gate->output_value_ = gate->left_input_ && (!gate->right_input_);
      break;
    }
    case BooleanOperation::GTE: {
      gate->output_value_ = gate->left_input_ || (!gate->right_input_);
      break;
    }
    default: {
      LOG_ERROR(
          "Unknown gate operation in EvaluateGate(): " +
          Itoa(static_cast<int>(gate->type_)));
      return false;
    }
  }

  return true;
}

bool EvaluateGate(StandardGate<slice>* gate) {
  if (gate->type_ == BooleanOperation::UNKNOWN) {
    LOG_ERROR("Unknown gate type in EvaluateGate().");
    return false;
  }

  // Make sure input wires have been set.
  if (!IsInputWiresSet(
          gate->left_input_set_, gate->right_input_set_, gate->type_)) {
    LOG_ERROR(
        "Unable to EvaluateGate() at level " + Itoa(gate->loc_.level_) +
        " and index " + Itoa(gate->loc_.index_) +
        ": Input wire values not set.");
    return false;
  }

  switch (gate->type_) {
    case BooleanOperation::IDENTITY: {
      gate->output_value_ =
          gate->left_input_set_ ? gate->left_input_ : gate->right_input_;
      break;
    }
    case BooleanOperation::NOT: {
      gate->output_value_ =
          gate->left_input_set_ ? ~(gate->left_input_) : ~(gate->right_input_);
      break;
    }
    case BooleanOperation::OR: {
      gate->output_value_ = gate->left_input_ | gate->right_input_;
      break;
    }
    case BooleanOperation::NOR: {
      gate->output_value_ = ~(gate->left_input_ | gate->right_input_);
      break;
    }
    case BooleanOperation::XOR: {
      gate->output_value_ = gate->left_input_ ^ gate->right_input_;
      break;
    }
    case BooleanOperation::EQ: {
      gate->output_value_ = ~(gate->left_input_ ^ gate->right_input_);
      break;
    }
    case BooleanOperation::AND: {
      gate->output_value_ = gate->left_input_ & gate->right_input_;
      break;
    }
    case BooleanOperation::NAND: {
      gate->output_value_ = ~(gate->left_input_ & gate->right_input_);
      break;
    }
    case BooleanOperation::LT: {
      gate->output_value_ = (~gate->left_input_) & gate->right_input_;
      break;
    }
    case BooleanOperation::LTE: {
      gate->output_value_ = (~gate->left_input_) | gate->right_input_;
      break;
    }
    case BooleanOperation::GT: {
      gate->output_value_ = gate->left_input_ & (~gate->right_input_);
      break;
    }
    case BooleanOperation::GTE: {
      gate->output_value_ = gate->left_input_ | (~gate->right_input_);
      break;
    }
    default: {
      LOG_ERROR(
          "Unknown gate operation in EvaluateGate(): " +
          Itoa(static_cast<int>(gate->type_)));
      return false;
    }
  }

  return true;
}

// Explicit instantiations of the two types that will be needed for all
// templates (i.e. the types that 'value_t' will assume).
// (These declarations are necessary to have template definitions in the
// present .cpp file (instead of the .h), and not encounter link errors...).
template class StandardGate<bool>;
template class StandardGate<slice>;
template class StandardCircuitLevel<bool>;
template class StandardCircuitLevel<slice>;
template class StandardCircuit<bool>;
template class StandardCircuit<slice>;

}  // namespace multiparty_computation
}  // namespace crypto
