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

#include "circuit_converter_utils.h"

#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"  // For OutputRecipient.
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"  // For StandardCircuit.
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit_by_gate.h"  // For CircuitByGate.
#include "MapUtils/map_utils.h"  // For FindOrInsert()
#include "MathUtils/constants.h"  // For slice
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "MathUtils/formula_utils.h"  // For Formula.
#include "global_utils.h"

#include <fstream>
#include <iostream>  // For std::cout.
#include <string>

using namespace map_utils;
using namespace math_utils;
using namespace string_utils;
using namespace std;

namespace crypto {
namespace multiparty_computation {

using namespace scratch;

namespace {
// For .circuit_by_gate format, we can force all gates to have depends_on_ indicate
// that all gates depend on all parties; this is useful for use-cases when all
// inputs are (already) secret-shared amongst all parties.
static bool kForceDependsOnAll = false;
}  // namespace

bool LoadCircuit(const string& filename, StandardCircuit<slice>* output) {
  return output->LoadCircuit(filename);
}

bool LoadCircuit(const string& filename, StandardCircuit<bool>* output) {
  output->load_function_description_ = true;
  output->load_all_metadata_ = true;
  return output->LoadCircuit(filename);
}

bool LoadCircuit(const string& filename, CircuitByGate* output) {
  output->SetCircuitFilename(filename);
  bool is_done = false;
  return output->ReadCircuitFile(true, &is_done) && is_done;
}

// TODO(PHB): Implement the following three LoadCircuit() APIs.
bool LoadCircuit(const string&, sri_circuit*) { return false; }
bool LoadCircuit(const string&, spar_gate*) { return false; }
bool LoadCircuit(const string&, durasift_circuit*) { return false; }

bool ConvertCircuit(const StandardCircuit<bool>* input, CircuitByGate* output) {
  const int num_parties = (int) input->input_types_.size();
  output->num_gates_ = (GateIndexDataType) input->size_;
  output->num_levels_ = (GateIndexDataType) input->levels_.size();
  output->num_gates_per_level_.reserve(output->num_levels_);
  for (const StandardCircuitLevel<bool>& level_i : input->levels_) {
    output->num_gates_per_level_.push_back((unsigned int) level_i.gates_.size());
  }
  output->num_outputs_ = (GateIndexDataType) input->num_outputs_;
  output->function_var_names_.resize(num_parties);
  for (int party = 0; party < num_parties; ++party) {
    vector<string>& party_i_var_names = output->function_var_names_[party];
    party_i_var_names.reserve(input->input_types_[party].size());
    for (const pair<string, DataType>& input_i : input->input_types_[party]) {
      party_i_var_names.push_back(input_i.first);
    }
  }
  output->function_description_ = input->function_description_;
  output->output_designations_ = input->output_designations_;
  for (size_t i = 0; i < input->output_designations_.size(); ++i) {
    const DataType output_i = input->output_designations_[i].second;
    if (output_i == DataType::BOOL) continue;
    output->datatypes_of_arith_from_bool_gates_.insert(
        make_pair(output->num_gates_ + i, output_i));
  }
  const int num_party_pairs = (num_parties * (num_parties - 1)) / 2;
  output->num_non_local_boolean_gates_per_party_pairs_.resize(
      num_party_pairs, 0);
  output->num_non_local_arithmetic_gates_per_party_pairs_.resize(
      num_party_pairs, 0);

  // Some work must be done to convert global output wires (bits) to the
  // appropriate output DataType it generates (this is because even though
  // the underlying circuit has all wires with bool values, the global
  // output wires might be supposed to be interpretted as a bit of a
  // non-bool value; in this case, we need to handle such output wires specially).
  vector<pair<uint64_t, uint64_t>> output_wire_to_output_index_and_bit;
  GetOutputWireIndexToGenericValueIndex(
      input->output_designations_, &output_wire_to_output_index_and_bit);
  if ((int64_t) output_wire_to_output_index_and_bit.size() !=
      input->num_output_wires_) {
    return false;
  }

  // We need to loop through the gates in StandardCircuit twice:
  //   1) Get the mapping of GateLocation (level, index) to gate-only index
  //   2) Now with the mapping, each gate's original (OutputWireLocation)
  //      output wires can be mapped to the new (gate-only) index.
  // Do (1); also set each Gate's depends_on_ and op_ fields, and overall
  // circuit's num_non_local_boolean_gates_per_party_pairs_, as we go.
  const int depends_on_size =
      num_parties / CHAR_BIT + ((num_parties % CHAR_BIT == 0) ? 0 : 1);
  map<GateLocation, GateIndexDataType> in_index_to_out_index;
  output->gates_.reserve(output->num_gates_ + output->num_outputs_);
  GateIndexDataType gate_index = 0;
  for (const StandardCircuitLevel<bool>& level : input->levels_) {
    for (const StandardGate<bool>& gate : level.gates_) {
      in_index_to_out_index.insert(make_pair(gate.loc_, gate_index));
      ++gate_index;
      Gate to_add;
      if (!kForceDependsOnAll) {
        to_add.depends_on_.resize(depends_on_size, 0);
        char byte_i = 0;
        int current_byte = 0;
        for (const int i : gate.depends_on_) {
          if (i / CHAR_BIT > current_byte) {
            to_add.depends_on_[current_byte] = byte_i;
            current_byte = i / CHAR_BIT;
            byte_i = 0;
          }
          byte_i = (char) (byte_i | 1 << (CHAR_BIT - 1 - (i % CHAR_BIT)));
        }
        // Update final byte of to_add.depends_on_ (which was not updated in loop).
        to_add.depends_on_[current_byte] = byte_i;
      }
      to_add.op_ = BoolOpToCircuitOp(gate.type_);
      if (!output->gates_.Push(to_add)) {
        return false;
      }
      // Update num_non_local_boolean_gates_per_party_pairs_.
      if (!gate.IsLocalGate()) {
        if (kForceDependsOnAll) {
          for (int i = 0; i < num_parties; ++i) {
            for (int j = i + 1; j < num_parties; ++j) {
              ++(output->num_non_local_boolean_gates_per_party_pairs_
                     [((i * (2 * num_parties - i - 1)) / 2) + (j - i - 1)]);
            }
          }
        } else {
          for (const int i : gate.depends_on_) {
            for (const int j : gate.depends_on_) {
              if (i >= j) continue;
              ++(output->num_non_local_boolean_gates_per_party_pairs_
                     [((i * (2 * num_parties - i - 1)) / 2) + (j - i - 1)]);
            }
          }
        }
      }
    }
  }
  // Now do (2).
  gate_index = 0;
  for (const StandardCircuitLevel<bool>& level : input->levels_) {
    for (const StandardGate<bool>& gate : level.gates_) {
      Gate& to_modify = output->gates_[gate_index];
      to_modify.output_wires_.reserve(gate.output_wire_locations_.size());
      for (const WireLocation& loc : gate.output_wire_locations_) {
        // Handle Global output wires separately.
        if (loc.loc_.level_ < 0) {
          // Global Output wire.
          const int64_t& orig_output_index = loc.loc_.index_;
          if (orig_output_index < 0 ||
              orig_output_index > input->num_output_wires_) {
            return false;
          }
          const pair<uint64_t, uint64_t>& index_and_bit =
              output_wire_to_output_index_and_bit[orig_output_index];
          const uint64_t num_bits_in_output = GetValueNumBits(
              input->output_designations_[index_and_bit.first].second);
          if (index_and_bit.first >= output->num_outputs_ ||
              index_and_bit.second >= num_bits_in_output) {
            return false;
          }
          if (num_bits_in_output > 1) {
            to_modify.output_wires_.push_back(OutputWireLocation(
                InputWireLocation(
                    true,
                    (GateIndexDataType) (output->num_gates_ + index_and_bit.first)),
                (unsigned char) index_and_bit.second));
          } else {
            to_modify.output_wires_.push_back(OutputWireLocation(InputWireLocation(
                true,
                (GateIndexDataType) (output->num_gates_ + index_and_bit.first))));
          }
        } else {
          // Non-Global Output wire.
          GateIndexDataType* index = FindOrNull(loc.loc_, in_index_to_out_index);
          if (index == nullptr) {
            return false;
          }
          to_modify.output_wires_.push_back(
              OutputWireLocation(InputWireLocation(loc.is_left_, *index)));
        }
      }
      ++gate_index;
    }
  }

  // Handle Parties' inputs.
  for (int party = 0; party < num_parties; ++party) {
    if (!input->input_types_[party].empty() &&
        (int) input->inputs_as_generic_value_locations_.size() <= party) {
      LOG_ERROR("Inconsistent input info for input circuit");
      return false;
    }
    for (int j = 0; j < (int) input->input_types_[party].size(); ++j) {
      const vector<set<WireLocation>>& input_bits =
          input->inputs_as_generic_value_locations_[party][j];
      output->inputs_.push_back(
          GlobalInputInfo(input->input_types_[party][j].second));
      for (int i = 0; i < (int) input_bits.size(); ++i) {
        const set<WireLocation>& output_wires_for_bit_i = input_bits[i];
        set<OutputWireLocation>& inserter = output->inputs_.back().to_;
        for (const WireLocation& loc : output_wires_for_bit_i) {
          GateIndexDataType* index = FindOrNull(loc.loc_, in_index_to_out_index);
          if (index == nullptr) {
            return false;
          }
          if (input->input_types_[party][j].second != DataType::BOOL) {
            inserter.insert(OutputWireLocation(
                InputWireLocation(loc.is_left_, *index), (unsigned char) i));
          } else if (i > 0) {
            return false;
          } else {
            inserter.insert(
                OutputWireLocation(InputWireLocation(loc.is_left_, *index)));
          }
        }
      }
    }
  }

  // Handle constant '0' inputs.
  const GenericValue zero(false);
  for (const WireLocation& loc : input->constant_zero_input_) {
    GateIndexDataType* index = FindOrNull(loc.loc_, in_index_to_out_index);
    if (index == nullptr) {
      return false;
    }
    if (loc.is_left_) {
      output->left_constant_input_.insert(make_pair(*index, zero));
    } else {
      output->right_constant_input_.insert(make_pair(*index, zero));
    }
  }

  // Handle constant '1' inputs.
  const GenericValue one(true);
  for (const WireLocation& loc : input->constant_one_input_) {
    GateIndexDataType* index = FindOrNull(loc.loc_, in_index_to_out_index);
    if (index == nullptr) {
      return false;
    }
    if (loc.is_left_) {
      output->left_constant_input_.insert(make_pair(*index, one));
    } else {
      output->right_constant_input_.insert(make_pair(*index, one));
    }
  }

  return true;
}

// TODO(PHB): The following code needs to be updated (won't compile as-is),
// and even then, it hasn't yet been tested...
bool ConvertCircuit(
    const sri_circuit* /*input*/, StandardCircuit<slice>* /*output*/) {
  /*
  const size_t num_gates = sizeof(sri_gate) / sizeof(*(input->gate));
  if (num_gates != input->ngates && input->ngates != 0) {
    cout << "Input circuit is invalid: mismatching number of gates." << endl;
    return false;
  }
  // Sanity-check input was loaded properly (i.e. it has the right number of bytes).
  if (sizeof(input) ==
      (sizeof(sri_gate) * num_gates + sizeof(input->ngates) + sizeof(input->nlevels) +
       sizeof(input->levelsize) + sizeof(input->nalice) + sizeof(input->nbob) +
       sizeof(input->bobsinputs) + sizeof(input->bobsinputindices) +
       sizeof(input->nout) + sizeof(input->outputs) + sizeof(input->outputindices))) {
    cout << "Input circuit does not represent a valid circuit." << endl;
    return false;
  }

  // To assist in constructing 'output', populate storage containers
  // which will keep track of the level and index of each gate.
  map<const sri_gate*, GateLocation> gate_locations;
  map<const sri_gate*, pair<bool, size_t>> inputs;
  set<GateLocation> outputs;
  const sri_gate* g = input->gate;
  for (size_t i = 0; i < num_gates; ++i) {
    const sri_gate& current_gate = g[i];

    // Add gate as an output gate, if appropriate.
    bool is_output_gate = current_gate.special == SpecialGate::OUTPUT;
    if (is_output_gate) {
      output->num_output_wires_++;
    }

    // Handle input wires.
    if (current_gate.type == sri_GateType::INPUT_WIRE) {
      if (is_output_gate) {
        cout << "Circuits with input wires that are also output wires "
             << "are not allowed." << endl;
        return false;
      }
      pair<bool, size_t>& party_and_index =
          inputs.insert(make_pair(&g[i], pair<bool, size_t>())).first->second;
      party_and_index.second = current_gate.inputindex;
      if (current_gate.special == SpecialGate::ALICE_INPUT) {
        party_and_index.first = true;
        // Update size of input_one_as_slice_locations_, if necessary
        // (this field can't actually be populated yet, since we don't know
        // which gates it leads to).
        if (output->input_one_as_slice_locations_.size() <=
            current_gate.inputindex) {
          output->input_one_as_slice_locations_.resize(current_gate.inputindex);
        }
      } else if (current_gate.special == SpecialGate::BOB_INPUT) {
        party_and_index.first = false;
        // Update size of input_two_as_slice_locations_, if necessary
        // (this field can't actually be populated yet, since we don't know
        // which gates it leads to).
        if (output->input_two_as_slice_locations_.size() <=
            current_gate.inputindex) {
          output->input_two_as_slice_locations_.resize(current_gate.inputindex);
        }
      } else {
        cout << "ERROR: Unexpected SpecialGate type: "
             << static_cast<int>(current_gate.special) << endl;
        return false;
      }
      continue;
    }

    output->size_++;

    // Not an input wire. Parse gate type.
    BooleanOperation gate_type;
    if (current_gate.type == sri_GateType::AND_GATE) {
      gate_type = BooleanOperation::AND;
    } else if (current_gate.type == sri_GateType::XOR_GATE) {
      gate_type = BooleanOperation::XOR;
    } else if (current_gate.type == sri_GateType::OR_GATE) {
      gate_type = BooleanOperation::OR;
    } else if (current_gate.type == sri_GateType::NAND_GATE) {
      gate_type = BooleanOperation::NAND;
    } else if (current_gate.type == sri_GateType::BIGB_GATE) {
      gate_type = BooleanOperation::LT;
    } else if (current_gate.type == sri_GateType::NOR_GATE) {
      gate_type = BooleanOperation::NOR;
    } else if (current_gate.type == sri_GateType::EQ_GATE) {
      gate_type = BooleanOperation::EQ;
    } else if (current_gate.type == sri_GateType::NOT_GATE) {
      gate_type = BooleanOperation::NOT;
    } else if (current_gate.type == sri_GateType::GT_GATE) {
      gate_type = BooleanOperation::GT;
    } else if (current_gate.type == sri_GateType::GTE_GATE) {
      gate_type = BooleanOperation::GTE;
    } else if (current_gate.type == sri_GateType::LT_GATE) {
      gate_type = BooleanOperation::LT;
    } else if (current_gate.type == sri_GateType::LTE_GATE) {
      gate_type = BooleanOperation::LTE;
    } else {
      cout << "Unexpected gate type: "
           <<  static_cast<int>(current_gate.type) << endl;
      return false;
    }

    // Get the locations of the input wires/gates to this gate.
    int64_t left_wire_level, left_wire_index;
    int64_t right_wire_level, right_wire_index;
    sri_gate* left_input = current_gate.leftinput;
    sri_gate* right_input = current_gate.rightinput;
    if (left_input == nullptr || right_input == nullptr) {
      cout << "Non-input wire of gate " << i
           << " has null as one of its input wires" << endl;
      return false;
    }
    map<const sri_gate*, GateLocation>::const_iterator left_gate_loc =
        gate_locations.find(left_input);
    map<const sri_gate*, GateLocation>::const_iterator right_gate_loc =
        gate_locations.find(right_input);
    set<WireLocation>* inputs_to_left_wire = nullptr;
    set<WireLocation>* inputs_to_right_wire = nullptr;
    if (left_gate_loc == gate_locations.end() &&
        right_gate_loc == gate_locations.end()) {
      // Unable to find location of either input gate; so both input wires
      // to this gate must be actual (circuit) input wires.
      map<const sri_gate*, pair<bool, size_t>>::const_iterator left_input_itr =
          inputs.find(left_input);
      map<const sri_gate*, pair<bool, size_t>>::const_iterator right_input_itr =
          inputs.find(right_input);
      if (left_input_itr == inputs.end() || right_input_itr == inputs.end()) {
        cout << "Unable to find input wires for gate " << i << endl;
        return false;
      }
      left_wire_level = left_input_itr->second.first ? -1 : -2;
      left_wire_index = left_input_itr->second.second;
      // Prepare to set Global Input info (can't set it just yet, we
      // need to first find the level and gate index of the current gate).
      const size_t& left_input_index = left_input_itr->first->inputindex;
      const bool left_input_is_party_one = left_input_itr->second.first;
      if (left_input_is_party_one) {
        inputs_to_left_wire =
            &output->input_one_as_slice_locations_[left_input_index];
      } else {
        inputs_to_left_wire =
            &output->input_two_as_slice_locations_[left_input_index];
      }
      right_wire_level = right_input_itr->second.first ? -1 : -2;
      right_wire_index = right_input_itr->second.second;
      // Prepare to set Global Input info (can't set it just yet, we
      // need to first find the level and gate index of the current gate).
      const size_t& right_input_index = right_input_itr->first->inputindex;
      const bool right_input_is_party_one = right_input_itr->second.first;
      if (right_input_is_party_one) {
        inputs_to_right_wire =
            &output->input_one_as_slice_locations_[right_input_index];
      } else {
        inputs_to_right_wire =
            &output->input_two_as_slice_locations_[right_input_index];
      }
    } else if (left_gate_loc == gate_locations.end()) {
      // The left wire to this gate is a (circuit) input wire.
      map<const sri_gate*, pair<bool, size_t>>::const_iterator left_input_itr =
          inputs.find(left_input);
      if (left_input_itr == inputs.end()) {
        cout << "Unable to find left input wire for gate " << i << endl;
        return false;
      }
      right_wire_level = right_gate_loc->second.level_;
      right_wire_index = right_gate_loc->second.index_;
      left_wire_level = left_input_itr->second.first ? -1 : -2;
      left_wire_index = left_input_itr->second.second;
      // Prepare to set Global Input info (can't set it just yet, we
      // need to first find the level and gate index of the current gate).
      const size_t& left_input_index = left_input_itr->first->inputindex;
      const bool left_input_is_party_one = left_input_itr->second.first;
      if (left_input_is_party_one) {
        inputs_to_left_wire =
            &output->input_one_as_slice_locations_[left_input_index];
      } else {
        inputs_to_left_wire =
            &output->input_two_as_slice_locations_[left_input_index];
      }
    } else if (right_gate_loc == gate_locations.end()) {
      // The right wire to this gate is a (circuit) input wire.
      map<const sri_gate*, pair<bool, size_t>>::const_iterator right_input_itr =
          inputs.find(right_input);
      if (right_input_itr == inputs.end()) {
        cout << "Unable to find right input wire for gate " << i << endl;
        return false;
      }
      left_wire_level = left_gate_loc->second.level_;
      left_wire_index = left_gate_loc->second.index_;
      right_wire_level = right_input_itr->second.first ? -1 : -2;
      right_wire_index = right_input_itr->second.second;
      // Prepare to set Global Input info (can't set it just yet, we
      // need to first find the level and gate index of the current gate).
      const size_t& right_input_index = right_input_itr->first->inputindex;
      const bool right_input_is_party_one = right_input_itr->second.first;
      if (right_input_is_party_one) {
        inputs_to_right_wire =
            &output->input_one_as_slice_locations_[right_input_index];
      } else {
        inputs_to_right_wire =
            &output->input_two_as_slice_locations_[right_input_index];
      }
    } else {
      // This gate is an internal gate. Get the locations of its input wires.
      left_wire_level = left_gate_loc->second.level_;
      left_wire_index = left_gate_loc->second.index_;
      right_wire_level = right_gate_loc->second.level_;
      right_wire_index = right_gate_loc->second.index_;
    }

    // Set level to be one higher than the greater (level) of its input wires.
    const int64_t current_gate_level =
        1 + max(left_wire_level, right_wire_level);

    // Add a new level to the circuit, if this is the first gate on its level.
    if (output->levels_.size() <= current_gate_level) {
      if (output->levels_.size() < current_gate_level) {
        // This should never happen.
        cout << "Unable to jump level indices." << endl;
        return false;
      }
      output->levels_.push_back(StandardCircuitLevel<slice>());
    }

    // Add current gate as the last gate on the current level.
    const int64_t current_gate_index =
        output->levels_[current_gate_level].gates_.size();
    output->levels_[current_gate_level].gates_.push_back(StandardGate<slice>());
    StandardGate<slice>& new_gate =
        output->levels_[current_gate_level].gates_.back();
    new_gate.type_ = gate_type;
    new_gate.loc_ = GateLocation(current_gate_level, current_gate_index);

    // Add this gate's location to 'gate_locations'.
    gate_locations.insert(make_pair(
        &g[i], GateLocation(current_gate_level, current_gate_index)));

    // Add this gate to outputs, if appropriate.
    if (is_output_gate) {
      outputs.insert(GateLocation(current_gate_level, current_gate_index));
    }

    // Add this gate's location as a target gate of one of the global inputs,
    // if appropriate.
    if (inputs_to_left_wire != nullptr) {
      inputs_to_left_wire->insert(WireLocation(
          current_gate_level, current_gate_index, true));
    }
    if (inputs_to_right_wire != nullptr) {
      inputs_to_right_wire->insert(WireLocation(
          current_gate_level, current_gate_index, false));
    }
  }

  // Populate circuit fields.
  output->depth_ = output->levels_.size();
  output->size_ = num_gates - inputs.size();
  output->num_output_wires_ = outputs.size();
*/

  return true;
}

// TODO(PHB): The code below is just copy-pasted from the ConvertCircuit()
// function for Format 1. It needs to be updated Format 2, which is non-trivial.
// So far, I've updated StandardCircuit fields and functions; perhaps useful
// would be to do a tkdiff of the relevant functions (e.g. LoadCircuit() and
// WriteCircuit(), maybe others...), and update present functions in this file
// to reflect the changes.
/*
bool ConvertCircuit(const sri_circuit* input, StandardCircuit<bool>* output) {

  const size_t num_gates = sizeof(sri_gate) / sizeof(*(input->gate));
  if (num_gates != input->ngates && input->ngates != 0) {
    cout << "Input circuit is invalid: mismatching number of gates." << endl;
    return false;
  }
  // Sanity-check input was loaded properly (i.e. it has the right number of bytes).
  if (sizeof(input) ==
      (sizeof(sri_gate) * num_gates + sizeof(input->ngates) + sizeof(input->nlevels) +
       sizeof(input->levelsize) + sizeof(input->nalice) + sizeof(input->nbob) +
       sizeof(input->bobsinputs) + sizeof(input->bobsinputindices) +
       sizeof(input->nout) + sizeof(input->outputs) + sizeof(input->outputindices))) {
    cout << "Input circuit does not represent a valid circuit." << endl;
    return false;
  }

  // To assist in constructing 'output', populate storage containers
  // which will keep track of the level and index of each gate.
  map<const sri_gate*, GateLocation> gate_locations;
  map<const sri_gate*, pair<bool, size_t>> inputs;
  set<GateLocation> outputs;
  const sri_gate* g = input->gate;
  for (size_t i = 0; i < num_gates; ++i) {
    const sri_gate& current_gate = g[i];

    // Add gate as an output gate, if appropriate.
    bool is_output_gate = current_gate.special == SpecialGate::OUTPUT;
    if (is_output_gate) {
      output->num_output_wires_++;
    }

    // Handle input wires.
    if (current_gate.type == sri_GateType::INPUT_WIRE) {
      if (is_output_gate) {
        cout << "Circuits with input wires that are also output wires "
             << "are not allowed." << endl;
        return false;
      }
      pair<bool, size_t>& party_and_index =
          inputs.insert(make_pair(&g[i], pair<bool, size_t>())).first->second;
      party_and_index.second = current_gate.inputindex;
      if (current_gate.special == SpecialGate::ALICE_INPUT) {
        party_and_index.first = true;
        // Update size of input_one_as_slice_locations_, if necessary
        // (this field can't actually be populated yet, since we don't know
        // which gates it leads to).
        if (output->input_one_as_slice_locations_.size() <=
            current_gate.inputindex) {
          output->input_one_as_slice_locations_.resize(current_gate.inputindex);
        }
      } else if (current_gate.special == SpecialGate::BOB_INPUT) {
        party_and_index.first = false;
        // Update size of input_two_as_slice_locations_, if necessary
        // (this field can't actually be populated yet, since we don't know
        // which gates it leads to).
        if (output->input_two_as_slice_locations_.size() <=
            current_gate.inputindex) {
          output->input_two_as_slice_locations_.resize(current_gate.inputindex);
        }
      } else {
        cout << "ERROR: Unexpected SpecialGate type: "
             << static_cast<int>(current_gate.special) << endl;
        return false;
      }
      continue;
    }

    output->size_++;

    // Not an input wire. Parse gate type.
    BooleanOperation gate_type;
    if (current_gate.type == sri_GateType::AND_GATE) {
      gate_type = BooleanOperation::AND;
    } else if (current_gate.type == sri_GateType::XOR_GATE) {
      gate_type = BooleanOperation::XOR;
    } else if (current_gate.type == sri_GateType::OR_GATE) {
      gate_type = BooleanOperation::OR;
    } else if (current_gate.type == sri_GateType::NAND_GATE) {
      gate_type = BooleanOperation::NAND;
    } else if (current_gate.type == sri_GateType::BIGB_GATE) {
      gate_type = BooleanOperation::LT;
    } else if (current_gate.type == sri_GateType::NOR_GATE) {
      gate_type = BooleanOperation::NOR;
    } else if (current_gate.type == sri_GateType::EQ_GATE) {
      gate_type = BooleanOperation::EQ;
    } else if (current_gate.type == sri_GateType::NOT_GATE) {
      gate_type = BooleanOperation::NOT;
    } else if (current_gate.type == sri_GateType::GT_GATE) {
      gate_type = BooleanOperation::GT;
    } else if (current_gate.type == sri_GateType::GTE_GATE) {
      gate_type = BooleanOperation::GTE;
    } else if (current_gate.type == sri_GateType::LT_GATE) {
      gate_type = BooleanOperation::LT;
    } else if (current_gate.type == sri_GateType::LTE_GATE) {
      gate_type = BooleanOperation::LTE;
    } else {
      cout << "Unexpected gate type: "
           <<  static_cast<int>(current_gate.type) << endl;
      return false;
    }

    // Get the locations of the input wires/gates to this gate.
    int64_t left_wire_level, left_wire_index;
    int64_t right_wire_level, right_wire_index;
    sri_gate* left_input = current_gate.leftinput;
    sri_gate* right_input = current_gate.rightinput;
    if (left_input == nullptr || right_input == nullptr) {
      cout << "Non-input wire of gate " << i
           << " has null as one of its input wires" << endl;
      return false;
    }
    map<const sri_gate*, GateLocation>::const_iterator left_gate_loc =
        gate_locations.find(left_input);
    map<const sri_gate*, GateLocation>::const_iterator right_gate_loc =
        gate_locations.find(right_input);
    set<WireLocation>* inputs_to_left_wire = nullptr;
    set<WireLocation>* inputs_to_right_wire = nullptr;
    if (left_gate_loc == gate_locations.end() &&
        right_gate_loc == gate_locations.end()) {
      // Unable to find location of either input gate; so both input wires
      // to this gate must be actual (circuit) input wires.
      map<const sri_gate*, pair<bool, size_t>>::const_iterator left_input_itr =
          inputs.find(left_input);
      map<const sri_gate*, pair<bool, size_t>>::const_iterator right_input_itr =
          inputs.find(right_input);
      if (left_input_itr == inputs.end() || right_input_itr == inputs.end()) {
        cout << "Unable to find input wires for gate " << i << endl;
        return false;
      }
      left_wire_level = left_input_itr->second.first ? -1 : -2;
      left_wire_index = left_input_itr->second.second;
      // Prepare to set Global Input info (can't set it just yet, we
      // need to first find the level and gate index of the current gate).
      const size_t& left_input_index = left_input_itr->first->inputindex;
      const bool left_input_is_party_one = left_input_itr->second.first;
      if (left_input_is_party_one) {
        inputs_to_left_wire =
            &output->input_one_as_slice_locations_[left_input_index];
      } else {
        inputs_to_left_wire =
            &output->input_two_as_slice_locations_[left_input_index];
      }
      right_wire_level = right_input_itr->second.first ? -1 : -2;
      right_wire_index = right_input_itr->second.second;
      // Prepare to set Global Input info (can't set it just yet, we
      // need to first find the level and gate index of the current gate).
      const size_t& right_input_index = right_input_itr->first->inputindex;
      const bool right_input_is_party_one = right_input_itr->second.first;
      if (right_input_is_party_one) {
        inputs_to_right_wire =
            &output->input_one_as_slice_locations_[right_input_index];
      } else {
        inputs_to_right_wire =
            &output->input_two_as_slice_locations_[right_input_index];
      }
    } else if (left_gate_loc == gate_locations.end()) {
      // The left wire to this gate is a (circuit) input wire.
      map<const sri_gate*, pair<bool, size_t>>::const_iterator left_input_itr =
          inputs.find(left_input);
      if (left_input_itr == inputs.end()) {
        cout << "Unable to find left input wire for gate " << i << endl;
        return false;
      }
      right_wire_level = right_gate_loc->second.level_;
      right_wire_index = right_gate_loc->second.index_;
      left_wire_level = left_input_itr->second.first ? -1 : -2;
      left_wire_index = left_input_itr->second.second;
      // Prepare to set Global Input info (can't set it just yet, we
      // need to first find the level and gate index of the current gate).
      const size_t& left_input_index = left_input_itr->first->inputindex;
      const bool left_input_is_party_one = left_input_itr->second.first;
      if (left_input_is_party_one) {
        inputs_to_left_wire =
            &output->input_one_as_slice_locations_[left_input_index];
      } else {
        inputs_to_left_wire =
            &output->input_two_as_slice_locations_[left_input_index];
      }
    } else if (right_gate_loc == gate_locations.end()) {
      // The right wire to this gate is a (circuit) input wire.
      map<const sri_gate*, pair<bool, size_t>>::const_iterator right_input_itr =
          inputs.find(right_input);
      if (right_input_itr == inputs.end()) {
        cout << "Unable to find right input wire for gate " << i << endl;
        return false;
      }
      left_wire_level = left_gate_loc->second.level_;
      left_wire_index = left_gate_loc->second.index_;
      right_wire_level = right_input_itr->second.first ? -1 : -2;
      right_wire_index = right_input_itr->second.second;
      // Prepare to set Global Input info (can't set it just yet, we
      // need to first find the level and gate index of the current gate).
      const size_t& right_input_index = right_input_itr->first->inputindex;
      const bool right_input_is_party_one = right_input_itr->second.first;
      if (right_input_is_party_one) {
        inputs_to_right_wire =
            &output->input_one_as_slice_locations_[right_input_index];
      } else {
        inputs_to_right_wire =
            &output->input_two_as_slice_locations_[right_input_index];
      }
    } else {
      // This gate is an internal gate. Get the locations of its input wires.
      left_wire_level = left_gate_loc->second.level_;
      left_wire_index = left_gate_loc->second.index_;
      right_wire_level = right_gate_loc->second.level_;
      right_wire_index = right_gate_loc->second.index_;
    }

    // Set level to be one higher than the greater (level) of its input wires.
    const int64_t current_gate_level =
        1 + max(left_wire_level, right_wire_level);

    // Add a new level to the circuit, if this is the first gate on its level.
    if (output->levels_.size() <= current_gate_level) {
      if (output->levels_.size() < current_gate_level) {
        // This should never happen.
        cout << "Unable to jump level indices." << endl;
        return false;
      }
      output->levels_.push_back(StandardCircuitLevel<bool>());
    }

    // Add current gate as the last gate on the current level.
    const int64_t current_gate_index =
        output->levels_[current_gate_level].gates_.size();
    output->levels_[current_gate_level].gates_.push_back(StandardGate<bool>());
    StandardGate<bool>& new_gate =
        output->levels_[current_gate_level].gates_.back();
    new_gate.type_ = gate_type;
    new_gate.loc_ = GateLocation(current_gate_level, current_gate_index);

    // Add this gate's location to 'gate_locations'.
    gate_locations.insert(make_pair(
        &g[i], GateLocation(current_gate_level, current_gate_index)));

    // Add this gate to outputs, if appropriate.
    if (is_output_gate) {
      outputs.insert(GateLocation(current_gate_level, current_gate_index));
    }

    // Add this gate's location as a target gate of one of the global inputs,
    // if appropriate.
    if (inputs_to_left_wire != nullptr) {
      inputs_to_left_wire->insert(WireLocation(
          current_gate_level, current_gate_index, true));
    }
    if (inputs_to_right_wire != nullptr) {
      inputs_to_right_wire->insert(WireLocation(
          current_gate_level, current_gate_index, false));
    }
  }

  // Populate circuit fields.
  output->depth_ = output->levels_.size();
  output->size_ = num_gates - inputs.size();
  output->num_output_wires_ = outputs.size();
  return true;
}
*/

// TODO(PHB): Implement all empty ConvertCircuit() APIs below.
bool ConvertCircuit(const StandardCircuit<slice>*, StandardCircuit<slice>*) {
  return false;
}
bool ConvertCircuit(const StandardCircuit<slice>*, StandardCircuit<bool>*) {
  return false;
}
bool ConvertCircuit(const StandardCircuit<slice>*, CircuitByGate*) {
  return false;
}
bool ConvertCircuit(const StandardCircuit<slice>*, sri_circuit*) {
  return false;
}
bool ConvertCircuit(const StandardCircuit<slice>*, spar_gate*) { return false; }
bool ConvertCircuit(const StandardCircuit<slice>*, durasift_circuit*) {
  return false;
}
bool ConvertCircuit(const StandardCircuit<bool>*, StandardCircuit<slice>*) {
  return false;
}
bool ConvertCircuit(const StandardCircuit<bool>*, StandardCircuit<bool>*) {
  return false;
}
bool ConvertCircuit(const StandardCircuit<bool>*, sri_circuit*) { return false; }
bool ConvertCircuit(const StandardCircuit<bool>*, spar_gate*) { return false; }
bool ConvertCircuit(const StandardCircuit<bool>*, durasift_circuit*) {
  return false;
}
bool ConvertCircuit(const CircuitByGate*, StandardCircuit<slice>*) {
  return false;
}
bool ConvertCircuit(const CircuitByGate*, StandardCircuit<bool>*) {
  return false;
}
bool ConvertCircuit(const CircuitByGate*, CircuitByGate*) { return false; }
bool ConvertCircuit(const CircuitByGate*, sri_circuit*) { return false; }
bool ConvertCircuit(const CircuitByGate*, spar_gate*) { return false; }
bool ConvertCircuit(const CircuitByGate*, durasift_circuit*) { return false; }
bool ConvertCircuit(const sri_circuit*, StandardCircuit<bool>*) { return false; }
bool ConvertCircuit(const sri_circuit*, CircuitByGate*) { return false; }
bool ConvertCircuit(const sri_circuit*, sri_circuit*) { return false; }
bool ConvertCircuit(const sri_circuit*, spar_gate*) { return false; }
bool ConvertCircuit(const sri_circuit*, durasift_circuit*) { return false; }
bool ConvertCircuit(const spar_gate*, StandardCircuit<slice>*) { return false; }
bool ConvertCircuit(const spar_gate*, StandardCircuit<bool>*) { return false; }
bool ConvertCircuit(const spar_gate*, CircuitByGate*) { return false; }
bool ConvertCircuit(const spar_gate*, sri_circuit*) { return false; }
bool ConvertCircuit(const spar_gate*, spar_gate*) { return false; }
bool ConvertCircuit(const spar_gate*, durasift_circuit*) { return false; }
bool ConvertCircuit(const durasift_circuit*, StandardCircuit<slice>*) {
  return false;
}
bool ConvertCircuit(const durasift_circuit*, StandardCircuit<bool>*) {
  return false;
}
bool ConvertCircuit(const durasift_circuit*, CircuitByGate*) { return false; }
bool ConvertCircuit(const durasift_circuit*, sri_circuit*) { return false; }
bool ConvertCircuit(const durasift_circuit*, spar_gate*) { return false; }
bool ConvertCircuit(const durasift_circuit*, durasift_circuit*) { return false; }

bool WriteCircuit(const string& filename, const StandardCircuit<slice>* input) {
  return input->WriteCircuitFile(filename);
}

bool WriteCircuit(const string& filename, const StandardCircuit<bool>* input) {
  return input->WriteCircuitFile(filename);
}

bool WriteCircuit(const string& filename, const CircuitByGate* input) {
  return input->WriteCircuitFile(filename);
}

// TODO(PHB): Implement the following three WriteCircuit() APIs.
bool WriteCircuit(const string&, const sri_circuit*) { return false; }
bool WriteCircuit(const string&, const spar_gate*) { return false; }
bool WriteCircuit(const string&, const durasift_circuit*) { return false; }

void SetDependsOnAll(const bool depends_on_all) {
  kForceDependsOnAll = depends_on_all;
}

}  // namespace multiparty_computation
}  // namespace crypto
