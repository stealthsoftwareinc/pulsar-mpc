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
// TODO(paul): What is meant to ``build a circuit''? In particular, will the resulting
// circuit ultimately just be written to file, or will the StandardCircuit object
// be used directly (i.e. while still in memory/within the building executable)?
// For most (all?) use-cases, it is just the former. The distinction is not
// super-important, but circuit-building code (below) can be made simpler/faster
// if we *only* support the former use-case, as in this case we don't need to
// track certain fields. Namely, fields that are not printed (or are optionally
// printed) in the circuit file can be ignored, e.g.:
//   - depth_
//   - size_
//   - num_non_local_gates_
//   - num_outputs_
//   - num_output_wires_
// (Note that these fields will ultimately be populated by LoadCircuit(), when
// the circuit file is read to populate the StandardCircuit object that is
// used by the executable doing circuit evaluation).
//
// TODO(paul): A bunch of function (APIs) and variables have size [u]int64_t
// instead of e.g. [u]int, and we're not ever gonna need those extra bits.
// For example, 'num_[one|two]_input_bits'.
// This would be a (relatively) easy speed-up of this code, to replace
// [u]int64_t with [u]int.

#include "circuit_builder_utils.h"

#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"  // For OutputRecipient.
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"
#include "GenericUtils/char_casting_utils.h"  // For ValueToByteString.
#include "MapUtils/map_utils.h"  // For FindOrInsert().
#include "MathUtils/constants.h"  // For slice.
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "MathUtils/formula_utils.h"  // For Formula.
#include "global_utils.h"

#include <fstream>  // For ofstream (used for debugging)
#include <math.h>  // For pow.
#include <memory>  // For unique_ptr.
#include <set>
#include <string>
#include <vector>

using namespace map_utils;
using namespace math_utils;
using namespace string_utils;
using namespace std;

namespace crypto {
namespace multiparty_computation {

const DataType kDefaultDataType = DataType::INT64;

static int kNumReductionsInCurrentReduceCircuit;
// NOTE: To print ReduceCircuit debug info, change the value of
// kPrintReduceCircuitDebugNumChangesThreshold below to '-1'.
static int kPrintReduceCircuitDebugNumChangesThreshold = 1000000000;
static int kCurrentReductionFunctionIndex = 0;
// For Argmin/Argmax circuits, we return a characteristic vector with a '1'
// in the min/max position. In case of ties, we deterministically take
// the first (resp. last) coordinate that represents the min/max.
// The following determines if we should take the first or last
// (it can be set via SetArgminBreakTiesPos()).
static bool kArgminBreakTiesTakeFirst = true;

// Turns on/off all ReduceCircuit() functionality.
static bool kAllowReduceCircuit = true;

// Only go up to 20!, because 21! > 2^64.
const uint64_t kFirstTwentyFactorials[] = {
    1,
    1,
    2,
    6,
    24,
    120,
    720,
    5040,
    40320,
    362880,
    3628800,
    39916800,  // 11!
    479001600,  // 12!
    6227020800,  // 13!
    87178291200,  // 14!
    1307674368000,  // 15!
    20922789888000,  // 16!
    355687428096000,  // 17!
    6402373705728000,  // 18!
    121645100408832000,  // 19!
    2432902008176640000,  // 20!
};

// The following variable controls ``lookahead'' addition, which is a
// tradeoff between number of gates vs. circuit depth for implementing
// addition: By partitioning the bits of the inputs into blocks, you
// can compute each block in parallel so that they don't depend on
// each other (via the 'carry-bit'), by simply initiating each sum
// by assuming a carry-bit of '0' and a carry-bit of '1' (as the last
// carry-bit output from the previous block). Then, once all of the
// 2*(num blocks) have been computed, we use ANDs to select the appropriate
// toggle for the carry-bit, based on its actual value.
// If l = number of 'blocks' and n = number of bits of each input, then
// circuit depth is: l + n / l (the first term is for l ANDs, which need
// to be computed in succession/sequentially, and the n/l is for computing
// the ADDition circuit for each of the l blocks (which is addition of n/l-bit
// integers); and the extra number of gates is: (l + k_l * C_n), where
// C_n is the original ADD circuit size (for two n-bit integers, based on
// doing standard/non-lookahead addition), and k_l is a factor close to 2
// (specifically, k_l = (2*l-1) / l = 2 - 1/l). Thus, in terms of the
// tradeoff of circuit depth vs. number of gates:
//   - Set l = 1 (no lookahead) for minimal number of gates (and maximal depth)
//   - Set l = sqrt{n} for minimial depth (and maximal number of gates)
// The variable below controls the number of blocks 'l'; default is to
// *not* do lookahead addition (so l = 1); but the value can be toggled
// by calling SetAdditionNumberLookaheadBlocks().
// NOTES:
//   1) Caller need not worry about relationship of n vs. l:
//      if l > n, code will automatically set l = sqrt{n}, which
//      is the far end of the scale in terms of minimizing circuit depth.
//   2) Currently, all lookahead blocks have the same size (n/l).
//      A further optimization is possible by having 'earlier' blocks
//      (those corresponding to the low-level bits) be smaller than
//      the blocks for the high-level bits (so that the ANDs for these
//      can be done in parallel with the actual ADDition of the
//      high-level blocks); this is not currently supported; but see
//      https://eprint.iacr.org/2018/762.pdf section 4.5 (and in
//      particular, Table 2 in that section as of 10/1/19) for
//      optimal block sizes.
static int kAdditionLookaheadBlocks = 1;

namespace {

// DEPRECATED: Not used.
/*
void DebugPrintDependencies(
    const string& filename, const StandardCircuit<bool>& circuit) {
  ofstream outfile;
  outfile.open(filename);

  for (size_t level = 0; level < circuit.levels_.size(); ++level) {
    outfile << endl << "Level " << level << ":" << endl;
    const StandardCircuitLevel<bool>& current_level = circuit.levels_[level];
    for (size_t gate = 0; gate < current_level.gates_.size(); ++gate) {
      const StandardGate<bool>& current_gate = current_level.gates_[gate];
      outfile << current_gate.loc_.Print() << ": IsLocalGate: "
              << current_gate.IsLocalGate() << ", depends on Parties: {"
              << JoinValues<int>(current_gate.depends_on_, ", ") << "}, op:"
              << GetOpString(current_gate.type_) << endl;
    }
  }
  outfile.close();
}

void DebugPrintInputs (
    const string& filename,
    const vector<vector<GateLocation>*>& gate_to_left_input,
    const vector<vector<GateLocation>*>& gate_to_right_input) {
  if (gate_to_left_input.size() != gate_to_right_input.size()) LOG_FATAL("Fatal Error.");
  ofstream outfile;
  outfile.open(filename);

  for (size_t i = 0; i < gate_to_left_input.size(); ++i) {
    outfile << endl << "Level " << i << " Inputs:" << endl;
    const vector<GateLocation>& left_inputs = *(gate_to_left_input[i]);
    const vector<GateLocation>& right_inputs = *(gate_to_right_input[i]);
    const size_t max_bits = max(left_inputs.size(), right_inputs.size());
    for (size_t j = 0; j < max_bits; ++j) {
      outfile << "(" << i << ", " << j << "): ";
      if (j < left_inputs.size()) {
        outfile << "Left: " << left_inputs[j].Print() << " ";
      } else {
        outfile << "Left: " << "None" << " ";
      }
      if (j < right_inputs.size()) {
        outfile << "Right: " << right_inputs[j].Print() << " ";
      } else {
        outfile << "Right: " << "None" << " ";
      }
      outfile << endl;
    }
  }
  outfile.close();
}
*/

// Call after each call to MoveGate(), sets the (level, index) of the
// next gate to process.
void GetNextStartPosition(
    const bool level_had_one_gate,
    const int64_t& prev_processed_gate_level,
    const int64_t& prev_processed_gate_index,
    const StandardCircuit<bool>& circuit,
    int64_t* level,
    int64_t* index) {
  // First check the corner case that the previous gate (re)moved was
  // the very last gate in the circuit, and that this was the only gate
  // on its level.
  if (prev_processed_gate_level == (int64_t) circuit.levels_.size()) {
    if (!level_had_one_gate) {
      LOG_FATAL(
          "prev_processed gate: (" + Itoa(prev_processed_gate_level) + ", " +
          Itoa(prev_processed_gate_index) +
          "), circuit depth: " + Itoa(circuit.levels_.size()));
    }
    // Just processed the last gate. Point level to prev_processed_gate_level
    // and index to zero, which corresponds to the first gate on a non-existent
    // level, so that all calling functions know they're done.
    *level = prev_processed_gate_level;
    *index = 0;
    return;
  }

  if (prev_processed_gate_level >= (int64_t) circuit.levels_.size()) {
    LOG_FATAL(
        "prev_processed gate: (" + Itoa(prev_processed_gate_level) + ", " +
        Itoa(prev_processed_gate_index) +
        "), circuit depth: " + Itoa(circuit.levels_.size()));
  }

  if (prev_processed_gate_index < 0 ||
      (size_t) prev_processed_gate_index >
          circuit.levels_[prev_processed_gate_level].gates_.size()) {
    LOG_FATAL(
        "prev_processed gate: (" + Itoa(prev_processed_gate_level) + ", " +
        Itoa(prev_processed_gate_index) +
        "), circuit depth: " + Itoa(circuit.levels_.size()) +
        ", num gates on previously processed level: " +
        Itoa(circuit.levels_[prev_processed_gate_level].gates_.size()));
  }
  if (level_had_one_gate) {
    // The circuit killed the level of the gate being (re)moved. So the
    // next level to check is still the old one; just need to reset the
    // start_index to the first gate on this level.
    *level = prev_processed_gate_level;
    *index = 0;
  } else if (
      prev_processed_gate_index ==
      (int64_t) circuit.levels_[prev_processed_gate_level].gates_.size()) {
    // The circuit (re)moved the last gate on some level.
    // Reset next start position to be the first gate on the next level.
    *level = prev_processed_gate_level + 1;
    *index = 0;
  }
  // Otherwise, no change, since the gate index of the previously processed
  // gate will remain the desired index of the next gate to process
  // (since everything shifted when the gate was (re)moved).
  *level = prev_processed_gate_level;
  *index = prev_processed_gate_index;
}

// Returns the number of items in 'to_search' that are smaller than 'input'.
// If 'forbid_match' is true, makes sure 'input' is not in 'to_search'.
int64_t FindNumSmallerIndices(
    const bool forbid_match,
    const int64_t& input,
    const set<int64_t>& to_search) {
  int64_t to_return = 0;
  for (const int64_t& current : to_search) {
    if (current == input) {
      if (forbid_match) LOG_FATAL("Fatal Error.");
    }
    if (current >= input) break;
    ++to_return;
  }

  return to_return;
}

// Iterates through Formula, replacing all variables that appear as a key of
// 'orig_to_new_var_names' with the corresponding value (note there there is
// no demand that all variables encountered in 'output' appear in
// 'orig_to_new_var_names'; if not present, no change is made to them).
void UpdateFormulaVarNames(
    const map<string, string> orig_to_new_var_names, Formula* output) {
  if (output->subterm_one_ != nullptr) {
    UpdateFormulaVarNames(orig_to_new_var_names, output->subterm_one_.get());
  }
  if (output->subterm_two_ != nullptr) {
    UpdateFormulaVarNames(orig_to_new_var_names, output->subterm_two_.get());
  }
  if (output->op_.type_ == OperationType::BOOLEAN &&
      output->op_.gate_op_ == BooleanOperation::IDENTITY) {
    const string* replace_with =
        FindOrNull(GetGenericValueString(output->value_), orig_to_new_var_names);
    if (replace_with != nullptr) {
      output->value_ = GenericValue(*replace_with);
    }
  }
}
// Same as above, but the thing replacing the string may itself be a Formula
// (rather than simply a variable name).
void UpdateFormulaVarNames(
    const map<string, const Formula*> orig_to_new_var_names, Formula* output) {
  if (output->subterm_one_ != nullptr) {
    UpdateFormulaVarNames(orig_to_new_var_names, output->subterm_one_.get());
  }
  if (output->subterm_two_ != nullptr) {
    UpdateFormulaVarNames(orig_to_new_var_names, output->subterm_two_.get());
  }
  if (output->op_.type_ == OperationType::BOOLEAN &&
      output->op_.gate_op_ == BooleanOperation::IDENTITY) {
    const auto* replace_with =
        FindOrNull(GetGenericValueString(output->value_), orig_to_new_var_names);
    if (replace_with != nullptr) {
      output->clone(**replace_with);
    }
  }
}

// Maps an output wire index (for Format 2 circuit) to the output index
// (the latter w.r.t. e.g. StandardCircuit.output_designations_).
uint64_t GetOutputIndexFromWireIndex(
    const int64_t& output_wire_index,
    const vector<pair<OutputRecipient, DataType>>& output_designations) {
  if (output_wire_index < 0) LOG_FATAL("Fatal Error.");
  uint64_t to_return = 0;
  int64_t bits_accounted_for = 0;
  for (const pair<OutputRecipient, DataType>& output : output_designations) {
    bits_accounted_for += GetValueNumBits(output.second);
    if (bits_accounted_for > output_wire_index) return to_return;
    ++to_return;
  }
  LOG_FATAL("output_wire_index too big: " + Itoa(output_wire_index));
  return 0;
}

// Takes a given circuit, whose output wires correspond to a single number,
// and adds output wires that will be the leading bits of the new output
// value, so that the actual output value is unchanged (but is represented
// with more bits). In particular, this means having the extra output wires
// all be constant zero (if output DataType is unsigned), or they should
// take the value of the leading bit of the original output wires (i.e.
// the output wire with the highest index).
bool CastCircuitOutputAsMoreBits(
    const bool is_signed_type,
    const int target_num_bits,
    StandardCircuit<bool>* circuit) {
  if (circuit->output_designations_.size() != 1) {
    LOG_ERROR(
        "Invalid number of outputs: " +
        Itoa(circuit->output_designations_.size()));
    return false;
  }

  // Get the number of bits in the current output type.
  const int64_t orig_num_output_bits = circuit->num_output_wires_;
  // Sanity check number of outputs matches.
  if (circuit->num_outputs_ != 1 &&
      circuit->num_outputs_ != orig_num_output_bits) {
    LOG_ERROR(
        "Mismatching number of output wires: " +
        Itoa(circuit->num_output_wires_) + ", " + Itoa(circuit->num_outputs_) +
        ", " + Itoa(orig_num_output_bits));
    return false;
  }
  // Early abort based on target_num_bits and orig_num_output_bits.
  if (target_num_bits == orig_num_output_bits) {
    return true;
  } else if (target_num_bits < orig_num_output_bits) {
    LOG_ERROR("Cannot cast as fewer bits.");
    return false;
  }

  // Get target DataType.
  DataType output_type;
  if (!GetIntegerDataType(is_signed_type, (int) target_num_bits, &output_type)) {
    return false;
  }

  // Update fields.
  circuit->num_outputs_ = 1;
  circuit->num_output_wires_ = target_num_bits;
  circuit->output_designations_[0].second = output_type;

  // Now add extra output wires.
  const int num_bits_needed = (int) (target_num_bits - orig_num_output_bits);
  if (is_signed_type) {
    // Signed type. Perpetuate original leading bit.
    // First, find the gate whose output wire is the original leading bit.
    for (StandardCircuitLevel<bool>& level : circuit->levels_) {
      for (StandardGate<bool>& gate : level.gates_) {
        bool current_gate_is_leading_output_bit = false;
        for (const WireLocation& wire : gate.output_wire_locations_) {
          if (wire.loc_.level_ == -1 &&
              wire.loc_.index_ == orig_num_output_bits - 1) {
            current_gate_is_leading_output_bit = true;
            break;
          }
        }
        if (current_gate_is_leading_output_bit) {
          for (int i = 0; i < num_bits_needed; ++i) {
            gate.output_wire_locations_.insert(
                WireLocation(-1, orig_num_output_bits + i));
          }
          return true;
        }
      }
    }
  } else {
    // Unsigned type. All leading bits should be zero. Check to see if
    // there are already any constant zero gates, and if so, add
    // (global) output wires to it. Otherwise, add a constant zero gate
    // to the end of Level 1, and make it output all the zero outputs.
    StandardGate<bool>* zero_gate = nullptr;
    for (const WireLocation& zero_wire : circuit->constant_zero_input_) {
      if (circuit->levels_[zero_wire.loc_.level_]
              .gates_[zero_wire.loc_.index_]
              .type_ == BooleanOperation::IDENTITY) {
        zero_gate = &(circuit->levels_[zero_wire.loc_.level_]
                          .gates_[zero_wire.loc_.index_]);
        break;
      }
    }
    if (zero_gate == nullptr) {
      if (circuit->levels_.empty()) {
        LOG_ERROR("Empty Circuit");
        return false;
      }
      circuit->constant_zero_input_.insert(
          WireLocation(0, circuit->levels_[0].gates_.size(), true));
      circuit->levels_[0].gates_.push_back(StandardGate<bool>());
      zero_gate = &(circuit->levels_[0].gates_.back());
      zero_gate->loc_ = GateLocation(0, circuit->levels_[0].num_gates_);
      zero_gate->type_ = BooleanOperation::IDENTITY;
      zero_gate->depends_on_.clear();
      ++circuit->size_;
      ++circuit->levels_[0].num_gates_;
    }

    for (int i = 0; i < num_bits_needed; ++i) {
      zero_gate->output_wire_locations_.insert(
          WireLocation(-1, orig_num_output_bits + i));
    }
  }

  return true;
}

// Called at the end of the ConstructEqCircuit() routine, to clean-up
// the function_description, which may have gotten overly complicated.
void WriteEqFunctionDescription(
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    StandardCircuit<bool>* output) {
  if (output->function_description_.size() != 1) LOG_FATAL("Fatal Error.");
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::COMPARISON;
  formula.op_.comparison_op_ = ComparisonOperation::COMP_EQ;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);
}

// Adds the indicated WireLocation to the appropriate set of
// output wires ('gate' may point to a global input as opposed to
// an actual gate location).
void ChangeOutputWireLocation(
    const WireLocation& orig_loc,
    const WireLocation& new_loc,
    const GateLocation& gate,
    StandardCircuit<bool>* output) {
  if (gate.level_ == -1) LOG_FATAL("Bad input.");
  else if (gate.level_ == -2) {
    // The wire to be removed is a global constant '0' input.
    if (output->constant_zero_input_.erase(orig_loc) != 1) {
      LOG_FATAL("Failed to find output wire");
    }
    output->constant_zero_input_.insert(new_loc);
  } else if (gate.level_ == -3) {
    // The wire to be removed is a global constant '1' input.
    if (output->constant_one_input_.erase(orig_loc) != 1) {
      LOG_FATAL("Failed to find output wire");
    }
    output->constant_one_input_.insert(new_loc);
  } else if (gate.level_ < -3) {
    // The wire to be moved is a global input from Party N, first find N.
    const int64_t party = -4 - gate.level_;

    // Grab the output locations for this gate.
    if ((int64_t) output->inputs_as_generic_value_locations_[party].size() <=
        gate.index_) {
      LOG_FATAL("Fatal Error.");
    }
    vector<set<WireLocation>>& inputs =
        output->inputs_as_generic_value_locations_[party][gate.index_];
    bool found_bit = false;
    for (set<WireLocation>& input_bit_to_wires : inputs) {
      found_bit = input_bit_to_wires.erase(orig_loc) == 1;
      if (found_bit) {
        input_bit_to_wires.insert(new_loc);
        break;
      }
    }
    if (!found_bit) LOG_FATAL("Failed to find output wire");
  } else {
    // The wire to be removed is the output of another gate.
    if (1 !=
        output->levels_[gate.level_]
            .gates_[gate.index_]
            .output_wire_locations_.erase(orig_loc)) {
      LOG_FATAL("Failed to find output wire.");
    }
    output->levels_[gate.level_]
        .gates_[gate.index_]
        .output_wire_locations_.insert(new_loc);
  }
}

// Removes the indicated WireLocation from the appropriate set of
// output wires ('gate' may point to a global input as opposed to
// an actual gate location).
void RemoveOutputWire(
    const WireLocation& loc,
    const GateLocation& gate,
    StandardCircuit<bool>* output) {
  if (gate.level_ == -1) LOG_FATAL("Bad input.");
  else if (gate.level_ == -2) {
    // The wire to be removed is a global constant '0' input.
    if (output->constant_zero_input_.erase(loc) != 1) {
      LOG_FATAL("Failed to find output wire");
    }
  } else if (gate.level_ == -3) {
    // The wire to be removed is a global constant '1' input.
    if (output->constant_one_input_.erase(loc) != 1) {
      LOG_FATAL("Failed to find output wire");
    }
  } else if (gate.level_ < -3) {
    // The wire to be removed is a global input from Party N, first find N.
    const int64_t party = -4 - gate.level_;

    // The wire to be removed is a global input from Party 1.
    if ((int64_t) output->inputs_as_generic_value_locations_[party].size() <=
        gate.index_) {
      LOG_FATAL("Fatal Error.");
    }
    vector<set<WireLocation>>& inputs =
        output->inputs_as_generic_value_locations_[party][gate.index_];
    bool found_bit = false;
    for (set<WireLocation>& input_bit_to_wires : inputs) {
      found_bit = input_bit_to_wires.erase(loc) == 1;
      if (found_bit) break;
    }
    if (!found_bit) LOG_FATAL("Failed to find output wire");
  } else {
    // The wire to be removed is the output of another gate.
    if (1 !=
        output->levels_[gate.level_]
            .gates_[gate.index_]
            .output_wire_locations_.erase(loc)) {
      LOG_FATAL("Failed to find output wire.");
    }
  }
}

// Returns true if the input gate operation is symmetric with respect to
// its input wires.
bool IsSymmetricGate(const BooleanOperation gate_op) {
  return (
      gate_op == BooleanOperation::IDENTITY ||
      gate_op == BooleanOperation::NOT || gate_op == BooleanOperation::OR ||
      gate_op == BooleanOperation::XOR || gate_op == BooleanOperation::EQ ||
      gate_op == BooleanOperation::AND || gate_op == BooleanOperation::NAND ||
      gate_op == BooleanOperation::NOR);
}

// Returns the resulting Boolean Operation that is obtained if the
// input wires were to be flip-flopped.
BooleanOperation WiresFlippedOp(const BooleanOperation& gate_op) {
  return (
      IsSymmetricGate(gate_op) ?
          gate_op :
          (gate_op == BooleanOperation::GT ?
               BooleanOperation::LT :
               (gate_op == BooleanOperation::GTE ?
                    BooleanOperation::LTE :
                    (gate_op == BooleanOperation::LT ?
                         BooleanOperation::GT :
                         (gate_op == BooleanOperation::LTE ?
                              BooleanOperation::GTE :
                              BooleanOperation::UNKNOWN)))));
}

// Outputs the NOT of the input operation.
BooleanOperation ReverseGateOp(const BooleanOperation& op) {
  if (op == BooleanOperation::UNKNOWN) LOG_FATAL("Fatal Error.");
  if (op == BooleanOperation::IDENTITY) {
    return BooleanOperation::NOT;
  } else if (op == BooleanOperation::NOT) {
    return BooleanOperation::IDENTITY;
  } else if (op == BooleanOperation::OR) {
    return BooleanOperation::NOR;
  } else if (op == BooleanOperation::XOR) {
    return BooleanOperation::EQ;
  } else if (op == BooleanOperation::EQ) {
    return BooleanOperation::XOR;
  } else if (op == BooleanOperation::AND) {
    return BooleanOperation::NAND;
  } else if (op == BooleanOperation::NAND) {
    return BooleanOperation::AND;
  } else if (op == BooleanOperation::NOR) {
    return BooleanOperation::OR;
  } else if (op == BooleanOperation::GT) {
    return BooleanOperation::LTE;
  } else if (op == BooleanOperation::GTE) {
    return BooleanOperation::LT;
  } else if (op == BooleanOperation::LT) {
    return BooleanOperation::GTE;
  } else if (op == BooleanOperation::LTE) {
    return BooleanOperation::GT;
  }

  // Code will never reach here.
  LOG_FATAL("Fatal Error.");
  return BooleanOperation::UNKNOWN;
}
// Same as above, but replaces the input gate's type_ in-place.
void ReverseGateOp(StandardGate<bool>& gate) {
  gate.type_ = ReverseGateOp(gate.type_);
}

// Updates target_gate's operation to reflect that its left wire (resp. right
// wire, if 'input_wire_is_left' is false) used to be NOT'ed, but now it won't
// be; e.g. so a LT gate, which is only true if left wire is '0' and right wire
// is '1', should only now be true if the NOT of the left wire is '0' (i.e.
// left wire is '1') and right wire is '1', which is AND.
void FlipGateOp(const bool input_wire_is_left, StandardGate<bool>& target_gate) {
  if (target_gate.type_ == BooleanOperation::UNKNOWN) LOG_FATAL("Fatal Error.");
  if (target_gate.type_ == BooleanOperation::IDENTITY) {
    target_gate.type_ = BooleanOperation::NOT;
  } else if (target_gate.type_ == BooleanOperation::NOT) {
    target_gate.type_ = BooleanOperation::IDENTITY;
  } else if (target_gate.type_ == BooleanOperation::OR) {
    if (input_wire_is_left) {
      target_gate.type_ = BooleanOperation::LTE;
    } else {
      target_gate.type_ = BooleanOperation::GTE;
    }
  } else if (target_gate.type_ == BooleanOperation::XOR) {
    target_gate.type_ = BooleanOperation::EQ;
  } else if (target_gate.type_ == BooleanOperation::EQ) {
    target_gate.type_ = BooleanOperation::XOR;
  } else if (target_gate.type_ == BooleanOperation::AND) {
    if (input_wire_is_left) {
      target_gate.type_ = BooleanOperation::LT;
    } else {
      target_gate.type_ = BooleanOperation::GT;
    }
  } else if (target_gate.type_ == BooleanOperation::NAND) {
    if (input_wire_is_left) {
      target_gate.type_ = BooleanOperation::GTE;
    } else {
      target_gate.type_ = BooleanOperation::LTE;
    }
  } else if (target_gate.type_ == BooleanOperation::NOR) {
    if (input_wire_is_left) {
      target_gate.type_ = BooleanOperation::GT;
    } else {
      target_gate.type_ = BooleanOperation::LT;
    }
  } else if (target_gate.type_ == BooleanOperation::GT) {
    if (input_wire_is_left) {
      target_gate.type_ = BooleanOperation::NOR;
    } else {
      target_gate.type_ = BooleanOperation::AND;
    }
  } else if (target_gate.type_ == BooleanOperation::GTE) {
    if (input_wire_is_left) {
      target_gate.type_ = BooleanOperation::NAND;
    } else {
      target_gate.type_ = BooleanOperation::OR;
    }
  } else if (target_gate.type_ == BooleanOperation::LT) {
    if (input_wire_is_left) {
      target_gate.type_ = BooleanOperation::AND;
    } else {
      target_gate.type_ = BooleanOperation::NOR;
    }
  } else if (target_gate.type_ == BooleanOperation::LTE) {
    if (input_wire_is_left) {
      target_gate.type_ = BooleanOperation::OR;
    } else {
      target_gate.type_ = BooleanOperation::NAND;
    }
  }
}

// Many of the reductions made in ReduceCircuit require knowledge of
// input wires, which is not easily accessible (not stored directly in
// any of the StandardCircuit fields). Rather than performing a search
// to find input wires for every reduction call, just do the search once
// at the outset of ReduceCircuit, and then keep the mappings up-to-date
// through all reductions. This will (hopefully) save time (with the
// *hopefully* part in somewhat of question, as maintaining the input
// mappings may get as cumbersome as just traversing the circuit anyway,
// since e.g. removing a gate from a level will cause all numbering
// to get out of whack...
bool GetInputWireMappings(
    const StandardCircuit<bool>& input,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input) {
  // First, go through (global) input wires for each party.
  for (size_t party = 0; party < input.inputs_as_generic_value_locations_.size();
       ++party) {
    for (size_t input_index = 0;
         input_index < input.inputs_as_generic_value_locations_[party].size();
         ++input_index) {
      const vector<set<WireLocation>>& input_one_i =
          input.inputs_as_generic_value_locations_[party][input_index];
      for (uint64_t bit_index = 0; bit_index < input_one_i.size(); ++bit_index) {
        for (const WireLocation& wire : input_one_i[bit_index]) {
          if (wire.is_left_) {
            (*((*gate_to_left_input)[wire.loc_.level_]))[wire.loc_.index_] =
                GateLocation(-4 - party, input_index);
          } else {
            (*((*gate_to_right_input)[wire.loc_.level_]))[wire.loc_.index_] =
                GateLocation(-4 - party, input_index);
          }
        }
      }
    }
  }
  // Go through Constant '0' inputs.
  for (const WireLocation& wire : input.constant_zero_input_) {
    if (wire.is_left_) {
      (*((*gate_to_left_input)[wire.loc_.level_]))[wire.loc_.index_] =
          GateLocation(-2, 0);
    } else {
      (*((*gate_to_right_input)[wire.loc_.level_]))[wire.loc_.index_] =
          GateLocation(-2, 0);
    }
  }
  // Go through Constant '1' inputs.
  for (const WireLocation& wire : input.constant_one_input_) {
    if (wire.is_left_) {
      (*((*gate_to_left_input)[wire.loc_.level_]))[wire.loc_.index_] =
          GateLocation(-3, 0);
    } else {
      (*((*gate_to_right_input)[wire.loc_.level_]))[wire.loc_.index_] =
          GateLocation(-3, 0);
    }
  }

  // Now update gate_to_input_wires with information that comes from the
  // output wires of each gate.
  for (uint64_t level = 0; level < input.levels_.size(); ++level) {
    for (uint64_t gate = 0; gate < input.levels_[level].gates_.size(); ++gate) {
      const StandardGate<bool>& current_gate = input.levels_[level].gates_[gate];
      for (const WireLocation& wire : current_gate.output_wire_locations_) {
        // Ignore (global) output wires.
        if (wire.loc_.level_ == -1) continue;
        if (wire.is_left_) {
          (*((*gate_to_left_input)[wire.loc_.level_]))[wire.loc_.index_] =
              GateLocation(level, gate);
        } else {
          (*((*gate_to_right_input)[wire.loc_.level_]))[wire.loc_.index_] =
              GateLocation(level, gate);
        }
      }
    }
  }

  return true;
}

// To be used as a subroutine of ConstructEqCircuit() (and of
// ConstructGtLtCircuit()). Creates a circuit that evaluates bits
// [bit_index, bit_index + num_input_bits), and outputs whether these bits
// (of input one) are EQ to these bits (of input two).
bool ConstructEqSubcircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output) {
  if (num_input_bits == 1) {
    return ConstructBitComparisonCircuit(
        one_is_twos_complement,
        two_is_twos_complement,
        value_one_party_index,
        value_two_party_index,
        value_one_input_index,
        bit_index,
        value_two_input_index,
        bit_index,
        BooleanOperation::EQ,
        output);
  } else {
    const uint64_t midpoint = num_input_bits / 2;
    const uint64_t num_upper_bits = midpoint;
    const uint64_t num_lower_bits = num_input_bits - midpoint;
    StandardCircuit<bool> upper_bits_eq, lower_bits_eq;
    if (!ConstructEqSubcircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index + num_lower_bits,
            num_upper_bits,
            &upper_bits_eq) ||
        !ConstructEqSubcircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index,
            num_lower_bits,
            &lower_bits_eq)) {
      LOG_ERROR(
          "Failed to create subcircuits for (" + Itoa(bit_index) + ", " +
          Itoa(num_input_bits) + ")");
      return false;
    }
    return MergeCircuits(
        true, BooleanOperation::AND, upper_bits_eq, lower_bits_eq, output);
  }

  // Code will never reach here.
  return false;
}

// To be used as a subroutine of ConstructGtLtCircuit(). Creates a circuit
// that evaluates bits [bit_index, bit_index + num_input_bits), and outputs
// whether these bits (of input one) are GT these bits (of input two).
bool ConstructGtLtSubcircuit(
    const bool is_gt,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output) {
  // Return if comparing a single bit.
  if (num_input_bits == 1) {
    return ConstructBitComparisonCircuit(
        one_is_twos_complement,
        two_is_twos_complement,
        value_one_party_index,
        value_two_party_index,
        value_one_input_index,
        bit_index,
        value_two_input_index,
        bit_index,
        (is_gt ? BooleanOperation::GT : BooleanOperation::LT),
        output);
    // Otherwise, split bits in half, and recursively call GT on the Left and
    // Right halves: Take the left half (higher-order bits) answer if they're
    // not equal, otherwise, take right half answer.
  } else {
    const uint64_t midpoint = num_input_bits / 2;
    const uint64_t num_upper_bits = midpoint;
    const uint64_t num_lower_bits = num_input_bits - midpoint;
    StandardCircuit<bool> upper_bits_gt, upper_bits_eq, lower_bits_gt;
    if (!ConstructGtLtSubcircuit(
            is_gt,
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index + num_lower_bits,
            num_upper_bits,
            &upper_bits_gt) ||
        !ConstructEqSubcircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index + num_lower_bits,
            num_upper_bits,
            &upper_bits_eq) ||
        !ConstructGtLtSubcircuit(
            is_gt,
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index,
            num_lower_bits,
            &lower_bits_gt)) {
      LOG_ERROR(
          "Failed to create subcircuits for (" + Itoa(bit_index) + ", " +
          Itoa(num_input_bits) + ")");
      return false;
    }
    // Above, there were three sub-circuits built:
    //   1) GT on right (lower order) bits
    //   2) EQ on left (higer order) bits
    //   3) GT on left (higer order) bits
    // Result is: (3) || ((2) && (1))
    // First, combine (2) && (1).
    StandardCircuit<bool> lower_bits_output;
    if (!MergeCircuits(
            true,
            BooleanOperation::AND,
            upper_bits_eq,
            lower_bits_gt,
            &lower_bits_output)) {
      LOG_ERROR(
          "Failed to merge GtSubcircuit for (" + Itoa(bit_index) + ", " +
          Itoa(num_input_bits) + ")");
      return false;
    }
    // Now, combine (3) || ((2) && (1)).
    return MergeCircuits(
        true, BooleanOperation::OR, upper_bits_gt, lower_bits_output, output);
  }

  // Code will never reach here.
  return false;
}

bool ConstructEqCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  const uint64_t num_one_non_sign_bits =
      num_one_input_bits - (one_is_twos_complement ? 1 : 0);
  const uint64_t num_two_non_sign_bits =
      num_two_input_bits - (two_is_twos_complement ? 1 : 0);
  const uint64_t num_common_bits =
      min(num_one_non_sign_bits, num_two_non_sign_bits);
  if (num_one_non_sign_bits <= 0 || num_two_non_sign_bits <= 0 ||
      num_common_bits <= 0) {
    LOG_FATAL("Fatal Error.");
  }

  const bool compare_bits_directly =
      (num_one_input_bits == num_two_input_bits) &&
      (one_is_twos_complement == two_is_twos_complement);

  // First, construct a circuit that compares the "common" bits (i.e. compares
  // the least-significant 'num_common_bits' bits of the inputs.
  StandardCircuit<bool> compare_common_bits;
  StandardCircuit<bool> sign_bit_and_common_bits;
  if (!ConstructEqSubcircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          0,
          (compare_bits_directly && one_is_twos_complement ?
               num_common_bits + 1 :
               num_common_bits),
          (compare_bits_directly ?
               output :
               (one_is_twos_complement || two_is_twos_complement ?
                    &compare_common_bits :
                    &sign_bit_and_common_bits)))) {
    return false;
  }

  // The above circuit is the final one, if the two inputs have the same
  // number of bits, and we don't have to handle 2's complement leading bit
  // (i.e. an unsigned int, or some other data type where leading bit
  // is a value bit, not sign bit).
  if (compare_bits_directly) {
    // Overwrite function_description_, which may have gotten overly complicated.
    WriteEqFunctionDescription(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        output);

    return true;
  }

  // Compare sign bit(s), if either type is signed.
  if (one_is_twos_complement || two_is_twos_complement) {
    StandardCircuit<bool> compare_sign_bits;
    if (one_is_twos_complement && two_is_twos_complement) {
      if (!ConstructBitComparisonCircuit(
              one_is_twos_complement,
              two_is_twos_complement,
              value_one_party_index,
              value_two_party_index,
              value_one_input_index,
              num_one_input_bits - 1,
              value_two_input_index,
              num_two_input_bits - 1,
              BooleanOperation::EQ,
              &compare_sign_bits)) {
        LOG_ERROR("Failed to create the leading bit comparison circuits.");
        return false;
      }
    } else if (one_is_twos_complement) {
      if (!ConstructSingleBitNotCircuit(
              true,
              value_one_party_index,
              value_one_input_index,
              num_one_input_bits - 1,
              &compare_sign_bits)) {
        LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
        return false;
      }
    } else if (two_is_twos_complement) {
      if (!ConstructSingleBitNotCircuit(
              true,
              value_two_party_index,
              value_two_input_index,
              num_two_input_bits - 1,
              &compare_sign_bits)) {
        LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
        return false;
      }
    }

    // Now, combine circuits:
    //   compare_sign_bits && compare_common_bits
    if (!MergeCircuits(
            true,
            BooleanOperation::AND,
            compare_sign_bits,
            compare_common_bits,
            (num_one_non_sign_bits == num_two_non_sign_bits ?
                 output :
                 &sign_bit_and_common_bits))) {
      LOG_ERROR("Failed to merge lower bits with leading bit.");
      return false;
    }
  }

  if (num_one_non_sign_bits == num_two_non_sign_bits) {
    // Code can only reach here if one of the inputs is signed and the other
    // isn't, and the unsigned one has one less bit than the signed one
    // (e.g. BOOL and INT2); otherwise, we would have returned above.
    // In this case, sign_bit_and_common_bits already contains all the
    // necessary comparisons, just return.
    WriteEqFunctionDescription(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        output);
    return true;
  } else if (num_one_input_bits == num_two_input_bits) {
    // Code can only reach here if one of the inputs is signed and the other
    // isn't, and the two DataTypes have the same number of bits (e.g.
    // INT2 vs UINT2). In this case, just need to pick out the NOT of the
    // leading bit of the unsigned input, and AND with sign_bit_and_common_bits.
    StandardCircuit<bool> leading_unsigned_bit;
    if (one_is_twos_complement) {
      if (!ConstructSingleBitNotCircuit(
              false,
              value_one_party_index,
              value_one_input_index,
              num_one_input_bits - 1,
              &leading_unsigned_bit)) {
        LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
        return false;
      }
    } else {
      if (!ConstructSingleBitNotCircuit(
              false,
              value_two_party_index,
              value_two_input_index,
              num_two_input_bits - 1,
              &leading_unsigned_bit)) {
        LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
        return false;
      }
    }

    // Now merge with 'sign_bit_and_common_bits'.
    if (!MergeCircuits(
            true,
            BooleanOperation::AND,
            leading_unsigned_bit,
            sign_bit_and_common_bits,
            output)) {
      LOG_ERROR("Failed to merge lower bits with leading bit.");
      return false;
    }

    // Overwrite function_description_, which may have gotten overly complicated.
    WriteEqFunctionDescription(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        output);
    return true;
  }

  // The fact that we reached here means that:
  //   - num_one_non_sign_bits != num_two_non_sign_bits
  //   - num_one_input_bits    != num_two_input_bits
  //   - The above two together imply:
  //       num_one_non_sign_bits > num_two_non_sign_bits iff
  //       num_one_input_bits > num_two_input_bits
  //     (and ditto for '<').

  // Now, go through extra bits in input one, returning false if:
  //   - Any of these extra bits is non-zero, AND:
  //     Input one is unsigned OR input one is non-negative
  //   - Any of these extra bits is non-one, AND:
  //     Input one is signed AND input one is negative
  if (num_one_non_sign_bits > num_two_non_sign_bits) {
    // Construct trivial circuits that pick out the (extra) bits of input one.
    vector<StandardCircuit<bool>> identity_bits(
        num_one_non_sign_bits - num_two_non_sign_bits);
    for (uint64_t i = 0; i < identity_bits.size(); ++i) {
      if (!ConstructSelectBitCircuit(
              one_is_twos_complement,
              value_one_party_index,
              value_one_input_index,
              num_common_bits + i,
              &identity_bits[i])) {
        return false;
      }
    }
    // Merge extra bits:
    //   - OR them together, so result is '1' iff any of the bits are '1'
    //   - AND them together, so result is '1' iff all bits are '1'
    vector<StandardCircuit<bool>> or_identity_bits(identity_bits.size() - 1);
    vector<StandardCircuit<bool>> and_identity_bits(identity_bits.size() - 1);
    for (uint64_t i = 0; i < or_identity_bits.size(); ++i) {
      if (!MergeCircuits(
              true,
              BooleanOperation::OR,
              (i == 0 ? identity_bits[0] : or_identity_bits[i - 1]),
              identity_bits[i + 1],
              &or_identity_bits[i]) ||
          !MergeCircuits(
              true,
              BooleanOperation::AND,
              (i == 0 ? identity_bits[0] : and_identity_bits[i - 1]),
              identity_bits[i + 1],
              &and_identity_bits[i])) {
        return false;
      }
    }

    // We care about the 'or_identity_bits' iff input one is unsigned type OR
    // if input one is non-negative.
    if (one_is_twos_complement) {
      // Need to check leading bit of input one: If it is negative, we need
      // all extra bits to be 1; otherwise, they should all be zero.
      // First, merge the 'Leading bit 1' with 'all bits 1'.
      StandardCircuit<bool> leading_bit_one;
      if (!ConstructSelectBitCircuit(
              true,
              value_one_party_index,
              value_one_input_index,
              num_one_input_bits - 1,
              &leading_bit_one)) {
        LOG_ERROR("Failed to ConstructSelectBitCircuit.");
        return false;
      }
      StandardCircuit<bool> all_bits_one;
      if (!MergeCircuits(
              true,
              BooleanOperation::AND,
              (or_identity_bits.empty() ? identity_bits.back() :
                                          and_identity_bits.back()),
              leading_bit_one,
              &all_bits_one)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
      // Next, merge 'Leading bit 0' with 'no bits 1'.
      StandardCircuit<bool> leading_bit_zero;
      if (!ConstructSingleBitNotCircuit(
              true,
              value_one_party_index,
              value_one_input_index,
              num_one_input_bits - 1,
              &leading_bit_zero)) {
        LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
        return false;
      }
      // Note: All extra bits (including leading bit) are 0 if:
      //   (!or_identity_bits) && leading_bit_zero
      // which is the same as: or_identity_bits < leading_bit_zero.
      StandardCircuit<bool> all_bits_zero;
      if (!MergeCircuits(
              true,
              BooleanOperation::LT,
              (or_identity_bits.empty() ? identity_bits.back() :
                                          or_identity_bits.back()),
              leading_bit_zero,
              &all_bits_zero)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
      // Now, merge these two together.
      StandardCircuit<bool> leading_bits_eq;
      if (!MergeCircuits(
              true,
              BooleanOperation::OR,
              all_bits_one,
              all_bits_zero,
              &leading_bits_eq)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
      // Finally, merge with 'sign_bit_and_common_bits'.
      if (!MergeCircuits(
              true,
              BooleanOperation::AND,
              leading_bits_eq,
              sign_bit_and_common_bits,
              output)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
    } else {
      // Combine with the result of the 'sign_bit_and_common_bits' bits. Notice I want:
      //   (!x) && y,
      // where x is the OR'ed together bits of input one, and y is the output of
      // the 'sign_bit_and_common_bits' circuit. The (!x && y) gate is same as x < y.
      if (!MergeCircuits(
              true,
              BooleanOperation::LT,
              (or_identity_bits.empty() ? identity_bits.back() :
                                          or_identity_bits.back()),
              sign_bit_and_common_bits,
              output)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
    }
  }

  // Now, go through extra bits in input two, returning false if:
  //   - Any of these extra bits is non-zero, AND:
  //     Input two is unsigned OR input one is non-negative
  //   - Any of these extra bits is non-one, AND:
  //     Input two is signed AND input one is negative
  if (num_one_non_sign_bits < num_two_non_sign_bits) {
    // Construct trivial circuits that pick out the (extra) bits of input one.
    vector<StandardCircuit<bool>> identity_bits(
        num_two_non_sign_bits - num_one_non_sign_bits);
    for (uint64_t i = 0; i < identity_bits.size(); ++i) {
      if (!ConstructSelectBitCircuit(
              two_is_twos_complement,
              value_two_party_index,
              value_two_input_index,
              num_common_bits + i,
              &identity_bits[i])) {
        return false;
      }
    }
    // Merge extra bits:
    //   - OR them together, so result is '1' iff any of the bits are '1'
    //   - AND them together, so result is '1' iff all bits are '1'
    vector<StandardCircuit<bool>> or_identity_bits(identity_bits.size() - 1);
    vector<StandardCircuit<bool>> and_identity_bits(identity_bits.size() - 1);
    for (uint64_t i = 0; i < or_identity_bits.size(); ++i) {
      if (!MergeCircuits(
              true,
              BooleanOperation::OR,
              (i == 0 ? identity_bits[0] : or_identity_bits[i - 1]),
              identity_bits[i + 1],
              &or_identity_bits[i]) ||
          !MergeCircuits(
              true,
              BooleanOperation::AND,
              (i == 0 ? identity_bits[0] : and_identity_bits[i - 1]),
              identity_bits[i + 1],
              &and_identity_bits[i])) {
        return false;
      }
    }

    // We care about the 'or_identity_bits' iff input two is unsigned type OR
    // if input two is non-negative.
    if (two_is_twos_complement) {
      // Need to check leading bit of input two: If it is negative, we need
      // all extra bits to be 1; otherwise, they should all be zero.
      // First, merge the 'Leading bit 1' with 'all bits 1'.
      StandardCircuit<bool> leading_bit_one;
      if (!ConstructSelectBitCircuit(
              true,
              value_two_party_index,
              value_two_input_index,
              num_two_input_bits - 1,
              &leading_bit_one)) {
        LOG_ERROR("Failed to ConstructSelectBitCircuit.");
        return false;
      }
      StandardCircuit<bool> all_bits_one;
      if (!MergeCircuits(
              true,
              BooleanOperation::AND,
              (or_identity_bits.empty() ? identity_bits.back() :
                                          and_identity_bits.back()),
              leading_bit_one,
              &all_bits_one)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
      // Next, merge 'Leading bit 0' with 'no bits 1'.
      StandardCircuit<bool> leading_bit_zero;
      if (!ConstructSingleBitNotCircuit(
              true,
              value_two_party_index,
              value_two_input_index,
              num_two_input_bits - 1,
              &leading_bit_zero)) {
        LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
        return false;
      }
      // Note: All extra bits (including leading bit) are 0 if:
      //   (!or_identity_bits) && leading_bit_zero
      // which is the same as: or_identity_bits < leading_bit_zero.
      StandardCircuit<bool> all_bits_zero;
      if (!MergeCircuits(
              true,
              BooleanOperation::LT,
              (or_identity_bits.empty() ? identity_bits.back() :
                                          or_identity_bits.back()),
              leading_bit_zero,
              &all_bits_zero)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
      // Now, merge these two together.
      StandardCircuit<bool> leading_bits_eq;
      if (!MergeCircuits(
              true,
              BooleanOperation::OR,
              all_bits_one,
              all_bits_zero,
              &leading_bits_eq)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
      // Finally, merge with 'sign_bit_and_common_bits'.
      if (!MergeCircuits(
              true,
              BooleanOperation::AND,
              leading_bits_eq,
              sign_bit_and_common_bits,
              output)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
    } else {
      // Combine with the result of the 'sign_bit_and_common_bits' bits. Notice I want:
      //   (!x) && y,
      // where x is the OR'ed together bits of input two, and y is the output of
      // the 'sign_bit_and_common_bits' circuit. The (!x && y) gate is same as x < y.
      if (!MergeCircuits(
              true,
              BooleanOperation::LT,
              (or_identity_bits.empty() ? identity_bits.back() :
                                          or_identity_bits.back()),
              sign_bit_and_common_bits,
              output)) {
        LOG_ERROR("Unable to merge uncommon bits with EQ for common bits.");
        return false;
      }
    }
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  WriteEqFunctionDescription(
      value_one_party_index,
      value_one_input_index,
      value_two_party_index,
      value_two_input_index,
      output);

  return true;
}

bool ConstructGtLtCircuit(
    const bool is_gt,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  if (num_one_input_bits <= 1 && one_is_twos_complement)
    LOG_FATAL("Fatal Error.");
  if (num_two_input_bits <= 1 && two_is_twos_complement)
    LOG_FATAL("Fatal Error.");

  // First, handle the case that the two inputs have different DataType sizes:
  // Take the smaller input, and expand it out by either 0-padding (if it
  // is an unsigned type), or copying the leading (2's complement) bit (if signed type)
  if (num_one_input_bits != num_two_input_bits) {
    const int num_max_bits = (int) max(num_one_input_bits, num_two_input_bits);
    // Construct a GT/LT circuit, assuming the smaller input has already
    // been expanded.
    StandardCircuit<bool> circuit_of_equal_bits;
    if (!ConstructGtLtCircuit(
            is_gt,
            one_is_twos_complement,
            two_is_twos_complement,
            0,
            0,
            1,
            0,
            num_max_bits,
            num_max_bits,
            &circuit_of_equal_bits)) {
      LOG_ERROR("Failed to ConstructGtLtCircuit");
      return false;
    }

    // Construct identity circuits for the two inputs.
    // First, construct an identity circuit for the first input.
    StandardCircuit<bool> input_one;
    if (!ConstructIdentityCircuit(
            false,
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            num_one_input_bits,
            &input_one)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_one's fields.
    input_one.num_outputs_ = 1;
    DataType output_one_type;
    if (!GetIntegerDataType(true, (int) num_one_input_bits, &output_one_type)) {
      return false;
    }
    input_one.output_designations_.clear();
    input_one.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_one_type));
    input_one.function_description_.clear();
    input_one.function_description_.resize(1);
    Formula& formula = input_one.function_description_[0];
    formula.op_.type_ = OperationType::BOOLEAN;
    formula.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str =
        "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
    formula.value_ = GenericValue(var_str);

    // Now construct an identity circuit for the second input.
    StandardCircuit<bool> input_two;
    if (!ConstructIdentityCircuit(
            false,
            two_is_twos_complement,
            value_two_party_index,
            value_two_input_index,
            num_two_input_bits,
            &input_two)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_two's fields.
    input_two.num_outputs_ = 1;
    DataType output_two_type;
    if (!GetIntegerDataType(true, (int) num_two_input_bits, &output_two_type)) {
      return false;
    }
    input_two.output_designations_.clear();
    input_two.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_two_type));
    input_two.function_description_.clear();
    input_two.function_description_.resize(1);
    Formula& formula_two = input_two.function_description_[0];
    formula_two.op_.type_ = OperationType::BOOLEAN;
    formula_two.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str_two =
        "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
    formula_two.value_ = GenericValue(var_str_two);

    // Expand the smaller input to the equivalent representation using
    // the bigger datatype (e.g. -2 = 10 (INT2) -> 1110 (INT4)).
    if (num_one_input_bits < num_two_input_bits) {
      if (!CastCircuitOutputAsMoreBits(
              one_is_twos_complement, (int) num_max_bits, &input_one)) {
        return false;
      }

      // Join expanded first input and second input with GT circuit.
      return JoinCircuits(input_one, input_two, circuit_of_equal_bits, output);
    } else {
      if (!CastCircuitOutputAsMoreBits(
              two_is_twos_complement, (int) num_max_bits, &input_two)) {
        return false;
      }

      // Join expanded first input and second input with GT circuit.
      return JoinCircuits(input_one, input_two, circuit_of_equal_bits, output);
    }
  }

  // That we reached here means num_one_input_bits == num_two_input_bits.

  // If one number is twos complement and the other isn't, we'll need to
  // handle the leading bit specially (and even if they're both the same
  // type, we still need to handle the leading bit specially, since it
  // has different implications on whether it is a sign (2's complement)
  // bit or not.
  const uint64_t num_common_bits =
      min((num_one_input_bits - (one_is_twos_complement ? 1 : 0)),
          (num_two_input_bits - (two_is_twos_complement ? 1 : 0)));
  if (num_common_bits <= 0) LOG_FATAL("Fatal Error.");

  // First, construct a circuit that compares the "common" bits (i.e. compares
  // the least-significant 'num_common_bits' bits of the inputs.
  StandardCircuit<bool> compare_common_bits;
  if (!ConstructGtLtSubcircuit(
          is_gt,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          0,
          num_common_bits,
          ((one_is_twos_complement || two_is_twos_complement) ?
               &compare_common_bits :
               output))) {
    return false;
  }

  // The above circuit is the final one, if neither input is in 2's complement.
  if (!one_is_twos_complement && !two_is_twos_complement) {
    return true;
  }

  // Now, go through extra bits in input one.
  // If these bits matter (which they will, unless one or both types are
  // signed and the leading (2's complement) bit determines the answer),
  // then the right thing to do is check if *any* of these bits are non-
  // zero, and if so:
  //   - Return TRUE  if  is_gt and input one is unsigned.
  //   - Return FALSE if !is_gt and input one is unsigned.
  //   - Return FALSE if  is_gt and input one is signed with leading bit 1
  //   - Return FALSE if  is_gt and input one is signed with leading bit 0
  //   (resp. FALSE, if
  // is_gt is false) if ANY of them are non-zero.

  // Leading bit is 2's complement -2^n bit (for at least one of the inputs).
  // Need to compare leading bits appropriately, and then Merge with the
  // circuit for comparing the lower bits.
  if (one_is_twos_complement && two_is_twos_complement) {
    StandardCircuit<bool> leading_bit_gt, leading_bit_eq;
    if (!ConstructBitComparisonCircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_two_party_index,
            value_one_input_index,
            num_one_input_bits - 1,
            value_two_input_index,
            num_two_input_bits - 1,
            (is_gt ? BooleanOperation::LT : BooleanOperation::GT),
            &leading_bit_gt) ||
        !ConstructBitComparisonCircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_two_party_index,
            value_one_input_index,
            num_one_input_bits - 1,
            value_two_input_index,
            num_two_input_bits - 1,
            BooleanOperation::EQ,
            &leading_bit_eq)) {
      LOG_ERROR("Failed to create the leading bit comparison circuits.");
      return false;
    }

    // Now, combine circuits:
    //   leading_bit_gt OR (leading_bit_eq && compare_common_bits)
    StandardCircuit<bool> leading_bit_eq_and_lower_bits_output;
    if (!MergeCircuits(
            true,
            BooleanOperation::AND,
            leading_bit_eq,
            compare_common_bits,
            &leading_bit_eq_and_lower_bits_output) ||
        !MergeCircuits(
            true,
            BooleanOperation::OR,
            leading_bit_gt,
            leading_bit_eq_and_lower_bits_output,
            output)) {
      LOG_ERROR("Failed to merge lower bits with leading bit.");
      return false;
    }
    return true;
  }

  // The fact that code reached here means that one of the numbers is
  // two's complement, and the other isn't. In this case, the leading
  // bit of either input will completely determine the output it it is '1',
  // otherwise we'll need to look at lower bits.
  //
  // First, write circuits that pick out the leading bits (and their 'not').
  StandardCircuit<bool> leading_bit_one, leading_bit_two;
  StandardCircuit<bool> not_leading_bit_one, not_leading_bit_two;
  if (!ConstructSelectBitCircuit(
          one_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          num_one_input_bits - 1,
          &leading_bit_one) ||
      !ConstructSingleBitNotCircuit(
          one_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          num_one_input_bits - 1,
          &not_leading_bit_one) ||
      !ConstructSelectBitCircuit(
          two_is_twos_complement,
          value_two_party_index,
          value_two_input_index,
          num_two_input_bits - 1,
          &leading_bit_two) ||
      !ConstructSingleBitNotCircuit(
          two_is_twos_complement,
          value_two_party_index,
          value_two_input_index,
          num_two_input_bits - 1,
          &not_leading_bit_two)) {
    LOG_ERROR("Failed to create the leading bit comparison circuits.");
    return false;
  }

  // Now, combine the appropriate circuits based on is_gt and which
  // input is the one in 2's complement.
  if (one_is_twos_complement) {
    // The first input is 2's complement, the second isn't. This means
    // the second number is unsigned, and hence we should return:
    //   - False, if is_gt is true and leading_bit is '1'
    //   - True, if is_gt is false and leading_bit is '1'
    //   - False, if is_gt is true and leading_bit of other is '1'
    //   - True, if is_gt is false and leading_bit of other is '1'
    //   - Result of lower bits, if both leading_bit are '0'.
    // Succinctly:
    //   - If is_gt:
    //       !leading_bit_one && !leading_bit_two && lower_bits_output
    //   - If !is_gt:
    //       leading_bit_one || leading_bit_two || lower_bits_output
    if (is_gt) {
      StandardCircuit<bool> combined_leading_bits;
      if (!MergeCircuits(
              true,
              BooleanOperation::AND,
              not_leading_bit_one,
              not_leading_bit_two,
              &combined_leading_bits) ||
          !MergeCircuits(
              true,
              BooleanOperation::AND,
              combined_leading_bits,
              compare_common_bits,
              output)) {
        LOG_ERROR("Failed to merge lower bits with leading bit.");
        return false;
      }
    } else {
      StandardCircuit<bool> combined_leading_bits;
      if (!MergeCircuits(
              true,
              BooleanOperation::OR,
              leading_bit_one,
              leading_bit_two,
              &combined_leading_bits) ||
          !MergeCircuits(
              true,
              BooleanOperation::OR,
              combined_leading_bits,
              compare_common_bits,
              output)) {
        LOG_ERROR("Failed to merge lower bits with leading bit.");
        return false;
      }
    }
  } else {
    // The second input is 2's complement, the first isn't. This means
    // the first number is unsigned, and hence we should return:
    //   - True, if is_gt is true and leading_bit is '1'
    //   - False, if is_gt is false and leading_bit is '1'
    //   - True, if is_gt is true and leading_bit of other is '1'
    //   - False, if is_gt is false and leading_bit of other is '1'
    //   - Result of lower bits, if both leading_bit are '0'.
    // Succinctly:
    //   - If !is_gt:
    //       !leading_bit_one && !leading_bit_two && lower_bits_output
    //   - If is_gt:
    //       leading_bit_one || leading_bit_two || lower_bits_output
    if (!is_gt) {
      StandardCircuit<bool> combined_leading_bits;
      if (!MergeCircuits(
              true,
              BooleanOperation::AND,
              not_leading_bit_one,
              not_leading_bit_two,
              &combined_leading_bits) ||
          !MergeCircuits(
              true,
              BooleanOperation::AND,
              combined_leading_bits,
              compare_common_bits,
              output)) {
        LOG_ERROR("Failed to merge lower bits with leading bit.");
        return false;
      }
    } else {
      StandardCircuit<bool> combined_leading_bits;
      if (!MergeCircuits(
              true,
              BooleanOperation::OR,
              leading_bit_one,
              leading_bit_two,
              &combined_leading_bits) ||
          !MergeCircuits(
              true,
              BooleanOperation::OR,
              combined_leading_bits,
              compare_common_bits,
              output)) {
        LOG_ERROR("Failed to merge lower bits with leading bit.");
        return false;
      }
    }
  }

  return true;
}

bool ConstructNeqCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  StandardCircuit<bool> eq;
  if (!ConstructEqCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          &eq) ||
      !ConstructNotCircuit(eq, output)) {
    return false;
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  if (output->function_description_.size() != 1) LOG_FATAL("Fatal Error.");
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::COMPARISON;
  formula.op_.comparison_op_ = ComparisonOperation::COMP_NEQ;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

bool ConstructGtCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  if (!ConstructGtLtCircuit(
          true,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          output)) {
    return false;
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  if (output->function_description_.size() != 1) LOG_FATAL("Fatal Error.");
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::COMPARISON;
  formula.op_.comparison_op_ = ComparisonOperation::COMP_GT;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

bool ConstructGteCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  StandardCircuit<bool> gt, eq;
  if (!ConstructGtCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          &gt) ||
      !ConstructEqCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          &eq) ||
      !MergeCircuits(true, BooleanOperation::OR, gt, eq, output)) {
    return false;
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  if (output->function_description_.size() != 1) LOG_FATAL("Fatal Error.");
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::COMPARISON;
  formula.op_.comparison_op_ = ComparisonOperation::COMP_GTE;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

bool ConstructLtCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  if (!ConstructGtLtCircuit(
          false,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          output)) {
    return false;
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  if (output->function_description_.size() != 1) LOG_FATAL("Fatal Error.");
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::COMPARISON;
  formula.op_.comparison_op_ = ComparisonOperation::COMP_LT;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

bool ConstructLteCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  StandardCircuit<bool> lt, eq;
  if (!ConstructLtCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          &lt) ||
      !ConstructEqCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          &eq) ||
      !MergeCircuits(true, BooleanOperation::OR, lt, eq, output)) {
    return false;
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  if (output->function_description_.size() != 1) LOG_FATAL("Fatal Error.");
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::COMPARISON;
  formula.op_.comparison_op_ = ComparisonOperation::COMP_LTE;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

// Constructs the single-bit addition circuit, without outputting Carry Bit:
//   - 3 inputs: 2 actual inputs, plus a carry input
//   - 1 outputs: 1 actual output (sum) (Carry bit not output).
/* Diagram:
                                   ____
                                  |    \
  C ----------------------------- | XOR \ ______  SUM
                               __ |     /
                              /   |____/
                             /
                 ____       /
         ______ |    \     / 
        /       | XOR \ __/
       /     __ |     /
  A __/     /   |____/
           /
          /
         /
        /
       /
  B __/
*/
bool ConstructAddBitNoCarrySubcircuit(
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  // Create the A XOR B circuit:
  // In diagrams below:
  //   u = value_one_party_index
  //   v = value_two_party_index
  //   i = value_one_input_index
  //   j = value_two_input_index
  //   b = bit_index
  //   d = 1 + max(value_one_input_index, value_two_input_index)
  /*
                             ____
                     ______ |    \
                    /       | XOR \ __
                   /     __ |     /
  A = (u, i, b) __/     /   |____/
                       /
                      /
                     /
                    / 
                   /   
  B = (v, j, b) __/
                  
  */
  StandardCircuit<bool> a_xor_b;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_one_party_index,
          value_two_party_index,
          value_one_input_index,
          bit_index,
          value_two_input_index,
          bit_index,
          BooleanOperation::XOR,
          (bit_index == 0 ? output : &a_xor_b))) {
    LOG_ERROR("Unable to construct Addition Subcircuit XOR circuit");
    return false;
  }

  if (bit_index == 0) return true;

  const uint64_t dummy_input_index =
      max(value_one_input_index, value_two_input_index) + 1;

  // Create the Sum XOR circuit: (A XOR B) XOR C:
  /*
                                     ____
                                    |    \
  C = (x, d, 0) ------------------- | XOR \
                                 __ |     /
                                /   |____/
                               /
                              /
                             /
  (A XOR B) = (y, 0, 0) ____/
  */
  StandardCircuit<bool> a_xor_b_xor_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          0,
          1,
          dummy_input_index,
          0,
          0,
          0,
          BooleanOperation::XOR,
          &a_xor_b_xor_c)) {
    LOG_ERROR("Unable to construct Addition Subcircuit XOR circuit");
    return false;
  }

  // Now, combine circuits:
  /*
                                               ____
                                              |    \
  C = (x, d, 0) ----------------------------- | XOR \ ______  SUM
                                           __ |     /
                                          /   |____/
                                         /
                             ____       /
                     ______ |    \     / 
                    /       | XOR \ __/
                   /     __ |     /
  A = (u, i, b) __/     /   |____/
                       /
                      /
                     /
                    /
                   /
  B = (v, j, b) __/
  */
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  //     Note on how to hook these circuits up:
  //       - a_xor_b has output gates:
  //           0: A XOR B
  //       - a_xor_b_xor_c has input mapping (where 'd' denotes dummy_input_index):
  //           XOR Gate:
  //             Left Wire:  (x, d, 0)
  //             Right Wire: (y, 0, 0)
  set<pair<int, pair<uint64_t, uint64_t>>>* xor_output_to_input_wire =
      FindOrInsert(
          (int64_t) 0,
          output_to_input,
          set<pair<int, pair<uint64_t, uint64_t>>>());
  xor_output_to_input_wire->insert(make_pair(1, make_pair(0, 0)));
  if (!JoinCircuits(output_to_input, a_xor_b, a_xor_b_xor_c, output)) {
    LOG_ERROR("Unable to join circuit.");
    return false;
  }

  return true;
}

// Constructs the single-bit addition circuit:
//   - 3 inputs: 2 actual inputs, plus a carry input
//   - 2 outputs: 1 actual output (sum), plus a carry output.
/* Diagram:
                                   ____
                                  |    \
  C ----------------------------- | XOR \ ______  SUM
                        \      __ |     /
                         \    /   |____/
                          \  /
                 ____      \/
         ______ |    \     /\
        /       | XOR \ __/  \     ____
       /     __ |     /   \   \__ |    \
  A __/     /   |____/     \      | AND \ __
      \    /                \____ |     /   \
       \  /                       |____/     \
        \/                                    \
        /\                                     \
       /  \                                     \     ____
  B __/    \     ____                            \__ |    \
      \     \__ |    \                               | OR  \ _______  Carry
       \        | AND \ ____________________________ |     /
        \______ |     /                              |____/
                |____/
*/
// In diagrams below:
//   u = value_one_party_index
//   v = value_two_party_index
//   i = value_one_input_index
//   j = value_two_input_index
//   b = bit_index
//   d = 1 + max(value_one_input_index, value_two_input_index)
bool ConstructAddBitWithCarrySubcircuit(
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  // Create the A XOR B circuit:
  /*
                             ____
                     ______ |    \
                    /       | XOR \ __
                   /     __ |     /
  A = (u, i, b) __/     /   |____/
                       /
                      /
                     /
                    / 
                   /   
  B = (v, j, b) __/
                  
  */
  StandardCircuit<bool> a_xor_b;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_one_party_index,
          value_two_party_index,
          value_one_input_index,
          bit_index,
          value_two_input_index,
          bit_index,
          BooleanOperation::XOR,
          &a_xor_b)) {
    LOG_ERROR("Unable to construct Addition Subcircuit XOR circuit");
    return false;
  }

  // Create the A AND B circuit:
  /*
  A = (u, i, b) __
                  \
                   \
                    \
                     \
                      \
  B = (v, j, b) __     \     ____
                  \     \__ |    \
                   \        | AND \ __
                    \______ |     /
                            |____/
  */
  StandardCircuit<bool> a_and_b;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_one_party_index,
          value_two_party_index,
          value_one_input_index,
          bit_index,
          value_two_input_index,
          bit_index,
          BooleanOperation::AND,
          &a_and_b)) {
    LOG_ERROR("Unable to construct Addition Subcircuit AND circuit");
    return false;
  }

  // If bit_index is 0, "carry" (wire C above) is 0, and circuit simplifies:
  /*
                             ____
                     ______ |    \
                    /       | XOR \ __ Output Wire 0 (Sum)
                   /     __ |     /
  A = (u, i, b) __/     /   |____/
                  \    /
                   \  /
                    \/                                    
                    /\
                   /  \
  B = (v, j, b) __/    \     ____
                  \     \__ |    \
                   \        | AND \ ___ Output Wire 1 (Carry)
                    \______ |     /
                            |____/
  */
  if (bit_index == 0) {
    if (!MergeCircuits(
            true, BooleanOperation::IDENTITY, a_xor_b, a_and_b, output)) {
      LOG_ERROR("Unable to create trivial (bit-zero) Add Subcircuit.");
      return false;
    }
    return true;
  }

  // d (a.k.a. 'dummy_input_index') = 1 + max(value_one_input_index, value_two_input_index).
  const uint64_t dummy_input_index =
      max(value_one_input_index, value_two_input_index) + 1;

  // Create the Sum XOR circuit: (A XOR B) XOR C:
  /*
                                     ____
                                    |    \
  C = (x, d, 0) ------------------- | XOR \
                                 __ |     /
                                /   |____/
                               /
                              /
                             /
  (A XOR B) = (y, 0, 0) ____/
  */
  StandardCircuit<bool> a_xor_b_xor_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          0,
          1,
          dummy_input_index,
          0,
          0,
          0,
          BooleanOperation::XOR,
          &a_xor_b_xor_c)) {
    LOG_ERROR("Unable to construct Addition Subcircuit XOR circuit");
    return false;
  }

  // Create the Carry AND circuit: (A XOR B) AND C:
  /*

  C = (x, d, 0) ----------
                          \
                           \
                            \
                             \
                              \
  (A XOR B) = (y, 0, 0)  ___   \     ____
                            \   \__ |    \
                             \      | AND \ __
                              \____ |     /
                                    |____/
  */
  StandardCircuit<bool> a_xor_b_and_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          0,
          1,
          dummy_input_index,
          0,
          0,
          0,
          BooleanOperation::AND,
          &a_xor_b_and_c)) {
    LOG_ERROR("Unable to construct Addition Subcircuit AND circuit");
    return false;
  }

  // Create the Carry OR circuit: ((A XOR B) AND C) OR (A AND B):
  /*

    ((A XOR B) AND C) = (x, 0, 0) ____________
                                              \
                                               \
                                                \
                                                 \
                                                  \     ____
                                                   \__ |    \
                                                       | OR  \ _______  Carry
    (A AND B) = (y, 0, 0) ____________________________ |     /
                                                       |____/
  */
  StandardCircuit<bool> final_carry;
  if (!ConstructBitComparisonCircuit(
          false, BooleanOperation::OR, &final_carry)) {
    LOG_ERROR("Unable to construct Addition Subcircuit Carry circuit");
    return false;
  }

  // Now, combine circuits.
  //   1) Merge (A XOR B) and (A AND B) circuits:
  /*
                            ____
                    ______ |    \
                   /       | XOR \ __ Output Wire 0
                  /     __ |     /   
 A = (u, i, b) __/     /   |____/
                 \    /
                  \  /
                   \/
                   /\
                  /  \
 B = (v, j, b) __/    \     ____
                 \     \__ |    \
                  \        | AND \ __ Output Wire 1
                   \______ |     /
                           |____/
  */
  StandardCircuit<bool> first_level;
  if (!MergeCircuits(
          true,
          // The following indicates not to actually merge the two above
          // circuits via an Operation, but rather just but them "side-by-side".
          BooleanOperation::IDENTITY,
          a_xor_b,
          a_and_b,
          &first_level)) {
    LOG_ERROR("Unable to merge first level circuit.");
    return false;
  }

  //  2) Create second-level circuit, by merging a_xor_b_xor_c and a_xor_b_and_c.
  /* Diagram:
                                     ____
                                    |    \
 C = (x, d ,0) -------------------- | XOR \ ______ Output Wire 0
                          \      __ |     /
                           \    /   |____/
                            \  /
                             \/
                             /\
 (A XOR B) = (y, 0, 0) _____/  \     ____
                            \   \__ |    \
                             \      | AND \ ______ Output Wire 1
                              \____ |     /
                                    |____/
  */
  StandardCircuit<bool> second_level;
  if (!MergeCircuits(
          true,
          // The following indicates not to actually merge the two above
          // circuits via an Operation, but rather just but them "side-by-side".
          BooleanOperation::IDENTITY,
          a_xor_b_xor_c,
          a_xor_b_and_c,
          &second_level)) {
    LOG_ERROR("Unable to merge first level circuit.");
    return false;
  }

  //  3) Join first_level circuit with second_level circuit.
  /* Diagram:
                                               ____
                                              |    \
  C = (x, d, 0) ----------------------------- | XOR \ ______ Output Wire 1
                                    \      __ |     /
                                     \    /   |____/
                                      \  /
                             ____      \/
                     ______ |    \     /\
                    /       | XOR \ __/  \     ____
                   /     __ |     /   \   \__ |    \
  A = (u, i, b) __/     /   |____/     \      | AND \ ______ Output Wire 2
                  \    /                \____ |     /
                   \  /                       |____/
                    \/                                    
                    /\
                   /  \
  B = (v, j, b) __/    \     ____
                  \     \__ |    \
                   \        | AND \ ________________________ Output Wire 0
                    \______ |     /
                            |____/
  */
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  //     Note on how to hook these circuits up:
  //       - first_level has output gates:
  //           0: A XOR B
  //           1: A AND B
  //       - second_level has input mapping (where 'd' denotes dummy_input_index):
  //           XOR Gate:
  //             Left Wire:  (x, d, 0)
  //             Right Wire: (y, 0, 0)
  //           AND Gate:
  //             Left Wire:  (x, d, 0)
  //             Right Wire: (y, 0, 0)
  set<pair<int, pair<uint64_t, uint64_t>>>* xor_output_to_input_wire =
      FindOrInsert(
          (int64_t) 0,
          output_to_input,
          set<pair<int, pair<uint64_t, uint64_t>>>());
  xor_output_to_input_wire->insert(make_pair(1, make_pair(0, 0)));
  StandardCircuit<bool> joined_second_level;
  if (!JoinCircuits(
          output_to_input, first_level, second_level, &joined_second_level)) {
    LOG_ERROR("Unable to join first and second levels.");
    return false;
  }

  //  4) Join circuits:
  //       'one':  joined_second_level
  //       'two':   final_carry
  //     Note on how to hook these circuits up:
  //       - joined_second_level has output gates:
  //           0: A AND B
  //           1: (A XOR B) XOR C
  //           2: (A XOR B) AND C
  //       - final_carry has input mapping (where 'd' denotes dummy_input_index):
  //           OR Gate:
  //             Left Wire:  (x, 0, 0)
  //             Right Wire: (y, 0, 0)
  //
  /* Diagram:
                                               ____
                                              |    \
  C = (x, d, 0) ----------------------------- | XOR \ ___________________ Output Wire 0 (Sum)
                                    \      __ |     /
                                     \    /   |____/
                                      \  /
                             ____      \/
                     ______ |    \     /\
                    /       | XOR \ __/  \     ____
                   /     __ |     /   \   \__ |    \
  A = (u, i, b) __/     /   |____/     \      | AND \ __
                  \    /                \____ |     /   \
                   \  /                       |____/     \
                    \/                                    \
                    /\                                     \
                   /  \                                     \     ___
  B = (v, j, b) __/    \     ____                            \__ |   \
                  \     \__ |    \                               | OR \__ Output Wire 1 (Carry)
                   \        | AND \ ____________________________ |    /
                    \______ |     /                              |___/
                            |____/
  */
  output_to_input.clear();
  set<pair<int, pair<uint64_t, uint64_t>>>* output_to_input_wire = FindOrInsert(
      (int64_t) 0, output_to_input, set<pair<int, pair<uint64_t, uint64_t>>>());
  output_to_input_wire->insert(make_pair(1, make_pair(0, 0)));
  output_to_input_wire = FindOrInsert(
      (int64_t) 2, output_to_input, set<pair<int, pair<uint64_t, uint64_t>>>());
  output_to_input_wire->insert(make_pair(0, make_pair(0, 0)));
  if (!JoinCircuits(output_to_input, joined_second_level, final_carry, output)) {
    LOG_ERROR("Unable to join second and carry levels.");
    return false;
  }

  return true;
}

bool ConstructAddBitSubcircuit(
    const bool output_carry_bit,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  if (output_carry_bit) {
    return ConstructAddBitWithCarrySubcircuit(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        bit_index,
        output);
  } else {
    return ConstructAddBitNoCarrySubcircuit(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        bit_index,
        output);
  }

  // Code will never reach here.
  return false;
}

// We construct the final circuit via the following steps; for notation, let
// l denote the number of blocks, each of m = n / l bits.
//   0) Construct trivial circuits for:
//        i) (Identity) Constant Input '0'
//       ii) (Identity) Constant Input '1'
//      iii) (Identity) Variable Input 'w'
//       iv) (Identity) Variable Input 'z'
//        v) (Identity+Not) Variable Input 'u', two outputs: (!u, u)
//      Note that the circuits (iii) and (iv) are identical, except that
//      the input wire is labelled differently.
//   1) Construct the 'bit' addition circuits (there will be 'n' total).
//   2) Construct the 'lookahead block' circuits (there will be 'l' total),
//      by Joining the appropriate 'm' bit circuits from Step 1.
//      After the Joins, there will be a total of 'l' "lookahead block" circuits:
//         i) For the least-significant block, there are 2*m inputs:
//            (x_0, x_1, ..., x_m-1, y_0, y_1, ..., y_m-1) and 2m+1 output bits:
//            (s_0, s_1, ..., s_m-1, c_0), where s_i are the 'sum' bits and
//            'c_0' is the final 'carry' bit.
//        ii) For all 'internal' blocks (not the least significant nor most significant),
//            there are (2*m + 1) inputs:
//            (x_i*m, x_i*m+1, ..., x_(i+1)*m-1, y_i*m, ..., y_(i+1)*m-1, c_i)
//            and 2m+1 output bits: (s_i*m, ..., s_(i+1)*m-1, c_i)
//       iii) For the most-significant block, there are (2*m + 1) inputs
//            (the same inputs as in (ii)), and 2m output bits
//            (same outputs as (ii), but no final carry bit)
//    3) For all circuits in (2) *except* for (2.i) (the block of least-significant bits):
//         i) Join the circuit with the circuit in (0.i), so that the output
//            wire of (0.i) leads to the input wire corresponding to the
//            carry bit wire c_i.
//        ii) Ditto, except use (0.ii) instead of (0.i) in the Join.
//    4) For all of the circuits from Step 3 (there are 2*(l-1) of them), Merge
//       them with the circuit from Step 0.iii (resp. 0.iv) via the AND operator.
//       Namely:
//         i) For each circuit from (3.i), all of its output wires (there are
//            (2m+1) of them, or 2m of them for the very last block) are
//            AND'ed with the single output wire of circuit (0.iii).
//        ii) For each circuit from (3.ii), all of its output wires (there are
//            (2m+1) of them, or 2m of them for the very last block) are
//            AND'ed with the single output wire of circuit (0.iv).
//    5) Merge the circuits from Step 4.i with the circuits from 4.ii via XOR.
//       Namely, all output wires from a circuit in 4.i are XORed with the
//       corresponding wire of the corresponding circuit in 4.ii.
//    6) Recursively hook up all circuits, by using the carry-bit from the
//       previous block as the inputs 'w' and 'z' of the next block. Namely:
//         i) Hook-up the circuit from Step 2.i with the first circuit in Step 5:
//              a) Join circuit 2.i with circuit 0.v: The carry-bit output
//                 from circuit 2.i feeds the single input wire of circuit 0.v.
//              b) Join circuit 6.i.a with (the first) circuit from Step 5:
//                 The circuit from Step 6.i.a has 2*m + 2 outputs: the
//                 2*m sum bits and the carry-bit and its opposite.
//                 Have those final two outputs (carry-bit and its opposite)
//                 feed the input wires of the (first) circuit of Step 5
//                 that correspond to the 'w' and 'z' input wires.
//        ii) (Recursive). Ditto Step 6.i, except that instead of Joining together
//            circuits 2.i with the (first) circuit in Step 5, we use for the first
//            input to Join the circuit generated by (the previous iteration)
//            of Step 6, and for the second input to Join we use the corresponding
//            circuit of Step 5.
bool ConstructLookaheadAddCircuit(
    const DataType target_type,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_input_bits,
    const uint64_t num_lookahead_blocks,
    StandardCircuit<bool>* a_plus_b) {
  if (num_lookahead_blocks * num_lookahead_blocks > num_input_bits) {
    LOG_FATAL(
        "Bad input to ConstructLookaheadAddCircuit(); this should never happen.");
  }
  const uint64_t m = num_input_bits / num_lookahead_blocks;
  const uint64_t first_m = m + (num_input_bits % num_lookahead_blocks);

  // Do Step 0: Construct the 5 indicated circuits.
  StandardCircuit<bool> zero;  // Circuit 0.i
  StandardCircuit<bool> one;  // Circuit 0.ii
  StandardCircuit<bool> left_id;  // Circuit 0.iii
  StandardCircuit<bool> right_id;  // Circuit 0.iv
  StandardCircuit<bool> id_and_not;  // Circuit 0.v
  ConstructConstantCircuit(false, &zero);
  ConstructConstantCircuit(true, &one);
  // Relabel input-wires for 'left_id' and 'right_id', to make sure they
  // can be uniquely identified. To do this, we'll set the input wire label
  // for the 'left_id' circuit to be (P0, d+1, 0); and for the 'right_id'
  // circuit to be (P0, d+2, 0), where we artificially just assign "Party 0"
  // as the party providing the input, and make sure the input index is
  // unique by using index 'd+1' for left_id and 'd+2' for right_id, where
  // d := 1 + max(value_one_input_index, value_two_input_index)
  // (The reason we don't use 'd' and 'd+1' is because 'd' is already used
  // as the input wire index (for the carry-bit from the previous bits)).
  const uint64_t d =
      (value_one_party_index == 0 ? 1 + value_one_input_index : 0) +
      (value_two_party_index == 0 ? 1 + value_two_input_index : 0);
  const uint64_t left_id_input_index = d + 1;
  const uint64_t right_id_input_index = d + 2;
  StandardCircuit<bool> left_id_tmp;
  StandardCircuit<bool> right_id_tmp;
  ConstructSingleBitIdentityCircuit(false, 0, left_id_input_index, &left_id_tmp);
  ConstructSingleBitIdentityCircuit(
      false, 0, right_id_input_index, &right_id_tmp);
  // It will be more convenient to have the 'w' and 'z' idenity circuits
  // (from Step 0.iii and 0.iv) to have many output wires, so that they
  // can be directly used in Merge (by having a matching number of output
  // wires as the circuit they are to be merged with). For all blocks except
  // the last, we'll be ANDing together m+1 wires (for the last block we'll be
  // ANDing together m wires; i.e. no AND of the (non-existent) carry-bit wire).
  StandardCircuit<bool> left_id_last;
  StandardCircuit<bool> right_id_last;
  DuplicateOutputs(left_id_tmp, m + 1, &left_id);
  DuplicateOutputs(left_id_tmp, m, &left_id_last);
  DuplicateOutputs(right_id_tmp, m + 1, &right_id);
  DuplicateOutputs(right_id_tmp, m, &right_id_last);
  StandardCircuit<bool> id_circuit;
  StandardCircuit<bool> not_circuit;
  ConstructSingleBitIdentityCircuit(false, &id_circuit);
  ConstructSingleBitNotCircuit(false, &not_circuit);
  MergeCircuits(
      true, BooleanOperation::IDENTITY, not_circuit, id_circuit, &id_and_not);

  // Do Step 1: Construct the 'bit' addition circuits (note that because inputs
  // are in 2's complement, all bits are just added; i.e. no need to do anything
  // special with the leading bit).
  // Loop through bits (starting at the least significant).
  vector<StandardCircuit<bool>> add_subcircuits(num_input_bits);
  for (uint64_t bit_index = 0; bit_index < num_input_bits; ++bit_index) {
    if (!ConstructAddBitSubcircuit(
            bit_index != num_input_bits - 1,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index,
            &add_subcircuits[bit_index])) {
      LOG_ERROR(
          "Failed to create Addition Subcircuit at bit index " +
          Itoa(bit_index));
      return false;
    }
    // Overwrite input types, which were determined via 'bit_index'
    // instead of 'num_input_bits'.
    const size_t num_one_expected_inputs =
        (value_one_party_index == value_two_party_index ? 2 : 1) +
        ((value_one_party_index == 0 && bit_index != 0) ? 1 : 0);
    const size_t num_two_expected_inputs =
        (value_one_party_index == value_two_party_index ? 2 : 1) +
        ((value_two_party_index == 0 && bit_index != 0) ? 1 : 0);
    if (add_subcircuits[bit_index].input_types_[value_one_party_index].size() !=
            num_one_expected_inputs ||
        add_subcircuits[bit_index].input_types_[value_two_party_index].size() !=
            num_two_expected_inputs) {
      LOG_ERROR(
          "Unexpected input_types_ size for bit index: " + Itoa(bit_index));
      return false;
    }
    add_subcircuits[bit_index].input_types_[value_one_party_index][0] =
        make_pair("P" + Itoa(value_one_party_index) + "_0", target_type);
    if (value_one_party_index == value_two_party_index) {
      add_subcircuits[bit_index].input_types_[value_one_party_index][1] =
          make_pair("P" + Itoa(value_one_party_index) + "_1", target_type);
    } else {
      add_subcircuits[bit_index].input_types_[value_two_party_index][0] =
          make_pair("P" + Itoa(value_two_party_index) + "_0", target_type);
    }
  }

  // Do Step 2: Within each block, join the 'add-bit' subcircuits.
  //  Note on how to hook-up the sub-circuits in each block:
  //    - add_subcircuits[0] (used as circuit 'one' for when bit_index = 0 in
  //      loop below) has output gates:
  //        0: sum_bit_0
  //        1: carry_bit_0
  //    - joined_circuits (used as circuit 'one' for when bit_index > 0 in
  //      loop below) has output gates:
  //        0: sum_bit_0
  //        1: sum_bit_1
  //        ...
  //        b: sum_bit_b
  //      b+1: carry_bit_b
  //    - add_subcircuits (used as circuit 'two' in loop below) has input mapping:
  //        Wire A: (value_one_party_index, value_one_input_index, bit_index)
  //        Wire B: (value_two_party_index, value_two_input_index, bit_index)
  //      And for all add_subcircuits except the first one (which has no input
  //      for carry bit):
  //        Wire C: (x, d, 0)
  //      where d = 1 + max(value_one_input_index, value_two_input_index)
  vector<StandardCircuit<bool>> lookahead_blocks(num_lookahead_blocks);
  uint64_t num_bits_done = 0;
  for (uint64_t i = 0; i < num_lookahead_blocks; ++i) {
    const uint64_t num_bits_to_do = i == 0 ? first_m : m;
    if (num_bits_to_do < 2) {
      lookahead_blocks[i] = add_subcircuits[num_bits_done];
      ++num_bits_done;
      continue;
    }
    vector<StandardCircuit<bool>> temp_blocks(num_bits_to_do - 2);
    for (uint64_t bit_index = num_bits_done;
         bit_index < num_bits_done + num_bits_to_do - 1;
         ++bit_index) {
      map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
      set<pair<int, pair<uint64_t, uint64_t>>>* sum_output_to_input_wire =
          FindOrInsert(
              (int64_t) (bit_index - num_bits_done + 1),
              output_to_input,
              set<pair<int, pair<uint64_t, uint64_t>>>());
      sum_output_to_input_wire->insert(make_pair(0, make_pair(d, 0)));
      if (!JoinCircuits(
              true,
              false,
              output_to_input,
              (bit_index == num_bits_done ?
                   add_subcircuits[bit_index] :
                   temp_blocks[bit_index - num_bits_done - 1]),
              add_subcircuits[bit_index + 1],
              (bit_index == num_bits_done + num_bits_to_do - 2 ?
                   &lookahead_blocks[i] :
                   &temp_blocks[bit_index - num_bits_done]))) {
        LOG_ERROR(
            "Failed to join Addition Subcircuit at bit index " +
            Itoa(bit_index));
        return false;
      }
    }
    num_bits_done += num_bits_to_do;
  }

  // At the end of the above loop, lookahead_blocks circuits look like
  // (in notation below, let l = num_lookahead_blocks and let
  // m = n / l denote the number of bits in each 'lookahead' block):
  //   - lookahead_blocks[0]:
  //     Input wires:
  //        Wire 0:    (value_one_party_index, value_one_input_index, 0)
  //        Wire 1:    (value_two_party_index, value_two_input_index, 0)
  //        Wire 2:    (value_one_party_index, value_one_input_index, 1)
  //        Wire 3:    (value_two_party_index, value_two_input_index, 1)
  //        ...
  //        Wire 2m-2: (value_one_party_index, value_one_input_index, m - 1)
  //        Wire 2m-1: (value_two_party_index, value_two_input_index, m - 1)
  //     Output wires:
  //        0: sum_bit_0
  //        1: sum_bit_1
  //        ...
  //      m-1: sum_bit_m-1
  //        m: carry_bit_m
  //   - lookahead_blocks[i], for 1 <= i < l-1:
  //     Input wires (Notice extra 'carry-bit' input, in contrast to lookahead_blocks[0] above):
  //        Wire 0:    (value_one_party_index, value_one_input_index, i*m)
  //        Wire 1:    (value_two_party_index, value_two_input_index, i*m)
  //        Wire 2:    (value_one_party_index, value_one_input_index, i*m + 1)
  //        Wire 3:    (value_two_party_index, value_two_input_index, i*m + 1)
  //        ...
  //        Wire 2m-2: (value_one_party_index, value_one_input_index, (i+1)m - 1)
  //        Wire 2m-1: (value_two_party_index, value_two_input_index, (i+1)m - 1)
  //        Wire 2m:   (x, d, 0)
  //                   where d = 1 + max(value_one_input_index, value_two_input_index):
  //     Output wires:
  //        0: sum_bit_(i*m)
  //        1: sum_bit_(i*m + 1)
  //        ...
  //      m-1: sum_bit_(i*m + m - 1)
  //        m: carry_bit_(i*m + m)
  //   - lookahead_blocks[l-1]:
  //     Same input wires and output wires as lookahead_blocks[i],
  //     EXCEPT it doesn't have the final output wire (no final carry bit).

  // Do Step 3: Duplicate each lookahead block circuit (except the first),
  // and hook it up with constant '0' (resp. constant '1') circuit.
  vector<StandardCircuit<bool>> lookahead_blocks_w_constant(
      2 * (num_lookahead_blocks - 1));
  for (uint64_t i = 0; i < num_lookahead_blocks - 1; ++i) {
    map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
    set<pair<int, pair<uint64_t, uint64_t>>>* sum_output_to_input_wire =
        FindOrInsert(
            (int64_t) 0,
            output_to_input,
            set<pair<int, pair<uint64_t, uint64_t>>>());
    sum_output_to_input_wire->insert(make_pair(0, make_pair(d, 0)));
    if (!JoinCircuits(
            true,
            false,
            output_to_input,
            zero,
            lookahead_blocks[i + 1],
            &(lookahead_blocks_w_constant[2 * i])) ||
        !JoinCircuits(
            true,
            false,
            output_to_input,
            one,
            lookahead_blocks[i + 1],
            &(lookahead_blocks_w_constant[2 * i + 1]))) {
      LOG_ERROR("Unable to form lookahead_blocks_w_constant circuit " + Itoa(i));
      return false;
    }
  }

  // Do Step 4: Merge (via AND) Step 3 circuits with Step 0.iii (resp. 0.iv) circuits.
  vector<StandardCircuit<bool>> conditional_lookahead_blocks(
      2 * (num_lookahead_blocks - 1));
  for (uint64_t i = 0; i < num_lookahead_blocks - 1; ++i) {
    if (!MergeCircuits(
            true,
            false,
            BooleanOperation::AND,
            (i == num_lookahead_blocks - 2 ? left_id_last : left_id),
            lookahead_blocks_w_constant[2 * i],
            &(conditional_lookahead_blocks[2 * i])) ||
        !MergeCircuits(
            true,
            false,
            BooleanOperation::AND,
            (i == num_lookahead_blocks - 2 ? right_id_last : right_id),
            lookahead_blocks_w_constant[2 * i + 1],
            &(conditional_lookahead_blocks[2 * i + 1]))) {
      LOG_ERROR(
          "Unable to form conditional_lookahead_blocks circuit " + Itoa(i));
      return false;
    }
  }

  // Do Step 5: XOR contiguous circuits in conditional_lookahead_blocks.
  vector<StandardCircuit<bool>> xored_lookahead_blocks(num_lookahead_blocks - 1);
  for (uint64_t i = 0; i < num_lookahead_blocks - 1; ++i) {
    if (!MergeCircuits(
            true,
            false,
            BooleanOperation::XOR,
            conditional_lookahead_blocks[2 * i],
            conditional_lookahead_blocks[2 * i + 1],
            &(xored_lookahead_blocks[i]))) {
      LOG_ERROR("Unable to form xored_lookahead_blocks circuit " + Itoa(i));
      return false;
    }
  }

  // Do Step 6: merge all circuits together.
  // Note: As we build the circuit, the carry bit will always be on output wire
  // S + 1, where S = number of (sum) bits that the cummulative block outputs.
  vector<StandardCircuit<bool>> cummulative_lookahead_blocks(
      num_lookahead_blocks - 2);
  for (uint64_t i = 0; i < num_lookahead_blocks - 1; ++i) {
    // Step 6.a: Join current cummulative_lookahead_blocks with circuit 0.v,
    // so that the carry-bit 'c_i' splits into two bits: (!c_i, c_i).
    const uint64_t num_sum_bits = first_m + i * m;
    map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
    set<pair<int, pair<uint64_t, uint64_t>>>* sum_output_to_input_wire =
        FindOrInsert(
            (int64_t) num_sum_bits,
            output_to_input,
            set<pair<int, pair<uint64_t, uint64_t>>>());
    sum_output_to_input_wire->insert(make_pair(0, make_pair(0, 0)));
    StandardCircuit<bool> tmp_cumm_block;
    if (!JoinCircuits(
            true,
            false,
            output_to_input,
            (i == 0 ? lookahead_blocks[0] : cummulative_lookahead_blocks[i - 1]),
            id_and_not,
            &tmp_cumm_block)) {
      LOG_ERROR("Failed to join Addition Subcircuit at bit index " + Itoa(i));
      return false;
    }

    // Step 6.b: Join tmp_cumm_block with corresponding Step 5 circuit.
    output_to_input.clear();
    sum_output_to_input_wire = FindOrInsert(
        (int64_t) num_sum_bits,
        output_to_input,
        set<pair<int, pair<uint64_t, uint64_t>>>());
    sum_output_to_input_wire->insert(
        make_pair(0, make_pair(left_id_input_index, 0)));
    sum_output_to_input_wire = FindOrInsert(
        (int64_t) num_sum_bits + 1,
        output_to_input,
        set<pair<int, pair<uint64_t, uint64_t>>>());
    sum_output_to_input_wire->insert(
        make_pair(0, make_pair(right_id_input_index, 0)));
    if (!JoinCircuits(
            true,
            false,
            output_to_input,
            tmp_cumm_block,
            xored_lookahead_blocks[i],
            (i == num_lookahead_blocks - 2 ?
                 a_plus_b :
                 &(cummulative_lookahead_blocks[i])))) {
      LOG_ERROR("Failed to join Addition Subcircuit at bit index " + Itoa(i));
      return false;
    }
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  a_plus_b->num_outputs_ = 1;
  a_plus_b->output_designations_.clear();
  a_plus_b->output_designations_.resize(
      1, make_pair(OutputRecipient(), target_type));
  a_plus_b->function_description_.clear();
  a_plus_b->function_description_.resize(1);
  Formula& formula = a_plus_b->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::ADD;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

bool ConstructAddCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* a_plus_b) {
  if (num_one_input_bits <= 1 && one_is_twos_complement)
    LOG_FATAL("Fatal Error.");
  if (num_two_input_bits <= 1 && two_is_twos_complement)
    LOG_FATAL("Fatal Error.");

  // First, handle the case that the two inputs have different DataType sizes:
  // Take the smaller input, and expand it out by either 0-padding (if it
  // is an unsigned type), or copying the leading (2's complement) bit (if signed type)
  if (num_one_input_bits != num_two_input_bits) {
    const int num_max_bits = (int) max(num_one_input_bits, num_two_input_bits);
    // Construct an ADD circuit, assuming the smaller input has already
    // been expanded.
    StandardCircuit<bool> circuit_of_equal_bits;
    if (!ConstructAddCircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            0,
            0,
            1,
            0,
            num_max_bits,
            num_max_bits,
            &circuit_of_equal_bits)) {
      LOG_ERROR("Failed to ConstructAddCircuit");
      return false;
    }

    // Construct identity circuits for the two inputs.
    // First, construct an identity circuit for the second input.
    StandardCircuit<bool> input_one;
    if (!ConstructIdentityCircuit(
            false,
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            num_one_input_bits,
            &input_one)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_one's fields.
    input_one.num_outputs_ = 1;
    DataType output_one_type;
    if (!GetIntegerDataType(true, (int) num_one_input_bits, &output_one_type)) {
      return false;
    }
    input_one.output_designations_.clear();
    input_one.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_one_type));
    input_one.function_description_.clear();
    input_one.function_description_.resize(1);
    Formula& formula = input_one.function_description_[0];
    formula.op_.type_ = OperationType::BOOLEAN;
    formula.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str =
        "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
    formula.value_ = GenericValue(var_str);
    // Now construct an identity circuit for the second input.
    StandardCircuit<bool> input_two;
    if (!ConstructIdentityCircuit(
            false,
            two_is_twos_complement,
            value_two_party_index,
            value_two_input_index,
            num_two_input_bits,
            &input_two)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_two's fields.
    input_two.num_outputs_ = 1;
    DataType output_two_type;
    if (!GetIntegerDataType(true, (int) num_two_input_bits, &output_two_type)) {
      return false;
    }
    input_two.output_designations_.clear();
    input_two.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_two_type));
    input_two.function_description_.clear();
    input_two.function_description_.resize(1);
    Formula& formula_two = input_two.function_description_[0];
    formula_two.op_.type_ = OperationType::BOOLEAN;
    formula_two.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str_two =
        "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
    formula_two.value_ = GenericValue(var_str_two);

    // Expand the smaller input to the equivalent representation using
    // the bigger datatype (e.g. -2 = 10 (INT2) -> 1110 (INT4)).
    if (num_one_input_bits < num_two_input_bits) {
      if (!CastCircuitOutputAsMoreBits(
              one_is_twos_complement, (int) num_max_bits, &input_one)) {
        return false;
      }

      // Join expanded first input and second input with GT circuit.
      return JoinCircuits(input_one, input_two, circuit_of_equal_bits, a_plus_b);
    } else {
      if (!CastCircuitOutputAsMoreBits(
              two_is_twos_complement, (int) num_max_bits, &input_two)) {
        return false;
      }

      // Join expanded first input and second input with GT circuit.
      return JoinCircuits(input_one, input_two, circuit_of_equal_bits, a_plus_b);
    }
  }

  // That we reached here means num_one_input_bits == num_two_input_bits.
  if (num_one_input_bits != num_two_input_bits) LOG_FATAL("Fatal Error.");
  if (num_one_input_bits <= 0) LOG_FATAL("Fatal Error.");
  // Special handling for 1-bit inputs.
  if (num_one_input_bits == 1) {
    // Technically, if two bools are added, this should be done in Z_2, so that
    // e.g. 1 + 1 = 0. However, this is likely *not* what the user intended
    // (otherwise, user would have written (x XOR y), not (x + y)).
    // In general, we don't modify the output type
    // of Addition/Subtraction operation (with the possible exception of
    // changing the output type from Unsigned to Signed if the operation
    // is SUB and/or one of the inputs is Unsigned). However, a common use-case
    // may be to add BOOLs together (e.g. for Hamming Distance).
    // So in the case of ADD on two BOOLs, we cast the output DataType as UINT16
    // (we chose UINT16 somewhat arbitrarily: Unsigned makes sense, since inputs
    // are unsigned (BOOL); and 16-bits seems like it is a nice trade-off of
    // not being too big (in terms of resulting circuit size), and yet big
    // enough to hold the output of any actual computation (i.e. it is unlikely
    // that the user will enter an expression that adds more than 2^16 BOOLs, but
    // a user might want to add more than the next smallest possibility, 2^8 = 256).
    // First, create a circuit for adding the two bools. We can't use XOR,
    // because this will yield 1 + 1 = 0. We could do ADD for UINT16 (since
    // that's the final output type we'll cast to), but this adds extra
    // complexity to the circuit: the inputs are BOOLs afterall, so we're
    // wasting gates/computations on all the leading bits, which are 0.
    // So, we'll cast the inputs first as UINT2, and then update the output
    // type from UINT2 to UINT16.
    // First, expand the one bit inputs into 2 bits: the trailing bit will
    // be the input bit, the other will be constant zero.
    StandardCircuit<bool> input_one, input_two;
    if (!ConstructIdentityCircuit(
            value_one_party_index,
            value_one_input_index,
            DataType::BOOL,
            &input_one) ||
        !ConstructIdentityCircuit(
            value_two_party_index,
            value_two_input_index,
            DataType::BOOL,
            &input_two)) {
      LOG_ERROR("Failed to construct id circuits.");
      return false;
    }
    // For these to output 2 bits.
    if (!CastCircuitOutputAsMoreBits(false, 2, &input_one) ||
        !CastCircuitOutputAsMoreBits(false, 2, &input_two)) {
      return false;
    }

    // Construct a generic addition circuit for two UINT2 values.
    StandardCircuit<bool> two_bit_sum;
    if (!ConstructAddCircuit(false, false, 0, 0, 1, 0, 2, 2, &two_bit_sum)) {
      LOG_ERROR("Unable to add two 2-bit values.");
      return false;
    }

    // Overwrite output type: UINT2 -> UINT16.
    if (!CastCircuitOutputAsMoreBits(false, 16, &two_bit_sum)) {
      return false;
    }

    // Join.
    if (!JoinCircuits(input_one, input_two, two_bit_sum, a_plus_b)) {
      LOG_ERROR("Unable to build final boolean sum circuit.");
      return false;
    }

    return true;
  }

  // Grab the final output data type, based on number of bits and signed/unsigned.
  DataType target_type;
  if (!GetIntegerDataType(
          one_is_twos_complement || two_is_twos_complement,
          (int) num_one_input_bits,
          &target_type)) {
    LOG_ERROR("Failed to get integer data type.");
    return false;
  }

  // Do ``lookahead'' addition, if appropriate.
  if (kAdditionLookaheadBlocks > 1) {
    // Determine the number of ``lookahead'' blocks to use.
    const int sqrt_n = (int) sqrt(num_one_input_bits);
    const int num_lookahead_blocks =
        kAdditionLookaheadBlocks <= sqrt_n ? kAdditionLookaheadBlocks : sqrt_n;
    if (num_lookahead_blocks > 1) {
      return ConstructLookaheadAddCircuit(
          target_type,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_lookahead_blocks,
          a_plus_b);
    }
  }

  // Standard (no lookahead) addition.

  // First, create an Addition circuit for each bit (because inputs are in
  // 2's complement, all bits are just added; i.e. no need to do anything
  // special with the leading bit).
  // Loop through bits (starting at the least significant).
  vector<StandardCircuit<bool>> add_subcircuits(num_one_input_bits);
  for (uint64_t bit_index = 0; bit_index < num_one_input_bits; ++bit_index) {
    if (!ConstructAddBitSubcircuit(
            bit_index != num_one_input_bits - 1,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index,
            &add_subcircuits[bit_index])) {
      LOG_ERROR(
          "Failed to create Addition Subcircuit at bit index " +
          Itoa(bit_index));
      return false;
    }
    // Overwrite input types, which were determined via 'bit_index'
    // instead of 'num_one_input_bits'.
    const size_t num_one_expected_inputs =
        (value_one_party_index == value_two_party_index ? 2 : 1) +
        ((value_one_party_index == 0 && bit_index != 0) ? 1 : 0);
    const size_t num_two_expected_inputs =
        (value_one_party_index == value_two_party_index ? 2 : 1) +
        ((value_two_party_index == 0 && bit_index != 0) ? 1 : 0);
    if (add_subcircuits[bit_index].input_types_[value_one_party_index].size() !=
            num_one_expected_inputs ||
        add_subcircuits[bit_index].input_types_[value_two_party_index].size() !=
            num_two_expected_inputs) {
      LOG_ERROR(
          "Unexpected input_types_ size for bit index: " + Itoa(bit_index));
      return false;
    }
    add_subcircuits[bit_index].input_types_[value_one_party_index][0] =
        make_pair("P" + Itoa(value_one_party_index) + "_0", target_type);
    if (value_one_party_index == value_two_party_index) {
      add_subcircuits[bit_index].input_types_[value_one_party_index][1] =
          make_pair("P" + Itoa(value_one_party_index) + "_1", target_type);
    } else {
      add_subcircuits[bit_index].input_types_[value_two_party_index][0] =
          make_pair("P" + Itoa(value_two_party_index) + "_0", target_type);
    }
  }

  // Join the add_subcircuits.
  vector<StandardCircuit<bool>> joined_circuits(num_one_input_bits - 2);
  //  Note on how to hook these circuits up:
  //    - add_subcircuits (used as circuit 'one' for when bit_index = 0 in
  //      loop below) has output gates:
  //        0: sum_bit_0
  //        1: carry_bit_0
  //    - joined_circuits (used as circuit 'one' for when bit_index > 0 in
  //      loop below) has output gates:
  //        0: sum_bit_0
  //        1: sum_bit_1
  //        ...
  //        b: sum_bit_b
  //      b+1: carry_bit_b
  //    - add_subcircuits (used as circuit 'two' in loop below) has input mapping:
  //        Wire A: (value_one_party_index, value_one_input_index, bit_index)
  //        Wire B: (value_two_party_index, value_two_input_index, bit_index)
  //      And for all add_subcircuits except the first one (which has no input
  //      for carry bit):
  //        Wire C: (x, d, 0)
  //      where d = 1 + max(value_one_input_index, value_two_input_index):
  const uint64_t d =
      (value_one_party_index == 0 ? 1 + value_one_input_index : 0) +
      (value_two_party_index == 0 ? 1 + value_two_input_index : 0);
  for (uint64_t bit_index = 0; bit_index < num_one_input_bits - 1; ++bit_index) {
    map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
    set<pair<int, pair<uint64_t, uint64_t>>>* sum_output_to_input_wire =
        FindOrInsert(
            (int64_t) bit_index + 1,
            output_to_input,
            set<pair<int, pair<uint64_t, uint64_t>>>());
    sum_output_to_input_wire->insert(make_pair(0, make_pair(d, 0)));
    if (!JoinCircuits(
            true,
            false,
            output_to_input,
            (bit_index == 0 ? add_subcircuits[0] :
                              joined_circuits[bit_index - 1]),
            add_subcircuits[bit_index + 1],
            (bit_index == num_one_input_bits - 2 ?
                 a_plus_b :
                 &joined_circuits[bit_index]))) {
      LOG_ERROR(
          "Failed to join Addition Subcircuit at bit index " + Itoa(bit_index));
      return false;
    }
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  a_plus_b->num_outputs_ = 1;
  a_plus_b->output_designations_.clear();
  a_plus_b->output_designations_.resize(
      1, make_pair(OutputRecipient(), target_type));
  a_plus_b->function_description_.clear();
  a_plus_b->function_description_.resize(1);
  Formula& formula = a_plus_b->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::ADD;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

// Constructs the single-bit subtraction, with no borrow (for highest bit) circuit:
//   - 3 inputs: 2 actual inputs, plus borrow bit (from previous bit's output)
//   - 1 output: 1 actual output (difference)
/* Diagram:
                                       ____
                                      |    \
  A --------------------------------- | XOR \ ______  Difference
                                  ___ |     /
                                 /    |____/
                                /
                               /
                              /
                             /
                 ____       / 
         ______ |    \     /
        /       | XOR \ __/
       /     __ |     /
  B __/     /   |____/
           /
          /
         /
        /
       /
  C __/
*/
bool ConstructSubtractLastBitSubcircuit(
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  const uint64_t dummy_input_index =
      max(value_one_input_index, value_two_input_index) + 1;

  // Create the B XOR C circuit:
  /*
                             ____
                     ______ |    \
                    /       | XOR \ __
                   /     __ |     /
  B = (v, j, b) __/     /   |____/
                       /
                      /
                     /
                    / 
                   /   
  C = (x, d, 0) __/
                  
  */
  StandardCircuit<bool> b_xor_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_two_party_index,
          0,
          value_two_input_index,
          bit_index,
          dummy_input_index,
          0,
          BooleanOperation::XOR,
          &b_xor_c)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit XOR circuit");
    return false;
  }

  // Create the Sum XOR circuit: A XOR (B XOR C):
  /*
                                     ____
                                    |    \
  A = (u, i, b) ------------------- | XOR \
                                 __ |     /
                                /   |____/
                               /
                              /
                             /
  (B XOR C) = (y, 0, 0) ____/
  */
  StandardCircuit<bool> a_xor_b_xor_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_one_party_index,
          1,
          value_one_input_index,
          bit_index,
          0,
          0,
          BooleanOperation::XOR,
          &a_xor_b_xor_c)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit XOR circuit");
    return false;
  }

  // Join Circuits.
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  //     Note on how to hook these circuits up:
  //       - b_xor_c has output gate:
  //           0: B XOR C
  //       - a_xor_b_xor_c has input mapping:
  //           XOR Gate:
  //             Left Wire:  (u, i, b)
  //             Right Wire: (y, 0, 0)
  set<pair<int, pair<uint64_t, uint64_t>>>* xor_output_to_input_wire =
      FindOrInsert(
          (int64_t) 0,
          output_to_input,
          set<pair<int, pair<uint64_t, uint64_t>>>());
  xor_output_to_input_wire->insert(make_pair(1, make_pair(0, 0)));
  StandardCircuit<bool> joined_second_level;
  if (!JoinCircuits(output_to_input, b_xor_c, a_xor_b_xor_c, output)) {
    LOG_ERROR("Unable to join first and second levels.");
    return false;
  }

  return true;
}

/* Diagram
                                      ____
                                     |    \
  A -------------------------------- | XOR \ ______  Difference
                        \        ___ |     /
                         \      /    |____/
                          \    /
                           \  /
                            \/
                            /\
                           /  \
                          /    \     ____
                         /      \__ |    \
                        /           | LT  \ _________  Borrow
  B ___________________/___________ |     /   
                                    |____/     
*/
bool ConstructSubtractFirstBitSubcircuit(
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  /*
                                      ____
                                     |    \
  A -------------------------------- | XOR \ ______  Difference
                                 ___ |     /
                                /    |____/
                               /
                              /
                             /
                            /
                           /
                          /
                         /
                        /
  B ___________________/
  */
  StandardCircuit<bool> a_xor_b;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_one_party_index,
          value_two_party_index,
          value_one_input_index,
          bit_index,
          value_two_input_index,
          bit_index,
          BooleanOperation::XOR,
          &a_xor_b)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit XOR circuit");
    return false;
  }

  // Create the A < B circuit:
  /*

  A --------------------
                        \
                         \
                          \
                           \
                            \
                             \
                              \
                               \     ____
                                \__ |    \
                                    | LT  \ _________  Borrow
  B _______________________________ |     /   
                                    |____/     
  */
  StandardCircuit<bool> a_lt_b;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_one_party_index,
          value_two_party_index,
          value_one_input_index,
          bit_index,
          value_two_input_index,
          bit_index,
          BooleanOperation::LT,
          &a_lt_b)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit LT circuit");
    return false;
  }
  /*
                                      ____
                                     |    \
  A -------------------------------- | XOR \ ______  Difference
                        \        ___ |     /
                         \      /    |____/
                          \    /
                           \  /
                            \/
                            /\
                           /  \
                          /    \     ____
                         /      \__ |    \
                        /           | LT  \ _________  Borrow
  B ___________________/___________ |     /   
                                    |____/     
  */
  if (!MergeCircuits(
          true, BooleanOperation::IDENTITY, a_xor_b, a_lt_b, output)) {
    LOG_ERROR("Unable to create trivial (bit-zero) Add Subcircuit.");
    return false;
  }

  return true;
}

/* Diagram
                                      ____
                                     |    \
  A -------------------------------- | XOR \ ______  Difference
                                 ___ |     /
                                /    |____/
                               /
                              /
                             /
                            /
                           /
                          /
                         /
                        /
  B ___________________/
*/
bool ConstructSubtractFirstAndLastBitSubcircuit(
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  return ConstructBitComparisonCircuit(
      false,
      false,
      value_one_party_index,
      value_two_party_index,
      value_one_input_index,
      bit_index,
      value_two_input_index,
      bit_index,
      BooleanOperation::XOR,
      output);
}

// Constructs the single-bit subtraction (A-B, w/ C previous carry) circuit:
//   - 3 inputs: 2 actual inputs ('A' and 'B'), plus a borrow input 'C'
//   - 2 outputs: 1 actual output (difference), plus a borrow output.
/* Diagram:
                                   ____
                                  |    \
  A ----------------------------- | XOR \ ______  Difference
                        \      __ |     /
                         \    /   |____/
                          \  /
                 ____      \/ 
         ______ |    \     /\
        /       | XOR \ __/  \     ____
       /     __ |     /   \   \__ |    \
  B __/     /   |____/     \      | LT  \ __
      \    /                \____ |     /   \
       \  /                       |____/     \
        \/                                    \
        /\                                     \
       /  \                                     \     ____
  C __/    \     ____                            \__ |    \
      \     \__ |    \                               | OR  \ _______  Borrow
       \        | AND \ ____________________________ |     /
        \______ |     /                              |____/
                |____/
In diagram above:
   u = value_one_party_index
   v = value_two_party_index
   i = value_one_input_index
   j = value_two_input_index
   b = bit_index
   d = 1 + max(value_one_input_index, value_two_input_index)
*/
bool ConstructSubtractBitWithBorrowSubcircuit(
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  const uint64_t dummy_input_index =
      max(value_one_input_index, value_two_input_index) + 1;

  // Create the B XOR C circuit:
  /*
                             ____
                     ______ |    \
                    /       | XOR \ __
                   /     __ |     /
  B = (v, j, b) __/     /   |____/
                       /
                      /
                     /
                    / 
                   /   
  C = (x, d, 0) __/
                  
  */
  StandardCircuit<bool> b_xor_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_two_party_index,
          0,
          value_two_input_index,
          bit_index,
          dummy_input_index,
          0,
          BooleanOperation::XOR,
          &b_xor_c)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit XOR circuit");
    return false;
  }

  // Create the B AND C circuit:
  /*
  B = (v, k, b) __
                  \
                   \
                    \
                     \
                      \
  C = (x, d, 0) __     \     ____
                  \     \__ |    \
                   \        | AND \ __
                    \______ |     /
                            |____/
  */
  StandardCircuit<bool> b_and_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_two_party_index,
          0,
          value_two_input_index,
          bit_index,
          dummy_input_index,
          0,
          BooleanOperation::AND,
          &b_and_c)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit AND circuit");
    return false;
  }

  // Create the Difference XOR circuit: A XOR (B XOR C):
  /*
                                     ____
                                    |    \
  A = (u, i, b) ------------------- | XOR \
                                 __ |     /
                                /   |____/
                               /
                              /
                             /
  (B XOR C) = (y, 0, 0) ____/
  */
  StandardCircuit<bool> a_xor_b_xor_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_one_party_index,
          1,
          value_one_input_index,
          bit_index,
          0,
          0,
          BooleanOperation::XOR,
          &a_xor_b_xor_c)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit XOR circuit");
    return false;
  }

  // Create the Borrow LT circuit: A < (B XOR C):
  /*

  A = (u, i, b) ---------
                          \
                           \
                            \
                             \
                              \
  (B XOR C) = (y, 0, 0)  ___   \     ____
                            \   \__ |    \
                             \      | LT  \ __
                              \____ |     /
                                    |____/
  */
  StandardCircuit<bool> a_lt_b_xor_c;
  if (!ConstructBitComparisonCircuit(
          false,
          false,
          value_one_party_index,
          1,
          value_one_input_index,
          bit_index,
          0,
          0,
          BooleanOperation::LT,
          &a_lt_b_xor_c)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit AND circuit");
    return false;
  }

  // Create the Borrow OR circuit: (A < (B XOR C)) OR (B AND C):
  /*

    (A < (B XOR C)) = (x, 0, 0) ___________
                                              \
                                               \
                                                \
                                                 \
                                                  \     ____
                                                   \__ |    \
                                                       | OR  \ _______  Borrow
    (B AND C) = (y, 0, 0) ____________________________ |     /
                                                       |____/
  */
  StandardCircuit<bool> final_borrow;
  if (!ConstructBitComparisonCircuit(
          false, BooleanOperation::OR, &final_borrow)) {
    LOG_ERROR("Unable to construct Subtraction Subcircuit Borrow circuit");
    return false;
  }

  // Now, combine circuits.
  //   1) Merge (B XOR C) and (B AND C) circuits:
  /*
                            ____
                    ______ |    \
                   /       | XOR \ __ Output Wire 0
                  /     __ |     /   
 B = (v, j, b) __/     /   |____/
                 \    /
                  \  /
                   \/
                   /\
                  /  \
 C = (x, d, 0) __/    \     ____
                 \     \__ |    \
                  \        | AND \ __ Output Wire 1
                   \______ |     /
                           |____/
  */
  StandardCircuit<bool> first_level;
  if (!MergeCircuits(
          true,
          // The following indicates not to actually merge the two above
          // circuits via an Operation, but rather just but them "side-by-side".
          BooleanOperation::IDENTITY,
          b_xor_c,
          b_and_c,
          &first_level)) {
    LOG_ERROR("Unable to merge first level circuit.");
    return false;
  }

  //  2) Create second-level circuit, by merging a_xor_b_xor_c and a_lt_b_xor_c.
  /* Diagram:
                                     ____
                                    |    \
 A = (u, i , b) ------------------- | XOR \ ______ Output Wire 0
                          \      __ |     /
                           \    /   |____/
                            \  /
                             \/
                             /\
 (B XOR C) = (y, 0, 0) _____/  \     ____
                            \   \__ |    \
                             \      | LT  \ ______ Output Wire 1
                              \____ |     /
                                    |____/
  */
  StandardCircuit<bool> second_level;
  if (!MergeCircuits(
          true,
          // The following indicates not to actually merge the two above
          // circuits via an Operation, but rather just but them "side-by-side".
          BooleanOperation::IDENTITY,
          a_xor_b_xor_c,
          a_lt_b_xor_c,
          &second_level)) {
    LOG_ERROR("Unable to merge first level circuit.");
    return false;
  }

  //  3) Join first_level circuit with second_level circuit.
  /* Diagram:
                                               ____
                                              |    \
  A = (u, i, b) ----------------------------- | XOR \ ______ Output Wire 1
                                    \      __ |     /
                                     \    /   |____/
                                      \  /
                             ____      \/
                     ______ |    \     /\
                    /       | XOR \ __/  \     ____
                   /     __ |     /   \   \__ |    \
  B = (v, j, b) __/     /   |____/     \      | LT  \ ______ Output Wire 2
                  \    /                \____ |     /
                   \  /                       |____/
                    \/                                    
                    /\
                   /  \
  C = (x, d, 0) __/    \     ____
                  \     \__ |    \
                   \        | AND \ ________________________ Output Wire 0
                    \______ |     /
                            |____/
  */
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  //     Note on how to hook these circuits up:
  //       - first_level has output gates:
  //           0: B XOR C
  //           1: B AND C
  //       - second_level has input mapping (where 'd' denotes dummy_input_index):
  //           XOR Gate:
  //             Left Wire:  (u, i, b)
  //             Right Wire: (y, 0, 0)
  //           LT Gate:
  //             Left Wire:  (u, i, b)
  //             Right Wire: (y, 0, 0)
  set<pair<int, pair<uint64_t, uint64_t>>>* xor_output_to_input_wire =
      FindOrInsert(
          (int64_t) 0,
          output_to_input,
          set<pair<int, pair<uint64_t, uint64_t>>>());
  xor_output_to_input_wire->insert(make_pair(1, make_pair(0, 0)));
  StandardCircuit<bool> joined_second_level;
  if (!JoinCircuits(
          output_to_input, first_level, second_level, &joined_second_level)) {
    LOG_ERROR("Unable to join first and second levels.");
    return false;
  }

  //  4) Join circuits:
  //       'one':  joined_second_level
  //       'two':   final_borrow
  //     Note on how to hook these circuits up:
  //       - joined_second_level has output gates:
  //           0: B AND C
  //           1: A XOR (B XOR C)
  //           2: A < (B XOR C)
  //       - final_borrow has input mapping (where 'd' denotes dummy_input_index):
  //           OR Gate:
  //             Left Wire:  (x, 0, 0)
  //             Right Wire: (y, 0, 0)
  //
  /* Diagram:
                                               ____
                                              |    \
  A = (u, i, b) ----------------------------- | XOR \ ___________________ Output Wire 0 (Sum)
                                    \      __ |     /
                                     \    /   |____/
                                      \  /
                             ____      \/
                     ______ |    \     /\
                    /       | XOR \ __/  \     ____
                   /     __ |     /   \   \__ |    \
  B = (v, j, b) __/     /   |____/     \      | LT  \ __
                  \    /                \____ |     /   \
                   \  /                       |____/     \
                    \/                                    \
                    /\                                     \
                   /  \                                     \     ___
  C = (x, d, 0) __/    \     ____                            \__ |   \
                  \     \__ |    \                               | OR \_ Output Wire 1 (Borrow)
                   \        | AND \ ____________________________ |    /
                    \______ |     /                              |___/
                            |____/
  */
  output_to_input.clear();
  set<pair<int, pair<uint64_t, uint64_t>>>* output_to_input_wire = FindOrInsert(
      (int64_t) 0, output_to_input, set<pair<int, pair<uint64_t, uint64_t>>>());
  output_to_input_wire->insert(make_pair(1, make_pair(0, 0)));
  output_to_input_wire = FindOrInsert(
      (int64_t) 2, output_to_input, set<pair<int, pair<uint64_t, uint64_t>>>());
  output_to_input_wire->insert(make_pair(0, make_pair(0, 0)));
  if (!JoinCircuits(
          output_to_input, joined_second_level, final_borrow, output)) {
    LOG_ERROR("Unable to join second and carry levels.");
    return false;
  }

  return true;
}

bool ConstructSubtractBitSubcircuit(
    const bool output_borrow_bit,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  if (!output_borrow_bit && bit_index == 0) {
    return ConstructSubtractFirstAndLastBitSubcircuit(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        bit_index,
        output);
  } else if (bit_index == 0) {
    return ConstructSubtractFirstBitSubcircuit(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        bit_index,
        output);
  } else if (output_borrow_bit) {
    return ConstructSubtractBitWithBorrowSubcircuit(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        bit_index,
        output);
  } else {
    return ConstructSubtractLastBitSubcircuit(
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        bit_index,
        output);
  }

  // Code will never reach here.
  return false;
}

// Similar/analogous to ConstructLookaheadSubCircuit, but for subtraction.
bool ConstructLookaheadSubCircuit(
    const DataType target_type,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_input_bits,
    const uint64_t num_lookahead_blocks,
    StandardCircuit<bool>* a_minus_b) {
  if (num_lookahead_blocks * num_lookahead_blocks > num_input_bits) {
    LOG_FATAL(
        "Bad input to ConstructLookaheadSubCircuit(); this should never happen.");
  }
  const uint64_t m = num_input_bits / num_lookahead_blocks;
  const uint64_t first_m = m + (num_input_bits % num_lookahead_blocks);

  // Do Step 0: Construct the 5 indicated circuits.
  StandardCircuit<bool> zero;  // Circuit 0.i
  StandardCircuit<bool> one;  // Circuit 0.ii
  StandardCircuit<bool> left_id;  // Circuit 0.iii
  StandardCircuit<bool> right_id;  // Circuit 0.iv
  StandardCircuit<bool> id_and_not;  // Circuit 0.v
  ConstructConstantCircuit(false, &zero);
  ConstructConstantCircuit(true, &one);
  // Relabel input-wires for 'left_id' and 'right_id', to make sure they
  // can be uniquely identified. To do this, we'll set the input wire label
  // for the 'left_id' circuit to be (P0, d+1, 0); and for the 'right_id'
  // circuit to be (P0, d+2, 0), where we artificially just assign "Party 0"
  // as the party providing the input, and make sure the input index is
  // unique by using index 'd+1' for left_id and 'd+2' for right_id, where
  // d := 1 + max(value_one_input_index, value_two_input_index)
  // (The reason we don't use 'd' and 'd+1' is because 'd' is already used
  // as the input wire index (for the borrow-bit from the previous bits)).
  const uint64_t d =
      (value_one_party_index == 0 ? 1 + value_one_input_index : 0) +
      (value_two_party_index == 0 ? 1 + value_two_input_index : 0);
  const uint64_t left_id_input_index = d + 1;
  const uint64_t right_id_input_index = d + 2;
  StandardCircuit<bool> left_id_tmp;
  StandardCircuit<bool> right_id_tmp;
  ConstructSingleBitIdentityCircuit(false, 0, left_id_input_index, &left_id_tmp);
  ConstructSingleBitIdentityCircuit(
      false, 0, right_id_input_index, &right_id_tmp);
  // It will be more convenient to have the 'w' and 'z' idenity circuits
  // (from Step 0.iii and 0.iv) to have many output wires, so that they
  // can be directly used in Merge (by having a matching number of output
  // wires as the circuit they are to be merged with). For all blocks except
  // the last, we'll be ANDing together m+1 wires (for the last block we'll be
  // ANDing together m wires; i.e. no AND of the (non-existent) borrow-bit wire).
  StandardCircuit<bool> left_id_last;
  StandardCircuit<bool> right_id_last;
  DuplicateOutputs(left_id_tmp, m + 1, &left_id);
  DuplicateOutputs(left_id_tmp, m, &left_id_last);
  DuplicateOutputs(right_id_tmp, m + 1, &right_id);
  DuplicateOutputs(right_id_tmp, m, &right_id_last);
  StandardCircuit<bool> id_circuit;
  StandardCircuit<bool> not_circuit;
  ConstructSingleBitIdentityCircuit(false, &id_circuit);
  ConstructSingleBitNotCircuit(false, &not_circuit);
  MergeCircuits(
      true, BooleanOperation::IDENTITY, not_circuit, id_circuit, &id_and_not);

  // Do Step 1: Construct the 'bit' subtraction circuits (note that because inputs
  // are in 2's complement, all bits are just subtracted; i.e. no need to do anything
  // special with the leading bit).
  // Loop through bits (starting at the least significant).
  vector<StandardCircuit<bool>> subtract_subcircuits(num_input_bits);
  for (uint64_t bit_index = 0; bit_index < num_input_bits; ++bit_index) {
    if (!ConstructSubtractBitSubcircuit(
            bit_index != num_input_bits - 1,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index,
            &subtract_subcircuits[bit_index])) {
      LOG_ERROR(
          "Failed to create Subtraction Subcircuit at bit index " +
          Itoa(bit_index));
      return false;
    }
    // Overwrite input types, which were determined via 'bit_index'
    // instead of 'num_input_bits'.
    const size_t num_one_expected_inputs =
        (value_one_party_index == value_two_party_index ? 2 : 1) +
        ((value_one_party_index == 0 && bit_index != 0) ? 1 : 0);
    const size_t num_two_expected_inputs =
        (value_one_party_index == value_two_party_index ? 2 : 1) +
        ((value_two_party_index == 0 && bit_index != 0) ? 1 : 0);
    if (subtract_subcircuits[bit_index]
                .input_types_[value_one_party_index]
                .size() != num_one_expected_inputs ||
        subtract_subcircuits[bit_index]
                .input_types_[value_two_party_index]
                .size() != num_two_expected_inputs) {
      LOG_ERROR(
          "Unexpected input_types_ size for bit index: " + Itoa(bit_index));
      return false;
    }
    subtract_subcircuits[bit_index].input_types_[value_one_party_index][0] =
        make_pair("P" + Itoa(value_one_party_index) + "_0", target_type);
    if (value_one_party_index == value_two_party_index) {
      subtract_subcircuits[bit_index].input_types_[value_one_party_index][1] =
          make_pair("P" + Itoa(value_one_party_index) + "_1", target_type);
    } else {
      subtract_subcircuits[bit_index].input_types_[value_two_party_index][0] =
          make_pair("P" + Itoa(value_two_party_index) + "_0", target_type);
    }
  }

  // Do Step 2: Within each block, join the 'subtract-bit' subcircuits.
  //  Note on how to hook-up the sub-circuits in each block:
  //    - subtract_subcircuits[0] (used as circuit 'one' for when bit_index = 0 in
  //      loop below) has output gates:
  //        0: difference_bit_0
  //        1: borrow_bit_0
  //    - joined_circuits (used as circuit 'one' for when bit_index > 0 in
  //      loop below) has output gates:
  //        0: difference_bit_0
  //        1: difference_bit_1
  //        ...
  //        b: difference_bit_b
  //      b+1: borrow_bit_b
  //    - subtract_subcircuits (used as circuit 'two' in loop below) has input mapping:
  //        Wire A: (value_one_party_index, value_one_input_index, bit_index)
  //        Wire B: (value_two_party_index, value_two_input_index, bit_index)
  //      And for all subtract_subcircuits except the first one (which has no input
  //      for borrow bit):
  //        Wire C: (x, d, 0)
  //      where d = 1 + max(value_one_input_index, value_two_input_index)
  vector<StandardCircuit<bool>> lookahead_blocks(num_lookahead_blocks);
  uint64_t num_bits_done = 0;
  for (uint64_t i = 0; i < num_lookahead_blocks; ++i) {
    const uint64_t num_bits_to_do = i == 0 ? first_m : m;
    if (num_bits_to_do < 2) {
      lookahead_blocks[i] = subtract_subcircuits[num_bits_done];
      ++num_bits_done;
      continue;
    }
    vector<StandardCircuit<bool>> temp_blocks(num_bits_to_do - 2);
    for (uint64_t bit_index = num_bits_done;
         bit_index < num_bits_done + num_bits_to_do - 1;
         ++bit_index) {
      map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
      set<pair<int, pair<uint64_t, uint64_t>>>* difference_output_to_input_wire =
          FindOrInsert(
              (int64_t) (bit_index - num_bits_done + 1),
              output_to_input,
              set<pair<int, pair<uint64_t, uint64_t>>>());
      difference_output_to_input_wire->insert(make_pair(0, make_pair(d, 0)));
      if (!JoinCircuits(
              true,
              false,
              output_to_input,
              (bit_index == num_bits_done ?
                   subtract_subcircuits[bit_index] :
                   temp_blocks[bit_index - num_bits_done - 1]),
              subtract_subcircuits[bit_index + 1],
              (bit_index == num_bits_done + num_bits_to_do - 2 ?
                   &lookahead_blocks[i] :
                   &temp_blocks[bit_index - num_bits_done]))) {
        LOG_ERROR(
            "Failed to join Subtraction Subcircuit at bit index " +
            Itoa(bit_index));
        return false;
      }
    }
    num_bits_done += num_bits_to_do;
  }

  // At the end of the above loop, lookahead_blocks circuits look like
  // (in notation below, let l = num_lookahead_blocks and let
  // m = n / l denote the number of bits in each 'lookahead' block):
  //   - lookahead_blocks[0]:
  //     Input wires:
  //        Wire 0:    (value_one_party_index, value_one_input_index, 0)
  //        Wire 1:    (value_two_party_index, value_two_input_index, 0)
  //        Wire 2:    (value_one_party_index, value_one_input_index, 1)
  //        Wire 3:    (value_two_party_index, value_two_input_index, 1)
  //        ...
  //        Wire 2m-2: (value_one_party_index, value_one_input_index, m - 1)
  //        Wire 2m-1: (value_two_party_index, value_two_input_index, m - 1)
  //     Output wires:
  //        0: difference_bit_0
  //        1: difference_bit_1
  //        ...
  //      m-1: difference_bit_m-1
  //        m: borrow_bit_m
  //   - lookahead_blocks[i], for 1 <= i < l-1:
  //     Input wires (Notice extra 'borrow-bit' input, in contrast to lookahead_blocks[0] above):
  //        Wire 0:    (value_one_party_index, value_one_input_index, i*m)
  //        Wire 1:    (value_two_party_index, value_two_input_index, i*m)
  //        Wire 2:    (value_one_party_index, value_one_input_index, i*m + 1)
  //        Wire 3:    (value_two_party_index, value_two_input_index, i*m + 1)
  //        ...
  //        Wire 2m-2: (value_one_party_index, value_one_input_index, (i+1)m - 1)
  //        Wire 2m-1: (value_two_party_index, value_two_input_index, (i+1)m - 1)
  //        Wire 2m:   (x, d, 0)
  //                   where d = 1 + max(value_one_input_index, value_two_input_index):
  //     Output wires:
  //        0: difference_bit_(i*m)
  //        1: difference_bit_(i*m + 1)
  //        ...
  //      m-1: difference_bit_(i*m + m - 1)
  //        m: borrow_bit_(i*m + m)
  //   - lookahead_blocks[l-1]:
  //     Same input wires and output wires as lookahead_blocks[i],
  //     EXCEPT it doesn't have the final output wire (no final borrow bit).

  // Do Step 3: Duplicate each lookahead block circuit (except the first),
  // and hook it up with constant '0' (resp. constant '1') circuit.
  vector<StandardCircuit<bool>> lookahead_blocks_w_constant(
      2 * (num_lookahead_blocks - 1));
  for (uint64_t i = 0; i < num_lookahead_blocks - 1; ++i) {
    map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
    set<pair<int, pair<uint64_t, uint64_t>>>* difference_output_to_input_wire =
        FindOrInsert(
            (int64_t) 0,
            output_to_input,
            set<pair<int, pair<uint64_t, uint64_t>>>());
    difference_output_to_input_wire->insert(make_pair(0, make_pair(d, 0)));
    if (!JoinCircuits(
            true,
            false,
            output_to_input,
            zero,
            lookahead_blocks[i + 1],
            &(lookahead_blocks_w_constant[2 * i])) ||
        !JoinCircuits(
            true,
            false,
            output_to_input,
            one,
            lookahead_blocks[i + 1],
            &(lookahead_blocks_w_constant[2 * i + 1]))) {
      LOG_ERROR("Unable to form lookahead_blocks_w_constant circuit " + Itoa(i));
      return false;
    }
  }

  // Do Step 4: Merge (via AND) Step 3 circuits with Step 0.iii (resp. 0.iv) circuits.
  vector<StandardCircuit<bool>> conditional_lookahead_blocks(
      2 * (num_lookahead_blocks - 1));
  for (uint64_t i = 0; i < num_lookahead_blocks - 1; ++i) {
    if (!MergeCircuits(
            true,
            false,
            BooleanOperation::AND,
            (i == num_lookahead_blocks - 2 ? left_id_last : left_id),
            lookahead_blocks_w_constant[2 * i],
            &(conditional_lookahead_blocks[2 * i])) ||
        !MergeCircuits(
            true,
            false,
            BooleanOperation::AND,
            (i == num_lookahead_blocks - 2 ? right_id_last : right_id),
            lookahead_blocks_w_constant[2 * i + 1],
            &(conditional_lookahead_blocks[2 * i + 1]))) {
      LOG_ERROR(
          "Unable to form conditional_lookahead_blocks circuit " + Itoa(i));
      return false;
    }
  }

  // Do Step 5: XOR contiguous circuits in conditional_lookahead_blocks.
  vector<StandardCircuit<bool>> xored_lookahead_blocks(num_lookahead_blocks - 1);
  for (uint64_t i = 0; i < num_lookahead_blocks - 1; ++i) {
    if (!MergeCircuits(
            true,
            false,
            BooleanOperation::XOR,
            conditional_lookahead_blocks[2 * i],
            conditional_lookahead_blocks[2 * i + 1],
            &(xored_lookahead_blocks[i]))) {
      LOG_ERROR("Unable to form xored_lookahead_blocks circuit " + Itoa(i));
      return false;
    }
  }

  // Do Step 6: merge all circuits together.
  // Note: As we build the circuit, the borrow bit will always be on output wire
  // S + 1, where S = number of (difference) bits that the cummulative block outputs.
  vector<StandardCircuit<bool>> cummulative_lookahead_blocks(
      num_lookahead_blocks - 2);
  for (uint64_t i = 0; i < num_lookahead_blocks - 1; ++i) {
    // Step 6.a: Join current cummulative_lookahead_blocks with circuit 0.v,
    // so that the borrow-bit 'c_i' splits into two bits: (!c_i, c_i).
    const uint64_t num_difference_bits = first_m + i * m;
    map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
    set<pair<int, pair<uint64_t, uint64_t>>>* difference_output_to_input_wire =
        FindOrInsert(
            (int64_t) num_difference_bits,
            output_to_input,
            set<pair<int, pair<uint64_t, uint64_t>>>());
    difference_output_to_input_wire->insert(make_pair(0, make_pair(0, 0)));
    StandardCircuit<bool> tmp_cumm_block;
    if (!JoinCircuits(
            true,
            false,
            output_to_input,
            (i == 0 ? lookahead_blocks[0] : cummulative_lookahead_blocks[i - 1]),
            id_and_not,
            &tmp_cumm_block)) {
      LOG_ERROR("Failed to join Subtraction Subcircuit at bit index " + Itoa(i));
      return false;
    }

    // Step 6.b: Join tmp_cumm_block with corresponding Step 5 circuit.
    output_to_input.clear();
    difference_output_to_input_wire = FindOrInsert(
        (int64_t) num_difference_bits,
        output_to_input,
        set<pair<int, pair<uint64_t, uint64_t>>>());
    difference_output_to_input_wire->insert(
        make_pair(0, make_pair(left_id_input_index, 0)));
    difference_output_to_input_wire = FindOrInsert(
        (int64_t) num_difference_bits + 1,
        output_to_input,
        set<pair<int, pair<uint64_t, uint64_t>>>());
    difference_output_to_input_wire->insert(
        make_pair(0, make_pair(right_id_input_index, 0)));
    if (!JoinCircuits(
            true,
            false,
            output_to_input,
            tmp_cumm_block,
            xored_lookahead_blocks[i],
            (i == num_lookahead_blocks - 2 ?
                 a_minus_b :
                 &(cummulative_lookahead_blocks[i])))) {
      LOG_ERROR("Failed to join Subtraction Subcircuit at bit index " + Itoa(i));
      return false;
    }
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  a_minus_b->num_outputs_ = 1;
  a_minus_b->output_designations_.clear();
  a_minus_b->output_designations_.resize(
      1, make_pair(OutputRecipient(), target_type));
  a_minus_b->function_description_.clear();
  a_minus_b->function_description_.resize(1);
  Formula& formula = a_minus_b->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::SUB;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

bool ConstructSubtractCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* a_minus_b) {
  if (num_one_input_bits <= 1 && one_is_twos_complement)
    LOG_FATAL("Fatal Error.");
  if (num_two_input_bits <= 1 && two_is_twos_complement)
    LOG_FATAL("Fatal Error.");

  // First, handle the case that the two inputs have different DataType sizes:
  // Take the smaller input, and expand it out by either 0-padding (if it
  // is an unsigned type), or copying the leading (2's complement) bit (if signed type)
  if (num_one_input_bits != num_two_input_bits) {
    const uint64_t num_max_bits =
        (int) max(num_one_input_bits, num_two_input_bits);
    // Construct a Subtraction circuit, assuming the smaller input has already
    // been expanded.
    StandardCircuit<bool> circuit_of_equal_bits;
    if (!ConstructSubtractCircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            0,
            0,
            1,
            0,
            num_max_bits,
            num_max_bits,
            &circuit_of_equal_bits)) {
      LOG_ERROR("Failed to ConstructSubtractCircuit");
      return false;
    }

    // Construct identity circuits for the two inputs.
    // First, construct an identity circuit for the second input.
    StandardCircuit<bool> input_one;
    if (!ConstructIdentityCircuit(
            false,
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            num_one_input_bits,
            &input_one)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_one's fields.
    input_one.num_outputs_ = 1;
    DataType output_one_type;
    if (!GetIntegerDataType(
            true /* Since this is Subtract circuit, we demand a signed output type */
            ,
            (int) num_one_input_bits,
            &output_one_type)) {
      return false;
    }
    input_one.output_designations_.clear();
    input_one.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_one_type));
    input_one.function_description_.clear();
    input_one.function_description_.resize(1);
    Formula& formula = input_one.function_description_[0];
    formula.op_.type_ = OperationType::BOOLEAN;
    formula.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str =
        "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
    formula.value_ = GenericValue(var_str);

    // Now construct an identity circuit for the second input.
    StandardCircuit<bool> input_two;
    if (!ConstructIdentityCircuit(
            false,
            two_is_twos_complement,
            value_two_party_index,
            value_two_input_index,
            num_two_input_bits,
            &input_two)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_two's fields.
    input_two.num_outputs_ = 1;
    DataType output_two_type;
    if (!GetIntegerDataType(
            true /* Since this is Subtract circuit, we demand a signed output type */
            ,
            (int) num_two_input_bits,
            &output_two_type)) {
      return false;
    }
    input_two.output_designations_.clear();
    input_two.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_two_type));
    input_two.function_description_.clear();
    input_two.function_description_.resize(1);
    Formula& formula_two = input_two.function_description_[0];
    formula_two.op_.type_ = OperationType::BOOLEAN;
    formula_two.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str_two =
        "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
    formula_two.value_ = GenericValue(var_str_two);

    // Expand the smaller input to the equivalent representation using
    // the bigger datatype (e.g. -2 = 10 (INT2) -> 1110 (INT4)).
    if (num_one_input_bits < num_two_input_bits) {
      if (!CastCircuitOutputAsMoreBits(
              one_is_twos_complement, (int) num_max_bits, &input_one)) {
        return false;
      }

      // Join expanded first input and second input with GT circuit.
      return JoinCircuits(
          input_one, input_two, circuit_of_equal_bits, a_minus_b);
    } else {
      if (!CastCircuitOutputAsMoreBits(
              two_is_twos_complement, (int) num_max_bits, &input_two)) {
        return false;
      }

      // Join expanded first input and second input with GT circuit.
      return JoinCircuits(
          input_one, input_two, circuit_of_equal_bits, a_minus_b);
    }
  }

  // That we reached here means num_one_input_bits == num_two_input_bits.
  if (num_one_input_bits != num_two_input_bits) LOG_FATAL("Fatal Error.");
  if (num_one_input_bits <= 0) LOG_FATAL("Fatal Error.");
  // Special handling for 1-bit inputs.
  if (num_one_input_bits == 1) {
    // Technically, if two bools are added, this should be done in Z_2, so that
    // e.g. 1 + 1 = 0. However, this is likely *not* what the user intended
    // (otherwise, user would have written (x XOR y), not (x + y)).
    // In general, we don't modify the output type
    // of Addition/Subtraction operation (with the possible exception of
    // changing the output type from Unsigned to Signed if the operation
    // is SUB and/or one of the inputs is Unsigned). However, a common use-case
    // may be to add BOOLs together (e.g. for Hamming Distance).
    // So in the case of ADD on two BOOLs, we cast the output DataType as UINT16
    // (we chose UINT16 somewhat arbitrarily: Unsigned makes sense, since inputs
    // are unsigned (BOOL); and 16-bits seems like it is a nice trade-off of
    // not being too big (in terms of resulting circuit size), and yet big
    // enough to hold the output of any actual computation (i.e. it is unlikely
    // that the user will enter an expression that adds more than 2^16 BOOLs, but
    // a user might want to add more than the next smallest possibility, 2^8 = 256).
    // First, create a circuit for adding the two bools. We can't use XOR,
    // because this will yield 1 + 1 = 0. We could do ADD for UINT16 (since
    // that's the final output type we'll cast to), but this adds extra
    // complexity to the circuit: the inputs are BOOLs afterall, so we're
    // wasting gates/computations on all the leading bits, which are 0.
    // So, we'll cast the inputs first as UINT2, and then update the output
    // type from UINT2 to UINT16.
    // First, expand the one bit inputs into 2 bits: the trailing bit will
    // be the input bit, the other will be constant zero.
    StandardCircuit<bool> input_one, input_two;
    if (!ConstructIdentityCircuit(
            value_one_party_index,
            value_one_input_index,
            DataType::BOOL,
            &input_one) ||
        !ConstructIdentityCircuit(
            value_two_party_index,
            value_two_input_index,
            DataType::BOOL,
            &input_two)) {
      LOG_ERROR("Failed to construct id circuits.");
      return false;
    }
    // For these to output 2 bits.
    if (!CastCircuitOutputAsMoreBits(false, 2, &input_one) ||
        !CastCircuitOutputAsMoreBits(false, 2, &input_two)) {
      return false;
    }

    // Construct a generic subtraction circuit for two UINT2 values.
    StandardCircuit<bool> two_bit_diff;
    if (!ConstructSubtractCircuit(
            false, false, 0, 0, 1, 0, 2, 2, &two_bit_diff)) {
      LOG_ERROR("Unable to subtract two 2-bit values.");
      return false;
    }

    // Overwrite output type: UINT2 -> UINT16.
    if (!CastCircuitOutputAsMoreBits(true, 16, &two_bit_diff)) {
      return false;
    }

    // Join.
    if (!JoinCircuits(input_one, input_two, two_bit_diff, a_minus_b)) {
      LOG_ERROR("Unable to build final boolean sum circuit.");
      return false;
    }

    return true;
  }

  // Grab the final output data type, based on number of bits and signed/unsigned.
  DataType target_type;
  // For Subtraction, we demand the output type is signed, even if
  // both inputs are unsigned (so that in case the second input is larger
  // than the first, the output, which ought to be negative, does not
  // "underflow" to a large positive value).
  if (!GetIntegerDataType(true, (int) num_one_input_bits, &target_type)) {
    LOG_ERROR("Failed to get integer data type.");
    return false;
  }

  // Do ``lookahead'' addition, if appropriate.
  if (kAdditionLookaheadBlocks > 1) {
    // Determine the number of ``lookahead'' blocks to use.
    const int sqrt_n = (int) sqrt(num_one_input_bits);
    const int num_lookahead_blocks =
        kAdditionLookaheadBlocks <= sqrt_n ? kAdditionLookaheadBlocks : sqrt_n;
    if (num_lookahead_blocks > 1) {
      return ConstructLookaheadSubCircuit(
          target_type,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_lookahead_blocks,
          a_minus_b);
    }
  }

  // Standard (no lookahead) subraction.

  // First, create a Subtraction circuit for each bit (because inputs are in
  // 2's complement, all bits are just subtracted; i.e. no need to do anything
  // special with the leading bit).
  // Loop through bits (starting at the least significant).
  vector<StandardCircuit<bool>> subtract_subcircuits(num_one_input_bits);
  for (uint64_t bit_index = 0; bit_index < num_one_input_bits; ++bit_index) {
    if (!ConstructSubtractBitSubcircuit(
            bit_index != num_one_input_bits - 1,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            bit_index,
            &subtract_subcircuits[bit_index])) {
      LOG_ERROR(
          "Failed to create Subtraction Subcircuit at bit index " +
          Itoa(bit_index));
      return false;
    }
    // Overwrite input types, which were determined via 'bit_index'
    // instead of 'num_one_input_bits'.
    const size_t num_one_expected_inputs =
        (value_one_party_index == value_two_party_index ? 2 : 1) +
        ((value_one_party_index == 0 && bit_index != 0) ? 1 : 0);
    const size_t num_two_expected_inputs =
        (value_one_party_index == value_two_party_index ? 2 : 1) +
        ((value_two_party_index == 0 && bit_index != 0) ? 1 : 0);
    if (subtract_subcircuits[bit_index]
                .input_types_[value_one_party_index]
                .size() != num_one_expected_inputs ||
        subtract_subcircuits[bit_index]
                .input_types_[value_two_party_index]
                .size() != num_two_expected_inputs) {
      LOG_ERROR(
          "Unexpected input_types_ size for bit index: " + Itoa(bit_index));
      return false;
    }
    subtract_subcircuits[bit_index].input_types_[value_one_party_index][0] =
        make_pair("P" + Itoa(value_one_party_index) + "_0", target_type);
    if (value_one_party_index == value_two_party_index) {
      subtract_subcircuits[bit_index].input_types_[value_one_party_index][1] =
          make_pair("P" + Itoa(value_one_party_index) + "_1", target_type);
    } else {
      subtract_subcircuits[bit_index].input_types_[value_two_party_index][0] =
          make_pair("P" + Itoa(value_two_party_index) + "_0", target_type);
    }
  }

  // Join the subtract_subcircuits.
  vector<StandardCircuit<bool>> joined_circuits(num_one_input_bits - 2);
  //  Note on how to hook these circuits up:
  //    - subtract_subcircuits (used as circuit 'one' for when bit_index = 0 in
  //      loop below) has output gates:
  //        0: difference_bit_0
  //        1: borrow_bit_0
  //    - joined_circuits (used as circuit 'one' for when bit_index > 0 in
  //      loop below) has output gates:
  //        0: difference_bit_0
  //        1: difference_bit_1
  //        ...
  //        b: difference_bit_b
  //      b+1: borrow_bit_b
  //    - subtract_subcircuits (used as circuit 'two' in loop below) has input mapping:
  //        Wire A: (value_one_party_index, value_one_input_index, bit_index)
  //        Wire B: (value_two_party_index, value_two_input_index, bit_index)
  //      And for all subtract_subcircuits except the first one (which has no input
  //      for borrow bit):
  //        Wire C: (0, d, 0)
  //      where d is:
  //        - 0: If neither value_[one | two]_party_index equals 0;
  //        - 1 + value_one_input_index: If P0 index is 0 but P1 index isn't;
  //        - 1 + value_two_input_index: If P1 index is 0 but P0 index isn't;
  //        - 2 + value_two_input_index + value_two_input_index: If P0 = P1 = 0
  const uint64_t d =
      (value_one_party_index == 0 ? 1 + value_one_input_index : 0) +
      (value_two_party_index == 0 ? 1 + value_two_input_index : 0);
  for (uint64_t bit_index = 0; bit_index < num_one_input_bits - 1; ++bit_index) {
    map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
    set<pair<int, pair<uint64_t, uint64_t>>>* difference_output_to_input_wire =
        FindOrInsert(
            (int64_t) bit_index + 1,
            output_to_input,
            set<pair<int, pair<uint64_t, uint64_t>>>());
    difference_output_to_input_wire->insert(make_pair(0, make_pair(d, 0)));
    if (!JoinCircuits(
            true,
            false,
            output_to_input,
            (bit_index == 0 ? subtract_subcircuits[0] :
                              joined_circuits[bit_index - 1]),
            subtract_subcircuits[bit_index + 1],
            (bit_index == num_one_input_bits - 2 ?
                 a_minus_b :
                 &joined_circuits[bit_index]))) {
      LOG_ERROR(
          "Failed to join Subtraction Subcircuit at bit index " +
          Itoa(bit_index));
      return false;
    }
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  a_minus_b->num_outputs_ = 1;
  a_minus_b->output_designations_.clear();
  a_minus_b->output_designations_.resize(
      1, make_pair(OutputRecipient(), target_type));
  a_minus_b->function_description_.clear();
  a_minus_b->function_description_.resize(1);
  Formula& formula = a_minus_b->function_description_[0];
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::SUB;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  return true;
}

// Multiplication by 0 or 1. Just use AND.
bool ConstructMultiplicationByBitCircuit(
    const bool is_signed_type,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* a_times_b) {
  // Duplicate the appropriate bit, to have size matching the other input.
  StandardCircuit<bool> repeated_bit;
  StandardCircuit<bool> identity;
  if (!ConstructSingleBitIdentityCircuit(
          false,
          value_one_party_index,
          value_one_input_index,
          num_two_input_bits > 1 ? &identity : &repeated_bit)) {
    LOG_ERROR("Failed to ConstructSingleBitIdentityCircuit.");
    return false;
  }
  if (num_two_input_bits > 1 &&
      !DuplicateOutputs<bool>(identity, num_two_input_bits, &repeated_bit)) {
    LOG_ERROR("Failed to DuplicateOutputs.");
    return false;
  }

  // Construct Identity circuit for the second (non-boolean) input.
  StandardCircuit<bool> value;
  if (!ConstructIdentityCircuit(
          false,
          is_signed_type,
          value_two_party_index,
          value_two_input_index,
          num_two_input_bits,
          &value)) {
    LOG_ERROR("Failed to ConstructIdentityCircuit");
    return false;
  }

  // AND the wires together.
  if (!MergeCircuits(
          true, BooleanOperation::AND, repeated_bit, value, a_times_b)) {
    LOG_ERROR("Failed to MergeCircuits.");
    return false;
  }

  // Update the function_description_, num_outputs_, and output_designations_,
  // since we know the structure of the output wires (i.e. they form a DataType
  // of the appropriate number of bits).
  a_times_b->num_outputs_ = 1;
  a_times_b->output_designations_.clear();
  DataType int_type;
  if (!GetIntegerDataType(is_signed_type, (int) num_two_input_bits, &int_type)) {
    return false;
  }
  a_times_b->output_designations_.resize(
      1, make_pair(OutputRecipient(), int_type));
  a_times_b->function_description_.clear();
  a_times_b->function_description_.resize(1);
  Formula& formula = a_times_b->function_description_[0];
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::MULT;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_str_one =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  formula.subterm_one_->value_ = GenericValue(var_str_one);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_str_two =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.subterm_two_->value_ = GenericValue(var_str_two);

  ReduceCircuit(false, a_times_b);
  return true;
}

bool ConstructBitShiftCircuit(
    const int shift_by,
    const bool is_signed,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& num_input_bits,
    const int num_output_bits,
    StandardCircuit<bool>* output) {
  if (num_input_bits < 1) LOG_FATAL("Bad input.");
  if (num_output_bits <= shift_by) LOG_FATAL("Bad input.");

  // Trailing bits are all zero, leading bits come from the input, shifted.
  // First, construct a circuit that outputs the appropriate number
  // of '0's (i.e. for 0-padding the trailing bits).
  StandardCircuit<bool> zero;
  if (shift_by > 0 &&
      !ConstructConstantCircuit(false, (uint64_t) shift_by, &zero)) {
    return false;
  }

  // Now, select the trailing bits of input.
  const uint64_t num_trailing_bits_to_select =
      min(num_input_bits, (uint64_t) (num_output_bits - shift_by));
  vector<pair<uint64_t, uint64_t>> bit_indices(num_trailing_bits_to_select);
  for (uint64_t i = 0; i < num_trailing_bits_to_select; ++i) {
    bit_indices[i] = make_pair(input_index, i);
  }
  StandardCircuit<bool> trailing_bits;
  if (!ConstructSelectBitsCircuit(
          is_signed,
          party_index,
          bit_indices,
          (shift_by > 0 ? &trailing_bits : output))) {
    LOG_ERROR("Failed to ConstructSelectBitsCircuit.");
    return false;
  }

  // Merge the above circuits.
  if (shift_by > 0 &&
      !MergeCircuitsInternal(
          true, BooleanOperation::IDENTITY, zero, trailing_bits, output)) {
    LOG_ERROR("Failed to Merge Circuits.");
    return false;
  }

  // Clean-up function description.
  output->num_outputs_ = 1;
  DataType output_type;
  if (!GetIntegerDataType(is_signed, (int) num_output_bits, &output_type)) {
    return false;
  }
  output->output_designations_.clear();
  output->output_designations_.resize(
      1, make_pair(OutputRecipient(), output_type));
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_str = "P" + Itoa(party_index) + "_" + Itoa(input_index);
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::MULT;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ =
      GenericValue((uint64_t) pow((uint64_t) 2, shift_by));
  // Fill it out to the appropriate number of output bits, with the leading bit
  // being 0-padded or replicating leading bit of input_one, as appropriate.
  if (!CastCircuitOutputAsMoreBits(is_signed, (int) num_output_bits, output)) {
    return false;
  }

  return true;
}

// Overflow bits are chopped off, so caller is responsible for ensuring overflow
// does not occur for the given DataTypes and actual values used.
// TODO(paul): If time to do multiplication becomes a bottleneck of overall
// circuit construction, there are some easy(ish) speed-ups that can be done:
//   1) There are 6 Integer DataTypes (not counting signed vs. unsigned), and
//      thus only 36 possible circuits in terms of multiplication. The only
//      difference then between any multiplication circuit is how it fits
//      with the rest of the circuit/function, i.e. where its input wires
//      come from, and where its output wires map to. Rather than always
//      generating a multiplication circuit from scratch every time, you
//      could pre-generate all 36 of them, and then load them from file
//      (which is much faster than generating them from scratch), and then
//      just have this function redirect the input/output wires.
//   2) Perhaps having a generic function
//      that takes as input a bunch of circuits and sums them all together
//      would be useful. This function could then optimize how the final
//      sum circuit is constructed (i.e. it may just be the divide-and-conquer
//      approach currently used, or maybe it is a more manual/faster
//      way, that leverage the fact that I know what the final circuit will
//      look like, so rather than do a recursive call to a generic function,
//      I can set the gates_ manually/directly (still in a loop, but now the
//      loop wouldn't be calling a function, and there would be no need for
//      a ReduceCircuit() call at the end, which is the bottleneck anyway).
bool ConstructMultiplicationCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* a_times_b) {
  if (num_two_input_bits < 2) {
    LOG_ERROR("Use alternate API (ConstructMultiplicationByBitCircuit) for "
              "multiplying by a single bit");
    return false;
  }
  // Multiply first input by 2^i, for each i \in [0..num_two_input_bits).
  vector<StandardCircuit<bool>> first_input_shifts(num_two_input_bits);
  for (int i = 0; i < (int) num_two_input_bits; ++i) {
    if (!ConstructBitShiftCircuit(
            i,
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            num_one_input_bits,
            (int) max(num_one_input_bits, num_two_input_bits),
            &(first_input_shifts[i]))) {
      LOG_ERROR("Unable to ConstructBitShiftCircuit at " + Itoa(i));
      return false;
    }
    ReduceCircuit(false, &first_input_shifts[i]);
  }

  // Now, "multiply" each of the above circuits by 0 or 1, based on the
  // corresponding bit of num_two_input_bits.
  DataType input_two_type;
  if (!GetIntegerDataType(
          two_is_twos_complement, (int) num_two_input_bits, &input_two_type)) {
    LOG_ERROR("Failed to get type.");
    return false;
  }
  vector<StandardCircuit<bool>> first_input_shifts_selected(num_two_input_bits);
  for (int i = 0; i < (int) num_two_input_bits; ++i) {
    // Construct 'select bit' circuit to pick out the i^th bit of input two.
    StandardCircuit<bool> bit_i;
    if (!ConstructSelectBitCircuit(
            two_is_twos_complement,
            value_two_party_index,
            value_two_input_index,
            i,
            &bit_i)) {
      LOG_ERROR("Unable to select bit " + Itoa(i));
      return false;
    }
    // Correct bit_i's input type, which was based on i instead of num_two_input_bits.
    if ((int) bit_i.input_types_.size() <= value_two_party_index) {
      bit_i.input_types_.resize(value_two_party_index + 1);
    }
    bit_i.input_types_[value_two_party_index][0].second = input_two_type;

    // Multiply bit_i times input one shifted by 2^i.
    if (!MergeCircuits(
            true,
            ArithmeticOperation::MULT,
            one_is_twos_complement,
            false /* Ignored */,
            first_input_shifts[i],
            bit_i,
            &(first_input_shifts_selected[i]))) {
      LOG_ERROR("Unable to multiply a * 2^i * bit_i for i: " + Itoa(i));
      return false;
    }
    ReduceCircuit(false, &first_input_shifts_selected[i]);
  }

  // Now add all circuits together.
  // NOTE: There are several ways I could sum together all the circuits in
  // first_input_shifts_selected:
  //   1) "Linearly": Loop though in the naive way:
  //      First pass:  Store first_input_shifts_selected[0] + first_input_shifts_selected[1]
  //                   in temporary storage sums[0]
  //      Next passes: Store sums[i - 1] + first_input_shifts_selected[i + 1] in sums[i]
  //   2) "Divide-and-Conquer": In the first pass, sum all "adjacent" circuits
  //      (i.e. sum together circuits (i, i+1) for even i's in [0..num_two_input_bits/2)),
  //      and store the results in temporary storage "sums2". Then on the next pass sum
  //      together adjacent sums2 circuits, store in sums4, etc.
  // Both ways work fine, and end up summing all circuits together, as desired.
  // However, the Linear way is *slower* than doing things in a binary
  // divide-and-conquer way, as a result of the fact
  // that the "linear" approach will create progressively deeper circuits, and
  // deeper circuits take longer to Reduce.
  // Thus, below I do (2), but I leave (1) commented-out below for the sake
  // of comparison.
  /*
  vector<StandardCircuit<bool>> sums(num_two_input_bits - 2);
  for (int i = 0; i < (int) num_two_input_bits - 1; ++i) {
    if (!MergeCircuits(
            true, ArithmeticOperation::ADD,
            one_is_twos_complement, one_is_twos_complement,
            (i == 0 ? first_input_shifts_selected[0] : sums[i - 1]),
            first_input_shifts_selected[i + 1],
            (i == num_two_input_bits - 2 ? a_times_b : &(sums[i])))) {
      LOG_ERROR("Failed to construct sum circuit at: " + Itoa(i));
      return false;
    }
    ReduceCircuit(false, i == num_two_input_bits - 2 ? a_times_b : &sums[i]);
  }
  */
  vector<StandardCircuit<bool>> sums(num_two_input_bits - 2);
  int index_wrt_orig = 0;
  int index_wrt_sums = 0;
  for (int i = 0; i < (int) num_two_input_bits - 1; ++i) {
    if (index_wrt_orig < (int) num_two_input_bits - 1) {
      if (!MergeCircuits(
              true,
              ArithmeticOperation::ADD,
              one_is_twos_complement,
              one_is_twos_complement,
              first_input_shifts_selected[index_wrt_orig],
              first_input_shifts_selected[index_wrt_orig + 1],
              (i == (int) (num_two_input_bits - 2) ? a_times_b : &(sums[i])))) {
        LOG_ERROR("Failed to construct sum circuit at: " + Itoa(i));
        return false;
      }
      ReduceCircuit(
          false, i == (int) (num_two_input_bits - 2) ? a_times_b : &sums[i]);
      index_wrt_orig += 2;
    } else if (index_wrt_orig == (int) (num_two_input_bits - 1)) {
      if (!MergeCircuits(
              true,
              ArithmeticOperation::ADD,
              one_is_twos_complement,
              one_is_twos_complement,
              first_input_shifts_selected[index_wrt_orig],
              sums[index_wrt_sums],
              (i == (int) (num_two_input_bits - 2) ? a_times_b : &(sums[i])))) {
        LOG_ERROR("Failed to construct sum circuit at: " + Itoa(i));
        return false;
      }
      ReduceCircuit(
          false, i == (int) (num_two_input_bits - 2) ? a_times_b : &sums[i]);
      ++index_wrt_orig;
      ++index_wrt_sums;
    } else {
      if (!MergeCircuits(
              true,
              ArithmeticOperation::ADD,
              one_is_twos_complement,
              one_is_twos_complement,
              sums[index_wrt_sums],
              sums[index_wrt_sums + 1],
              (i == (int) (num_two_input_bits) -2 ? a_times_b : &(sums[i])))) {
        LOG_ERROR("Failed to construct sum circuit at: " + Itoa(i));
        return false;
      }
      ReduceCircuit(
          false, i == (int) (num_two_input_bits) -2 ? a_times_b : &sums[i]);
      index_wrt_sums += 2;
    }
  }

  // Clean up output descriptions, as these may have gotten complicated.
  a_times_b->num_outputs_ = 1;
  DataType output_type;
  if (!GetIntegerDataType(
          one_is_twos_complement || two_is_twos_complement,
          (int) max(num_one_input_bits, num_two_input_bits),
          &output_type)) {
    return false;
  }
  a_times_b->output_designations_.clear();
  a_times_b->output_designations_.resize(
      1, make_pair(OutputRecipient(), output_type));
  a_times_b->function_description_.clear();
  a_times_b->function_description_.resize(1);
  Formula& formula = a_times_b->function_description_[0];
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::MULT;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  ReduceCircuit(false, a_times_b);

  return true;
}

bool ConstructSingleBitExponentPowerCircuit(
    const bool one_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    StandardCircuit<bool>* a_pow_b) {
  DataType output_type;
  if (!GetIntegerDataType(
          one_is_twos_complement, (int) num_one_input_bits, &output_type)) {
    return false;
  }

  // Construct identity circuit for input one.
  StandardCircuit<bool> input_one;
  if (!ConstructIdentityCircuit(
          false,
          one_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          num_one_input_bits,
          &input_one)) {
    LOG_ERROR("Failed to construct identity.");
    return false;
  }
  // Clean-up input_one.
  input_one.num_outputs_ = 1;
  DataType output_one_type;
  if (!GetIntegerDataType(
          one_is_twos_complement, (int) num_one_input_bits, &output_one_type)) {
    return false;
  }
  input_one.output_designations_.clear();
  input_one.output_designations_.resize(
      1, make_pair(OutputRecipient(), output_one_type));
  input_one.function_description_.clear();
  input_one.function_description_.resize(1);
  Formula& input_one_formula = input_one.function_description_[0];
  input_one_formula.op_.type_ = OperationType::BOOLEAN;
  input_one_formula.op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  input_one_formula.value_ = GenericValue(var_str);

  // Multiply input two times input one.
  StandardCircuit<bool> input_one_times_two;
  if (!ConstructArithmeticCircuit(
          true,
          ArithmeticOperation::MULT,
          false,
          false,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          1,
          &input_one_times_two)) {
    LOG_ERROR("Failed to construct multiplication circuit.");
    return false;
  }

  // Construct constant '0' circuit.
  StandardCircuit<bool> zero;
  if (!ConstructConstantCircuit(false, (uint64_t) 1, &zero)) {
    LOG_ERROR("Failed to construct constant circuit.");
    return false;
  }

  // Construct circuit for NOT of input two.
  StandardCircuit<bool> not_input_two;
  if (!ConstructSingleBitNotCircuit(
          false, value_two_party_index, value_two_input_index, &not_input_two)) {
    LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
    return false;
  }

  // Construct a first input != 0 circuit.
  StandardCircuit<bool> bits_not_all_zero;
  if (!ConstructComparisonCircuit(
          ComparisonOperation::COMP_NEQ,
          false,
          false,
          num_one_input_bits,
          1,
          &bits_not_all_zero)) {
    LOG_ERROR("Failed to ConstructComparisonCircuit.");
    return false;
  }
  StandardCircuit<bool> input_one_not_zero;
  if (!JoinCircuits(input_one, zero, bits_not_all_zero, &input_one_not_zero)) {
    LOG_ERROR("Failed to JoinCircuits.");
    return false;
  }

  // 'AND' together: (first_input != 0) AND (second_input == 0)
  StandardCircuit<bool> constant_one_toggle;
  if (!MergeCircuitsInternal(
          true,
          BooleanOperation::AND,
          input_one_not_zero,
          not_input_two,
          &constant_one_toggle)) {
    LOG_ERROR("Failed to construct constant_one_toggle.");
    return false;
  }
  // Make this circuit have num_one_bits.
  constant_one_toggle.num_outputs_ = 1;
  constant_one_toggle.output_designations_.clear();
  constant_one_toggle.output_designations_.resize(
      1, make_pair(OutputRecipient(), output_type));
  // I won't both to muck with the function description, it won't be used anyway.
  // Just need to make sure it has same size as output_designations_ (namely, 1).
  constant_one_toggle.function_description_.clear();
  constant_one_toggle.function_description_.resize(1);
  // Fill it out to the appropriate number of output bits, with the leading bit
  // being 0-padded or replicating leading bit of input_one, as appropriate.
  if (!CastCircuitOutputAsMoreBits(
          false, (int) num_one_input_bits, &constant_one_toggle)) {
    return false;
  }

  // Add the two circuits. Since one of the circuits is necessarily zero,
  // just 'OR' the output bits, which is faster than doing an actual sum.
  if (!MergeCircuitsInternal(
          true,
          BooleanOperation::OR,
          constant_one_toggle,
          input_one_times_two,
          a_pow_b)) {
    LOG_ERROR("Failed to Add circuits.");
    return false;
  }

  // Clean up output descriptions, as these may have gotten complicated.
  a_pow_b->num_outputs_ = 1;
  a_pow_b->output_designations_.clear();
  a_pow_b->output_designations_.resize(
      1, make_pair(OutputRecipient(), output_type));
  a_pow_b->function_description_.clear();
  a_pow_b->function_description_.resize(1);
  Formula& formula = a_pow_b->function_description_[0];
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::POW;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  ReduceCircuit(false, a_pow_b);
  return true;
}

// Overflow bits are chopped off, so caller is responsible for ensuring overflow
// does not occur for the given DataTypes and actual values used.
bool ConstructPowerCircuit(
    const bool one_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* a_pow_b) {
  if (num_two_input_bits == 0) LOG_FATAL("Bad input.");

  // If 2nd input is BOOL (0 or 1):
  //   - Output '1' if 2nd input is '0' (as long as first input isn't also 0)
  //   - Output Identity circuit for first input if 2nd input is '1'.
  if (num_two_input_bits == 1) {
    return ConstructSingleBitExponentPowerCircuit(
        one_is_twos_complement,
        value_one_party_index,
        value_one_input_index,
        value_two_party_index,
        value_two_input_index,
        num_one_input_bits,
        a_pow_b);
  }

  // Potential optimization if num_two_input_bits is small:
  // We don't need to compute power a^n for values of n that are larger
  // than the max expressible value in 'num_two_input_bits'.
  // We also have a hard cutoff at 6, since 2^6 = 64, and we don't allow
  // exponents bigger than this.
  const int num_powers_required = min((int) 6, (int) num_two_input_bits);
  const int minimal_num_output_bits =
      min((int) 64, (int) num_one_input_bits * num_powers_required);
  // Set number of output bits to be the smallest data type that can hold
  // minimal_num_output_bits.
  DataType output_type;
  if (!GetIntegerDataType(
          one_is_twos_complement, minimal_num_output_bits, &output_type)) {
    return false;
  }
  const int num_output_bits = (int) GetValueNumBits(output_type);

  // Below, we'll need a circuit for x != 0. Go ahead and build it now.
  StandardCircuit<bool> bits_not_all_zero;
  if (!ConstructComparisonCircuit(
          ComparisonOperation::COMP_NEQ,
          false,
          false,
          num_one_input_bits,
          1,
          &bits_not_all_zero)) {
    LOG_ERROR("Failed to ConstructComparisonCircuit.");
    return false;
  }
  StandardCircuit<bool> zero;
  if (!ConstructConstantCircuit(false, (uint64_t) 1, &zero)) {
    LOG_ERROR("Failed to construct constant circuit.");
    return false;
  }

  // Construct identity circuit for first input.
  StandardCircuit<bool> input_one;
  if (!ConstructIdentityCircuit(
          false,
          one_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          num_one_input_bits,
          &input_one)) {
    LOG_ERROR("Failed to ConstructIdentityCircuit");
    return false;
  }
  // Clean-up input_one.
  input_one.num_outputs_ = 1;
  DataType output_one_type;
  if (!GetIntegerDataType(
          one_is_twos_complement, (int) num_one_input_bits, &output_one_type)) {
    return false;
  }
  input_one.output_designations_.clear();
  input_one.output_designations_.resize(
      1, make_pair(OutputRecipient(), output_one_type));
  input_one.function_description_.clear();
  input_one.function_description_.resize(1);
  Formula& input_one_formula = input_one.function_description_[0];
  input_one_formula.op_.type_ = OperationType::BOOLEAN;
  input_one_formula.op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  input_one_formula.value_ = GenericValue(var_str);

  StandardCircuit<bool> input_one_not_zero;
  if (!JoinCircuits(input_one, zero, bits_not_all_zero, &input_one_not_zero)) {
    LOG_ERROR("Failed to JoinCircuits.");
    return false;
  }

  // Create a generic "squared" circuit, that squares its input.
  StandardCircuit<bool> square_circuit;
  if (!ConstructMultiplicationCircuit(
          one_is_twos_complement,
          one_is_twos_complement,
          0,
          0,
          0,
          0,
          num_output_bits,
          num_output_bits,
          &square_circuit)) {
    LOG_ERROR("Failed to construct squared circuit.");
    return false;
  }
  ReduceCircuit(false, &square_circuit);

  // Create a bunch of (6) circuits that compute a^(2^n), for each
  // n = 0, 1, 2, ..., num_powers_required
  vector<StandardCircuit<bool>> first_input_powers(num_powers_required);
  first_input_powers[0] = input_one;
  // Fill it out to the appropriate number of output bits, with the leading bit
  // being 0-padded or replicating leading bit of input_one, as appropriate.
  if (!CastCircuitOutputAsMoreBits(
          one_is_twos_complement,
          (int) num_output_bits,
          &first_input_powers[0])) {
    return false;
  }
  for (int i = 1; i < num_powers_required; ++i) {
    if (!JoinCircuits(
            first_input_powers[i - 1],
            square_circuit,
            &(first_input_powers[i]))) {
      LOG_ERROR("Unable to compute powers at " + Itoa(i));
      return false;
    }
    ReduceCircuit(false, &first_input_powers[i]);
  }

  // Now, "multiply" each of the above circuits by 0 or 1, based on the
  // corresponding bit of num_two_input_bits.
  DataType input_two_type;
  if (!GetIntegerDataType(false, (int) num_two_input_bits, &input_two_type)) {
    LOG_ERROR("Failed to get type.");
    return false;
  }
  vector<StandardCircuit<bool>> first_input_powers_selected(num_powers_required);
  for (int i = 0; i < num_powers_required; ++i) {
    // Construct 'select bit' circuit to pick out the i^th bit of input two.
    StandardCircuit<bool> bit_i;
    if (!ConstructSelectBitCircuit(
            false, value_two_party_index, value_two_input_index, i, &bit_i)) {
      LOG_ERROR("Unable to select bit " + Itoa(i));
      return false;
    }
    // Correct bit_i's input type, which was based on i instead of num_two_input_bits.
    if ((int) bit_i.input_types_.size() <= value_two_party_index) {
      bit_i.input_types_.resize(value_two_party_index + 1);
    }
    bit_i.input_types_[value_two_party_index][0].second = input_two_type;

    // Multiply bit_i times input one raised to the 2^i.
    StandardCircuit<bool> first_input_power_times_bit_i;
    if (!MergeCircuits(
            true,
            ArithmeticOperation::MULT,
            one_is_twos_complement,
            false /* Ignored */,
            first_input_powers[i],
            bit_i,
            &first_input_power_times_bit_i)) {
      LOG_ERROR("Unable to multiply a^(2^i) * bit_i for i: " + Itoa(i));
      return false;
    }
    ReduceCircuit(false, &first_input_power_times_bit_i);

    // If bit_i is zero, the above multiplication will yield output '0', which
    // isn't what we want (we want '1', since anything raised to the 0 is 1).
    // Thus, OR the result with the not bit_i circuit.
    StandardCircuit<bool> not_bit_i;
    if (!ConstructSingleBitNotCircuit(
            false,
            value_two_party_index,
            value_two_input_index,
            i,
            &not_bit_i)) {
      LOG_ERROR("Unable to select bit " + Itoa(i));
      return false;
    }
    // Correct not_bit_i's input type, which was based on i instead of num_two_input_bits.
    if ((int) not_bit_i.input_types_.size() <= value_two_party_index) {
      not_bit_i.input_types_.resize(value_two_party_index + 1);
    }
    not_bit_i.input_types_[value_two_party_index][0].second = input_two_type;
    // Fill it out to the appropriate number of output bits, with the leading bit
    // being 0-padded or replicating leading bit of input_one, as appropriate.
    if (!CastCircuitOutputAsMoreBits(false, (int) num_output_bits, &not_bit_i)) {
      return false;
    }
    // Overwrite output type, to get it to agree with first_input_power_times_bit_i.
    // (I needed to 0-pad not_bit_i, even/especially if not_bit_i outputs '1',
    // since I'll be OR'ing it below instead of adding it; but, first_input_power_
    // times_bit_i may have signed type, so I need to update not_bit_i to match
    // this type, as otherwise MergeCircuitInternal will complain).
    if (one_is_twos_complement) {
      not_bit_i.output_designations_[0].second = output_type;
    }

    // Now 'OR' these together (in reality, I want to ADD them together, but
    // since one of them is necessarily zero, 'OR' requires fewer gates and
    // will yield the same result).
    if (!MergeCircuitsInternal(
            true,
            BooleanOperation::OR,
            first_input_power_times_bit_i,
            not_bit_i,
            &(first_input_powers_selected[i]))) {
      LOG_ERROR("Unable to multiply a^(2^i) * bit_i for i: " + Itoa(i));
      return false;
    }
    ReduceCircuit(false, &first_input_powers_selected[i]);
  }

  // Now multiply all circuits together.
  // See comment above corresponding loop in ConstructMultiplicationCircuit()
  // about the logic behind this loop (and why we don't just use the more
  // straightforward, commented-out loop below, which would result in the
  // same circuit); although this is less significant here, where the loop
  // is over at most 6 terms, versus 64 terms for the Multiplication analog.
  /*
  vector<StandardCircuit<bool>> products(num_powers_required - 2);
  for (int i = 0; i < num_powers_required - 1; ++i) {
    if (!MergeCircuits(
            true, ArithmeticOperation::MULT,
            one_is_twos_complement, one_is_twos_complement,
            (i == 0 ? first_input_powers_selected[0] : products[i - 1]),
            first_input_powers_selected[i + 1],
            (i == num_powers_required - 2 ? a_pow_b : &(products[i])))) {
      LOG_ERROR("Failed to construct sum circuit at: " + Itoa(i));
      return false;
    }
  }
  */
  vector<StandardCircuit<bool>> products(num_powers_required - 1);
  int index_wrt_orig = 0;
  int index_wrt_products = 0;
  for (int i = 0; i < num_powers_required - 1; ++i) {
    if (index_wrt_orig < num_powers_required - 1) {
      if (!MergeCircuits(
              true,
              ArithmeticOperation::MULT,
              one_is_twos_complement,
              one_is_twos_complement,
              first_input_powers_selected[index_wrt_orig],
              first_input_powers_selected[index_wrt_orig + 1],
              &(products[i]))) {
        LOG_ERROR("Failed to construct sum circuit at: " + Itoa(i));
        return false;
      }
      index_wrt_orig += 2;
    } else if (index_wrt_orig == num_powers_required - 1) {
      if (!MergeCircuits(
              true,
              ArithmeticOperation::MULT,
              one_is_twos_complement,
              one_is_twos_complement,
              first_input_powers_selected[index_wrt_orig],
              products[index_wrt_products],
              &(products[i]))) {
        LOG_ERROR("Failed to construct sum circuit at: " + Itoa(i));
        return false;
      }
      ++index_wrt_orig;
      ++index_wrt_products;
    } else {
      if (!MergeCircuits(
              true,
              ArithmeticOperation::MULT,
              one_is_twos_complement,
              one_is_twos_complement,
              products[index_wrt_products],
              products[index_wrt_products + 1],
              &(products[i]))) {
        LOG_ERROR("Failed to construct sum circuit at: " + Itoa(i));
        return false;
      }
      index_wrt_products += 2;
    }
    ReduceCircuit(false, &products[i]);
  }

  // We also need to handle the special case: Input one and/or two are zero:
  //   a) If input one is zero, output '0'
  //   b) If input one is non-zero and input two is zero, output '1'
  // Note that the above 'products' circuit already accomplishes (b).
  // So it remains to accomplish (a), but multiplying the final circuit by (x != 0).
  if (!MergeCircuits(
          true,
          ArithmeticOperation::MULT,
          one_is_twos_complement,
          false /* Ignored */,
          products[num_powers_required - 2],
          input_one_not_zero,
          a_pow_b)) {
    LOG_ERROR("Unable to multiply corner case.");
    return false;
  }
  ReduceCircuit(false, a_pow_b);

  // Clean up output descriptions, as these may have gotten complicated.
  a_pow_b->num_outputs_ = 1;
  a_pow_b->output_designations_.clear();
  a_pow_b->output_designations_.resize(
      1, make_pair(OutputRecipient(), output_type));
  a_pow_b->function_description_.clear();
  a_pow_b->function_description_.resize(1);
  Formula& formula = a_pow_b->function_description_[0];
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::POW;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_one_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  formula.subterm_one_->value_ = GenericValue(var_one_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_two_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.subterm_two_->value_ = GenericValue(var_two_str);

  ReduceCircuit(false, a_pow_b);

  return true;
}

bool ConstructFlipSignCircuit(
    const bool is_twos_complement,
    const int value_party_index,
    const uint64_t& value_input_index,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output) {
  if (!is_twos_complement) {
    LOG_ERROR("Flipping signs not valid for Unsigned DataTypes.");
    return false;
  }
  if (num_input_bits < 2) {
    LOG_ERROR("1-bit values do not have a sign to flip.");
    return false;
  }

  // Flipping the sign, since we use 2's complement, means:
  // Flipping all bits, then addding 1 (this is true for both neg->pos
  // and pos->neg).
  // First, construct the flip all bits circuit.
  StandardCircuit<bool> flipped_bits;
  if (!ConstructNotCircuit(
          false,
          true,
          value_party_index,
          value_input_index,
          num_input_bits,
          &flipped_bits)) {
    return false;
  }
  // Clean-up output type of NOT circuit (the above treated everything as bits,
  // want to treat the output wires as representing a single value).
  flipped_bits.num_outputs_ = 1;
  DataType flipped_output_type;
  if (!GetIntegerDataType(
          is_twos_complement, (int) num_input_bits, &flipped_output_type)) {
    return false;
  }
  flipped_bits.output_designations_.clear();
  flipped_bits.output_designations_.resize(
      1, make_pair(OutputRecipient(), flipped_output_type));
  flipped_bits.function_description_.clear();
  flipped_bits.function_description_.resize(1);
  Formula& not_formula = flipped_bits.function_description_[0];
  not_formula.op_.type_ = OperationType::BOOLEAN;
  not_formula.op_.gate_op_ = BooleanOperation::NOT;
  not_formula.subterm_one_.reset(new Formula());
  not_formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  not_formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string not_var_str =
      "P" + Itoa(value_party_index) + "_" + Itoa(value_input_index);
  not_formula.subterm_one_->value_ = GenericValue(not_var_str);

  // Construct a constant '1' circuit.
  StandardCircuit<bool> one;
  if (!ConstructConstantCircuit((uint64_t) 1, (int) num_input_bits, &one)) {
    LOG_ERROR("Failed to ConstructConstantCircuit.");
    return false;
  }

  // Construct a Sum circuit.
  StandardCircuit<bool> sum;
  if (!ConstructArithmeticCircuit(
          true,
          ArithmeticOperation::ADD,
          true,
          true,
          num_input_bits,
          num_input_bits,
          &sum)) {
    LOG_ERROR("Failed to Construct Sum Circuit.");
    return false;
  }

  // Join the 'flipped_bits' and the 'one' circuits to 'sum'.
  if (!JoinCircuits(flipped_bits, one, sum, output)) {
    LOG_ERROR("Failed to JoinCircuits.");
    return false;
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  output->num_outputs_ = 1;
  DataType output_type;
  if (!GetIntegerDataType(
          is_twos_complement, (int) num_input_bits, &output_type)) {
    return false;
  }
  output->output_designations_.clear();
  output->output_designations_.resize(
      1, make_pair(OutputRecipient(), output_type));
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_str =
      "P" + Itoa(value_party_index) + "_" + Itoa(value_input_index);
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::FLIP_SIGN;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_str);

  return true;
}

bool ConstructAbsCircuit(
    const bool is_twos_complement,
    const int value_party_index,
    const uint64_t& value_input_index,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output) {
  if (num_input_bits < 2) {
    LOG_ERROR("Absolute Value not valid for 1-bit values");
    return false;
  }

  // First, construct an Identity circuit.
  StandardCircuit<bool> id;
  if (!ConstructIdentityCircuit(
          false,
          is_twos_complement,
          value_party_index,
          value_input_index,
          num_input_bits,
          (is_twos_complement ? &id : output))) {
    LOG_ERROR("Unable to construct ID circuit.");
    return false;
  }
  // Clean-up output type of circuit (the above treated everything as bits,
  // want to treat the output wires as representing a single value).
  id.num_outputs_ = 1;
  DataType id_output_type;
  if (!GetIntegerDataType(
          is_twos_complement, (int) num_input_bits, &id_output_type)) {
    return false;
  }
  id.output_designations_.clear();
  id.output_designations_.resize(
      1, make_pair(OutputRecipient(), id_output_type));
  id.function_description_.clear();
  id.function_description_.resize(1);
  Formula& id_formula = id.function_description_[0];
  id_formula.op_.type_ = OperationType::BOOLEAN;
  id_formula.op_.gate_op_ = BooleanOperation::IDENTITY;
  const string not_var_str =
      "P" + Itoa(value_party_index) + "_" + Itoa(value_input_index);
  id_formula.value_ = GenericValue(not_var_str);

  // If input type is Unsigned, nothing to do (just return Identity circuit).
  if (is_twos_complement) {
    // Construct the negative circuit.
    StandardCircuit<bool> flip_sign;
    if (!ConstructFlipSignCircuit(
            is_twos_complement,
            value_party_index,
            value_input_index,
            num_input_bits,
            &flip_sign)) {
      LOG_ERROR("Unable to ConstructFlipSignCircuit");
      return false;
    }

    // The leading bit determines the sign of the input. Pick this out.
    StandardCircuit<bool> leading_bit;
    if (!ConstructSelectBitCircuit(
            is_twos_complement,
            value_party_index,
            value_input_index,
            num_input_bits - 1,
            &leading_bit)) {
      LOG_ERROR("Unable to ConstructSelectBitCircuit");
      return false;
    }
    // Also pick out it's NOT.
    StandardCircuit<bool> not_leading_bit;
    if (!ConstructSingleBitNotCircuit(
            is_twos_complement,
            value_party_index,
            value_input_index,
            num_input_bits - 1,
            &not_leading_bit)) {
      LOG_ERROR("Unable to ConstructSelectBitCircuit");
      return false;
    }

    // Multiply 'Id' by NOT leading_bit, and 'flip_sign' by leading_bit.
    StandardCircuit<bool> mult_by_bit;
    if (!ConstructMultiplicationByBitCircuit(
            is_twos_complement, 0, 0, 1, 0, num_input_bits, &mult_by_bit)) {
      LOG_ERROR("Failed to get multiplication circuits.");
      return false;
    }
    StandardCircuit<bool> id_mult, flip_mult;
    if (!JoinCircuits(not_leading_bit, id, mult_by_bit, &id_mult) ||
        !JoinCircuits(leading_bit, flip_sign, mult_by_bit, &flip_mult)) {
    }

    // OR results.
    if (!MergeCircuitsInternal(
            true, BooleanOperation::OR, id_mult, flip_mult, output)) {
      LOG_ERROR("Failed to OR circuits");
      return false;
    }
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  output->num_outputs_ = 1;
  DataType output_type;
  if (!GetIntegerDataType(false, (int) num_input_bits, &output_type)) {
    return false;
  }
  output->output_designations_.clear();
  output->output_designations_.resize(
      1, make_pair(OutputRecipient(), output_type));
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_str =
      "P" + Itoa(value_party_index) + "_" + Itoa(value_input_index);
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::ABS;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_str);

  return true;
}

// All values 0!, 1!, 2!, 3!, .., 20! have been precomputed. Use the bits
// of input to pick the right one.
// NOTE/WARNING: If the last 5 bits of the input represent a number that is
// *bigger* than 20, than this circuit will output '0'.
bool ConstructFactorialCircuit(
    const int value_party_index,
    const uint64_t& value_input_index,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output) {
  if (num_input_bits == 0) LOG_FATAL("Bad input.");

  // Since 20! is the largest factorial that is representable in 64 bits
  // (the current DataType max), we only allow computations up to 20!
  // If the input is larger than this, we just look at the trailing 5
  // bits, and use that value.
  const int num_input_bits_to_use = min((int) 5, (int) num_input_bits);
  const int num_factorials_needed = num_input_bits_to_use == 5 ?
      21 :
      (int) (pow((int) 2, (int) num_input_bits_to_use));

  // Construct identity circuit for this input (only selects the
  // trailing 'num_input_bits_to_use' bits).
  vector<pair<uint64_t, uint64_t>> bit_indices(num_input_bits_to_use);
  for (int i = 0; i < num_input_bits_to_use; ++i) {
    bit_indices[i] = make_pair(value_input_index, i);
  }
  StandardCircuit<bool> id;
  if (!ConstructSelectBitsCircuit(false, value_party_index, bit_indices, &id)) {
    LOG_ERROR("Failed to construct identity circuit");
    return false;
  }
  // Overwrite some of input_one's fields.
  id.num_outputs_ = 1;
  DataType id_output_type;
  if (!GetIntegerDataType(false, (int) num_input_bits_to_use, &id_output_type)) {
    return false;
  }
  id.output_designations_.clear();
  id.output_designations_.resize(
      1, make_pair(OutputRecipient(), id_output_type));
  id.function_description_.clear();
  id.function_description_.resize(1);
  Formula& id_formula = id.function_description_[0];
  id_formula.op_.type_ = OperationType::BOOLEAN;
  id_formula.op_.gate_op_ = BooleanOperation::IDENTITY;
  const string id_var_str =
      "P" + Itoa(value_party_index) + "_" + Itoa(value_input_index);
  id_formula.value_ = GenericValue(id_var_str);
  // Fill it out to the appropriate number of output bits, with the leading bit
  // being 0-padded or replicating leading bit of input_one, as appropriate.
  if (!CastCircuitOutputAsMoreBits(
          false, (int) GetValueNumBits(id_output_type), &id)) {
    return false;
  }

  // Construct circuits for each n!, for n \in 0..20.
  vector<StandardCircuit<bool>> factorial_circuits(num_factorials_needed);
  for (int i = 0; i < num_factorials_needed; ++i) {
    if (!ConstructConstantCircuit(
            kFirstTwentyFactorials[i], 64, &(factorial_circuits[i]))) {
      LOG_ERROR("Failed to construct circuit for (" + Itoa(i) + "!).");
      return false;
    }
  }

  // Multiply each of the above circuits by 0 or 1, with all of them
  // being multiplied by 0 except for (at most) one of them; i.e.
  // select the relevant circuit, based on the input.
  vector<StandardCircuit<bool>> factorial_circuits_selected(
      num_factorials_needed);
  for (int i = 0; i < num_factorials_needed; ++i) {
    // Create a constant circuit, that outputs value 'i'.
    StandardCircuit<bool> constant_i;
    if (!ConstructConstantCircuit(
            (uint64_t) i, (int) GetValueNumBits(id_output_type), &constant_i)) {
      LOG_ERROR("Failed to construct constant circuit for " + Itoa(i));
      return false;
    }

    // Create a circuit that inputs the current input,
    // and outputs '1' if the current input equals i, and 0 otherwise.
    StandardCircuit<bool> equals_i;
    if (!MergeCircuits(
            true,
            ComparisonOperation::COMP_EQ,
            false,
            false,
            constant_i,
            id,
            &equals_i)) {
      LOG_ERROR("Failed to construct circuit for id == " + Itoa(i));
      return false;
    }

    // Multiply 'equals_i' by the circuit for i!.
    if (!MergeCircuits(
            true,
            ArithmeticOperation::MULT,
            false,
            false,
            factorial_circuits[i],
            equals_i,
            &(factorial_circuits_selected[i]))) {
      LOG_ERROR(
          "Failed to construct factorial_circuits_selected for : " + Itoa(i));
      return false;
    }
  }

  // Now add all circuits together.
  vector<StandardCircuit<bool>> sums(num_factorials_needed - 2);
  for (int i = 0; i < num_factorials_needed - 1; ++i) {
    if (!MergeCircuits(
            true,
            ArithmeticOperation::ADD,
            false,
            false,
            (i == 0 ? factorial_circuits_selected[0] : sums[i - 1]),
            factorial_circuits_selected[i + 1],
            (i == num_factorials_needed - 2 ? output : &sums[i]))) {
      LOG_ERROR("Failed to construct factorial sum at: " + Itoa(i));
      return false;
    }
  }

  // Now clean up output description.
  output->num_outputs_ = 1;
  DataType output_type;
  const int num_output_bits_required = num_input_bits_to_use == 1 ?
      1 :  // 1! = 1, can be stored in BOOL
      (num_input_bits_to_use == 2 ? 4 :  // 3! = 6, can be stored in UINT4
                                    (num_input_bits_to_use == 3 ?
                                         16 :  // 7! = 5,040 can be stored in UINT16
                (num_input_bits_to_use == 4 ?
                                              64 :  // 15! > 2^32, so need to use UINT64
                     (num_input_bits_to_use == 5 ? 64 : 0))));
  if (!GetIntegerDataType(false, (int) num_output_bits_required, &output_type)) {
    return false;
  }
  output->output_designations_.clear();
  output->output_designations_.resize(
      1, make_pair(OutputRecipient(), output_type));
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  const string var_str =
      "P" + Itoa(value_party_index) + "_" + Itoa(value_input_index);
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ = ArithmeticOperation::FACTORIAL;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_str);

  ReduceCircuit(false, output);

  return true;
}

bool ConstructVectorCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* v) {
  // Create the identity circuit for a single input.
  StandardCircuit<bool> left_coordinate, right_coordinate;
  if (!ConstructIdentityCircuit(
          true,
          one_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          num_one_input_bits,
          &left_coordinate) ||
      !ConstructIdentityCircuit(
          true,
          two_is_twos_complement,
          value_two_party_index,
          value_two_input_index,
          num_two_input_bits,
          &right_coordinate)) {
    return false;
  }

  return MergeCircuitsInternal(
      true, BooleanOperation::IDENTITY, left_coordinate, right_coordinate, v);
}

bool ConstructMinCircuit(
    const bool is_min,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* min_a_b) {
  const int max_num_input_bits =
      (int) max(num_one_input_bits, num_two_input_bits);
  if (max_num_input_bits > 64) {
    LOG_ERROR("Bad input to ConstructMinCircuit");
    return false;
  }

  // Construct LT (or GT for max) circuit for the two inputs.
  StandardCircuit<bool> lt;
  if (!ConstructComparisonCircuit(
          (is_min ? ComparisonOperation::COMP_LT : ComparisonOperation::COMP_GT),
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          &lt)) {
    LOG_ERROR("Unable to construct LT circuit.");
    return false;
  }

  // Add an output wire (will need two outputs for the LT circuit; we could
  // duplicate the circuit, but this is wasteful. Instead, leverage that
  // StandardCircuit allows 2-in-n-out, for n > 1).
  StandardCircuit<bool> lt_w_two_outputs;
  if (!DuplicateOutputs<bool>(lt, &lt_w_two_outputs)) {
    LOG_ERROR("Unable to construct LT circuit with duplicate outputs.");
    return false;
  }

  // Flip the bit of one of the two outputs.
  StandardCircuit<bool> not_circuit;
  if (!ConstructSingleBitNotCircuit(false, &not_circuit)) {
    LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
    return false;
  }
  StandardCircuit<bool> lt_and_not_lt;
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  set<pair<int, pair<uint64_t, uint64_t>>>& input_mapping =
      output_to_input
          .insert(make_pair(1, set<pair<int, pair<uint64_t, uint64_t>>>()))
          .first->second;
  input_mapping.insert(make_pair(0, make_pair(0, 0)));
  if (!JoinCircuits(
          output_to_input, lt_w_two_outputs, not_circuit, &lt_and_not_lt)) {
    LOG_ERROR("Failed to JoinCircuits.");
    return false;
  }

  // Generate the circuit that equals the first input (i.e. 'a', for Min(a,b)) if
  // it is the min, or 0 otherwise. First, generate multiplication of the 'a' by a bit.
  const uint64_t first_mult_bit_input_index =
      (value_one_party_index == 0 ? 1 + value_one_input_index : 0) +
      (value_two_party_index == 0 ? 1 + value_two_input_index : 0);
  StandardCircuit<bool> first_input_mult;
  if (!ConstructArithmeticCircuit(
          true,
          ArithmeticOperation::MULT,
          true,
          one_is_twos_complement /* Ignored */,
          0,
          first_mult_bit_input_index,
          value_one_party_index,
          value_one_input_index,
          1,
          max_num_input_bits,
          &first_input_mult)) {
    LOG_ERROR("Failed to pick out the first input.");
    return false;
  }
  // Make sure output has the appropriate number of bits:
  // To "Add" first input plus the second input, we'll need them to have
  // the same number of bits. Actually, even more importantly, if 'a'
  // is chosen by the circuit, since the circuit output will take the
  // DataType of the larger input, this means we need to transform 'a', which
  // is currently the smaller input, into the larger input type. This means:
  //   - If 'a' is Unsigned, we should 0-pad the higher-order bits
  //   - If 'a' is signed, we should perpetuate 'a' 2's complement bit to
  //     all of the padded (leading) bits. This is true whether or not
  //     'b' has a signed type, since by convention, if at least one of
  //     the inputs is signed, the output will be defined to be signed.
  //     Notice that perpetuating the leading (2's complement) bit of 'a'
  //     is the right thing to do, for example if 'a' = -2 has type INT2
  //     and 'b' = 1 has type INT4, then 'a' is the min, and so we should
  //     output -2, but the output type is INT4, so -2 = 1110, and 'a'
  //     was input as 10 (since it is INT2), so we want to perpetuate
  //     the leading '1' to the new leading (padded) bits.
  // Add leading '0' or '1' bits to first_input, if necessary.
  StandardCircuit<bool> temp;
  StandardCircuit<bool>* first_input_w_correct_num_bits = nullptr;
  if (num_one_input_bits < num_two_input_bits) {
    // Construct identity circuit for first input.
    StandardCircuit<bool> input_one;
    if (!ConstructIdentityCircuit(
            false,
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            num_one_input_bits,
            &input_one)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_one's fields.
    input_one.num_outputs_ = 1;
    DataType output_one_type;
    if (!GetIntegerDataType(
            one_is_twos_complement,
            (int) num_one_input_bits,
            &output_one_type)) {
      return false;
    }
    input_one.output_designations_.clear();
    input_one.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_one_type));
    input_one.function_description_.clear();
    input_one.function_description_.resize(1);
    Formula& formula = input_one.function_description_[0];
    formula.op_.type_ = OperationType::BOOLEAN;
    formula.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str =
        "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
    formula.value_ = GenericValue(var_str);
    // Fill it out to the appropriate number of output bits, with the leading bit
    // being 0-padded or replicating leading bit of input_one, as appropriate.
    if (!CastCircuitOutputAsMoreBits(
            one_is_twos_complement, (int) num_two_input_bits, &input_one)) {
      return false;
    }

    // Join with first_input_mult.
    output_to_input.clear();
    for (int j = 0; j < max_num_input_bits; ++j) {
      set<pair<int, pair<uint64_t, uint64_t>>>& join_input_mapping =
          output_to_input
              .insert(make_pair(j, set<pair<int, pair<uint64_t, uint64_t>>>()))
              .first->second;
      join_input_mapping.insert(
          make_pair(value_one_party_index, make_pair(value_one_input_index, j)));
    }
    if (!JoinCircuits(output_to_input, input_one, first_input_mult, &temp)) {
      LOG_ERROR("Unable to construct first_input_w_correct_num_bits.");
      return false;
    }
    first_input_w_correct_num_bits = &temp;
  } else {
    first_input_w_correct_num_bits = &first_input_mult;
  }

  // Generate the circuit that equals the second input (i.e. 'b', for Min(a,b)) if
  // it is the min, or 0 otherwise. First, generate multiplication of the 'b' by a bit.
  StandardCircuit<bool> second_input_mult;
  if (!ConstructArithmeticCircuit(
          true,
          ArithmeticOperation::MULT,
          true,
          two_is_twos_complement /* Ignored */,
          0,
          first_mult_bit_input_index + 1,
          value_two_party_index,
          value_two_input_index,
          1,
          max_num_input_bits,
          &second_input_mult)) {
    LOG_ERROR("Failed to pick out the second input.");
    return false;
  }

  // Make sure output has the appropriate number of bits. See comment above.
  StandardCircuit<bool>* second_input_w_correct_num_bits = nullptr;
  if (num_one_input_bits > num_two_input_bits) {
    DataType output_type;
    if (!GetIntegerDataType(true, max_num_input_bits, &output_type)) {
      return false;
    }
    // Construct identity circuit for second input.
    StandardCircuit<bool> input_two;
    if (!ConstructIdentityCircuit(
            false,
            two_is_twos_complement,
            value_two_party_index,
            value_two_input_index,
            num_two_input_bits,
            &input_two)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_two's fields.
    input_two.num_outputs_ = 1;
    DataType output_two_type;
    if (!GetIntegerDataType(
            two_is_twos_complement,
            (int) num_two_input_bits,
            &output_two_type)) {
      return false;
    }
    input_two.output_designations_.clear();
    input_two.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_two_type));
    input_two.function_description_.clear();
    input_two.function_description_.resize(1);
    Formula& formula_two = input_two.function_description_[0];
    formula_two.op_.type_ = OperationType::BOOLEAN;
    formula_two.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str_two =
        "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
    formula_two.value_ = GenericValue(var_str_two);

    // Fill it out to the appropriate number of output bits, with the leading bit
    // being 0-padded or replicating leading bit of input_one, as appropriate.
    if (!CastCircuitOutputAsMoreBits(
            two_is_twos_complement, (int) num_one_input_bits, &input_two)) {
      return false;
    }

    // Join with second_input_mult.
    output_to_input.clear();
    for (int j = 0; j < max_num_input_bits; ++j) {
      set<pair<int, pair<uint64_t, uint64_t>>>& join_input_mapping =
          output_to_input
              .insert(make_pair(j, set<pair<int, pair<uint64_t, uint64_t>>>()))
              .first->second;
      join_input_mapping.insert(
          make_pair(value_two_party_index, make_pair(value_two_input_index, j)));
    }
    if (!JoinCircuits(output_to_input, input_two, second_input_mult, &temp)) {
      LOG_ERROR("Unable to construct second_input_w_correct_num_bits.");
      return false;
    }
    second_input_w_correct_num_bits = &temp;
  } else {
    second_input_w_correct_num_bits = &second_input_mult;
  }

  // Merge these circuits.
  StandardCircuit<bool> two_products;
  if (!MergeCircuits(
          true,
          BooleanOperation::IDENTITY,
          *first_input_w_correct_num_bits,
          *second_input_w_correct_num_bits,
          &two_products)) {
    LOG_ERROR("Unable to MergeCircuits.");
    return false;
  }

  // Create a circuit that ADDs two values (actually, since one of the values
  // will be '0', it will be faster to do bitwise-OR).
  StandardCircuit<bool> add;
  if (!ConstructBooleanCircuit(
          BooleanOperation::OR, false, max_num_input_bits, &add)) {
    LOG_ERROR("Failed to construct add circuit.");
    return false;
  }

  // Join the two_products circuit with the circuit that adds their outputs.
  StandardCircuit<bool> chosen_value;
  if (!JoinCircuits(two_products, add, &chosen_value)) {
    LOG_ERROR("Failed to JoinCircuits.");
    return false;
  }

  // Finally, join lt_and_not_lt and chosen_value.
  output_to_input.clear();
  set<pair<int, pair<uint64_t, uint64_t>>>& lt_wire_mapping =
      output_to_input
          .insert(make_pair(0, set<pair<int, pair<uint64_t, uint64_t>>>()))
          .first->second;
  lt_wire_mapping.insert(make_pair(0, make_pair(first_mult_bit_input_index, 0)));
  set<pair<int, pair<uint64_t, uint64_t>>>& not_lt_wire_mapping =
      output_to_input
          .insert(make_pair(1, set<pair<int, pair<uint64_t, uint64_t>>>()))
          .first->second;
  not_lt_wire_mapping.insert(
      make_pair(0, make_pair(first_mult_bit_input_index + 1, 0)));
  if (!JoinCircuits(output_to_input, lt_and_not_lt, chosen_value, min_a_b)) {
    LOG_ERROR("Failed to join circuit.");
    return false;
  }

  // Need to update the function_description_ and output_designations_, which
  // currently are at the bit level.
  if ((int) min_a_b->function_description_.size() != max_num_input_bits ||
      (int) min_a_b->num_output_wires_ != max_num_input_bits ||
      (int) min_a_b->num_outputs_ != max_num_input_bits ||
      (int) min_a_b->output_designations_.size() != max_num_input_bits) {
    LOG_ERROR("Unexpected circuit fields.");
    return false;
  }

  min_a_b->num_outputs_ = 1;
  min_a_b->function_description_.clear();
  min_a_b->output_designations_.clear();
  // We determine the output DataType as follows:
  //   - If one_is_twos_complement == two_is_twos_complement,
  //     use Signed vs. Unsigned according to them
  //   - Otherwise, there is no definitive way to know which one to take,
  //     since this function just builds the circuit, and is independent
  //     of the actual inputs, so there is no way to know which DataType
  //     to respect. We default to use the Signed DataType, and hope the
  //     user knows that when comparing a Signed vs. Unsigned, that the
  //     unsigned value lies in the bottom half of its max range.
  const bool same_signed_type = one_is_twos_complement == two_is_twos_complement;
  DataType type;
  if (!GetIntegerDataType(
          same_signed_type ? one_is_twos_complement : true,
          max_num_input_bits,
          &type)) {
    return false;
  }
  min_a_b->output_designations_.resize(1, make_pair(OutputRecipient(), type));
  min_a_b->function_description_.resize(1);
  Formula& formula = min_a_b->function_description_[0];
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ =
      is_min ? ArithmeticOperation::MIN : ArithmeticOperation::MAX;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_one =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  formula.subterm_one_->value_ = GenericValue(var_one);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_two =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.subterm_two_->value_ = GenericValue(var_two);

  ReduceCircuit(false, min_a_b);

  return true;
}

bool ConstructArgMinCircuit(
    const bool is_min,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* min_a_b) {
  const int max_num_input_bits =
      (int) max(num_one_input_bits, num_two_input_bits);
  if (max_num_input_bits > 64) {
    LOG_ERROR("Bad input to ConstructArgMinCircuit");
    return false;
  }

  // Construct LT (or GT for max) circuit for the two inputs.
  StandardCircuit<bool> lt;
  const ComparisonOperation first_op = is_min ?
      (kArgminBreakTiesTakeFirst ? ComparisonOperation::COMP_LTE :
                                   ComparisonOperation::COMP_LT) :
      (kArgminBreakTiesTakeFirst ? ComparisonOperation::COMP_GTE :
                                   ComparisonOperation::COMP_GT);
  if (!ConstructComparisonCircuit(
          first_op,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          &lt)) {
    LOG_ERROR("Unable to construct LT circuit.");
    return false;
  }

  // Add an output wire (will need two outputs for ARGMIN, since the output of
  // this circuit is a characteristic vector representing the location of the min).
  // NOTE: We could duplicate the circuit, but this is wasteful. Instead,
  // leverage that StandardCircuit allows 2-in-n-out, for n > 1).
  StandardCircuit<bool> lt_w_two_outputs;
  if (!DuplicateOutputs<bool>(lt, &lt_w_two_outputs)) {
    LOG_ERROR("Unable to construct LT circuit with duplicate outputs.");
    return false;
  }

  // Flip the bit of one of the two outputs (so that one output wire is LT,
  // and the other is !LT).
  StandardCircuit<bool> not_circuit;
  if (!ConstructSingleBitNotCircuit(false, &not_circuit)) {
    LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
    return false;
  }
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  set<pair<int, pair<uint64_t, uint64_t>>>& input_mapping =
      output_to_input
          .insert(make_pair(1, set<pair<int, pair<uint64_t, uint64_t>>>()))
          .first->second;
  input_mapping.insert(make_pair(0, make_pair(0, 0)));
  if (!JoinCircuits(output_to_input, lt_w_two_outputs, not_circuit, min_a_b)) {
    LOG_ERROR("Failed to JoinCircuits.");
    return false;
  }

  // Need to update the function_description_ and output_designations_.
  min_a_b->function_description_.clear();
  min_a_b->output_designations_.clear();
  min_a_b->num_outputs_ = 2;
  min_a_b->output_designations_.resize(
      2, make_pair(OutputRecipient(), DataType::BOOL));
  min_a_b->function_description_.resize(2);
  Formula& formula = min_a_b->function_description_[0];
  formula.op_.type_ = OperationType::COMPARISON;
  formula.op_.comparison_op_ = first_op;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_one =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  formula.subterm_one_->value_ = GenericValue(var_one);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_two =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.subterm_two_->value_ = GenericValue(var_two);
  Formula& formula_two = min_a_b->function_description_[1];
  formula_two.op_.type_ = OperationType::COMPARISON;
  const ComparisonOperation second_op = is_min ?
      (kArgminBreakTiesTakeFirst ? ComparisonOperation::COMP_GT :
                                   ComparisonOperation::COMP_GTE) :
      (kArgminBreakTiesTakeFirst ? ComparisonOperation::COMP_LT :
                                   ComparisonOperation::COMP_LTE);
  formula_two.op_.comparison_op_ = second_op;
  formula_two.subterm_one_.reset(new Formula());
  formula_two.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula_two.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula_two.subterm_one_->value_ = GenericValue(var_one);
  formula_two.subterm_two_.reset(new Formula());
  formula_two.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula_two.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula_two.subterm_two_->value_ = GenericValue(var_two);

  ReduceCircuit(false, min_a_b);

  return true;
}

bool ConstructArgMinInternalCircuit(
    const bool is_min,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* min_a_b) {
  const int max_num_input_bits =
      (int) max(num_one_input_bits, num_two_input_bits);
  if (max_num_input_bits > 64) {
    LOG_ERROR("Bad input to ConstructArgMinInternalCircuit");
    return false;
  }

  // Construct LT (or GT for max) circuit for the two inputs.
  StandardCircuit<bool> lt;
  const ComparisonOperation first_op = is_min ?
      (kArgminBreakTiesTakeFirst ? ComparisonOperation::COMP_LTE :
                                   ComparisonOperation::COMP_LT) :
      (kArgminBreakTiesTakeFirst ? ComparisonOperation::COMP_GTE :
                                   ComparisonOperation::COMP_GT);
  if (!ConstructComparisonCircuit(
          first_op,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          &lt)) {
    LOG_ERROR("Unable to construct LT circuit.");
    return false;
  }

  // Add an output wire (will need two outputs for ARGMIN, since the output of
  // this circuit is a characteristic vector representing the location of the min).
  // NOTE: We could duplicate the circuit, but this is wasteful. Instead,
  // leverage that StandardCircuit allows 2-in-n-out, for n > 1).
  StandardCircuit<bool> lt_w_two_outputs;
  if (!DuplicateOutputs<bool>(lt, &lt_w_two_outputs)) {
    LOG_ERROR("Unable to construct LT circuit with duplicate outputs.");
    return false;
  }

  // Flip the bit of one of the two outputs.
  StandardCircuit<bool> not_circuit;
  if (!ConstructSingleBitNotCircuit(false, &not_circuit)) {
    LOG_ERROR("Failed to ConstructSingleBitNotCircuit.");
    return false;
  }
  StandardCircuit<bool> lt_and_not_lt;
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  set<pair<int, pair<uint64_t, uint64_t>>>& input_mapping =
      output_to_input
          .insert(make_pair(1, set<pair<int, pair<uint64_t, uint64_t>>>()))
          .first->second;
  input_mapping.insert(make_pair(0, make_pair(0, 0)));
  if (!JoinCircuits(
          output_to_input, lt_w_two_outputs, not_circuit, &lt_and_not_lt)) {
    LOG_ERROR("Failed to JoinCircuits.");
    return false;
  }

  // Duplicate the outputs of lt_and_not_lt: One set will be used to multiply
  // the inputs (so that the minimum value gets output), and the other set
  // will map directly to the final output (so that the charactersitic vector
  // representing the position of the minimum gets output).
  StandardCircuit<bool> lt_and_not_lt_w_two_outputs;
  if (!DuplicateOutputs<bool>(lt_and_not_lt, &lt_and_not_lt_w_two_outputs)) {
    LOG_ERROR("Unable to construct LT circuit with duplicate outputs.");
    return false;
  }

  // Generate the circuit that equals the first input (i.e. 'a', for Min(a,b)) if
  // it is the min, or 0 otherwise. First, generate multiplication of the 'a' by a bit.
  const uint64_t first_mult_bit_input_index =
      (value_one_party_index == 0 ? 1 + value_one_input_index : 0) +
      (value_two_party_index == 0 ? 1 + value_two_input_index : 0);
  StandardCircuit<bool> first_input_mult;
  if (!ConstructArithmeticCircuit(
          true,
          ArithmeticOperation::MULT,
          true,
          one_is_twos_complement /* Ignored */,
          0,
          first_mult_bit_input_index,
          value_one_party_index,
          value_one_input_index,
          1,
          max_num_input_bits,
          &first_input_mult)) {
    LOG_ERROR("Failed to pick out the first input.");
    return false;
  }
  // Make sure output has the appropriate number of bits:
  // To "Add" first input plus the second input, we'll need them to have
  // the same number of bits. Actually, even more importantly, if 'a'
  // is chosen by the circuit, since the circuit output will take the
  // DataType of the larger input, this means we need to transform 'a', which
  // is currently the smaller input, into the larger input type. This means:
  //   - If 'a' is Unsigned, we should 0-pad the higher-order bits
  //   - If 'a' is signed, we should perpetuate 'a' 2's complement bit to
  //     all of the padded (leading) bits. This is true whether or not
  //     'b' has a signed type, since by convention, if at least one of
  //     the inputs is signed, the output will be defined to be signed.
  //     Notice that perpetuating the leading (2's complement) bit of 'a'
  //     is the right thing to do, for example if 'a' = -2 has type INT2
  //     and 'b' = 1 has type INT4, then 'a' is the min, and so we should
  //     output -2, but the output type is INT4, so -2 = 1110, and 'a'
  //     was input as 10 (since it is INT2), so we want to perpetuate
  //     the leading '1' to the new leading (padded) bits.
  // Add leading '0' or '1' bits to first_input, if necessary.
  StandardCircuit<bool> temp;
  StandardCircuit<bool>* first_input_w_correct_num_bits = nullptr;
  if (num_one_input_bits < num_two_input_bits) {
    // Construct identity circuit for first input.
    StandardCircuit<bool> input_one;
    if (!ConstructIdentityCircuit(
            false,
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            num_one_input_bits,
            &input_one)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_one's fields.
    input_one.num_outputs_ = 1;
    DataType output_one_type;
    if (!GetIntegerDataType(
            one_is_twos_complement,
            (int) num_one_input_bits,
            &output_one_type)) {
      return false;
    }
    input_one.output_designations_.clear();
    input_one.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_one_type));
    input_one.function_description_.clear();
    input_one.function_description_.resize(1);
    Formula& formula = input_one.function_description_[0];
    formula.op_.type_ = OperationType::BOOLEAN;
    formula.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str =
        "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
    formula.value_ = GenericValue(var_str);
    // Fill it out to the appropriate number of output bits, with the leading bit
    // being 0-padded or replicating leading bit of input_one, as appropriate.
    if (!CastCircuitOutputAsMoreBits(
            one_is_twos_complement, (int) num_two_input_bits, &input_one)) {
      return false;
    }

    // Join with first_input_mult.
    output_to_input.clear();
    for (int j = 0; j < max_num_input_bits; ++j) {
      set<pair<int, pair<uint64_t, uint64_t>>>& join_input_mapping =
          output_to_input
              .insert(make_pair(j, set<pair<int, pair<uint64_t, uint64_t>>>()))
              .first->second;
      join_input_mapping.insert(
          make_pair(value_one_party_index, make_pair(value_one_input_index, j)));
    }
    if (!JoinCircuits(output_to_input, input_one, first_input_mult, &temp)) {
      LOG_ERROR("Unable to construct first_input_w_correct_num_bits.");
      return false;
    }
    first_input_w_correct_num_bits = &temp;
  } else {
    first_input_w_correct_num_bits = &first_input_mult;
  }

  // Generate the circuit that equals the second input (i.e. 'b', for Min(a,b)) if
  // it is the min, or 0 otherwise. First, generate multiplication of the 'b' by a bit.
  StandardCircuit<bool> second_input_mult;
  if (!ConstructArithmeticCircuit(
          true,
          ArithmeticOperation::MULT,
          true,
          two_is_twos_complement /* Ignored */,
          0,
          first_mult_bit_input_index + 1,
          value_two_party_index,
          value_two_input_index,
          1,
          max_num_input_bits,
          &second_input_mult)) {
    LOG_ERROR("Failed to pick out the second input.");
    return false;
  }

  // Make sure output has the appropriate number of bits. See comment above.
  StandardCircuit<bool>* second_input_w_correct_num_bits = nullptr;
  if (num_one_input_bits > num_two_input_bits) {
    DataType output_type;
    if (!GetIntegerDataType(true, max_num_input_bits, &output_type)) {
      return false;
    }
    // Construct identity circuit for second input.
    StandardCircuit<bool> input_two;
    if (!ConstructIdentityCircuit(
            false,
            two_is_twos_complement,
            value_two_party_index,
            value_two_input_index,
            num_two_input_bits,
            &input_two)) {
      LOG_ERROR("Failed to ConstructIdentityCircuit");
      return false;
    }
    // Overwrite some of input_two's fields.
    input_two.num_outputs_ = 1;
    DataType output_two_type;
    if (!GetIntegerDataType(
            two_is_twos_complement,
            (int) num_two_input_bits,
            &output_two_type)) {
      return false;
    }
    input_two.output_designations_.clear();
    input_two.output_designations_.resize(
        1, make_pair(OutputRecipient(), output_two_type));
    input_two.function_description_.clear();
    input_two.function_description_.resize(1);
    Formula& formula_two = input_two.function_description_[0];
    formula_two.op_.type_ = OperationType::BOOLEAN;
    formula_two.op_.gate_op_ = BooleanOperation::IDENTITY;
    const string var_str_two =
        "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
    formula_two.value_ = GenericValue(var_str_two);

    // Fill it out to the appropriate number of output bits, with the leading bit
    // being 0-padded or replicating leading bit of input_one, as appropriate.
    if (!CastCircuitOutputAsMoreBits(
            two_is_twos_complement, (int) num_one_input_bits, &input_two)) {
      return false;
    }

    // Join with second_input_mult.
    output_to_input.clear();
    for (int j = 0; j < max_num_input_bits; ++j) {
      set<pair<int, pair<uint64_t, uint64_t>>>& join_input_mapping =
          output_to_input
              .insert(make_pair(j, set<pair<int, pair<uint64_t, uint64_t>>>()))
              .first->second;
      join_input_mapping.insert(
          make_pair(value_two_party_index, make_pair(value_two_input_index, j)));
    }
    if (!JoinCircuits(output_to_input, input_two, second_input_mult, &temp)) {
      LOG_ERROR("Unable to construct second_input_w_correct_num_bits.");
      return false;
    }
    second_input_w_correct_num_bits = &temp;
  } else {
    second_input_w_correct_num_bits = &second_input_mult;
  }

  // Merge these circuits.
  StandardCircuit<bool> two_products;
  if (!MergeCircuits(
          true,
          BooleanOperation::IDENTITY,
          *first_input_w_correct_num_bits,
          *second_input_w_correct_num_bits,
          &two_products)) {
    LOG_ERROR("Unable to MergeCircuits.");
    return false;
  }

  // Create a circuit that ADDs two values (actually, since one of the values
  // will be '0', it will be faster to do bitwise-OR).
  StandardCircuit<bool> add;
  if (!ConstructBooleanCircuit(
          BooleanOperation::OR, false, max_num_input_bits, &add)) {
    LOG_ERROR("Failed to construct add circuit.");
    return false;
  }

  // Join the two_products circuit with the circuit that adds their outputs.
  StandardCircuit<bool> chosen_value;
  if (!JoinCircuits(two_products, add, &chosen_value)) {
    LOG_ERROR("Failed to JoinCircuits.");
    return false;
  }

  // Finally, join lt_and_not_lt_w_two_outputs and chosen_value.
  output_to_input.clear();
  set<pair<int, pair<uint64_t, uint64_t>>>& lt_wire_mapping =
      output_to_input
          .insert(make_pair(0, set<pair<int, pair<uint64_t, uint64_t>>>()))
          .first->second;
  lt_wire_mapping.insert(make_pair(0, make_pair(first_mult_bit_input_index, 0)));
  set<pair<int, pair<uint64_t, uint64_t>>>& not_lt_wire_mapping =
      output_to_input
          .insert(make_pair(1, set<pair<int, pair<uint64_t, uint64_t>>>()))
          .first->second;
  not_lt_wire_mapping.insert(
      make_pair(0, make_pair(first_mult_bit_input_index + 1, 0)));
  if (!JoinCircuits(
          output_to_input, lt_and_not_lt_w_two_outputs, chosen_value, min_a_b)) {
    LOG_ERROR("Failed to join circuit.");
    return false;
  }

  // We determine the output DataType as follows:
  //   - If one_is_twos_complement == two_is_twos_complement,
  //     use Signed vs. Unsigned according to them
  //   - Otherwise, there is no definitive way to know which one to take,
  //     since this function just builds the circuit, and is independent
  //     of the actual inputs, so there is no way to know which DataType
  //     to respect. We default to use the Signed DataType, and hope the
  //     user knows that when comparing a Signed vs. Unsigned, that the
  //     unsigned value lies in the bottom half of its max range.
  const bool same_signed_type = one_is_twos_complement == two_is_twos_complement;
  DataType type;
  if (!GetIntegerDataType(
          same_signed_type ? one_is_twos_complement : true,
          max_num_input_bits,
          &type)) {
    return false;
  }
  const int64_t num_bits_in_min = GetValueNumBits(type);

  // Actually, our convention is to have the min/max *value* be the first
  // output, and the characteristic vector be the next n outputs. However,
  // the above circuit reverses this, so that the min/max value is the
  // *last* output. Change this (just need to cycle through each gate's
  // output_wire_locations_, and update the indices of the global output wires).
  for (StandardCircuitLevel<bool>& level : min_a_b->levels_) {
    for (StandardGate<bool>& gate : level.gates_) {
      bool is_global_output_gate = false;
      for (const WireLocation& output_wire : gate.output_wire_locations_) {
        if (output_wire.loc_.level_ == -1) {
          is_global_output_gate = true;
          break;
        }
      }
      if (is_global_output_gate) {
        const set<WireLocation> copied_outputs = gate.output_wire_locations_;
        gate.output_wire_locations_.clear();
        for (const WireLocation& output_wire : copied_outputs) {
          if (output_wire.loc_.level_ == -1) {
            const int64_t orig_index = output_wire.loc_.index_;
            const int64_t toggle = orig_index < 2 ? num_bits_in_min : -2;
            gate.output_wire_locations_.insert(
                WireLocation(-1, orig_index + toggle));
          } else {
            gate.output_wire_locations_.insert(output_wire);
          }
        }
      }
    }
  }

  // Need to update the function_description_ and output_designations_.
  min_a_b->function_description_.clear();
  min_a_b->output_designations_.clear();
  min_a_b->num_outputs_ = 3;
  min_a_b->output_designations_.resize(3);
  min_a_b->output_designations_[0] = make_pair(OutputRecipient(), type);
  min_a_b->output_designations_[1] =
      make_pair(OutputRecipient(), DataType::BOOL);
  min_a_b->output_designations_[2] =
      make_pair(OutputRecipient(), DataType::BOOL);
  min_a_b->function_description_.resize(3);
  Formula& formula = min_a_b->function_description_[0];
  formula.op_.type_ = OperationType::ARITHMETIC;
  formula.op_.arithmetic_op_ =
      is_min ? ArithmeticOperation::MIN : ArithmeticOperation::MAX;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_one =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  formula.subterm_one_->value_ = GenericValue(var_one);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_two =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.subterm_two_->value_ = GenericValue(var_two);
  Formula& formula_two = min_a_b->function_description_[1];
  formula_two.op_.type_ = OperationType::COMPARISON;
  formula_two.op_.comparison_op_ = first_op;
  formula_two.subterm_one_.reset(new Formula());
  formula_two.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula_two.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula_two.subterm_one_->value_ = GenericValue(var_one);
  formula_two.subterm_two_.reset(new Formula());
  formula_two.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula_two.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula_two.subterm_two_->value_ = GenericValue(var_two);
  Formula& formula_three = min_a_b->function_description_[2];
  formula_three.op_.type_ = OperationType::COMPARISON;
  const ComparisonOperation second_op = is_min ?
      (kArgminBreakTiesTakeFirst ? ComparisonOperation::COMP_GT :
                                   ComparisonOperation::COMP_GTE) :
      (kArgminBreakTiesTakeFirst ? ComparisonOperation::COMP_LT :
                                   ComparisonOperation::COMP_LTE);
  formula_three.op_.comparison_op_ = second_op;
  formula_three.subterm_one_.reset(new Formula());
  formula_three.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula_three.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula_three.subterm_one_->value_ = GenericValue(var_one);
  formula_three.subterm_two_.reset(new Formula());
  formula_three.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula_three.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula_three.subterm_two_->value_ = GenericValue(var_two);

  ReduceCircuit(false, min_a_b);

  return true;
}

// The POWER circuit will limit the number of bits in the exponent to 6
// (since 2^6 = 64, and 64 is the largest exponent we allow). If the
// exponent DataType has 8 or more bits, we just look at the trailing
// 6 bits. In particular, update the (identity?) circuit for the
// expononent, limiting the number of output bits (wires) to 6.
void ModifyPowerCircuit(StandardCircuit<bool>* circuit) {
  const int64_t num_output_wires_to_remove = circuit->num_output_wires_ - 6;
  circuit->num_output_wires_ = 6;
  int64_t num_output_wires_removed = 0;
  // Go through all gates of the circuit, checking if they are a (global)
  // output gate, and if so, removing it as an output wire if the output
  // wire index is more than 6 (or '5', since we use 0-based indexing).
  // For performance, we go through the circuit *backwards*, since the
  // output wires are more likely to be at the bottom.
  for (int64_t level = circuit->depth_ - 1; level >= 0; --level) {
    StandardCircuitLevel<bool>& current_level = circuit->levels_[level];
    for (int64_t gate = current_level.num_gates_ - 1; gate >= 0; --gate) {
      StandardGate<bool>& current_gate = current_level.gates_[gate];
      set<WireLocation> to_remove;
      for (const WireLocation& output_wire :
           current_gate.output_wire_locations_) {
        if (output_wire.loc_.level_ == -1 && output_wire.loc_.index_ >= 6) {
          to_remove.insert(output_wire);
        }
      }
      for (const WireLocation& remove_wire : to_remove) {
        current_gate.output_wire_locations_.erase(remove_wire);
      }
      num_output_wires_removed += to_remove.size();
      if (num_output_wires_removed >= num_output_wires_to_remove) break;
    }
    if (num_output_wires_removed >= num_output_wires_to_remove) break;
  }
}

// Recurses through formula (in order), picking out the leaf values, which
// corresond to the variables that the min/max is taken over.
bool GetMinOrMaxVars(const Formula* input, vector<GenericValue>* vars) {
  // If 'leaf' value, push into 'vars' and return.
  if (input->op_.type_ == OperationType::BOOLEAN &&
      input->op_.gate_op_ == BooleanOperation::IDENTITY) {
    vars->push_back(input->value_);
    return true;
  }

  // Not a leaf value. First, sanity-check op type.
  if (input->op_.type_ != OperationType::ARITHMETIC ||
      (input->op_.arithmetic_op_ != ArithmeticOperation::MIN &&
       input->op_.arithmetic_op_ != ArithmeticOperation::ARGMIN &&
       input->op_.arithmetic_op_ != ArithmeticOperation::ARGMIN_INTERNAL &&
       input->op_.arithmetic_op_ != ArithmeticOperation::MAX &&
       input->op_.arithmetic_op_ != ArithmeticOperation::ARGMAX &&
       input->op_.arithmetic_op_ != ArithmeticOperation::ARGMAX_INTERNAL) ||
      input->subterm_one_ == nullptr || input->subterm_two_ == nullptr) {
    LOG_ERROR("Unexpected left_circuit formula: " + GetFormulaString(*input));
    return false;
  }

  // Recurse down left-subterm, then right-subterm.
  return (
      GetMinOrMaxVars(input->subterm_one_.get(), vars) &&
      GetMinOrMaxVars(input->subterm_two_.get(), vars));
}

// Used to help distinguish the use-case of moving a gate, so we know
// how to update the circuit.
enum MoveGateCase {
  REMOVE_GATE,
  MERGE_GATE,
  FLATTEN_GATE,
  REDUCE_SINGLE_INPUT_GATE
};

// Move (or Remove) a gate. There are three use-cases that are all handled here:
//   1) Remove the gate
//   2) Merge the gate with a gate at a lower level or same level but lower index
//   3) Move the gate from its current level to a lower level, specifically, add it
//      as a *new* gate (added at the end, so highest index) to the target level.
//      This case further subdivides based on *why* the gate is being moved:
//        a) Flatten: The gate's input wires came from gates that were both
//           at least two levels above the gate's current location;
//        b) Single-Input: A single input gate (that can't otherwise be removed;
//           see discussion above RemoveSingleInputGate()) will be moved
//           to the same level as its parent (only one parent, since it is
//           single input).
// Regarding Identifying which Use-Case is being called: It used to be the case
// that the MoveGateCase parameter was *not* part of the input to MoveGate();
// however, I needed to distinguish Case (3a) from (3b), which was not possible
// to discern from the (previous) parameters; so now the use-case is explicitly
// provided as a parameter. But, the following should still be true anyway:
//   - Use-Case (1) if to_level and to_index equal -1.
//   - Use-Case (2) if to_index is less than output->levels_[to_level].size().
//   - Use-Case (3) if to_index equals output->levels_[to_level].size().
// So, what does this function actually do?:
//   A) Update input/output wire mappings of the gate being (re)moved:
//       - For use-case (1): the caller should have already done this
//       - For use-case (2): The present function will take care of:
//           i) Adding the current gate's output wires to the output wires of
//              the gate it is being merged with;
//          ii) Moving the current gate's parents' output wires to point to
//              the duplicate gate instead of the current gate
//       - For use-case (3a): The present function will take care of:
//           i) Updating the current gate's input wires from the sets of its
//              parent(s) output wires, reflecting this gate's new position
//         NOTE: Nothing needs to be done with this gate's output wires,
//         unless moving this gate to a lower level means that there aren't
//         any other gates left on its original level, in which case
//         the entire level is removed, which shifts the output wiring
//         for not just this gate, but for *all* gates that had an output
//         wire going to a level below the one that is getting removed.
//         Removing a level (and updating all output wirings) is handled here.
//       - For use-case (3b): The wirings of this gate are not touched
//         (they were already updated in RemoveSingleInputGate())
//      See also item (F) below, which discusses how updated wirings are
//      relayed to gate_to_[left | right]_input for all of the other gates
//      that may be affected by the present gate's (re)moving.
//   B) Update all other output wire mappings that are affected by this gate
//      being (re)moved; namely, these will be the output wires that map to
//      gates that are:
//        - On the same level as the (re)moved gate, and with a higher index; OR
//        - On a higer level as the (re)moved gate, in the case that the
//          (re)moved gate is the *only* gate on its level.
//   C) Updates StandardCircuit.levels_ and StandardCircuitLevel.gates_,
//      including the StandardCircuitLevel level_ and num_gates_ fiels and
//      the StandardGate.loc_ field, to reflect the new indexing as a result
//      of (re)moving the gate
//   D) Updates the additional StandardCircuit fields, as appropriate:
//        depth_, size_
//   E) In the case of Use-Case (1), this function will check if the gate
//      being removed was the *only* output wire of either of its parents,
//      and if so, it will (recusively) call MoveGate() on its parent.
//   F) Updates the passed-in parameters:
//        level_had_one_gate, gate_to_[left | right]_input
//      Regarding the latter: There are two kinds of changes that may need
//      to be made to gate_to_[left | right]_input:
//        i) Gates directly affected by the (re)moved gate. Namely, the gate
//           itself, and the gates at the other end of its input/output wires.
//       ii) For any gate that received a new index due to (re)moving the
//           current gate, we'll need to update all of their children's
//           entry in gate_to_[left | right]_input so that these gates'
//           new location is updated. Specifically, the entries that will
//           need to be modified are the children of gates whose position
//           was modified (and note that the parent's position is modified
//           iff the parent was on the same level with a higher index than
//           the (re)moved gate, or if the (re)moved gate was the only gate
//           on its level (so the whole level is deleted), and then all gates
//           at a higher level will have their level shifted one).
//       Specifically, the following changes are made to gate_to_[left | right]_input
//         a) For use-case (1): Only need to make changes as per F.ii.
//         b) For use-case (2): The changes as per F.ii should be done.
//            Additionally, in terms of F.i, the children of the moved gate will
//            have their entries of gate_to_[left | right]_input updated to
//            reflect the moved gate's new location. Notice that the entries
//            of gate_to_[left | right]_input corresponding to the gate itself
//            and its parents don't need to be modified, since the parent's
//            input mappings remain valid, and the gate itself's input mappings
//            are irrelevant (the gate is effectively being removed).
//         c) For use-case (3): The changes as per F.ii should be done.
//            Additionally, in terms of F.i, there are two additonal
//            changes that will be made to gate_to_[left | right]_input:
//              i) The *new* gate being added needs an entry in
//                 gate_to_[left | right]_input. This will simply copy the
//                 the entry of gate_to_[left | right]_input for the gate
//                 being moved
//             ii) Each gate that is an output wire of the gate being moved
//                 will have a new input location: moved from
//                 (from_level, from_index) to (to_level, to_index)
// The 'maintain_ordering' flag is only used for Use-Cases (2) and (3) (use-case
// (1) sets it to 'true', but it is ignored), and it specifies that for all wires
// that lead to the gate being moved, if they should maintain their left/right status
// when they get moved/added as an output wire of the '(to_level, to_index)' gate,
// or whether their ordering should be flipped (this can happen e.g. in the
// DeduplicateGates case, where the duplicate gate actually has it's wires
// in flipped from its duplicate, but the GateOperation is symmetric).
void MoveGate(
    const MoveGateCase use_case,
    const bool maintain_ordering,
    const uint64_t& from_level,
    const uint64_t& from_index,
    const int64_t& to_level,
    const int64_t& to_index,
    bool* level_had_one_gate,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input,
    StandardCircuit<bool>* output) {
  // Sanity check input.
  if (!((to_level == -1 && to_index == -1) ||
        (to_level >= 0 && to_index >= 0 && (int64_t) from_level >= to_level &&
         ((int64_t) from_level > to_level ||
          (int64_t) from_index > to_index)))) {
    LOG_FATAL(
        "From (" + Itoa(from_level) + ", " + Itoa(from_index) + ") to (" +
        Itoa(to_level) + ", " + Itoa(to_index) + ")");
  }

  // Sanity check API is consistent with from/to index.
  const bool is_api_one = use_case == MoveGateCase::REMOVE_GATE;
  const bool is_api_two = use_case == MoveGateCase::MERGE_GATE;
  const bool is_api_three = use_case == MoveGateCase::FLATTEN_GATE ||
      use_case == MoveGateCase::REDUCE_SINGLE_INPUT_GATE;
  if (is_api_one && (to_level != -1 || to_index != -1)) {
    LOG_FATAL(
        "From (" + Itoa(from_level) + ", " + Itoa(from_index) + ") to (" +
        Itoa(to_level) + ", " + Itoa(to_index) + ")");
  }
  if (is_api_two &&
      (to_level < 0 || to_index < 0 ||
       (int64_t) output->levels_.size() <= to_level ||
       (int64_t) output->levels_[to_level].gates_.size() <= to_index)) {
    LOG_FATAL(
        "From (" + Itoa(from_level) + ", " + Itoa(from_index) + ") to (" +
        Itoa(to_level) + ", " + Itoa(to_index) + ")");
  }
  if (is_api_three &&
      (to_level < 0 || to_index < 0 ||
       (int64_t) output->levels_.size() <= to_level ||
       (int64_t) output->levels_[to_level].gates_.size() != to_index)) {
    LOG_FATAL(
        "From (" + Itoa(from_level) + ", " + Itoa(from_index) + ") to (" +
        Itoa(to_level) + ", " + Itoa(to_index) + ")");
  }

  // Grab some information that will be needed below.
  *level_had_one_gate = output->levels_[from_level].gates_.size() == 1;
  StandardGate<bool>& current_gate =
      output->levels_[from_level].gates_[from_index];
  const GateLocation& left_parent =
      (*((*gate_to_left_input)[from_level]))[from_index];
  const GateLocation& right_parent =
      (*((*gate_to_right_input)[from_level]))[from_index];

  // For Use-Cases (2) and (3a), update this gate's parent(s) output wires to point
  // to this gate's new location. This is (part of) item (A) from comments at top.
  // NOTE: We don't do this for (3b), because this gate's parent's output wire
  // was already handled in RemoveSingleInputGate().
  if (is_api_two || use_case == MoveGateCase::FLATTEN_GATE) {
    if (left_parent.level_ != -1) {
      ChangeOutputWireLocation(
          WireLocation(from_level, from_index, true),
          WireLocation(to_level, to_index, maintain_ordering),
          left_parent,
          output);
    }
    if (right_parent.level_ != -1) {
      ChangeOutputWireLocation(
          WireLocation(from_level, from_index, false),
          WireLocation(to_level, to_index, !maintain_ordering),
          right_parent,
          output);
    }
  }

  // For Use-Case (2) (Merge gate with its duplicate), add this gate's output
  // wires to the set of output wires of its duplicate gate (as per item (A)).
  // Also, update gate_to_[left | right]_input, as per item (F.i).
  if (is_api_two) {
    StandardGate<bool>& duplicate_gate =
        output->levels_[to_level].gates_[to_index];
    for (const WireLocation& wire : current_gate.output_wire_locations_) {
      duplicate_gate.output_wire_locations_.insert(wire);
      if (wire.loc_.level_ >= 0) {
        if (wire.is_left_) {
          (*((*gate_to_left_input)[wire.loc_.level_]))[wire.loc_.index_] =
              GateLocation(to_level, to_index);
        } else {
          (*((*gate_to_right_input)[wire.loc_.level_]))[wire.loc_.index_] =
              GateLocation(to_level, to_index);
        }
      }
    }
  }

  // For Use-Case (3) (Move gate to last gate at an earlier level), update
  // the gate's loc_ field to indicate its new position.
  // Also, in case the gate being moved is the only gate on its level
  // (so that all levels get shifted up), the output wires of this gate
  // need to be updated, to reflect a level one less than they were
  // previously (this is also true of all other gates, but all other gates
  // have logic below to handle this; this is the unique gate that will
  // need to do this manually).
  // Also, update gate_to_[left | right]_input, as per item (F.i).
  if (is_api_three) {
    current_gate.loc_ = GateLocation(to_level, to_index);
    // Add an entry for the new gate's input wires, as per item (F.c.i)
    ((*gate_to_left_input)[to_level])
        ->push_back((*((*gate_to_left_input)[from_level]))[from_index]);
    ((*gate_to_right_input)[to_level])
        ->push_back((*((*gate_to_right_input)[from_level]))[from_index]);
    // Update all gates at the output wires, indicating new position
    // of their input wires (as per item F.c.ii).
    for (const WireLocation& wire : current_gate.output_wire_locations_) {
      if (wire.loc_.level_ >= 0) {
        if (wire.is_left_) {
          (*((*gate_to_left_input)[wire.loc_.level_]))[wire.loc_.index_] =
              GateLocation(to_level, to_index);
        } else {
          (*((*gate_to_right_input)[wire.loc_.level_]))[wire.loc_.index_] =
              GateLocation(to_level, to_index);
        }
      }
    }
    if (*level_had_one_gate) {
      const set<WireLocation> old_outputs = current_gate.output_wire_locations_;
      current_gate.output_wire_locations_.clear();
      for (const WireLocation& old_loc : old_outputs) {
        if (old_loc.loc_.level_ == -1) {
          // Preserve old global output locations.
          current_gate.output_wire_locations_.insert(old_loc);
        } else {
          current_gate.output_wire_locations_.insert(WireLocation(
              old_loc.loc_.level_ - 1, old_loc.loc_.index_, old_loc.is_left_));
        }
      }
    }
  }

  // Update all affected output wire mappings (Step (B)):
  //   - All gates on the same level as the gate being (re)moved and with
  //     a higher index than this gate will now have their index offset by -1
  //   - If the gate being (re)moved is the *only* gate on its level, then
  //     all gates on a higher level will have their level offset by -1.
  // Also, update gate_to_[left | right]_input while we're at it (Step (F.ii)).
  if (*level_had_one_gate) {
    for (uint64_t level = from_level + 1; level < output->levels_.size();
         ++level) {
      (*gate_to_left_input)[level - 1] = (*gate_to_left_input)[level];
      (*gate_to_right_input)[level - 1] = (*gate_to_right_input)[level];
      for (uint64_t gate = 0; gate < output->levels_[level].gates_.size();
           ++gate) {
        const GateLocation& current_left_parent =
            (*((*gate_to_left_input)[level]))[gate];
        const GateLocation& current_right_parent =
            (*((*gate_to_right_input)[level]))[gate];
        // Update the output wires for this gate's parents, reflecting the
        // fact that this gate will now be on a level index that is one less
        // than before (since a level is being removed from the circuit).
        // NOTE: We don't do this if the parent gate is:
        //   - Undefined. I.e. the gate is a single-operation gate.
        //   - The gate being moved, and use-case is (3). This is because
        //     the output wires of the parent were manually updated
        //     appropriately above.
        if (current_left_parent.level_ != -1 &&
            (!is_api_three || current_left_parent.level_ != to_level ||
             current_left_parent.index_ != to_index)) {
          ChangeOutputWireLocation(
              WireLocation(level, gate, true),
              WireLocation(level - 1, gate, true),
              current_left_parent,
              output);
        }
        if (current_right_parent.level_ != -1 &&
            (!is_api_three || current_right_parent.level_ != to_level ||
             current_right_parent.index_ != to_index)) {
          ChangeOutputWireLocation(
              WireLocation(level, gate, false),
              WireLocation(level - 1, gate, false),
              current_right_parent,
              output);
        }
      }
    }
    // Now update gate_to_[left | right]_input.
    // Stop the loop one early, because gate_to_[left | right]_input has
    // all entries shifted; so in particular, the previous last entry
    // is now in (both) the last entry, as well as the entry before that
    // (the one in the last entry gets removed below, but as of now, it's
    // still there). If we don't stop one early, stuff in the last entry
    // gets hit twice.
    for (uint64_t level = from_level + 1; level < output->levels_.size() - 1;
         ++level) {
      vector<GateLocation>* left_indices = (*gate_to_left_input)[level];
      for (GateLocation& location : *left_indices) {
        if (location.level_ > (int64_t) from_level) --(location.level_);
      }
      vector<GateLocation>* right_indices = (*gate_to_right_input)[level];
      for (GateLocation& location : *right_indices) {
        if (location.level_ > (int64_t) from_level) --(location.level_);
      }
    }
    gate_to_left_input->pop_back();
    gate_to_right_input->pop_back();
  } else {
    for (uint64_t gate = from_index + 1;
         gate < output->levels_[from_level].gates_.size();
         ++gate) {
      (*((*gate_to_left_input)[from_level]))[gate - 1] =
          (*((*gate_to_left_input)[from_level]))[gate];
      (*((*gate_to_right_input)[from_level]))[gate - 1] =
          (*((*gate_to_right_input)[from_level]))[gate];
      const GateLocation& current_left_parent =
          (*((*gate_to_left_input)[from_level]))[gate];
      const GateLocation& current_right_parent =
          (*((*gate_to_right_input)[from_level]))[gate];
      if (current_left_parent.level_ != -1) {
        ChangeOutputWireLocation(
            WireLocation(from_level, gate, true),
            WireLocation(from_level, gate - 1, true),
            current_left_parent,
            output);
      }
      if (current_right_parent.level_ != -1) {
        ChangeOutputWireLocation(
            WireLocation(from_level, gate, false),
            WireLocation(from_level, gate - 1, false),
            current_right_parent,
            output);
      }
    }
    // Update input mappings for all gates whose input(s) come from
    // the same level (with higher index) as the gate that is being
    // (re)moved: The input mappings should subtract '1' from the
    // location index, reflecting the fact that all the gates on
    // the same level as the (re)moved gate get shifted, so their
    // index is reduced by one.
    // NOTE: Rather than iterating through all mappings, it will
    // be faster to work the other way around: start with gates
    // on the same level as the gate being (re)moved (that have
    // higher index), and use the output wires of those gates to
    // determine which target gates will need to have their inputs updated.
    const StandardCircuitLevel<bool>& removed_gates_level =
        output->levels_[from_level];
    for (size_t gate = from_index + 1; gate < removed_gates_level.gates_.size();
         ++gate) {
      const StandardGate<bool>& higher_index_gate =
          removed_gates_level.gates_[gate];
      for (const WireLocation& output_wire :
           higher_index_gate.output_wire_locations_) {
        // Global output wires don't have an entry in gate_to_[left | right]_input.
        if (output_wire.loc_.level_ < 0) continue;
        if (output_wire.is_left_) {
          --((*((*gate_to_left_input)[output_wire.loc_.level_]))[output_wire.loc_
                                                                     .index_]
                 .index_);
        } else {
          --((*((*gate_to_right_input)[output_wire.loc_
                                           .level_]))[output_wire.loc_.index_]
                 .index_);
        }
      }
    }
    (*gate_to_left_input)[from_level]->resize(
        (*gate_to_left_input)[from_level]->size() - 1);
    (*gate_to_right_input)[from_level]->resize(
        (*gate_to_right_input)[from_level]->size() - 1);
  }

  // Now go through circuit, updating location of gates.
  int64_t start_gate_index = from_index;
  const size_t stop_level =
      *level_had_one_gate ? output->levels_.size() : from_level + 1;
  for (uint64_t level = from_level; level < stop_level; ++level) {
    if (*level_had_one_gate && level > from_level) {
      output->levels_[level - 1].gates_.resize(
          output->levels_[level].gates_.size());
      output->levels_[level - 1].num_gates_ =
          output->levels_[level].gates_.size();
    }
    for (uint64_t gate = start_gate_index;
         gate < output->levels_[level].gates_.size();
         ++gate) {
      // Move this gate, if appropriate.
      if (level == from_level) {
        // If this is the gate to move, move it.
        if (gate == from_index) {
          if (is_api_one || is_api_two) {
            // This gate is being removed or merged. Update the number of gates.
            --output->size_;
          } else if (is_api_three) {
            // Modify gate's loc_ field.
            output->levels_[from_level].gates_[from_index].loc_ =
                GateLocation(to_level, to_index);
            // Move gate.
            output->levels_[to_level].gates_.push_back(
                output->levels_[from_level].gates_[from_index]);
            ++(output->levels_[to_level].num_gates_);
          }
        } else {
          // This gate is on the far side of the gate that was (re)moved; toggle
          // it's index by reducing it by one.
          --(output->levels_[from_level].gates_[gate].loc_.index_);
          output->levels_[from_level].gates_[gate - 1] =
              output->levels_[from_level].gates_[gate];
        }
      } else {
        // Move this gate to a lower level.
        --(output->levels_[level].gates_[gate].loc_.level_);
        output->levels_[level - 1].gates_[gate] =
            output->levels_[level].gates_[gate];
      }
    }

    // Resize this level by removing the last gate, if appropriate.
    if (level == from_level && !(*level_had_one_gate)) {
      output->levels_[level].gates_.resize(
          output->levels_[level].gates_.size() - 1);
      --output->levels_[level].num_gates_;
    }

    start_gate_index = 0;
  }

  // We already moved all gates, but in the case a level was removed, everything
  // got shifted up a level, but we still need to delete the last level.
  if (*level_had_one_gate) {
    output->levels_.resize(output->levels_.size() - 1);
    --output->depth_;
  }
}

// This gate's input wires are both constants. Proceed as follows:
//   0) Precompute the output value of this gate, which is either '0' or '1'
//      (this is possible, because both inputs are global inputs, and
//      thus we know each input wire's value, and we know the gate op).
//   1) For all non-global outputs:
//      a) Remove them from the set of outputs of the current gate
//      b) Add them to the output wires of either global constant '0' or '1',
//         as per Step (0) above.
//      c) Update gate_to_left_input (resp. gate_to_right_input) to reflect
//         that their input wire now comes directly from a global (constant) input
//   2) If all outputs are non-global, mark the gate to be removed (return true)
//   3) Otherwise, don't do anything with global output wires (i.e. return false),
//      but update the gate type to be IDENTITY (on the appropriate global
//      constant input, as per Step (0) above).
//      Note that in this case, since all non-global output wires were removed
//      in Step (2a) above, the gate now has only global outputs.
//      NOTE: The reason we don't simply remove the gate, and rely on
//      the constant_[one | zero]_input_ fields to specify a (global) output
//      wire as its destination, is because: even though this could work in
//      the context of already having a StandardCircuit object, it doesn't
//      work in the context of reading/writing circuits to file (which is the
//      ultimate output of the circuit_builder_utils code), since circuit files
//      have no way to handle/express inputs that go directly as outputs, other
//      than introducing an IDENTIY gate for them to pass through.
bool RemoveConstantGate(
    StandardGate<bool>& gate,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input,
    StandardCircuit<bool>* output) {
  // Update num_non_local_gates_, if necessary (in theory, this field should
  // be accurate/up-to-date before the call to this function; but, other
  // circuit reductions may have made this gate get its inputs directly from
  // (global) constant inputs, and failed to update the gate type.
  if (gate.depends_on_.size() > 1) {
    --(output->num_non_local_gates_);
  }
  gate.depends_on_.clear();

  // Find the parents: should be an output wire of either be a global zero or one.
  const bool left_input_is_constant_zero =
      output->constant_zero_input_.find(
          WireLocation(gate.loc_.level_, gate.loc_.index_, true)) !=
      output->constant_zero_input_.end();
  const bool left_input_is_constant_one =
      output->constant_one_input_.find(
          WireLocation(gate.loc_.level_, gate.loc_.index_, true)) !=
      output->constant_one_input_.end();
  const bool right_input_is_constant_zero =
      output->constant_zero_input_.find(
          WireLocation(gate.loc_.level_, gate.loc_.index_, false)) !=
      output->constant_zero_input_.end();
  const bool right_input_is_constant_one =
      output->constant_one_input_.find(
          WireLocation(gate.loc_.level_, gate.loc_.index_, false)) !=
      output->constant_one_input_.end();
  if (left_input_is_constant_zero == left_input_is_constant_one ||
      right_input_is_constant_zero == right_input_is_constant_one) {
    LOG_FATAL("Left and/or Right input should come from exactly one of "
              "constant '0' or constant '1' global inputs.");
  }

  // Figure out what the output value of this gate should be.
  bool output_value = false;
  if (gate.type_ == BooleanOperation::OR) {
    output_value = left_input_is_constant_one || right_input_is_constant_one;
  } else if (gate.type_ == BooleanOperation::NOR) {
    output_value = left_input_is_constant_zero && right_input_is_constant_zero;
  } else if (gate.type_ == BooleanOperation::XOR) {
    output_value = left_input_is_constant_zero != right_input_is_constant_zero;
  } else if (gate.type_ == BooleanOperation::AND) {
    output_value = left_input_is_constant_one && right_input_is_constant_one;
  } else if (gate.type_ == BooleanOperation::NAND) {
    output_value = left_input_is_constant_zero || right_input_is_constant_zero;
  } else if (gate.type_ == BooleanOperation::EQ) {
    output_value = left_input_is_constant_zero == right_input_is_constant_zero;
  } else if (gate.type_ == BooleanOperation::GT) {
    output_value = left_input_is_constant_one && right_input_is_constant_zero;
  } else if (gate.type_ == BooleanOperation::GTE) {
    output_value = left_input_is_constant_one || right_input_is_constant_zero;
  } else if (gate.type_ == BooleanOperation::LT) {
    output_value = left_input_is_constant_zero && right_input_is_constant_one;
  } else if (gate.type_ == BooleanOperation::LTE) {
    output_value = left_input_is_constant_zero || right_input_is_constant_one;
  } else {
    LOG_FATAL("Unexpected Gate Type: " + GetOpString(gate.type_));
  }

  // If any of the output wires of this gate are global outputs, we'll
  // keep this gate around, but make it so that *all* of its outputs
  // are global outputs. For all of the non-global outputs, update the
  // target gates so that their input comes from the appropriate global
  // constant input, as opposed to as an output of this gate.
  bool has_global_output = false;
  const set<WireLocation> output_wires = gate.output_wire_locations_;
  for (const WireLocation& wire : output_wires) {
    if (wire.loc_.level_ == -1) {
      has_global_output = true;
    } else {
      gate.output_wire_locations_.erase(wire);
      if (output_value) {
        output->constant_one_input_.insert(wire);
      } else {
        output->constant_zero_input_.insert(wire);
      }
      if (wire.is_left_) {
        (*((*gate_to_left_input)[wire.loc_.level_]))[wire.loc_.index_] =
            GateLocation(output_value ? -3 : -2, 0);
      } else {
        (*((*gate_to_right_input)[wire.loc_.level_]))[wire.loc_.index_] =
            GateLocation(output_value ? -3 : -2, 0);
      }
    }
  }

  // If none of the output wires are global outputs, the current gate can
  // be removed. In this case, we need to remove the current gate as
  // an output wire of its parent(s).
  // Actually, even if the gate is *not* being removed, we're going to
  // update its input wires anyway, so that the gate will have the
  // IDENTITY operation on the appropriate global constant 0/1 input.
  if (left_input_is_constant_zero) {
    output->constant_zero_input_.erase(
        WireLocation(gate.loc_.level_, gate.loc_.index_, true));
  } else {
    output->constant_one_input_.erase(
        WireLocation(gate.loc_.level_, gate.loc_.index_, true));
  }
  if (right_input_is_constant_zero) {
    output->constant_zero_input_.erase(
        WireLocation(gate.loc_.level_, gate.loc_.index_, false));
  } else {
    output->constant_one_input_.erase(
        WireLocation(gate.loc_.level_, gate.loc_.index_, false));
  }

  // Change input mappings for this gate: This gate will either be removed
  // (in which case input mappings will be updated automatically
  // for the removed gate), or if not, it will be replaced with an
  // IDENTITY gate. In the latter case (which occurs iff this gate has
  // at least one global output), we need to update the input mappings
  // for this gate, to reflect it now has one global constant input,
  // as well as update the gate type to IDENTITY.
  if (has_global_output) {
    gate.type_ = BooleanOperation::IDENTITY;
    (*((*gate_to_left_input)[gate.loc_.level_]))[gate.loc_.index_] =
        GateLocation(-1, -1);
    (*((*gate_to_right_input)[gate.loc_.level_]))[gate.loc_.index_] =
        GateLocation(-1, -1);
    // Now, add the proper input wire.
    (*((*gate_to_left_input)[gate.loc_.level_]))[gate.loc_.index_] =
        GateLocation(output_value ? -3 : -2, 0);
    if (output_value) {
      output->constant_one_input_.insert(
          WireLocation(gate.loc_.level_, gate.loc_.index_, true));
    } else {
      output->constant_zero_input_.insert(
          WireLocation(gate.loc_.level_, gate.loc_.index_, true));
    }
  }

  return !has_global_output;
}

// Exactly one of the input wires for this gate is constant. The gate can be
// turned into an IDENTITY or NOT gate as follows:
//   - If constant is '0', then:
//       AND, GT: Then the gate can be replaced with constant '0', IDENTITY
//       NAND, LTE: Then the gate can be replaced with constant '1', IDENTITY
//       OR, XOR, LT: Then the gate can be replaced with IDENTITY of the non-constant wire
//       NOR, EQ, GTE: Then the gate can be replaced with NOT of the non-constant wire
//   - If constant is '1', then:
//       NOR, LT: Then the gate can be replaced with constant '0', IDENTITY
//       OR, GTE: Then the gate can be replaced with constant '1', IDENTITY
//       AND, EQ, LTE: Then the gate can be replaced with IDENTITY of the non-constant wire
//       NAND, XOR, GT: Then the gate can be replaced with NOT of the non-constant wire
// This function will update the gate accordingly, and take care of all wiring.
// This function will *not* do further clean-up: The gate can be further simplified,
// since it will be a single-input gate after this function call. Rather than
// process the Single-input gate here, we return to the calling function
// (RemoveConstantAndSingleInputGatesInternal), and rely on the call to
// RemoveSingleInputGate to handle it.
void SimplifyOneInputConstantGate(
    const bool constant_input_is_zero,
    const bool constant_input_is_left_input,
    const int64_t& non_constant_input_level,
    const int64_t& non_constant_input_index,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input,
    StandardGate<bool>* gate,
    StandardCircuit<bool>* output) {
  const WireLocation gate_loc_as_constant_output_wire = WireLocation(
      gate->loc_.level_, gate->loc_.index_, constant_input_is_left_input);
  const WireLocation gate_loc_as_non_constant_output_wire = WireLocation(
      gate->loc_.level_, gate->loc_.index_, !constant_input_is_left_input);
  // One of the input wires will be able to be removed. Record which one.
  bool remove_constant_input = false;
  if (constant_input_is_zero) {
    if (gate->type_ == BooleanOperation::AND ||
        (constant_input_is_left_input && gate->type_ == BooleanOperation::GT) ||
        (!constant_input_is_left_input && gate->type_ == BooleanOperation::LT)) {
      // This gate can be replaced with a constant '0' gate:
      remove_constant_input = false;
      //   1) Update gate fields.
      //        - num_non_local_gates_
      if (!gate->IsLocalGate() && gate->depends_on_.size() > 1) {
        --(output->num_non_local_gates_);
      }
      //        - type_
      gate->type_ = BooleanOperation::IDENTITY;
      //        - depends_on_. NOTE: Even though children of this
      //          gate may also need to have *their* depends_on_
      //          field updated, we don't do this now, because:
      //            a) There threatens to be a recursive nightmare, which
      //               is costly both in terms of time and code complexity;
      //            b) The children will all get updated anyway, as the
      //               ReduceCircuit works its way down through the circuit.
      gate->depends_on_.clear();
      //   2) No need to update constant zero global inputs to map to this gate,
      //      because it's already an output gate of that.
      //   3) Remove this gate as an output wire of its parents.
      //      a) No need to remove it as an output wire of global constant input
      //         zero, because we want it to remain an output of that.
      //      b) Remove it from the output wires of the non-constant parent.
      //         (Will be done below, since this code is common to all cases).
      //   4) Remove the non-constant input from gate_to_[left | right]_input
      //      (Will be done below, since this code is common to all cases).
    } else if (
        gate->type_ == BooleanOperation::NAND ||
        (constant_input_is_left_input && gate->type_ == BooleanOperation::LTE) ||
        (!constant_input_is_left_input &&
         gate->type_ == BooleanOperation::GTE)) {
      // This gate can be replaced with a constant '1' gate:
      remove_constant_input = false;
      //   1) Update gate fields.
      //        - num_non_local_gates_
      if (!gate->IsLocalGate() && gate->depends_on_.size() > 1) {
        --(output->num_non_local_gates_);
      }
      //        - type_
      gate->type_ = BooleanOperation::IDENTITY;
      //        - depends_on_.
      gate->depends_on_.clear();
      //   2) Update constant one global inputs to map to this gate.
      output->constant_one_input_.insert(gate_loc_as_constant_output_wire);
      if (constant_input_is_left_input) {
        (*((*gate_to_left_input)[gate->loc_.level_]))[gate->loc_.index_] =
            GateLocation(-3, 0);
      } else {
        (*((*gate_to_right_input)[gate->loc_.level_]))[gate->loc_.index_] =
            GateLocation(-3, 0);
      }
      //   3) Remove this gate as an output wire of its parents.
      //      a) Remove it as an output wire of global constant input zero.
      if (1 !=
          output->constant_zero_input_.erase(gate_loc_as_constant_output_wire)) {
        LOG_FATAL("Fatal Error");
      }
      //      b) Remove it from the output wires of the non-constant parent.
      //         (Will be done below, since this code is common to all cases).
      //   4) Remove the non-constant input from gate_to_[left | right]_input
      //      (Will be done below, since this code is common to all cases).
    } else if (
        gate->type_ == BooleanOperation::OR ||
        gate->type_ == BooleanOperation::XOR ||
        (constant_input_is_left_input && gate->type_ == BooleanOperation::LT) ||
        (!constant_input_is_left_input && gate->type_ == BooleanOperation::GT)) {
      // This gate can be replaced with an IDENTITY gate (on its non-constant parent):
      remove_constant_input = true;
      //   1) Update gate fields.
      //        - num_non_local_gates_.
      if (!gate->IsLocalGate() && gate->depends_on_.size() > 1) {
        --(output->num_non_local_gates_);
      }
      //        - type_
      gate->type_ = BooleanOperation::IDENTITY;
      //   2) Remove this gate as an output wire of its constant parent.
      //      (Will be done below, since this code is common to all cases).
      //   3) Remove the constant input from gate_to_[left | right]_input
      //      (Will be done below, since this code is common to all cases).
    } else if (
        gate->type_ == BooleanOperation::NOR ||
        gate->type_ == BooleanOperation::EQ ||
        (constant_input_is_left_input && gate->type_ == BooleanOperation::GTE) ||
        (!constant_input_is_left_input &&
         gate->type_ == BooleanOperation::LTE)) {
      // This gate can be replaced with an NOT gate (on its non-constant parent):
      remove_constant_input = true;
      //   1) Update gate fields.
      //        - num_non_local_gates_
      if (!gate->IsLocalGate() && gate->depends_on_.size() > 1) {
        --(output->num_non_local_gates_);
      }
      //        - type_
      gate->type_ = BooleanOperation::NOT;
      //   2) Remove this gate as an output wire of its constant parent.
      //      (Will be done below, since this code is common to all cases).
      //   3) Remove the constant input from gate_to_[left | right]_input
      //      (Will be done below, since this code is common to all cases).
    } else {
      LOG_FATAL("Unexpected GateOperation: " + GetOpString(gate->type_));
    }
  } else {
    // The constant input to this gate is '1'. Toggle based on gate type.
    if (gate->type_ == BooleanOperation::OR ||
        (constant_input_is_left_input && gate->type_ == BooleanOperation::GTE) ||
        (!constant_input_is_left_input &&
         gate->type_ == BooleanOperation::LTE)) {
      // This gate can be replaced with a constant '1' gate:
      remove_constant_input = false;
      //   1) Update gate fields.
      //        - num_non_local_gates_
      if (!gate->IsLocalGate() && gate->depends_on_.size() > 1) {
        --(output->num_non_local_gates_);
      }
      //        - type_
      gate->type_ = BooleanOperation::IDENTITY;
      //        - depends_on_.
      gate->depends_on_.clear();
      //   2) No need to update constant one global inputs to map to this gate,
      //      because it's already an output gate of that.
      //   3) Remove this gate as an output wire of its parents.
      //      a) No need to remove it as an output wire of global constant input
      //         one, because we want it to remain an output of that.
      //      b) Remove it from the output wires of the non-constant parent.
      //         (Will be done below, since this code is common to all cases).
      //   4) Remove the non-constant input from gate_to_[left | right]_input
      //      (Will be done below, since this code is common to all cases).
    } else if (
        gate->type_ == BooleanOperation::NOR ||
        (constant_input_is_left_input && gate->type_ == BooleanOperation::LT) ||
        (!constant_input_is_left_input && gate->type_ == BooleanOperation::GT)) {
      // This gate can be replaced with a constant '0' gate:
      remove_constant_input = false;
      //   1) Update gate fields.
      //        - num_non_local_gates_
      if (!gate->IsLocalGate() && gate->depends_on_.size() > 1) {
        --(output->num_non_local_gates_);
      }
      //        - type_
      gate->type_ = BooleanOperation::IDENTITY;
      //        - depends_on_.
      gate->depends_on_.clear();
      //   2) Update constant zero global inputs to map to this gate.
      output->constant_zero_input_.insert(gate_loc_as_constant_output_wire);
      if (constant_input_is_left_input) {
        (*((*gate_to_left_input)[gate->loc_.level_]))[gate->loc_.index_] =
            GateLocation(-2, 0);
      } else {
        (*((*gate_to_right_input)[gate->loc_.level_]))[gate->loc_.index_] =
            GateLocation(-2, 0);
      }
      //   3) Remove this gate as an output wire of its parents.
      //      a) Remove it as an output wire of global constant input one.
      if (1 !=
          output->constant_one_input_.erase(gate_loc_as_constant_output_wire)) {
        LOG_FATAL("Fatal Error");
      }
      //      b) Remove it from the output wires of the non-constant parent.
      //         (Will be done below, since this code is common to all cases).
      //   4) Remove the non-constant input from gate_to_[left | right]_input
      //      (Will be done below, since this code is common to all cases).
    } else if (
        gate->type_ == BooleanOperation::AND ||
        gate->type_ == BooleanOperation::EQ ||
        (constant_input_is_left_input && gate->type_ == BooleanOperation::LTE) ||
        (!constant_input_is_left_input &&
         gate->type_ == BooleanOperation::GTE)) {
      // This gate can be replaced with an IDENTITY gate (on its non-constant parent):
      remove_constant_input = true;
      //   1) Update gate fields.
      //        - num_non_local_gates_
      if (!gate->IsLocalGate() && gate->depends_on_.size() > 1) {
        --(output->num_non_local_gates_);
      }
      //        - type_
      gate->type_ = BooleanOperation::IDENTITY;
      //   2) Remove this gate as an output wire of its constant parent.
      //      (Will be done below, since this code is common to all cases).
      //   3) Remove the constant input from gate_to_[left | right]_input
      //      (Will be done below, since this code is common to all cases).
    } else if (
        gate->type_ == BooleanOperation::NAND ||
        gate->type_ == BooleanOperation::XOR ||
        (constant_input_is_left_input && gate->type_ == BooleanOperation::GT) ||
        (!constant_input_is_left_input && gate->type_ == BooleanOperation::LT)) {
      // This gate can be replaced with a NOT gate (on its non-constant parent):
      remove_constant_input = true;
      //   1) Update gate fields.
      //        - num_non_local_gates_
      if (!gate->IsLocalGate() && gate->depends_on_.size() > 1) {
        --(output->num_non_local_gates_);
      }
      //        - type_
      gate->type_ = BooleanOperation::NOT;
      //   2) Remove this gate as an output wire of its constant parent.
      //      (Will be done below, since this code is common to all cases).
      //   3) Remove the constant input from gate_to_[left | right]_input
      //      (Will be done below, since this code is common to all cases).
    } else {
      LOG_FATAL("Unexpected GateOperation: " + GetOpString(gate->type_));
    }
  }

  // Now remove this gate as an output wire of its constant or non-constant
  // parent, as per 'remove_constant_input'.
  if (remove_constant_input) {
    // Update gate_to_[left | right]_input with the removal of this input wire.
    if (constant_input_is_left_input) {
      (*((*gate_to_left_input)[gate->loc_.level_]))[gate->loc_.index_] =
          GateLocation(-1, -1);
    } else {
      (*((*gate_to_right_input)[gate->loc_.level_]))[gate->loc_.index_] =
          GateLocation(-1, -1);
    }
    // Update the appropriate set of output wires, to no longer map to this gate.
    if (constant_input_is_zero) {
      if (1 !=
          output->constant_zero_input_.erase(gate_loc_as_constant_output_wire)) {
        LOG_FATAL("Fatal Error");
      }
    } else {
      if (1 !=
          output->constant_one_input_.erase(gate_loc_as_constant_output_wire)) {
        LOG_FATAL("Fatal Error");
      }
    }
  } else {
    // Update gate_to_[left | right]_input with the removal of this input wire.
    if (constant_input_is_left_input) {
      (*((*gate_to_right_input)[gate->loc_.level_]))[gate->loc_.index_] =
          GateLocation(-1, -1);
    } else {
      (*((*gate_to_left_input)[gate->loc_.level_]))[gate->loc_.index_] =
          GateLocation(-1, -1);
    }
    // Update the appropriate set of output wires, to no longer map to this gate.
    if (non_constant_input_level >= 0) {
      // The non-constant input wire is the output of another gate.
      StandardGate<bool>& non_constant_parent =
          output->levels_[non_constant_input_level]
              .gates_[non_constant_input_index];
      if (1 !=
          non_constant_parent.output_wire_locations_.erase(
              gate_loc_as_non_constant_output_wire)) {
        LOG_FATAL("Fatal Error.");
      }
    } else if (non_constant_input_level >= -3) {
      LOG_FATAL("Fatal Error.");
    } else {
      // The non-constant input wire is a global input from Party N. First find N.
      const int party = (int) (-4 - non_constant_input_level);
      // Get input info for this input.
      if ((int64_t) output->inputs_as_generic_value_locations_[party].size() <=
          non_constant_input_index) {
        LOG_FATAL("Fatal Error.");
      }
      vector<set<WireLocation>>& inputs =
          output->inputs_as_generic_value_locations_[party]
                                                    [non_constant_input_index];
      bool found_bit = false;
      for (set<WireLocation>& input_bit_to_wires : inputs) {
        found_bit =
            input_bit_to_wires.erase(gate_loc_as_non_constant_output_wire) == 1;
        if (found_bit) break;
      }
      if (!found_bit) LOG_FATAL("Fatal Error");
    }
  }
}

// The input gate is a single-input (IDENTITY or NOT) gate.
// Remove/Modify this gate as follows:
//   1) For all non-global output wires of this gate (even if gate has
//      some global output wires as well, the following will still be
//      done to its non-global output wires):
//      a) Update the gate type of the target gate, if appropriate:
//         I.e. if current gate's type is IDENTITY, nothing to do.
//         Otherwise if it is NOT, then need to take the NOT of the
//         target gate's operation.
//      b) Update parent gate's output wire to skip the current gate,
//         and instead map directly to the target gate.
//      c) Update gate_to_[left | right]_input to reflect the new
//         input wires for each target gate, as a result of (1b) above
//   2) For all global output wires (even if gate has non-global output
//      wires too, the following will be done to the global output wires):
//      a) If the current gate's parent is a *global* input:
//         No reduction can be made (must keep this gate).
//      b) If the current gate's parent is *not* a global input:
//         (i)  If gate op is IDENTITY *or* parent gate has only one output:
//              We'll just replace the current gate with it's parent gate.
//              This means transferring the present gate's global output wires
//              to the parent gate, and updating the parent's gate type,
//              if appropriate (i.e if the current gate's operation is NOT,
//              update the parent gate's operation to be the NOT of its
//              current operation; otherwise, leave the parent op as-is).
//         (ii) If gate op is NOT *and* parent gate has more than one output:
//              Move the gate to be the last gate at it's parents level,
//              and give it the same inputs that its parent has. Update
//              the gate operation to be the NOT of its parent's operation.
//              Also, update gate_to_[left | right]_input to reflect that
//              this gate's inputs now come from the grandparents, not
//              the parent.
//   3) If the current gate is to be (re)moved (see (4) below):
//      Remove the current gate's input wire from the set of its parent's
//      gate output wires.
//   4) If all of the output wires are non-global or we were able to Merge
//      this gate with its parent (i.e. (2b.i) above), remove the gate.
//      Otherwise, if (2b.ii) above, move the gate. Otherwise, if case (2a),
//      nothing to do (keep the gate; although all of its non-global output
//      wires have been moved, as per (1) above).
// This function will return:
//   - (-2, -2): If no further action is required by the calling code.
//               (This is case (2a) above: the current gate has at least one global
//               output wire, and the input to this gate is a global input).
//   - (-1, -1): If the present gate is to be removed. This happens if:
//                 - All output wires are non-global, or
//                 - Case 2b.i: The current gate op is IDENTITY or the parent
//                   gate has a single output (namely, the input wire of the
//                   present gate)
//   - (parent level, parent_level.num_gates_): Otherwise. Namely, the gate
//               is to be moved. This means we must fall under case 2b.ii,
//               i.e.: There is at least one global output wire, the gate
//               operation is NOT, and this gate's parent had more than one
//               output. The returned value indicates where this gate should
//               be moved (namely, to the last gate on its parent's level).
GateLocation RemoveSingleInputGate(
    const bool input_is_left_wire,
    const int64_t& parent_level,
    const int64_t& parent_index,
    const GateLocation& left_grandparent,
    const GateLocation& right_grandparent,
    StandardGate<bool>& gate,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input,
    StandardCircuit<bool>* output) {
  // Grab the BooleanOperation for this gate.
  const BooleanOperation gate_op = gate.type_;
  if (gate_op != BooleanOperation::IDENTITY &&
      gate_op != BooleanOperation::NOT) {
    LOG_FATAL("Fatal Error.");
  }

  // Grab this gate's location, as an output wire of its parent.
  const WireLocation loc_as_output =
      WireLocation(gate.loc_.level_, gate.loc_.index_, input_is_left_wire);

  // Grab the set of output wires for this gate's parent gate.
  const bool parent_is_global_input = parent_level < 0;
  set<WireLocation>* parent_outputs = nullptr;
  if (!parent_is_global_input) {
    parent_outputs = &output->levels_[parent_level]
                          .gates_[parent_index]
                          .output_wire_locations_;
  } else if (parent_level == -2) {
    parent_outputs = &output->constant_zero_input_;
  } else if (parent_level == -3) {
    parent_outputs = &output->constant_one_input_;
  } else if (parent_level < -3) {
    // First, identify which party this input belongs to.
    const int party = (int) (-4 - parent_level);
    vector<set<WireLocation>>& input_bits =
        output->inputs_as_generic_value_locations_[party][parent_index];
    for (size_t i = 0; i < input_bits.size(); ++i) {
      if (input_bits[i].find(loc_as_output) != input_bits[i].end()) {
        parent_outputs = &input_bits[i];
        break;
      }
    }
  } else {
    LOG_FATAL("Fatal Error: " + Itoa(parent_level));
  }
  if (parent_outputs == nullptr) {
    LOG_FATAL(
        "FATAL ERROR. Gate: " + gate.loc_.Print() + ", parent_level: " +
        Itoa(parent_level) + ", parent_index: " + Itoa(parent_index));
  }

  // Go through all output wires, handling all non-global outputs as
  // outlined above, and doing nothing with global outputs (for now).
  // This block implements Step (1) listed at the top.
  bool has_global_output = false;
  const set<WireLocation> output_wires = gate.output_wire_locations_;
  for (const WireLocation& wire : output_wires) {
    if (wire.loc_.level_ == -1) {
      has_global_output = true;
    } else {
      gate.output_wire_locations_.erase(wire);
      parent_outputs->insert(wire);
      if (gate_op == BooleanOperation::NOT) {
        FlipGateOp(
            wire.is_left_,
            output->levels_[wire.loc_.level_].gates_[wire.loc_.index_]);
      }
      if (wire.is_left_) {
        (*((*gate_to_left_input)[wire.loc_.level_]))[wire.loc_.index_] =
            GateLocation(parent_level, parent_index);
      } else {
        (*((*gate_to_right_input)[wire.loc_.level_]))[wire.loc_.index_] =
            GateLocation(parent_level, parent_index);
      }
    }
  }

  // If no global outputs, nothing left to do: Mark the gate as ready to be
  // removed (will be removed by calling code); this is Step (4) at the top.
  if (!has_global_output) {
    // This gate will be removed.
    // Remove the current gate's input wire from the set of its parent's output wires.
    parent_outputs->erase(
        WireLocation(gate.loc_.level_, gate.loc_.index_, input_is_left_wire));
    return GateLocation(-1, -1);
  }

  // At least one global output, so we need to determine what to do
  // based on whether the parent is a global input and how many output wires
  // the parent has (see Step (2) listed at the top).
  // First, check if parent is a global input wire (as opposed to the output
  // wire of another gate). If so, no further reduction is possible.
  if (parent_is_global_input) return GateLocation(-2, -2);

  // The fact that we're here means we're in case (2b) listed at the top.
  // Determine if we fall under Case 2b.i: This gate is the *only* output wire
  // of its parent, or the gate op is IDENTITY.
  if (parent_outputs->size() == 1 || gate_op == BooleanOperation::IDENTITY) {
    // Since the parent has a single output (or current gate's operation is ID),
    // we can merge the present gate with its parent (this is Step (2b.i) at the top).
    // In particular:
    //   - Update parent's gate type (if current gate type is NOT)
    //   - Remove the current gate from the set of the parent's outputs
    //   - Have parent output to all of current gate's global outputs
    if (gate_op == BooleanOperation::NOT) {
      ReverseGateOp(output->levels_[parent_level].gates_[parent_index]);
    }
    parent_outputs->erase(
        WireLocation(gate.loc_.level_, gate.loc_.index_, input_is_left_wire));
    // All of the current gate's output wires are (now) global outputs,
    // as all non-global output wires were already removed above.
    for (const WireLocation& wire : gate.output_wire_locations_) {
      parent_outputs->insert(wire);
    }
    return GateLocation(-1, -1);
  }

  // Parent had multiple outputs and current gate type is NOT, so we can't
  // merge current gate with it. This is Step (2b.ii) at the top.
  // Instead, we introduce a new gate at the parent's level, and give it the
  // same input wires as the parent got, and an operation that is the NOT
  // of the parent's gate op.
  if (left_grandparent.level_ == -1 || right_grandparent.level_ == -1) {
    LOG_FATAL(
        "Parent should have two inputs, since single-input gates "
        "are processed removed from top-down (parents first), and "
        "hence if the parent gate is single-input, it survived "
        "being removed, which means: all of its non-global output "
        "wires were removed (so it *only* has global output wires). "
        "Hence, it is an error if the present gate has an input wire "
        "from its parent (indicating the parent has a non-global output).");
  }
  // Update gate_to_[left | right]_input to indicate that the input wires
  // for the present gate will change (used to be from parent, now will come
  // from Grandparent).
  (*((*gate_to_left_input)[gate.loc_.level_]))[gate.loc_.index_] =
      left_grandparent;
  (*((*gate_to_right_input)[gate.loc_.level_]))[gate.loc_.index_] =
      right_grandparent;
  // Remove the current gate's input wire from the set of its parent's output wires.
  parent_outputs->erase(
      WireLocation(gate.loc_.level_, gate.loc_.index_, input_is_left_wire));
  const int64_t new_gate_index = output->levels_[parent_level].num_gates_;
  // Add new gate as an output wire of parent's left parent.
  if (left_grandparent.level_ >= 0) {
    output->levels_[left_grandparent.level_]
        .gates_[left_grandparent.index_]
        .output_wire_locations_.insert(
            WireLocation(parent_level, new_gate_index, true));
  } else if (left_grandparent.level_ == -1) {
    LOG_FATAL("Fatal Error");
  } else if (left_grandparent.level_ == -2) {
    output->constant_zero_input_.insert(
        WireLocation(parent_level, new_gate_index, true));
  } else if (left_grandparent.level_ == -3) {
    output->constant_one_input_.insert(
        WireLocation(parent_level, new_gate_index, true));
  } else if (left_grandparent.level_ < -3) {
    // First, identify which party this input belongs to.
    const int party = (int) (-4 - left_grandparent.level_);
    // Grab the bit index.
    vector<set<WireLocation>>& input_bits =
        output
            ->inputs_as_generic_value_locations_[party][left_grandparent.index_];
    for (size_t i = 0; i < input_bits.size(); ++i) {
      if (input_bits[i].find(WireLocation(parent_level, parent_index, true)) !=
          input_bits[i].end()) {
        input_bits[i].insert(WireLocation(parent_level, new_gate_index, true));
        break;
      }
    }
  }
  // Add new gate as an output wire of parent's right parent.
  if (right_grandparent.level_ >= 0) {
    output->levels_[right_grandparent.level_]
        .gates_[right_grandparent.index_]
        .output_wire_locations_.insert(
            WireLocation(parent_level, new_gate_index, false));
  } else if (right_grandparent.level_ == -1) {
    LOG_FATAL("Fatal Error");
  } else if (right_grandparent.level_ == -2) {
    output->constant_zero_input_.insert(
        WireLocation(parent_level, new_gate_index, false));
  } else if (right_grandparent.level_ == -3) {
    output->constant_one_input_.insert(
        WireLocation(parent_level, new_gate_index, false));
  } else if (right_grandparent.level_ < -3) {
    // First, identify which party this input belongs to.
    const int party = (int) (-4 - right_grandparent.level_);
    // Grab the bit index.
    vector<set<WireLocation>>& input_bits =
        output->inputs_as_generic_value_locations_[party]
                                                  [right_grandparent.index_];
    for (size_t i = 0; i < input_bits.size(); ++i) {
      if (input_bits[i].find(WireLocation(parent_level, parent_index, false)) !=
          input_bits[i].end()) {
        input_bits[i].insert(WireLocation(parent_level, new_gate_index, false));
        break;
      }
    }
  }

  // We return the index of the new gate. Note that technically, we are
  // moving the present gate to the new gate location. The input wires
  // for this gate were set above; but we need to adjust the gate type,
  // which should be the NOT of its parent's gate type.
  gate.type_ =
      ReverseGateOp(output->levels_[parent_level].gates_[parent_index].type_);
  return GateLocation(parent_level, new_gate_index);
}

// Goes through circuit, looking for any gates whose input wires both come
// from a gate whose level is more than two lower than the gate itself.
// If found, moves that gate 'up' so that it lies on the level directly
// below its (the one with higher index) parent's gate.
bool FlattenCircuitInternal(
    const vector<int>&,
    int64_t* start_level,
    int64_t* start_index,
    map<pair<BooleanOperation, pair<GateLocation, GateLocation>>, GateLocation>*,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input,
    StandardCircuit<bool>* output) {
  kCurrentReductionFunctionIndex = 2;
  if (kNumReductionsInCurrentReduceCircuit >
      kPrintReduceCircuitDebugNumChangesThreshold) {
    LOG_INFO(
        "FlattenCircuit *start_level: " + Itoa(*start_level) +
        ", start_index: " + Itoa(*start_index));
  }
  if (*start_level >= (int64_t) output->levels_.size()) {
    return false;
  }
  // Iterate through circuit, searching for a gate whose closest parent
  // is *not* directly in the level above it.
  int64_t gate_start_index = *start_index;
  for (uint64_t level = *start_level; level < output->levels_.size(); ++level) {
    for (uint64_t gate = gate_start_index;
         gate < output->levels_[level].gates_.size();
         ++gate) {
      // Get location (level) of this gate's parent(s).
      const GateLocation& left_loc = (*((*gate_to_left_input)[level]))[gate];
      const GateLocation& right_loc = (*((*gate_to_right_input)[level]))[gate];
      const int64_t closest_input = max(left_loc.level_, right_loc.level_);
      if ((closest_input < 0 && level > 0) ||
          (closest_input >= 0 && level - closest_input > 1)) {
        const uint64_t collapse_to = closest_input < 0 ? 0 : closest_input + 1;
        bool collapsed_level = false;
        if (kNumReductionsInCurrentReduceCircuit >
            kPrintReduceCircuitDebugNumChangesThreshold) {
          LOG_INFO(
              "Flatten is moving gate (" + Itoa(level) + ", " + Itoa(gate) +
              ") to (" + Itoa(collapse_to) + ", " +
              Itoa(output->levels_[collapse_to].gates_.size()) + ")");
        }
        MoveGate(
            MoveGateCase::FLATTEN_GATE,
            true,
            level,
            gate,
            collapse_to,
            output->levels_[collapse_to].gates_.size(),
            &collapsed_level,
            gate_to_left_input,
            gate_to_right_input,
            output);
        GetNextStartPosition(
            collapsed_level, level, gate, *output, start_level, start_index);
        // Return here instead of recursively calling FlattenCircuitInternal(),
        // to avoid segfault crashes due to overflowing stack in large recursion.
        return true;
      }
    }
    gate_start_index = 0;
  }

  return false;
}

// Removes any gate that doesn't have any output wires.
bool RemoveZeroOutputGatesInternal(
    const vector<int>&,
    int64_t* start_level,
    int64_t* start_index,
    map<pair<BooleanOperation, pair<GateLocation, GateLocation>>, GateLocation>*,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input,
    StandardCircuit<bool>* output) {
  kCurrentReductionFunctionIndex = 3;
  if (kNumReductionsInCurrentReduceCircuit >
      kPrintReduceCircuitDebugNumChangesThreshold) {
    LOG_INFO(
        "RemoveZeroOutputGates *start_level: " + Itoa(*start_level) +
        ", start_index: " + Itoa(*start_index));
  }
  if (output->levels_.empty()) return false;

  // RemoveZeroOutputGatesInternal is the unique reduction function that
  // iterates through the circuit *backwards*. If this is the very first call,
  // ignore/overwrite (start_level, start_index) to the appropriate values
  // (namely, the final gate in the circuit); otherwise, leave it as is.
  if (*start_level == 0 && *start_index == 0) {
    *start_level = output->levels_.size() - 1;
    *start_index = output->levels_.back().gates_.size() - 1;
  } else if (*start_level == -1 && *start_index == -1) {
    // This is a special case to indicate we are currently considering the very first
    // gate in the circuit; it was given the special (wrong!) GatePosition
    // intentionally, to avoid collision with the special (0, 0) case
    // (which indicated the very first call to RemoveZeroOutputGatesInternal).
    *start_level = 0;
    *start_index = 0;
  }

  // Iterate through gates in the circuit *backwards*, looking for any that
  // should be removed.
  for (int64_t level = *start_level; level >= 0; --level) {
    int64_t curr_index_start = level == *start_level ?
        *start_index :
        output->levels_[level].gates_.size() - 1;
    for (int64_t index = curr_index_start; index >= 0; --index) {
      // Remove this gate, if output_wire_locations_ for this gate is empty.
      if (output->levels_[level].gates_[index].output_wire_locations_.empty()) {
        // Since this gate is to be removed, remove it as an output wire of its parent(s).
        const GateLocation& left_parent =
            (*((*gate_to_left_input)[level]))[index];
        const GateLocation& right_parent =
            (*((*gate_to_right_input)[level]))[index];
        RemoveOutputWire(WireLocation(level, index, true), left_parent, output);
        RemoveOutputWire(
            WireLocation(level, index, false), right_parent, output);
        if (kNumReductionsInCurrentReduceCircuit >
            kPrintReduceCircuitDebugNumChangesThreshold) {
          LOG_INFO(
              "RemoveZeroOutputGates is removing gate (" + Itoa(level) + ", " +
              Itoa(index) + ")");
        }
        bool collapsed_level = false;
        if (!output->levels_[level].gates_[index].IsLocalGate() &&
            output->levels_[level].gates_[index].depends_on_.size() > 1) {
          --(output->num_non_local_gates_);
        }
        MoveGate(
            MoveGateCase::REMOVE_GATE,
            true,
            level,
            index,
            -1,
            -1,
            &collapsed_level,
            gate_to_left_input,
            gate_to_right_input,
            output);

        // Update (start_level, start_index) to be one *earlier* than before
        // (since RemoveZeroOutputGatesInternal walks through the circuit backwards).
        if (index == 0) {
          if (level == 0) {
            // We just finished evaluating the final gate. Go ahead and mark
            // (start_level, start_index) to the special values indicating the
            // first gate; which means the next call will also evaluate this
            // gate (but will return false, since this gate won't need to be removed).
            *start_level = -1;
            *start_index = -1;
          } else {
            *start_level = level - 1;
            *start_index = output->levels_[*start_level].gates_.size() - 1;
          }
        } else if (index == 1 && level == 0) {
          // The next gate to evaluate will be the first gate of the circuit.
          // Use the special indexing to indicate this.
          *start_level = -1;
          *start_index = -1;
        } else {
          // No special case here. Just update *start_index to the previous value.
          *start_index = index - 1;
          *start_level = level;
        }
        return true;
      }
    }
  }

  return false;
}

bool DeduplicateCircuitInternal(
    const vector<int>& sum_of_earlier_inputs,
    int64_t* start_level,
    int64_t* start_index,
    map<pair<BooleanOperation, pair<GateLocation, GateLocation>>, GateLocation>*
        gate_type_and_input_wires_to_target_gate,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input,
    StandardCircuit<bool>* output) {
  kCurrentReductionFunctionIndex = 1;
  if (kNumReductionsInCurrentReduceCircuit >
      kPrintReduceCircuitDebugNumChangesThreshold) {
    LOG_INFO(
        "Dedup *start_level: " + Itoa(*start_level) +
        ", start_index: " + Itoa(*start_index));
  }
  if (*start_level >= (int64_t) output->levels_.size()) {
    return false;
  }
  // We need a data structure to quickly identify duplicate gates.
  // This structure will have Key: (GateType, (Left Parent, Right Parent)),
  // and Value: (GateLocation of Child).
  // This map is only guaranteed to be complete up through "child" gates
  // at GateLocation (start_level, start_index). Therefore, continue
  // iterating through the circuit starting at this point, and updating
  // 'gate_type_and_input_wires_to_target_gate' as we go; if at any point we
  // hit a duplicate, remove it.
  int64_t gate_start_index = *start_index;
  for (uint64_t level = *start_level; level < output->levels_.size(); ++level) {
    for (uint64_t gate = gate_start_index;
         gate < output->levels_[level].gates_.size();
         ++gate) {
      const BooleanOperation gate_op = output->levels_[level].gates_[gate].type_;
      GateLocation left_parent = (*((*gate_to_left_input)[level]))[gate];
      GateLocation right_parent = (*((*gate_to_right_input)[level]))[gate];
      if (left_parent.level_ == -1 && right_parent.level_ == -1) {
        LOG_FATAL("Unable to find either parent");
      }
      // If either of the parents is a global input wire, we need to overwrite
      // left_parent/right_parent with a new format, so that they also
      // specify bit_index (gate_to_left_input and gate_to_right_input only carry
      // the global input source (Constant 0, Constant 1, Party i) and, in case
      // of Party i, the GateLocation.index_ specifies the input's bit index).
      // We follow the convention, which differs from the original convention
      // used for gate_to_[left | right]_input (see Disscussion above their def'n):
      //   - Constant 0: GateLocation.level_ = -2, GateLocation.index_ = N/A
      //   - Constant 1: GateLocation.level_ = -3, GateLocation.index_ = N/A
      //   - Party n:    GateLocation.level_ = -4 - I_{n-1} - i
      //                 GateLocation.index_ = bit_index
      //     Where:
      //       i:       Denotes the input index of this input (for Party n)
      //       I_{n-1}: Denotes the sum of the *number of inputs* of each Party j,
      //                for 0 <= j < n.
      if (left_parent.level_ < 0) {
        if (left_parent.level_ == -1) {
          if (gate_op != BooleanOperation::IDENTITY &&
              gate_op != BooleanOperation::NOT) {
            LOG_FATAL("Unable to find left parent");
          }
        } else if (left_parent.level_ < -3) {
          // First, identify which party this input belongs to.
          const int party = (int) (-4 - left_parent.level_);

          // Grab the global input index of this input for this party.
          if (party >= (int) sum_of_earlier_inputs.size()) {
            LOG_FATAL("Invalid party index");
          }
          const int global_input_index =
              (int) (sum_of_earlier_inputs[party] + left_parent.index_);

          // Next, need to find the bit index that leads to this gate.
          WireLocation target = WireLocation(level, gate, true);
          int64_t bit_index = -1;
          const vector<set<WireLocation>>& bits_to_wires =
              output->inputs_as_generic_value_locations_[party]
                                                        [left_parent.index_];
          for (size_t i = 0; i < bits_to_wires.size(); ++i) {
            for (const WireLocation& output_wire : bits_to_wires[i]) {
              if (output_wire == target) {
                bit_index = i;
                break;
              }
            }
            if (bit_index >= 0) break;
          }
          if (bit_index == -1) {
            LOG_FATAL(
                "Unable to find input bit mapping to this gate. (" +
                Itoa(level) + ", " + Itoa(gate) +
                "), Left Parent: " + left_parent.Print());
          }
          left_parent = GateLocation(-4 - global_input_index, bit_index);
        } else if (left_parent.level_ != -2 && left_parent.level_ != -3) {
          // Nothing to do for constant 0 and constant 1 inputs, as
          // left_parent.level_ is correct (at -2 or -3, respectively) and
          // left_parent.index_ is not used.
          LOG_FATAL("Unexpected left parent location.");
        }
      }
      if (right_parent.level_ < 0) {
        if (right_parent.level_ == -1) {
          if (gate_op != BooleanOperation::IDENTITY &&
              gate_op != BooleanOperation::NOT) {
            LOG_FATAL("Unable to find right parent");
          }
        } else if (right_parent.level_ < -3) {
          // First, identify which party this input belongs to.
          const int party = (int) (-4 - right_parent.level_);

          // Grab the global input index of this input for this party.
          if (party >= (int) sum_of_earlier_inputs.size()) {
            LOG_FATAL("Invalid party index");
          }
          const int global_input_index =
              (int) (sum_of_earlier_inputs[party] + right_parent.index_);

          // Next, need to find the bit index that leads to this gate.
          WireLocation target = WireLocation(level, gate, false);
          int64_t bit_index = -1;
          const vector<set<WireLocation>>& bits_to_wires =
              output->inputs_as_generic_value_locations_[party]
                                                        [right_parent.index_];
          for (size_t i = 0; i < bits_to_wires.size(); ++i) {
            for (const WireLocation& output_wire : bits_to_wires[i]) {
              if (output_wire == target) {
                bit_index = i;
                break;
              }
            }
            if (bit_index >= 0) break;
          }
          if (bit_index == -1) {
            LOG_FATAL(
                "Unable to find input bit mapping to this gate. (" +
                Itoa(level) + ", " + Itoa(gate) +
                ", Right Parent: " + right_parent.Print());
          }
          right_parent = GateLocation(-4 - global_input_index, bit_index);
        } else if (right_parent.level_ != -2 && right_parent.level_ != -3) {
          // Nothing to do for constant 0 and constant 1 inputs, as
          // right_parent.level_ is correct (at -2 or -3, respectively) and
          // right_parent.index_ is not used.
          LOG_FATAL("Unexpected right parent location.");
        }
      }
      // First check for duplicates where the potential match is
      // the same, just with the order of left/right wires flipped.
      const BooleanOperation flipped_op = WiresFlippedOp(gate_op);
      if (flipped_op == BooleanOperation::UNKNOWN) LOG_FATAL("Fatal Error.");
      map<pair<BooleanOperation, pair<GateLocation, GateLocation>>,
          GateLocation>::const_iterator itr =
          gate_type_and_input_wires_to_target_gate->find(
              make_pair(flipped_op, make_pair(right_parent, left_parent)));
      if (itr != gate_type_and_input_wires_to_target_gate->end()) {
        // We've already seen this combination of (Op, (Left Parent, Right Parent))
        // before, i.e. present gate is a duplicate gate. Merge it with it's
        // doppleganger.
        bool collapsed_level = false;
        if (kNumReductionsInCurrentReduceCircuit >
            kPrintReduceCircuitDebugNumChangesThreshold) {
          LOG_INFO(
              "Dedup is moving gate (" + Itoa(level) + ", " + Itoa(gate) +
              ") to (" + Itoa(itr->second.level_) + ", " +
              Itoa(itr->second.index_) + ")");
        }
        if (!output->levels_[level].gates_[gate].IsLocalGate() &&
            output->levels_[level].gates_[gate].depends_on_.size() > 1) {
          --(output->num_non_local_gates_);
        }
        MoveGate(
            MoveGateCase::MERGE_GATE,
            false,
            level,
            gate,
            itr->second.level_,
            itr->second.index_,
            &collapsed_level,
            gate_to_left_input,
            gate_to_right_input,
            output);
        GetNextStartPosition(
            collapsed_level, level, gate, *output, start_level, start_index);
        return true;
      }

      // Now check if this combination exists as-is.
      const pair<
          map<pair<BooleanOperation, pair<GateLocation, GateLocation>>,
              GateLocation>::iterator,
          bool>
          insert_info =
              gate_type_and_input_wires_to_target_gate->insert(make_pair(
                  make_pair(gate_op, make_pair(left_parent, right_parent)),
                  GateLocation(level, gate)));
      if (!insert_info.second) {
        // We've already seen this combination of (Op, (Left Parent, Right Parent))
        // before, i.e. present gate is a duplicate gate. Merge it with it's
        // doppleganger.
        bool collapsed_level = false;
        if (kNumReductionsInCurrentReduceCircuit >
            kPrintReduceCircuitDebugNumChangesThreshold) {
          LOG_INFO(
              "Dedup is moving gate (" + Itoa(level) + ", " + Itoa(gate) +
              ") to (" + Itoa(insert_info.first->second.level_) + ", " +
              Itoa(insert_info.first->second.index_) + ")");
        }
        if (!output->levels_[level].gates_[gate].IsLocalGate() &&
            output->levels_[level].gates_[gate].depends_on_.size() > 1) {
          --(output->num_non_local_gates_);
        }
        MoveGate(
            MoveGateCase::MERGE_GATE,
            true,
            level,
            gate,
            insert_info.first->second.level_,
            insert_info.first->second.index_,
            &collapsed_level,
            gate_to_left_input,
            gate_to_right_input,
            output);
        GetNextStartPosition(
            collapsed_level, level, gate, *output, start_level, start_index);
        return true;
      }
    }
    gate_start_index = 0;
  }

  // No duplicates found.
  return false;
}

bool RemoveConstantAndSingleInputGatesInternal(
    const vector<int>&,
    int64_t* start_level,
    int64_t* start_index,
    map<pair<BooleanOperation, pair<GateLocation, GateLocation>>, GateLocation>*,
    vector<vector<GateLocation>*>* gate_to_left_input,
    vector<vector<GateLocation>*>* gate_to_right_input,
    StandardCircuit<bool>* output) {
  kCurrentReductionFunctionIndex = 0;
  if (kNumReductionsInCurrentReduceCircuit >
      kPrintReduceCircuitDebugNumChangesThreshold) {
    LOG_INFO(
        "Remove Constants and Single Input *start_level: " + Itoa(*start_level) +
        ", start_index: " + Itoa(*start_index));
  }
  if (*start_level >= (int64_t) output->levels_.size()) {
    return false;
  }
  // Go through all gates, looking for single-input gates, and removing them.
  uint64_t start_gate_index = *start_index;
  for (uint64_t level = *start_level; level < output->levels_.size(); ++level) {
    for (uint64_t gate = start_gate_index;
         gate < output->levels_[level].gates_.size();
         ++gate) {
      StandardGate<bool>& current_gate = output->levels_[level].gates_[gate];
      // First check if this is a single-input gate.
      const bool is_single_input_gate =
          current_gate.type_ == BooleanOperation::IDENTITY ||
          current_gate.type_ == BooleanOperation::NOT;
      const GateLocation& left_input = (*((*gate_to_left_input)[level]))[gate];
      const GateLocation& right_input = (*((*gate_to_right_input)[level]))[gate];
      if (is_single_input_gate) {
        const bool is_left_wire = left_input.level_ != -1;
        const int64_t parent_level =
            is_left_wire ? left_input.level_ : right_input.level_;
        const int64_t parent_index =
            is_left_wire ? left_input.index_ : right_input.index_;
        // The function below may also need the parent's input wire mappings.
        // Grab them now, if available.
        GateLocation left_grandparent = GateLocation(-1, -1);
        GateLocation right_grandparent = GateLocation(-1, -1);
        if (parent_level >= 0) {
          left_grandparent =
              (*((*gate_to_left_input)[parent_level]))[parent_index];
          right_grandparent =
              (*((*gate_to_right_input)[parent_level]))[parent_index];
        }
        const GateLocation move_to = RemoveSingleInputGate(
            is_left_wire,
            parent_level,
            parent_index,
            left_grandparent,
            right_grandparent,
            current_gate,
            gate_to_left_input,
            gate_to_right_input,
            output);
        // Check return value of call to RemoveSingleInputGate: If more
        // work is to be done (i.e. a gate was (re)moved), then call
        // MoveGate(). Otherwise, the circuit is up-to-date with the
        // Single-input gate already handled in RemoveSingleInputGate,
        // so we may continue processing the circuit.
        if (move_to.level_ != -2) {
          bool collapsed_level = false;
          if (kNumReductionsInCurrentReduceCircuit >
              kPrintReduceCircuitDebugNumChangesThreshold) {
            LOG_INFO(
                "RemoveSingleInput is moving gate (" + Itoa(level) + ", " +
                Itoa(gate) + ") to (" + Itoa(move_to.level_) + ", " +
                Itoa(move_to.index_) + ")");
          }
          MoveGate(
              (move_to.level_ == -1 ? MoveGateCase::REMOVE_GATE :
                                      MoveGateCase::REDUCE_SINGLE_INPUT_GATE),
              true,
              level,
              gate,
              move_to.level_,
              move_to.index_,
              &collapsed_level,
              gate_to_left_input,
              gate_to_right_input,
              output);
          GetNextStartPosition(
              collapsed_level, level, gate, *output, start_level, start_index);
          return true;
        }
        continue;
      }
      // The fact that we reached here means that the gate is not single-input.
      // Now check if the gate can be removed/modified because
      // (one or both of) its input wires are constant.
      bool left_parent_is_constant =
          (left_input.level_ == -2 || left_input.level_ == -3);
      bool right_parent_is_constant =
          (right_input.level_ == -2 || right_input.level_ == -3);
      if (left_parent_is_constant && right_parent_is_constant) {
        if (RemoveConstantGate(
                current_gate, gate_to_left_input, gate_to_right_input, output)) {
          bool collapsed_level = false;
          if (kNumReductionsInCurrentReduceCircuit >
              kPrintReduceCircuitDebugNumChangesThreshold) {
            LOG_INFO(
                "RemoveConstantGate is removing gate (" + Itoa(level) + ", " +
                Itoa(gate) + ")");
          }
          MoveGate(
              MoveGateCase::REMOVE_GATE,
              true,
              level,
              gate,
              -1,
              -1,
              &collapsed_level,
              gate_to_left_input,
              gate_to_right_input,
              output);
          GetNextStartPosition(
              collapsed_level, level, gate, *output, start_level, start_index);
          return true;
        }
        continue;
      }
      // This gate isn't a single-input (IDENTITY or NOT) gate, nor is it
      // a constant gate (both input wires are constants).
      // However, also check if one of its input wires comes from a constant
      // (global input, or output of a constant gate), in which case the gate
      // can be simplified to a IDENTITY or NOT gate (and then subsequently
      // removed on a follow-up call to the present function).
      // Based on the CONSTANT GATE GUARANTEE (see comment above ReduceCircuit),
      // since the parent level has already been processed, for a gate to have an
      // input wire that is constant, it necessarily means that the input wire
      // is from a *global* constant input wire (as opposed to the output of a constant gate).
      // Proof: Suppose Not.
      // Then the constant input wire is the output of a gate, where both of the
      // parent gate's wires were constants. Consider what happened the parent
      // gate was being processed: It first go duplicated if necessary so that
      // all output wires were non-global (the current gate being processed was
      // one of those output wires), then the gate was removed via
      // RemoveConstantGate(), resulting in all of its output wires coming
      // directly from a global input wire).
      if (left_parent_is_constant || right_parent_is_constant) {
        const int64_t non_constant_parent_level =
            left_parent_is_constant ? right_input.level_ : left_input.level_;
        const int64_t non_constant_parent_index =
            left_parent_is_constant ? right_input.index_ : left_input.index_;
        if (kNumReductionsInCurrentReduceCircuit >
            kPrintReduceCircuitDebugNumChangesThreshold) {
          const string who = left_parent_is_constant ? "left" : "right";
          const string what =
              (left_input.level_ == -2 || right_input.level_ == -2) ? "0" : "1";
          LOG_INFO(
              "SimplifyOneInputConstantGate is simplifying gate " +
              current_gate.loc_.Print() + ", whose " + who +
              "wire is constant '" + what + "'");
        }
        SimplifyOneInputConstantGate(
            (left_input.level_ == -2 || right_input.level_ == -2),
            left_parent_is_constant,
            non_constant_parent_level,
            non_constant_parent_index,
            gate_to_left_input,
            gate_to_right_input,
            &current_gate,
            output);
        // The above function updated the gate so that it became a single
        // input gate; now we'll want to reprocess it, so that it triggers
        // the 'is_single_input_gate' condition above.
        --gate;
      }
    }
    start_gate_index = 0;
  }

  // No single-input gates found.
  return false;
}

}  // namespace

void SetAllowReduceCircuit(const bool should_allow) {
  kAllowReduceCircuit = should_allow;
}

void SetArgminBreakTiesPos(const bool use_first) {
  kArgminBreakTiesTakeFirst = use_first;
}

void SetAdditionNumberLookaheadBlocks(const int num_blocks) {
  kAdditionLookaheadBlocks = num_blocks;
}

// ReduceCircuit will simplify circuits by reducing the depth and size by:
//   A) Eliminating Constant Gates.
//   B) Eliminating Single-Input (IDENTITY and NOT) Gates.
//   C) Eliminating Duplicate Gates.
//   D) Flattening. Guarantee:
// In particular, after a call to ReduceCircuit(), the following invariants/
// gurantees will be observed:
//   A) CONSTANT GATE GURANTEE:
//      Any gate that has an input wire that depends on neither Party 1 nor
//      Party 2 (i.e. the input wire is a constant) is necessarily an IDENTIY
//      gate whose only outputs are global outputs.
//   B) SINGLE-INPUT GUARANTEE:
//      All IDENTITY and NOT gates have at least one global output wire.
//   C) DUPLICATE GATE GUARANTEE:
//      There does not exist any two gates that have the same inputs and gate type
//   D) FLAT GUARANTEE:
//      All gates have at least one of its input wires coming from the level
//      directly above it (i.e. on the "parent" level).
// The "Constant Gate Guarantee" is achieved by removing/introducing gates as follows:
//   1) For any gate that has both input wires constant:
//      a) Make sure all output wires are either all global outputs, or all
//         non-global outputs. Do this by introducting a duplicate gate if
//         necessary, where one of the gates does all of the global output
//         wires, and the other does all the non-global output wires.
//      b) Now if all output wires of this gate are global, the invariant/
//         guarantee is satisfied for this gate; nothing to do.
//      c) If all output wires of this gate are non-global, then the gate
//         can (will) be removed via RemoveConstantGate().
//   2) For any gate that has exactly one input coming from a constant:
//      a) Ditto step (1a) above, so that all output wires of this gate
//         are global or all are non-global
//      b) Ditto (1b) above: If all output wires are global, nothing to do.
//      c) If all output wires of this gate are non-global, then the gate
//         can (will) be removed first by transforming it into a single-input
//         (IDENTITY or NOT) gate via SimplifyOneInputConstantGate(), and
//         then it will be removed via a subsequent call to RemoveSingleInputGate().
int ReduceCircuit(const bool print_status, StandardCircuit<bool>* output) {
  if (!kAllowReduceCircuit) return 0;

  if (output == nullptr) LOG_FATAL("Fatal Error.");
  // To speed up ReduceCircuit time, the following will be done:
  //   1) Keep a counter on the first gate that should be checked
  //      for a possible reduction (for when we walk through the circuit
  //      looking for reductions, don't need to start at the root every time).
  //   2) Get a mapping from each gate to its input wires
  //   3) For Deduplication: Keep a mapping from each gate to its gate type
  //      and its parents' wires.

  // The following allow for speed-up (1).
  int64_t start_level = 0;
  int64_t start_index = 0;

  // The following will be useful for keeping track of global inputs from
  // each Party; namely, it provides a global indexing, i.e. a mapping
  // for a given party's input i:
  //   (Party Index, Input Index) -> Overall input index,
  // specifically:
  //   (i, j) -> sum_of_earlier_inputs[i] + j
  vector<int> sum_of_earlier_inputs(output->input_types_.size(), 0);
  for (size_t party_index = 1; party_index < output->input_types_.size();
       ++party_index) {
    sum_of_earlier_inputs[party_index] =
        (int) (sum_of_earlier_inputs[party_index - 1] +
               output->input_types_[party_index - 1].size());
  }

  // The following allow for speed-up (2).
  // The two data structures below will map each gate to its left (resp. right)
  // parents. The vectors are arranged to represent the gate's position;
  // i.e. outer vector index 'i' and inner vector index 'j' would correspond
  // to the gate at position 'j' of level 'i'. The final entry is the
  // GateLocation of the left/right parent. If the left/right parent is a
  // *global* input, we use a negative level_ to denote this, with
  // the following convention:
  //   - The GateLocation.level_ will be negative:
  //       -1: Unused, denotes an invalid/uninitialized value
  //       -2: Denotes global constant '0' input
  //       -3: Denotes global constant '1' input
  //       -N: Denotes global input from Party (N - 4)
  //   - The GateLocation.index_ will be:
  //       -1: Unitialized
  //        0: For global constant '0/1' inputs.
  //        i: The input index (Key of inputs_as_generic_value_locations_[N-4])
  //           for global inputs from Party (N-4).
  //     NOTICE: The bit index is not encoded (it is not needed).
  // We use -1 for a GateLocation.level_ to denote an invalid/unset level;
  // this can be used e.g. to detect that a given (single input) gate has
  // only a left (or right) parent, e.g. the GateLocation stored for this
  // gate will indicate level_ = -1.
  // Also, we use '-1' for GateLocation.index_ for unitialized/unset
  // parent locations, as all valid (set) locations, gate index is non-negative.
  // Finally, we use the vector<vector<GateLocation>> data structure when
  // representing a gate's location (as opposed to e.g.
  // map<GateLocation, GateLocation>) because it is faster to update
  // as circuit reductions are made: If we remove a gate, now we just need
  // to update a single (outer-vector) entry, as opposed to updating
  // all GateLocations. This also explains why the inner-vector is a pointer:
  // so that when an entire level is removed, I can shift all levels above
  // it down just by moving a single pointer per level, as opposed to having
  // to move every single gate.
  vector<vector<GateLocation>*> gate_to_left_input(output->depth_);
  vector<vector<GateLocation>*> gate_to_right_input(output->depth_);
  // Generate local values for the inner-vectors, so that the pointers to
  // these can be stored on the stack instead of the heap.
  vector<vector<GateLocation>> temp_left(output->depth_);
  vector<vector<GateLocation>> temp_right(output->depth_);
  for (int64_t i = 0; i < output->depth_; ++i) {
    // As mentioned above, initialize the GateLocation of each input wire to
    // (-1, -1) to denote an unset/invalid location.
    temp_left[i] = vector<GateLocation>(
        output->levels_[i].num_gates_, GateLocation(-1, -1));
    temp_right[i] = vector<GateLocation>(
        output->levels_[i].num_gates_, GateLocation(-1, -1));
    gate_to_left_input[i] = &temp_left[i];
    gate_to_right_input[i] = &temp_right[i];
  }
  if (!GetInputWireMappings(
          *output, &gate_to_left_input, &gate_to_right_input)) {
    LOG_ERROR("Failed to get input mappings.");
    return false;
  }

  // The following allows for speed-up (3).
  map<pair<BooleanOperation, pair<GateLocation, GateLocation>>, GateLocation>
      gate_type_and_input_wires_to_target_gate;

  typedef bool (*reduction_ptr)(
      const vector<int>&,
      int64_t*,
      int64_t*,
      map<pair<BooleanOperation, pair<GateLocation, GateLocation>>,
          GateLocation>*,
      vector<vector<GateLocation>*>*,
      vector<vector<GateLocation>*>*,
      StandardCircuit<bool>*);
  vector<reduction_ptr> reductions(4);
  reductions[0] = &RemoveConstantAndSingleInputGatesInternal;
  reductions[1] = &DeduplicateCircuitInternal;
  reductions[2] = &FlattenCircuitInternal;
  reductions[3] = &RemoveZeroOutputGatesInternal;
  // TODO: Bit-slicing: packing/unpacking. Take advantage of fact that
  // wires are words (32, 64 bits), not a single bit. And pay the cost
  // of bit-packing separate inputs into a single word, applying the gate,
  // and unpacking on the other side. This can reduce overall number of gates.
  vector<string> function_names;
  function_names.push_back("SingleInput");
  function_names.push_back("Dedup");
  function_names.push_back("Flatten");
  function_names.push_back("NoOutput");
  int num_changes_made = -1;
  int num_transitions_made = 0;
  kNumReductionsInCurrentReduceCircuit = -1;

  while (true) {
    ++num_changes_made;
    ++kNumReductionsInCurrentReduceCircuit;
    // Log status/stats.
    if (print_status) {
      if ((num_changes_made > 100 && num_changes_made < 1000 &&
           (num_changes_made % 100 == 1)) ||
          (num_changes_made > 1000 && num_changes_made < 10000 &&
           (num_changes_made % 250 == 1)) ||
          (num_changes_made > 10000 && num_changes_made < 100000 &&
           (num_changes_made % 1000 == 1)) ||
          (num_changes_made > 1000000 && (num_changes_made % 10000 == 1))) {
        TLOG_INFO(
            "Still reducing (" + Itoa(num_changes_made - 1) +
            " changes so far...). Current size: (" + Itoa(output->depth_) +
            ", " + Itoa(output->size_) +
            "). Num fn switches since last update: " +
            Itoa(num_transitions_made) +
            ", Current Fn: " + function_names[kCurrentReductionFunctionIndex] +
            " at: (" + Itoa(start_level) + ", " + Itoa(start_index) + ").");
      }
      num_transitions_made = 0;
    }

    if (kNumReductionsInCurrentReduceCircuit >
        kPrintReduceCircuitDebugNumChangesThreshold) {
      LOG_INFO("Number reductions made so far: " + Itoa(num_changes_made));
    }

    // Loop through the 4 reduction functions, seeing if any of them can
    // reduce the circuit.
    if ((*reductions[0])(
            sum_of_earlier_inputs,
            &start_level,
            &start_index,
            &gate_type_and_input_wires_to_target_gate,
            &gate_to_left_input,
            &gate_to_right_input,
            output)) {
      continue;
    }

    ++num_transitions_made;

    // Transition. Reset gate_type_and_input_wires_to_target_gate and
    // start (level, index).
    start_level = 0;
    start_index = 0;
    gate_type_and_input_wires_to_target_gate.clear();

    if ((*reductions[1])(
            sum_of_earlier_inputs,
            &start_level,
            &start_index,
            &gate_type_and_input_wires_to_target_gate,
            &gate_to_left_input,
            &gate_to_right_input,
            output)) {
      // Swap first element of 'reductions' with this one, since we're unlikely
      // to need to do reductions of type reductions[0] anymore, and it is
      // inefficient to keep checking it.
      reduction_ptr temp = reductions[0];
      reductions[0] = reductions[1];
      reductions[1] = temp;
      continue;
    }

    // Transition. Reset gate_type_and_input_wires_to_target_gate and
    // start (level, index).
    start_level = 0;
    start_index = 0;
    gate_type_and_input_wires_to_target_gate.clear();

    if ((*reductions[2])(
            sum_of_earlier_inputs,
            &start_level,
            &start_index,
            &gate_type_and_input_wires_to_target_gate,
            &gate_to_left_input,
            &gate_to_right_input,
            output)) {
      // Swap first element of 'reductions' with this one.
      reduction_ptr temp = reductions[0];
      reductions[0] = reductions[2];
      reductions[2] = temp;
      continue;
    }

    // Transition. Reset gate_type_and_input_wires_to_target_gate and
    // start (level, index).
    start_level = 0;
    start_index = 0;
    gate_type_and_input_wires_to_target_gate.clear();

    if ((*reductions[3])(
            sum_of_earlier_inputs,
            &start_level,
            &start_index,
            &gate_type_and_input_wires_to_target_gate,
            &gate_to_left_input,
            &gate_to_right_input,
            output)) {
      // Swap first element of 'reductions' with this one.
      reduction_ptr temp = reductions[0];
      reductions[0] = reductions[3];
      reductions[3] = temp;
      continue;
    }

    // Having made it here means no further reductions can be made.
    break;
  }

  return num_changes_made;
}

template<typename value_t>
bool DuplicateOutputs(
    const StandardCircuit<value_t>& input,
    const uint64_t& duplication_factor,
    StandardCircuit<value_t>* output) {
  // Start by copying the circuit.
  output->CopyFrom(input);

  const uint64_t orig_num_output_wires = input.num_output_wires_;
  const uint64_t orig_num_outputs = input.num_outputs_;

  // Set global fields.
  output->num_non_local_gates_ = 2 * input.num_non_local_gates_;
  output->num_outputs_ = orig_num_outputs * duplication_factor;
  output->num_output_wires_ = orig_num_output_wires * duplication_factor;
  output->function_description_.resize(orig_num_outputs * duplication_factor);
  output->output_designations_.resize(orig_num_outputs * duplication_factor);
  for (uint64_t i = 0; i < orig_num_outputs; ++i) {
    for (uint64_t j = 1; j < duplication_factor; ++j) {
      output->function_description_[i + j * orig_num_outputs] =
          input.function_description_[i];
      output->output_designations_[i + j * orig_num_outputs] =
          input.output_designations_[i];
    }
  }

  // Walk through circuit, updating the output_wire_locations_
  // of each (global) output gate to have an second output.
  for (StandardCircuitLevel<value_t>& level : output->levels_) {
    for (StandardGate<value_t>& gate : level.gates_) {
      // Copy original output_wire_locations_.
      const set<WireLocation> orig_outputs = gate.output_wire_locations_;
      gate.output_wire_locations_.clear();
      for (const WireLocation& orig_output_i : orig_outputs) {
        gate.output_wire_locations_.insert(orig_output_i);
        if (orig_output_i.loc_.level_ == -1) {
          for (uint64_t i = 1; i < duplication_factor; ++i) {
            gate.output_wire_locations_.insert(WireLocation(
                -1,
                orig_output_i.loc_.index_ + i * orig_num_output_wires,
                orig_output_i.is_left_));
          }
        }
      }
    }
  }

  return true;
}

bool ConstructConstantCircuit(
    const slice& value,
    const uint64_t& num_outputs,
    StandardCircuit<slice>* output) {
  output->format_ = CircuitFormat::FORMAT_ONE;
  output->depth_ = 1;
  output->size_ = 1;
  output->num_non_local_gates_ = 0;
  output->num_outputs_ = num_outputs;
  output->num_output_wires_ = num_outputs;
  output->function_description_.resize(num_outputs);
  output->output_designations_.resize(num_outputs);
  set<WireLocation>& locations =
      output->constant_slice_input_.insert(make_pair(value, set<WireLocation>()))
          .first->second;
  locations.insert(WireLocation(0, 0, true));
  for (uint64_t i = 0; i < num_outputs; ++i) {
    Formula& formula_i = output->function_description_[i];
    formula_i.op_.type_ = OperationType::BOOLEAN;
    formula_i.op_.gate_op_ = BooleanOperation::IDENTITY;
    formula_i.value_ = GenericValue(value);
    output->output_designations_[i] =
        make_pair(OutputRecipient(), DataType::SLICE);
  }

  output->levels_.resize(1);
  output->levels_[0].level_ = 0;
  output->levels_[0].num_gates_ = 1;
  output->levels_[0].gates_.resize(1);
  output->levels_[0].gates_[0].loc_ = GateLocation(0, 0);
  output->levels_[0].gates_[0].type_ = BooleanOperation::IDENTITY;
  for (uint64_t i = 0; i < num_outputs; ++i) {
    output->levels_[0].gates_[0].output_wire_locations_.insert(
        WireLocation(-1, i));
  }

  return true;
}

bool ConstructConstantCircuit(
    const bool value,
    const uint64_t& num_outputs,
    StandardCircuit<bool>* output) {
  output->format_ = CircuitFormat::FORMAT_TWO;
  output->depth_ = 1;
  output->size_ = 1;
  output->num_non_local_gates_ = 0;
  output->num_outputs_ = num_outputs;
  output->num_output_wires_ = num_outputs;
  output->function_description_.resize(num_outputs);
  output->output_designations_.resize(num_outputs);
  set<WireLocation>& locations =
      value ? output->constant_one_input_ : output->constant_zero_input_;
  locations.insert(WireLocation(0, 0, true));
  for (uint64_t i = 0; i < num_outputs; ++i) {
    Formula& formula_i = output->function_description_[i];
    formula_i.op_.type_ = OperationType::BOOLEAN;
    formula_i.op_.gate_op_ = BooleanOperation::IDENTITY;
    formula_i.value_ = GenericValue(value);
    output->output_designations_[i] =
        make_pair(OutputRecipient(), DataType::BOOL);
  }

  output->levels_.resize(1);
  output->levels_[0].level_ = 0;
  output->levels_[0].num_gates_ = 1;
  output->levels_[0].gates_.resize(1);
  output->levels_[0].gates_[0].loc_ = GateLocation(0, 0);
  output->levels_[0].gates_[0].type_ = BooleanOperation::IDENTITY;
  for (uint64_t i = 0; i < num_outputs; ++i) {
    output->levels_[0].gates_[0].output_wire_locations_.insert(
        WireLocation(-1, i));
  }

  return true;
}

bool ConstructConstantCircuit(
    const uint64_t& value, const int num_bits, StandardCircuit<bool>* output) {
  if (num_bits <= 0 || num_bits > 64) return false;
  // Create constant circuits for each bit.
  uint64_t mask = 1;
  vector<StandardCircuit<bool>> bit_circuits(num_bits);
  for (int i = 0; i < num_bits; ++i) {
    mask *= 2;
    mask |= 1;
    const bool bit_i = (value >> i) & (uint64_t) 1;
    if (!ConstructConstantCircuit(
            bit_i, (num_bits == 1 ? output : &bit_circuits[i]))) {
      LOG_ERROR("Failed to construct constant circuit at bit " + Itoa(i));
      return false;
    }
  }

  // Merge together the above circuits.
  vector<StandardCircuit<bool>> merged_bit_circuits(num_bits - 1);
  for (int i = 0; i < num_bits - 1; ++i) {
    if (!MergeCircuitsInternal(
            true,
            BooleanOperation::IDENTITY,
            (i == 0 ? bit_circuits[0] : merged_bit_circuits[i - 1]),
            bit_circuits[i + 1],
            (i == num_bits - 2 ? output : &merged_bit_circuits[i]))) {
      LOG_ERROR("Failed to merge constant circuit at bit " + Itoa(i));
      return false;
    }
  }

  // Overwrite number of outputs, which treated outputs as bits instead
  // of appropriate data type.
  DataType type;
  if (!GetIntegerDataType(false, (int) num_bits, &type)) {
    LOG_ERROR("Unable to find appropriate DataType.");
    return false;
  }
  output->num_non_local_gates_ = 0;
  output->num_outputs_ = 1;
  output->output_designations_.clear();
  output->output_designations_.resize(1, make_pair(OutputRecipient(), type));
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.value_ = GenericValue(value & mask);

  // Reduce circuit.
  ReduceCircuit(false, output);

  return true;
}

bool ConstructConstantCircuit(
    const int64_t& value, const int num_bits, StandardCircuit<bool>* output) {
  if (num_bits <= 0 || num_bits > 64) return false;
  if (value >= 0) {
    LOG_ERROR(
        "This API to ConstructConstantCircuit only takes negative values.");
    return false;
  }

  // Create constant circuits for each bit.
  // We stop one bit early, so that the final bit will automatically be '1'
  // for the sign (2's complement) bit.
  uint64_t mask = 1;
  vector<StandardCircuit<bool>> bit_circuits(num_bits);
  for (int i = 0; i < num_bits - 1; ++i) {
    mask *= 2;
    mask |= 1;
    const bool bit_i = (value >> i) & (uint64_t) 1;
    if (!ConstructConstantCircuit(
            bit_i, (num_bits == 1 ? output : &bit_circuits[i]))) {
      LOG_ERROR("Failed to construct constant circuit at bit " + Itoa(i));
      return false;
    }
  }
  // Construct a circuit for the sign (2's Complement) bit.
  if (!ConstructConstantCircuit(
          true, (num_bits == 1 ? output : &bit_circuits[num_bits - 1]))) {
    LOG_ERROR(
        "Failed to construct constant circuit at bit " + Itoa(num_bits - 1));
    return false;
  }

  // Merge together the above circuits.
  vector<StandardCircuit<bool>> merged_bit_circuits(num_bits - 1);
  for (int i = 0; i < num_bits - 1; ++i) {
    if (!MergeCircuitsInternal(
            true,
            BooleanOperation::IDENTITY,
            (i == 0 ? bit_circuits[0] : merged_bit_circuits[i - 1]),
            bit_circuits[i + 1],
            (i == num_bits - 2 ? output : &merged_bit_circuits[i]))) {
      LOG_ERROR("Failed to merge constant circuit at bit " + Itoa(i));
      return false;
    }
  }

  // Overwrite number of outputs, which treated outputs as bits instead
  // of appropriate data type.
  DataType type;
  if (!GetIntegerDataType(true, (int) num_bits, &type)) {
    LOG_ERROR("Unable to find appropriate DataType.");
    return false;
  }
  output->num_non_local_gates_ = 0;
  output->num_outputs_ = 1;
  output->output_designations_.clear();
  output->output_designations_.resize(1, make_pair(OutputRecipient(), type));
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.value_ = GenericValue(value & mask);

  // Reduce circuit.
  ReduceCircuit(false, output);

  return true;
}

bool ConstructSingleBitIdentityCircuit(
    const bool is_format_one,
    const int party_index,
    const uint64_t& input_index,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");

  output->depth_ = 1;
  output->size_ = 1;
  // IDENTITY gate can be computed locally, so doesn't count as non-local gate.
  output->num_non_local_gates_ = 0;
  output->num_outputs_ = 1;
  output->num_output_wires_ = 1;
  output->output_designations_.resize(
      1,
      make_pair<OutputRecipient, DataType>(OutputRecipient(), DataType::BOOL));
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_expression =
      "P" + Itoa(party_index) + "_" + Itoa(input_index);
  formula.value_ = GenericValue(var_expression);

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = 1;
  level.gates_.push_back(StandardGate<bool>());
  StandardGate<bool>& gate = level.gates_.back();
  gate.loc_ = GateLocation(0, 0);
  gate.type_ = BooleanOperation::IDENTITY;
  gate.depends_on_.insert(party_index);
  gate.output_wire_locations_.insert(WireLocation(-1, 0));

  if ((int) output->input_types_.size() <= party_index) {
    output->input_types_.resize(party_index + 1);
  }
  if (is_format_one) {
    output->input_types_[party_index].resize(input_index + 1);
    output->input_types_[party_index][input_index] =
        make_pair(var_expression, DataType::SLICE);
    if ((int) output->inputs_as_slice_locations_.size() <= party_index) {
      output->inputs_as_slice_locations_.resize(party_index + 1);
    }
    output->inputs_as_slice_locations_[party_index].resize(1 + input_index);
    output->inputs_as_slice_locations_[party_index][input_index].insert(
        WireLocation(0, 0, true));
  } else {
    output->input_types_[party_index].resize(input_index + 1);
    output->input_types_[party_index][input_index] =
        make_pair(var_expression, DataType::BOOL);
    if ((int) output->inputs_as_generic_value_locations_.size() <= party_index) {
      output->inputs_as_generic_value_locations_.resize(party_index + 1);
    }
    if (output->inputs_as_generic_value_locations_[party_index].size() <=
        input_index) {
      output->inputs_as_generic_value_locations_[party_index].resize(
          input_index + 1, vector<set<WireLocation>>());
    }
    vector<set<WireLocation>>& left_input_wire_for_first_input =
        output->inputs_as_generic_value_locations_[party_index][input_index];
    if (!left_input_wire_for_first_input.empty()) {
      LOG_FATAL("Unexpected.");
    }
    left_input_wire_for_first_input.push_back(set<WireLocation>());
    left_input_wire_for_first_input[0].insert(WireLocation(0, 0, true));
  }

  return true;
}

bool ConstructSingleBitIdentityCircuit(
    const bool is_format_one, StandardCircuit<bool>* output) {
  return ConstructSingleBitIdentityCircuit(is_format_one, 0, 0, output);
}

bool ConstructIdentityCircuit(
    const bool is_format_one,
    const bool is_signed_type,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& num_inputs,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");
  if (!is_format_one && num_inputs > sizeof(uint64_t) * CHAR_BIT) {
    LOG_FATAL("Identity circuit for a format 2 DataType is only supported "
              "for DataTypes with at most 64 bits (which is all of them, except "
              "STRINGXX for XX > 64).");
  }

  output->depth_ = 1;
  output->size_ = num_inputs;
  // IDENTITY gate can be computed locally, so doesn't count as non-local gate.
  output->num_non_local_gates_ = 0;
  output->num_outputs_ = num_inputs;
  output->num_output_wires_ = num_inputs;
  output->output_designations_.resize(
      num_inputs,
      make_pair<OutputRecipient, DataType>(
          OutputRecipient(), is_format_one ? DataType::SLICE : DataType::BOOL));
  output->function_description_.resize(num_inputs);
  for (uint64_t i = 0; i < num_inputs; ++i) {
    Formula& formula = output->function_description_[i];
    formula.op_.type_ = OperationType::BOOLEAN;
    formula.op_.gate_op_ =
        is_format_one ? BooleanOperation::IDENTITY : BooleanOperation::AND;
    const string var_expression = "P" + Itoa(party_index) + "_" +
        Itoa(input_index + (is_format_one ? i : 0));
    if (is_format_one) {
      formula.value_ = GenericValue(var_expression);
    } else {
      formula.subterm_one_.reset(new Formula());
      formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
      formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
      formula.subterm_one_->value_ = GenericValue(var_expression);
      formula.subterm_two_.reset(new Formula());
      formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
      formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
      const uint64_t bit_mask = (uint64_t) 1 << i;
      formula.subterm_two_->value_ = GenericValue(bit_mask);
    }
  }

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = num_inputs;

  level.gates_.resize(num_inputs);
  if ((int) output->input_types_.size() <= party_index) {
    output->input_types_.resize(party_index + 1);
  }
  if (is_format_one) {
    output->input_types_[party_index].resize(num_inputs + input_index);
    if ((int) output->inputs_as_slice_locations_.size() <= party_index) {
      output->inputs_as_slice_locations_.resize(party_index + 1);
    }
    output->inputs_as_slice_locations_[party_index].resize(
        num_inputs + input_index);
  } else {
    DataType int_type;
    if (!GetIntegerDataType(is_signed_type, (int) num_inputs, &int_type)) {
      return false;
    }
    // It's possible that the caller of this function already set the
    // input DataType, i.e. if the current function was called via the
    // API that specifies DataType; if not, treat this as an unsigned
    // DataType of the appropriate number of bits.
    if (output->input_types_[party_index].size() <= input_index) {
      output->input_types_[party_index].resize(input_index + 1);
      output->input_types_[party_index][input_index] =
          make_pair("P" + Itoa(party_index) + "_" + Itoa(input_index), int_type);
    }
    if ((int) output->inputs_as_generic_value_locations_.size() <= party_index) {
      output->inputs_as_generic_value_locations_.resize(party_index + 1);
    }
  }

  for (uint64_t gate_index = 0; gate_index < num_inputs; ++gate_index) {
    StandardGate<bool>& gate = level.gates_[gate_index];
    gate.loc_ = GateLocation(0, gate_index);
    gate.type_ = BooleanOperation::IDENTITY;
    gate.depends_on_.insert(party_index);
    gate.output_wire_locations_.insert(WireLocation(-1, gate_index));

    if (is_format_one) {
      const string var_expression =
          "P" + Itoa(party_index) + "_" + Itoa(gate_index + input_index);
      output->input_types_[party_index][gate_index + input_index] =
          make_pair(var_expression, DataType::SLICE);
      output->inputs_as_slice_locations_[party_index][gate_index + input_index]
          .insert(WireLocation(0, gate_index, true));
    } else {
      if (output->inputs_as_generic_value_locations_[party_index].size() <=
          input_index) {
        output->inputs_as_generic_value_locations_[party_index].resize(
            input_index + 1, vector<set<WireLocation>>());
      }
      vector<set<WireLocation>>& left_input_wire_for_first_input =
          output->inputs_as_generic_value_locations_[party_index][input_index];
      if (left_input_wire_for_first_input.size() <= gate_index) {
        left_input_wire_for_first_input.resize(gate_index + 1);
      }
      left_input_wire_for_first_input[gate_index].insert(
          WireLocation(0, gate_index, true));
    }
  }

  return true;
}

bool ConstructIdentityCircuit(
    const int party_index,
    const uint64_t& input_index,
    const DataType type,
    StandardCircuit<bool>* output) {
  return ConstructIdentityCircuit(
      false,
      IsSignedDataType(type),
      party_index,
      input_index,
      GetValueNumBits(type),
      output);
}

bool ConstructIdentityCircuit(
    const bool is_format_one,
    const bool is_signed_type,
    const uint64_t& num_inputs,
    StandardCircuit<bool>* output) {
  return ConstructIdentityCircuit(
      is_format_one, is_signed_type, 0, 0, num_inputs, output);
}

bool ConstructIdentityCircuit(
    const DataType type, StandardCircuit<bool>* output) {
  return ConstructIdentityCircuit(
      false, IsSignedDataType(type), GetValueNumBits(type), output);
}

bool ConstructSingleBitNotCircuit(
    const bool is_signed_type,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");
  if (bit_index >= sizeof(uint64_t) * CHAR_BIT) {
    LOG_FATAL("Identity circuit for a format 2 DataType is only supported "
              "for DataTypes with at most 64 bits (which is all of them, except "
              "STRINGXX for XX > 64).");
  }

  output->depth_ = 1;
  output->size_ = 1;
  output->num_outputs_ = 1;
  output->num_output_wires_ = 1;
  // NOT gate can be computed locally, so doesn't count as non-local gate.
  output->num_non_local_gates_ = 0;
  output->output_designations_.resize(
      1,
      make_pair<OutputRecipient, DataType>(OutputRecipient(), DataType::BOOL));
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = BooleanOperation::NOT;
  const string var_expression =
      "P" + Itoa(party_index) + "_" + Itoa(input_index);
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::AND;
  formula.subterm_one_->subterm_one_.reset(new Formula());
  formula.subterm_one_->subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->subterm_one_->value_ = GenericValue(var_expression);
  formula.subterm_one_->subterm_two_.reset(new Formula());
  formula.subterm_one_->subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const uint64_t bit_mask = (uint64_t) 1 << bit_index;
  formula.subterm_one_->subterm_two_->value_ = GenericValue(bit_mask);

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = 1;
  level.gates_.push_back(StandardGate<bool>());
  StandardGate<bool>& gate = level.gates_.back();
  gate.loc_ = GateLocation(0, 0);
  gate.type_ = BooleanOperation::NOT;
  gate.depends_on_.insert(party_index);
  gate.output_wire_locations_.insert(WireLocation(-1, 0));

  // Pick an appropriate DataType, based on best guess at number of bits
  // in this input.
  DataType int_type;
  if (!GetIntegerDataType(is_signed_type, (int) bit_index + 1, &int_type)) {
    return false;
  }

  if ((int) output->input_types_.size() <= party_index) {
    output->input_types_.resize(party_index + 1);
  }
  if ((int) output->inputs_as_generic_value_locations_.size() <= party_index) {
    output->inputs_as_generic_value_locations_.resize(party_index + 1);
  }
  output->input_types_[party_index].resize(input_index + 1);
  output->input_types_[party_index][input_index] =
      make_pair(var_expression, int_type);
  if (output->inputs_as_generic_value_locations_[party_index].size() <=
      input_index) {
    output->inputs_as_generic_value_locations_[party_index].resize(
        input_index + 1, vector<set<WireLocation>>());
  }
  vector<set<WireLocation>>& left_input_wire_for_first_input =
      output->inputs_as_generic_value_locations_[party_index][input_index];
  if (left_input_wire_for_first_input.size() <= bit_index) {
    left_input_wire_for_first_input.resize(bit_index + 1);
  }
  left_input_wire_for_first_input[bit_index].insert(WireLocation(0, 0, true));

  return true;
}

bool ConstructSingleBitNotCircuit(
    const bool is_format_one,
    const int party_index,
    const uint64_t& input_index,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");

  output->depth_ = 1;
  output->size_ = 1;
  output->num_outputs_ = 1;
  output->num_output_wires_ = 1;
  // NOT gate can be computed locally, so doesn't count as non-local gate.
  output->num_non_local_gates_ = 0;
  output->output_designations_.resize(
      1,
      make_pair<OutputRecipient, DataType>(OutputRecipient(), DataType::BOOL));
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = BooleanOperation::NOT;
  const string var_expression =
      "P" + Itoa(party_index) + "_" + Itoa(input_index);
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(var_expression);

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = 1;
  level.gates_.push_back(StandardGate<bool>());
  StandardGate<bool>& gate = level.gates_.back();
  gate.loc_ = GateLocation(0, 0);
  gate.type_ = BooleanOperation::NOT;
  gate.depends_on_.insert(party_index);
  gate.output_wire_locations_.insert(WireLocation(-1, 0));

  if ((int) output->input_types_.size() <= party_index) {
    output->input_types_.resize(party_index + 1);
  }
  if (is_format_one) {
    output->input_types_[party_index].resize(input_index + 1);
    output->input_types_[party_index][input_index] =
        make_pair(var_expression, DataType::SLICE);
    if ((int) output->inputs_as_slice_locations_.size() <= party_index) {
      output->inputs_as_slice_locations_.resize(party_index + 1);
    }
    output->inputs_as_slice_locations_[party_index].resize(1 + input_index);
    output->inputs_as_slice_locations_[party_index][input_index].insert(
        WireLocation(0, 0, true));
  } else {
    output->input_types_[party_index].resize(input_index + 1);
    output->input_types_[party_index][input_index] =
        make_pair(var_expression, DataType::BOOL);
    if ((int) output->inputs_as_generic_value_locations_.size() <= party_index) {
      output->inputs_as_generic_value_locations_.resize(party_index + 1);
    }
    if (output->inputs_as_generic_value_locations_[party_index].size() <=
        input_index) {
      output->inputs_as_generic_value_locations_[party_index].resize(
          input_index + 1, vector<set<WireLocation>>());
    }
    vector<set<WireLocation>>& left_input_wire_for_first_input =
        output->inputs_as_generic_value_locations_[party_index][input_index];
    if (left_input_wire_for_first_input.size() <= 0) {
      left_input_wire_for_first_input.resize(1);
    }
    left_input_wire_for_first_input[0].insert(WireLocation(0, 0, true));
  }

  return true;
}

bool ConstructSingleBitNotCircuit(
    const bool is_format_one, StandardCircuit<bool>* output) {
  return ConstructSingleBitNotCircuit(is_format_one, 0, (uint64_t) 0, output);
}

bool ConstructNotCircuit(
    const bool is_format_one,
    const bool is_signed_type,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& num_inputs,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");
  if (!is_format_one && num_inputs > sizeof(uint64_t) * CHAR_BIT) {
    LOG_FATAL("Identity circuit for a format 2 DataType is only supported "
              "for DataTypes with at most 64 bits (which is all of them, except "
              "STRINGXX for XX > 64).");
  }

  output->depth_ = 1;
  output->size_ = num_inputs;
  // NOT gate can be computed locally, so doesn't count as non-local gate.
  output->num_non_local_gates_ = 0;
  output->num_outputs_ = num_inputs;
  output->num_output_wires_ = num_inputs;
  output->output_designations_.resize(
      num_inputs,
      make_pair<OutputRecipient, DataType>(
          OutputRecipient(), is_format_one ? DataType::SLICE : DataType::BOOL));
  output->function_description_.resize(num_inputs);
  for (uint64_t i = 0; i < num_inputs; ++i) {
    Formula& formula = output->function_description_[i];
    formula.op_.type_ = OperationType::BOOLEAN;
    const string var_expression = "P" + Itoa(party_index) + "_" +
        Itoa(input_index + (is_format_one ? i : 0));
    formula.op_.gate_op_ = BooleanOperation::NOT;
    if (is_format_one) {
      formula.subterm_one_.reset(new Formula());
      formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
      formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
      formula.subterm_one_->value_ = GenericValue(var_expression);
    } else {
      formula.subterm_one_.reset(new Formula());
      formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
      formula.subterm_one_->op_.gate_op_ = BooleanOperation::AND;
      formula.subterm_one_->subterm_one_.reset(new Formula());
      formula.subterm_one_->subterm_one_->op_.type_ = OperationType::BOOLEAN;
      formula.subterm_one_->subterm_one_->op_.gate_op_ =
          BooleanOperation::IDENTITY;
      formula.subterm_one_->subterm_one_->value_ = GenericValue(var_expression);
      formula.subterm_one_->subterm_two_.reset(new Formula());
      formula.subterm_one_->subterm_two_->op_.type_ = OperationType::BOOLEAN;
      formula.subterm_one_->subterm_two_->op_.gate_op_ =
          BooleanOperation::IDENTITY;
      const uint64_t bit_mask = (uint64_t) 1 << i;
      formula.subterm_one_->subterm_two_->value_ = GenericValue(bit_mask);
    }
  }

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = num_inputs;

  level.gates_.resize(num_inputs);
  if ((int) output->input_types_.size() <= party_index) {
    output->input_types_.resize(party_index + 1);
  }
  if (is_format_one) {
    output->input_types_[party_index].resize(num_inputs + input_index);
    if ((int) output->inputs_as_slice_locations_.size() <= party_index) {
      output->inputs_as_slice_locations_.resize(party_index + 1);
    }
    output->inputs_as_slice_locations_[party_index].resize(
        input_index + num_inputs);
  } else {
    DataType int_type;
    if (!GetIntegerDataType(is_signed_type, (int) num_inputs, &int_type)) {
      return false;
    }

    // It's possible that the caller of this function already set the
    // input DataType, i.e. if the current function was called via the
    // API that specifies DataType; if not, treat this as an unsigned
    // DataType of the appropriate number of bits.
    if (output->input_types_[party_index].size() <= input_index) {
      output->input_types_[party_index].resize(input_index + 1);
      output->input_types_[party_index][input_index] =
          make_pair("P" + Itoa(party_index) + "_" + Itoa(input_index), int_type);
    }
    if ((int) output->inputs_as_generic_value_locations_.size() <= party_index) {
      output->inputs_as_generic_value_locations_.resize(party_index + 1);
    }
    output->inputs_as_generic_value_locations_[party_index].resize(
        input_index + 1);
  }

  for (uint64_t gate_index = 0; gate_index < num_inputs; ++gate_index) {
    StandardGate<bool>& gate = level.gates_[gate_index];
    gate.loc_ = GateLocation(0, gate_index);
    gate.type_ = BooleanOperation::NOT;
    gate.depends_on_.insert(party_index);
    gate.output_wire_locations_.insert(WireLocation(-1, gate_index));

    if (is_format_one) {
      const string var_expression =
          "P" + Itoa(party_index) + "_" + Itoa(gate_index + input_index);
      output->input_types_[party_index][gate_index + input_index] =
          make_pair(var_expression, DataType::SLICE);
      output->inputs_as_slice_locations_[party_index][gate_index + input_index]
          .insert(WireLocation(0, gate_index, true));
    } else {
      vector<set<WireLocation>>& left_input_wire_for_first_input =
          output->inputs_as_generic_value_locations_[party_index][input_index];
      if (left_input_wire_for_first_input.size() <= gate_index) {
        left_input_wire_for_first_input.resize(gate_index + 1);
      }
      left_input_wire_for_first_input[gate_index].insert(
          WireLocation(0, gate_index, true));
    }
  }

  return true;
}

bool ConstructNotCircuit(
    const bool is_format_one,
    const bool is_signed_type,
    const uint64_t& num_inputs,
    StandardCircuit<bool>* output) {
  return ConstructNotCircuit(
      is_format_one, is_signed_type, 0, 0, num_inputs, output);
}

bool ConstructNotCircuit(const DataType type, StandardCircuit<bool>* output) {
  return ConstructNotCircuit(
      false, IsSignedDataType(type), GetValueNumBits(type), output);
}

bool ConstructNotCircuit(
    const int party_index,
    const uint64_t& input_index,
    const DataType type,
    StandardCircuit<bool>* output) {
  return ConstructNotCircuit(
      false,
      IsSignedDataType(type),
      party_index,
      input_index,
      GetValueNumBits(type),
      output);
}

bool ConstructNotCircuit(
    const StandardCircuit<bool>& input, StandardCircuit<bool>* output) {
  if (output == nullptr || input.levels_.empty()) LOG_FATAL("Fatal Error.");
  // Don't trust input.depth_, just in case it's not set.
  const uint64_t input_depth = input.levels_.size();
  // Don't trust input.num_outputs_, just in case it's not set.
  uint64_t num_outputs = 0;

  // Start by just copying relevant fields of input circuit directly.
  output->depth_ = input_depth + 1;
  output->inputs_as_slice_locations_ = input.inputs_as_slice_locations_;
  output->inputs_as_generic_value_locations_ =
      input.inputs_as_generic_value_locations_;
  output->input_types_ = input.input_types_;
  output->constant_slice_input_ = input.constant_slice_input_;
  output->constant_zero_input_ = input.constant_zero_input_;
  output->constant_one_input_ = input.constant_one_input_;
  output->output_designations_ = input.output_designations_;
  // This method just adds a NOT for each output wire. Since NOT is a locally
  // computable gate, the number of non-locally computable gates per party
  // is unchanged.
  output->num_non_local_gates_ = input.num_non_local_gates_;
  if (!input.function_description_.empty()) {
    output->function_description_.resize(input.function_description_.size());
    for (size_t i = 0; i < input.function_description_.size(); ++i) {
      Formula& output_i = output->function_description_[i];
      output_i.op_.type_ = OperationType::BOOLEAN;
      output_i.op_.gate_op_ = BooleanOperation::NOT;
      output_i.subterm_one_ = unique_ptr<Formula>(new Formula());
      output_i.subterm_one_->clone(input.function_description_[i]);
    }
  }

  // Walk through input circuit, copying each (non-output) gate.
  // For output gates, re-direct their output wires to a gate on the
  // new output level.
  output->levels_.resize(input.levels_.size() + 1);
  // The following keeps track of of the dependencies of each (global)
  // output wire of 'input'.
  vector<set<int>> output_depends_on(input.num_output_wires_);
  for (uint64_t level = 0; level < input.levels_.size(); ++level) {
    const StandardCircuitLevel<bool>& old_level = input.levels_[level];
    StandardCircuitLevel<bool>& new_level = output->levels_[level];
    new_level.level_ = level;
    new_level.num_gates_ = old_level.gates_.size();
    const uint64_t num_gates = old_level.gates_.size();
    new_level.gates_.resize(num_gates);
    for (uint64_t gate_index = 0; gate_index < num_gates; ++gate_index) {
      const StandardGate<bool>& old_gate = old_level.gates_[gate_index];
      StandardGate<bool>& new_gate = new_level.gates_[gate_index];
      new_gate.loc_ = GateLocation(level, gate_index);
      new_gate.depends_on_ = old_gate.depends_on_;
      new_gate.type_ = old_gate.type_;
      for (const WireLocation& old_loc : old_gate.output_wire_locations_) {
        // Test if the output wire is a global/circuit output wire. If so,
        // update it to point to a gate on the (newly created) last level;
        // otherwise, just copy the location to the new gate.
        if (old_loc.loc_.level_ == -1) {
          new_gate.output_wire_locations_.insert(
              WireLocation(input_depth, old_loc.loc_.index_, true));
          output_depends_on[old_loc.loc_.index_] = old_gate.depends_on_;
          ++num_outputs;
        } else {
          new_gate.output_wire_locations_.insert(WireLocation(
              old_loc.loc_.level_, old_loc.loc_.index_, old_loc.is_left_));
        }
      }
    }
  }

  // Now construct a final level, with all gates equal to NOT (input wires
  // to these gates were already set above, as the previous circuit's outputs).
  StandardCircuitLevel<bool>& new_level = output->levels_.back();
  new_level.level_ = input_depth;
  new_level.num_gates_ = num_outputs;
  new_level.gates_.resize(num_outputs);
  for (uint64_t i = 0; i < num_outputs; ++i) {
    StandardGate<bool>& new_gate = new_level.gates_[i];
    new_gate.loc_ = GateLocation(input_depth, i);
    new_gate.type_ = BooleanOperation::NOT;
    new_gate.depends_on_ = output_depends_on[i];
    new_gate.output_wire_locations_.insert(WireLocation(-1, i));
  }

  // Finish remaining fields, now that we know how many gates were added.
  output->size_ = input.size_ + num_outputs;
  output->num_output_wires_ = num_outputs;
  output->num_outputs_ = num_outputs;

  return true;
}

bool ConstructSelectBitCircuit(
    const bool is_signed_type,
    const int party_index,
    const uint64_t& input_index,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");
  if (bit_index >= sizeof(uint64_t) * CHAR_BIT) {
    LOG_FATAL("SelectBit circuit for a Format 2 DataType is only supported "
              "for DataTypes with at most 64 bits (which is all of them, except "
              "STRINGXX for XX > 64).");
  }

  output->depth_ = 1;
  output->size_ = 1;
  output->num_outputs_ = 1;
  output->num_output_wires_ = 1;
  // IDENTITY gate can be computed locally, so doesn't count as non-local gate.
  output->num_non_local_gates_ = 0;
  output->output_designations_.resize(
      1,
      make_pair<OutputRecipient, DataType>(OutputRecipient(), DataType::BOOL));
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = BooleanOperation::AND;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string var_expression =
      "P" + Itoa(party_index) + "_" + Itoa(input_index);
  formula.subterm_one_->value_ = GenericValue(var_expression);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const uint64_t bit_mask = (uint64_t) 1 << bit_index;
  formula.subterm_two_->value_ = GenericValue(bit_mask);

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = 1;
  level.gates_.push_back(StandardGate<bool>());
  StandardGate<bool>& gate = level.gates_.back();
  gate.loc_ = GateLocation(0, 0);
  gate.type_ = BooleanOperation::IDENTITY;
  gate.depends_on_.insert(party_index);
  gate.output_wire_locations_.insert(WireLocation(-1, 0));

  DataType int_type;
  if (!GetIntegerDataType(is_signed_type, (int) bit_index + 1, &int_type)) {
    return false;
  }

  // It's possible that the caller of this function already set the
  // input DataType, i.e. if the current function was called via the
  // API that specifies DataType; if not, treat this as an unsigned
  // DataType of the appropriate number of bits.
  if ((int) output->input_types_.size() <= party_index) {
    output->input_types_.resize(party_index + 1);
  }
  if ((int) output->inputs_as_generic_value_locations_.size() <= party_index) {
    output->inputs_as_generic_value_locations_.resize(party_index + 1);
  }
  if (output->input_types_[party_index].size() <= input_index) {
    output->input_types_[party_index].resize(input_index + 1);
    output->input_types_[party_index][input_index] =
        make_pair("P" + Itoa(party_index) + "_" + Itoa(input_index), int_type);
  }
  if (output->inputs_as_generic_value_locations_[party_index].size() <=
      input_index) {
    output->inputs_as_generic_value_locations_[party_index].resize(
        input_index + 1, vector<set<WireLocation>>());
  }
  vector<set<WireLocation>>& left_input_wire_for_first_input =
      output->inputs_as_generic_value_locations_[party_index][input_index];
  if (left_input_wire_for_first_input.size() <= bit_index) {
    left_input_wire_for_first_input.resize(bit_index + 1);
  }
  left_input_wire_for_first_input[bit_index].insert(WireLocation(0, 0, true));

  return true;
}

bool ConstructSelectBitCircuit(
    const bool is_signed_type,
    const uint64_t& bit_index,
    StandardCircuit<bool>* output) {
  return ConstructSelectBitCircuit(is_signed_type, 0, 0, bit_index, output);
}

bool ConstructSelectBitsCircuit(
    const bool is_signed_type,
    const int party_index,
    const vector<pair<uint64_t, uint64_t>>& bit_indices,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");

  const uint64_t num_bits_selected = bit_indices.size();

  output->depth_ = 1;
  output->size_ = num_bits_selected;
  output->num_outputs_ = num_bits_selected;
  output->num_output_wires_ = num_bits_selected;
  // IDENTITY gate can be computed locally, so doesn't count as non-local gate.
  output->num_non_local_gates_ = 0;
  output->output_designations_.resize(
      num_bits_selected,
      make_pair<OutputRecipient, DataType>(OutputRecipient(), DataType::BOOL));
  output->function_description_.resize(num_bits_selected);
  for (size_t i = 0; i < num_bits_selected; ++i) {
    const uint64_t& input_index = bit_indices[i].first;
    const uint64_t& bit_index = bit_indices[i].second;
    const string var_expression =
        "P" + Itoa(party_index) + "_" + Itoa(input_index);
    Formula& formula = output->function_description_[i];
    formula.op_.type_ = OperationType::BOOLEAN;
    formula.op_.gate_op_ = BooleanOperation::AND;
    formula.subterm_one_.reset(new Formula());
    formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
    formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
    formula.subterm_one_->value_ = GenericValue(var_expression);
    formula.subterm_two_.reset(new Formula());
    formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
    formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
    const uint64_t bit_mask = (uint64_t) 1 << bit_index;
    formula.subterm_two_->value_ = GenericValue(bit_mask);
  }

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = num_bits_selected;
  level.gates_.resize(num_bits_selected);

  for (uint64_t i = 0; i < num_bits_selected; ++i) {
    StandardGate<bool>& gate = level.gates_[i];
    gate.loc_ = GateLocation(0, i);
    gate.type_ = BooleanOperation::IDENTITY;
    gate.depends_on_.insert(party_index);
    gate.output_wire_locations_.insert(WireLocation(-1, i));

    const uint64_t& input_index = bit_indices[i].first;
    const uint64_t& bit_index = bit_indices[i].second;
    if (bit_index >= sizeof(uint64_t) * CHAR_BIT) {
      LOG_FATAL(
          "SelectBit circuit for a Format 2 DataType is only supported "
          "for DataTypes with at most 64 bits (which is all of them, except "
          "STRINGXX for XX > 64).");
    }

    DataType int_type;
    if (!GetIntegerDataType(is_signed_type, (int) bit_index + 1, &int_type)) {
      return false;
    }

    // It's possible that the caller of this function already set the
    // input DataType, i.e. if the current function was called via the
    // API that specifies DataType; if not, treat this as an unsigned
    // DataType of the appropriate number of bits.
    if ((int) output->input_types_.size() <= party_index) {
      output->input_types_.resize(party_index + 1);
    }
    if (output->input_types_[party_index].size() <= input_index) {
      output->input_types_[party_index].resize(input_index + 1);
      output->input_types_[party_index][input_index] =
          make_pair("P" + Itoa(party_index) + "_" + Itoa(input_index), int_type);
      // An earlier loop through may have set number of bits based on a lower
      // bit-index, if we have a higher one here, update the DataType.
    } else {
      pair<string, DataType>& existing_entry =
          output->input_types_[party_index][input_index];
      if (existing_entry.first !=
          ("P" + Itoa(party_index) + "_" + Itoa(input_index))) {
        LOG_FATAL("Fatal Error.");
      }
      if (GetValueNumBits(existing_entry.second) <= bit_index) {
        existing_entry.second = int_type;
      }
    }
    if ((int) output->inputs_as_generic_value_locations_.size() <= party_index) {
      output->inputs_as_generic_value_locations_.resize(party_index + 1);
    }
    if (output->inputs_as_generic_value_locations_[party_index].size() <=
        input_index) {
      output->inputs_as_generic_value_locations_[party_index].resize(
          input_index + 1, vector<set<WireLocation>>());
    }
    vector<set<WireLocation>>& left_input_wire_for_first_input =
        output->inputs_as_generic_value_locations_[party_index][input_index];
    if (left_input_wire_for_first_input.size() <= bit_index) {
      left_input_wire_for_first_input.resize(bit_index + 1);
    }
    left_input_wire_for_first_input[bit_index].insert(WireLocation(0, i, true));
  }

  return true;
}

bool ConstructSelectBitsCircuit(
    const bool is_signed_type,
    const vector<uint64_t>& bit_indices,
    StandardCircuit<bool>* output) {
  vector<pair<uint64_t, uint64_t>> temp(bit_indices.size());
  for (uint64_t i = 0; i < bit_indices.size(); ++i) {
    temp[i] = make_pair(0, bit_indices[i]);
  }
  return ConstructSelectBitsCircuit(is_signed_type, true, temp, output);
}

bool ConstructScalarMultiplicationCircuit(
    const uint64_t& vector_size, StandardCircuit<bool>* output) {
  // First construct a circuit that multiplies two bits.
  StandardCircuit<bool> bit_product;
  if (!ConstructBooleanCircuit(
          BooleanOperation::AND,
          false,
          1,
          (vector_size == 1 ? output : &bit_product))) {
    return false;
  }

  // Create a bunch of duplicate circuits.
  vector<StandardCircuit<bool>> bit_products(vector_size - 1);
  if (vector_size > 1) bit_products[0] = bit_product;
  for (uint64_t i = 1; i < vector_size; ++i) {
    if (!MergeCircuitsInternal(
            true,
            BooleanOperation::IDENTITY,
            bit_product,
            bit_products[i - 1],
            (i < (vector_size - 1) ? &(bit_products[i]) : output))) {
      return false;
    }
  }

  // Just need to relabel the inputs (for the vector, it thinks it has
  // size one, and the same coordinate is used over and over).
  output->input_types_.resize(2);
  output->input_types_[1].resize(vector_size);
  output->inputs_as_generic_value_locations_.resize(2);
  output->inputs_as_generic_value_locations_[1].resize(vector_size);
  for (uint64_t i = 0; i < vector_size; ++i) {
    output->input_types_[1][i] = make_pair("P1_" + Itoa(i), DataType::BOOL);
    output->inputs_as_generic_value_locations_[1][i].resize(1);

    set<WireLocation> multiplier_loc;
    multiplier_loc.insert(WireLocation(0, i, false));
    output->inputs_as_generic_value_locations_[1][i][0] = multiplier_loc;
  }

  return true;
}

bool ConstructScalarMultiplicationCircuit(
    const DataType type,
    const uint64_t& vector_size,
    StandardCircuit<bool>* output) {
  // First construct a circuit that multiplies two values.
  StandardCircuit<bool> product;
  if (!ConstructArithmeticCircuit(
          true,
          ArithmeticOperation::MULT,
          type,
          type,
          (vector_size == 1 ? output : &product))) {
    return false;
  }

  // Create a bunch of duplicate circuits.
  vector<StandardCircuit<bool>> products(vector_size - 1);
  if (vector_size > 1) products[0] = product;
  for (uint64_t i = 1; i < vector_size; ++i) {
    if (!MergeCircuitsInternal(
            true,
            BooleanOperation::IDENTITY,
            product,
            products[i - 1],
            (i < (vector_size - 1) ? &(products[i]) : output))) {
      return false;
    }
  }

  // Just need to relabel the inputs (for the vector, it thinks it has
  // size one, and the same coordinate is used over and over).
  output->input_types_.resize(2);
  output->input_types_[1].resize(vector_size);
  output->inputs_as_generic_value_locations_.resize(2);
  output->inputs_as_generic_value_locations_[1].resize(vector_size);
  const int num_bits_per_value = (int) GetValueNumBits(type);
  for (uint64_t i = 0; i < vector_size; ++i) {
    output->input_types_[1][i] = make_pair("P1_" + Itoa(i), type);
    output->inputs_as_generic_value_locations_[1][i].resize(vector_size);
    for (int j = 0; j < num_bits_per_value; ++j) {
      set<WireLocation> gate_loc;
      gate_loc.insert(WireLocation(0, i * num_bits_per_value + j, false));
      output->inputs_as_generic_value_locations_[1][i][j] = gate_loc;
    }
  }

  return true;
}

bool ConstructVectorConcatenationCircuit(
    const uint64_t& left_vector_size,
    const uint64_t& right_vector_size,
    StandardCircuit<bool>* output) {
  return ConstructVectorConcatenationCircuit(
      DataType::BOOL, left_vector_size, right_vector_size, output);
}

bool ConstructVectorConcatenationCircuit(
    const DataType type,
    const uint64_t& left_vector_size,
    const uint64_t& right_vector_size,
    StandardCircuit<bool>* output) {
  // Create the identity circuit for a single input.
  StandardCircuit<bool> party_one, party_two;
  if (!ConstructIdentityCircuit(0, 0, type, &party_one) ||
      !ConstructIdentityCircuit(1, 0, type, &party_two)) {
    return false;
  }

  // Merge these identity circuits together, so they are the identity
  // on the proper number of values (based on vector length).
  vector<StandardCircuit<bool>> party_one_all(left_vector_size);
  party_one_all[0] = party_one;
  for (uint64_t i = 1; i < left_vector_size; ++i) {
    if (!MergeCircuitsInternal(
            false,
            BooleanOperation::IDENTITY,
            party_one_all[i - 1],
            party_one,
            &party_one_all[i])) {
      return false;
    }
  }
  vector<StandardCircuit<bool>> party_two_all(right_vector_size);
  party_two_all[0] = party_two;
  for (uint64_t i = 1; i < right_vector_size; ++i) {
    if (!MergeCircuitsInternal(
            false,
            BooleanOperation::IDENTITY,
            party_two_all[i - 1],
            party_two,
            &party_two_all[i])) {
      return false;
    }
  }

  return MergeCircuitsInternal(
      true,
      BooleanOperation::IDENTITY,
      party_one_all.back(),
      party_two_all.back(),
      output);
}

bool ConstructBitComparisonCircuit(
    const bool is_format_one,
    const BooleanOperation& op,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");
  // Use alternate API for IDENTITY and NOT circuits.
  if (op == BooleanOperation::IDENTITY || op == BooleanOperation::NOT) {
    LOG_FATAL("Fatal Error.");
  }

  output->depth_ = 1;
  output->size_ = 1;
  const int is_non_local_gate =
      (op == BooleanOperation::XOR || op == BooleanOperation::EQ) ? 0 : 1;
  output->num_non_local_gates_ = is_non_local_gate ? 1 : 0;
  output->num_outputs_ = 1;
  output->num_output_wires_ = 1;
  output->output_designations_.resize(
      1,
      make_pair<OutputRecipient, DataType>(OutputRecipient(), DataType::BOOL));
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = op;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(string("P0_0"));
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(string("P1_0"));

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = 1;
  level.gates_.push_back(StandardGate<bool>());
  StandardGate<bool>& gate = level.gates_.back();
  gate.loc_ = GateLocation(0, 0);
  gate.type_ = op;
  gate.depends_on_.insert(0);
  gate.depends_on_.insert(1);
  gate.output_wire_locations_.insert(WireLocation(-1, 0));

  if (output->input_types_.size() < 2) {
    output->input_types_.resize(2);
  }
  output->input_types_[0].resize(1);
  output->input_types_[0][0] =
      make_pair("P0_0", (is_format_one ? DataType::SLICE : DataType::BOOL));
  output->input_types_[1].resize(1);
  output->input_types_[1][0] =
      make_pair("P1_0", (is_format_one ? DataType::SLICE : DataType::BOOL));
  if (is_format_one) {
    if (output->inputs_as_slice_locations_.size() < 2) {
      output->inputs_as_slice_locations_.resize(2);
    }
    output->inputs_as_slice_locations_[0].resize(1);
    output->inputs_as_slice_locations_[0][0].insert(WireLocation(0, 0, true));
    output->inputs_as_slice_locations_[1].resize(1);
    output->inputs_as_slice_locations_[1][0].insert(WireLocation(0, 0, false));
  } else {
    if (output->inputs_as_generic_value_locations_.size() < 2) {
      output->inputs_as_generic_value_locations_.resize(2);
    }
    output->inputs_as_generic_value_locations_[0].resize(
        1, vector<set<WireLocation>>(1, set<WireLocation>()));
    output->inputs_as_generic_value_locations_[0][0][0].insert(
        WireLocation(0, 0, true));
    output->inputs_as_generic_value_locations_[1].resize(
        1, vector<set<WireLocation>>(1, set<WireLocation>()));
    output->inputs_as_generic_value_locations_[1][0][0].insert(
        WireLocation(0, 0, false));
  }

  return true;
}

bool ConstructBitComparisonCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int bit_one_party_index,
    const int bit_two_party_index,
    const uint64_t& one_input_index,
    const uint64_t& one_bit_index,
    const uint64_t& two_input_index,
    const uint64_t& two_bit_index,
    const BooleanOperation& op,
    StandardCircuit<bool>* output) {
  if (output == nullptr) LOG_FATAL("Null input.");

  output->depth_ = 1;
  output->size_ = 1;
  output->num_non_local_gates_ =
      (op == BooleanOperation::XOR || op == BooleanOperation::EQ) ? 0 : 1;
  output->num_outputs_ = 1;
  output->num_output_wires_ = 1;
  output->output_designations_.resize(
      1,
      make_pair<OutputRecipient, DataType>(OutputRecipient(), DataType::BOOL));
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = op;
  // Set left ('one') input.
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::AND;
  formula.subterm_one_->subterm_one_.reset(new Formula());
  formula.subterm_one_->subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string one_var_expression =
      "P" + Itoa(bit_one_party_index) + "_" + Itoa(one_input_index);
  formula.subterm_one_->subterm_one_->value_ = GenericValue(one_var_expression);
  formula.subterm_one_->subterm_two_.reset(new Formula());
  formula.subterm_one_->subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const uint64_t one_bit_mask = (uint64_t) 1 << one_bit_index;
  formula.subterm_one_->subterm_two_->value_ = GenericValue(one_bit_mask);
  // Set right ('two') input.
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::AND;
  formula.subterm_two_->subterm_one_.reset(new Formula());
  formula.subterm_two_->subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string two_var_expression =
      "P" + Itoa(bit_two_party_index) + "_" + Itoa(two_input_index);
  formula.subterm_two_->subterm_one_->value_ = GenericValue(two_var_expression);
  formula.subterm_two_->subterm_two_.reset(new Formula());
  formula.subterm_two_->subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const uint64_t two_bit_mask = (uint64_t) 1 << two_bit_index;
  formula.subterm_two_->subterm_two_->value_ = GenericValue(two_bit_mask);

  output->levels_.push_back(StandardCircuitLevel<bool>());
  StandardCircuitLevel<bool>& level = output->levels_.back();
  level.level_ = 0;
  level.num_gates_ = 1;
  level.gates_.push_back(StandardGate<bool>());
  StandardGate<bool>& gate = level.gates_.back();
  gate.loc_ = GateLocation(0, 0);
  gate.type_ = op;
  gate.depends_on_.insert(bit_one_party_index);
  gate.depends_on_.insert(bit_two_party_index);
  gate.output_wire_locations_.insert(WireLocation(-1, 0));

  DataType one_int_type;
  if (!GetIntegerDataType(
          one_is_twos_complement, (int) one_bit_index + 1, &one_int_type)) {
    return false;
  }
  DataType two_int_type;
  if (!GetIntegerDataType(
          two_is_twos_complement, (int) two_bit_index + 1, &two_int_type)) {
    return false;
  }

  if ((int) output->input_types_.size() <= bit_one_party_index) {
    output->input_types_.resize(bit_one_party_index + 1);
  }
  output->input_types_[bit_one_party_index].resize(one_input_index + 1);
  output->input_types_[bit_one_party_index][one_input_index] =
      make_pair(one_var_expression, one_int_type);
  if ((int) output->inputs_as_generic_value_locations_.size() <=
      bit_one_party_index) {
    output->inputs_as_generic_value_locations_.resize(bit_one_party_index + 1);
  }
  if (output->inputs_as_generic_value_locations_[bit_one_party_index].size() <=
      one_input_index) {
    output->inputs_as_generic_value_locations_[bit_one_party_index].resize(
        one_input_index + 1, vector<set<WireLocation>>());
  }
  vector<set<WireLocation>>& left_input_wire_for_first_input =
      output->inputs_as_generic_value_locations_[bit_one_party_index]
                                                [one_input_index];
  if (left_input_wire_for_first_input.size() <= one_bit_index) {
    left_input_wire_for_first_input.resize(one_bit_index + 1);
  }
  left_input_wire_for_first_input[one_bit_index].insert(
      WireLocation(0, 0, true));
  if ((int) output->input_types_.size() <= bit_two_party_index) {
    output->input_types_.resize(bit_two_party_index + 1);
  }
  if (output->input_types_[bit_two_party_index].size() <= two_input_index) {
    output->input_types_[bit_two_party_index].resize(two_input_index + 1);
  }
  output->input_types_[bit_two_party_index][two_input_index] =
      make_pair(two_var_expression, two_int_type);
  if ((int) output->inputs_as_generic_value_locations_.size() <=
      bit_two_party_index) {
    output->inputs_as_generic_value_locations_.resize(bit_two_party_index + 1);
  }
  if (output->inputs_as_generic_value_locations_[bit_two_party_index].size() <=
      two_input_index) {
    output->inputs_as_generic_value_locations_[bit_two_party_index].resize(
        two_input_index + 1, vector<set<WireLocation>>());
  }
  vector<set<WireLocation>>& right_input_wire_for_first_input =
      output->inputs_as_generic_value_locations_[bit_two_party_index]
                                                [two_input_index];
  if (right_input_wire_for_first_input.size() <= two_bit_index) {
    right_input_wire_for_first_input.resize(two_bit_index + 1);
  }
  right_input_wire_for_first_input[two_bit_index].insert(
      WireLocation(0, 0, false));

  return true;
}

bool ConstructBitComparisonCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const uint64_t& one_input_index,
    const uint64_t& one_bit_index,
    const uint64_t& two_input_index,
    const uint64_t& two_bit_index,
    const BooleanOperation& op,
    StandardCircuit<bool>* output) {
  return ConstructBitComparisonCircuit(
      one_is_twos_complement,
      two_is_twos_complement,
      0,
      1,
      one_input_index,
      one_bit_index,
      two_input_index,
      two_bit_index,
      op,
      output);
}

bool ConstructBitComparisonCircuit(
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const uint64_t& one_bit_index,
    const uint64_t& two_bit_index,
    const BooleanOperation& op,
    StandardCircuit<bool>* output) {
  return ConstructBitComparisonCircuit(
      one_is_twos_complement,
      two_is_twos_complement,
      0,
      one_bit_index,
      0,
      two_bit_index,
      op,
      output);
}

bool ConstructBooleanCircuit(
    const BooleanOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output) {
  // Handle the two single-input BooleanOperation's (IDENTITY and NOT) separately.
  if (op == BooleanOperation::IDENTITY) {
    return ConstructIdentityCircuit(
        false,
        one_is_twos_complement,
        value_one_party_index,
        value_one_input_index,
        num_input_bits,
        output);
  } else if (op == BooleanOperation::NOT) {
    return ConstructNotCircuit(
        false,
        one_is_twos_complement,
        value_one_party_index,
        value_one_input_index,
        num_input_bits,
        output);
  }

  // Make a bunch of depth-1 circuits that just compare one bit.
  vector<StandardCircuit<bool>> bit_comparisons(num_input_bits);
  for (uint64_t i = 0; i < num_input_bits; ++i) {
    if (!ConstructBitComparisonCircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_two_party_index,
            value_one_input_index,
            i,
            value_two_input_index,
            i,
            op,
            num_input_bits == 1 ? output : &bit_comparisons[i])) {
      return false;
    }
  }

  // Now Merge together the above circuits.
  vector<StandardCircuit<bool>> merged_bit_comparisons(num_input_bits - 1);
  for (uint64_t i = 0; i < num_input_bits - 1; ++i) {
    if (!MergeCircuits(
            true,
            BooleanOperation::IDENTITY,
            (i == 0 ? bit_comparisons[0] : merged_bit_comparisons[i - 1]),
            bit_comparisons[i + 1],
            (i == num_input_bits - 2 ? output : &merged_bit_comparisons[i]))) {
      return false;
    }
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  if (output->function_description_.size() != num_input_bits) {
    LOG_FATAL("Fatal Error.");
  }
  output->function_description_.clear();
  output->function_description_.resize(num_input_bits);
  if (num_input_bits == 1) {
    Formula& formula = output->function_description_[0];
    const string var_one_str =
        "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
    const string var_two_str =
        "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
    formula.op_.type_ = OperationType::BOOLEAN;
    formula.op_.gate_op_ = op;
    formula.subterm_one_.reset(new Formula());
    formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
    formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
    formula.subterm_one_->value_ = GenericValue(var_one_str);
    formula.subterm_two_.reset(new Formula());
    formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
    formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
    formula.subterm_two_->value_ = GenericValue(var_two_str);
  } else {
    for (uint64_t i = 0; i < num_input_bits; ++i) {
      Formula& formula_i = output->function_description_[i];
      const string mask_str =
          num_input_bits == 1 ? "" : (" AND " + Itoa(pow((uint64_t) 2, i)));
      const string var_one_str =
          "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
      const string var_two_str =
          "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
      formula_i.op_.type_ = OperationType::BOOLEAN;
      formula_i.op_.gate_op_ = op;

      formula_i.subterm_one_.reset(new Formula());
      formula_i.subterm_one_->op_.type_ = OperationType::BOOLEAN;
      formula_i.subterm_one_->op_.gate_op_ = BooleanOperation::AND;
      formula_i.subterm_one_->subterm_one_.reset(new Formula());
      formula_i.subterm_one_->subterm_one_->op_.type_ = OperationType::BOOLEAN;
      formula_i.subterm_one_->subterm_one_->op_.gate_op_ =
          BooleanOperation::IDENTITY;
      formula_i.subterm_one_->subterm_one_->value_ = GenericValue(var_one_str);
      formula_i.subterm_one_->subterm_two_.reset(new Formula());
      formula_i.subterm_one_->subterm_two_->op_.type_ = OperationType::BOOLEAN;
      formula_i.subterm_one_->subterm_two_->op_.gate_op_ =
          BooleanOperation::IDENTITY;
      formula_i.subterm_one_->subterm_two_->value_ =
          GenericValue(pow((uint64_t) 2, i));

      formula_i.subterm_two_.reset(new Formula());
      formula_i.subterm_two_->op_.type_ = OperationType::BOOLEAN;
      formula_i.subterm_two_->op_.gate_op_ = BooleanOperation::AND;
      formula_i.subterm_two_->subterm_one_.reset(new Formula());
      formula_i.subterm_two_->subterm_one_->op_.type_ = OperationType::BOOLEAN;
      formula_i.subterm_two_->subterm_one_->op_.gate_op_ =
          BooleanOperation::IDENTITY;
      formula_i.subterm_two_->subterm_one_->value_ = GenericValue(var_two_str);
      formula_i.subterm_two_->subterm_two_.reset(new Formula());
      formula_i.subterm_two_->subterm_two_->op_.type_ = OperationType::BOOLEAN;
      formula_i.subterm_two_->subterm_two_->op_.gate_op_ =
          BooleanOperation::IDENTITY;
      formula_i.subterm_two_->subterm_two_->value_ =
          GenericValue(pow((uint64_t) 2, i));
    }
  }

  return true;
}

bool ConstructBooleanCircuit(
    const BooleanOperation& op,
    const bool is_signed_type,
    const uint64_t& num_input_bits,
    StandardCircuit<bool>* output) {
  // Handle the two single-input BooleanOperation's (IDENTITY and NOT) separately.
  if (op == BooleanOperation::IDENTITY) {
    return ConstructIdentityCircuit(
        false, is_signed_type, num_input_bits, output);
  } else if (op == BooleanOperation::NOT) {
    return ConstructNotCircuit(false, is_signed_type, num_input_bits, output);
  }

  // Make a bunch of depth-1 circuits that just compare one bit.
  vector<StandardCircuit<bool>> bit_comparisons(num_input_bits);
  for (uint64_t i = 0; i < num_input_bits; ++i) {
    if (!ConstructBitComparisonCircuit(
            is_signed_type,
            is_signed_type,
            0,
            1,
            i,
            0,
            i,
            0,
            op,
            num_input_bits == 1 ? output : &bit_comparisons[i])) {
      return false;
    }
  }

  // Now Merge together the above circuits.
  vector<StandardCircuit<bool>> merged_bit_comparisons(num_input_bits - 1);
  for (uint64_t i = 0; i < num_input_bits - 1; ++i) {
    if (!MergeCircuits(
            true,
            BooleanOperation::IDENTITY,
            (i == 0 ? bit_comparisons[0] : merged_bit_comparisons[i - 1]),
            bit_comparisons[i + 1],
            (i == num_input_bits - 2 ? output : &merged_bit_comparisons[i]))) {
      return false;
    }
  }

  // Overwrite function_description_, which may have gotten overly complicated.
  if (output->function_description_.size() != num_input_bits) {
    LOG_FATAL("Fatal Error.");
  }
  output->function_description_.clear();
  output->function_description_.resize(num_input_bits);
  for (uint64_t i = 0; i < num_input_bits; ++i) {
    Formula& formula_i = output->function_description_[i];
    const string var_one_str = "P0_" + Itoa(i);
    const string var_two_str = "P1_" + Itoa(i);
    formula_i.op_.type_ = OperationType::BOOLEAN;
    formula_i.op_.gate_op_ = op;

    formula_i.subterm_one_.reset(new Formula());
    formula_i.subterm_one_->op_.type_ = OperationType::BOOLEAN;
    formula_i.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
    formula_i.subterm_one_->value_ = GenericValue(var_one_str);
    formula_i.subterm_two_.reset(new Formula());
    formula_i.subterm_two_->op_.type_ = OperationType::BOOLEAN;
    formula_i.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
    formula_i.subterm_two_->value_ = GenericValue(var_two_str);
  }

  return true;
}

bool ConstructBooleanCircuit(
    const BooleanOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const DataType input_type,
    StandardCircuit<bool>* output) {
  const uint64_t input_type_num_bits = GetValueNumBits(input_type);
  if (!ConstructBooleanCircuit(
          op,
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          input_type_num_bits,
          output)) {
    LOG_ERROR("Failed to ConstructBooleanCircuit");
    return false;
  }

  // The above created a circuit whose input and output types were treated as bits.
  // Instead, we want to view the bits as representing a single value
  // (of type 'input_type').
  output->num_outputs_ = 1;
  output->output_designations_.clear();
  output->output_designations_.resize(
      1, make_pair(OutputRecipient(), input_type));
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = op;
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string one_var_str =
      "P" + Itoa(value_one_party_index) + "_" + Itoa(value_one_input_index);
  formula.subterm_one_->value_ = GenericValue(one_var_str);
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  const string two_var_str =
      "P" + Itoa(value_two_party_index) + "_" + Itoa(value_two_input_index);
  formula.subterm_two_->value_ = GenericValue(two_var_str);

  return true;
}

bool ConstructBooleanCircuit(
    const BooleanOperation& op,
    const DataType input_type,
    StandardCircuit<bool>* output) {
  if (!ConstructBooleanCircuit(
          op,
          IsSignedDataType(input_type),
          IsSignedDataType(input_type),
          0,
          0,
          1,
          0,
          input_type,
          output)) {
    LOG_ERROR("Failed to ConstructBooleanCircuit");
    return false;
  }

  // The above created a circuit whose output types were treated as bits.
  // Instead, we want to view the bits as representing a single value
  // (of type 'input_type').
  output->num_outputs_ = 1;
  output->output_designations_.clear();
  output->output_designations_.resize(
      1, make_pair(OutputRecipient(), input_type));
  output->function_description_.clear();
  output->function_description_.resize(1);
  Formula& formula = output->function_description_[0];
  formula.op_.type_ = OperationType::BOOLEAN;
  formula.op_.gate_op_ = op;
  if (op == BooleanOperation::IDENTITY) {
    formula.value_ = GenericValue(string("P0_0"));
    formula.subterm_one_ = nullptr;
    formula.subterm_two_ = nullptr;
    return true;
  }
  formula.subterm_one_.reset(new Formula());
  formula.subterm_one_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_one_->value_ = GenericValue(string("P0_0"));
  if (op == BooleanOperation::NOT) {
    formula.subterm_two_ = nullptr;
    return true;
  }
  formula.subterm_two_.reset(new Formula());
  formula.subterm_two_->op_.type_ = OperationType::BOOLEAN;
  formula.subterm_two_->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula.subterm_two_->value_ = GenericValue(string("P1_0"));

  return true;
}

bool ConstructComparisonCircuit(
    const ComparisonOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  switch (op) {
    case ComparisonOperation::COMP_EQ: {
      return ConstructEqCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          output);
    }
    case ComparisonOperation::COMP_NEQ: {
      return ConstructNeqCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          output);
    }
    case ComparisonOperation::COMP_GT: {
      return ConstructGtCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          output);
    }
    case ComparisonOperation::COMP_GTE: {
      return ConstructGteCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          output);
    }
    case ComparisonOperation::COMP_LT: {
      return ConstructLtCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          output);
    }
    case ComparisonOperation::COMP_LTE: {
      return ConstructLteCircuit(
          one_is_twos_complement,
          two_is_twos_complement,
          value_one_party_index,
          value_one_input_index,
          value_two_party_index,
          value_two_input_index,
          num_one_input_bits,
          num_two_input_bits,
          output);
    }
    default:
      LOG_FATAL("Unsupported Boolean Comparison Operation: " + GetOpString(op));
  }

  // Code should never reach here.
  return false;
}

bool ConstructComparisonCircuit(
    const ComparisonOperation& op,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  return ConstructComparisonCircuit(
      op,
      true,
      true,
      value_one_party_index,
      value_one_input_index,
      value_two_party_index,
      value_two_input_index,
      num_one_input_bits,
      num_two_input_bits,
      output);
}

bool ConstructComparisonCircuit(
    const ComparisonOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  return ConstructComparisonCircuit(
      op,
      one_is_twos_complement,
      two_is_twos_complement,
      0,
      0,
      1,
      0,
      num_one_input_bits,
      num_two_input_bits,
      output);
}

bool ConstructComparisonCircuit(
    const ComparisonOperation& op,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  return ConstructComparisonCircuit(
      op, 0, 0, 1, 0, num_one_input_bits, num_two_input_bits, output);
}

bool ConstructComparisonCircuit(
    const ComparisonOperation& op,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const DataType input_one_type,
    const DataType input_two_type,
    StandardCircuit<bool>* output) {
  return ConstructComparisonCircuit(
      op,
      IsDataTypeTwosComplement(input_one_type),
      IsDataTypeTwosComplement(input_two_type),
      value_one_party_index,
      value_one_input_index,
      value_two_party_index,
      value_two_input_index,
      GetValueNumBits(input_one_type),
      GetValueNumBits(input_two_type),
      output);
}

bool ConstructComparisonCircuit(
    const ComparisonOperation& op,
    const DataType input_one_type,
    const DataType input_two_type,
    StandardCircuit<bool>* output) {
  return ConstructComparisonCircuit(
      op, 0, 0, 1, 0, input_one_type, input_two_type, output);
}

bool ConstructArithmeticCircuit(
    const bool as_boolean,
    const ArithmeticOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  // TODO(paul): All of the operators below are implemented only for boolean
  // circuits. For some operations (e.g. ABS, FLIP_SIGN, ADD, SUB, MIN, MAX, FACTORIAL)
  // this is just fine, but for others (MULT, DIV, SQRT, POW), this may not
  // be the most efficient way to perform the operation. Consider implementing
  // true arithmetic circuits for these (input parameter 'as_boolean' toggles
  // whether the operation is instantiated via a boolean circuit, or via
  // an (as yet unimplemented) arithmetic circuit).
  switch (op) {
    // Single-Input Operators:
    case ArithmeticOperation::ABS: {
      if (num_two_input_bits != 0) LOG_FATAL("Fatal Error.");
      if (as_boolean) {
        return ConstructAbsCircuit(
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            num_one_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::FLIP_SIGN: {
      if (num_two_input_bits != 0) LOG_FATAL("Fatal Error.");
      if (as_boolean) {
        return ConstructFlipSignCircuit(
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            num_one_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::FACTORIAL: {
      if (num_two_input_bits != 0) LOG_FATAL("Fatal Error.");
      if (one_is_twos_complement) {
        LOG_ERROR("Factorial only available for Unsigned DataTypes.");
        return false;
      }
      return ConstructFactorialCircuit(
          value_one_party_index,
          value_one_input_index,
          num_one_input_bits,
          output);
    }
    case ArithmeticOperation::SQRT: {
      if (num_two_input_bits != 0) LOG_FATAL("Fatal Error.");
      LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
      return false;
    }
    // Double-Input Operators:
    case ArithmeticOperation::ADD: {
      if (as_boolean) {
        return ConstructAddCircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::SUB: {
      if (as_boolean) {
        return ConstructSubtractCircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::MULT: {
      if (as_boolean) {
        if (num_one_input_bits == 1 || num_two_input_bits == 1) {
          return ConstructMultiplicationByBitCircuit(
              (num_one_input_bits == 1 ? two_is_twos_complement :
                                         one_is_twos_complement),
              (num_one_input_bits == 1 ? value_one_party_index :
                                         value_two_party_index),
              (num_one_input_bits == 1 ? value_one_input_index :
                                         value_two_input_index),
              (num_one_input_bits == 1 ? value_two_party_index :
                                         value_one_party_index),
              (num_one_input_bits == 1 ? value_two_input_index :
                                         value_one_input_index),
              (num_one_input_bits == 1 ? num_two_input_bits :
                                         num_one_input_bits),
              output);
        } else {
          // Currently, ConstructMultiplicationCircuit is designed to fill
          // leading bits of the first number, while assuming the second
          // number can be left as-is. Thus, make sure the first input
          // is the smaller one.
          if (num_one_input_bits <= num_two_input_bits) {
            return ConstructMultiplicationCircuit(
                one_is_twos_complement,
                two_is_twos_complement,
                value_one_party_index,
                value_one_input_index,
                value_two_party_index,
                value_two_input_index,
                num_one_input_bits,
                num_two_input_bits,
                output);
          } else {
            return ConstructMultiplicationCircuit(
                two_is_twos_complement,
                one_is_twos_complement,
                value_two_party_index,
                value_two_input_index,
                value_one_party_index,
                value_one_input_index,
                num_two_input_bits,
                num_one_input_bits,
                output);
          }
        }
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::DIV: {
      LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
      return false;
    }
    case ArithmeticOperation::POW: {
      if (as_boolean) {
        if (two_is_twos_complement) {
          LOG_ERROR("Signed exponents not supported.");
          return false;
        }
        return ConstructPowerCircuit(
            one_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::VEC: {
      if (as_boolean) {
        return ConstructVectorCircuit(
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::MIN: {
      if (as_boolean) {
        return ConstructMinCircuit(
            true,
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::MAX: {
      if (as_boolean) {
        return ConstructMinCircuit(
            false,
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::ARGMIN: {
      if (as_boolean) {
        return ConstructArgMinCircuit(
            true,
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::ARGMAX: {
      if (as_boolean) {
        return ConstructArgMinCircuit(
            false,
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::ARGMIN_INTERNAL: {
      if (as_boolean) {
        return ConstructArgMinInternalCircuit(
            true,
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    case ArithmeticOperation::ARGMAX_INTERNAL: {
      if (as_boolean) {
        return ConstructArgMinInternalCircuit(
            false,
            one_is_twos_complement,
            two_is_twos_complement,
            value_one_party_index,
            value_one_input_index,
            value_two_party_index,
            value_two_input_index,
            num_one_input_bits,
            num_two_input_bits,
            output);
      } else {
        LOG_ERROR("Unsupported Arithemetic Operation: " + GetOpString(op));
        return false;
      }
    }
    default:
      LOG_FATAL("Unsupported Arithemetic Operation: " + GetOpString(op));
  }

  // Code should never reach here.
  return false;
}

bool ConstructArithmeticCircuit(
    const bool as_boolean,
    const ArithmeticOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const uint64_t& num_one_input_bits,
    const uint64_t& num_two_input_bits,
    StandardCircuit<bool>* output) {
  return ConstructArithmeticCircuit(
      as_boolean,
      op,
      one_is_twos_complement,
      two_is_twos_complement,
      0,
      0,
      1,
      0,
      num_one_input_bits,
      num_two_input_bits,
      output);
}

bool ConstructArithmeticCircuit(
    const bool as_boolean,
    const ArithmeticOperation& op,
    const int value_one_party_index,
    const uint64_t& value_one_input_index,
    const int value_two_party_index,
    const uint64_t& value_two_input_index,
    const DataType input_one_type,
    const DataType input_two_type,
    StandardCircuit<bool>* output) {
  return ConstructArithmeticCircuit(
      as_boolean,
      op,
      IsDataTypeTwosComplement(input_one_type),
      IsDataTypeTwosComplement(input_two_type),
      value_one_party_index,
      value_one_input_index,
      value_two_party_index,
      value_two_input_index,
      GetValueNumBits(input_one_type),
      GetValueNumBits(input_two_type),
      output);
}

bool ConstructArithmeticCircuit(
    const bool as_boolean,
    const ArithmeticOperation& op,
    const DataType input_one_type,
    const DataType input_two_type,
    StandardCircuit<bool>* output) {
  return ConstructArithmeticCircuit(
      as_boolean,
      op,
      IsDataTypeTwosComplement(input_one_type),
      IsDataTypeTwosComplement(input_two_type),
      GetValueNumBits(input_one_type),
      GetValueNumBits(input_two_type),
      output);
}

bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>>&
        output_to_input,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  // Set known fields.
  output->depth_ = one.depth_ + two.depth_;
  output->size_ = one.size_ + two.size_;
  // We initialize num_non_local_gates_ to be the number of such gates in circuit
  // 'one'. This may have to be updated below to add in the number of non-local gates
  // from circuit_two; but those will have to be recomputed, since dependencies
  // may have changed now that (some of) circuit two's inputs come from the
  // outputs of circuit one.
  output->num_non_local_gates_ = one.num_non_local_gates_;
  // This gets adjusted below, for unmapped output wires from circuit 'one'.
  output->num_outputs_ = two.num_outputs_;
  output->num_output_wires_ = two.num_output_wires_;
  // This gets adjusted below, for unmapped input wires from circuit 'two'.
  output->input_types_ = one.input_types_;

  // Set inputs and initial levels to be copied from one.
  output->inputs_as_generic_value_locations_ =
      one.inputs_as_generic_value_locations_;
  output->levels_.resize(one.depth_ + two.depth_);
  // Constant (0) inputs.
  output->constant_zero_input_ = one.constant_zero_input_;
  for (const WireLocation& to_gate : two.constant_zero_input_) {
    output->constant_zero_input_.insert(WireLocation(
        to_gate.loc_.level_ + one.depth_,
        to_gate.loc_.index_,
        to_gate.is_left_));
  }
  // Constant (1) inputs.
  output->constant_one_input_ = one.constant_one_input_;
  for (const WireLocation& to_gate : two.constant_one_input_) {
    output->constant_one_input_.insert(WireLocation(
        to_gate.loc_.level_ + one.depth_,
        to_gate.loc_.index_,
        to_gate.is_left_));
  }

  // Perhaps not all of the input wires from 'two' get mapped to by an
  // output wire of 'one'. For all the unmapped wires, keep them as
  // (global) input wires.
  // First, go through and get a list of all input wires that are mapped to.
  map<int, set<pair<uint64_t, uint64_t>>> mapped_input_wires;
  set<pair<uint64_t, uint64_t>> mapped_two_input_wires;
  map<uint64_t, set<pair<int, uint64_t>>> one_output_to_two_input;
  for (const pair<const int64_t, set<pair<int, pair<uint64_t, uint64_t>>>>&
           map_itr : output_to_input) {
    const uint64_t one_output_index =
        GetOutputIndexFromWireIndex(map_itr.first, one.output_designations_);
    for (const pair<int, pair<uint64_t, uint64_t>>& mapped_wires :
         map_itr.second) {
      set<pair<uint64_t, uint64_t>>* to_insert = FindOrInsert(
          mapped_wires.first,
          mapped_input_wires,
          set<pair<uint64_t, uint64_t>>());
      to_insert->insert(mapped_wires.second);
      set<pair<int, uint64_t>>* input_two_loc = FindOrInsert(
          one_output_index, one_output_to_two_input, set<pair<int, uint64_t>>());
      input_two_loc->insert(
          make_pair(mapped_wires.first, mapped_wires.second.first));
    }
  }
  // Now go through all circuit 'two' inputs, and for each that is unmapped,
  // add it as an input wire to circuit 'output'.
  vector<uint64_t> num_unmapped_circuit_two_inputs_per_party(
      two.input_types_.size(), 0);
  for (int party = 0; party < (int) two.input_types_.size(); ++party) {
    const uint64_t num_one_inputs_this_party =
        (int) one.input_types_.size() <= party ? 0 :
                                                 one.input_types_[party].size();
    for (uint64_t input_index = 0;
         input_index < two.inputs_as_generic_value_locations_[party].size();
         ++input_index) {
      const vector<set<WireLocation>>& two_input_one =
          two.inputs_as_generic_value_locations_[party][input_index];
      // We demand that for a given input index of circuit 2, either all
      // of its bits are mapped to, or none are. Thus, just check the first bit.
      const pair<uint64_t, uint64_t> two_input_one_i_bit_zero =
          make_pair(input_index, (uint64_t) 0);
      // Check if this input wire will be mapped to by an output wire of 'one'.
      if (mapped_input_wires.find(party) != mapped_input_wires.end() &&
          mapped_input_wires[party].find(two_input_one_i_bit_zero) !=
              mapped_input_wires[party].end()) {
        // This input wire is mapped to.
        continue;
      }
      // This input wire is NOT mapped to. Need to keep it as a global input wire.
      const uint64_t new_input_index = preserve_input_indexing ?
          input_index :
          num_one_inputs_this_party +
              num_unmapped_circuit_two_inputs_per_party[party];
      ++num_unmapped_circuit_two_inputs_per_party[party];
      for (uint64_t bit_index = 0; bit_index < two_input_one.size();
           ++bit_index) {
        if ((int) output->input_types_.size() <= party) {
          output->input_types_.resize(party + 1);
        }
        if (output->input_types_[party].size() < new_input_index + 1) {
          output->input_types_[party].resize(new_input_index + 1);
        }
        if (output->input_types_[party][new_input_index].first.empty()) {
          output->input_types_[party][new_input_index] =
              two.input_types_[party][input_index];
        } else if (
            output->input_types_[party][new_input_index] !=
            two.input_types_[party][input_index]) {
          LOG_FATAL(
              "Mismatching input_types_: (" +
              output->input_types_[party][new_input_index].first + ", " +
              GetDataTypeString(
                  output->input_types_[party][new_input_index].second) +
              "), second: (" + two.input_types_[party][new_input_index].first +
              ", " +
              GetDataTypeString(
                  two.input_types_[party][new_input_index].second) +
              ")");
        }
        if ((int) output->inputs_as_generic_value_locations_.size() <= party) {
          output->inputs_as_generic_value_locations_.resize(party + 1);
        }
        if (output->inputs_as_generic_value_locations_[party].size() <=
            new_input_index) {
          output->inputs_as_generic_value_locations_[party].resize(
              new_input_index + 1, vector<set<WireLocation>>());
        }
        vector<set<WireLocation>>& new_wires =
            output->inputs_as_generic_value_locations_[party][new_input_index];
        if (new_wires.size() <= bit_index) {
          new_wires.resize(bit_index + 1);
        }
        for (const WireLocation& wire : two_input_one[bit_index]) {
          // The mappings for the original input wires need to be updated:
          // all gates of circuit 'two' have been offset by one.depth_.
          new_wires[bit_index].insert(WireLocation(
              wire.loc_.level_ + one.depth_, wire.loc_.index_, wire.is_left_));
        }
      }
    }
  }

  // As we iterate through circuit 'one', copying it to 'output', we need to
  // keep track of the (global/circuit) output wires: which will remain as
  // (global) output wires of 'output' vs. which will get mapped to an input
  // wire of 'two'. Then, we'll need to re-index all output wires of 'output'.
  uint64_t num_one_global_outputs = 0;
  set<int64_t> one_output_indices_that_become_inputs_to_two;
  map<GateLocation, set<int64_t>> dependencies_from_left_parent;
  map<GateLocation, set<int64_t>> dependencies_from_right_parent;
  for (int level = 0; level < one.depth_; ++level) {
    const StandardCircuitLevel<bool>& one_level = one.levels_[level];
    StandardCircuitLevel<bool>& new_level = output->levels_[level];
    new_level.level_ = level;
    const uint64_t num_gates = one_level.gates_.size();
    new_level.num_gates_ = num_gates;
    new_level.gates_.resize(num_gates);
    for (uint64_t gate_index = 0; gate_index < num_gates; ++gate_index) {
      const StandardGate<bool>& one_gate = one_level.gates_[gate_index];
      StandardGate<bool>& new_gate = new_level.gates_[gate_index];
      new_gate.loc_ = GateLocation(level, gate_index);
      new_gate.type_ = one_gate.type_;
      new_gate.depends_on_ = one_gate.depends_on_;
      // Copy output wires, which will be identical to the originals (from
      // circuit one), except for global/circuit output wires, which should
      // either remain as a (global) output wire or be mapped to the appropriate
      // input wire of circuit two, as determined by 'output_to_input' map.
      for (const WireLocation& loc : one_gate.output_wire_locations_) {
        if (loc.loc_.level_ == -1) {
          const set<pair<int, pair<uint64_t, uint64_t>>>* targets =
              FindOrNull(loc.loc_.index_, output_to_input);
          if (targets == nullptr) {
            // This (global) output wire does not map to an input wire of
            // circuit 'two'. Keep it as a global output.
            ++num_one_global_outputs;
            new_gate.output_wire_locations_.insert(loc);
          } else {
            // This (global) output wire maps to an input wire of circuit 'two'.
            // Remove it as a global output, and add it to the appropriate
            // circuit 'two' input wire(s).
            one_output_indices_that_become_inputs_to_two.insert(loc.loc_.index_);
            for (const pair<int, pair<uint64_t, uint64_t>>& target : *targets) {
              const vector<set<WireLocation>>& input_gate_locations =
                  two.inputs_as_generic_value_locations_[target.first]
                                                        [target.second.first];
              if (input_gate_locations.size() <= target.second.second) {
                LOG_FATAL(
                    Itoa(target.first) + ", " + Itoa(target.second.first) +
                    ", " + Itoa(target.second.second) + ", " +
                    Itoa(input_gate_locations.size()));
              }
              const set<WireLocation>& input_gate_locations_i =
                  input_gate_locations[target.second.second];
              // This will map to an input wire of circuit two, and that input
              // wire's GateLocation (level, index) is specified in
              // input_gate_locations. However, the level specified needs to be
              // offset by one.depth_, since all circuit 'two' gates will be off-
              // set by one.depth_, based on the nature of joining it with 'one'.
              for (const WireLocation& input_loc : input_gate_locations_i) {
                new_gate.output_wire_locations_.insert(WireLocation(
                    input_loc.loc_.level_ + one.depth_,
                    input_loc.loc_.index_,
                    input_loc.is_left_));
                if (input_loc.is_left_) {
                  set<int64_t>* input_gate_dependencies = FindOrInsert(
                      GateLocation(input_loc.loc_.level_, input_loc.loc_.index_),
                      dependencies_from_left_parent,
                      set<int64_t>());
                  for (const int k : new_gate.depends_on_) {
                    input_gate_dependencies->insert(k);
                  }
                } else {
                  set<int64_t>* input_gate_dependencies = FindOrInsert(
                      GateLocation(input_loc.loc_.level_, input_loc.loc_.index_),
                      dependencies_from_right_parent,
                      set<int64_t>());
                  for (const int k : new_gate.depends_on_) {
                    input_gate_dependencies->insert(k);
                  }
                }
              }
            }
          }
        } else {
          new_gate.output_wire_locations_.insert(loc);
        }
      }
    }
  }

  // Now, need to go through all global output wires, and adjust the output index
  // (since some of the global output wires are no longer output wires (they are
  // input wires to circuit 'two').
  output->num_outputs_ += num_one_global_outputs;
  output->num_output_wires_ += num_one_global_outputs;
  for (StandardCircuitLevel<bool>& level : output->levels_) {
    for (StandardGate<bool>& gate : level.gates_) {
      // Iteration through sets is automatically const, as otherwise (since
      // set is an ordered container), the set will be modified as you loop
      // through, invalidating the iteration. Instead, make a copy, and
      // set this gate's output_wire_locations_ from scratch.
      const set<WireLocation> temp_copy = gate.output_wire_locations_;
      gate.output_wire_locations_.clear();
      for (const WireLocation& wire : temp_copy) {
        if (wire.loc_.level_ != -1) {
          gate.output_wire_locations_.insert(wire);
        } else {
          const int64_t offset = FindNumSmallerIndices(
              true,
              wire.loc_.index_,
              one_output_indices_that_become_inputs_to_two);
          gate.output_wire_locations_.insert(
              WireLocation(-1, wire.loc_.index_ - offset, wire.is_left_));
        }
      }
    }
  }

  // Now, add all levels for circuit two.
  // NOTE: We'll need to update the depends_on_ fields of all gates
  // that have a root at one of the input gates that got replaced by an
  // output wire of circuit one, to reflect the fact that those gates no
  // longer just depend on [x] (resp. y), but now they can depend on neither,
  // x, and/or y (depending on what the first circuit's output gate depended on).
  // First, update dependencies_from_[left | right]_parent with all (non-mapped-to)
  // inputs of circuit two.
  for (int party = 0;
       party < (int) two.inputs_as_generic_value_locations_.size();
       ++party) {
    for (uint64_t input_index = 0;
         input_index < two.inputs_as_generic_value_locations_[party].size();
         ++input_index) {
      const vector<set<WireLocation>>& input_to_bit_and_loc =
          two.inputs_as_generic_value_locations_[party][input_index];
      for (uint64_t bit_index = 0; bit_index < input_to_bit_and_loc.size();
           ++bit_index) {
        // If this input wire is mapped to from circuit one's output wire(s),
        // don't copy the original (circuit two) dependency information (instead,
        // we'll use circuit one's dependency info from the corresponding
        // output wire, which was already stored in
        // dependencies_from_[left | right]_parent in the code above.
        if (mapped_input_wires.find(party) != mapped_input_wires.end() &&
            mapped_input_wires[party].find(make_pair(input_index, bit_index)) !=
                mapped_input_wires[party].end()) {
          continue;
        }
        for (const WireLocation& wire : input_to_bit_and_loc[bit_index]) {
          if (wire.is_left_) {
            set<int64_t>* input_gate_dependencies = FindOrInsert(
                GateLocation(wire.loc_.level_, wire.loc_.index_),
                dependencies_from_left_parent,
                set<int64_t>());
            input_gate_dependencies->insert(party);
          } else {
            set<int64_t>* input_gate_dependencies = FindOrInsert(
                GateLocation(wire.loc_.level_, wire.loc_.index_),
                dependencies_from_right_parent,
                set<int64_t>());
            input_gate_dependencies->insert(party);
          }
        }
      }
    }
  }

  for (int level = 0; level < two.depth_; ++level) {
    const StandardCircuitLevel<bool>& two_level = two.levels_[level];
    StandardCircuitLevel<bool>& new_level = output->levels_[one.depth_ + level];
    new_level.level_ = one.depth_ + level;
    const uint64_t num_gates = two_level.gates_.size();
    new_level.num_gates_ = num_gates;
    new_level.gates_.resize(num_gates);
    for (uint64_t gate_index = 0; gate_index < num_gates; ++gate_index) {
      const StandardGate<bool>& two_gate = two_level.gates_[gate_index];
      StandardGate<bool>& new_gate = new_level.gates_[gate_index];
      new_gate.loc_ = GateLocation(one.depth_ + level, gate_index);
      new_gate.type_ = two_gate.type_;
      set<int64_t>* deps_from_left_parent = FindOrNull(
          GateLocation(level, gate_index), dependencies_from_left_parent);
      if (deps_from_left_parent != nullptr) {
        for (const int64_t k : *deps_from_left_parent) {
          new_gate.depends_on_.insert((int) k);
        }
      }
      set<int64_t>* deps_from_right_parent = FindOrNull(
          GateLocation(level, gate_index), dependencies_from_right_parent);
      if (deps_from_right_parent != nullptr) {
        for (const int64_t k : *deps_from_right_parent) {
          new_gate.depends_on_.insert((int) k);
        }
      }
      if (!new_gate.IsLocalGate() && new_gate.depends_on_.size() > 1) {
        ++output->num_non_local_gates_;
      }
      // Copy output wires, which are adjusted from the original values by:
      //   - Global output wires have their index offset by num_one_global_outputs
      //   - All other output wires' level is offset by one.depth_
      for (const WireLocation& loc : two_gate.output_wire_locations_) {
        if (loc.loc_.level_ == -1) {
          new_gate.output_wire_locations_.insert(WireLocation(
              loc.loc_.level_,
              loc.loc_.index_ + num_one_global_outputs,
              loc.is_left_));
        } else {
          new_gate.output_wire_locations_.insert(WireLocation(
              loc.loc_.level_ + one.depth_, loc.loc_.index_, loc.is_left_));
        }
        // Update dependencies_from_[left | right]_parent.
        if (loc.is_left_) {
          set<int64_t>* left_gate_deps = FindOrInsert(
              GateLocation(loc.loc_.level_, loc.loc_.index_),
              dependencies_from_left_parent,
              set<int64_t>());
          for (const int k : new_gate.depends_on_) {
            left_gate_deps->insert(k);
          }
        } else {
          set<int64_t>* right_gate_deps = FindOrInsert(
              GateLocation(loc.loc_.level_, loc.loc_.index_),
              dependencies_from_right_parent,
              set<int64_t>());
          for (const int k : new_gate.depends_on_) {
            right_gate_deps->insert(k);
          }
        }
      }
    }
  }

  // Update function_description_ and output_designations_.
  // Map circuit two variable names to the appropriate output function from
  // circuit one.
  map<string, const Formula*> var_name_to_formula;
  if (update_function_description) {
    for (const pair<const uint64_t, set<pair<int, uint64_t>>>&
             output_index_to_input_indices : one_output_to_two_input) {
      const Formula* formula =
          &one.function_description_[output_index_to_input_indices.first];
      const string formula_str = GetFormulaString(*formula);
      for (const pair<int, uint64_t>& input_index :
           output_index_to_input_indices.second) {
        const vector<pair<string, DataType>>& input_var_names =
            two.input_types_[input_index.first];
        if (input_index.second >= input_var_names.size())
          LOG_FATAL("Fatal Error.");
        if (!var_name_to_formula
                 .insert(make_pair(
                     input_var_names[input_index.second].first, formula))
                 .second &&
            GetFormulaString(
                *(var_name_to_formula[input_var_names[input_index.second]
                                          .first])) != formula_str) {
          LOG_FATAL(
              "Fatal Error: '" +
              GetFormulaString(
                  *var_name_to_formula[input_var_names[input_index.second]
                                           .first]) +
              "', '" + formula_str + "'");
        }
      }
    }
  }
  // Get a list of output indices from circuit one that remain global outputs.
  set<uint64_t> one_global_outputs;
  for (uint64_t i = 0; i < one.output_designations_.size(); ++i) {
    if (one_output_to_two_input.find(i) == one_output_to_two_input.end()) {
      one_global_outputs.insert(i);
    }
  }
  const uint64_t num_outputs =
      one_global_outputs.size() + two.output_designations_.size();
  output->output_designations_.resize(num_outputs);
  if (update_function_description) {
    output->function_description_.resize(num_outputs);
  }
  // First, set the output_designation_ and function_description of the first
  // 'one_global_outputs.size()' outputs, just by copying these from the
  // appropriate corresponding entries from circuit one.
  uint64_t final_output_index = 0;
  for (const uint64_t one_global_output_index : one_global_outputs) {
    output->output_designations_[final_output_index] =
        one.output_designations_[one_global_output_index];
    if (update_function_description) {
      output->function_description_[final_output_index] =
          one.function_description_[one_global_output_index];
    }
    ++final_output_index;
  }
  // Now, the rest of the final circuit's outputs come from circuit two.
  // Copy the corresponding entries from circuit two, updating the
  // formula with inputs that come from one's outputs.
  for (uint64_t i = 0; i < two.output_designations_.size(); ++i) {
    output->output_designations_[final_output_index + i] =
        two.output_designations_[i];
    if (!update_function_description) continue;
    output->function_description_[final_output_index + i] =
        two.function_description_[i];
    Formula& formula_i = output->function_description_[final_output_index + i];
    // Update formula, replacing original input variables with the appropriate
    // formula for the circuit one output function.
    UpdateFormulaVarNames(var_name_to_formula, &formula_i);
  }

  return true;
}

bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const map<int64_t, set<pair<int, uint64_t>>>& output_to_input,
    const StandardCircuit<slice>& one,
    const StandardCircuit<slice>& two,
    StandardCircuit<slice>* output) {
  // Set known fields.
  output->depth_ = one.depth_ + two.depth_;
  output->size_ = one.size_ + two.size_;
  // We initialize num_non_local_gates_ to be the number of such gates in circuit
  // 'one'. This may have to be updated below to add in the number of non-local gates
  // from circuit_two; but those will have to be recomputed, since dependencies
  // may have changed now that (some of) circuit two's inputs come from the
  // outputs of circuit one.
  output->num_non_local_gates_ = one.num_non_local_gates_;
  // This gets adjusted below, for unmapped output wires from circuit 'one'.
  output->num_outputs_ = two.num_output_wires_;
  output->num_output_wires_ = two.num_output_wires_;
  // This gets adjusted below, for unmapped input wires from circuit 'two'.
  output->input_types_ = one.input_types_;

  // Set inputs and initial levels to be copied from one.
  output->inputs_as_slice_locations_ = one.inputs_as_slice_locations_;
  // Constant inputs.
  output->constant_slice_input_ = one.constant_slice_input_;
  for (const pair<const slice, set<WireLocation>>& two_constants :
       two.constant_slice_input_) {
    const slice& value = two_constants.first;
    set<WireLocation>& to_gates =
        output->constant_slice_input_
            .insert(make_pair(value, set<WireLocation>()))
            .first->second;
    for (const WireLocation& to_gate : two_constants.second) {
      to_gates.insert(WireLocation(
          to_gate.loc_.level_ + one.depth_,
          to_gate.loc_.index_,
          to_gate.is_left_));
    }
  }

  // Perhaps not all of the input wires from 'two' get mapped to by an
  // output wire of 'one'. For all the unmapped wires, keep them as
  // (global) input wires.
  // First, go through and get a list of all input wires that are mapped to.
  map<int, set<uint64_t>> mapped_input_wires;
  map<int64_t, set<pair<int, uint64_t>>> one_output_to_two_input;
  for (const pair<const int64_t, set<pair<int, uint64_t>>>& map_itr :
       output_to_input) {
    for (const pair<int, uint64_t>& mapped_wires : map_itr.second) {
      set<uint64_t>* to_insert =
          FindOrInsert(mapped_wires.first, mapped_input_wires, set<uint64_t>());
      to_insert->insert(mapped_wires.second);
      set<pair<int, uint64_t>>* input_two_loc = FindOrInsert(
          map_itr.first, one_output_to_two_input, set<pair<int, uint64_t>>());
      input_two_loc->insert(make_pair(mapped_wires.first, mapped_wires.second));
    }
  }
  // Now go through all circuit 'two' inputs, and for each that is unmapped,
  // add it as an input wire to circuit 'output'.
  vector<uint64_t> num_unmapped_circuit_two_inputs_per_party(
      two.input_types_.size(), 0);
  for (int party = 0; party < (int) two.input_types_.size(); ++party) {
    const uint64_t num_one_inputs_this_party =
        (int) one.input_types_.size() <= party ? 0 :
                                                 one.input_types_[party].size();
    for (uint64_t i = 0; i < two.inputs_as_slice_locations_[party].size(); ++i) {
      // Check if this input wire will be mapped to by an output wire of 'one'.
      if (mapped_input_wires.find(party) != mapped_input_wires.end() &&
          mapped_input_wires[party].find(i) != mapped_input_wires[party].end()) {
        // This input wire is mapped to.
        continue;
      }
      // This input wire is NOT mapped to. Need to keep it as a global input wire.
      const uint64_t new_input_index = preserve_input_indexing ?
          i :
          num_one_inputs_this_party +
              num_unmapped_circuit_two_inputs_per_party[party];
      ++num_unmapped_circuit_two_inputs_per_party[party];
      if ((int) output->input_types_.size() <= party) {
        output->input_types_.resize(party + 1);
      }
      if (output->input_types_[party].size() < new_input_index + 1) {
        output->input_types_[party].resize(new_input_index + 1);
      }
      if (output->input_types_[party][new_input_index].first.empty()) {
        output->input_types_[party][new_input_index] =
            two.input_types_[party][i];
      } else if (
          output->input_types_[party][new_input_index] !=
          two.input_types_[party][i]) {
        LOG_FATAL(
            "Mismatching input_types_: (" +
            output->input_types_[party][new_input_index].first + ", " +
            GetDataTypeString(
                output->input_types_[party][new_input_index].second) +
            "), second: (" + two.input_types_[party][new_input_index].first +
            ", " +
            GetDataTypeString(two.input_types_[party][new_input_index].second) +
            ")");
      }
      if ((int) output->inputs_as_slice_locations_.size() <= party) {
        output->inputs_as_slice_locations_.resize(party + 1);
      }
      if (output->inputs_as_slice_locations_[party].size() <= new_input_index) {
        output->inputs_as_slice_locations_[party].resize(new_input_index + 1);
      }
      set<WireLocation>& new_wires =
          output->inputs_as_slice_locations_[party][new_input_index];
      const set<WireLocation>& two_input_one =
          two.inputs_as_slice_locations_[party][i];
      for (const WireLocation& wire : two_input_one) {
        // The mappings for the original input wires need to be updated:
        // all gates of circuit 'two' have been offset by one.depth_.
        new_wires.insert(WireLocation(
            wire.loc_.level_ + one.depth_, wire.loc_.index_, wire.is_left_));
      }
    }
  }

  // As we iterate through circuit 'one', copying it to 'output', we need to
  // keep track of the (global/circuit) output wires: which will remain as
  // (global) output wires of 'output', and which will get mapped to an input
  // wire of 'two'. Then, we'll need to re-index all output wires of 'output'.
  uint64_t num_one_global_outputs = 0;
  set<int64_t> one_output_indices_that_become_inputs_to_two;
  output->levels_.resize(one.depth_ + two.depth_);
  map<GateLocation, set<int64_t>> dependencies_from_left_parent;
  map<GateLocation, set<int64_t>> dependencies_from_right_parent;
  for (int level = 0; level < one.depth_; ++level) {
    const StandardCircuitLevel<slice>& one_level = one.levels_[level];
    StandardCircuitLevel<slice>& new_level = output->levels_[level];
    new_level.level_ = level;
    const uint64_t num_gates = one_level.gates_.size();
    new_level.num_gates_ = num_gates;
    new_level.gates_.resize(num_gates);
    for (uint64_t gate_index = 0; gate_index < num_gates; ++gate_index) {
      const StandardGate<slice>& one_gate = one_level.gates_[gate_index];
      StandardGate<slice>& new_gate = new_level.gates_[gate_index];
      new_gate.loc_ = GateLocation(level, gate_index);
      new_gate.type_ = one_gate.type_;
      new_gate.depends_on_ = one_gate.depends_on_;
      // Copy output wires, which will be identical to the originals (from
      // circuit one), except for global/circuit output wires, which should
      // either remain a (global) output wire or be mapped to the appropriate
      // input wire of circuit two, as determined by 'output_to_input' map.
      for (const WireLocation& loc : one_gate.output_wire_locations_) {
        if (loc.loc_.level_ == -1) {
          const set<pair<int, uint64_t>>* targets =
              FindOrNull(loc.loc_.index_, output_to_input);
          if (targets == nullptr) {
            // This (global) output wire does not map to an input wire of
            // circuit 'two'. Keep it as a global output.
            ++num_one_global_outputs;
            new_gate.output_wire_locations_.insert(loc);
          } else {
            // This (global) output wire maps to an input wire of circuit 'two'.
            // Remove it as a global output, and add it to the appropriate
            // circuit 'two' input wire(s).
            one_output_indices_that_become_inputs_to_two.insert(loc.loc_.index_);
            for (const pair<int, uint64_t>& target : *targets) {
              const vector<set<WireLocation>>& input_gate_locations =
                  two.inputs_as_slice_locations_[target.first];
              if (input_gate_locations.size() <= target.second)
                LOG_FATAL("Fatal Error.");
              // This will map to an input wire of circuit two, and that input
              // wire's GateLocation (level, index) is specified in
              // input_gate_locations. However, the level specified needs to be
              // offset by one.depth_, since all circuit 'two' gates will be off-
              // set by one.depth_, based on the nature of joining it with 'one'.
              for (const WireLocation& input_loc :
                   input_gate_locations[target.second]) {
                new_gate.output_wire_locations_.insert(WireLocation(
                    input_loc.loc_.level_ + one.depth_,
                    input_loc.loc_.index_,
                    input_loc.is_left_));
                if (input_loc.is_left_) {
                  set<int64_t>* input_gate_dependencies = FindOrInsert(
                      GateLocation(input_loc.loc_.level_, input_loc.loc_.index_),
                      dependencies_from_left_parent,
                      set<int64_t>());
                  for (const int k : new_gate.depends_on_) {
                    input_gate_dependencies->insert(k);
                  }
                } else {
                  set<int64_t>* input_gate_dependencies = FindOrInsert(
                      GateLocation(input_loc.loc_.level_, input_loc.loc_.index_),
                      dependencies_from_right_parent,
                      set<int64_t>());
                  for (const int k : new_gate.depends_on_) {
                    input_gate_dependencies->insert(k);
                  }
                }
              }
            }
          }
        } else {
          new_gate.output_wire_locations_.insert(loc);
        }
      }
    }
  }

  // Now, need to go through all global output wires, and adjust the output index
  // (since some of the global output wires are no longer output wires (they are
  // input wires to circuit 'two').
  output->num_outputs_ += num_one_global_outputs;
  output->num_output_wires_ += num_one_global_outputs;
  for (StandardCircuitLevel<slice>& level : output->levels_) {
    for (StandardGate<slice>& gate : level.gates_) {
      // Iteration through sets is automatically const, as otherwise (since
      // set is an ordered container), the set will be modified as you loop
      // through, invalidating the iteration. Instead, make a copy, and
      // set this gate's output_wire_locations_ from scratch.
      const set<WireLocation> temp_copy = gate.output_wire_locations_;
      gate.output_wire_locations_.clear();
      for (const WireLocation& wire : temp_copy) {
        if (wire.loc_.level_ != -1) {
          gate.output_wire_locations_.insert(wire);
        } else {
          const int64_t offset = FindNumSmallerIndices(
              true,
              wire.loc_.index_,
              one_output_indices_that_become_inputs_to_two);
          gate.output_wire_locations_.insert(
              WireLocation(-1, wire.loc_.index_ - offset, wire.is_left_));
        }
      }
    }
  }

  // Now, add all levels for circuit two.
  // NOTE: We'll need to update the depends_on_ fields of all gates
  // that have a root at one of the input gates that got replaced by an
  // output wire of circuit one, to reflect the fact that those gates no
  // longer just depend on [x] (resp. y), but now they can depend on neither,
  // x, and/or y (depending on what the first circuit's output gate depended on).
  // First, update dependencies_from_[left | right]_parent with all (non-mapped-to)
  // inputs of circuit two.
  for (int party = 0; party < (int) two.inputs_as_slice_locations_.size();
       ++party) {
    for (int input_index = 0;
         input_index < (int) two.inputs_as_slice_locations_[party].size();
         ++input_index) {
      // If this input wire is mapped to from circuit one's output wire(s),
      // don't copy the original (circuit two) dependency information (instead,
      // we'll use circuit one's dependency info from the corresponding
      // output wire, which was already stored in
      // dependencies_from_[left | right]_parent in the code above.
      if (mapped_input_wires.find(input_index) != mapped_input_wires.end()) {
        continue;
      }
      for (const WireLocation& wire :
           two.inputs_as_slice_locations_[party][input_index]) {
        if (wire.is_left_) {
          set<int64_t>* input_gate_dependencies = FindOrInsert(
              GateLocation(wire.loc_.level_, wire.loc_.index_),
              dependencies_from_left_parent,
              set<int64_t>());
          input_gate_dependencies->insert(0);
        } else {
          set<int64_t>* input_gate_dependencies = FindOrInsert(
              GateLocation(wire.loc_.level_, wire.loc_.index_),
              dependencies_from_right_parent,
              set<int64_t>());
          input_gate_dependencies->insert(0);
        }
      }
    }
  }

  for (int level = 0; level < two.depth_; ++level) {
    const StandardCircuitLevel<slice>& two_level = two.levels_[level];
    StandardCircuitLevel<slice>& new_level = output->levels_[one.depth_ + level];
    new_level.level_ = one.depth_ + level;
    const uint64_t num_gates = two_level.gates_.size();
    new_level.num_gates_ = num_gates;
    new_level.gates_.resize(num_gates);
    for (uint64_t gate_index = 0; gate_index < num_gates; ++gate_index) {
      const StandardGate<slice>& two_gate = two_level.gates_[gate_index];
      StandardGate<slice>& new_gate = new_level.gates_[gate_index];
      new_gate.loc_ = GateLocation(one.depth_ + level, gate_index);
      new_gate.type_ = two_gate.type_;
      set<int64_t>* deps_from_left_parent = FindOrNull(
          GateLocation(level, gate_index), dependencies_from_left_parent);
      if (deps_from_left_parent != nullptr) {
        for (const int64_t k : *deps_from_left_parent) {
          new_gate.depends_on_.insert((int) k);
        }
      }
      set<int64_t>* deps_from_right_parent = FindOrNull(
          GateLocation(level, gate_index), dependencies_from_right_parent);
      if (deps_from_right_parent != nullptr) {
        for (const int64_t k : *deps_from_right_parent) {
          new_gate.depends_on_.insert((int) k);
        }
      }
      if (!new_gate.IsLocalGate() && new_gate.depends_on_.size() > 1) {
        ++output->num_non_local_gates_;
      }
      // Copy output wires, which are adjusted from the original values by:
      //   - Global output wires have their index offset by num_one_global_outputs
      //   - All other output wires' level is offset by one.depth_
      for (const WireLocation& loc : two_gate.output_wire_locations_) {
        if (loc.loc_.level_ == -1) {
          new_gate.output_wire_locations_.insert(WireLocation(
              loc.loc_.level_,
              loc.loc_.index_ + num_one_global_outputs,
              loc.is_left_));
        } else {
          new_gate.output_wire_locations_.insert(WireLocation(
              loc.loc_.level_ + one.depth_, loc.loc_.index_, loc.is_left_));
        }
        // Update dependencies_from_[left | right]_parent.
        if (loc.is_left_) {
          set<int64_t>* left_gate_deps = FindOrInsert(
              GateLocation(loc.loc_.level_, loc.loc_.index_),
              dependencies_from_left_parent,
              set<int64_t>());
          for (const int k : new_gate.depends_on_) {
            left_gate_deps->insert(k);
          }
        } else {
          set<int64_t>* right_gate_deps = FindOrInsert(
              GateLocation(loc.loc_.level_, loc.loc_.index_),
              dependencies_from_right_parent,
              set<int64_t>());
          for (const int k : new_gate.depends_on_) {
            right_gate_deps->insert(k);
          }
        }
      }
    }
  }

  // Update function_description_ and output_designations_.
  // Map circuit two variable names to the appropriate output function from
  // circuit one.
  map<string, const Formula*> var_name_to_formula;
  if (update_function_description) {
    for (const pair<const int64_t, set<pair<int, uint64_t>>>&
             output_index_to_input_indices : one_output_to_two_input) {
      const Formula* formula =
          &one.function_description_[output_index_to_input_indices.first];
      const string formula_str = GetFormulaString(*formula);
      for (const pair<int, uint64_t>& input_index :
           output_index_to_input_indices.second) {
        const vector<pair<string, DataType>>& input_var_names =
            two.input_types_[input_index.first];
        if (input_index.second >= input_var_names.size())
          LOG_FATAL("Fatal Error.");
        if (!var_name_to_formula
                 .insert(make_pair(
                     input_var_names[input_index.second].first, formula))
                 .second) {
          LOG_FATAL("Fatal Error");
        }
      }
    }
  }
  // Get a list of output indices from circuit one that remain global outputs.
  set<uint64_t> one_global_outputs;
  for (uint64_t i = 0; i < one.output_designations_.size(); ++i) {
    if (one_output_to_two_input.find(i) == one_output_to_two_input.end()) {
      one_global_outputs.insert(i);
    }
  }
  const uint64_t num_outputs =
      one_global_outputs.size() + two.output_designations_.size();
  output->output_designations_.resize(num_outputs);
  if (update_function_description) {
    output->function_description_.resize(num_outputs);
  }
  // First, set the output_designation_ and function_description of the first
  // 'one_global_outputs.size()' outputs, just by copying these from the
  // appropriate corresponding entries from circuit one.
  uint64_t final_output_index = 0;
  for (const uint64_t one_global_output_index : one_global_outputs) {
    output->output_designations_[final_output_index] =
        one.output_designations_[one_global_output_index];
    if (update_function_description) {
      output->function_description_[final_output_index] =
          one.function_description_[one_global_output_index];
    }
    ++final_output_index;
  }
  // Now, the rest of the final circuit's outputs come from circuit two.
  // Copy the corresponding entries from circuit two, updating the
  // formula with inputs that come from one's outputs.
  for (uint64_t i = 0; i < two.output_designations_.size(); ++i) {
    output->output_designations_[final_output_index + i] =
        two.output_designations_[i];
    if (!update_function_description) continue;
    output->function_description_[final_output_index + i] =
        two.function_description_[i];
    Formula& formula_i = output->function_description_[final_output_index + i];
    // Update formula, replacing original input variables with the appropriate
    // formula for the circuit one output function.
    UpdateFormulaVarNames(var_name_to_formula, &formula_i);
  }

  return true;
}

bool JoinCircuits(
    const StandardCircuit<slice>& one,
    const StandardCircuit<slice>& two,
    StandardCircuit<slice>* output) {
  int64_t num_two_inputs = 0;
  for (int party = 0; party < (int) two.inputs_as_slice_locations_.size();
       ++party) {
    num_two_inputs += two.inputs_as_slice_locations_[party].size();
  }
  if (one.num_output_wires_ != num_two_inputs) {
    LOG_FATAL("Fatal Error");
  }
  map<int64_t, set<pair<int, uint64_t>>> output_to_input;
  int64_t num_outputs_processed = 0;
  for (int party = 0; party < (int) two.inputs_as_slice_locations_.size();
       ++party) {
    for (uint64_t i = 0; i < two.inputs_as_slice_locations_[party].size(); ++i) {
      set<pair<int, uint64_t>>* value = FindOrInsert(
          (int64_t) num_outputs_processed,
          output_to_input,
          set<pair<int, uint64_t>>());
      value->insert(make_pair(party, i));
      ++num_outputs_processed;
    }
  }

  return JoinCircuits(output_to_input, one, two, output);
}

bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  // Count all inputs to circuit two.
  size_t num_two_input_bits = 0;
  for (int party = 0;
       party < (int) two.inputs_as_generic_value_locations_.size();
       ++party) {
    for (const auto& two_input : two.inputs_as_generic_value_locations_[party]) {
      num_two_input_bits += two_input.size();
    }
  }
  if (one.num_output_wires_ != (int64_t) num_two_input_bits) {
    LOG_FATAL(
        "Mismatching number of one output wires (" +
        Itoa(one.num_output_wires_) + ") and two input bits (" +
        Itoa(num_two_input_bits) + ")");
  }
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  uint64_t i = 0;
  for (int party = 0;
       party < (int) two.inputs_as_generic_value_locations_.size();
       ++party) {
    for (size_t input_index = 0;
         input_index < two.inputs_as_generic_value_locations_[party].size();
         ++input_index) {
      const vector<set<WireLocation>>& input_two_inputs =
          two.inputs_as_generic_value_locations_[party][input_index];
      for (uint64_t bit_index = 0; bit_index < input_two_inputs.size();
           ++bit_index) {
        set<pair<int, pair<uint64_t, uint64_t>>>* value = FindOrInsert(
            (int64_t) i,
            output_to_input,
            set<pair<int, pair<uint64_t, uint64_t>>>());
        value->insert(make_pair(party, make_pair(input_index, bit_index)));
        ++i;
      }
    }
  }

  return JoinCircuits(
      preserve_input_indexing,
      update_function_description,
      output_to_input,
      one,
      two,
      output);
}

bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const map<int64_t, set<pair<uint64_t, uint64_t>>>& left_output_to_input,
    const map<int64_t, set<pair<uint64_t, uint64_t>>>& right_output_to_input,
    const StandardCircuit<bool>& left,
    const StandardCircuit<bool>& right,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  // Use the overloaded/special-case of MergeCircuits, to place left and right
  // "side-by-side".
  StandardCircuit<bool> side_by_side;
  if (!MergeCircuits(
          preserve_input_indexing,
          BooleanOperation::IDENTITY,
          left,
          right,
          &side_by_side)) {
    return false;
  }

  // Prepare to call the other JoinCircuits API, by creating the output_to_input
  // mapping for the 'side_by_side' circuit.
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  for (const pair<const int64_t, set<pair<uint64_t, uint64_t>>>& left :
       left_output_to_input) {
    set<pair<int, pair<uint64_t, uint64_t>>>* value = FindOrInsert(
        left.first, output_to_input, set<pair<int, pair<uint64_t, uint64_t>>>());
    for (const pair<uint64_t, uint64_t>& left_target : left.second) {
      value->insert(make_pair(0, left_target));
    }
  }
  // Now go through the right circuit mappings, updating them with an offset.
  const uint64_t right_circuit_output_offset = left.num_output_wires_;
  for (const pair<const int64_t, set<pair<uint64_t, uint64_t>>>& right :
       right_output_to_input) {
    set<pair<int, pair<uint64_t, uint64_t>>>* value = FindOrInsert(
        (int64_t) (right.first + right_circuit_output_offset),
        output_to_input,
        set<pair<int, pair<uint64_t, uint64_t>>>());
    for (const pair<uint64_t, uint64_t>& right_target : right.second) {
      value->insert(make_pair(1, right_target));
    }
  }

  return JoinCircuits(
      preserve_input_indexing,
      update_function_description,
      output_to_input,
      side_by_side,
      two,
      output);
}

bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const map<int64_t, set<uint64_t>>& left_output_to_input,
    const map<int64_t, set<uint64_t>>& right_output_to_input,
    const StandardCircuit<slice>& left,
    const StandardCircuit<slice>& right,
    const StandardCircuit<slice>& two,
    StandardCircuit<slice>* output) {
  // Use the overloaded/special-case of MergeCircuits, to place left and right
  // "side-by-side".
  StandardCircuit<slice> side_by_side;
  if (!MergeCircuits(
          preserve_input_indexing,
          BooleanOperation::IDENTITY,
          left,
          right,
          &side_by_side)) {
    return false;
  }

  // Prepare to call the other JoinCircuits API, by creating the output_to_input
  // mapping for the 'side_by_side' circuit.
  map<int64_t, set<pair<int, uint64_t>>> output_to_input;
  for (const pair<const int64_t, set<uint64_t>>& left : left_output_to_input) {
    set<pair<int, uint64_t>>* value =
        FindOrInsert(left.first, output_to_input, set<pair<int, uint64_t>>());
    for (const uint64_t& left_target : left.second) {
      value->insert(make_pair(0, left_target));
    }
  }
  // Now go through the right circuit mappings, updating them with an offset.
  const uint64_t right_circuit_output_offset = left.num_output_wires_;
  for (const pair<const int64_t, set<uint64_t>>& right : right_output_to_input) {
    set<pair<int, uint64_t>>* value = FindOrInsert(
        (int64_t) (right.first + right_circuit_output_offset),
        output_to_input,
        set<pair<int, uint64_t>>());
    for (const uint64_t& right_target : right.second) {
      value->insert(make_pair(1, right_target));
    }
  }

  return JoinCircuits(
      preserve_input_indexing,
      update_function_description,
      output_to_input,
      side_by_side,
      two,
      output);
}

bool JoinCircuits(
    const StandardCircuit<slice>& left,
    const StandardCircuit<slice>& right,
    const StandardCircuit<slice>& two,
    StandardCircuit<slice>* output) {
  if (left.num_output_wires_ != (int) two.inputs_as_slice_locations_[0].size()) {
    LOG_FATAL("Fatal Error.");
  }
  map<int64_t, set<uint64_t>> left_output_to_input;
  for (int64_t i = 0; i < left.num_output_wires_; ++i) {
    set<uint64_t>* value =
        FindOrInsert((int64_t) i, left_output_to_input, set<uint64_t>());
    value->insert(i);
  }
  if (right.num_output_wires_ !=
      (int) two.inputs_as_slice_locations_[1].size()) {
    LOG_FATAL("Fatal Error.");
  }
  map<int64_t, set<uint64_t>> right_output_to_input;
  for (int64_t i = 0; i < right.num_output_wires_; ++i) {
    set<uint64_t>* value =
        FindOrInsert((int64_t) i, right_output_to_input, set<uint64_t>());
    value->insert(i);
  }
  return JoinCircuits(
      left_output_to_input, right_output_to_input, left, right, two, output);
}

bool JoinCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const StandardCircuit<bool>& left,
    const StandardCircuit<bool>& right,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  if (two.inputs_as_generic_value_locations_.size() != 2) {
    LOG_FATAL(
        "Unexpected number of parties for bottom circuit: " +
        Itoa(two.inputs_as_generic_value_locations_.size()));
  }
  size_t num_two_one_input_bits = 0;
  for (const auto& two_one_input : two.inputs_as_generic_value_locations_[0]) {
    num_two_one_input_bits += two_one_input.size();
  }
  if (left.num_output_wires_ != (int) num_two_one_input_bits) {
    LOG_FATAL(
        "Mismatching number of one output wires (" +
        Itoa(left.num_output_wires_) + ") and two input bits (" +
        Itoa(num_two_one_input_bits) + ")");
  }
  map<int64_t, set<pair<uint64_t, uint64_t>>> left_output_to_input;
  uint64_t i = 0;
  for (size_t input_index = 0;
       input_index < two.inputs_as_generic_value_locations_[0].size();
       ++input_index) {
    const vector<set<WireLocation>>& input_two_inputs =
        two.inputs_as_generic_value_locations_[0][input_index];
    for (uint64_t bit_index = 0; bit_index < input_two_inputs.size();
         ++bit_index) {
      set<pair<uint64_t, uint64_t>>* value = FindOrInsert(
          (int64_t) i, left_output_to_input, set<pair<uint64_t, uint64_t>>());
      value->insert(make_pair(input_index, bit_index));
      ++i;
    }
  }
  // Sanity-check inputs.
  size_t num_two_two_input_bits = 0;
  for (const auto& two_two_input : two.inputs_as_generic_value_locations_[1]) {
    num_two_two_input_bits += two_two_input.size();
  }
  if (right.num_output_wires_ != (int) num_two_two_input_bits) {
    LOG_FATAL(
        "Mismatching number of one output wires (" +
        Itoa(right.num_output_wires_) + ") and two input bits (" +
        Itoa(num_two_two_input_bits) + ")");
  }
  map<int64_t, set<pair<uint64_t, uint64_t>>> right_output_to_input;
  i = 0;
  for (size_t input_index = 0;
       input_index < two.inputs_as_generic_value_locations_[1].size();
       ++input_index) {
    const vector<set<WireLocation>>& input_two_inputs =
        two.inputs_as_generic_value_locations_[1][input_index];
    for (uint64_t bit_index = 0; bit_index < input_two_inputs.size();
         ++bit_index) {
      set<pair<uint64_t, uint64_t>>* value = FindOrInsert(
          (int64_t) i, right_output_to_input, set<pair<uint64_t, uint64_t>>());
      value->insert(make_pair(input_index, bit_index));
      ++i;
    }
  }

  return JoinCircuits(
      preserve_input_indexing,
      update_function_description,
      left_output_to_input,
      right_output_to_input,
      left,
      right,
      two,
      output);
}

template<typename value_t>
bool MergeCircuitsInternal(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const BooleanOperation& op,
    const StandardCircuit<value_t>& one,
    const StandardCircuit<value_t>& two,
    StandardCircuit<value_t>* output) {
  // Sanity-check input has been set.
  if (output == nullptr) {
    LOG_FATAL("Fatal Error.");
  }
  // This API is only appropriate for merging circuits that have the same number
  // of outputs, except the special case that op == IDENTITY.
  if (one.num_output_wires_ != two.num_output_wires_ &&
      op != BooleanOperation::IDENTITY) {
    LOG_FATAL(Itoa(one.num_output_wires_) + ", " + Itoa(two.num_output_wires_));
  }
  // Determine if the circuits are in Format 1 or 2.
  const bool is_one_format_one = one.IsCircuitFormatOne();
  const bool is_two_format_one = two.IsCircuitFormatOne();
  if (is_one_format_one != is_two_format_one) LOG_FATAL("Fatal Error.");

  const uint64_t one_depth = one.levels_.size();
  const uint64_t two_depth = two.levels_.size();
  const uint64_t max_depth = max(one_depth, two_depth);

  // Merge input mappings: keep the mappings from circuit one entact (since
  // the indexing of Level 0 gates for circuit one didn't change (since
  // circuit one was processed first)). Then go through the mappings for
  // circuit two, incrementing the gate index of each WireLocation by the
  // number of gates on that level from circuit one.
  // Also, if preserve_input_indexing is false, update the input index
  // of the second circuit's inputs (for each Party), by the number of inputs
  // in the first circuit (for each Party).
  const int num_one_parties = (int) one.input_types_.size();
  const int num_two_parties = (int) two.input_types_.size();
  const int num_parties = max(num_one_parties, num_two_parties);
  if (is_one_format_one) {
    output->inputs_as_slice_locations_ = one.inputs_as_slice_locations_;
    output->inputs_as_slice_locations_.resize(num_parties);
    for (int party = 0; party < num_parties; ++party) {
      const int num_one_party_inputs = party < num_one_parties ?
          (int) one.inputs_as_slice_locations_[party].size() :
          0;
      const int num_two_party_inputs = party < num_one_parties ?
          (int) two.inputs_as_slice_locations_[party].size() :
          0;
      output->inputs_as_slice_locations_[party].resize(
          preserve_input_indexing ?
              max(num_one_party_inputs, num_two_party_inputs) :
              num_one_party_inputs + num_two_party_inputs);
      const uint64_t offset = preserve_input_indexing ? 0 : num_one_party_inputs;
      for (int i = 0; i < num_two_party_inputs; ++i) {
        const set<WireLocation>& wires_i =
            two.inputs_as_slice_locations_[party][i];
        set<WireLocation>& new_wires_i =
            output->inputs_as_slice_locations_[party][offset + i];
        for (const WireLocation& loc : wires_i) {
          const int64_t index_offset = loc.loc_.level_ >= (int64_t) one_depth ?
              0 :
              (int64_t) one.levels_[loc.loc_.level_].gates_.size();
          new_wires_i.insert(WireLocation(
              loc.loc_.level_, loc.loc_.index_ + index_offset, loc.is_left_));
        }
      }
    }

    // Constant inputs.
    output->constant_slice_input_ = one.constant_slice_input_;
    for (const pair<const slice, set<WireLocation>>& two_constants :
         two.constant_slice_input_) {
      const slice& value = two_constants.first;
      set<WireLocation>& to_gates =
          output->constant_slice_input_
              .insert(make_pair(value, set<WireLocation>()))
              .first->second;
      for (const WireLocation& to_gate : two_constants.second) {
        const int64_t index_offset = to_gate.loc_.level_ >= (int64_t) one_depth ?
            0 :
            (int64_t) one.levels_[to_gate.loc_.level_].gates_.size();
        to_gates.insert(WireLocation(
            to_gate.loc_.level_,
            to_gate.loc_.index_ + index_offset,
            to_gate.is_left_));
      }
    }
  } else {
    output->inputs_as_generic_value_locations_.resize(num_parties);
    // I could initialize output->inputs_as_generic_value_locations_ with
    // one.inputs_as_generic_value_locations_ (and then update it with values
    // from two.inputs_as_generic_value_locations_), but I need to know the
    // *number* of inputs into circuit one, which is not directly available.
    // So instead, I just walk through one.inputs_as_generic_value_locations_,
    // updating output->inputs_as_generic_value_locations_ as I go, and also
    // keeping track of the number of circuit one inputs.
    vector<uint64_t> num_circuit_one_inputs_one_per_party(
        one.input_types_.size(), 0);
    for (int party = 0; party < (int) one.input_types_.size(); ++party) {
      for (size_t input_index = 0;
           input_index < one.inputs_as_generic_value_locations_[party].size();
           ++input_index) {
        const vector<set<WireLocation>>& input_to_wire =
            one.inputs_as_generic_value_locations_[party][input_index];
        if (input_index + 1 > num_circuit_one_inputs_one_per_party[party]) {
          num_circuit_one_inputs_one_per_party[party] = input_index + 1;
        }
        if (output->inputs_as_generic_value_locations_[party].size() <=
            input_index) {
          output->inputs_as_generic_value_locations_[party].resize(
              input_index + 1, vector<set<WireLocation>>());
        }
        vector<set<WireLocation>>& new_wires =
            output->inputs_as_generic_value_locations_[party][input_index];
        if (new_wires.size() < input_to_wire.size()) {
          new_wires.resize(input_to_wire.size());
        }
        for (uint64_t bit_index = 0; bit_index < input_to_wire.size();
             ++bit_index) {
          const set<WireLocation>& wires = input_to_wire[bit_index];
          set<WireLocation>& new_wires_i = new_wires[bit_index];
          for (const WireLocation& loc : wires) {
            new_wires_i.insert(
                WireLocation(loc.loc_.level_, loc.loc_.index_, loc.is_left_));
          }
        }
      }
    }
    // Now add in circuit two's inputs_as_generic_value_locations_.
    for (int party = 0; party < (int) two.input_types_.size(); ++party) {
      const uint64_t offset = preserve_input_indexing ?
          0 :
          ((int) num_circuit_one_inputs_one_per_party.size() > party ?
               num_circuit_one_inputs_one_per_party[party] :
               0);
      for (size_t input_index = 0;
           input_index < two.inputs_as_generic_value_locations_[party].size();
           ++input_index) {
        const vector<set<WireLocation>>& input_to_wire =
            two.inputs_as_generic_value_locations_[party][input_index];
        if (output->inputs_as_generic_value_locations_[party].size() <=
            input_index + offset) {
          output->inputs_as_generic_value_locations_[party].resize(
              input_index + offset + 1, vector<set<WireLocation>>());
        }
        vector<set<WireLocation>>& new_wires =
            output->inputs_as_generic_value_locations_[party]
                                                      [input_index + offset];
        if (new_wires.size() < input_to_wire.size()) {
          new_wires.resize(input_to_wire.size());
        }
        for (uint64_t bit_index = 0; bit_index < input_to_wire.size();
             ++bit_index) {
          const set<WireLocation>& wires = input_to_wire[bit_index];
          set<WireLocation>& new_wires_i = new_wires[bit_index];
          for (const WireLocation& loc : wires) {
            const int64_t index_offset = loc.loc_.level_ >= (int64_t) one_depth ?
                0 :
                one.levels_[loc.loc_.level_].gates_.size();
            new_wires_i.insert(WireLocation(
                loc.loc_.level_, loc.loc_.index_ + index_offset, loc.is_left_));
          }
        }
      }
    }

    // Constant (0) inputs.
    output->constant_zero_input_ = one.constant_zero_input_;
    for (const WireLocation& to_gate : two.constant_zero_input_) {
      const int64_t index_offset = to_gate.loc_.level_ >= (int64_t) one_depth ?
          0 :
          one.levels_[to_gate.loc_.level_].gates_.size();
      output->constant_zero_input_.insert(WireLocation(
          to_gate.loc_.level_,
          to_gate.loc_.index_ + index_offset,
          to_gate.is_left_));
    }
    // Constant (1) inputs.
    output->constant_one_input_ = one.constant_one_input_;
    for (const WireLocation& to_gate : two.constant_one_input_) {
      const int64_t index_offset = to_gate.loc_.level_ >= (int64_t) one_depth ?
          0 :
          one.levels_[to_gate.loc_.level_].gates_.size();
      output->constant_one_input_.insert(WireLocation(
          to_gate.loc_.level_,
          to_gate.loc_.index_ + index_offset,
          to_gate.is_left_));
    }
  }

  // The Merged circuit can just concatenate (put side-by-side) all the levels
  // together, until the final level, where instead of outputing the result,
  // the two output wires are combined (at one deeper level) via 'op'.
  // Loop through all levels of each circuit, concatentating them.
  uint64_t num_gates = 0;
  output->levels_.resize(max_depth);
  vector<set<int>> dependencies_of_global_outputs(one.num_output_wires_);
  for (uint64_t level = 0; level < max_depth; ++level) {
    StandardCircuitLevel<value_t>& current_level = output->levels_[level];
    uint64_t num_gates_on_current_level = 0;

    // Loop through all gates on this level of circuit one, copying them to output.
    if (level < one_depth) {
      const StandardCircuitLevel<value_t>& one_level = one.levels_[level];
      const uint64_t one_num_gates = one_level.gates_.size();
      current_level.gates_.resize(one_num_gates);
      for (uint64_t gate_index = 0; gate_index < one_num_gates; ++gate_index) {
        const StandardGate<value_t>& one_gate = one_level.gates_[gate_index];
        StandardGate<value_t>& current_gate = current_level.gates_[gate_index];
        current_gate.loc_ = GateLocation(level, num_gates_on_current_level);
        current_gate.type_ = one_gate.type_;
        current_gate.left_input_set_ = false;
        current_gate.right_input_set_ = false;
        current_gate.depends_on_ = one_gate.depends_on_;
        // Go through the output wires of this gate. For all global/circuit
        // output wires, change the WireLocation to be directed to the new
        // combinor gate at depth max_depth (except in the special case
        // op == IDENTITY, in which case just keep output as is); otherwise,
        // copy the output WireLocation.
        for (const WireLocation& output_loc : one_gate.output_wire_locations_) {
          if (output_loc.loc_.level_ == -1) {
            // This is a global output wire for circuit 1. Remap it to a gate
            // on the (new) last level, so that it can be merged with the
            // corresponding output wire of circuit 2.
            if (op == BooleanOperation::IDENTITY) {
              current_gate.output_wire_locations_.insert(
                  WireLocation(-1, output_loc.loc_.index_));
            } else {
              current_gate.output_wire_locations_.insert(
                  WireLocation(max_depth, output_loc.loc_.index_, true));
              for (const int k : current_gate.depends_on_) {
                dependencies_of_global_outputs[output_loc.loc_.index_].insert(k);
              }
            }
          } else {
            current_gate.output_wire_locations_.insert(WireLocation(
                output_loc.loc_.level_,
                output_loc.loc_.index_,
                output_loc.is_left_));
          }
        }
        ++num_gates_on_current_level;
      }
    }

    const uint64_t num_gates_on_circuit_one_this_level =
        num_gates_on_current_level;

    // Loop through all gates on this level of circuit two, copying them to output.
    if (level < two_depth) {
      const StandardCircuitLevel<value_t>& two_level = two.levels_[level];
      const uint64_t two_num_gates = two_level.gates_.size();
      current_level.gates_.resize(
          num_gates_on_circuit_one_this_level + two_num_gates);
      for (uint64_t gate_index = 0; gate_index < two_num_gates; ++gate_index) {
        const StandardGate<value_t>& two_gate = two_level.gates_[gate_index];
        StandardGate<value_t>& current_gate =
            current_level
                .gates_[num_gates_on_circuit_one_this_level + gate_index];
        current_gate.loc_ = GateLocation(level, num_gates_on_current_level);
        current_gate.type_ = two_gate.type_;
        current_gate.left_input_set_ = false;
        current_gate.right_input_set_ = false;
        current_gate.depends_on_ = two_gate.depends_on_;
        // Go through the output wires of this gate. For all global/circuit
        // output wires, change the WireLocation to be directed to the new
        // combinor gate at depth max_depth (except in the special case
        // op == IDENTITY, in which case just keep output as is); otherwise,
        // copy the output WireLocation.
        for (const WireLocation& output_loc : two_gate.output_wire_locations_) {
          if (output_loc.loc_.level_ == -1) {
            // This is a global output wire for circuit 1. Remap it to a gate
            // on the (new) last level, so that it can be merged with the
            // corresponding output wire of circuit 2.
            if (op == BooleanOperation::IDENTITY) {
              current_gate.output_wire_locations_.insert(WireLocation(
                  -1, output_loc.loc_.index_ + one.num_output_wires_));
            } else {
              current_gate.output_wire_locations_.insert(
                  WireLocation(max_depth, output_loc.loc_.index_, false));
              for (const int k : current_gate.depends_on_) {
                dependencies_of_global_outputs[output_loc.loc_.index_].insert(k);
              }
            }
          } else {
            const uint64_t offset =
                (output_loc.loc_.level_ >= (int64_t) one_depth) ?
                0 :
                one.levels_[output_loc.loc_.level_].gates_.size();
            current_gate.output_wire_locations_.insert(WireLocation(
                output_loc.loc_.level_,
                output_loc.loc_.index_ + offset,
                output_loc.is_left_));
          }
        }
        ++num_gates_on_current_level;
      }
    }

    // Set global level_ fields.
    current_level.level_ = level;
    current_level.num_gates_ = num_gates_on_current_level;
    num_gates += num_gates_on_current_level;
  }

  // Update input variable indices by shifting them by however many inputs
  // circuit one had.
  map<string, string> circuit_two_var_names;
  // Set input types mappings.
  output->input_types_.resize(num_parties);
  for (int party = 0; party < num_parties; ++party) {
    const int num_one_party_inputs =
        party < num_one_parties ? (int) one.input_types_[party].size() : 0;
    const int num_two_party_inputs =
        party < num_two_parties ? (int) two.input_types_[party].size() : 0;
    const int max_num_inputs = max(num_one_party_inputs, num_two_party_inputs);
    if (preserve_input_indexing) {
      output->input_types_[party].resize(max_num_inputs);
      for (int i = 0; i < max_num_inputs; ++i) {
        if (i < num_one_party_inputs && i < num_two_party_inputs) {
          if (one.input_types_[party][i].first !=
                  two.input_types_[party][i].first &&
              !one.input_types_[party][i].first.empty() &&
              !two.input_types_[party][i].first.empty()) {
            LOG_FATAL(
                "For i=" + Itoa(i) + " and Party = " + Itoa(party) +
                ", one.input_types_[party][i].var_name = '" +
                one.input_types_[party][i].first +
                "', two_input_types var name: '" +
                two.input_types_[party][i].first + "', one DataType: " +
                Itoa(static_cast<int>(one.input_types_[party][i].second)) +
                " two DataType: " +
                Itoa(static_cast<int>(two.input_types_[party][i].second)));
          }
          // One of the input circuits may have empty input information.
          // If this is the case, use the other.
          if (one.input_types_[party][i].first.empty()) {
            if (one.input_types_[party][i].second != DataType::UNKNOWN) {
              LOG_FATAL("Unexpected empty variable has DataType set.");
            }
            output->input_types_[party][i] = two.input_types_[party][i];
          } else if (two.input_types_[party][i].first.empty()) {
            if (two.input_types_[party][i].second != DataType::UNKNOWN) {
              LOG_FATAL("Unexpected empty variable has DataType set.");
            }
            output->input_types_[party][i] = one.input_types_[party][i];
          } else if (
              one.input_types_[party][i].second == DataType::UNKNOWN ||
              two.input_types_[party][i].second == DataType::UNKNOWN) {
            LOG_FATAL("Unexpected unknown DataType.");
            // If DataType is the same for both inputs, then
            //   one.input_types_[party][i] == two.input_types_[party][i],
            // and so it doesn't matter which one we use.
          } else if (
              one.input_types_[party][i].second ==
              two.input_types_[party][i].second) {
            output->input_types_[party][i] = one.input_types_[party][i];
            // It is a valid use-case to have the DataTypes not match. Pick
            // the larger of the two.
          } else if (
              GetValueNumBits(one.input_types_[party][i].second) >
              GetValueNumBits(two.input_types_[party][i].second)) {
            output->input_types_[party][i] = one.input_types_[party][i];
          } else if (
              GetValueNumBits(one.input_types_[party][i].second) <
              GetValueNumBits(two.input_types_[party][i].second)) {
            output->input_types_[party][i] = two.input_types_[party][i];
            // The remaining cases means that the DataTypes are different
            // but have the same number of bytes. By convention, choose
            // the signed DataType.
          } else if (IsSignedDataType(one.input_types_[party][i].second)) {
            output->input_types_[party][i] = one.input_types_[party][i];
          } else {
            output->input_types_[party][i] = two.input_types_[party][i];
          }
        } else if (i < num_one_party_inputs) {
          output->input_types_[party][i] = one.input_types_[party][i];
        } else {
          output->input_types_[party][i] = two.input_types_[party][i];
        }
      }
    } else {
      if (party < num_one_parties) {
        output->input_types_[party].reserve(num_one_party_inputs);
        output->input_types_[party].insert(
            output->input_types_[party].end(),
            one.input_types_[party].begin(),
            one.input_types_[party].end());
      }
      output->input_types_[party].resize(
          num_one_party_inputs + num_two_party_inputs);
      for (int i = 0; i < num_two_party_inputs; ++i) {
        const pair<string, DataType>& orig_var_i = two.input_types_[party][i];
        if (orig_var_i.first != "P" + Itoa(party) + "_" + Itoa(i)) {
          LOG_FATAL("Fatal Error.");
        }
        const string new_var_name =
            "P" + Itoa(party) + "_" + Itoa(i + num_one_party_inputs);
        circuit_two_var_names.insert(make_pair(orig_var_i.first, new_var_name));
        output->input_types_[party][num_one_party_inputs + i] =
            make_pair(new_var_name, orig_var_i.second);
      }
    }
  }

  // Test if this is the special "Side-by-Side" use-case of Merge, in which
  // case update final fields and return.
  if (op == BooleanOperation::IDENTITY) {
    output->depth_ = output->levels_.size();
    output->size_ = num_gates;
    output->num_outputs_ = one.num_outputs_ + two.num_outputs_;
    output->num_output_wires_ = one.num_output_wires_ + two.num_output_wires_;
    output->num_non_local_gates_ =
        one.num_non_local_gates_ + two.num_non_local_gates_;
    output->output_designations_ = one.output_designations_;
    const uint64_t offset = one.output_designations_.size();
    output->output_designations_.resize(
        offset + two.output_designations_.size());
    if (update_function_description) {
      output->function_description_ = one.function_description_;
      output->function_description_.resize(
          offset + two.function_description_.size());
    }
    for (size_t i = 0; i < two.output_designations_.size(); ++i) {
      output->output_designations_[offset + i] = two.output_designations_[i];
      if (!update_function_description) continue;
      output->function_description_[offset + i] = two.function_description_[i];
      if (!preserve_input_indexing) {
        UpdateFormulaVarNames(
            circuit_two_var_names, &output->function_description_[offset + i]);
      }
    }

    return true;
  }

  // Now, construct the new level, which combines the output wires of the
  // two circuits.
  output->levels_.push_back(StandardCircuitLevel<value_t>());
  StandardCircuitLevel<value_t>& last_level = output->levels_.back();
  last_level.level_ = max_depth;
  last_level.num_gates_ = one.num_output_wires_;
  last_level.gates_.resize(one.num_output_wires_);
  int64_t num_new_non_local_gates = 0;
  for (int64_t gate_index = 0; gate_index < one.num_output_wires_;
       ++gate_index) {
    StandardGate<value_t>& output_gate = last_level.gates_[gate_index];
    output_gate.loc_ = GateLocation(max_depth, gate_index);
    output_gate.type_ = op;
    output_gate.left_input_set_ = false;
    output_gate.right_input_set_ = false;
    output_gate.depends_on_ = dependencies_of_global_outputs[gate_index];
    if (output_gate.depends_on_.size() >= 2 && op != BooleanOperation::XOR &&
        op != BooleanOperation::EQ) {
      ++num_new_non_local_gates;
    }
    // Set output wire location level as "-1" to indicate (circuit) output wire.
    output_gate.output_wire_locations_.insert(WireLocation(-1, gate_index));
    ++num_gates;
  }

  // Update global circuit fields.
  output->depth_ = output->levels_.size();
  output->size_ = num_gates;
  output->num_outputs_ = one.num_outputs_;
  output->num_output_wires_ = one.num_output_wires_;
  output->num_non_local_gates_ = one.num_non_local_gates_ +
      two.num_non_local_gates_ + num_new_non_local_gates;
  output->output_designations_.resize(one.output_designations_.size());
  if (update_function_description) {
    output->function_description_.resize(one.function_description_.size());
  }
  for (size_t i = 0; i < one.output_designations_.size(); ++i) {
    const pair<OutputRecipient, DataType> one_output_i =
        one.output_designations_[i];
    const pair<OutputRecipient, DataType> two_output_i =
        two.output_designations_[i];
    if (one_output_i.second != two_output_i.second) {
      LOG_FATAL(
          "Unable to merge mismatching output types for output " + Itoa(i) +
          GetDataTypeString(one_output_i.second) + " vs. " +
          GetDataTypeString(two_output_i.second));
    }
    OutputRecipient target_i;
    if (one_output_i.first.all_) {
      target_i = two_output_i.first;
    } else if (one_output_i.first.none_) {
      if (!two_output_i.first.none_) LOG_FATAL("Fatal Error.");
      target_i.all_ = false;
      target_i.none_ = true;
    } else if (two_output_i.first.none_) {
      LOG_FATAL("If one circuit specifies NEITHER, so must the other");
    } else {
      if (one_output_i.first.to_ != two_output_i.first.to_) {
        LOG_FATAL("Circuits specify different output targets.");
      }
      target_i = OutputRecipient(one_output_i.first.to_);
    }
    output->output_designations_[i] = make_pair(target_i, one_output_i.second);

    if (!update_function_description) continue;
    Formula& function_i = output->function_description_[i];
    function_i.op_.type_ = OperationType::BOOLEAN;
    function_i.op_.gate_op_ = op;
    function_i.subterm_one_ = unique_ptr<Formula>(new Formula());
    function_i.subterm_one_->clone(one.function_description_[i]);
    function_i.subterm_two_ = unique_ptr<Formula>(new Formula());
    function_i.subterm_two_->clone(two.function_description_[i]);
    if (!preserve_input_indexing) {
      UpdateFormulaVarNames(
          circuit_two_var_names, function_i.subterm_two_.get());
    }
  }

  return true;
}

bool MergeCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const ComparisonOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  // Sanity-check input has been set.
  if (one.levels_.empty() || two.levels_.empty() || output == nullptr) {
    LOG_FATAL("Fatal Error.");
  }
  // We assume num_output_wires_ fields have been set.
  if (one.num_output_wires_ <= 0 || two.num_output_wires_ <= 0) {
    LOG_FATAL("Fatal Error.");
  }
  uint64_t num_one_outputs = one.num_output_wires_;
  uint64_t num_two_outputs = two.num_output_wires_;

  // Construct a circuit that will compare the outputs of the two circuits
  // (NOTE: This circuit won't yet be connected, i.e. we'll still need to connect
  // this circuit's input wires to the appropriate output wires of the above
  // merged circuit).
  StandardCircuit<bool> comparison;
  if (!ConstructComparisonCircuit(
          op,
          one_is_twos_complement,
          two_is_twos_complement,
          num_one_outputs,
          num_two_outputs,
          &comparison)) {
    return false;
  }

  // Now, merge the two above circuits, by connecting the output wires of
  // one to the input wires of the other.
  return JoinCircuits(
      preserve_input_indexing,
      update_function_description,
      one,
      two,
      comparison,
      output);
}

bool MergeCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const ArithmeticOperation& op,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  // Sanity-check input has been set.
  if (one.levels_.empty() || output == nullptr) {
    LOG_FATAL("Fatal Error.");
  }
  // We assume num_output_wires_ fields have been set.
  if (one.num_output_wires_ <= 0) {
    LOG_FATAL("Fatal Error.");
  }
  // There may be some valid use-cases of this API when the second circuit
  // 'two' is empty, e.g. if 'op' is a single input operation.
  if (!IsSingleInputOperation(op) &&
      (two.levels_.empty() || two.num_output_wires_ <= 0)) {
    LOG_FATAL("Fatal Error.");
  }

  uint64_t num_one_outputs = one.num_output_wires_;
  uint64_t num_two_outputs = two.num_output_wires_;

  // Construct a circuit that will combine the outputs of the two circuits
  // via the specified arithmetic operation.
  // (NOTE: This circuit won't yet be connected, i.e. we'll still need to connect
  // this circuit's input wires to the appropriate output wires of the above
  // merged circuit).
  StandardCircuit<bool> arithmetic;
  // TODO(paul): Once/if actual arithemetic circuits exist, this function may
  // change: the first argument to 'ConstructArithmeticCircuit' below should
  // be determined based on the code above, i.e. what the formats (Boolean vs.
  // Arithmetic) are for the two circuits being merged.
  if (!ConstructArithmeticCircuit(
          true,
          op,
          one_is_twos_complement,
          two_is_twos_complement,
          num_one_outputs,
          num_two_outputs,
          &arithmetic)) {
    return false;
  }

  // Now, merge the two above circuits, by connecting the output wires of
  // one to the input wires of the other.
  if (IsSingleInputOperation(op)) {
    return JoinCircuits(
        preserve_input_indexing,
        update_function_description,
        one,
        arithmetic,
        output);
  } else {
    return JoinCircuits(
        preserve_input_indexing,
        update_function_description,
        one,
        two,
        arithmetic,
        output);
  }
}

bool MergeCircuits(
    const bool preserve_input_indexing,
    const bool update_function_description,
    const OperationHolder& op_holder,
    const bool one_is_twos_complement,
    const bool two_is_twos_complement,
    const StandardCircuit<bool>& one,
    const StandardCircuit<bool>& two,
    StandardCircuit<bool>* output) {
  if (!op_holder.IsValid() || op_holder.type_ == OperationType::MATH) {
    LOG_FATAL("Fatal Error.");
  }
  if (op_holder.type_ == OperationType::BOOLEAN) {
    return MergeCircuits(
        preserve_input_indexing,
        update_function_description,
        op_holder.gate_op_,
        one,
        two,
        output);
  }
  if (op_holder.type_ == OperationType::COMPARISON) {
    return MergeCircuits(
        preserve_input_indexing,
        update_function_description,
        op_holder.comparison_op_,
        one_is_twos_complement,
        two_is_twos_complement,
        one,
        two,
        output);
  }
  if (op_holder.type_ == OperationType::ARITHMETIC) {
    return MergeCircuits(
        preserve_input_indexing,
        update_function_description,
        op_holder.arithmetic_op_,
        one_is_twos_complement,
        two_is_twos_complement,
        one,
        two,
        output);
  }

  return false;
}

bool MergeArgminCircuits(
    const ArithmeticOperation& op,
    const StandardCircuit<bool>& left_circuit,
    const StandardCircuit<bool>& right_circuit,
    StandardCircuit<bool>* out) {
  if (left_circuit.output_designations_.empty() ||
      right_circuit.output_designations_.empty()) {
    return false;
  }

  // Typically, the call to MergeArgminCircuits() is merging two circuits
  // ('left_circuit' and 'right_circuit'), where each of those two circuits
  // is an ARGMIN_INTERNAL circuit, which in particular means the output
  // of each circuit is one value and one vector: (min, ARGMIN(...)).
  // However, it is also possible that 'left_circuit' (and/or 'right_circuit')
  // represents a variable itself, as opposed to the output of an (internal)
  // argmin. Thus, we can distinguish which case we are in by looking at
  // the number of outputs of each circuit: there will be one output in
  // the latter case, and otherwise more than one.
  // We want to unify these two use-cases, so in the latter case, we modify
  // the relevant circuit(s) so that it obeys the same convention as if
  // it were an ARGMIN_INTERNAL circuit. Namely, instead of a single output
  // (representing the value of the variable), we make it have two outputs:
  //   (min, ARGMIN()) = (x, (1)),
  // where the ARGMIN is just a length-1 vector with a '1' in the 0th coordinate.
  const bool left_is_argmin = left_circuit.output_designations_.size() > 1;
  const bool right_is_argmin = right_circuit.output_designations_.size() > 1;
  StandardCircuit<bool> left_temp, right_temp;
  const StandardCircuit<bool>* left = &left_circuit;
  const StandardCircuit<bool>* right = &right_circuit;
  if (!left_is_argmin) {
    // Construct circuit that always outputs bit with value '1'.
    StandardCircuit<bool> constant_one;
    if (!ConstructConstantCircuit(true, &constant_one)) return false;
    // Merge (put side-by-side) with left_circuit.
    if (!MergeCircuitsInternal(
            true,
            BooleanOperation::IDENTITY,
            left_circuit,
            constant_one,
            &left_temp)) {
      return false;
    }
    left = &left_temp;
  }
  if (!right_is_argmin) {
    // Construct circuit that always outputs bit with value '1'.
    StandardCircuit<bool> constant_one;
    if (!ConstructConstantCircuit(true, &constant_one)) return false;
    // Merge (put side-by-side) with right_circuit.
    if (!MergeCircuitsInternal(
            true,
            BooleanOperation::IDENTITY,
            right_circuit,
            constant_one,
            &right_temp)) {
      return false;
    }
    right = &right_temp;
  }

  // Grab the vector size of each circuit.
  const uint64_t size_vector_left = left->output_designations_.size() - 1;
  const uint64_t size_vector_right = right->output_designations_.size() - 1;

  // Grab the data-types of the subcircuits.
  const DataType left_type = left_circuit.output_designations_[0].second;
  const DataType right_type = right_circuit.output_designations_[0].second;

  // Grab the number of bits in the output value of left_ and right_circuit.
  const uint64_t num_bits_in_left_value = GetValueNumBits(left_type);
  const uint64_t num_bits_in_right_value = GetValueNumBits(right_type);

  // The rest of the logic of this function is as follows:
  //   1) Construct the basic ARGMIN/ARGMAX (or ARGMIN/MAX_INTERNAL) circuit:
  //      takes two values as inputs, and outputs:
  //        a) (In case of doing the ARGMIN/MAX_INTERNAL): Min (or Max) value; and
  //        b) Characteristic vector (1, 0) or (0, 1) (or (1, 1)).
  //   2) Construct a circuit that takes n + 1 inputs (bits), and outputs
  //      n bits, where each bit of the input (except the first) has been
  //      multiplied by the first input. In other words, this circuit
  //      represents the vector scalar product:
  //        f(b, v) = bv = (bv1, bv2, ..., bvn)
  //      Do this twice: for n = size_vector_left and n = size_vector_right.
  //      Merge the results (place side-by-side).
  //   3) Construct a circuit that takes as input two vectors (of arbitrary,
  //      perhaps unequal, size) and concatentates them.
  //   4) Put left_circuit and right_circuit side-by-side. Thus, this has outputs:
  //        a) The two value outputs, one from left_circuit and one from right_circuit
  //           (representing the min value of the left and right circuits, respectively)
  //        b) Two vector outputs, one from left_circuit and one from right_circuit
  //           (representing the argmins of the left and right circuits, respectively)
  //   5) Hook up the circuits in (2) -> (3): The outputs of (2) are the inputs to (3).
  //   6) Hook up the circuits in (4) -> (1):
  //         - The two values that are input into (1) are the two value
  //           outputs of (4a)
  //         - The final outputs (in order) are:
  //             a) The two vector outputs of (4b); these take up n1 + n2 output bits
  //             b) (In case of doing the ARGMIN/MAX_INTERNAL): The value output of (1a)
  //             c) The (size 2) vector output of (1b)
  //   7) Hook up the circuits in (6) -> (5):
  //         - The inputs (two bits and two vectors) to the merged circuit in (5)
  //           are: The two bits are the outputs (6c) and the two vectors are
  //           the outputs (6a).
  //         - The final outputs (in order) are:
  //             a) (In case of doing the ARGMIN/MAX_INTERNAL): The value output of (6b)
  //             b) The output of (5), which is the ARGMIN (i.e. a characteristic
  //                vector with a '1' in the position of the min).

  // Do (1).
  StandardCircuit<bool> step_one;
  const bool left_is_twos_complement = IsDataTypeTwosComplement(left_type);
  const bool right_is_twos_complement = IsDataTypeTwosComplement(right_type);
  if (!ConstructArithmeticCircuit(
          true,
          op,
          left_is_twos_complement,
          right_is_twos_complement,
          num_bits_in_left_value,
          num_bits_in_right_value,
          &step_one)) {
    return false;
  }

  // Do (2).
  StandardCircuit<bool> step_two_left, step_two_right;
  if (!ConstructScalarMultiplicationCircuit(size_vector_left, &step_two_left) ||
      !ConstructScalarMultiplicationCircuit(
          size_vector_right, &step_two_right)) {
    return false;
  }
  StandardCircuit<bool> step_two;
  if (!MergeCircuitsInternal(
          false,
          BooleanOperation::IDENTITY,
          step_two_left,
          step_two_right,
          &step_two)) {
    return false;
  }

  // Do (3).
  StandardCircuit<bool> step_three;
  if (!ConstructVectorConcatenationCircuit(
          size_vector_left, size_vector_right, &step_three)) {
    return false;
  }

  // Do (4).
  StandardCircuit<bool> step_four;
  if (!MergeCircuitsInternal(
          true, BooleanOperation::IDENTITY, *left, *right, &step_four)) {
    return false;
  }

  // Do (5).
  StandardCircuit<bool> step_five;
  if (!JoinCircuits(step_two, step_three, &step_five)) {
    return false;
  }

  // Do (6).
  // First, specify the mapping for connect output wires of the circuit
  // built in (4) with the input wires of the circuit built in (1).
  map<int64_t, set<pair<int, pair<uint64_t, uint64_t>>>> output_to_input;
  for (uint64_t i = 0; i < num_bits_in_left_value; ++i) {
    set<pair<int, pair<uint64_t, uint64_t>>> target_i;
    target_i.insert(make_pair(0, make_pair(0, i)));
    output_to_input.insert(make_pair(i, target_i));
  }
  for (uint64_t i = 0; i < num_bits_in_right_value; ++i) {
    set<pair<int, pair<uint64_t, uint64_t>>> target_i;
    target_i.insert(make_pair(1, make_pair(0, i)));
    output_to_input.insert(
        make_pair(num_bits_in_left_value + size_vector_left + i, target_i));
  }
  StandardCircuit<bool> step_six;
  if (!JoinCircuits(output_to_input, step_four, step_one, &step_six)) {
    return false;
  }

  // Do (7).
  output_to_input.clear();
  const uint64_t num_bits_in_min_value =
      (op == ArithmeticOperation::ARGMIN || op == ArithmeticOperation::ARGMAX) ?
      0 :
      max(num_bits_in_left_value, num_bits_in_right_value);
  const uint64_t step_six_output_index_for_lt =
      size_vector_left + size_vector_right + num_bits_in_min_value;
  const uint64_t step_six_output_index_for_not_lt =
      step_six_output_index_for_lt + 1;
  set<pair<int, pair<uint64_t, uint64_t>>> step_five_lt_input_loc;
  step_five_lt_input_loc.insert(make_pair(0, make_pair(0, 0)));
  output_to_input.insert(
      make_pair(step_six_output_index_for_lt, step_five_lt_input_loc));
  set<pair<int, pair<uint64_t, uint64_t>>> step_five_not_lt_input_loc;
  step_five_not_lt_input_loc.insert(make_pair(0, make_pair(1, 0)));
  output_to_input.insert(
      make_pair(step_six_output_index_for_not_lt, step_five_not_lt_input_loc));
  for (uint64_t i = 0; i < size_vector_left; ++i) {
    set<pair<int, pair<uint64_t, uint64_t>>> target_i;
    target_i.insert(make_pair(1, make_pair(i, 0)));
    output_to_input.insert(make_pair(i, target_i));
  }
  for (uint64_t i = 0; i < size_vector_right; ++i) {
    set<pair<int, pair<uint64_t, uint64_t>>> target_i;
    target_i.insert(make_pair(1, make_pair(size_vector_left + i, 0)));
    output_to_input.insert(make_pair(size_vector_left + i, target_i));
  }

  if (!JoinCircuits(output_to_input, step_six, step_five, out)) {
    return false;
  }

  // Update function description.
  // Discussion: Rather than combining the *.function_description_ of the
  // circuits built in Steps (1) - (7) above, we create the new
  // function_description_ based solely on the initial inputs
  // ('left_circuit' and 'right_circuit'). In particular, 'left_circuit' has
  // outputs i:
  //   i = 0: m (= min(x1, ..., xN))
  //   i = 1: b1 (b1 = 1 iff x1 = min)
  //   ...
  //   i = N: bN (bN = 1 iff xN = min)
  // Similarly, 'right_circuit' has outputs i:
  //   i = 0: m (= min(y1, ..., yN))
  //   i = 1: b1 (b1 = 1 iff y1 = min)
  //   ...
  //   i = N: bN (bN = 1 iff yN = min)
  // Thus, the final outputs will be:
  //   i = 0: m (= min(x1, ..., xN, y1, ..., yN))
  //   i = 1: b1 (b1 = 1 iff x1 = min)
  //   ...
  //   i = N: bN (bN = 1 iff xN = min)
  //   i = N+1: b{N+1} (b{N+1} = 1 iff y1 = min)
  //   ...
  //   i = 2N: b{2N} (b{2N} = 1 iff yN = min)
  // We will construct the output formulas by picking out the var_names
  // {x1, ..., xN} and {y1, ..., yN} from the input circuits 'left_circuit' and
  // 'right_circuit', and then use these to construct each output formula.
  const int toggle =
      (op == ArithmeticOperation::ARGMIN || op == ArithmeticOperation::ARGMAX) ?
      0 :
      1;
  // Grab var names from [left | right]_circuit's function_description_.
  if (left_circuit.function_description_.empty() ||
      right_circuit.function_description_.empty()) {
    LOG_ERROR("Incomplete left or right circuit function_description_.");
    return false;
  }

  // Even though op is ARGMIN, ARGMAX, the formula description will just use MIN, MAX.
  const ArithmeticOperation formula_op =
      (op == ArithmeticOperation::ARGMIN ||
       op == ArithmeticOperation::ARGMIN_INTERNAL) ?
      ArithmeticOperation::MIN :
      ArithmeticOperation::MAX;

  // Construct a formula for: MIN(x1, ..., xN, y1, ..., yN).
  Formula min_formula;
  Formula* current_term = &min_formula;
  current_term->op_.type_ = OperationType::ARITHMETIC;
  current_term->op_.arithmetic_op_ = formula_op;
  current_term->subterm_one_.reset(new Formula(left->function_description_[0]));
  current_term->subterm_two_.reset(new Formula(right->function_description_[0]));

  // Now update function_description_.
  const int output_char_vector_length =
      (int) (size_vector_left + size_vector_right);
  out->function_description_.clear();
  out->function_description_.resize(toggle + output_char_vector_length);

  // Update the first output, which is the minimum (value) of all inputs.
  if (toggle == 1) {
    out->function_description_[0] = min_formula;
  }

  // Now, update the rest of the formulas which are:
  //   Formula_i: min(v1, ..., vn) == vi
  for (int i = 0; i < output_char_vector_length; ++i) {
    const Formula& var_i_formula = i < (int) size_vector_left ?
        left->function_description_[1 + i] :
        right->function_description_[1 + i - size_vector_left];
    Formula& formula_i = out->function_description_[toggle + i];
    formula_i.op_.type_ = OperationType::COMPARISON;
    formula_i.op_.comparison_op_ = ComparisonOperation::COMP_EQ;
    formula_i.subterm_one_.reset(new Formula(var_i_formula));
    formula_i.subterm_two_.reset(new Formula(min_formula));
  }

  ReduceCircuit(false, out);
  return true;
}

bool MergeVectorsCircuit(
    const StandardCircuit<bool>& left_circuit,
    const StandardCircuit<bool>& right_circuit,
    StandardCircuit<bool>* out) {
  return MergeCircuitsInternal(
      true, BooleanOperation::IDENTITY, left_circuit, right_circuit, out);
}

bool MergeViaInnerProductCircuit(
    const StandardCircuit<bool>& left_circuit,
    const StandardCircuit<bool>& right_circuit,
    StandardCircuit<bool>* out) {
  const size_t n = left_circuit.num_outputs_;
  if (right_circuit.num_outputs_ < 0 ||
      n != (size_t) right_circuit.num_outputs_ ||
      n != left_circuit.output_designations_.size() ||
      n != right_circuit.output_designations_.size()) {
    return false;
  }

  // First, create circuits that multiply each coordinate-pair.
  StandardCircuit<bool> dot_product;
  vector<StandardCircuit<bool>> products(n);
  for (size_t i = 0; i < n; ++i) {
    if (!ConstructArithmeticCircuit(
            true,
            ArithmeticOperation::MULT,
            left_circuit.output_designations_[i].second,
            right_circuit.output_designations_[i].second,
            (n == 1 ? &dot_product : &(products[i])))) {
      return false;
    }
  }

  // Next, add all of these together.
  // Respect the DataType for this sum; specifically, if DataType of
  // left, right is BOOL, then do addition in Z2. Otherwise, do addition
  // in whatever the DataType of left, right.
  bool add_in_z_two = true;
  for (const pair<OutputRecipient, DataType>& out_type :
       left_circuit.output_designations_) {
    if (out_type.second != DataType::BOOL) {
      add_in_z_two = false;
      break;
    }
  }
  if (add_in_z_two) {
    for (const pair<OutputRecipient, DataType>& out_type :
         right_circuit.output_designations_) {
      if (out_type.second != DataType::BOOL) {
        add_in_z_two = false;
        break;
      }
    }
  }
  if (n > 1) {
    vector<StandardCircuit<bool>> sums(n - 2);
    for (size_t i = 0; i < n - 1; ++i) {
      const StandardCircuit<bool>& left = i == 0 ? products[0] : sums[i - 1];
      const StandardCircuit<bool>& right = products[i + 1];
      if (!add_in_z_two &&
          !MergeCircuits(
              false,
              ArithmeticOperation::ADD,
              IsDataTypeTwosComplement(left.output_designations_[0].second),
              IsDataTypeTwosComplement(right.output_designations_[0].second),
              left,
              right,
              (i == n - 2 ? &dot_product : &(sums[i])))) {
        return false;
      } else if (
          add_in_z_two &&
          !MergeCircuits(
              false,
              BooleanOperation::XOR,
              left,
              right,
              (i == n - 2 ? &dot_product : &(sums[i])))) {
        return false;
      }
    }
  }

  // Hook up inputs to dot_product.
  if (!JoinCircuits(left_circuit, right_circuit, dot_product, out)) return false;

  return true;
}

bool CircuitFromIdentityFormula(
    const bool demand_var_name_match,
    const GenericValue& value,
    vector<vector<pair<string, DataType>>>* input_types,
    StandardCircuit<bool>* output) {
  if (IsStringDataType(value)) {
    // This term is a variable. See if we can find it in input_types.
    const string var_name = GetGenericValueString(value);
    int party_index = -1;
    int64_t input_index = -1;
    for (int party = 0; party < (int) input_types->size(); ++party) {
      for (int64_t i = 0; i < (int64_t) (*input_types)[party].size(); ++i) {
        if ((*input_types)[party][i].first == var_name) {
          if (party_index >= 0 || input_index >= 0) {
            LOG_ERROR(
                "Variable '" + var_name +
                "' appears multiple times "
                "in input_types.");
            return false;
          }
          party_index = party;
          input_index = i;
        }
      }
    }
    if (input_index >= 0) {
      const DataType output_type =
          (*input_types)[party_index][input_index].second;
      if (!ConstructIdentityCircuit(
              party_index, input_index, output_type, output)) {
        LOG_ERROR("Failed to ConstructIdentityCircuit");
        return false;
      }
      if ((int) output->input_types_[party_index].size() <= input_index) {
        LOG_ERROR("Failed to ConstructIdentityCircuit");
        return false;
      }
      // Update input_types_[party_index], which defaulted variable name to "Pk_N",
      // where k = party_index and N = input_index.
      output->input_types_[party_index][input_index] =
          make_pair(var_name, output_type);
      // Update output type and formulas, which will have assumed BOOL.
      output->num_outputs_ = 1;
      output->output_designations_.clear();
      output->output_designations_.resize(
          1, make_pair(OutputRecipient(), output_type));
      output->function_description_.clear();
      output->function_description_.resize(1);
      Formula& formula = output->function_description_[0];
      formula.op_.type_ = OperationType::BOOLEAN;
      formula.op_.gate_op_ = BooleanOperation::IDENTITY;
      formula.value_ = GenericValue(var_name);
      return true;
    } else if (demand_var_name_match) {
      LOG_ERROR(
          "Unable to find variable '" + var_name + "' in both input_types");
      return false;
    } else {
      // Unable to find this variable name in input_types.
      // Since demand_var_name_match is false,
      // go ahead and add it to the appropriate set of inputs:
      // If variable has format "Pk_...", treat it as a Party k input,
      // otherwise treat it as an input from Party 0.
      const size_t div_pos = var_name.find("_");
      int party_index = 0;
      if (HasPrefixString(var_name, "P") && div_pos != string::npos &&
          div_pos > 0) {
        if (!Stoi(var_name.substr(1, div_pos - 1), &party_index) ||
            party_index != 1) {
          party_index = 0;
        }
      }
      uint64_t input_index;
      if ((int) input_types->size() <= party_index) {
        input_types->resize(1 + party_index);
      }
      input_index = (*input_types)[party_index].size();
      (*input_types)[party_index].push_back(
          make_pair(var_name, kDefaultDataType));
      const DataType output_type = kDefaultDataType;
      if (!ConstructIdentityCircuit(
              party_index, input_index, kDefaultDataType, output)) {
        LOG_ERROR("Failed to ConstructIdentityCircuit");
        return false;
      }
      if ((int) output->input_types_.size() <= party_index) {
        output->input_types_.resize(party_index + 1);
      }
      if (output->input_types_[party_index].size() <= input_index) {
        LOG_ERROR("Failed to ConstructIdentityCircuit");
        return false;
      }
      // Update input_types_[party_index], which defaulted variable name to "Pi_N",
      // where "N" is one_input_index.
      output->input_types_[party_index][input_index] =
          make_pair(var_name, output_type);

      // Update output type and formulas, which will have assumed BOOL.
      output->num_outputs_ = 1;
      output->output_designations_.clear();
      output->output_designations_.resize(
          1, make_pair(OutputRecipient(), output_type));
      output->function_description_.clear();
      output->function_description_.resize(1);
      Formula& formula = output->function_description_[0];
      formula.op_.type_ = OperationType::BOOLEAN;
      formula.op_.gate_op_ = BooleanOperation::IDENTITY;
      formula.value_ = GenericValue(var_name);
      return true;
    }
  } else if (IsIntegerDataType(value)) {
    const string value_str = GetGenericValueString(value);
    const int num_bits = (int) GetValueNumBits(value);
    if (HasPrefixString(value_str, "-")) {
      int64_t int_value;
      if (!Stoi(value_str, &int_value)) {
        LOG_ERROR("Unable to parse '" + value_str + "' as an integer");
        return false;
      }
      return ConstructConstantCircuit(int_value, num_bits, output);
    } else {
      uint64_t int_value;
      if (!Stoi(value_str, &int_value)) {
        LOG_ERROR("Unable to parse '" + value_str + "' as an integer");
        return false;
      }
      return ConstructConstantCircuit(int_value, num_bits, output);
    }
  } else {
    LOG_ERROR("Unsupported DataType: " + Itoa(static_cast<int>(value.type_)));
    return false;
  }
}

// Constructs a circuit for the provided Formula.
// If 'demand_var_name_match' is true, then all encountered variables
// must reside in input_types. Otherwise, when a variable is encountered,
// it will search through input_types for the variable name, and
// if it doesn't find it, it will append the new variable name to
// input_types_[k], where k = 0 unless the variable name starts with 'Pk_',
// in which case 'k' is parsed as the integer between 'P' and '_'.
bool CircuitFromFormula(
    const bool print_debug,
    const bool demand_var_name_match,
    const Formula& output_formula,
    vector<vector<pair<string, DataType>>>* input_types,
    StandardCircuit<bool>* output) {
  // Discussion: This function is made much more complicated due to the desire
  // to avoid recurssion (for suitably complex formulas, the program execution
  // stack runs out of memory). Instead, we create a call stack that is manually
  // maintained, with each iteration of a while-loop iterating through the stack.
  // In particular, the loop below will cycle through 'stack', one element at a
  // time, until it is exhausted. The 'stack' starts off with one element, and
  // each time through the loop, it's size will either change by -1, 0, 1, or 2;
  // more precisely, exactly one element will be consumed from the stack, but
  // then 0, 1, 2, or 3 more elements will get added, depending on the current
  // operation being run.
  // Each element in the 'stack' falls under one of three categories:
  //   1) At least one subcircuit needs to be constructed
  //   2) The formula is simply a variable (or constant), and hence a circuit
  //      can be constructed directly.
  //   3) Subcircuit(s) have already been constructed (and exist
  //      in 'subcircuit_stack'), and we now combine it/them with the
  //      appropriate Boolean/Comparision/Arithmetic operation.
  // Begin by placing the input formula into the call stack.
  vector<pair<const Formula*, OperationHolder>> stack;
  stack.push_back(make_pair(&output_formula, OperationHolder()));
  vector<StandardCircuit<bool>*> subcircuit_stack;

  uint64_t stack_itr = 0;
  uint64_t num_formula_terms = 0;
  uint64_t num_subterms_parsed = 0;
  if (print_debug) {
    num_formula_terms = CountAllFormulaTerms(output_formula);
  }
  while (!stack.empty()) {
    ++stack_itr;
    if (print_debug &&
        ((stack_itr < 100000 && stack_itr % 1000 == 1) ||
         (stack_itr < 1000000 && stack_itr % 10000 == 1) ||
         (stack_itr < 10000000 && stack_itr % 100000 == 1) ||
         stack_itr % 1000000 == 1)) {
      TLOG_INFO(
          "At iteration " + Itoa(stack_itr) +
          " of parsing circuit formula. "
          "Parsed " +
          Itoa(num_subterms_parsed) + " of " + Itoa(num_formula_terms) +
          " formula terms. Recursion stack size: " + Itoa(stack.size()) +
          ", num subcircuits built: " + Itoa(subcircuit_stack.size()));
    }

    // Grab the current instruction from the call 'stack'.
    const Formula* current_formula = stack.back().first;
    const OperationHolder current_op = stack.back().second;
    stack.pop_back();

    // Categories (1) and (2) are identified by stack.first != null.
    if (current_formula != nullptr) {
      const OperationHolder& op = current_formula->op_;

      // Check if this is Category (2) (formula is a variable or constant).
      if (op.type_ == OperationType::BOOLEAN &&
          op.gate_op_ == BooleanOperation::IDENTITY) {
        // Read the value_ field, and construct the appropriate circuit.
        subcircuit_stack.push_back(new StandardCircuit<bool>());
        if (!CircuitFromIdentityFormula(
                demand_var_name_match,
                current_formula->value_,
                input_types,
                subcircuit_stack.back())) {
          LOG_ERROR(
              "Failed to create Identity circuit (" + Itoa(stack_itr) + ").");
          return false;
        }
        ++num_subterms_parsed;
        continue;
      }

      // That we reached here means we are in Category (1), so constructing
      // this circuit cannot be done directly; i.e. at least one subcircuit
      // must first be built. Add more instructions to the call 'stack',
      // indicating the subcircuits to build, and how to combine them.
      if (IsSingleInputOperation(op)) {
        if (current_formula->subterm_one_ == nullptr ||
            current_formula->subterm_two_ != nullptr) {
          LOG_ERROR(
              "Single-Argument Operation " + GetOpString(current_formula->op_) +
              " should have first subterm set.");
          return false;
        }
        stack.push_back(make_pair(nullptr, op));
        stack.push_back(
            make_pair(current_formula->subterm_one_.get(), OperationHolder()));
      } else {
        if (current_formula->subterm_one_ == nullptr ||
            current_formula->subterm_two_ == nullptr) {
          LOG_ERROR(
              "Double-Argument Operation " + GetOpString(current_formula->op_) +
              " should have subterms set.");
          return false;
        }
        stack.push_back(make_pair(nullptr, op));
        // Process the "left" sub-formula first; so push the "right" subformula
        // onto the stack first, followed by the left.
        stack.push_back(
            make_pair(current_formula->subterm_two_.get(), OperationHolder()));
        stack.push_back(
            make_pair(current_formula->subterm_one_.get(), OperationHolder()));
      }
      continue;
    }

    // That we reached here means we're in Category (3): Subcircuits exist, and
    // need to be merged.
    if (current_op.type_ == OperationType::BOOLEAN &&
        current_op.gate_op_ == BooleanOperation::IDENTITY) {
      LOG_FATAL("This should never happen.");
    } else if (IsSingleInputOperation(current_op)) {
      if (subcircuit_stack.empty()) LOG_FATAL("This should never happen");
      StandardCircuit<bool>* left_circuit = subcircuit_stack.back();
      StandardCircuit<bool>* out = new StandardCircuit<bool>();
      if (current_op.type_ == OperationType::BOOLEAN &&
          current_op.gate_op_ == BooleanOperation::NOT) {
        ConstructNotCircuit(*left_circuit, out);
      } else {
        if (left_circuit->output_designations_.size() != 1) {
          LOG_ERROR(
              "Unexpected number of outputs: " +
              Itoa(left_circuit->output_designations_.size()));
          return false;
        }
        const DataType type = left_circuit->output_designations_[0].second;
        const bool left_is_twos_complement = IsDataTypeTwosComplement(type);
        if (!MergeCircuits(
                true,
                current_op.arithmetic_op_,
                left_is_twos_complement,
                false /* Ignored */,
                *left_circuit,
                StandardCircuit<bool>() /* Ignored */,
                out)) {
          delete left_circuit;
          delete out;
          LOG_ERROR("Failed to Merge circuits (" + Itoa(stack_itr) + ").");
          return false;
        }
      }
      ReduceCircuit(false, out);
      delete left_circuit;
      subcircuit_stack.back() = out;
      ++num_subterms_parsed;
    } else {
      // Grab the two already built subcircuits. Since we processed the 'left'
      // subformula first and the 'right' subformula second, and since these
      // were added to the stack in that order, it is the 'right' formula
      // that will get 'popped' first.
      if (subcircuit_stack.size() < 2) LOG_FATAL("This should never happen");
      StandardCircuit<bool>* right_circuit = subcircuit_stack.back();
      subcircuit_stack.pop_back();
      StandardCircuit<bool>* left_circuit = subcircuit_stack.back();
      StandardCircuit<bool>* out = new StandardCircuit<bool>();

      // Special logic for the vector-valued op's, which require special handling:
      //   ARGMIN, ARGMAX, ARGMIN_INTERNAL, ARGMAX_INTERNAL, VEC, INNER_PRODUCT.
      if (current_op.type_ == OperationType::ARITHMETIC &&
          (current_op.arithmetic_op_ == ArithmeticOperation::ARGMIN ||
           current_op.arithmetic_op_ == ArithmeticOperation::ARGMIN_INTERNAL ||
           current_op.arithmetic_op_ == ArithmeticOperation::ARGMAX ||
           current_op.arithmetic_op_ == ArithmeticOperation::ARGMAX_INTERNAL)) {
        if (!MergeArgminCircuits(
                current_op.arithmetic_op_, *left_circuit, *right_circuit, out)) {
          LOG_ERROR("Failed to Merge circuits (" + Itoa(stack_itr) + ").");
          delete left_circuit;
          delete right_circuit;
          delete out;
          return false;
        }
      } else if (
          current_op.type_ == OperationType::ARITHMETIC &&
          current_op.arithmetic_op_ == ArithmeticOperation::VEC) {
        if (!MergeVectorsCircuit(*left_circuit, *right_circuit, out)) {
          LOG_ERROR("Failed to Merge circuits (" + Itoa(stack_itr) + ").");
          delete left_circuit;
          delete right_circuit;
          delete out;
          return false;
        }
      } else if (
          current_op.type_ == OperationType::ARITHMETIC &&
          current_op.arithmetic_op_ == ArithmeticOperation::INNER_PRODUCT) {
        if (!MergeViaInnerProductCircuit(*left_circuit, *right_circuit, out)) {
          LOG_ERROR("Failed to Merge circuits (" + Itoa(stack_itr) + ").");
          delete left_circuit;
          delete right_circuit;
          delete out;
          return false;
        }
      } else {
        // Sanity-check the subcircuits can be combined.
        if (left_circuit->output_designations_.size() != 1 ||
            right_circuit->output_designations_.size() != 1) {
          LOG_ERROR(
              "Unexpected number of outputs: " +
              Itoa(left_circuit->output_designations_.size()) + ", " +
              Itoa(right_circuit->output_designations_.size()));
          delete left_circuit;
          delete right_circuit;
          delete out;
          return false;
        }

        // Special logic for The POWER circuit: The number of bits in the
        // exponent is limited to 6 (since 2^6 = 64, and 64 is the largest
        // exponent we allow). If the exponent DataType has 8 or more bits,
        // we just look at the trailing 6 bits. In particular, update the
        // (identity?) circuit for the expononent, limiting the number of
        // output bits (wires) to 6.
        if (current_op.type_ == OperationType::ARITHMETIC &&
            current_op.arithmetic_op_ == ArithmeticOperation::POW &&
            GetValueNumBits(right_circuit->output_designations_[0].second) >=
                8) {
          ModifyPowerCircuit(right_circuit);
        }

        // Grab the data-types of the subcircuits.
        const DataType left_type = left_circuit->output_designations_[0].second;
        const DataType right_type =
            right_circuit->output_designations_[0].second;

        // For Boolean Comparision, the left and right DataTypes may not be a
        // BOOL, since BooleanOperations can be applied to non-BOOL inputs.
        // Instead, we just check that the DataTypes of left and right match.
        if (current_op.type_ == OperationType::BOOLEAN &&
            left_type != right_type) {
          LOG_ERROR(
              "Unexpected (non-boolean) DataType for at least one "
              "subcircuit being merged via " +
              GetOpString(current_op) + ": (" + GetDataTypeString(left_type) +
              ", " + GetDataTypeString(right_type) + ")");
          delete left_circuit;
          delete right_circuit;
          delete out;
          return false;
        }

        // Merging the circuits will depend on if they are 2's complement.
        const bool left_is_twos_complement = IsDataTypeTwosComplement(left_type);
        const bool right_is_twos_complement =
            IsDataTypeTwosComplement(right_type);
        if (!MergeCircuits(
                true,
                current_op,
                left_is_twos_complement,
                right_is_twos_complement,
                *left_circuit,
                *right_circuit,
                out)) {
          delete left_circuit;
          delete right_circuit;
          delete out;
          LOG_ERROR("Failed to Merge circuits (" + Itoa(stack_itr) + ").");
          return false;
        }
      }

      ReduceCircuit(false, out);
      delete left_circuit;
      delete right_circuit;
      subcircuit_stack.back() = out;
      ++num_subterms_parsed;
    }
  }

  if (subcircuit_stack.size() != 1) {
    LOG_FATAL("This should never happen.");
  }

  *output = *(subcircuit_stack[0]);
  delete subcircuit_stack[0];
  return true;
}

bool CircuitFromFunction(
    const bool print_reductions,
    const vector<vector<pair<string, DataType>>>& input_types,
    const vector<pair<OutputRecipient, DataType>>& output_designations,
    const vector<Formula>& output_formulas,
    StandardCircuit<bool>* output) {
  const int num_outputs = (int) output_formulas.size();
  if (num_outputs == 0 ||
      (!output_designations.empty() &&
       num_outputs != (int) output_designations.size())) {
    LOG_ERROR("Bad input.");
    return false;
  }

  const bool expect_var_name_match = !input_types.empty();

  // Two temporary circuits to hold the merged circuits as we generate them
  // (one output at a time).
  StandardCircuit<bool> current_odd_merged_circuit;
  StandardCircuit<bool> current_even_merged_circuit;
  // Construct a circuit for each output.
  for (int i = 0; i < num_outputs; ++i) {
    if (print_reductions) {
      LOG_LINE();
      TLOG_INFO("Parsing output " + Itoa(i + 1) + " of " + Itoa(num_outputs));
    }
    vector<vector<pair<string, DataType>>> mutable_input_types = input_types;
    StandardCircuit<bool> circuit_i;
    if (!CircuitFromFormula(
            print_reductions,
            expect_var_name_match,
            output_formulas[i],
            &mutable_input_types,
            (num_outputs == 1 ?
                 output :
                 (i == 0 ? &current_odd_merged_circuit : &circuit_i)))) {
      LOG_ERROR(
          "Unable to construct a circuit for output " + Itoa(i + 1) +
          ", which has formula:\n" + GetFormulaString(output_formulas[i]));
      return false;
    }
    StandardCircuit<bool>& current_circuit = num_outputs == 1 ?
        *output :
        (i == 0 ? current_odd_merged_circuit : circuit_i);
    if (current_circuit.output_designations_.size() != 1) {
      LOG_ERROR(
          "Unexpected number of outputs: " +
          Itoa(current_circuit.output_designations_.size()));
      return false;
    }
    const DataType output_type = current_circuit.output_designations_[0].second;
    // Sanity-check output_types match.
    if (expect_var_name_match && !output_designations.empty()) {
      // Rewrite output recipient, which automatically gets assigned to 'A'
      // during building of basic circuits.
      current_circuit.output_designations_[0].first =
          output_designations[i].first;
      if (output_type != output_designations[i].second) {
        if (!IsDataTypeSubType(output_type, output_designations[i].second)) {
          LOG_ERROR(
              "Unexpected output type (" + GetDataTypeString(output_type) +
              " vs. expected " +
              GetDataTypeString(output_designations[i].second) +
              ") for output formula " + Itoa(i));
          return false;
        }
        current_circuit.output_designations_.clear();
        current_circuit.output_designations_.resize(1, output_designations[i]);
        if (!CastCircuitOutputAsMoreBits(
                IsDataTypeTwosComplement(output_designations[i].second),
                (int) GetValueNumBits(output_designations[i].second),
                &current_circuit)) {
          LOG_ERROR("Unable to modify output type.");
          return false;
        }
      }
    } else {
      // Overwrite function metadata, if we have reason to question the
      // output types (i.e. if input types weren't provided).
      if (!output_designations.empty()) {
        if (!IsDataTypeSubType(output_type, output_designations[i].second)) {
          LOG_ERROR(
              "Unexpected output type (" + GetDataTypeString(output_type) +
              " vs. expected " +
              GetDataTypeString(output_designations[i].second) +
              ") for output formula " + Itoa(i));
          return false;
        }
        current_circuit.output_designations_.clear();
        current_circuit.output_designations_.resize(1, output_designations[i]);
        if (!CastCircuitOutputAsMoreBits(
                IsDataTypeTwosComplement(output_designations[i].second),
                (int) GetValueNumBits(output_designations[i].second),
                &current_circuit)) {
          LOG_ERROR("Unable to modify output type.");
          return false;
        }
      } else {
        const int num_bits = (int) GetValueNumBits(output_type);
        if (current_circuit.num_output_wires_ != num_bits) {
          LOG_ERROR(
              "Wrong number of output wires (" +
              Itoa(current_circuit.num_output_wires_) + " found, " +
              Itoa(num_bits) + " expected)");
          return false;
        }
        const bool is_signed_type = IsDataTypeTwosComplement(output_type);
        DataType final_output_type;
        GetIntegerDataType(is_signed_type, (int) num_bits, &final_output_type);
        current_circuit.num_outputs_ = 1;
        current_circuit.output_designations_.clear();
        current_circuit.output_designations_.resize(
            1, make_pair(OutputRecipient(), final_output_type));
      }
    }
    // Overwrite Function formula (it may have gotten mangled/overly-complex
    // while constructing the circuit) if available.
    current_circuit.function_description_.clear();
    current_circuit.function_description_.resize(1, output_formulas[i]);
    if (print_reductions) {
      LOG_LINE();
      TLOG_INFO("Optimizing circuit for output " + Itoa(i + 1) + "...");
    }
    // Reduce circuit.
    ReduceCircuit(print_reductions, &current_circuit);

    // Merge this circuit with the circuits for the previous output(s).
    // NOTE: Prior code didn't merge circuits as the outputs were processed,
    // but it rather kept a separate circuit for each output, and then
    // merged them all at the end. However, that approach was *much* slower,
    // as calling ReduceCircuit() on a very large circuit takes much longer,
    // than calling ReduceCircuit() many times.
    if (i > 0) {
      // We toggle between using current_odd_merged_circuit and
      // current_even_merged_circuit; clear the one that is older.
      if (i != num_outputs - 1) {
        if (i % 2 == 0) current_odd_merged_circuit.Clear();
        else current_even_merged_circuit.Clear();
      }
      if (!MergeCircuitsInternal(
              !input_types.empty(),
              BooleanOperation::IDENTITY,
              ((i % 2 == 0) ? current_even_merged_circuit :
                              current_odd_merged_circuit),
              circuit_i,
              (i == num_outputs - 1 ?
                   output :
                   ((i % 2 == 0) ? &current_odd_merged_circuit :
                                   &current_even_merged_circuit)))) {
        LOG_ERROR("Failed to merge circuits at " + Itoa(i + 1));
        return false;
      }
      ReduceCircuit(
          print_reductions,
          (i == num_outputs - 1 ? output :
               (i % 2 == 0)     ? &current_odd_merged_circuit :
                                  &current_even_merged_circuit));
    }
  }

  // Overwrite inputs.
  if (expect_var_name_match) {
    if (output->input_types_.size() != input_types.size()) {
      if (output->input_types_.size() > input_types.size()) {
        LOG_ERROR(
            "Unexpected number of parties: " +
            Itoa(output->input_types_.size()));
        return false;
      }
      output->input_types_.resize(input_types.size());
    }
    for (size_t j = 0; j < output->input_types_.size(); ++j) {
      if (output->input_types_[j].size() != input_types[j].size()) {
        LOG_ERROR(
            "Unexpected number of inputs for party " + Itoa(j) + ": " +
            Itoa(output->input_types_[j].size()));
        return false;
      }
      for (size_t k = 0; k < output->input_types_[j].size(); ++k) {
        if (output->input_types_[j][k] != input_types[j][k]) {
          LOG_ERROR(
              "Unexpected number of input " + Itoa(k) + " for party " + Itoa(j) +
              ": (" + output->input_types_[j][k].first + ", " +
              Itoa(static_cast<int>(output->input_types_[j][k].second)) + ")");
          return false;
        }
      }
    }
  }

  return true;
}

bool CircuitFromFunction(
    const bool print_reductions,
    const string& function,
    StandardCircuit<bool>* output) {
  // Parse the function into a vector of Formulas (possible with output
  // desigination information).
  bool output_designation_present = false;
  vector<pair<OutputRecipient, DataType>> output_designations;
  vector<vector<string>> input_names;
  vector<Formula> output_formulas;
  if (!ParseFunctionString(
          function,
          &output_designation_present,
          &input_names,
          &output_formulas,
          &output_designations)) {
    LOG_ERROR("Unable to parse function string:\n" + function);
    return false;
  }

  // Add variable names with default DataType kDefaultDataType (INT64)
  // to expected input types.
  const int num_parties = (int) input_names.size();
  vector<vector<pair<string, DataType>>> input_types(num_parties);
  for (int party = 0; party < num_parties; ++party) {
    input_types[party].resize(input_names[party].size());
    int i = 0;
    for (const string& var_name : input_names[party]) {
      input_types[party][i] = make_pair(var_name, kDefaultDataType);
      ++i;
    }
  }

  return CircuitFromFunction(
      print_reductions,
      input_types,
      output_designations,
      output_formulas,
      output);
}

}  // namespace multiparty_computation
}  // namespace crypto
