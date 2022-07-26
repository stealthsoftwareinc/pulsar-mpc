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
//   Data structure and functions for evaluation of 'standard' (2-in-N-out) circuits.
//
// Discussion Points:
// 0) Regarding High-Level Design:
//    There are currently two approaches to circuit evaluation:
//      A) Per-Level Evaluation ("Breadth-First", or "Flat"):
//         The circuit is grouped into distinct *levels* with gates put into the
//         lowest-depth level possible. Implications:
//           - Evaluation is done level-by-level. So there is a single back-and-
//             forth communication for every level: Client sends Server masked
//             values for all gates on the level, Server evaluates all gates,
//             and returns all obfuscated truth tables.
//           - Number of "rounds" of communication is minimized (number of levels),
//             and each individual communication is large. Thus, good for scenarios
//             where the cost of reestablishing connection/hand-shake is high, but
//             bad for high-latency scenarios, where parties are dormant while
//             waiting for each (large) communication.
//      B) Per-Gate Evaluation ("Depth-First", or "Deep"):
//         The circuit is viewed as a single chain, with all gates having a linear
//         indexing (gate0, gate1, ...). When a gate is to be evaluated, it is
//         guaranteed that the inputs are available (either from a lower-index
//         gate evaluation, or as global inputs from one of the parties). Implications:
//           - Evaluation is done gate-by-gate. Queues (FIFO) are maintained
//             and processed as soon as they are ready.
//           - Number of "rounds" of communication is maximized (number of gates).
//             Thus, bad for scenarios where cost of reestablish connection is
//             high; but may be good for high-latency scenarios, where work
//             can be done simultaneously while waiting for communication transfer.
//     This file implements (A), standard_circuit_by_gate.h implements (B).
// 1) Regarding Circuit Format:
//    There are currently two circuit formats that are supported:
//      Format 1: Each wire represents sizeof(slice) independent values (bits),
//                and each (boolean) gate evaluates those values in-parallel
//                (and independently from the other bits on the same wire)
//      Format 2: Each wire represents a single bit
//    The idea of Format 1 is that we can leverage the processor's ability to
//    handle sizeof(slice) bits in parallel, and thus evaluating a gate on
//    sizeof(slice) bits takes the same amount of time/processing as evaluating
//    a gate on a single bit. The problem with this format is that it basically
//    requires that a circuit treats (up to) sizeof(slice) inputs separately,
//    and does an identical computation on them. In other words, this is an
//    optimization if we want to evaluate multiple sets of inputs on the same
//    circuit; but it does NOT help if we want to evaluate a set of inputs on
//    a single circuit; i.e. the final computation is a function of all the
//    inputs. So if you want to do the same computation on multiple inputs
//    (e.g. evaluate {x1 < y1}, {x2 < y2}, ..., {xN < yN}), then using Format 1
//    will save you a factor of sizeof(slice) (probably 64x) in processing time.
//    Otherwise, use Format 2.
//    Note that Format 1 circuits are currently only supported for 32-bit
//    (unsigned) integers; i.e. all the functions that do the bit-slicing
//    (see e.g. PackSliceBits()) are built for 32-bit integers.
//
//    StandardCircuit is a templated-class, with the template type specifying
//    the Format (1 vs. 2) of the circuit. Specifically, Format 1 circuits
//    have template type ('value_t') == slice; Format 2 have type bool.
//    The format_ field explicitly specifies the Format type, though this
//    is implicitly set at construction based on the provided template type.
//
// 2) Regarding Circuit File Format:
//    Circuits are loaded into memory (i.e. the StandardCircuit object) via
//    LoadCircuit(), and StandardCircuit objects are written to file via
//    WriteCircuit(). Both of these functions support either Format 1 or 2.
//    Here is the strucutre of a circuit file (for both Format 1 and 2):
//      - Comment lines (prefixed with '#') are ignored
//      - Top set of lines is the "metadata". This (optionally) contains information
//        about the function that the circuit represents (i.e. a string representation
//        of it), the names and data types of each party's inputs, and the output
//        data types and designations (a.k.a. OutputRecipients).
//        Metadata lines are all 'comment lines', and so should start with '#'.
//      - File is organized into blocks within blocks:
//          - Outermost block is the circuit itself, optionally with details of depth, etc.
//          - Within the circuit blocks are blocks for each Level of the circuit
//          - Within each Level block are blocks for each gate on that level
//          - Within each Gate block are the details of that gate: location
//            of the left and right wires and the gate type, and whether it is
//            a global output gate
//      - A template of a circuit file is:
//        # Circuit Function:
//        #   f(x1, x2, ..., xn; y1, y2, ..., ym; ... ; z1, z2, ..., zl) = (
//        # (BOOL)[B]:   x1 > y1;
//        # (UINT64)[N]: x2 + y2;
//        # ...;
//        # (BOOL)[X]:   xn == ym
//        # )
//        #
//        # Party Inputs (0):
//        # x1:UINT32
//        # x2:BOOL
//        # ...
//        # xn:STRING
//        #
//        # Party Inputs (1):
//        # y1:BOOL
//        # ...
//        # ym:UINT8
//        # ...
//        #
//        # Party Inputs (N):
//        # ...
//        #
//        Circuit {
//          depth : D          # Optional (can be determined by number of Levels)
//          num_gates : |C|    # Optional (can be determined by number of Gates)
//          num_outputs : |O|  # Optional (can be deterined); typically, |O| = 1
//          Level 0 {
//            num_gates : |L|  # Optional (can be determined by number of Gates)
//            Gate 0 {
//              type : BOOLEAN_OPERATION  # One of the 10 BooleanOperations
//              # Left/Right Wire Info. Format is:
//              #    (L, i)
//              # which refers to the location (level and index) of the
//              # gate whose output wire corresponds to this input wire.
//              # In the special case that the input wire is from a *global* input:
//              #      FORMAT 1: ([-1 | -2 | -3], i)
//              #      FORMAT 2: ([Pk | c], i, j)
//              #   The 1st coordinate ({-1, -2, -3} for FORMAT 1 and {Pk, c}
//              #   for FORMAT 2) specifies which Party will be providing the input:
//              #      FORMAT 1: -1 refers to constant input, -2 is input from P1, -3 from P2
//              #      FORMAT 2: 'c' refers to constant input, Pk is input from Party k.
//              #   The 2nd coordinate 'i' denotes which input (index) of that Party
//              #   to use; i.e. it is the (0-based) index i of that Party;
//              #   (In the special case of a constant input, we overload 'i' to
//              #   represent the value of the constant, which should either be a
//              #   slice value for Format 1 circuits, or a bit (0 or 1) for Format 2).
//              #   The 3rd coordinate 'j' is for FORMAT 2 only, and also only if the
//              #   1st coordinate was *not* 'c'. It represents which bit of the
//              #   i^th input to use; where we adopt the convention:
//              #     ALL SIGNED INPUTS ARE REPRESENTED IN 2's COMPLEMENT; ALL OTHER
//              #     DATATYPES ARE REPRESENTED AS A BINARY STRING,
//              #     AND THEN BIT 'j' REPRESENTS BIT 2^j; E.G. j = 0
//              #     REFERS TO THE LEAST-SIGNIFICANT (RIGHT-MOST) BIT
//              #   (Note that the assumption that all inputs are in binary string
//              #    or 2's complement format removes endianness issues, since these
//              #    are automatically in big-endian format).
//              left_wire  : (L, i, [j]) # Optional when left_wire is a global input
//              right_wire : (L, i, [j]) # Optional when BooleanOperation is 'NOT',
//                                       # or when right_wire is a global input
//              output_gate : i      # Mandatory for global output gates; its
//                                   # presence indicates this is an output gate
//                                   # "i" indicates the output *bit* (wire) index:
//                                   # Since this is boolean circuit, all output
//                                   # wires are bits; later, a process will convert/
//                                   # map the output bit/wire index to form the
//                                   # actual output value(s).
//            }
//            Gate 1 {
//              ...
//            }
//            ...
//          }
//          Level 1 {
//            Gate 0 {
//              ...
//            }
//            Gate 1 {
//              ...
//            }
//            ...
//          }
//          ...
//          Level L {
//            Gate 0 {
//              ...
//            }
//            Gate 1 {
//              ...
//            }
//            ...
//          }
//        }
//    One Final Comment Regarding Circuit File Format:
//    Notice that the above specified format is general enough to handle non-standard
//    (2-in, 1-out) circuits: they can represent (2-in, n-out) circuits, for arbitrary n.
//    However, LoadCircuit() will hiccup if you try to read in a file that
//    represents a non-standard circuit.
#ifndef STANDARD_CIRCUIT_H
#define STANDARD_CIRCUIT_H

#include "MathUtils/constants.h"  // For slice.
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "MathUtils/formula_utils.h"  // For Formula.
#include "MathUtils/number_conversion_utils.h"  // For PackSliceBits().
#include "TestUtils/timer_utils.h"  // For Timer.
#include "circuit_utils.h"  // For OutputRecipient.

#include <map>
#include <set>
#include <string>
#include <tuple>  // For std::tie, std::pair.
#include <vector>

namespace crypto {
namespace multiparty_computation {

// Labels a circuit as Format 1 or 2.
enum class CircuitFormat {
  UNKNOWN,
  FORMAT_ONE,
  FORMAT_TWO,
};

// Holds information identifying a gate's position within a circuit:
//    - Level (0 for gates at the base level (only input wires go into it);
//             D = depth for output gate(s))
//    - Gate Index: With respect to its level, a value 0 through |L|, where
//                  |L| is the number of gates on level L.
struct GateLocation {
  int64_t level_;
  int64_t index_;

  GateLocation() {
    level_ = -1;
    index_ = -1;
  }

  GateLocation(const int64_t& level, const int64_t& index) {
    level_ = level;
    index_ = index;
  }

  // So that GateLocation can be the Key of a set/map.
  bool operator<(const GateLocation& x) const {
    return std::tie(level_, index_) < std::tie(x.level_, x.index_);
  }

  bool operator==(const GateLocation& x) const {
    return level_ == x.level_ && index_ == x.index_;
  }

  // Prints wire location in format: (level_, index).
  std::string Print() const;
};

// Holds information identifying a wire's position within a circuit:
//    - GateLocation: Specifies the location of the gate at the *OUTPUT* end
//                    of the wire
//    - Left/Right: Whether the wire is the left or right input wire of the
//                  gate (at the *OUTPUT* end of the wire)
struct WireLocation {
  GateLocation loc_;
  bool is_left_;

  WireLocation() : loc_() {}

  WireLocation(const int64_t& level, const int64_t& index, const bool is_left) :
      loc_(level, index) {
    is_left_ = is_left;
  }

  // Sometimes a wire's left/right location is not needed (e.g. for output wires).
  WireLocation(const int64_t& level, const int64_t& index) : loc_(level, index) {
    is_left_ = false;
  }

  // So that WireLocation can be the Key of a set/map.
  bool operator<(const WireLocation& x) const {
    return std::tie(loc_, is_left_) < std::tie(x.loc_, x.is_left_);
  }

  bool operator==(const WireLocation& x) const {
    return loc_ == x.loc_ && is_left_ == x.is_left_;
  }

  // Prints wire location in format: (is_left_, level_, index).
  std::string Print() const;
};

template<typename value_t>
struct StandardGate {
  // It may not be necessary to store the GateLocation explicitly in loc_ below:
  // when the StandardGate is an entry in StandardCircuitLevel.gates_, we have
  // the circuit level (from StandardCircuitLevel.level_ and/or from within
  // the context of where that StandardCircuitLevel came from, which has the level),
  // and the gate index within that level is simply this StandardGate's index
  // within gates_.
  GateLocation loc_;
  math_utils::BooleanOperation type_;
  value_t left_input_;
  bool left_input_set_;
  value_t right_input_;
  bool right_input_set_;

  // The following field can be used to avoid GMW-evaluation amongst all players:
  // if the input wires are independent of some player(s)' inputs.
  // The set includes all the indices of all players on which (at least) one input
  // wire depends.
  // NOTE: This field is only relevant for GMW circuit evaluation, but we include
  // it as part of StandardGate becuase GMW uses StandardGate (via the
  // StandardCircuit 'circuit_' field).
  std::set<int> depends_on_;

  value_t output_value_;
  std::set<WireLocation> output_wire_locations_;

  // The following fields are only used for GMW circuit evaluation.
  // COMMENT: It would be more natural to have a separate structure (struct)
  // for a "GmwStandardGate", which has all of the StandardGate fields, plus
  // the extra ones below. Then there would be two ways to do this:
  //   1) Have the 'GmwStandardGate' be independent from StandardGate, and
  //      just duplicate code everywhere
  //   2) Have GmwStandardGate be an inherited class of StandardGate, and
  //      just add the extra fields in the inherited class
  //   3) Have a single class (struct) that has all the fields needed for
  //      StandardGate, as well as the extra fields needed for GmwStandardGate.
  // Option (2) is certainly the better design, but it doesn't play nice with
  // the fact that StandardGate is stored in a vector<> in a field of
  // StandardCircuit: vectors of inherited classes don't work (see "Object Slicing"),
  // as only the fields of the base class get stored. There is a way around
  // this: namely, can store a vector of *pointers* to the objects, and then
  // dynmaically cast those pointers to the appropriate class. But this
  // approach isn't ideal either, as having a vector of pointers is messier
  // than just a vector of objects (of course using smart pointers would be
  // the way to go, but still a little bit of a pain).
  // Originally I did (1), apprehensive of modifying code to deal with vector
  // of pointers. Currently (hence the fields below), I do (3).
  std::pair<std::pair<value_t, value_t>, std::pair<value_t, value_t>> mask_;
  bool mask_set_;

  StandardGate() : loc_(), mask_() {
    type_ = math_utils::BooleanOperation::UNKNOWN;
    left_input_set_ = false;
    right_input_set_ = false;
    left_input_ = 0;
    right_input_ = 0;
    output_value_ = 0;

    mask_set_ = false;
  }

  StandardGate(const int64_t& level, const int64_t& index) :
      loc_(level, index),
      mask_() {
    type_ = math_utils::BooleanOperation::UNKNOWN;
    left_input_set_ = false;
    right_input_set_ = false;
    left_input_ = 0;
    right_input_ = 0;
    output_value_ = 0;

    mask_set_ = false;
  }

  void CopyFrom(const StandardGate& other);

  // Returns whether this gate can be computed locally (by one of the parties).
  bool IsLocalGate() const;

  // *** For 2-Party GMW circuit evaluation only ***
  // Returns whether this gate is locally computable.
  bool IsLocallyComputable() const;
};

// Holds all the gates and wires for a given "level" (a.k.a. depth) of a circuit
template<typename value_t>
struct StandardCircuitLevel {
  // It may not be necessary to store the level explicitly in level_ below:
  // e.g. when the StandardCircuitLevel is an entry of StandardCircuit.levels_,
  // the level is simply the StandardCircuitLevel's index within levels_.
  int64_t level_;

  // Total number of gates in this level.
  // May not be set (since gates_.size() equals num_gates_).
  int64_t num_gates_;

  std::vector<StandardGate<value_t>> gates_;

  StandardCircuitLevel() {
    level_ = -1;
    num_gates_ = 0;
  }

  StandardCircuitLevel(const int64_t& level) {
    level_ = level;
    num_gates_ = 0;
  }

  void CopyFrom(const StandardCircuitLevel& other);

  // Evaluates each gate in the StandardCircuitLevel based on the values on the
  // input wires to the gate and the gate type; populates the gate's
  // output_value_ with the result.
  bool EvaluateLevel();
};

// Represents a full (standard) circuit.
// NOTE TWO: Output gates are identified by those that have a WireLocation
// within their output_wire_locations_ field that has a negative value for
// that location's level_; and then the index of this output gate (w.r.t.
// outputs_as_[slice | generic_value]_) is given by the location's index_.
template<typename value_t>
struct StandardCircuit {
  // Whether this circuit is in Format 1 or Format 2 (see Discussion Points
  // (1) and (2) at top of this file).
  CircuitFormat format_;

  // Some of the fields below (function_description_ and input_types_)
  // are not necessary for circuit evaluation, and are just useful for debugging
  // and the process of creating/writing circuit files.
  // However, populating these fields (which happens during LoadCircuit(),
  // and in particular in the call to ReadCircuitFileMetadata()) can take
  // a long time, and so they should *not* be populated in production code.
  bool load_function_description_;
  bool load_all_metadata_;

  // Depth of the circuit (i.e. depth of the output gate(s)).
  // May not be set (since levels_.size() equals the depth_).
  int64_t depth_;

  // The following field stores the actual circuit.
  std::vector<StandardCircuitLevel<value_t>> levels_;

  // Total size (|C| = number of gates) of the circuit.
  // May not be set (since summing over levels_[i].gates_.size() equals size_).
  int64_t size_;

  // Counts how many *non-locally computable* gates there are.
  // NOTE: This is needed for GMW circuit evaluation, to determine how many OT bits
  // each party needs to generate. Here, a gate is 'locally computable' if:
  //   - Gate Op is: {ID, NOT, EQ, XOR}; OR
  //   - Input wires depend on (at most) one party.
  int64_t num_non_local_gates_;

  // A string representation of the function that this circuit computes, e.g.:
  //   f(x1, x2; y1, y2, y3) = (x1 + x2, x1 > y1, (x2 < y2) | (x2 == y2 + y3))
  // The size of the vector is the number of outputs of the circuit, and in
  // particular it should equal num_outputs_ (as well as match the size of
  // output_designations_ and outputs_as_[slice | generic_value]_).
  std::vector<math_utils::Formula> function_description_;

  // ============================= Output Info =================================
  // Number of (global) outputs for the circuit.
  // NOTE: For Format 2 circuits, the field below represents the total number of
  // circuit outputs, which might be different than the number of output wires:
  // The latter represents the number of total *bits* across all outputs.
  // So, e.g. a circuit that outputs one BOOL and one UINT64 value will have
  // num_outputs_ = 2, while the number of output wires is 65 (= 1 + 64).
  int64_t num_outputs_;

  // This will match the above field for Format 1 circuits, and for Format 2
  // circuits whose output DataType is BOOL for all outputs.
  int64_t num_output_wires_;

  // Designation of where the outputs go, and the DataType of each output.
  // Indexing is consistent with outputs_as_[slice | generic_value]_.
  std::vector<std::pair<OutputRecipient, math_utils::DataType>>
      output_designations_;

  // Holds the values on each of the output wires. This field will be populated
  // (after circuit evaluation) iff circuit is Format 2 (Format 1 circuit
  // outputs are stored directly in output_values_ below).
  // NOTE: This field (when populated, i.e. iff Format 2) will have size
  // equal to num_outputs_wires_. We use a vector<unsigned char> instead of a
  // vector<bool> since C++ doesn't like the latter; interpret each byte
  // as a bit by just looking at the last (least significant) bit of each byte.
  std::vector<unsigned char> outputs_as_bits_;
  // Holds the output values:
  //  - For Format 1 circuits, this is the same as the (slice) values on the wires
  //  - For Format 2 circuits, the bit values on the wires (as stored in
  //    'outputs_as_bits_') have been merged appropriately (viewing the wires as
  //    comprising the 2's Complement representation of the output value(s)).
  std::vector<math_utils::slice> outputs_as_slice_;
  std::vector<math_utils::GenericValue> outputs_as_generic_value_;

  // ============================= Input Info =================================
  // Specifies the Variable Name and DataType of each Party's inputs.
  // Outer-vector is indexed by party (i.e. has size equal to number of parties),
  // inner-vector is indexed by that party's variable indexing.
  // NOTE: DataType is always SLICE for Format 1 circuits (see DISCUSSION below).
  std::vector<std::vector<std::pair<std::string, math_utils::DataType>>>
      input_types_;

  // Maps inputs from each Party (or constant values) to the wires those
  // inputs should be applied to.
  // NOTE 1: Inputs from parties are stored in a container based on the
  //         Format (1 vs. 2) of the circuit:
  //           - FORMAT 1 inputs are stored in a vector<slice>, with the j^th entry
  //             of the i^th vector representing that Party i's j^th input.
  //           - FORMAT 2 inputs can be any arbitrary value (bits, numeric,
  //             string, etc.). For each party, they are stored in a nested
  //             vector, where the index in those vectors corresponds to the
  //             (input index, bit index) of that input, and where each entry of
  //             the inner vectors corresponds to all of the wire locations that
  //             this (input index, bit index) bit maps to.
  //           - Constant inputs (slice for Format 1, or '0' or '1' for Format 2)
  //             are mapped to the wires they apply to.
  // NOTE 2: These fields just provide input *mappings*, but they don't acutally
  //         place any values on the wires. Indeed, placing actual input
  //         values on the wires is done just before circuit evaluation, and
  //         is done via LoadInputsToCircuit(), which takes in each Party's input
  //         values and using the mappings below to load each (global input) gate's
  //         [left | right]_wire_value_.
  //
  // FORMAT 1 Input Mappings.
  // Outer-vector: Indexed by party
  // Inner-vector: Indexed as per Party i's inputs
  std::vector<std::vector<std::set<WireLocation>>> inputs_as_slice_locations_;
  std::map<math_utils::slice, std::set<WireLocation>> constant_slice_input_;
  // FORMAT 2 Input Mappings.
  // Outer-vector: Indexed by party
  // Middle-vector: Indexed as per Party i's inputs
  // Inner-vector: Indexed as bit corresponding to that Party's input.
  std::vector<std::vector<std::vector<std::set<WireLocation>>>>
      inputs_as_generic_value_locations_;
  std::set<WireLocation> constant_zero_input_;
  std::set<WireLocation> constant_one_input_;

  // =============================== Timers ====================================
  // NOTE: Many (all?) of these timers are only relevant/used for GMW use-cases,
  // e.g. StandardCircuit by itself has no notion of Client vs. Server.
  //
  // Timers (activated based on debug level 'timer_level_': A timer is
  // activated iff it's "level" is less than or equal to timer_level_).
  int timer_level_;

  // Level 0 timers.
  test_utils::Timer evaluate_circuit_overall_timer_;
  test_utils::Timer server_generate_ot_secrets_timer_;
  test_utils::Timer server_generate_ot_masks_timer_;
  test_utils::Timer client_generate_ot_selection_bits_timer_;
  test_utils::Timer load_ot_bits_timer_;
  test_utils::Timer ot_protocol_timer_;
  test_utils::Timer write_ot_bits_timer_;
  test_utils::Timer server_load_ot_bits_to_gate_masks_timer_;
  test_utils::Timer client_store_ot_bits_timer_;
  test_utils::Timer exchange_inputs_timer_;
  test_utils::Timer load_inputs_timer_;
  test_utils::Timer evaluate_circuit_only_timer_;
  test_utils::Timer exchange_outputs_timer_;
  test_utils::Timer write_outputs_timer_;
  test_utils::Timer initiate_connection_timer_;
  test_utils::Timer close_connection_timer_;

  // Level 1 timers.
  test_utils::Timer server_evaluate_level_timer_;
  test_utils::Timer server_awaiting_selection_bits_timer_;
  test_utils::Timer server_sending_server_mask_timer_;
  test_utils::Timer server_computing_gates_timer_;
  test_utils::Timer server_updating_output_wires_timer_;
  test_utils::Timer client_evaluate_level_timer_;
  test_utils::Timer client_preparing_selection_bits_timer_;
  test_utils::Timer client_sending_selection_bits_timer_;
  test_utils::Timer client_awaiting_server_mask_timer_;
  test_utils::Timer client_computing_gates_timer_;
  test_utils::Timer client_updating_output_wires_timer_;

  // ============================== Functions ==================================
  StandardCircuit() {
    if (sizeof(value_t) == sizeof(math_utils::slice)) {
      format_ = CircuitFormat::FORMAT_ONE;
    } else if (sizeof(value_t) == sizeof(math_utils::slice)) {
      format_ = CircuitFormat::FORMAT_TWO;
    } else {
      format_ = CircuitFormat::UNKNOWN;
    }
    load_function_description_ = false;
    load_all_metadata_ = true;
    // Initialize depth to -1, since a depth 0 circuit is possible (input gates
    // equal output gates).
    depth_ = -1;
    size_ = 0;
    num_non_local_gates_ = 0;
    num_outputs_ = 0;
    num_output_wires_ = 0;
    timer_level_ = -1;  // No timers activated.
  }

  // Effectively destroys the circuit: not only the values stored on the wires,
  // but the circuit layout as well (i.e. removes all gates and wires).
  // If you just want to clear the values on a circuit (e.g. in between
  // evaluations of different sets of inputs), use ClearCircuitValues().
  void Clear() {
    // Initialize depth to -1, since a depth 0 circuit is possible (input gates
    // equal output gates).
    depth_ = -1;
    size_ = 0;
    num_non_local_gates_ = 0;
    num_outputs_ = 0;
    num_output_wires_ = 0;
    levels_.clear();
    outputs_as_bits_.clear();
    outputs_as_slice_.clear();
    outputs_as_generic_value_.clear();
    function_description_.clear();
    output_designations_.clear();
    input_types_.clear();
    inputs_as_slice_locations_.clear();
    constant_slice_input_.clear();
    inputs_as_generic_value_locations_.clear();
    constant_zero_input_.clear();
    constant_one_input_.clear();
  }

  void CopyFrom(const StandardCircuit& other);

  // Loads the circuit represented in 'filename', populating StandardCircuit fields:
  //   depth_, size_, num_outputs_, num_output_wires_,
  //   levels_:
  //     gates_:
  //       loc_, type_, output_wire_locations_(loc_), depends_on_
  // Will also populate the following fields from the Metadata, if present:
  //   function_description_, output_designations_, input_types_,
  //   inputs_as_[slice | generic_value]_locations_
  // Notice the input/output wire *values* are NOT loaded (except for constant values).
  bool LoadCircuit(const std::string& filename);
  // Helper function for LoadCircuit: parses a line representing a (global) input wire.
  bool ParseInputWire(
      const bool is_left,
      const std::string& line,
      const int64_t& current_level,
      const int64_t& current_gate_index,
      int* max_party_index);

  // Prints the circuit to a circuit file (that can be loaded via LoadCircuit()).
  bool WriteCircuitFile(const std::string& filename) const;

  // Returns whether the input location is valid for the given circuit.
  bool IsValidGateLocation(const GateLocation& location) const;

  // Determines whether or not a given circuit is in Format 1 (vs. Format 2)
  // based on which of its input fields are populated. Crashes if all input
  // fields are empty, or if incompatible fields are populated (i.e. some of
  // each); otherwise returns whether the circuit is in format one.
  bool IsCircuitFormatOne() const;

  // Prints all timers_ above, if they have more than 0.001 seconds elapsed.
  std::string PrintTimers() const;

  // Prints inputs_as_[slice | generic_value]_locations_ (useful for debugging).
  std::string PrintInputMappings() const;

  // Clears all values on all wires (but leaves entact circuit mappings, i.e.
  // location of all gates and wires remains the same).
  void ClearCircuitValues();

  // Goes through output_designations_, and counts the number of bits in each
  // output value's DataType.
  uint64_t GetNumberOutputBits() const;

  // Converts (Format 2) output wires (which form the bits of a GenericValue)
  // to the output values they represent. This will populate the
  // outputs_as_generic_value_ field.
  bool ConvertOutputs();

  // Overwrites the passed-in location with the next gate location, which
  // is either the next gate index on the same level, or if the current
  // location is the last gate on a level, then it is the first gate on
  // the next level. Returns false if the input location is invalid or is
  // the last gate in the circuit; otherwise returns true.
  bool GetNextGateLocation(GateLocation* location) const;

  // Helper function for EvaluateCircuit: After evaluating all the gates at
  // a given level, this function copies the value in each
  // StandardGate.output_value_ to the appropriate wire (as indicated by that
  // gate's output_wire_locations_).
  bool SetInputsForNextLevel(const int64_t& prev_level_index);

  // Evaluates the input (standard) circuit based on the inputs, which have already
  // been loaded to the circuit->levels_[i].gates_[j].[left | right]_input_ fields.
  bool EvaluateCircuit();
};

// Returns a string representation of the function, e.g.:
//   f(x1, x2; y1, y2) = (x1 == y1; x2 < y2)
extern std::string PrintFunction(
    const bool print_comment_symbol,
    const std::vector<std::vector<std::string>>& input_var_names,
    const std::vector<std::pair<OutputRecipient, math_utils::DataType>>&
        output_types,
    const std::vector<math_utils::Formula>& function);
// Same as above, with API expecting 2-parties in function LHS.
extern std::string PrintFunction(
    const bool print_comment_symbol,
    const std::vector<std::vector<std::pair<std::string, math_utils::DataType>>>&
        input_types,
    const std::vector<std::pair<OutputRecipient, math_utils::DataType>>&
        output_types,
    const std::vector<math_utils::Formula>& function);

// Most gates are 2-in (1-out), although a couple (IDENTITY, NOT) are 1-in (1-out).
// This function checks that both wires have been set for the former gate types,
// or that exactly one input wire has been set for the latter types.
extern bool IsInputWiresSet(
    const bool is_left_wire_set,
    const bool is_right_wire_set,
    const math_utils::BooleanOperation type);

// Given a specification of the DataType of each output (in the provided
// circuit's output_designations_ field), maps the output wire to the
// appropriate (output index, output bit index).
extern bool GetOutputWireIndexToGenericValueIndex(
    const std::vector<std::pair<OutputRecipient, math_utils::DataType>>&
        output_types,
    std::vector<std::pair<uint64_t, uint64_t>>*
        output_wire_to_output_index_and_bit);

// Parses a function string, of format:
//   f(x1, ..., xn; y1, ..., ym) = (
//     (BOOL)[B]:  x1 < y1;
//     (BOOL)[B]:  x1 < y1;
//     ...;
//     (BOOL)[B]:  x1 < y1
//   )
// Populates function, and if the optional "(DataType)[OutputRecipient]:"
// prefixes appear on each output line, then sets output_designation_present
// to true and populates output_types.
// Parsing is whitespace-independent, so spaces, tabs, and line returns are
// ignored; and the punctuation is critical to identify partitioning of the
// string parts.
extern bool ParseFunctionString(
    const std::string& input,
    const std::vector<std::pair<std::string, std::string>>& common_terms,
    bool* output_designation_present,
    std::vector<std::vector<std::string>>* var_names,
    std::vector<math_utils::Formula>* function,
    std::vector<std::pair<OutputRecipient, math_utils::DataType>>* output_types);
// Same as above, with empty set for common terms.
inline bool ParseFunctionString(
    const std::string& input,
    bool* output_designation_present,
    std::vector<std::vector<std::string>>* var_names,
    std::vector<math_utils::Formula>* function,
    std::vector<std::pair<OutputRecipient, math_utils::DataType>>*
        output_types) {
  return ParseFunctionString(
      input,
      std::vector<std::pair<std::string, std::string>>(),
      output_designation_present,
      var_names,
      function,
      output_types);
}

// This function is very similar to ReadCircuitFileMetadata() below,
// but can support both: 1) Reading metadata block at the top of circuit files;
// and 2) Reading "function files" that are used by Tool 1 to generate a circuit.
// The main differences (which are controlled via the 'is_circuit_file' flag) are:
//   0) Doesn't demand presence of "#" (it will just strip this char, if present)
//   1) Has the additional option to parse one set of inputs from the input lines;
//   2) Reads (and expects) an output filename
//   3) (Optionally) reads/parses the "Common Terms" block
extern bool ReadFunctionFile(
    const bool is_circuit_file,
    const std::string& filename,
    std::string* output_circuit_filename,
    std::vector<math_utils::Formula>* function,
    std::vector<std::vector<math_utils::GenericValue>>* input_values,
    std::vector<std::vector<std::pair<std::string, math_utils::DataType>>>*
        input_var_types,
    std::vector<std::pair<OutputRecipient, math_utils::DataType>>* output_types);

// Reads the information at the top of a circuit file, and populates the
// provided parameters.
// NOTE: Parsing 'function' via the call to ParseFunctionString() can take
// a long time, especially for a very long function description (string).
// Passing in a nullptr for 'function' skips parsing, and hence avoids
// this cost (i.e. make sure Production code does this, since there is no
// need for 'function' to be populated in any production code).
// Similarly, parsing input_[one, two]_var_types takes a non-trivial amount
// of time if the number of inputs is very large, and this can be skipped
// (by passing in nullptr for these parameters) in production code, since
// these fields are not required.
inline bool ReadCircuitFileMetadata(
    const std::string& filename,
    std::vector<math_utils::Formula>* function,
    std::vector<std::vector<std::pair<std::string, math_utils::DataType>>>*
        input_types,
    std::vector<std::pair<OutputRecipient, math_utils::DataType>>*
        output_types) {
  return ReadFunctionFile(
      true, filename, nullptr, function, nullptr, input_types, output_types);
}

// API for FORMAT 1:
// (See DISCUSSION above inputs_as_[slice | generic_value]_locations_).
// For Circuits that take inputs from N parties. Takes the N parties' inputs
// and loads them on the appropriate input wires. In Particular, on input,
// circuit->inputs_as_slice_locations_ fields should be set (e.g. via
// a call to SetStandardNPartyInputAsSliceMapping(), or when LoadCircuit() was
// called on a circuit file that specified (FORMAT 1) values for input wires),
// which indicate where the i^th input of each Party should go.
// Then this function takes the actual inputs from each Party, and uses the
// circuit->inputs_as_slice_locations_ mappings to set the appropriate
// Gate's input wire.
extern bool LoadInputsToCircuit(
    const std::vector<std::vector<math_utils::slice>>& inputs,
    StandardCircuit<math_utils::slice>* circuit);
// API for FORMAT 2:
// (See DISCUSSION above inputs_as_[slice | generic_value]_locations_).
// For Circuits that take inputs from N parties. Takes the N parties' inputs
// and loads them on the appropriate input wires. In Particular, on input,
// circuit->inputs_as_generic_value_locations_ fields should be set
// (i.e. when LoadCircuit was called, the corresponding circuit file should
// have specified (FORMAT 2) values for input wires), which indicate where the
// i^th input of each Party should go.
// Then this function takes the actual inputs from each Party, and uses the
// circuit->inputs_as_generic_value_locations_ mappings to set the
// appropriate Gate's input wire.
extern bool LoadInputsToCircuit(
    const std::vector<std::vector<math_utils::GenericValue>>& input,
    StandardCircuit<bool>* circuit);

// Evaluates the input (standard) circuit based on the provided inputs,
// which are mapped to the (input) gates they should feed into;
// output(s) are stored in circuit->outputs_as_[slice | generic_value]_.
extern bool EvaluateCircuit(
    const std::map<WireLocation, math_utils::slice>& inputs,
    StandardCircuit<math_utils::slice>* circuit);
// Same as above, for bits (instead of bit-slices; to support FORMAT 2 inputs).
extern bool EvaluateCircuit(
    const std::map<WireLocation, bool>& inputs, StandardCircuit<bool>* circuit);
// Same as above, but with a different API to distinguish left/right input wires.
extern bool EvaluateCircuit(
    const std::map<GateLocation, math_utils::slice>& left_inputs,
    const std::map<GateLocation, math_utils::slice>& right_inputs,
    StandardCircuit<math_utils::slice>* circuit);
// Same as above, for bits (instead of bit-slices; to support FORMAT 2 inputs).
extern bool EvaluateCircuit(
    const std::map<GateLocation, bool>& left_inputs,
    const std::map<GateLocation, bool>& right_inputs,
    StandardCircuit<bool>* circuit);

// On Input, circuit->inputs_as_slice_locations_ should be set (e.g. via
// SetStandardInputAsSliceMapping()), which indicate where the i^th input should go.
// Then this function takes the actual inputs and uses the mappings in
// circuit->inputs_as_slice_locations_ to set the appropriate Gate's input wire.
// Then, it evaluates the circuit.
extern bool EvaluateCircuit(
    const std::vector<math_utils::slice>& inputs,
    StandardCircuit<math_utils::slice>* circuit);
// Same as above, for FORMAT 2 inputs.
extern bool EvaluateCircuit(
    const std::vector<math_utils::GenericValue>& inputs,
    StandardCircuit<bool>* circuit);
// Same as above, but for N Parties. In Particular, on input,
// circuit->inputs_as_slice_locations_ fields should be set (e.g. via
// SetStandardNPartyInputAsSliceMapping()), which indicate where the i^th input of
// each Party should go. Then this function takes the actual inputs
// from each Party, and uses the circuit->inputs_as_slice_locations_ mappings
// to set the appropriate Gate's input wire. Then, it evaluates the circuit.
extern bool EvaluateCircuit(
    const std::vector<std::vector<math_utils::slice>>& inputs,
    StandardCircuit<math_utils::slice>* circuit);
// Same as above, for FORMAT 2 inputs.
extern bool EvaluateCircuit(
    const std::vector<std::vector<math_utils::GenericValue>>& inputs,
    StandardCircuit<bool>* circuit);

// Evaluates the gate according to the values on the input wires and the gate
// type; populates the gate's output_value_ with the result.
extern bool EvaluateGate(StandardGate<bool>* gate);
extern bool EvaluateGate(StandardGate<math_utils::slice>* gate);

// For Format 1 Circuits that compare a set of numbers, use this function to pack the
// inputs into slices, so that the comparisons can be parallelized. This will
// pack up to (CHAR_BIT * sizeof(slice)) values into a vector of slices, where
// the vector has size L = M * (sizeof(inputs[i])), where we pack
// M = inputs.size() / (CHAR_BIT * sizeof(slice)) inputs into a single "block"
// of sizeof(slice) inputs, and do this for as many blocks as required. For
// example, for 32-bit numbers, if we wish to compare 64(*) or less such pairs,
// we can fit this into a single "block", where we pack 64-bits into a slice,
// and do this for each of the 32 bits of each input (so output vectors have
// size 32); where '64' comes from the assumption of a 64-bit processsor, i.e.
// '64' really should be (CHAR_BIT * sizeof(slice)).
// NOTE: Some of the circuits we use have reversed the significance of the
// bits (so that trailing bits are the *most* significant); set 'reverse_bits'
// to true when using such circuits.
template<typename input_value_t>
inline bool PackInputs(
    const bool reverse_bits,
    const std::vector<input_value_t>& left_inputs,
    const std::vector<input_value_t>& right_inputs,
    std::vector<math_utils::slice>* packed_left_inputs,
    std::vector<math_utils::slice>* packed_right_inputs) {
  if (left_inputs.size() != right_inputs.size()) return false;
  return (
      math_utils::PackSliceBits<input_value_t, math_utils::slice>(
          reverse_bits, left_inputs, packed_left_inputs) &&
      math_utils::PackSliceBits<input_value_t, math_utils::slice>(
          reverse_bits, left_inputs, packed_left_inputs));
}

}  // namespace multiparty_computation
}  // namespace crypto

#endif
