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
// Description: Tools for converting between various circuit formats:
//   a) (PHB) StandardCircuit<slice>
//        In standard_circuit.h
//   b) (PHB) StandardCircuit<bool>
//        In standard_circuit.h
//   c) (PHB) CircuitByGate
//        In standard_circuit_by_gate.h
//   d) (Stealth) 'circuit':
//        From Original Targeting Demo for SRI, found in:
//        /Stealth/Brandeis/Enterprise_SRI/OriginalTargetingDemoFiles/
//        OTTEST/Miltest/Miltest/targeting.c
//   e) (Stealth) 'gate':
//        From SPAR code, models Yao's garbled circuit. Circuit is just
//        an array of 'gate' objects. Code in:
//        /Stealth/SPAR_cloud_storage/CodeBase/OldCode/yao.h
//   f) (Stealth) 'gate':
//        From durasift, look inside brett's repo under the "backend" directory,
//        inside the mpc.h file.
//
//
// NOTE 1: Currently implemented is only (b) -> (c).
//
// NOTE 2: For each, the anticipated code flow for the conversion is:
//   1) Load the circuit (file) in its original format via LoadCircuit()
//   2) Call ConvertCircuit() to put the circuit in the new object format
//   3) Call WriteCircuit() to print the circuit to file
//
// NOTE 3: Converting (a) <-> (d).
// StandardCircuit is a templated data structure with two formats
// (Format 1 has template type 'slice' and Format 2 has template type 'bool')
// based on the values assumed for the wires. Note that for Format 1, a wire
// representing a slice means that 64 (= num bits per slice) bits are being
// operated on in parallel (and independently from each other).
// Since the Stealth 'circuit' structure also assumes wire values are slices,
// there is a natural conversion between (a) and (d):
//   StandardCircuit<slice> <-> (Stealth) 'circuit'
//
// NOTE 4: Converting (b) <-> (d); primarily (b) <- (d).
// A question arises when translating back-and-forth between (Stealth) 'circuit' and
// StandardCircuit<bool> (or really the issue is going from (Stealth) 'circuit'
// to StandardCircuit<bool>): Should we "unpack" the (bit-sliced) inputs, so
// that the circuit effectively becomes 64x times larger (i.e. the 64x circuits
// that are evaluated in parallel by the slice format of a circuit would need
// to be separated into 64 separate circuits for the bit format)? Consider
// that when going the other way (StandardCircuit<bool> to (Stealth) 'circuit),
// the only thing that makes sense is to overload each slice and just set a single
// (e.g. the least significant) bit. Thus, if we want to preserve:
//   StandardCircuit<bool> -> Stealth 'circuit' -> StandardCircuit<bool>
// is the identity, then the 2nd arrow must take the interpretation that we just
// use a single (the least significant) bit of the slice, rather than blowing
// up the circuit by a factor of 64.
// There is no good answer here, and probably the answer is that you shouldn't
// mix-and-match; i.e. these circuit conversion tools should just be used to
// go between Stealth's 'circuit' and StandardCircuit<slice>. However, in case
// it is useful, we also provide conversion to/from StandardCircuit<bool>.
// As discussed above, there are alternate ways one could do this; the current
// implementation interprets this by treating a slice as a bool, i.e. just
// using the slice's least significant bit.
//
// NOTE 5: There is a lot of duplicate code here (especially with standard_circuit.h/cpp),
// to allow this file to be used as a standalone. For example, the
// StandardCircuit and StealthCircuit structs are both duplicated from elsewhere
// (indeed, you'll have conflicting definitions if you try to include e.g.
// standard_circuit.h in a build that also includes this file).

// NOTE 6: The 'circuit' struct has field elements that are pointers, and these
// pointers are stored on the heap. In particular, the LoadStealthCircuit()
// and ConvertCircuit() functions that populate a (Stealth) circuit will
// allocate memory on the heap, and the caller is responsible for cleaning up.

#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"  // For StandardCircuit.
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit_by_gate.h"  // For CircuitByGate.

#include <map>
#include <set>
#include <string>
#include <tuple>  // For std::tie.
#include <vector>

#ifndef CIRCUIT_CONVERTER_UTILS_H
#define CIRCUIT_CONVERTER_UTILS_H

namespace crypto {
namespace multiparty_computation {
namespace scratch {

// =========================== Structures for (d) ==============================
// The 'type' enum, which originally appears as a sub-enum of the 'circuit'
// struct; line 115 of targeting.c.
enum class sri_GateType {
  INPUT_WIRE,
  AND_GATE,
  XOR_GATE,
  OR_GATE,
  NAND_GATE,
  BIGB_GATE,
  NOR_GATE,
  EQ_GATE,
  // Additional Gate Types not in the original data structure:
  NOT_GATE,
  GT_GATE,
  GTE_GATE,
  LT_GATE,
  LTE_GATE
};

// The 'special' enum, which originally appears as a sub-enum of the 'circuit'
// struct; line 116 of targeting.c.
enum class SpecialGate { NONE, ALICE_INPUT, BOB_INPUT, OUTPUT };

// The 'gate' struct, which originally appears as a sub-struct of the 'circuit'
// struct; line 114 of targeting.c.
struct sri_gate {
  sri_GateType type;
  SpecialGate special;
  struct sri_gate* leftinput;
  struct sri_gate* rightinput;
  size_t inputindex;
  // Note: We skip the other three fields (actualinput, outputbit, set) in the
  // orginal 'gate' structure, since these are only needed for circuit
  // evaluation, and hence are not needed when converting between circuit types.
};

// The 'circuit' struct, on line 113 of targeting.c.
struct sri_circuit {
  struct sri_gate* gate;
  size_t ngates;
  size_t nlevels;
  size_t* levelsize;
  size_t nalice;
  size_t nbob;
  struct sri_gate** bobsinputs;
  size_t* bobsinputindices;
  size_t nout;
  struct sri_gate** outputs;
  size_t* outputindices;
};
// ========================= END Structures for (d) ============================

// =========================== Structures for (e) ==============================
enum class spar_gate_type {
  ZERO,
  AND,
  BIGA,
  AAA,
  BIGB,
  BBB,
  XOR,
  OR,
  NOR,
  EQ,
  NOTB,
  ALEQB,
  NOTA,
  BLEQA,
  NAND,
  ONE,
  INPUT,
  OUTPUT
};

// Notes/Restrictions:
// The 'spar_gate' object will encode the entire circuit by simply having an array
// of type 'spar_gate'. This array must satisfy:
//   1) (Global) Inputs must come first
//   2) A gate's parents (where left/right wires come from) must appear before the gate
//   3) (Global) output must come last
// For global inputs, field 'a' holds the input (bit) value, and 'b' is ignored
// For global output, 'a' is the gate number from within circuit to output and 'b'
// is the output bit number.
struct spar_gate {
  spar_gate_type type;
  size_t a;
  size_t b;
  bool tmp;
};
// ========================= END Structures for (e) ============================

// =========================== Structures for (f) ==============================
enum class durasift_GateType {
  ZERO,
  AND,
  BIGA,
  AAA,
  BIGB,
  BBB,
  XOR,
  OR,
  NOR,
  EQ,
  NOTB,
  ALEQB,
  NOTA,
  BLEQA,
  NAND,
  ONE,
  INPUT,
  OUTPUT
};

// Notes/Restrictions:
// The 'durasift_gate' object will encode the entire circuit by simply having an array
// of type 'durasift_gate'. This array must satisfy:
//   1) (Global) Inputs must come first
//   2) A gate's parents (where left/right wires come from) must appear before the gate
//   3) (Global) output must come last
// For global inputs, field 'a' holds the input (bit) value, and 'b' is ignored
// For global output, 'a' is the gate number from within circuit to output and 'b'
// is the output bit number.
struct durasift_gate {
  durasift_GateType type;
  size_t a;
  size_t b;
  // TODO(PHB): I can't find the original code for this structure, so I don't
  // know the type of 'mybool', hence it is commented out here.
  // mybool tmp;
};

// Comments:
// Now gates are defined level by level:
//   - ngates = total number of gates, na= total # of AND gates
//   - nlevel = number of levels
//   - ninput = number of inputs
//   - noutput = number of outputs
//   - level[i][j] = j'th gate on level i, gate.a and gate.b is is the "j" index
//     on level i-1, gates must be connected to level directly above them
//   - levelands[i] = # of AND gates on level i (currently I only support AND
//     and XOR gates, though eventually this will be all nonXOR nonEQ gates)
//   - levelgates[i] = # of gates on level i
struct durasift_circuit {
  struct durasift_gate* g;
  size_t ngates;
  size_t na;
  size_t nlevel;
  size_t ninput;
  size_t noutput;
  struct gate** level;
  size_t* levelands;
  size_t* levelgates;
};
// ========================= END Structures for (f) ============================

}  // namespace scratch

// =============== LoadCircuit, ConvertCircuit, and WriteCircuit ===============
// Note: API for the 'const' object paramaters are always pointers as opposed to
// const references: This is because for the 'Stealth' legacy circuits, the
// objects are arrays, and API's accept a pointer, so it is most natural to use
// a pointer API for those; and then for consistency (so that the calling code
// looks similar for all cases), we adopt the convention that the non-Stealth
// ('PHB') circuits are also const pointers.

// Status: Done.
extern bool LoadCircuit(
    const std::string& filename, StandardCircuit<math_utils::slice>* output);
// Status: Done.
extern bool LoadCircuit(
    const std::string& filename, StandardCircuit<bool>* output);
// Status: Done.
extern bool LoadCircuit(const std::string& filename, CircuitByGate* output);
// Status: Not supported.
extern bool LoadCircuit(
    const std::string& filename, scratch::sri_circuit* output);
// Status: Not supported.
extern bool LoadCircuit(const std::string& filename, scratch::spar_gate* output);
// Status: Not supported.
extern bool LoadCircuit(
    const std::string& filename, scratch::durasift_circuit* output);

// ConvertCircuit()
//   - (a) -> X. Status: Not supported.
extern bool ConvertCircuit(
    const StandardCircuit<math_utils::slice>* input,
    StandardCircuit<math_utils::slice>* output);
extern bool ConvertCircuit(
    const StandardCircuit<math_utils::slice>* input,
    StandardCircuit<bool>* output);
extern bool ConvertCircuit(
    const StandardCircuit<math_utils::slice>* input, CircuitByGate* output);
extern bool ConvertCircuit(
    const StandardCircuit<math_utils::slice>* input,
    scratch::sri_circuit* output);
extern bool ConvertCircuit(
    const StandardCircuit<math_utils::slice>* input, scratch::spar_gate* output);
extern bool ConvertCircuit(
    const StandardCircuit<math_utils::slice>* input,
    scratch::durasift_circuit* output);
//   - (b) -> X. Status: Supported only for (b) -> (c).
extern bool ConvertCircuit(
    const StandardCircuit<bool>* input,
    StandardCircuit<math_utils::slice>* output);
extern bool ConvertCircuit(
    const StandardCircuit<bool>* input, StandardCircuit<bool>* output);
extern bool ConvertCircuit(
    const StandardCircuit<bool>* input, CircuitByGate* output);
extern bool ConvertCircuit(
    const StandardCircuit<bool>* input, scratch::sri_circuit* output);
extern bool ConvertCircuit(
    const StandardCircuit<bool>* input, scratch::spar_gate* output);
extern bool ConvertCircuit(
    const StandardCircuit<bool>* input, scratch::durasift_circuit* output);
//   - (c) -> X. Status: Not supported.
extern bool ConvertCircuit(
    const CircuitByGate* input, StandardCircuit<math_utils::slice>* output);
extern bool ConvertCircuit(
    const CircuitByGate* input, StandardCircuit<bool>* output);
extern bool ConvertCircuit(const CircuitByGate* input, CircuitByGate* output);
extern bool ConvertCircuit(
    const CircuitByGate* input, scratch::sri_circuit* output);
extern bool ConvertCircuit(
    const CircuitByGate* input, scratch::spar_gate* output);
extern bool ConvertCircuit(
    const CircuitByGate* input, scratch::durasift_circuit* output);
//   - (d) -> X. Status: Not supported (untested template written for (d) -> (a)).
extern bool ConvertCircuit(
    const scratch::sri_circuit* input,
    StandardCircuit<math_utils::slice>* output);
extern bool ConvertCircuit(
    const scratch::sri_circuit* input, StandardCircuit<bool>* output);
extern bool ConvertCircuit(
    const scratch::sri_circuit* input, StandardCircuit<bool>* output);
extern bool ConvertCircuit(
    const scratch::sri_circuit* input, CircuitByGate* output);
extern bool ConvertCircuit(
    const scratch::sri_circuit* input, scratch::sri_circuit* output);
extern bool ConvertCircuit(
    const scratch::sri_circuit* input, scratch::spar_gate* output);
extern bool ConvertCircuit(
    const scratch::sri_circuit* input, scratch::durasift_circuit* output);
//   - (e) -> X. Status: Not supported.
extern bool ConvertCircuit(
    const scratch::spar_gate* input, StandardCircuit<math_utils::slice>* output);
extern bool ConvertCircuit(
    const scratch::spar_gate* input, StandardCircuit<bool>* output);
extern bool ConvertCircuit(
    const scratch::spar_gate* input, StandardCircuit<bool>* output);
extern bool ConvertCircuit(
    const scratch::spar_gate* input, CircuitByGate* output);
extern bool ConvertCircuit(
    const scratch::spar_gate* input, scratch::sri_circuit* output);
extern bool ConvertCircuit(
    const scratch::spar_gate* input, scratch::spar_gate* output);
extern bool ConvertCircuit(
    const scratch::spar_gate* input, scratch::durasift_circuit* output);
//   - (f) -> X. Status: Not supported.
extern bool ConvertCircuit(
    const scratch::durasift_circuit* input,
    StandardCircuit<math_utils::slice>* output);
extern bool ConvertCircuit(
    const scratch::durasift_circuit* input, StandardCircuit<bool>* output);
extern bool ConvertCircuit(
    const scratch::durasift_circuit* input, StandardCircuit<bool>* output);
extern bool ConvertCircuit(
    const scratch::durasift_circuit* input, CircuitByGate* output);
extern bool ConvertCircuit(
    const scratch::durasift_circuit* input, scratch::sri_circuit* output);
extern bool ConvertCircuit(
    const scratch::durasift_circuit* input, scratch::spar_gate* output);
extern bool ConvertCircuit(
    const scratch::durasift_circuit* input, scratch::durasift_circuit* output);

// Status: Done.
extern bool WriteCircuit(
    const std::string& filename,
    const StandardCircuit<math_utils::slice>* input);
// Status: Done.
extern bool WriteCircuit(
    const std::string& filename, const StandardCircuit<bool>* input);
// Status: Done.
extern bool WriteCircuit(
    const std::string& filename, const CircuitByGate* input);
// Status: Not supported.
extern bool WriteCircuit(
    const std::string& filename, const scratch::sri_circuit* input);
// Status: Not supported.
extern bool WriteCircuit(
    const std::string& filename, const scratch::spar_gate* input);
// Status: Not supported.
extern bool WriteCircuit(
    const std::string& filename, const scratch::durasift_circuit* input);
// =============== END LoadCircuit, ConvertCircuit, and WriteCircuit ===============

// The following sets the kForceDependsOnAll flag (see comments above that variable in
// circuit_converter_utils.cpp).
extern void SetDependsOnAll(const bool depends_on_all);

}  // namespace multiparty_computation
}  // namespace crypto
#endif
