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
//   Defines the structures and functions that allow 2-party computation
//   via GMW circuits.
//
// DISCUSSION:
// 0) Regarding circuit Format type:
//    There is a lengthy discussion about the two types of StandardCircuits
//    in standard_circuit.h. Here, we'll just mention this fact, and emphasize
//    the two types specify whether the values on the wires are slices or bits
//    (this in-turn affects how gate computations are done, and in particular
//    the (number of) OT bits required.
//
// 1) Regarding how GMW is implemented here:
//    A) We reduce N-Party GMW to standard 2-Party GMW as follows:
//         i) All gates are `standard' gates: 2 (or 1, for NOT, IDENTITY) input wires.
//        ii) Each wire has a value, which is (additively) secret-shared among
//            all Parties.
//       iii) Each Party is given a 'Party Index', which is determined by the
//            function description (LHS): The party that provides the first
//            set of inputs on the function LHS is Party '0', and so on.
//            When two Parties communicate, we use the convention that the
//            Party with the lower index will act as the (GMW) 'Server'.
//            TODO(paul): The convention of who is Server vs. Client is:
//              PRO: Well-defined and easy to implement
//              CON: Not maximizing efficiency, since there will be an
//                   imbalance for majority of Parties in terms of how often
//                   they are Client/Server, which in turn may not be optimal
//                   (e.g. a Party that is always Client will sit idle while
//                   all of its Partners are busy computing gate values; and/
//                   or the communication will happen in bursts, where it
//                   hits times that it needs to Send (resp. Receive) values
//                   across all links at the same time.
//            Consider changing this convention to optimally balance the number
//            of times each Party is Server vs. Client (e.g. act as Server
//            for the n/2 parties with smaller index, act as Client for n/2
//            parties with larger index (with wrap-around).
//        iv) All Gates op's (of type CircuitOperation) can be handled by
//            2-Party computations on their respective shares. For example,
//            each CircuitOperation is described for the 3-party case below:
//            i.e. each wire's value is shared: a \oplus b \oplus c
//              Boolean:
//              NOTE: Interpret all operations as in Z_2, so addition (+) is XOR,
//                    and multiplication (concatenation) is AND.
//                 ID: Nothing to do
//                NOT: Computed locally: Party A does NOT, Parties B and C do ID
//                AND: Use: x AND y = xy (in Z_2). Thus:
//                     (a + b + c) AND (x + y + z) =
//                       ax + ay + az + bx + by + bz + cx + cy + cz
//                     With each term reducing to 2-Party computation
//                     In general, N-Party AND is:
//                       N-even: \sum(Pairwise AND)
//                       N-odd:  \sum(Local AND of each party's shares) + \sum(Pairwise AND)
//                     For example, for N=2, Party 0 holds {a, x} and Party 1 has {b, y}
//                     and they want to compute: (a + b) AND (x + y) = ax + ay + bx + by,
//                     which is what is meant by '\sum(Pairwise AND)' for N-even case above.
//                     But for N=3 (already specified above), when we do the 3-pairs
//                     of 'Pairwise AND', we'd have the following terms:
//                       - P0 AND P1: ax + ay + bx + by
//                       - P0 AND P2: ax + az + cx + cz
//                       - P1 AND P2: by + bz + cy + cz
//                     Thus, the 'sum' of these is: ay + az + bx + bz + cx + cy,
//                     as the 'local AND' terms (ax, by, cz) cancel. This is why we
//                     need the extra '\sum(Local AND of each party's shares)' term
//                     for the N-odd case.
//               NAND: Same as above (with a NOT in front of it all).
//                     In particular, select one party (e.g. Party 0) that
//                     adds 1 to its output.
//                 OR: Use: x OR y = x + y + xy (in Z_2). Thus:
//                     (a + b + c) OR (x + y + z) =
//                        a + b + c + x + y + z +
//                        ax + ay + az + bx + by + bz + cx + cy + cz
//                     The 2nd line is AND, and the 1st line can be computed locally.
//                     In general, N-Party OR is:
//                       N-even: \sum(Local sum of each party's shares) + \sum(Pairwise AND)
//                       N-odd:  \sum(Local AND of each party's shares) +
//                               \sum(Local sum of each party's shares) + \sum(Pairwise AND)
//                NOR: Same as above (with a NOT in front of it all)
//                     In particular, select one party (e.g. Party 0) that
//                     adds 1 to its output.
//                XOR: Computed locally
//                 EQ: Computed locally. Parties XOR their own wires, and one party
//                     (e.g. Party 0) adds 1 to its output.
//                 GT: Use x > y = x + xy (in Z_2). Thus:
//                     (a + b + c) OR (x + y + z) =
//                       a + b + c +
//                       ax + ay + az + bx + by + bz + cx + cy + cz
//                     The 2nd line is AND, and the 1st line can be computed locally.
//                     In general, N-Party GT is:
//                       N-even: \sum(Each party's left wire share) + \sum(Pairwise AND)
//                       N-odd:  \sum(Local AND of each party's shares) +
//                               \sum(Each party's left wire share) + \sum(Pairwise AND)
//                LTE: Same as above (with a NOT in front)
//                     In particular, select one party (e.g. Party 0) that
//                     adds 1 to its output.
//                 LT: Use x < y = y + xy (in Z_2). Thus:
//                     (a + b + c) OR (x + y + z) =
//                       x + y + z +
//                       ax + ay + az + bx + by + bz + cx + cy + cz
//                     The 2nd line is AND, and the 1st line can be computed locally.
//                     In general, N-Party LT is:
//                       N-even: \sum(Each party's right wire share) + \sum(Pairwise AND)
//                       N-odd:  \sum(Local AND of each party's shares) +
//                               \sum(Each party's right wire share) + \sum(Pairwise AND)
//                GTE: Same as above (with a NOT in front)
//                     In particular, select one party (e.g. Party 0) that
//                     adds 1 to its output.
//             Arithmetic:
//               ADD: Computed locally, since (a + b + c) + (x + y + z) =
//                                              (a + x) + (b + y) + (c + z)
//               SUB: Computed locally, since (a + b + c) - (x + y + z) =
//                                              (a - x) + (b - y) + (c - z)
//               MULT: Use Beaver triples (not currently supported).
//               No other ArithmeticOperations are currently supported
//               (i.e. any circuit requiring Factorial, Power, etc. will
//               implement these via the appropriate expansion of Boolean gates).
//
//    B) We utilize Beaver's offline trick, so that the cost of doing the
//       actual OT is shoved into preprocessing (which can also be done online,
//       if it wasn't done beforehand). Here is quick summary of how Beaver's
//       offline/online trick works (in particular, this describes how the
//       present GMW code works):
//       1) Precompute OT bits.
//          Beaver's precomputed bit (slices) trick is to run 1-out-of-2 OT ahead
//          of time, so that Client knows (random) bit b and one of two of Server's
//          (random) bits (slices) s_b:
//            Input to 1-out-of-2 OT:
//              Client: (Random) bit b
//              Server: (Random) bits (slices) s_0, s_1
//            Output:
//              Client: Has (b, s_b); doesn't know s_(~b)
//              Server: Doesn't know b
//          There are many choices for the actual OT protocol used to achieve this;
//          see oblivious_transfer_utils.h.
//       2) Use Precomputed bits for 1-out-of-2 OT.
//          From output to Step (1), Client has (b, s_b). Now, we wish
//          to run 1-out-of-2 OT for new selection bit c and secrets (t_0, t_1):
//           Input to 1-out-of-2 OT:
//             Client: (b, s_b), c
//             Server: (s_0, s_1), (t_0, t_1)
//           Output:
//             Client: Has t_c, doesn't know t_(~c)
//             Server: Doesn't know c
//           Protocol (all additions are in Z_2, i.e. bitwise XOR):
//             a) Client sends z := b + c to Server
//             b) Server computes and sends to Client:
//                  i = t_0 + s_z   = t_0 + s_1 * (b + c) + s_0 * (1 + b + c)
//                  j = t_1 + s_~z  = t_1 + s_0 * (b + c) + s_1 * (1 + b + c)
//                Notice that we either have:
//                  (i, j) = (t_0 + s_0, t_1 + s_0), if (b == c) OR
//                  (i, j) = (t_0 + s_1, t_1 + s_1), if (b != c)
//             c) Client adds her share s_b to the appropriate {i, j} to get output
//                (based on "Notice" comment in Step (b):
//                  t_0 = i + s_b, (if c = 0) OR
//                  t_1 = j + s_b, (if c = 1)
//       3) For GMW evaluation of a gate, we need 1-out-of-4 OT, not 1-out-of-2.
//          But this can be directly obtained from two sets of 1-out-of-2 OT:
//           Input to 1-out-of-4 OT:
//             Client: (b, s_b), (c, t_c), r, s;
//                     where the first two 2-tuples are Client's outputs from
//                     two of the precomputed 1-out-of-2 OT's with server, and
//                     r, s represent Client's values on her input wires to the gate.
//             Server: (s_0, s_1), (t_0, t_1), (u_0, u_1), (v_0, v_1);
//                     where the first two 2-tuples are the random inputs the
//                     Server used in the first two 1-out-of-2 OT's with Client,
//                     and the second two 2-tuples represent the Server's truth
//                     table for the gate (i.e. think of (u_0, u_1) as the top
//                     row of the truth table, (v_0, v_1) as the bottom row).
//           Output:
//             Client: Knows 1-out-of-4 of the (u_0, u_1, v_0, v_1); i.e. the one
//                     that corresponds to the truth table entry for (r, s).
//             Server: Doesn't know (r, s).
//           Protocol:
//             a) Client sends Server:
//                  w := r + b
//                  z := s + c
//             b) Server computes and sends to Client (actually, the Server will also
//                XOR a random bit (slice) x to each, which represents the Server's
//                share of the output; we exclude that detail here for simplicity):
//                  i = u_0 + s_w  + t_z
//                  j = u_1 + s_w  + t_~z
//                  k = v_0 + s_~w + t_z
//                  l = v_1 + s_~w + t_~z
//                Notice that exactly one of the following is true:
//                  if (w, z) = (0, 0):
//                    (i, j, k, l) = (u0 + s0 + t0, u1 + s0 + t1, v0 + s1 + t0, v1 + s1 + t1)
//                  if (w, z) = (0, 1):
//                    (i, j, k, l) = (u0 + s0 + t1, u1 + s0 + t0, v0 + s1 + t1, v1 + s1 + t0)
//                  if (w, z) = (1, 0):
//                    (i, j, k, l) = (u0 + s1 + t0, u1 + s1 + t1, v0 + s0 + t0, v1 + s0 + t1)
//                  if (w, z) = (1, 1):
//                    (i, j, k, l) = (u0 + s1 + t1, u1 + s1 + t0, v0 + s0 + t1, v1 + s0 + t0)
//             c) Client adds her shares (s_b + t_c) to the appropriate coordinate
//                to get output (Notice from Steb (b) above that in any case,
//                there is exactly one of the 4 coordinates that the Client can
//                decode (by adding s_b + t_c), and that among the four cases,
//                any of the four possible outputs (u_0, u_1, v_0, v_1) can be
//                obtained by the Client with appropriate choice of (w, z).
//                Note that formally, Client computes output as:
//                  u_0 = i + s_b + t_c (if r = 0, s = 0)
//                  u_1 = j + s_b + t_c (if r = 0, s = 1)
//                  v_0 = k + s_b + t_c (if r = 1, s = 0)
//                  v_1 = l + s_b + t_c (if r = 1, s = 1)
//       4) Generalizing to slices (from bits), we just do everything above coordinate-
//          wise. Formally, this means replacing the "if" conditions in the equations
//          in (3b) with the more complicated (but equivalent) relations (all
//          calculations below are bit-wise; i.e. '+' -> 'XOR' and '*' -> 'AND'):
//            i = u_0 + (s_0 * ~w) + (s_1 * w)  + (t_0 * ~z) + (t_1 * z)
//            j = u_1 + (s_0 * ~w) + (s_1 * w)  + (t_0 * z)  + (t_1 * ~z)
//            k = v_0 + (s_0 * w)  + (s_1 * ~w) + (t_0 * ~z) + (t_1 * z)
//            l = v_1 + (s_0 * w)  + (s_1 * ~w) + (t_0 * z)  + (t_1 * ~z)
//          and in (3c):
//            s_b + t_c +
//            (i * (~r * ~s) + j * (~r * s) + k * (r * ~s) + l * (r * s))
//
// 2) Regarding how gates are locally evaluated (when possible):
//    There are 2 reasons a gate can be computed locally:
//      A) The gate type allows for local computation:
//           i) Boolean: {ID, NOT, XOR, EQ}
//          ii) Arithmetic: {ADD, SUB}, and MULT if one input is (global) constant
//      B) The gate does not depend on inputs from all parties
//    There are a few things to consider here:
//       i) Locally computing XOR and ID gates is a no-brainer (no reason not to)
//      ii) Locally computing ID and EQ gates is almost a no-brainer: there
//          is the one complication that having all parties locally compute
//          these gates necessarily means there is an asymmetry among the parties,
//          e.g. one party will do something, and the other something else.
//     iii) Locally computing {ADD, SUB, MULT} gates where one input wire is a
//          constant is relatively straightforward:
//            ADD/SUB: Designate one party to do the ADD/SUB locally; all other
//                     parties do IDENTITY.
//            MULT: All parties locally do the multiplication
//      iv) For case (B) (where a gate's inputs does not depend on (at least) one
//          party's original (global) inputs), it is less clear how to proceed.
//          In particular, we now must have each Gate hold the additional
//          information of which parties' inputs are on each input wire.
//    For n = 2 parties, (iv) may be reasonable; but for general n > 2, this
//    complicates both the logic, as well as having a memory impact (storing
//    all this information). Of course, there are also benefits of computing
//    gates as in (B) locally (among the players whose inputs are required):
//      - Less communication: No need to communicate with any non-relevant parties
//      - Less OT bits: Parties not needed for a gate need not generate OT
//                      bits for these gates.
//    CONCLUSION:
//      - For n = 2: Legacy code already exists for having all
//        locally computable gates, as in (A) and (B), done locally.
//        Since the code already exists, and since n = 2 may be the most common
//        case, this feature is left in place.
//      - For n > 2:
//        UPDATE: The present GMW class only supports n = 2.
//        However, gmw_circuit_by_gate supports arbitrary n. Based on quadratic
//        slow-down (in number of parties 'n') of circuit evaluation, it was
//        determined that supporting local computation (here, 'local' may not
//        be truly local, as communication between *some* of the parties may
//        still be necessary) was a trade-off worth making.
//
//    Here is how 'locally' computable gates are processed:
//    Our goal will be to develop rules that respect the following invariant:
//      INVARIANT: The value on every input wire (EXCEPT global constant inputs) is
//                 secret-shared amongst all parties on which the gate depends
//                 (any non-dependent parties have value '0' on such wires).
//    Constant global input wires satisfy a special invariant:
//      GLOBAL_CONSTANT INVARIANT: Fix a global constant input wire 'w', let 'g'
//                                 denote the gate this input wire leads to. Then:
//                                   i) If g.op_ == IDENTITY, then P0's input wire
//                                      has the value of the constant, and all other
//                                      parties' input wires are '0'.
//                                  ii) If g.op_ == MULT, then all parties in
//                                      g.depends_on_ will have the value of the
//                                      constant on their input wires, all other
//                                      parties have '0'.
//                                iii) For all other cases, let 'i' denote the
//                                     *lowest* party index in g.depends_on_.
//                                     Then Pi's input wire has the value of the
//                                     constant, and all other parties' input wires are '0'.
//    NOTE: Respecting the GLOBAL_CONSTANT INVARIANT will demand that the circuit has
//          reduced away all constant only gates. In the special case that a global
//          constant input is also a global output, the way circuit files are
//          formatted, this forces the introduction of an artificial IDENTITY gate
//          that takes the constant input and spits it out as global output;
//          this explains invariant (i) above.
//
//    Rules for locally computing gates, i.e. gates of type A.i, A.ii, or B (see above):
//      For Case B (gate depends on a subset of players), do the following:
//      C0 Use the INVARIANT above to evaluate the gate normally (either locally,
//         if the gate also falls under Case A.i or A.ii, or via GMW otherwise)
//         amongst the players on which the gate depends (for all parties whose
//         inputs are not needed for this gate, they output '0' for the gate output).
//      For Case A, adopt the following number convention:
//        1) Gate is IDENTITY or XOR
//        2) Gate is NOT
//        3) Gate is EQ
//        4) Gate is ADD/SUB
//        5) Gate is MULT, and (exactly) one input wire is constant
//      Then, do the following:
//      C1  All parties evaluate the gate locally (on their secret-shared inputs)
//      C2  Specially designated party (the lowest indexed party on which the gate
//          depends, i.e. Party '0' if gate depends on all parties)
//          evaluates NOT locally (on secret-shared input), all other
//          parties evaluate IDENTITY locally (on secret-shared input)
//      C3  Specially designated party (the lowest indexed party on which the gate
//          depends, i.e. Party '0' if gate depends on all parties)
//          evaluates EQ locally (on secret-shared input), all other parties
//          evaluate XOR locally (on secret-shared input)
//      C4  All parties evaluate the gate locally (on their secret-shared inputs).
//          (Note that in the case that (exactly) one input wire is a (global)
//          constant, the GLOBAL_CONSTANT INVARIANT guarantees that the constant
//          is properly shared amongst all parties, i.e. that only one party holds
//          the actual value, and all others hold '0').
//      C5  All parties evaluate the gate locally (on their secret-shared inputs).
//          (Note that the GLOBAL_CONSTANT INVARIANT guarantees all (dependent)
//          parties have the actual value of the constant).
#ifndef GMW_CIRCUIT_H
#define GMW_CIRCUIT_H

#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"
#include "Crypto/ObliviousTransfer/oblivious_transfer_utils.h"
#include "MathUtils/constants.h"  // For slice
#include "MathUtils/data_structures.h"  // For GenericValue
#include "Networking/socket.h"
#include "TestUtils/timer_utils.h"  // For Timer.

#include <map>
#include <memory>  // For unique_ptr.
#include <set>
#include <string>
#include <tuple>  // For pair.
#include <vector>

// Forward-declare SocketParams.
namespace networking {
class SocketParams;
}  // namespace networking

namespace crypto {
namespace multiparty_computation {

// Plays the role of the "server" in GMW circuits; i.e. the one who
// creates the truth tables from the gates, from which the client
// will use OT to select the proper one.
// This class is templated, with the template type 'value_t' denoting
// whether the underlying (Standard)Circuit that will be evaluated is
// of Format 1 or 2 (with corresponding value_t = slice or bool).
template<typename value_t>
class GmwServer {
public:
  GmwServer() {
    socket_ = nullptr;
    socket_type_ = networking::SocketType::OS_TCP;
    socket_info_ = "";
    ot_params_ = nullptr;
    output_filename_ = "";
    compute_gates_locally_ = true;
    elliptic_curve_based_dh_ = false;
    base_ot_ = OTProtocol::PAILLIER;
  }
  // Constructor with connection info specified.
  GmwServer(const networking::SocketParams& params) {
    SetupSocket(params, 0);
    ot_params_ = nullptr;
    output_filename_ = "";
    compute_gates_locally_ = true;
    elliptic_curve_based_dh_ = false;
    base_ot_ = OTProtocol::PAILLIER;
  }
  // Constructor with connection info and timeout specified.
  GmwServer(const networking::SocketParams& params, const uint64_t& ms) {
    SetupSocket(params, ms);
    ot_params_ = nullptr;
    output_filename_ = "";
    compute_gates_locally_ = true;
    elliptic_curve_based_dh_ = false;
    base_ot_ = OTProtocol::PAILLIER;
  }

  // Sets the fields identifying the party this GmwServer is engaging with.
  void SetOtherParty(const PartyIdentifier& party) { other_party_ = party; }

  // Sets the fields identifying *this* party.
  void SetSelfParty(const PartyIdentifier& party) { self_party_ = party; }

  // Creates a new socket_ either
  //    - TCP/IP: If 'tcp_ip' is non-empty, then use 'tcp_ip' and 'port'.
  //    - RabbitMQ: If 'tcp_ip' is empty, then use rabbitmq_ip and rabbitmq_port
  //                (and optionally set rabbitmq_[username | password], if non-empty).
  // Class maintains ownership (it will be destroyed when Class is destroyed).
  bool SetupSocket(const networking::SocketParams& params, const uint64_t& ms);

  // Returns a pointer to socket_, in case caller wants to pass additional
  // information across this communication channel. Class maintains ownership.
  const networking::Socket* GetSocket() { return socket_.get(); }
  // Sets whether Client requests to Server are blocking.
  void SetConnectNonBlocking(const bool is_non_blocking) {
    socket_->SetConnectNonBlocking(is_non_blocking);
  }
  void SetSocketParams(const networking::SocketParams& params) {
    socket_->SocketSetSocketParams(params);
  }

  bool LoadCircuit(const std::string& filename) {
    return circuit_.LoadCircuit(filename);
  }

  // Sets the server's input (for Format 1 processing inputs; see
  // DISCUSSION FOR LOADING INPUT WIRES above).
  void SetInput(const std::vector<math_utils::slice>& server_input) {
    input_as_slice_ = server_input;
  }
  // Sets the server's input (for Format 2 processing inputs; see
  // DISCUSSION FOR LOADING INPUT WIRES above).
  void SetInput(const std::vector<math_utils::GenericValue>& server_input) {
    input_as_generic_value_ = server_input;
  }

  // Sets compute_gates_locally_.
  void SetComputeGatesLocally(const bool compute_gates_locally) {
    compute_gates_locally_ = compute_gates_locally;
  }

  // Sets ot_params_.
  void SetOtParams(ServerOTParams* params) {
    ot_params_ = std::unique_ptr<ServerOTParams>(params->clone());
  }
  void SetOtParams(
      const bool use_ec_for_dh, const OTProtocol base_ot) {
    elliptic_curve_based_dh_ = use_ec_for_dh;
    base_ot_ = base_ot;
  }

  // Sets output_filename_.
  void SetOutputFilename(const std::string& filename) {
    output_filename_ = filename;
  }

  // Turns on/off timers.
  void SetActivateTimers(const int level) {
    circuit_.timer_level_ = level;
    socket_->ActivateTimers(level >= 0);
  }

  // Prints Timers (including underlying socket_.stats_).
  std::string PrintTimers() { return circuit_.PrintTimers() + socket_info_; }

  // Helper function for EvaluateCircuit: After evaluating all the gates at
  // a given level, this function copies the value in each
  // GmwStandardGate.gate_info_.output_value_ to the appropriate wire (as
  // indicated by that gate's output_wire_locations_).
  bool SetInputsForNextLevel(const size_t& level_index);

  // Clears all values on all wires (but leaves entact circuit mappings, i.e.
  // location of all gates and wires remains the same).
  void ClearCircuitValues() { circuit_.ClearCircuitValues(); }

  void SetOtBitsSeed(const std::vector<unsigned char>& seed) {
    ot_bits_prg_seed_ = seed;
    ot_bits_prg_seed_.resize(16, 0);
  }
  void SetOtBitsSeed(const std::string& seed) {
    ot_bits_prg_seed_.resize(16, (unsigned char) 0);
    for (size_t i = 0; i < seed.size() && i < 16; ++i) {
      ot_bits_prg_seed_[i] = seed.at(i);
    }
  }

  // The function communicates with the other party, and if both parties
  // have OT bits, then need_to_run_ot_protocol is set to false.
  bool DetermineWhetherToRunOtProtocol(
      const bool self_has_ot_bits_file, bool* need_to_run_ot_protocol);

  // This generates the Server's random bits (slices) that need to be
  // created for Beaver's precomputation OT. In particular, for each gate,
  // the Server will require 4 random bits (slices), of which the Client knows 1.
  // This function both generates the 4 random bits (slices) per gate, as well
  // as doing 1-out-of-4 OT to share one value (per gate) with the Client.
  static bool PrecomputeObliviousTransferBits(
      const bool is_format_one,
      const uint64_t& num_non_local_gates,
      const std::vector<unsigned char>& seed,
      test_utils::Timer* server_generate_ot_secrets_timer,
      test_utils::Timer* server_generate_ot_masks_timer,
      test_utils::Timer* ot_protocol_timer,
      ServerOTParams* ot_params,
      std::vector<TruthTableMask<value_t>>* output);
  // Same as above, but uses circuit_ to determine how many sets of OT bits
  // (slices) to generate, and then updates circuit_ directly with the result.
  // One other difference is that in addition to generating the (random)
  // TruthTableMasks, random bits (slices) will also be generated for each
  // output wire (representing the Server's share for that wire), and loaded
  // into the circuit_ via the gate_info_.output_value_ field of each gate.
  bool PrecomputeObliviousTransferBits();
  // Same as above, but optionally writes the Server's generated OT bits to file.
  bool PrecomputeObliviousTransferBits(const std::string& ot_bits_filename);
  // Same as above, but doesn't do the 1-out-of-4 OT with the Client.
  static void PrecomputeObliviousTransferBits(
      const bool is_format_one,
      const uint64_t& num_non_local_gates,
      const std::vector<unsigned char>& seed,
      test_utils::Timer* server_generate_ot_secrets_timer,
      std::vector<TruthTableMask<value_t>>* output);
  // If Beaver's protocol for generating offline OT bits (slices) has already
  // been done, load those bits (stored in 'filename') into the circuit_.
  // Also, generate random shares for each output wire, and load those into
  // circuit_ via LoadPrecomputedBitsIntoCircuit().
  // NOTE: File format of filename is a comma-separated list of 4 values (slices)
  // per line.
  bool LoadObliviousTransferBits(const std::string& filename);

  // Engages in 2-party protocol to evaluate the circuit_. Outputs are stored
  // in circuit_.outputs_as_[slice | generic_value]_.
  bool EvaluateCircuit();

  // Returns the number of gates in the circuit.
  int64_t GetNumGates() { return circuit_.size_; }
  // Returns the number of gates that *cannot* be computed locally (and hence
  // OT bits will need to be generated to GMW-Evaluate this gate).
  int64_t GetNumNonLocalGates() {
    return compute_gates_locally_ ? circuit_.num_non_local_gates_ :
                                    GetNumGates();
  }

  // Returns the output of (a Format 1) circuit.
  std::vector<math_utils::slice> GetOutputAsSlice() {
    return circuit_.outputs_as_slice_;
  }
  // Returns the output of (a Format 2) circuit.
  std::vector<math_utils::GenericValue> GetOutputAsGenericValue() {
    return circuit_.outputs_as_generic_value_;
  }

  // Write the output (shares) in circuit_.outputs_as_[slice | generic_value]_
  // to file 'output_filename_'.
  bool WriteOutputToFile();

private:
  // The circuit to compute.
  StandardCircuit<value_t> circuit_;
  // Information about the other party.
  PartyIdentifier other_party_;
  // Information about *this* party.
  PartyIdentifier self_party_;
  // Whether all gates should be computed via GMW, or if XOR and EQ gates
  // should be computed locally.
  bool compute_gates_locally_;

  // OT parameters for engaging in the OT protocol.
  std::unique_ptr<ServerOTParams> ot_params_;
  // If OT bits need to be generated, this specifies whether to use truly random
  // values to generate random secrets (pairs), or use a (seeded) deterministic
  // Random Number Generator.
  // If empty, use truly random; otherwise, use this vector (must have length
  // exactly 16) as a seed.
  std::vector<unsigned char> ot_bits_prg_seed_;
  // EC vs. DH toggle (only relevant if using DiffieHellman for base OT).
  bool elliptic_curve_based_dh_;
  // Base OT toggle (Paillier, DH).
  OTProtocol base_ot_;

  // The server's bit-sliced (Format 1) input to the circuit. The mapping of
  // these values to input wires is as specified in inputs_as_slice_locations_[0].
  // NOTE 1: If inputs are being processed as in Format 1
  // (see DISCUSSION FOR LOADING INPUT WIRES above), this field must be populated
  // (typically via SetInput) before EvaluateCircuit() is called; and it will
  // have the same size as inputs_as_slice_locations_[0]. If inputs are being
  // processed as in Format 2, then this field should be empty (and then
  // inputs_as_generic_values_ below should be populated instead).
  // NOTE 2: This represents the actual input that will be fed into the gates,
  // as opposed to the Server's original inputs (values). In particular,
  // PackSliceBits() has been called, to bit-slice the original inputs,
  // and put the first bit of each in the first slice, etc.
  std::vector<math_utils::slice> input_as_slice_;
  // The Server's non-bit-sliced (Format 2) input to the circuit. The mapping
  // of these values to input wires is specified in inputs_as_generic_value_locations_[0].
  std::vector<math_utils::GenericValue> input_as_generic_value_;
  // The following hold the Server's shares of all the inputs:
  //   (i)  Its own shares of its own inputs
  //   (ii) Its shares of the Client's inputs
  std::vector<math_utils::slice> servers_shares_of_servers_input_as_slice_;
  std::vector<math_utils::slice> servers_shares_of_clients_input_as_slice_;
  // The following fields serve the same purpose as
  // servers_shares_of_[clients | servers]_input_as_slice_ above, for Format 2.
  std::vector<unsigned char> servers_shares_of_servers_input_as_generic_value_;
  std::vector<unsigned char> servers_shares_of_clients_input_as_generic_value_;
  // For input in Format 2, we need a mapping from Server's input index
  // (w.r.t. input_as_generic_value_) to the index within
  // servers_shares_of_servers_input_as_generic_value_ where that input is stored.
  std::vector<uint64_t> server_input_index_to_server_shares_index_;
  // Ditto, for Client's input index to index within servers_shares_of_clients_input_.
  std::vector<uint64_t> client_input_index_to_client_shares_index_;
  // Connection to the Client.
  std::unique_ptr<networking::Socket> socket_;
  networking::SocketType socket_type_;
  std::string socket_info_;
  // The name of the file to write the (Server's shares of the) circuit output.
  std::string output_filename_;

  // Loads the precomputed random bits (slices) in mask_values into the relevant
  // StandardGate.mask_ fields of the circuit_.
  // Also generates a random bit (slice) for each gate, and stores the value in
  // the StandardGate.output_value_ field.
  bool LoadPrecomputedBitsIntoCircuit(
      const std::vector<TruthTableMask<value_t>>& mask_values);

  // The opposite of LoadObliviousTransferBits() above: writes mask_values to file.
  static bool WriteObliviousTransferBitsToFile(
      const std::string& filename,
      const std::vector<TruthTableMask<value_t>>& mask_values);

  // Ramdomly splits input_as_slice_ into two shares, keeping one and sending the
  // other to Client. Also receives Client's shares of their input. Afterwards,
  // servers_shares_of_[servers | clients]_input_as_[slice | generic_value]_ are
  // populated.
  bool ExchangeInputShares();
  bool ExchangeFormatOneInputShares();
  bool ExchangeFormatTwoInputShares();

  // Reveals the appropriate outputs (as determined by output_destinations_)
  // to Client, and gets Client's shares; XOR's them to get final circuit output,
  // storing result (and hence overwriting the output shares) in
  // circuit_.outputs_as_slice_.
  bool ExchangeOutputShares();

  // Loads inputs (servers_shares_of_[clients, servers]_input_) on the
  // appropriate input wires. In Particular, on input,
  // circuit->inputs_as_[slice | generic_value]_locations_ fields
  // should be set (e.g. when loading a circuit file of the appropriate format,
  // or via SetStandardTwoPartyInputAsSliceMapping()),
  // which indicate where the i^th input of Party 1 (resp. Party 2) should go.
  // Then this function takes the actual inputs from each Party, and uses the
  // circuit->inputs_as_[slice | generic_value]_locations_ mappings
  // to set the appropriate Gate's input wire.
  bool LoadInputsToCircuit();
  bool LoadFormatOneInputsToCircuit();
  bool LoadFormatTwoInputsToCircuit();

  // Evaluates a given level of the circuit. Requires first getting Client's
  // (selection) slices for the truth-table OT's (for each gate).
  bool EvaluateLevel(const size_t& level);
  // Called as a subroutine to the above, once Client's selection slices
  // have been obtained.
  bool EvaluateLevel(
      const size_t& level,
      const uint64_t& buffer_offset,
      const std::vector<char>& received_selection_bits,
      std::vector<ObfuscatedTruthTable<value_t>>* server_response);
  // Called as a subroutine to EvaluateLevel() above; evaluates a single gate.
  static bool EvaluateFormatOneGate(
      const std::pair<math_utils::slice, math_utils::slice>&
          client_selection_slices,
      StandardGate<value_t>* server_gate,
      ObfuscatedTruthTable<value_t>* obfuscated_truth_table);
  static bool EvaluateFormatTwoGate(
      const std::pair<unsigned char, unsigned char>& client_selection_bits,
      StandardGate<value_t>* server_gate,
      ObfuscatedTruthTable<value_t>* obfuscated_truth_table);
};

// Plays the role of the "client" in GMW circuits; i.e. the one who
// sends selection bits (slices) to the Server to get the relevant
// entry of the truth tables for each gate.
// This class is templated, with the template type 'value_t' denoting
// whether the underlying (Standard)Circuit that will be evaluated is
// of Format 1 or 2 (with corresponding value_t = slice or bool).
template<typename value_t>
class GmwClient {
public:
  GmwClient() {
    socket_ = nullptr;
    socket_type_ = networking::SocketType::OS_TCP;
    socket_info_ = "";
    ot_params_ = nullptr;
    elliptic_curve_based_dh_ = false;
    base_ot_ = OTProtocol::PAILLIER;
    compute_gates_locally_ = true;
    output_filename_ = "";
  }

  GmwClient(const networking::SocketParams& params) {
    SetupSocket(params, 0);
    ot_params_ = nullptr;
    elliptic_curve_based_dh_ = false;
    base_ot_ = OTProtocol::PAILLIER;
    compute_gates_locally_ = true;
    output_filename_ = "";
  }

  GmwClient(const networking::SocketParams& params, const uint64_t& ms) {
    SetupSocket(params, ms);
    ot_params_ = nullptr;
    elliptic_curve_based_dh_ = false;
    base_ot_ = OTProtocol::PAILLIER;
    compute_gates_locally_ = true;
    output_filename_ = "";
  }

  // Sets the fields identifying the party this GmwClient is engaging with.
  void SetOtherParty(const PartyIdentifier& party) { other_party_ = party; }

  // Sets the fields identifying *this* party.
  void SetSelfParty(const PartyIdentifier& party) { self_party_ = party; }

  // Creates a new socket_ either
  //    - TCP/IP: If 'tcp_ip' is non-empty, then use 'tcp_ip' and 'port'.
  //    - RabbitMQ: If 'tcp_ip' is empty, then use rabbitmq_ip and rabbitmq_port
  //                (and optionally set rabbitmq_[username | password], if non-empty).
  // Class maintains ownership (it will be destroyed when Class is destroyed).
  bool SetupSocket(const networking::SocketParams& params, const uint64_t& ms);

  // Returns a pointer to socket_, in case caller wants to pass additional
  // information across this communication channel. Class maintains ownership.
  const networking::Socket* GetSocket() { return socket_.get(); }
  // Sets whether Client requests to Server are blocking.
  void SetConnectNonBlocking(const bool is_non_blocking) {
    socket_->SetConnectNonBlocking(is_non_blocking);
  }
  void SetSocketParams(const networking::SocketParams& params) {
    socket_->SocketSetSocketParams(params);
  }

  bool LoadCircuit(const std::string& filename) {
    return circuit_.LoadCircuit(filename);
  }

  // Sets the client's input (for Format 1 processing inputs; see
  // DISCUSSION FOR LOADING INPUT WIRES above).
  void SetInput(const std::vector<math_utils::slice>& client_input) {
    input_as_slice_ = client_input;
  }
  // Sets the client's input (for Format 2 processing inputs; see
  // DISCUSSION FOR LOADING INPUT WIRES above).
  void SetInput(const std::vector<math_utils::GenericValue>& client_input) {
    input_as_generic_value_ = client_input;
  }

  // Sets compute_gates_locally_.
  void SetComputeGatesLocally(const bool compute_gates_locally) {
    compute_gates_locally_ = compute_gates_locally;
  }

  // Sets ot_params_.
  void SetOtParams(ClientOTParams* params) {
    ot_params_ = std::unique_ptr<ClientOTParams>(params->clone());
  }
  void SetOtParams(
      const bool use_ec_for_dh, const OTProtocol base_ot) {
    elliptic_curve_based_dh_ = use_ec_for_dh;
    base_ot_ = base_ot;
  }

  // Sets output_filename_.
  void SetOutputFilename(const std::string& filename) {
    output_filename_ = filename;
  }

  // Turns on/off timers.
  void SetActivateTimers(const int level) {
    circuit_.timer_level_ = level;
    socket_->ActivateTimers(level >= 0);
  }

  // Prints Timers (including underlying socket_.stats_).
  std::string PrintTimers() { return circuit_.PrintTimers() + socket_info_; }

  // Clears all values on all wires (but leaves entact circuit mappings, i.e.
  // location of all gates and wires remains the same).
  void ClearCircuitValues() { circuit_.ClearCircuitValues(); }

  void SetOtBitsSeed(const std::vector<unsigned char>& seed) {
    ot_bits_prg_seed_ = seed;
    ot_bits_prg_seed_.resize(16, 0);
  }
  void SetOtBitsSeed(const std::string& seed) {
    ot_bits_prg_seed_.resize(16, (unsigned char) 0);
    for (size_t i = 0; i < seed.size() && i < 16; ++i) {
      ot_bits_prg_seed_[i] = seed.at(i);
    }
  }

  // The function communicates with the other party, and if both parties
  // have OT bits, then need_to_run_ot_protocol is set to false.
  bool DetermineWhetherToRunOtProtocol(
      const bool self_has_ot_bits_file, bool* need_to_run_ot_protocol);

  // This function should be called to have the Client engage in the 2-Party
  // OT Protocol that generates all of the random bits the two parties will use for
  // the actual OT. In particular, for each gate in the circuit, this:
  //   1) Generates random pairs (b_1, b_2) of selection bits (slices) for 1-of-4 OT
  //   2) Engages in 1-of-4 OT (or more precisely, two sets of 1-out-of-2 OT) with
  //      the Server to learn the Server's (random) bits (slices) for this gate
  //   3) Stores the resulting pairs (b_1, s_b_1), (b_2, s_b_2)
  static bool PrecomputeObliviousTransferBits(
      const bool compute_gates_locally,
      const std::vector<unsigned char>& seed,
      const StandardCircuit<value_t>& circuit,
      test_utils::Timer* client_generate_ot_selection_bits_timer,
      test_utils::Timer* client_store_ot_bits_timer,
      test_utils::Timer* ot_protocol_timer,
      ClientOTParams* ot_params,
      std::map<GateLocation, SelectionBitAndValuePair<value_t>>* output);
  // Same as above, but using circuit_ to determine the number of gates,
  // ot_params_ for the OT Parameters, and storing the result in ot_bits_.
  bool PrecomputeObliviousTransferBits();
  // Same as above, but optionally writes the Client's ot_bits_ to file.
  bool PrecomputeObliviousTransferBits(const std::string& ot_bits_filename);
  // If Beaver's protocol for generating offline OT bits (slices) has already
  // been done, load those bits (stored in 'filename') into ot_bits_.
  // The format of 'filename' should be four comma-separated values per line,
  // representing the two (selection bit b, secret_b) pairs needed to perform
  // the 1-out-of-4 OT at each gate:
  //   selection_bit_slice1,secret_slice1,selection_bit_slice2,secret_slice2
  // Thus, the file should have circuit_.size_ such lines.
  // NOTE: Since each gate actually has (bits_per_slice) parallel computations,
  // there are actually (bits_per_slice) instances of 1-out-of-4 OT that get
  // done. Thus, each of the four values on each line should be value that
  // represents a 'slice' (the code will later interpret these slices as
  // binary strings when doing bit operations XOR, AND, etc.).
  // The file will be loaded into ot_bits_.
  bool LoadObliviousTransferBits(const std::string& filename);

  // Engages in 2-party protocol to evaluate the circuit_. Outputs are stored
  // in circuit_.outputs_as_[slice | generic_value]_.
  bool EvaluateCircuit();
  bool EvaluateLevel(const size_t& level);

  // Returns the number of gates in the circuit.
  int64_t GetNumGates() { return circuit_.size_; }
  // Returns the number of gates that *cannot* be computed locally (and hence
  // OT bits will need to be generated to GMW-Evaluate this gate).
  int64_t GetNumNonLocalGates() {
    return compute_gates_locally_ ? circuit_.num_non_local_gates_ :
                                    GetNumGates();
  }

  // Returns the output of the circuit.
  std::vector<math_utils::slice> GetOutputAsSlice() {
    return circuit_.outputs_as_slice_;
  }
  // Returns the output of (a Format 2) circuit.
  std::vector<math_utils::GenericValue> GetOutputAsGenericValue() {
    return circuit_.outputs_as_generic_value_;
  }

  // Write the output (shares) in circuit_.outputs_as_[slice | generic_value]_
  // to file 'output_filename_'.
  bool WriteOutputToFile();

private:
  // The circuit to compute.
  StandardCircuit<value_t> circuit_;
  // Information about the other party.
  PartyIdentifier other_party_;
  // Information about *this* party.
  PartyIdentifier self_party_;
  // Whether all gates should be computed via GMW, or if XOR and EQ gates
  // should be computed locally.
  bool compute_gates_locally_;

  // OT parameters for engaging in the OT protocol.
  std::unique_ptr<ClientOTParams> ot_params_;
  // If OT bits need to be generated, this specifies whether to use truly random
  // values to generate random selection bit(s), or use a (seeded) deterministic
  // Random Number Generator.
  // If empty, use truly random; otherwise, use this vector (must have length
  // exactly 16) as a seed.
  std::vector<unsigned char> ot_bits_prg_seed_;
  // The pregenerated OT bits to use during circuit evaluation.
  std::map<GateLocation, SelectionBitAndValuePair<value_t>> ot_bits_;
  // EC vs. DH toggle (only relevant if using DiffieHellman for base OT).
  bool elliptic_curve_based_dh_;
  // Base OT toggle (Paillier, DH).
  OTProtocol base_ot_;

  // The client's bit-sliced (Format 1) input to the circuit. The mapping of
  // these values to input wires is as specified in inputs_as_slice_locations_[1].
  // NOTE 1: If inputs are being processed as in Format 1
  // (see DISCUSSION FOR LOADING INPUT WIRES above), this field must be populated
  // (typically via SetInput) before EvaluateCircuit() is called; and it will
  // have the same size as inputs_as_slice_locations_[1]. If inputs are being
  // processed as in Format 2, then this field should be empty (and then
  // inputs_as_generic_values_ below should be populated instead).
  // NOTE 2: This represents the actual input that will be fed into the gates,
  // as opposed to the Client's original inputs (values). In particular,
  // PackSliceBits() has been called, to bit-slice the original inputs,
  // and put the first bit of each in the first slice, etc.
  std::vector<math_utils::slice> input_as_slice_;
  // The Client's non-bit-sliced (Format 2) input to the circuit. The mapping
  // of these values to input wires is specified in inputs_as_generic_value_locations_[1].
  std::vector<math_utils::GenericValue> input_as_generic_value_;
  // The following hold the Client's shares of all the inputs:
  //   (i)   Its own shares of its own inputs
  //   (ii) Its shares of the Server's inputs
  std::vector<math_utils::slice> clients_shares_of_clients_input_as_slice_;
  std::vector<math_utils::slice> clients_shares_of_servers_input_as_slice_;
  // The following fields serve the same purpose as
  // clients_shares_of_[clients | servers]_input_as_slice_ above, for Format 2.
  std::vector<unsigned char> clients_shares_of_clients_input_as_generic_value_;
  std::vector<unsigned char> clients_shares_of_servers_input_as_generic_value_;
  // For input in Format 2, we need a mapping from Client's input index
  // (w.r.t. input_as_generic_value_) to the index within
  // clients_shares_of_clients_input_as_generic_value_ where that input is stored.
  std::vector<uint64_t> client_input_index_to_client_shares_index_;
  // Ditto, for Client's input index to index within servers_shares_of_clients_input_.
  std::vector<uint64_t> server_input_index_to_server_shares_index_;
  // Connection to the Server.
  std::unique_ptr<networking::Socket> socket_;
  networking::SocketType socket_type_;
  std::string socket_info_;
  // The name of the file to write the (Client's shares of the) circuit output.
  std::string output_filename_;

  // The opposite of LoadObliviousTransferBits() above: writes ot_bits_ to file.
  bool WriteObliviousTransferBitsToFile(const std::string& filename);

  // Ramdomly splits input_as_slice_ into two shares, keeping one and sending the
  // other to Client. Also receives Client's shares of their input. Afterwards,
  // clients_shares_of_[servers | clients]_input_as_[slice | generic_value]_ are
  // populated.
  bool ExchangeInputShares();
  bool ExchangeFormatOneInputShares();
  bool ExchangeFormatTwoInputShares();

  // Reveals the appropriate outputs (as determined by output_destinations_)
  // to Server, and gets Server's shares; XOR's them to get final circuit output,
  // storing result (and hence overwriting the output shares) in
  // circuit_.outputs_as_slice_.
  bool ExchangeOutputShares();

  // Loads inputs (clients_shares_of_[clients, servers]_input_) on the
  // appropriate input wires. In Particular, on input,
  // circuit->inputs_as_[slice | generic_value]_locations_ fields
  // should be set (e.g. when loading a circuit file of the appropriate format,
  // or via SetStandardTwoPartyInputAsSliceMapping()),
  // which indicate where the i^th input of Party 1 (resp. Party 2) should go.
  // Then this function takes the actual inputs from each Party, and uses the
  // circuit->inputs_as_[slice | generic_value]_locations_ mappings
  // to set the appropriate Gate's input wire.
  bool LoadInputsToCircuit();
  bool LoadFormatOneInputsToCircuit();
  bool LoadFormatTwoInputsToCircuit();

  // For each gate, combines the Client's (shares of) values on the input wires
  // for that gate, together with the precomputed (random bit, selection bit) pair
  // (two pairs for each gate) to send the Server the relevant bit (slice) pairs
  // that are required for the 1-out-of-4 OT used to select the appropriate
  // entry of the truth table. See Discussion at top of this file regarding
  // "Evaluate GMW Gate Using Precomputed OT bits (slices)."
  bool GenerateSelectionSlices(
      const size_t& level_index,
      std::vector<unsigned char>* packed_selection_bits);

  // Parses the obfuscated truth table sent by the Server, picking out the
  // one entry that corresponds to the Client's inputs (on the left and right
  // input wires to each gate), and deobfuscating using the GMW+Beaver 1-out-of-4
  // OT technique.
  bool GetFormatOneOutputWireSharesFromTruthTables(
      const size_t& level_index,
      const std::vector<ObfuscatedTruthTable<math_utils::slice>>&
          server_response,
      std::vector<math_utils::slice>* output_shares);
  bool GetFormatTwoOutputWireSharesFromTruthTables(
      const size_t& level_index,
      const std::vector<ObfuscatedTruthTable<bool>>& server_response,
      std::vector<unsigned char>* output_shares);

  // Loads the indicated value on the input gate's output_value_,
  // as well as onto the appropriate input wire of each gate
  // in the input gate's output_wire_locations_.
  bool LoadOutputWire(
      const bool is_format_one,
      const value_t& value,
      StandardGate<value_t>* gate);

  // Exactly one of {outputs_as_slice, outputs_as_bits} will be non-empty.
  // Loads the values in the non-empty one into the appropriate gate's output
  // wire (i^th entry of 'outputs_as_[slice | bits]' gets loaded onto the i^th
  // gate of the given level) as well as to the relevant gate's input wire.
  bool LoadOutputWireShares(
      const size_t& level_index,
      const std::vector<math_utils::slice>& outputs_as_slice,
      const std::vector<unsigned char>& outputs_as_bits);
};

// Constructs Obfuscated TT from original truth table, Server's output bit,
// and Client's selection bit.
extern void ConstructObfuscatedTruthTable(
    const bool first_selection_bit,
    const bool second_selection_bit,
    const bool servers_output_share,
    const TruthTableMask<bool>& server_ot_bits,
    const TruthTableMask<bool>& truth_table,
    ObfuscatedTruthTable<bool>* obfuscated_truth_table);
// Inverse of the above: Extracts the output value of an Obfuscated truth table.
extern bool SelectValueFromObfuscatedTruthTable(
    const bool first_secret,
    const bool second_secret,
    const bool left_wire,
    const bool right_wire,
    const ObfuscatedTruthTable<bool>& tt);
// Same as above, but with 'left_wire' and 'right_wire' already baked into
// the obfuscated truth table itself.
extern bool SelectValueFromObfuscatedTruthTable(
    const bool first_secret,
    const bool second_secret,
    const ObfuscatedTruthTable<bool>& tt);

}  // namespace multiparty_computation
}  // namespace crypto

#endif
