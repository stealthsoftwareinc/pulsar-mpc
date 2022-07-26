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
//   Defines the structures and functions that allow n-party computation
//   via GMW circuits, in gate-centric (as opposed to level-centric) design.
//
// DISCUSSION: There is much discussion, which is organized as follows:
//   0) High-Level Design
//   1) N-Party GMW
//   2) Overview of the Design
//        A) Data Structures
//        B) Concurrency
//
// Without further ado:
//   0) Regarding High-Level Design:
//      There are currently two approaches to circuit evaluation:
//        A) Per-Level Evaluation ("Breadth-First", or "Flat").
//        B) Per-Gate Evaluation ("Depth-First", or "Deep").
//      This file does (B); see gmw_circuit.h for implementation of (A),
//      and standard_circuit_by_gate.h for more discussion on the distinction
//      (including pros/cons of each)
//   1) (N-Party) GMW circuit evaluation is discussed in comment (1) at the top
//      of gmw_circuit.h.
//   2) Overview of the Design.
//      A) Data Structures.
//         In addition to the data structures used by CircuitByGate (for gate
//         info (ops, wirings) and (input/output) values) the following data
//         structures will be used:
//           iv) (Queue) OT Bits.
//               Random selection bits for Client; Obfuscated Truth Table for Server.
//            v) (Queue) Values to Send.
//                Holds values (OT bits or Obf TT) ready to be sent to other party.
//           vi) (Queue) Received Values.
//               Holds values (OT bits or Obf TT) from other party.
//      B) Concurrency.
//         GMW Circuit evaluation involves the same three tasks as described in
//         standard_circuit_by_gate.h:
//             i) Read circuit file
//            ii) Parse global inputs
//           iii) Evaluate gates in 'Gates'
//         In addition to these tasks, GMW circuit evaluation also requires
//         the additional tasks:
//            iv) Generating or Reading OT bits
//             v) Sending (OT, inputs, values) bits to other party(ies)
//            vi) Receiving (OT, inputs, values) bits from other party(ies)
//         =====================================================================
//         UPDATE: April 26, 2018.
//         We used to dedicate a thread to each of the above six tasks (when
//         six threads were available). However, it turned out that dedicating
//         a separate thread for the *Receive* task actually made things slower.
//         The reason was: the processing that takes place *between* communication
//         is minimal and hence very fast, and so the code hits the point where
//         it needs to receive the next communication very quickly, more quickly
//         than this communication is available. So the thread sleeps(),
//         periodically waking to check if the bytes have been received yet.
//         It turns out, this sleeping is less efficient than whatever process
//         the OS's socket does when listening to receive bytes; and thus in
//         the end, the code ends up being faster when it calls Listen() to
//         wait for the communication as opposed to sleeping and checking for
//         when the 'Receive' thread has results.
//
//         As a concrete performance comparison: DeepCircuit (1M) was run
//         using 2 threads, with the 2nd thread being used only to receive
//         communication. With this setup, it took ~50s/10k gates, or
//         about 2:46:40 (almost 3 hours!) to run the full test, as compared
//         to ~28s to run the full test using one thread.
//
//         To see how tasks were partitioned amongst threads before, see any
//         push to the repository prior to the above date, and/or look at the
//         Snapshot on 4/26/2018, which was taken before the code was changed.
//         =====================================================================
//         Below, we discuss how concurrency/parallelization will proceed based
//         on number of available threads.
//            Below, when we say that some task is 'done Y times', this will
//         actually mean 'done *up to* Y times', with early termination before
//         Y items have been done if:
//           - There are fewer than 'Y' items to be done; OR
//           - The process cannot complete without some other task happening first
//         NOTE: We do not attempt to maximize efficiency (parallelize) for
//         OT generation. This is to keep code simpler (and thus faster to
//         implement), and because OT generation is designed to be done
//         offline; i.e. this code is not designed to optimize OT generation.
//           - 1 thread.
//               a) Read circuit file Metadata
//             b_0) If OT bits file not present, run OT generation protocol
//               b) Read all Global Inputs (into inputs_).
//               c) Exchange (send and receive) and load all Global Inputs:
//                    - Generate secret shares of (global) self-inputs,
//                      send these to each partner
//                    - Receive each partner's shares of their inputs
//                    - Load [left | right]_inputs_ with these
//                  NOTE: If running in the mode where inputs_ *already* repre-
//                  sents the secret-shared inputs (i.e. inputs_already_shared_
//                  is true), then this step is skipped, except the loading of
//                  [left | right]_inputs_ via LoadGlobalInputShares()
//               d) Cycle through Reading Gate info (from circuit file), reading
//                  OT bits, and evaluating gates, doing each task 'Y' times
//                  (where Y = kDefaultReadFewBytes is some small number)
//                  before context switching. More specifically:
//                    - Read Gate Info: Read Y gates from circuit file
//                    - Read OT Bits:   Read however many bits are needed
//                    - Eval Y Gates:   For each gate, and each Partner:
//                         i) (Client): Send OT selection bits
//                        ii) (Server): Receive OT selection bits
//                       iii) (Server): Evaluate Gate. Send obfuscated truth table
//                        iv) (Client): Receive Obf. TT
//           - 2 threads.
//             Use one thread each for reading the OT file and reading the circuit file.
//             Specifically:
//               a) Thread A reads circuit file metadata
//             b_0) If OT bits file not present, Thread A runs OT generation protocol
//               b) Thread B reads all Global inputs (see 1-thread Step (b) above).
//               c) Thread B Exchanges (Sends and Receives) global inputs
//               d) Thread B Read OT bits.
//               e) Thread A Cycles through the tasks of: Reading gate info,
//                  evaluating gates, and sending/receiving info. Specifically:
//                    - Read Gate Info: Read Y gates from circuit file
//                    - Eval Y Gates:   For each gate, and each Partner:
//                         i) (Client): Send OT selection bits
//                                      (requires thread B to have read them)
//                        ii) (Server): Receive OT selection bits
//                                      Evaluate Gate
//                                      Send obfuscated truth table.
//                       iii) (Client): Receive Obf. TT
//           - 3 threads.
//             Same as 2 threads above, but break out the task of reading the
//             circuit file and the evaluating of gates (both done by Thread 'A'
//             for the 2 thread scenario) into two different threads. Specifically:
//               a) Thread A reads circuit file metadata
//             b_0) If OT bits file not present, Thread A runs OT generation protocol
//               b) Thread B reads all Global inputs (see 1-thread Step (b) above).
//               c) Thread B Exchanges (Sends and Receives) global inputs
//               d) Thread B Read OT bits.
//               e) Thread A Reads Circuit File (metadata already read in Step (a) above)
//               f) Thread C Evaluates Gates (including sending/receiving communication).
//                  Namely, for each gate, and each Partner:
//                    i) (Client): Send OT selection bits
//                                 (requires thread B to have read them)
//                   ii) (Server): Receive OT selection bits
//                                 Evaluate Gate (requires thread A to have read gate info)
//                                 Send obfuscated truth table.
//                  iii) (Client): Receive Obf. TT
//           - > 3 threads.
//             We only use 3 threads. You could imagine using more threads by
//             partitioning out the send/receive tasks to their own threads,
//             but as noted in the UPDATE above, this is not done.
//             NOTE 1: In the case N > 2, it may make sense to try to use extra
//             threads to handle (speed-up) communication from the multitude of
//             players; e.g. have each link be controlled by its own thread; but
//             we do not pursue that now (again, the slowdown discussed above
//             may be compensated for by the speedup enjoyed if there are many
//             players, but the benefits would only be seen for many players
//             (and/or with a code redesign that avoids the issue discussed above)
//             and at this point it is not deemed worthwhile).
//             NOTE 2: We don't attempt to utilize any additional threads
//             for other tasks, e.g. partitioning circuit evaluation.
//             In theory, more threads could be used, but the benefits (faster)
//             are outweighed (at least as of now) by the drawbacks (messier/
//             more complicated code; longer code development time). If we
//             really want to optimize time in the future, here are how are
//             additional threads could be used:
//               - Multiple threads for Reading each file:
//                 Partition a file of N bytes into blocks of size B, and have
//                 successive threads jump ahead B bytes and start processing
//                 from there.
//                 This is difficult, as not only will it require the obvious
//                 logic of having threads reading from the same file in
//                 different places, but there is the complication that the
//                 'block' break will almost certainly not align well with
//                 a logical break in the file (e.g. the end of one gate and
//                 the beginning of another in the Circuit file). Further,
//                 the 2nd thread won't know that Gate/OT/Input index of
//                 the items it is processing, since this will require knowing
//                 how many Gates/OT bits/Inputs there were in the first block,
//                 which won't be known until the first thread terminates.
//               - Multiple threads for Evaluating Gates:
//                 This certainly could be done, but there are some challenges:
//                   - Multiple threads reading/writing from gates_ queue
//                   - The thread doing the non-head (second from top) gate
//                     may not be able to complete its task until the first
//                     thread finishes, if that second gate has an input wire
//                     from a gate being processed by the head gate
//                   - If the non-head (second from top) gate actually gets
//                     computed *before* the head gate (which is highly
//                     plausible to happen at some point, e.g. if it is a local
//                     gate and the other isn't, or if they happen to start at
//                     almost the exact same instant and then just (bad) luck),
//                     then things (e.g. send/receive queue) threaten to get
//                     out-of-order.
//               - Multiple threads for Send/Receive Queues.
//                 There are a couple of challenges/problems here:
//                   - If there is a single socket connection between the parties,
//                     then there's no gains to be made for having multiple threads.
//                     Thus, this really only makes sense if multiple sockets can
//                     be utilized; which now has another variable in terms of
//                     user's setup/parameters, and whether their system can
//                     tolerate multiple sockets, etc.
//                   - Things can get out of order. Thus, each communication will
//                     have to include metadata/indexing to keep track, and
//                     this in turn bloats communication complexity, which may
//                     be bad unto itself, but also could actually slow things
//                     down so that (code complexity notwithstanding) the single
//                     thread case actually outperforms the multi-thread case.
//               As can be seen, while many of the tasks *could* be multi-thread/
//               parallelized, there is much code complexity in each case, and
//               it's not clear that it will lead to that great of savings anyway.
//               Thus, at this point the code does not support multi-threading
//               beyond 2(n - 1) + 3 threads.
#ifndef GMW_CIRCUIT_BY_GATE_H
#define GMW_CIRCUIT_BY_GATE_H

#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit_by_gate.h"
#include "Crypto/ObliviousTransfer/oblivious_transfer_utils.h"
#include "GenericUtils/init_utils.h"  // For GetNumCores().
#include "MapUtils/map_utils.h"  // For InsertOrReplace()
#include "MathUtils/constants.h"  // For slice
#include "MathUtils/data_structures.h"  // For GenericValue
#include "Networking/socket.h"
#include "TestUtils/timer_utils.h"  // For Timer.

#include <map>
#include <memory>  // For unique_ptr.
#include <queue>
#include <set>
#include <string>
#include <tuple>  // For pair.
#include <vector>

namespace crypto {
namespace multiparty_computation {

static const char kOtBitsDir[] = "OtBitsFiles/CircuitByGate/";

// When doing by-level circuit evaluation, parties will compute what they
// can, and then wait for a communication with their partner(s) to compute
// the rest. This stores the preliminary information so that they know
// what to send and know what to do with the communication received.
// This data structure represents all the data needed for one gate.
struct PrelimEvalInfoPerLevel {
  bool is_boolean_gate_;
  std::vector<OutputWireLocation> output_wires_;
  math_utils::GenericValue local_value_;
  // Used if present party is the Client between the relevant partner;
  // the vector stores the per-partner info (so has length = num partners).
  std::vector<unsigned char> selection_bits_sent_;
  OTPair<bool> left_right_wires_;
  // Used if present party is the Server between the relevant partner.
  TruthTableMask<bool> truth_table_;
};

struct PartnerInfo {
  PartyIdentifier id_;
  // Connection info.
  std::unique_ptr<networking::Socket> socket_;
  networking::SocketParams* connection_properties_;
  std::string socket_info_;

  // Generic queues for storing the values to send/receive: Global Inputs, and
  // the bytes sent during gate evaluation (OT Selection Bits/Obfuscated TT).
  ReadWriteQueue<unsigned char> bytes_to_send_;
  ReadWriteQueue<unsigned char> received_bytes_;

  // This keeps track of this partner's share of each of self inputs.
  // This is necessary to minimize communication: when a party is not needed
  // for gate evaluation (because the gate does not depend on any inputs from that party),
  // then we want to allow gate evaluation without that non-dependent party.
  // If (at least) one of the input wires for this gate is actually a global input
  // from self, then we need that the non-dependent party's share of that input
  // wire is '0'; however, a-priori we don't know which gates don't require this
  // party (and even if we did, some gates that have a constant input from self
  // might depend on this party, even if others don't).
  // So, we keep track of each partner's share, so that if they're not involved
  // in a given gate (that involves a constant input wire from self), then self
  // can modify their own share to adjust it by this amount.
  // Outer-vector has length: num inputs from self; the DataType of each entry
  // 'i' matches the DataType of the present party's i^th input.
  std::vector<math_utils::GenericValue> partners_shares_of_my_inputs_;

  // For by-level evaluation only, this keeps track of how many gates
  // on the present level require OT communication with this partner.
  std::vector<GateIndexDataType> gmw_gates_this_level_;

  // Sleep timer (for waiting for communication from this Partner).
  test_utils::ExponentialEachNFailuresSleepTimer receive_communication_sleep_;
  // Sleep timer (for waiting for another thread to populate bytes_to_send_).
  test_utils::ExponentialEachNFailuresSleepTimer send_communication_sleep_;

  // --------------------------------- OT fields -------------------------------
  // OT parameters for engaging in the OT protocol; since this Party may act
  // as the `Server' for some partners and `Client' for others, we have fields
  // that can store parameters for either Server or Client; at most one set
  // of fields should be populated.
  // NOTE: As specified in gmw_server.h, we adopt the convention that when
  // Party i interacts with Party j, Party i will act as the Server iff i < j.
  std::unique_ptr<ServerOTParams> server_ot_params_;
  std::vector<ServerSecretPair> server_ot_secrets_;
  std::unique_ptr<ClientOTParams> client_ot_params_;
  std::vector<ClientSelectionBitAndSecret>
      client_ot_selection_bits_and_output_secret_;
  // If OT bits need to be generated, this specifies whether to use truly random
  // values to generate random secrets (pairs), or use a (seeded) deterministic
  // Random Number Generator.
  // If empty, use truly random; otherwise, use this vector (must have length
  // exactly 16) as a seed.
  std::vector<unsigned char> ot_bits_prg_seed_;
  // The name of the file where OT bits can be read, for this partner.
  std::string ot_bits_file_;
  // The next character (byte) to read from ot_bits_file_.
  uint64_t ot_bits_file_next_char_;
  // The Server's OT bits (for constructing the obfuscated truth tables).
  ReadWriteQueue<TruthTableMask<bool>> server_ot_bits_;
  // The Client's OT bits will be used as selection bits for the Server's
  // Obfuscated Truth Table.
  ReadWriteQueue<SelectionBitAndValuePair<bool>> client_ot_bits_;
  // Randomness to use (if parent party is Server) during gate evaluation.
  std::vector<unsigned char> server_randomness_;
  uint64_t server_randomness_current_byte_;
  char server_randomness_current_bit_;

  PartnerInfo() :
      bytes_to_send_(1),
      receive_communication_sleep_(),
      send_communication_sleep_() {
    socket_ = nullptr;
    connection_properties_ = nullptr;
    socket_info_ = "";
    server_ot_params_ = nullptr;
    client_ot_params_ = nullptr;
    ot_bits_file_next_char_ = 0;
    server_randomness_current_byte_ = 0;
    server_randomness_current_bit_ = 0;
  }
};

class GmwByGate {
public:
  GmwByGate() : circuit_() {
    compute_gates_locally_ = true;
    eval_by_gate_ = false;
    self_party_index_ = -1;
    session_id_ = 0;
    inputs_already_shared_ = false;
    /* We used to use all available cores (only up to three are actually used),
     * but the unit tests actually ran faster when num_threads_ = 1. While
     * this may have been a product of how the tests were run (i.e. on a single
     * machine for Client and Server, sharing resources/cores), for now we
     * use what appears to be the best performer, which is num_threads_ = 1.
     * TODO(paul): Run unit tests on multiple machines, to determine if fewer
     * threads really is faster.
    // Default is to use all available threads.
    const int num_cores = GetNumCores();
    num_threads_ = num_cores > 0 ? num_cores : 1;
    */
    num_threads_ = 1;
    // We only use one thread for the underlying CircuitByGate (independent of how
    // many threads are available on the system), since that subclass is only used
    // for ReadCircuitFile() and EvaluateCircuit(), each of which cannot be (are not)
    // partitioned into multiple threads.
    circuit_.SetNumThreads(1);
    SetNumTasksUntilContextSwitch();
    is_circuit_file_metadata_done_ = false;
    is_ot_bits_gen_done_ = false;
    is_parse_input_file_done_ = false;
    is_input_exchanged_done_ = false;
    is_circuit_file_done_ = false;
    is_read_ot_bits_done_ = false;
    is_evaluate_circuit_done_ = false;
    write_ot_to_file_ = true;
    ot_bits_dir_ = std::string(kOtBitsDir);
    elliptic_curve_based_dh_ = false;
    base_ot_ = OTProtocol::PAILLIER;
    output_filename_ = "";
    excel_logging_file_ = "";
    timeout_ms_ = 0;
    debug_ = false;
    send_sleep_time_ = 0;
    ot_sleep_time_ = 0;
    receive_selection_bit_sleep_time_ = 0;
    receive_obfuscated_truth_table_sleep_time_ = 0;
    evaluate_circuit_sleep_time_ = 0;
  }

  explicit GmwByGate(const int party_index) : GmwByGate() {
    self_party_index_ = party_index;
  }
  explicit GmwByGate(const bool inputs_already_secret_shared) : GmwByGate() {
    inputs_already_shared_ = inputs_already_secret_shared;
  }
  GmwByGate(const bool inputs_already_secret_shared, const int party_index) :
      GmwByGate() {
    inputs_already_shared_ = inputs_already_secret_shared;
    self_party_index_ = party_index;
  }
  GmwByGate(const int party_index, const std::string& circuit_file) :
      GmwByGate() {
    self_party_index_ = party_index;
    circuit_.SetCircuitFilename(circuit_file);
  }
  GmwByGate(
      const bool inputs_already_secret_shared,
      const int party_index,
      const std::string& circuit_file) :
      GmwByGate() {
    inputs_already_shared_ = inputs_already_secret_shared;
    self_party_index_ = party_index;
    circuit_.SetCircuitFilename(circuit_file);
  }
  void SetSelfPartyIndex(const int party_index) {
    self_party_index_ = party_index;
  }
  int GetSelfPartyIndex() const { return self_party_index_; }
  void SetSessionId(const uint64_t& id) { session_id_ = id; }

  void SetEvalByGate(const bool by_gate) { eval_by_gate_ = by_gate; }
  void InitializePrelimGateEvalDataHolder(const uint64_t& level) {
    const GateIndexDataType num_gates = circuit_.num_gates_per_level_[level];
    prelim_eval_info_.clear();
    prelim_eval_info_.resize(num_gates);
    for (PartnerInfo& partner_i : partners_) {
      partner_i.gmw_gates_this_level_.clear();
      partner_i.gmw_gates_this_level_.reserve(num_gates);
    }
  }
  // Copies provided information to the appropriate spot within prelim_eval_info_.
  void StorePrelimGateInfo(
      const bool is_boolean_value,
      const std::vector<OutputWireLocation>& output_wires,
      const math_utils::GenericValue& output_value) {
    prelim_eval_info_[circuit_.num_curr_level_gates_processed_]
        .is_boolean_gate_ = is_boolean_value;
    prelim_eval_info_[circuit_.num_curr_level_gates_processed_].output_wires_ =
        output_wires;
    prelim_eval_info_[circuit_.num_curr_level_gates_processed_].local_value_ =
        output_value;
  }

  void SetThreadStatus(const CircuitByGateTask task, const ThreadStatus status) {
    map_utils::InsertOrReplace(thread_status_, task, status);
  }
  ThreadStatus GetThreadStatus(const CircuitByGateTask task) {
    return thread_status_[task];
  }

  int GetNumThreads() const { return num_threads_; }
  void SetNumThreads(const int num_threads) { num_threads_ = num_threads; }

  void SetWriteOtToFile(const bool write_ot_to_file) {
    write_ot_to_file_ = write_ot_to_file;
  }

  void SetPartnerConnectionTimeout(const uint64_t& timeout_ms) {
    timeout_ms_ = timeout_ms;
  }

  // The following set values on the xxx_thread_num_tasks_until_context_switch_
  // member variables (for both current class and parent class CircuitByGate).
  // The rules for how these get set should respect the number of threads:
  //   - If num_threads_ == 1, then all tasks happen sequentially, and so
  //     all the xxx_context_switch_ fields should be set to the same value
  //   - If num_threads_ == 2, then the Read OT bits task is done separately,
  //     while the other tasks (Read Circuit File, Evaluate Gates) are done
  //     sequentially. Thus, field for the former can be anything (e.g. -1),
  //     while the latter two should match.
  //   - If num_threads_ >= 3, then each task is done independent of the others,
  //     and hence these values can be set independent of each other (e.g. each -1).
  void SetNumTasksUntilContextSwitch(
      const int64_t& num_bytes, const int64_t& num_tasks) {
    read_ot_bits_thread_num_tasks_until_context_switch_ = num_bytes;
    const int64_t num_tasks_for_eval = num_threads_ <= 2 ? num_tasks : -1;
    circuit_.SetNumTasksUntilContextSwitch(false, num_tasks_for_eval, num_tasks);
  }
  void SetNumTasksUntilContextSwitch(const int64_t& num_bytes) {
    SetNumTasksUntilContextSwitch(
        num_bytes,
        (num_threads_ <= 1 ?
             num_bytes :
             (num_threads_ <= 2 ? kDefaultNumGatesToProcessBeforeThreadSwitch :
                                  -1)));
  }
  void SetNumTasksUntilContextSwitch() {
    SetNumTasksUntilContextSwitch(num_threads_ <= 1 ? kDefaultReadFewBytes : -1);
  }
  void SetExcelLoggingFile(const std::string& filename) {
    excel_logging_file_ = filename;
  }

  // API's for the primary tasks:
  //   (0) Run OT protocol to generate OT Bits
  //   (i) Read Circuit File
  //  (ii) Read Global Inputs File
  // (iii) Send/Receive global inputs
  //  (iv) Read OT Bits File
  //   (v) Evaluate Circuit
  // These can either be done all at once via DoAll(), or they can be called separately.
  // In the former case, concurrency is handled automatically (optimizes parallelization
  // and sequence of processing circuit file, input file, and circuit evaluation).
  // In the latter case, concurrency is handled by the caller, with features:
  //   - If is_done is NULL, then Sleep() whenever not able to continue
  //     (which can happen when memory caps are hit, or if prequisite
  //     processing hasn't been done yet, etc.)
  //   - If is_done is non-null, then return whenever not able to continue
  //     (is_done will be false in this case).
  // Here, 'not able to continue' means:
  //   - Within ReadCircuitFile():
  //       a) Memory limit (of gates_) is reached; OR
  //       b) read_gates_thread_num_tasks_until_context_switch_ is reached
  //   - Within ParseGlobalInputs():
  //       a) Input DataTypes haven't yet been read (from circuit file metadata)
  //   - Within GenerateOtBits():
  //   - Within ReadOtBitsFile():
  //   - Within ExchangeGlobalInputs():
  //   - Within Send/Receive Values:
  //   - Within EvaluateCircuit():
  //       a) Circuit File metadata not read yet; OR
  //       b) Global inputs not read yet; OR
  //       c) No more gates ready to process (haven't read enough from circuit file); OR
  //       d) eval_gates_thread_num_tasks_until_context_switch_ is reached
  //       e) Missing input wire value; i.e. awaiting a value to be sent by
  //          another Party.
  // Note that caller is responsible for overriding default values, i.e. if
  // passing NULL is_done, probably should use the SetNumTasksUntilContextSwitch
  // API to set each xxx_thread_num_tasks_until_context_switch_ to -1.
  // Different APIs for DoAll():
  //   - How inputs are specified: as string (input file or list of inputs) vs.
  //     already parsed into vector<GenericValue>
  //   - Whether connection (to partners) info is provided, and if so,
  //     whether connections are handled via RabbitMQ or direct IP/PORT.
  //     NOTE: Although the first API appears to support both connection types,
  //     it will toggle behavior by:
  //       - For RabbitMQ connections: num_parties, rabbitmq_[ip,port] should
  //         all be set, and connect_ips, listen_ips, and ports should be empty.
  //       - For IP/PORT connections: rabbitmq_[ip,port] should be empty/0,
  //         and connect_ips, listen_ips, and ports should all be set
  //         (num_parties can be -1 or be accurately set; in the former case it
  //         can be determined indirectly by the number of ips/ports provided).
  bool DoAll(
      const int num_parties,
      const std::vector<networking::SocketParams*>& connection_properties,
      const std::string& inputs,
      const std::string& outputs_file) {
    return DoAll(
        num_parties,
        connection_properties,
        inputs,
        std::vector<math_utils::GenericValue>(),
        outputs_file);
  }
  // Same as above, alternate API for specifying inputs.
  bool DoAll(
      const int num_parties,
      const std::vector<networking::SocketParams*>& connection_properties,
      const std::vector<math_utils::GenericValue>& inputs,
      const std::string& outputs_file) {
    return DoAll(num_parties, connection_properties, "", inputs, outputs_file);
  }
  // Initial Sync with all Partners, to agree on circuit/function being run,
  // each party's role (which inputs they provide), generate OT bits, etc.
  bool InitialSync();
  // Used as a sub-routine of the above, actually sends/receives the communication
  // to each partner.
  bool InitialSync(std::map<int, GateIndexDataType>* ot_partners);
  // The input indicates which partners to run Beaver's offline generation of
  // OT bits, based on at least one of the peers not already having the
  // requisite bits (file).
  // As output, OT bits are saved to disk (in ot_bits_file_) for each PartnerInfo.
  bool GenerateOtBits(const std::map<int, GateIndexDataType>& partners);
  bool ReadOtBitsFile(bool* is_done);
  bool ReadCircuitFile(const bool parse_function_formula, bool* is_done);
  // Input can either be a filename or a string representation of all of this
  // party's inputs; will determine which is which based on:
  //   1) If a comma appears, treat as string of inputs
  //   2) If equal sign appears, treat as string of inputs
  //   3) Otherwise, treat as filename
  // NOTE: Set all_parties_inputs = true if 'inputs' represents the (secret-shared)
  // inputs from ALL parties (typically, this is true iff inputs_already_shared_ is true).
  bool ParseGlobalInputs(
      const bool all_parties_inputs, const std::string& inputs) {
    return ParseGlobalInputs(
        all_parties_inputs, inputs, std::vector<math_utils::GenericValue>());
  }
  // Same as above, alternate API for specifying inputs.
  bool ParseGlobalInputs(
      const bool all_parties_inputs,
      const std::vector<math_utils::GenericValue>& inputs) {
    return ParseGlobalInputs(all_parties_inputs, "", inputs);
  }
  bool ExchangeGlobalInputs();
  // In case Parties already have secret-shared the inputs (i.e. input_ represents
  // the present party's shares of all inputs), no need to call ExchangeGlobalInputs().
  // Since that function also loads the (global) input wires, the following function
  // does just that.
  bool LoadGlobalInputShares();
  // In order to support GMW computation of gates between only the requisite parties
  // (so that parties whose inputs are not (in)directly involved in the gate inputs
  // need not participate), we need to respect the INVARIANT on the input wires:
  // The actual input value for an input wire is shared *between relevant parties*
  // (see gmw_circuit.h, discussion point (2)). This means that when a party dealt
  // shares of its own inputs to each player (and then subtracted all these shares
  // from the actual input value to arrive at his own share value), that those
  // shares respect the invariant on a given input wire iff all parties are involved
  // in the corresponding gate computation. If not, we need to treat the shares
  // of non-participating parties as '0', and then readd their share values back
  // to the original party's self share (using partners_[].partners_shares_of_my_inputs_).
  // NOTE: This function is defined inline below for linking purposes (so that
  // executables that use standard_circuit_by_gate.o, but DON'T otherwise need
  // gmw_circuit_by_gate, don't need to link gmw_circuit_by_gate.o).
  void AdjustInputValue(
      const int input_index,
      const int bit_index,
      const std::vector<char>& depends_on,
      math_utils::GenericValue* value) {
    if (bit_index >= 0) {
      math_utils::DataType input_type = math_utils::DataType::UNKNOWN;
      unsigned char num_bytes_in_type = 0;
      unsigned char temp = 0;
      int byte_index;
      for (int i = 0; i < (int) partners_.size(); ++i) {
        if (i == self_party_index_) continue;
        if (!GateDependsOn(i, depends_on)) {
          if (input_type == math_utils::DataType::UNKNOWN) {
            input_type =
                partners_[i].partners_shares_of_my_inputs_[input_index].type_;
            num_bytes_in_type = (unsigned char) GetValueNumBytes(input_type);
            temp = 0;
            byte_index = num_bytes_in_type - 1 - bit_index / CHAR_BIT;
          }
          const std::vector<unsigned char> party_i_share =
              GetTwosComplementByteString(
                  partners_[i].partners_shares_of_my_inputs_[input_index]);
          temp = (unsigned char) (temp ^ party_i_share[byte_index]);
        }
      }
      const bool temp_bit = (temp >> (bit_index % CHAR_BIT)) & 1;
      if (temp_bit) *value += math_utils::GenericValue(true);
    } else {
      for (int i = 0; i < (int) partners_.size(); ++i) {
        if (i == self_party_index_) continue;
        if (!GateDependsOn(i, depends_on)) {
          *value += partners_[i].partners_shares_of_my_inputs_[input_index];
        }
      }
    }
  }

  bool EvaluateCircuit(
      const bool should_send, const bool should_receive, bool* is_done);
  bool EvaluateGate(
      const bool should_send,
      const bool should_receive,
      const bool is_mult_by_constant,
      const math_utils::CircuitOperation op,
      const std::vector<char>& depends_on,
      const math_utils::GenericValue& left,
      const math_utils::GenericValue& right,
      bool* store_result,
      math_utils::GenericValue* output);
  bool EvaluateLevel(
      const bool is_boolean_circuit,
      const bool should_send,
      const bool should_receive);
  bool ExchangeOutputShares();

  // Prints outputs, as well as desired prefix and suffix, and optionally
  // extra metadata (Circuit/function, Party Input (types), self-input values).
  bool PrintOutputs(
      const bool print_output,
      const bool print_metadata,
      const bool print_timers,
      const bool print_socket_info,
      const std::string& prefix,
      const std::string& suffix,
      const std::string& filename);
  // Returns party_outputs_.
  std::vector<math_utils::GenericValue> GetOutputs() const {
    return party_outputs_;
  }
  // Returns circuit_.global_outputs_.
  // Note: These represent this Party's shares of the outputs. To get
  // the actual outputs (at least those that this Party is able to get),
  // use GetOutputs().
  std::vector<math_utils::GenericValue> GetOriginalOutputs() const {
    return circuit_.global_outputs_;
  }
  // Returns circuit_.output_designations_.
  std::vector<std::pair<OutputRecipient, math_utils::DataType>>
  GetOutputDesignations() const {
    return circuit_.output_designations_;
  }

  void SetOtBitsDir(const std::string& dir) { ot_bits_dir_ = dir; }
  void SetOtParams(
      const bool use_ec_for_dh, const OTProtocol base_ot) {
    elliptic_curve_based_dh_ = use_ec_for_dh;
    base_ot_ = base_ot;
  }

  void SetDebug(const bool set_debug) {
    debug_ = set_debug;
    circuit_.SetDebug(set_debug);
    for (int i = 0; i < (int) partners_.size(); ++i) {
      if (i == self_party_index_) continue;
      partners_[i].socket_->ActivateTimers(set_debug);
    }
  }
  std::string PrintTimerInfo() const;

private:
  // -------------------------- Generic circuit fields -------------------------
  CircuitByGate circuit_;
  int num_threads_;

  // The party index is used to keep track of which inputs come from where,
  // who acts as Server/Client in each pairing of 2-party communication, etc.
  // It is defined to match the function fingerprint (LHS): which set of inputs
  // the present party holds. The party index could conceivable be determined by:
  //   a) Specified upon construction
  //   b) Manually set
  //   c) Determined based on function description (in circuit file metadata)
  //      together with the variable names of this party's input
  // Since the current specification of a Party's (global) inputs does *not*
  // include the variable name (just the DataType and Value), we don't
  // currently support (c); option (a) is supported via the appropriate
  // GmwByGate() constructor, and option (b) is via SetSelfPartyIndex().
  int self_party_index_;

  // A session-id, to distinguish a given MPC execution from others.
  uint64_t session_id_;

  // Information about the other parties (including self), including:
  //   Socket, OT bits, Bits to send/Received bits, etc.
  // This vector is arranged consistent with function fingerprint (LHS),
  // so that the first entry in partners_ will correspond to the Party
  // whose inputs appear first in the function description (LHS).
  std::vector<PartnerInfo> partners_;
  // The order in which the present party should communicate with partners.
  // This is an efficiency speed-up, reducing communication cost from
  // O(n^2) to O(n): instead of having one party talk to all partners,
  // then having next party do so, etc., we have parties talk to neighbors
  // (those with indices close to them) first. This keeps track of communication order.
  // NOTE: In order to avoid infinite hanging, this vector (when compared to other
  // parties' vectors) should not have any circularity, e.g P0 is waiting for P1
  // who is waiting for P2 who is waiting for P0. For example, the following
  // property would guarantee there is no circularity:
  //   For Party i, partner_communication_order_[k] == j iff
  //   For Party j, partner_communication_order_[k] == i.
  // The 'nearest-neighbor/telescoping' strategy satisfies the above if the number
  // of parties is even; and otherwise it *almost* satisfies that property (the
  // last party's vector will be off-by-one, i.e. if we were to shift all
  // elements of his vector to the right by one, then the property would hold);
  // but in all cases there won't be circularity (i.e. even in the odd number of
  // parties case, the last party will have to wait for Party 0 and Party 1 to
  // finish communicating before it is able to communicate with Party 0, but
  // there is no circularity).
  std::vector<int> partner_communication_order_;
  uint64_t timeout_ms_;

  // Whether all gates should be computed via GMW, or if XOR and EQ gates
  // should be computed locally.
  bool compute_gates_locally_;
  // Parties can compute all gates for one level, then do one big communication
  // back and forth, and then proceed to the next level; or parties can
  // communicate once per gate. There are trade-offs, depending on communication
  // properties between parties.
  bool eval_by_gate_;

  // The following are used for by-level circuit evaluation only. They enable
  // each party (Client and Server) to locally compute as much as they
  // can for each gate on a level, then do a bulk communication
  // (Client sends OT bits to Server), then have Server finish his
  // work constructing the obfuscated truth tables and returns them to Client
  // in one big communication (and finally Client processes that result).
  // Since the data structures store both per-gate info (output wires,
  // gate type, local value) as well as per-(gate+partner) info, we go
  // ahead and use a single data structure (per gate), and within it,
  // we store per-partner info, including Client vs. Server.
  // This data structure will be maintained by-level, so at any time,
  // it has size equal to the number of gates (not GMW gates, but
  // *all* gates; this is because the number of GMW gates per level
  // is *not* a constant, but depends on the Player, and more specifically,
  // on the (player, partner) pair) on that level.
  std::vector<PrelimEvalInfoPerLevel> prelim_eval_info_;

  // Fields to keep track of which tasks have been completed.
  bool is_circuit_file_metadata_done_;
  bool is_ot_bits_gen_done_;
  bool is_parse_input_file_done_;
  bool is_input_exchanged_done_;
  bool is_circuit_file_done_;
  bool is_read_ot_bits_done_;
  bool is_evaluate_circuit_done_;
  std::map<CircuitByGateTask, ThreadStatus> thread_status_;
  int64_t read_ot_bits_thread_num_tasks_until_context_switch_;

  // OT flags:
  bool write_ot_to_file_;
  //  - The name of the directory to place OT bits.
  std::string ot_bits_dir_;
  //  - EC vs. DH toggle (only relevant if using DiffieHellman for base OT).
  bool elliptic_curve_based_dh_;
  //  - Base OT toggle (Paillier, DH).
  OTProtocol base_ot_;

  // The name of the file to write the (Server's shares of the) circuit output.
  std::string output_filename_;

  // The name of the logging file to write to (for use with Excel Plugin)
  std::string excel_logging_file_;

  // The circuit outputs (in circuit_.global_outputs_) represent the output
  // *shares*. These shares are recombined (via ExchangeOutputShares()) and
  // stored in party_outputs_.
  // Note: This Party will only get the outputs he is entitled to (i.e. if
  // the OutputRecipient of the corresponding output is all_ or has this
  // Party's index in to_). However, party_outputs_.size() will always equal
  // circuit_.global_outputs_.size(); for those outputs 'i' that this Party is
  // *not* entitled, party_outputs_[i] = circuit_.global_outputs_[i] (i.e.
  // party_outputs_ will hold this Party's share of output i).
  std::vector<math_utils::GenericValue> party_outputs_;

  // ---------------------------- Global Inputs fields -------------------------
  // This Party's input to the circuit. Typically, these represent the pre-
  // shared values; but with 'inputs_already_shared_' set to true, this can
  // represent this Party's share of *all* the inputs.
  std::vector<math_utils::GenericValue> input_;
  bool inputs_already_shared_;

  // ---------------------------- Debugging ------------------------------------
  bool debug_;
  test_utils::Timer parse_global_inputs_timer_;
  test_utils::Timer load_global_inputs_timer_;
  test_utils::Timer generate_ot_bits_timer_;
  test_utils::Timer load_ot_bits_timer_;
  test_utils::Timer send_initial_sync_timer_;
  test_utils::Timer receive_initial_sync_timer_;
  test_utils::Timer exchange_global_inputs_timer_;
  test_utils::Timer evaluate_circuit_timer_;
  test_utils::Timer evaluate_level_timer_;
  test_utils::Timer evaluate_gate_timer_;
  test_utils::Timer send_selection_bits_timer_;
  test_utils::Timer receive_selection_bits_timer_;
  test_utils::Timer send_obf_tt_timer_;
  test_utils::Timer receive_obf_tt_timer_;
  test_utils::Timer exchange_outputs_timer_;
  test_utils::Timer main_thread_timer_;
  test_utils::Timer do_all_timer_;
  uint64_t send_sleep_time_;
  uint64_t ot_sleep_time_;
  uint64_t receive_selection_bit_sleep_time_;
  uint64_t receive_obfuscated_truth_table_sleep_time_;
  uint64_t evaluate_circuit_sleep_time_;

  // ---------------------------- Internal Functions ---------------------------
  bool SetupOtParams(const int party);
  bool SetupPartnerInfo(
      const int num_parties,
      const std::vector<networking::SocketParams*>& connection_properties);
  bool DoAll(
      const int num_parties,
      const std::vector<networking::SocketParams*>& connection_properties,
      const std::string& inputs_as_string,
      const std::vector<math_utils::GenericValue>& inputs,
      const std::string& outputs_file);
  bool ParseGlobalInputs(
      const bool all_parties_inputs,
      const std::string& inputs_as_string,
      const std::vector<math_utils::GenericValue>& inputs);
  // Sets circuit_.thread_status_ by inserting status UNSTARTED for each task.
  void InitializeThreadStatus();

  // Sends next 'num_bytes' in partners_[i].bytes_to_send_ to Partner i
  // (for i = partner_index).
  bool SendToPartner(
      const bool send_num_bytes,
      const int partner_index,
      const uint64_t& num_bytes);
  // Similar to above, but send contents of 'to_send' (as opposed to using
  // partner's bytes_to_send_ buffer).
  bool SendToPartner(
      const int partner_index, const std::vector<unsigned char>& to_send);
  // Listens for communication (num_bytes) from Partner i, stores in
  // partners_[i].received_bytes_ (for i = partner_index).
  // NOTE: There are only two valid calls to this API:
  //   i) If num_bytes > 0, then should Listen() until this many bytes
  //      have been received
  //  ii) If num_bytes = 0, then the first 8 bytes indicate how many more
  //      bytes to expect; i.e. the stop condition is the function
  //      ReceiveInt64Bytes.
  bool ReceiveFromPartner(
      const bool reset_connection,
      const int partner_index,
      const uint64_t& num_bytes,
      const int num_received_bytes_to_ignore);

  // Performs a single Gate Evaluation.
  bool EvaluateNonLocalBooleanGate(
      const bool should_send,
      const bool should_receive,
      const math_utils::CircuitOperation op,
      const std::vector<char>& depends_on,
      const bool& left,
      const bool& right,
      bool* output);
  bool EvaluateNonLocalBooleanGatePrelim(
      const bool should_send,
      const bool should_receive,
      const math_utils::CircuitOperation op,
      const std::vector<char>& depends_on,
      const bool& left,
      const bool& right,
      bool* store_result,
      bool* output);
  bool EvaluateNonLocalArithmeticGate(
      const bool should_send,
      const bool should_receive,
      const math_utils::CircuitOperation op,
      const std::vector<char>& depends_on,
      const math_utils::GenericValue& left,
      const math_utils::GenericValue& right,
      math_utils::GenericValue* output);
  bool EvaluateBooleanLevel(const bool should_send, const bool should_receive);
  bool EvaluateArithmeticLevel(
      const bool should_send, const bool should_receive);
  // Computes the local terms for this operation; see comments at top of gmw_circuit.h.
  bool ComputeLocalValue(
      const int num_dependent_parties,
      const int lowest_party_index,
      const math_utils::CircuitOperation op,
      const bool& left,
      const bool& right,
      bool* output);

  bool IsProgressBeingMade(
      const SleepReason reason, const ThreadStatus ot_reading_status);
};

// A non-member way to call (member function) EvaluateGate; this is needed so that
// standard_circuit_by_gate::EvaluateCircuit() can call GmwByGate::EvaluateGate(),
// WITHOUT needing to include gmw_circuit_by_gate.o when linking standard_circuit_by_gate
// (In other words, we could remove the following if we just had
// standard_circuit_by_gate::EvaluateCircuit() call parent->EvaluateGate().
// But this would mean that we need to link gmw_circuit_by_gate.o for any executable
// that needs standard_circuit_by_gate. And since the former unnecessarily inflates
// executable size (e.g. now networking, OT, etc. code needs to be linked), we save
// on this for executables that don't actually use the "parent" (i.e. the
// GmwByGate object) passed into standard_circuit_by_gate::EvaluateCircuit()).
inline bool EvaluateGateFunctionPointer(
    GmwByGate* parent,
    const bool should_send,
    const bool should_receive,
    const bool is_mult_by_constant,
    const math_utils::CircuitOperation op,
    const std::vector<char>& depends_on,
    const math_utils::GenericValue& left,
    const math_utils::GenericValue& right,
    bool* store_result,
    math_utils::GenericValue* output) {
  return parent->EvaluateGate(
      should_send,
      should_receive,
      is_mult_by_constant,
      op,
      depends_on,
      left,
      right,
      store_result,
      output);
}
// Ditto above, for EvaluateLevel()
inline bool EvaluateLevelFunctionPointer(
    GmwByGate* parent,
    const bool is_boolean_circuit,
    const bool should_send,
    const bool should_receive) {
  return parent->EvaluateLevel(is_boolean_circuit, should_send, should_receive);
}

}  // namespace multiparty_computation
}  // namespace crypto

#endif
