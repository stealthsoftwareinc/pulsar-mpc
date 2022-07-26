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
// Usage:
//   This is mostly copy-pasted from n_party_mpc_by_gate.cpp, with differences:
//     1) This is a non-main (non-executable), and so is invoked by some
//        other executable
//     2) The 'n_party_cookie_socket_nonmain()' API takes in an additional
//        parameter 'cookie_sockets', which (if non-empty) provides the
//        connection info between the parties.
//   Otherwise, usage is the same, so you can forward on to the 'nonmain' API
//   the following arguments:
//   --circuit FILENAME.circuit_by_gate
//   --input "x1 = a, x2 = b, ..." [or --input_file INPUTS_FILE]
//   CONNECTION_INFO
//   [--base_ot BASE_OT_TYPE] [--dh_group DH_GROUP]
//   [--input_preshared] [--ot_dir OT_DIRECTORY]
//   [--out FILENAME.txt] [--print[_only]]
//   [--session_id ID] [--timeout TIMEOUT_SECONDS] [--debug[ | 0 | 1 | 2 | 3]]
// where:
//   - FILENAME: Specifies the path to the .circuit_by_gate file to be processed
//   - x1 = a, x2 = b, ...: The variable names and values for this Party’s input
//   - CONNECTION_INFO: Specifies how parties communicate. This must take
//     one of two forms:
//      IP/PORT:  In this case, each party specifies an IP and PORT for all
//                other parties, e.g.:
//                  --[connect | listen]_ip_k IP_k --port_k PORT_k
//                where the IP is the *listen* IP if this party has a smaller
//                index than its partner, otherwise it is the connect IP.
//                Note that a Party's index is defined by the function fingerprint
//                (LHS of the function formula) in the .circuit_by_gate file,
//                i.e. for f(x; y; z) = ..., then Party 0 provides 'x', etc.
//                The specific IP used can be "localhost" or "network", or an IP
//                address of format xxx.xx.x.xxx. If the present party will act
//                as a server with this partner (whichever party has the lower
//                Party index is the server), then IP_k can be omitted (default
//                is to listen on 0.0.0.0); but if acting as Client, then
//                connect_ip must be provided.
//      RabbitMQ: In this case, the IP/PORT of the RabbitMQ server should be
//                provided. Additionally, we require explicit info on the
//                number of parties and the present party's index (this info
//                could be gleaned from the connect/listen ip's if using the
//                non-rabbitmq sockets, but most be provided directly here):
//                  --num_parties N --self_index i --rabbitmq_ip IP --rabbitmq_port PORT
//                Finally, there are optional arguments that can be provided:
//                  --[no]rabbitmq_ssl_verify_peer
//                  --[no]rabbitmq_ssl_verify_hostname
//                  --rabbitmq_ssl_ca_cert_file FILENAME
//                  --rabbitmq_ssl_client_cert_file FILENAME
//                  --rabbitmq_ssl_client_key_file FILENAME
//                  --rabbitmq_use_ssl
//                  --rabbitmq_user USERNAME
//                  --rabbitmq_pwd PASSWORD
//                  --send_queuename[_i] QUEUENAME:
//                      This will label the Send queue to Partner i with the name
//                      'QUEUENAME' (no spaces or punctuation allowed.)
//                      If [_i] is *not* provided, then this party's Send queue
//                      to every Partner i will be labelled: j_QUEUENAME_i,
//                      where 'j' is the self-party index.
//                  --rec_queuename[_i] QUEUENAME:
//                      Ditto above, for the Receive queue.
//                      Also, if [_i] is *not* provided, this party's Receive
//                      queue from every Partner i will be labelled: i_QUEUENAME_j,
//                      where 'j' is the self-party index (note the location
//                      of self-index 'j' vs. other party index 'i' has been
//                      flip-flopped in comparison to how Send queue is handled;
//                      this is necessary for compatibility/symmetry between players.
//                  DEPRECATED/NOT_SUPPORTED: --queuename[_i] QUEUENAME:
//                      Similar to above, but applies QUEUENAME to both the
//                      Send *and* Receive queues (i.e., the *same* queue will
//                      be used for Sending/Receiving data from each partner).
//                      If [_i] is *not* provided, then the Send/Rec queue
//                      to every Partner i will be labelled: j_QUEUENAME_i,
//                      where 'j' is the self-party index.
//                      UPDATE: We don't support this, as having the Send/Receive
//                      queues have the same label (i.e. this means the same
//                      queue is used for each) is a terrible idea, since you'll
//                      be receiving your own messages!
//                   --[no]declare_send_queue[_i]:
//                      Sets the 'declare_send_queue_' flag of the RabbitMqSocket
//                      corresponding to Partner i (or to all partners, if [_i]
//                      is not present).
//                   --[no]declare_rec_queue[_i]:
//                      Ditto above, for 'declare_rec_queue_' flag.
//                   --[no]declare_queue[_i]:
//                      Ditto above, for 'declare_send_queue_' and 'declare_rec_queue_'.
//   - base_ot: Toggles between Paillier or DH based-OT. Should be one of:
//                { paillier, dh }
//              Default is Paillier.
//   - dh_group: Specifies the DH-group. Should be one of:
//                { dh, ec }
//               Only relevant if base_ot == dh. Default is dh.
//   - input_preshared: Sets GmwByGate::inputs_already_shared_ to true.
//   - (--out) FILENAME: (Optional) Output is written to:
//                          OutputFiles/n_party_mpc_as_party_k_XXX.output,
//                        where 'XXX' is 'OUTPUT_FILENAME' (if provided), otherwise
//                        --session_id (if provided), otherwise timestamp
//   - print: If present, prints output to terminal
//   - print_only: If present, *only* prints output to terminal (i.e. not to file)
//   - ID: (Optional) Specifies an arbitrary session id; currently, this is just
//         used to name the output file (so that output files do not overwrite
//         each other); if no --session_id is provided, will use a timestamp
//   - timeout: The timeout (in Seconds) to use (applied to all partners/connections)
//   - debug: (Optional) If present, must be one of: {debug, debug1, debug2}.
//            Prints extra debug info to terminal and/or output file.
// Examples:
//  a) Two-party evaluation of 'AND' of two bits:
//     Party 0 runs:
//       ./n_party_mpc_by_gate.exe
//       --circuit ../Circuits/CircuitByGateFiles/and.circuit_by_gate
//       --listen_ip_1 localhost --port_1 4444
//       --input "x=0" --out OutputFiles/n_party_AND_as_0.output
//     Party 1 runs:
//       ./n_party_mpc_by_gate.exe
//       --circuit ../Circuits/CircuitByGateFiles/and.circuit_by_gate
//       --connect_ip_0 localhost --port_0 4444
//       --input "y=0" --out OutputFiles/n_party_AND_as_1.output
#include "n_party_mpc_by_gate_cookie_socket.h"

#include "Crypto/MultiPartyComputation/Circuits/circuit_builder_utils.h"
#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"  // For OutputRecipient.
#include "Crypto/MultiPartyComputation/Circuits/gmw_circuit.h"
#include "Crypto/MultiPartyComputation/Circuits/gmw_circuit_by_gate.h"
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit_by_gate.h"
#include "Crypto/ObliviousTransfer/oblivious_transfer_utils.h"
#include "FileReaderUtils/read_file_utils.h"
#include "MapUtils/map_utils.h"
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "MathUtils/formula_utils.h"  // For Formula.
#include "Networking/cookie_socket.h"
#include "global_utils.h"
#if (defined(USE_RABBITMQ))
#include "Networking/rabbitmq_socket.h"  // For RabbitMqSocketParams.
#endif
#include "Networking/socket.h"
#include "Networking/socket_utils.h"
#include "TestUtils/timer_utils.h"

#include <fstream>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

using namespace crypto;
using namespace crypto::encryption;
using namespace crypto::multiparty_computation;
using namespace file_reader_utils;
using namespace map_utils;
using namespace math_utils;
using namespace networking;
using namespace string_utils;
using namespace test_utils;
using namespace std;

namespace {

static const char kCircuitDir[] = "CircuitByGateFiles/";
static int kDebugLevel = -1;
static bool kBlockingConnect = false;
static bool kDebugColor = false;
static bool kPrintOutputToTerminal = false;
static bool kPrintOutputToTerminalOnly = false;
static bool kIsFromExcel = false;
static bool kIsInputAlreadyShared = false;

bool ParseInputsFromFile(const string& filename, string* inputs) {
  ifstream input_file(filename.c_str());
  if (!input_file.is_open()) return false;
  int line_num = 0;
  string orig_line, line;
  while (getline(input_file, orig_line)) {
    ++line_num;
    RemoveWindowsTrailingCharacters(&orig_line);
    line = RemoveAllWhitespace(orig_line);
    if (line.empty()) {
      --line_num;
      continue;
    }
    if (line_num > 1) *inputs += ",";
    *inputs += line;
  }
  input_file.close();
  return true;
}

// Simply calling:
//   socket_params->resize(size, new RabbitMqSocketParams());
// does not work, as vector::resize() is not working how I would expect,
// which is by calling 'new RabbitMqSocketParams()' on every element;
// instead what that does is call 'new RabbitMqSocketParams()' *once*,
// and then copy that value to all new elements; the result of which
// is that all new vector elements have the same pointer (to a single
// 'new' RabbitMqSocketParams object that was created.
// Thus, to get the desired property, I need the following to manually
// call 'new RabbitMqSocketParams()' on every new vector element.
void ResizeSocketParams(const int size, vector<SocketParams*>* socket_params) {
#if (defined(USE_RABBITMQ))
  socket_params->reserve(size);
  for (size_t i = socket_params->size(); i < size; ++i) {
    socket_params->push_back(new RabbitMqSocketParams());
  }
#endif
  // Unused parameter compiler warning.
  (void) size;
  (void) socket_params;
}

bool UpdateSocketParams(
    const int provided_index,
    const int required_vec_size,
    const int num_parties,
    const int self_index,
    const bool is_send_queue,
    // Exactly one of the following 2 args gets used (the latter, if non-empty).
    const bool declare,
    const string& queuename,
    vector<SocketParams*>* socket_params) {
#if (defined(USE_RABBITMQ))
  if (socket_params->size() < required_vec_size) {
    ResizeSocketParams(required_vec_size, socket_params);
  }
  if (provided_index < 0) {
    for (size_t j = 0; j < num_parties; ++j) {
      if (j == self_index) continue;
      RabbitMqSocketParams* params_j =
          (RabbitMqSocketParams*) ((*socket_params)[j]);
      params_j->is_default_ = false;
      if (queuename.empty()) {
        if (is_send_queue) params_j->declare_send_queue_ = declare;
        else params_j->declare_rec_queue_ = declare;
      } else {
        if (is_send_queue) {
          params_j->send_queuename_ =
              Itoa(self_index) + "_" + queuename + "_" + Itoa(j);
        } else {
          params_j->rec_queuename_ =
              Itoa(j) + "_" + queuename + "_" + Itoa(self_index);
        }
      }
    }
  } else {
    RabbitMqSocketParams* params_j =
        (RabbitMqSocketParams*) ((*socket_params)[provided_index]);
    params_j->is_default_ = false;
    if (queuename.empty()) {
      if (is_send_queue) params_j->declare_send_queue_ = declare;
      else params_j->declare_rec_queue_ = declare;
    } else {
      if (is_send_queue) params_j->send_queuename_ = queuename;
      else params_j->rec_queuename_ = queuename;
    }
  }
#else
  // Unused parameter compiler warning.
  (void) provided_index;
  (void) required_vec_size;
  (void) num_parties;
  (void) self_index;
  (void) is_send_queue;
  (void) declare;
  (void) queuename;
  (void) socket_params;
  return false;
#endif
  return true;
}

bool ParseArgs(
    int argc,
    const vector<string>& args,
    int* self_index,
    int* num_parties,
    string* rabbitmq_username,
    string* rabbitmq_password,
    string* rabbitmq_ip,
    long* rabbitmq_port,
    vector<string>* listen_ips,
    vector<string>* connect_ips,
    vector<long>* ports,
    unsigned int* timeout,
    bool* write_ot_to_file,
    bool* eval_by_level,
    bool* use_elliptic_curve_dh,
    OTProtocol* base_ot,
    bool* rabbitmq_use_ssl,
    bool* rabbitmq_ssl_verify_peer,
    bool* rabbitmq_ssl_verify_hostname,
    string* rabbitmq_ssl_ca_cert_file,
    string* rabbitmq_ssl_client_cert_file,
    string* rabbitmq_ssl_client_key_file,
    vector<SocketParams*>* socket_params,
    string* session_id,
    string* ot_dir,
    string* outfile_id,
    string* out,
    string* circuit,
    string* inputs,
    string* command) {
  *command = args[0];
  // Start loop at '1' (argument 0 is the executable itself).
  for (int i = 1; i < argc; ++i) {
    string arg = ToLowerCase(args[i]);
    *command += " " + arg;
    arg = Strip(arg, "%20");
    if (arg == "--debug") {
      kDebugLevel = 0;
    } else if (arg == "--debug0") {
      kDebugLevel = 0;
    } else if (arg == "--debug1") {
      kDebugLevel = 1;
    } else if (arg == "--debug2") {
      kDebugLevel = 2;
    } else if (arg == "--debug3") {
      kDebugLevel = 3;
    } else if (arg == "--from_excel") {
      kIsFromExcel = true;
    } else if (arg == "--input_preshared") {
      kIsInputAlreadyShared = true;
    } else if (arg == "--far") {
      kBlockingConnect = true;
    } else if (HasPrefixString(arg, "--listen_ip_")) {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--listen_ip'.");
        return false;
      }
      const string suffix = StripPrefixString(arg, "--listen_ip_");
      int party;
      if (!Stoi(suffix, &party) || party < 0) {
        LOG_ERROR("Invalid Party index: " + arg);
        return false;
      }
      if ((int) listen_ips->size() <= party) listen_ips->resize(1 + party);
      ++i;
      *command += " " + args[i];
      (*listen_ips)[party] = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (HasPrefixString(arg, "--connect_ip_")) {
      const string suffix = StripPrefixString(arg, "--connect_ip_");
      int party;
      if (!Stoi(suffix, &party) || party < 0) {
        LOG_ERROR("Invalid Party index: " + arg);
        return false;
      }
      if ((int) connect_ips->size() <= party) connect_ips->resize(1 + party);
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--connect_ip'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      (*connect_ips)[party] = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (HasPrefixString(arg, "--port_")) {
      const string suffix = StripPrefixString(arg, "--port_");
      int party;
      if (!Stoi(suffix, &party) || party < 0) {
        LOG_ERROR("Invalid Party index: " + arg);
        return false;
      }
      if ((int) ports->size() <= party) ports->resize(1 + party, -1);
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--port'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      uint64_t port;
      if (!Stoi(
              ToLowerCase(StripAllEnclosingPunctuationAndWhitespace(args[i])),
              &port)) {
        LOG_ERROR("Unable to parse port as a numeric value: '" + args[i] + "'");
        return false;
      }
      (*ports)[party] = (long) port;
    } else if (arg == "--rabbitmq_user" || arg == "--rabbitmq_username") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rabbitmq_user'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *rabbitmq_username = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (
        arg == "--rabbitmq_password" || arg == "--rabbitmq_pass" ||
        arg == "--rabbitmq_pwd") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rabbitmq_pwd'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *rabbitmq_password = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--rabbitmq_ip") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rabbitmq_ip'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *rabbitmq_ip = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--rabbitmq_port") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rabbitmq_port'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      uint64_t port;
      if (!Stoi(
              ToLowerCase(StripAllEnclosingPunctuationAndWhitespace(args[i])),
              &port)) {
        LOG_ERROR(
            "Unable to parse rabbitmq_port as a numeric value: '" + args[i] +
            "'");
        return false;
      }
      *rabbitmq_port = (long) port;
    } else if (HasPrefixString(arg, "--send_queuename")) {
      // First, see if this applies to all queues, or just one.
      int provided_index = -1;
      string suffix = StripPrefixString(arg, "--send_queuename");
      if (!suffix.empty()) {
        // A (partner) index was provided; parse it.
        if (!Stoi(StripPrefixString(suffix, "_"), &provided_index) ||
            provided_index < 0) {
          LOG_ERROR("Unable to parse arg: '" + args[i] + "'");
          return false;
        }
      }
      if (provided_index < 0 && (*num_parties < 0 || *self_index < 0)) {
        LOG_ERROR(
            "Cannot apply argument '--send_queuename' to all Send queues without "
            "knowing how many players there are and/or this party's index. "
            "You must either first specify the number of players via "
            "'--num_parties' and this party's index via '--self_index', or "
            "specify a partner index i in the flag '--send_queuename_i'");
        return false;
      }
      const int required_vec_size =
          (provided_index < 0) ? *num_parties : provided_index + 1;
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--send_queuename'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      if (!UpdateSocketParams(
              provided_index,
              required_vec_size,
              *num_parties,
              *self_index,
              true,
              true,
              StripAllEnclosingPunctuationAndWhitespace(args[i]),
              socket_params)) {
        LOG_ERROR("Updating SocketParams Failed.");
        return false;
      }
    } else if (HasPrefixString(arg, "--rec_queuename")) {
      // First, see if this applies to all queues, or just one.
      int provided_index = -1;
      string suffix = StripPrefixString(arg, "--rec_queuename");
      if (!suffix.empty()) {
        // A (partner) index was provided; parse it.
        if (!Stoi(StripPrefixString(suffix, "_"), &provided_index) ||
            provided_index < 0) {
          LOG_ERROR("Unable to parse arg: '" + args[i] + "'");
          return false;
        }
      }
      if (provided_index < 0 && (*num_parties < 0 || *self_index < 0)) {
        LOG_ERROR(
            "Cannot apply argument '--rec_queuename' to all Receive queues without "
            "knowing how many players there are and/or this party's index. "
            "You must either first specify the number of players via "
            "'--num_parties' and this party's index via '--self_index', or "
            "specify a partner index i in the flag '--rec_queuename_i'");
        return false;
      }
      const int required_vec_size =
          (provided_index < 0) ? *num_parties : provided_index + 1;
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rec_queuename'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      if (!UpdateSocketParams(
              provided_index,
              required_vec_size,
              *num_parties,
              *self_index,
              false,
              true,
              StripAllEnclosingPunctuationAndWhitespace(args[i]),
              socket_params)) {
        LOG_ERROR("Updating SocketParams Failed.");
        return false;
      }
    } else if (
        HasPrefixString(arg, "--declare_send_queue") ||
        HasPrefixString(arg, "--nodeclare_send_queue")) {
      // First, distinguish between declare vs. nodeclare.
      bool declare;
      string suffix;
      if (HasPrefixString(arg, "--declare_send_queue")) {
        declare = true;
        suffix = StripPrefixString(arg, "--declare_send_queue");
      } else {
        declare = false;
        suffix = StripPrefixString(arg, "--nodeclare_send_queue");
      }
      // Next, see if this applies to all queues, or just one.
      int provided_index = -1;
      if (!suffix.empty()) {
        // A (partner) index was provided; parse it.
        if (!Stoi(StripPrefixString(suffix, "_"), &provided_index) ||
            provided_index < 0) {
          LOG_ERROR("Unable to parse arg: '" + args[i] + "'");
          return false;
        }
      }
      if (provided_index < 0 && *num_parties < 0) {
        LOG_ERROR(
            "Cannot apply argument '--[no]declare_send_queue' to all Send queues "
            "without knowing how many players there are. You must either "
            "first specify the number of players via '--num_parties', or "
            "specify a partner index i in the flag '--[no]declare_send_queue_i'");
        return false;
      }
      const int required_vec_size =
          (provided_index < 0) ? *num_parties : provided_index + 1;
      if (!UpdateSocketParams(
              provided_index,
              required_vec_size,
              *num_parties,
              *self_index,
              true,
              declare,
              "",
              socket_params)) {
        LOG_ERROR("Updating SocketParams Failed.");
        return false;
      }
    } else if (
        HasPrefixString(arg, "--declare_rec_queue") ||
        HasPrefixString(arg, "--nodeclare_rec_queue")) {
      // First, distinguish between declare vs. nodeclare.
      bool declare;
      string suffix;
      if (HasPrefixString(arg, "--declare_rec_queue")) {
        declare = true;
        suffix = StripPrefixString(arg, "--declare_rec_queue");
      } else {
        declare = false;
        suffix = StripPrefixString(arg, "--nodeclare_rec_queue");
      }
      // Next, see if this applies to all queues, or just one.
      int provided_index = -1;
      if (!suffix.empty()) {
        // A (partner) index was provided; parse it.
        if (!Stoi(StripPrefixString(suffix, "_"), &provided_index) ||
            provided_index < 0) {
          LOG_ERROR("Unable to parse arg: '" + args[i] + "'");
          return false;
        }
      }
      if (provided_index < 0 && *num_parties < 0) {
        LOG_ERROR(
            "Cannot apply argument '--[no]declare_rec_queue' to all Send queues "
            "without knowing how many players there are. You must either "
            "first specify the number of players via '--num_parties', or "
            "specify a partner index i in the flag '--[no]declare_rec_queue_i'");
        return false;
      }
      const int required_vec_size =
          (provided_index < 0) ? *num_parties : provided_index + 1;
      if (!UpdateSocketParams(
              provided_index,
              required_vec_size,
              *num_parties,
              *self_index,
              false,
              declare,
              "",
              socket_params)) {
        LOG_ERROR("Updating SocketParams Failed.");
        return false;
      }
    } else if (
        HasPrefixString(arg, "--declare_queue") ||
        HasPrefixString(arg, "--nodeclare_queue")) {
      // First, distinguish between declare vs. nodeclare.
      bool declare;
      string suffix;
      if (HasPrefixString(arg, "--declare_queue")) {
        declare = true;
        suffix = StripPrefixString(arg, "--declare_queue");
      } else {
        declare = false;
        suffix = StripPrefixString(arg, "--nodeclare_queue");
      }
      // Next, see if this applies to all queues, or just one.
      int provided_index = -1;
      if (!suffix.empty()) {
        // A (partner) index was provided; parse it.
        if (!Stoi(StripPrefixString(suffix, "_"), &provided_index) ||
            provided_index < 0) {
          LOG_ERROR("Unable to parse arg: '" + args[i] + "'");
          return false;
        }
      }
      if (provided_index < 0 && *num_parties < 0) {
        LOG_ERROR(
            "Cannot apply argument '--[no]declare_queue' to all Send queues "
            "without knowing how many players there are. You must either "
            "first specify the number of players via '--num_parties', or "
            "specify a partner index i in the flag '--[no]declare_queue_i'");
        return false;
      }
      const int required_vec_size =
          (provided_index < 0) ? *num_parties : provided_index + 1;
      if (!UpdateSocketParams(
              provided_index,
              required_vec_size,
              *num_parties,
              *self_index,
              true,
              declare,
              "",
              socket_params) ||
          !UpdateSocketParams(
              provided_index,
              required_vec_size,
              *num_parties,
              *self_index,
              false,
              declare,
              "",
              socket_params)) {
        LOG_ERROR("Updating SocketParams Failed.");
        return false;
      }
    } else if (arg == "--self_index") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--self_index'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      if (!Stoi(
              ToLowerCase(StripAllEnclosingPunctuationAndWhitespace(args[i])),
              self_index)) {
        LOG_ERROR(
            "Unable to parse self_index as a numeric value: '" + args[i] + "'");
        return false;
      }
    } else if (arg == "--num_parties") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--num_parties'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      if (!Stoi(
              ToLowerCase(StripAllEnclosingPunctuationAndWhitespace(args[i])),
              num_parties)) {
        LOG_ERROR(
            "Unable to parse num_parties as a numeric value: '" + args[i] + "'");
        return false;
      }
    } else if (arg == "--write_ot") {
      *write_ot_to_file = true;
    } else if (arg == "--nowrite_ot") {
      *write_ot_to_file = false;
    } else if (arg == "--by_level") {
      *eval_by_level = true;
    } else if (arg == "--by_gate") {
      *eval_by_level = false;
    } else if (arg == "--dh_group") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--dh_group'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      const string group = StripAllEnclosingPunctuationAndWhitespace(args[i]);
      if (group == "dh") {
        *use_elliptic_curve_dh = false;
      } else if (group == "ec") {
        *use_elliptic_curve_dh = true;
      } else {
        LOG_ERROR("Unrecognized DiffieHellman base group: '" + args[i] + "'");
        return false;
      }
    } else if (arg == "--base_ot") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--base_ot'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      const string base = StripAllEnclosingPunctuationAndWhitespace(args[i]);
      if (base == "paillier") {
        *base_ot = OTProtocol::PAILLIER;
      } else if (base == "dh") {
        *base_ot = OTProtocol::DIFFIE_HELLMAN;
      } else {
        LOG_ERROR("Unrecognized base OT Protocol: '" + args[i] + "'");
        return false;
      }
    } else if (arg == "--rabbitmq_use_ssl") {
      *rabbitmq_use_ssl = true;
    } else if (
        arg == "--rabbitmq_ssl_verify_peer" ||
        arg == "--norabbitmq_ssl_verify_peer") {
      *rabbitmq_ssl_verify_peer = (arg == "--rabbitmq_ssl_verify_peer");
    } else if (
        arg == "--rabbitmq_ssl_verify_hostname" ||
        arg == "--norabbitmq_ssl_verify_hostname") {
      *rabbitmq_ssl_verify_hostname = (arg == "--rabbitmq_ssl_verify_hostname");
    } else if (arg == "--rabbitmq_ssl_ca_cert_file") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rabbitmq_ssl_ca_cert_file'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *rabbitmq_ssl_ca_cert_file =
          StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--rabbitmq_ssl_client_cert_file") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rabbitmq_ssl_client_cert_file'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *rabbitmq_ssl_client_cert_file =
          StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--rabbitmq_ssl_client_key_file") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rabbitmq_ssl_client_key_file'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *rabbitmq_ssl_client_key_file =
          StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--timeout") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--timeout'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      if (!Stoi(
              ToLowerCase(StripAllEnclosingPunctuationAndWhitespace(args[i])),
              timeout)) {
        LOG_ERROR(
            "Unable to parse timeout as a numeric value: '" + args[i] + "'");
        return false;
      }
    } else if (arg == "--session_id") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--session_id'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *session_id = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--out") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--out'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *out = StripQuotes(args[i]);
    } else if (arg == "--ot_dir") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--ot_dir'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *ot_dir = StripQuotes(args[i]);
    } else if (arg == "--outfile_id") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--outfile_id'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *outfile_id = StripQuotes(args[i]);
    } else if (arg == "--circuit") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--circuit'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *circuit = StripQuotes(args[i]);
    } else if (arg == "--input") {
      if (!inputs->empty()) {
        LOG_ERROR("Multiple input sources provided.");
        return false;
      }
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--input'.");
        return false;
      }
      ++i;
      *command += " \"" + args[i] + "\"";
      *inputs = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--input_file") {
      if (!inputs->empty()) {
        LOG_ERROR("Multiple input sources provided.");
        return false;
      }
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--input_file'.");
        return false;
      }
      ++i;
      *command += " \"" + args[i] + "\"";
      if (!ParseInputsFromFile(
              StripAllEnclosingPunctuationAndWhitespace(args[i]), inputs)) {
        LOG_ERROR(
            "Unable to parse inputs file: " +
            StripAllEnclosingPunctuationAndWhitespace(args[i]));
        return false;
      }
    } else if (arg == "--color") {
      kDebugColor = true;
    } else if (arg == "--print") {
      kPrintOutputToTerminal = true;
    } else if (arg == "--print_only") {
      kPrintOutputToTerminal = true;
      kPrintOutputToTerminalOnly = true;
    } else {
      LOG_ERROR("Unexpected command-line argument '" + arg + "'");
      return false;
    }
  }

  // Make sure inputs were provided.
  if (inputs->empty()) {
    LOG_ERROR("You must provide inputs via --input.");
    return false;
  }

  // Make sure a circuit file was specified.
  if (circuit->empty()) {
    LOG_ERROR("You must specifiy --circuit.");
    return false;
  }

  // Make sure circuit (or function) file exists.
  if (!FileExists(*circuit)) {
    // Try searching in kCircuitDir.
    const string temp = *circuit;
    *circuit = kCircuitDir + temp;
    if (!FileExists(*circuit)) {
      LOG_ERROR("Unable to find Circuit file '" + temp + "'");
      return false;
    }
  }

  // Fill out socket_params, if some were provided.
  if (!socket_params->empty() && (int) socket_params->size() < *num_parties) {
    ResizeSocketParams(*num_parties, socket_params);
  }

  return true;
}

bool RunNPartyMpcByGate(
    const bool write_ot_to_file,
    const bool eval_by_level,
    const bool use_elliptic_curve_dh,
    const OTProtocol base_ot,
    const string& command,
    const string& circuit,
    const string& ot_dir,
    const int num_parties,
    const vector<SocketParams*>& connection_properties,
    const unsigned int timeout_secs,
    const int self_party_index,
    const string& inputs,
    const string& output_filename,
    vector<GenericValue>* outputs) {
  // Setup MPC object.
  GmwByGate me(kIsInputAlreadyShared, self_party_index, circuit);
  if (timeout_secs > 0) me.SetPartnerConnectionTimeout(timeout_secs * 1000);
  if (kDebugLevel >= 0) me.SetDebug(true);
  if (kIsFromExcel) {
    // Extract Directory from output file directory.
    me.SetExcelLoggingFile(
        GetDirectory(true, output_filename) + "tmp_mpc_logging.txt");
    me.SetOtBitsDir(GetDirectory(true, output_filename) + "OtBitsFiles\\");
  } else if (!ot_dir.empty()) {
    me.SetOtBitsDir(ot_dir);
  }
  // Change where OT bits are stored.
  if (!write_ot_to_file) {
    me.SetWriteOtToFile(false);
  }
  // Change eval type (by level or by gate).
  if (!eval_by_level) {
    me.SetEvalByGate(true);
  }
  // Change default OT settings iff user specified non-default values.
  if (use_elliptic_curve_dh || base_ot != OTProtocol::PAILLIER) {
    me.SetOtParams(use_elliptic_curve_dh, base_ot);
  }
  // Run MPC.
  if (!me.DoAll(num_parties, connection_properties, inputs, "")) {
    if (kDebugLevel >= 0 && outputs == nullptr) {
      me.PrintOutputs(false, false, true, kDebugLevel >= 2, "", "", "");
    }
    return false;
  }

  // Write output file.
  string to_print = "Command:\n" + command + "\n\n";
  if (!kPrintOutputToTerminalOnly && outputs == nullptr &&
      !me.PrintOutputs(
          true,
          true,
          true,
          kDebugLevel >= 2,
          "Command:\n" + command + "\n\n",
          "",
          output_filename)) {
    return false;
  }

  // Write output to local memory, if appropriate.
  if (outputs != nullptr) {
    *outputs = me.GetOutputs();
    if (kDebugLevel >= 0 &&
        !me.PrintOutputs(
            false,
            kDebugLevel >= 3,
            kDebugLevel >= 0,
            kDebugLevel >= 2,
            "Command:\n" + command + "\n\n",
            "\n",
            "")) {
      return false;
    }
    return true;
  }

  // Will print output to terminal, useful for debugging.
  if (kPrintOutputToTerminal) {
    me.PrintOutputs(
        true, false, kDebugLevel >= 0, kDebugLevel >= 2, "\n", "\n", "");
  }

  // Print debug info, if appropriate.
  if (kDebugLevel >= 0 &&
      !me.PrintOutputs(
          false,
          kDebugLevel >= 3,
          kDebugLevel >= 0,
          kDebugLevel >= 2,
          "Command:\n" + command + "\n\n",
          "\n",
          "")) {
    return false;
  }

  return true;
}

}  // namespace

int n_party_cookie_socket_nonmain(
    int argc,
    char* argv[],
    const vector<CookieSocketParams>& cookie_sockets,
    vector<GenericValue>* outputs) {
  vector<string> args(argc);
  for (int i = 0; i < argc; ++i) {
    args[i] = string(argv[i]);
  }
  return n_party_cookie_socket_nonmain(args, cookie_sockets, outputs);
}

int n_party_cookie_socket_nonmain(
    int argc, char* argv[], const vector<CookieSocketParams>& cookie_sockets) {
  return n_party_cookie_socket_nonmain(argc, argv, cookie_sockets, nullptr);
}

int n_party_cookie_socket_nonmain(
    const vector<string>& args,
    const vector<CookieSocketParams>& cookie_sockets,
    vector<GenericValue>* outputs) {
  // Parse Command-line args.
  int self_party_index = -1;
  int num_parties = -1;
  string circuit = "";
  string inputs = "";
  string command = "";
  string ot_dir = "";
  string session_id = "";
  string outfile_id = "";
  string output_filename = "";
  string rabbitmq_username = "";
  string rabbitmq_password = "";
  string rabbitmq_ssl_ca_cert_file = "";
  string rabbitmq_ssl_client_cert_file = "";
  string rabbitmq_ssl_client_key_file = "";
  string rabbitmq_ip = "";
  long rabbitmq_port = 0;
  vector<string> listen_ips;
  vector<string> connect_ips;
  vector<long> ports;
  vector<SocketParams*> connection_properties;
  unsigned int timeout = 0;
  bool write_ot_to_file = true;
  bool eval_by_level = true;
  bool use_elliptic_curve_dh = false;
  bool rabbitmq_use_ssl = false;
  bool rabbitmq_ssl_verify_peer = false;
  bool rabbitmq_ssl_verify_hostname = false;
  OTProtocol base_ot = OTProtocol::DIFFIE_HELLMAN;

  if (!ParseArgs(
          (int) args.size(),
          args,
          &self_party_index,
          &num_parties,
          &rabbitmq_username,
          &rabbitmq_password,
          &rabbitmq_ip,
          &rabbitmq_port,
          &listen_ips,
          &connect_ips,
          &ports,
          &timeout,
          &write_ot_to_file,
          &eval_by_level,
          &use_elliptic_curve_dh,
          &base_ot,
          &rabbitmq_use_ssl,
          &rabbitmq_ssl_verify_peer,
          &rabbitmq_ssl_verify_hostname,
          &rabbitmq_ssl_ca_cert_file,
          &rabbitmq_ssl_client_cert_file,
          &rabbitmq_ssl_client_key_file,
          &connection_properties,
          &session_id,
          &ot_dir,
          &outfile_id,
          &output_filename,
          &circuit,
          &inputs,
          &command)) {
    LOG_ERROR("Usage:\n\tn_party_mpc_by_gate.exe --circuit CIRCUIT_FILE "
              "--input \"x1 = X1, x2 = X2, ...\"\n\t"
              "[CONNECTION_INFO]\nWhere CONNECTION_INFO is either the ip/port"
              "of all other parties, e.g.:\n\t"
              "--[listen|connect]_ip_0 IP_0 --port_0 PORT_0 ... "
              "--[listen|connect]_ip_n IP_n --port_n PORT_n\n"
              "Or it is the ip and port of a running RabbitMQ server, "
              "in which case the total number of parties and present party's "
              "index should be specified, e.g.:\n\t"
              "--num_parties N --self_index i "
              "--rabbitmq_user USERNAME --rabbitmq_pass PASSWORD "
              "--rabbitmq_ip IP --rabbitmq_port PORT\n");
    // Clean-up.
    if (!connection_properties.empty()) {
      for (size_t k = 0; k < connection_properties.size(); ++k) {
        delete connection_properties[k];
      }
    }
    return -1;
  }

  Timer outermost;
  if (kDebugLevel >= 0) StartTimer(&outermost);

  // Set self-party index:
  //   i) Directly from command-line/JSON params, if provided; OR
  //  ii) From number of connect ips (should have set --connect_ip_k for
  //      every 0 <= k < self-party-index); OR
  // iii) From looking at which slot of cookie_sockets is 'empty', where
  //      we identify/define this to mean send_ and recv_ are NULL.
  if (self_party_index < 0) {
    if (cookie_sockets.empty()) {
      self_party_index = (int) connect_ips.size();
    } else {
      for (int i = 0; i < (int) cookie_sockets.size(); ++i) {
        if (cookie_sockets[i].functions_.send_ == nullptr &&
            cookie_sockets[i].functions_.recv_ == nullptr) {
          self_party_index = i;
          break;
        }
      }
    }
    if (self_party_index < 0) {
      LOG_ERROR("Bad input.");
      return -1;
    }
  }

  // Set output filename, if not set already.
  if (output_filename.empty() && !kPrintOutputToTerminalOnly &&
      outputs == nullptr) {
    string outfile_id_str = outfile_id.empty() ? session_id : outfile_id;
    if (outfile_id_str.empty()) {
      // Use timestamp.
      const string time = GetTime();
      vector<string> split_time;
      Split(time, ":", &split_time);
      const string formatted_time = Join(split_time, "_");
      outfile_id_str = formatted_time;
    }
    output_filename = "OutputFiles/n_party_mpc_as_party_" +
        Itoa(self_party_index) + "_" + outfile_id_str + ".output";
    if (!CreateDir("OutputFiles")) {
      LOG_ERROR("Unable to create OutputFiles/ directory");
      // Clean-up.
      if (!connection_properties.empty()) {
        for (size_t k = 0; k < connection_properties.size(); ++k) {
          delete connection_properties[k];
        }
      }
      return -1;
    }
  }

  // Setup Connection Parameters.
  const int actual_num_parties = num_parties > 0 ?
      num_parties :
      max(max(max(1 + self_party_index, (int) connection_properties.size()),
              (int) ports.size()),
          (int) cookie_sockets.size());
  // Regarding Connection Properties: Ensure that all or none were specified.
  if (!connection_properties.empty() &&
      (int) connection_properties.size() != actual_num_parties &&
      ((int) connection_properties.size() != actual_num_parties - 1 ||
       self_party_index != actual_num_parties - 1)) {
    LOG_ERROR("Must specify all or none of the connection properties.");
    return -1;
  }
  connection_properties.resize(actual_num_parties, nullptr);
  const bool using_rabbitmq_server = !rabbitmq_ip.empty();
  const bool using_cookie_socket = !cookie_sockets.empty();
  if (using_rabbitmq_server) {
#if (defined(USE_RABBITMQ))
    for (int i = 0; i < actual_num_parties; ++i) {
      if (i == self_party_index) continue;
      const string rabbitmq_send_queue =
          Itoa(self_party_index) + "_to_" + Itoa(i);
      const string rabbitmq_rec_queue =
          Itoa(i) + "_to_" + Itoa(self_party_index);
      if (connection_properties[i] == nullptr) {
        connection_properties[i] = new RabbitMqSocketParams();
      }
      RabbitMqSocketParams* p = (RabbitMqSocketParams*) connection_properties[i];
      p->type_ = SocketType::RABBITMQ;
      p->is_default_ = false;
      p->socket_type_ = RabbitMqSocketType::TCP;
      if (p->send_queuename_.empty()) p->send_queuename_ = rabbitmq_send_queue;
      if (p->rec_queuename_.empty()) p->rec_queuename_ = rabbitmq_rec_queue;
      p->username_ = rabbitmq_username;
      p->password_ = rabbitmq_password;
      p->server_ip_ = rabbitmq_ip;
      p->server_port_ = rabbitmq_port;
      const bool use_ssl_params =
          (rabbitmq_use_ssl || rabbitmq_ssl_verify_peer ||
           rabbitmq_ssl_verify_hostname || !rabbitmq_ssl_ca_cert_file.empty() ||
           !rabbitmq_ssl_client_cert_file.empty() ||
           !rabbitmq_ssl_client_key_file.empty());
      if (use_ssl_params) {
        p->socket_type_ = RabbitMqSocketType::SSL_TLS;
        p->ssl_params_ = RabbitMqSslParams(
            rabbitmq_ssl_verify_peer,
            rabbitmq_ssl_verify_hostname,
            rabbitmq_ssl_ca_cert_file,
            rabbitmq_ssl_client_cert_file,
            rabbitmq_ssl_client_key_file);
      }
    }
#else
    LOG_ERROR("Using RabbitMq socket type requires compiling with the "
              "-D USE_RABBITMQ flag.");
    return -1;
#endif
  } else if (using_cookie_socket) {
    for (int i = 0; i < actual_num_parties; ++i) {
      connection_properties[i] = new CookieSocketParams(cookie_sockets[i]);
    }
  } else {
    for (int i = 0; i < actual_num_parties; ++i) {
      if (i == self_party_index) continue;
      if (connection_properties[i] == nullptr) {
        connection_properties[i] = new TcpSocketParams();
      }
      TcpSocketParams* p = (TcpSocketParams*) connection_properties[i];
      p->type_ = SocketType::OS_TCP;
      p->is_default_ = false;
      const bool is_server = self_party_index < i;
      p->role_ = is_server ? SocketRole::SERVER : SocketRole::CLIENT;
      p->connect_ip_ = is_server ? "" : connect_ips[i];
      p->listen_ip_ = is_server ? listen_ips[i] : "";
      p->port_ = ports[i];
    }
  }

  // Run GMW.
  if (!RunNPartyMpcByGate(
          write_ot_to_file,
          eval_by_level,
          use_elliptic_curve_dh,
          base_ot,
          command,
          circuit,
          ot_dir,
          num_parties,
          connection_properties,
          timeout,
          self_party_index,
          inputs,
          output_filename,
          outputs)) {
    // Clean-up.
    if (!connection_properties.empty()) {
      for (size_t k = 0; k < connection_properties.size(); ++k) {
        delete connection_properties[k];
      }
    }
    if (kIsFromExcel) {
      ofstream output_file;
      output_file.open(
          GetDirectory(true, output_filename) + "tmp_mpc_logging.txt",
          ofstream::app);
      if (!output_file.is_open()) {
        return -1;
      }
      output_file << "ERROR#" << endl;
      output_file.close();
    } else {
      LOG_ERROR("Failed to run MPC.");
    }
    return -1;
  }

  // Clean-up.
  if (!connection_properties.empty()) {
    for (size_t k = 0; k < connection_properties.size(); ++k) {
      delete connection_properties[k];
    }
  }

  if (kDebugLevel >= 0) {
    // Write outermost timer to file.
    StopTimer(&outermost);
    LOG_INFO("Outermost time: " + GetElapsedTimeString(outermost));
    if (!kPrintOutputToTerminalOnly && outputs == nullptr) {
      ofstream output_file;
      output_file.open(output_filename, ofstream::out | ofstream::app);
      if (!output_file.is_open()) {
        LOG_ERROR("Unable to open output file '" + output_filename + "'");
        if (kIsFromExcel) {
          ofstream excel_output_file;
          excel_output_file.open(
              GetDirectory(true, output_filename) + "tmp_mpc_logging.txt",
              ofstream::app);
          if (!excel_output_file.is_open()) {
            return -1;
          }
          excel_output_file << "ERROR#" << endl;
          excel_output_file.close();
        }
        return -1;
      }

      // Write command.
      output_file << "Outermost time: " << GetElapsedTimeString(outermost)
                  << endl;
      output_file.close();
    }
  }

  LOG_LINE();
  const string done_msg = kPrintOutputToTerminalOnly ?
      "See results printed above." :
      ("Check output in:\n\t" + output_filename);
  TLOG_INFO("Done! " + done_msg);
  if (kIsFromExcel) {
    ofstream output_file;
    output_file.open(
        GetDirectory(true, output_filename) + "tmp_mpc_logging.txt",
        ofstream::app);
    if (!output_file.is_open()) {
      return -1;
    }
    output_file << "DONE#" << endl;
    output_file.close();
  }

  return 0;
}

int n_party_cookie_socket_nonmain(
    const vector<string>& args,
    const vector<CookieSocketParams>& cookie_sockets) {
  return n_party_cookie_socket_nonmain(args, cookie_sockets, nullptr);
}
