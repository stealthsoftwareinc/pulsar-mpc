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
//   This is mostly copy-pasted from two_party_mpc.cpp, with differences:
//     1) This is a non-main (non-executable), and so is invoked by some
//        other executable
//     2) The 'two_party_cookie_socket_nonmain()' API takes in an additional
//        parameter 'cookie_sockets', which (if non-empty) provides the
//        connection info between the parties.
//   Otherwise, usage is the same, so you can forward on to the 'nonmain' API
//   the following arguments:
//   --circuit CIRCUIT_FILE [or --function FUNCTION_FILE]
//   --input \"x1 = X1, x2 = X2, ...\" [or --input_file INPUTS_FILE]
//   CONNECTION_INFO
//   [--base_ot BASE_OT_TYPE] [--dh_group DH_GROUP]
//   [--session_id ID] [--as_[client | server] [--ot_filepath PATH_AND_FILENAME_FOR_OT]
//   [--outfile_path PATH_TO_OUTPUT_DIRECTORY] [--outfile_id OUTPUT_FILENAME]
//   [--timeout TIMEOUT_SECONDS]
//   [--debug[ | 1 | 2]]
// where:
//   - Role of Client vs. Server is determined by:
//       1) User explicitly provides [--as_[client | server] flag
//       2) Input specification includes variable names
//       3) User provided exactly one of --[connect | listen]_ip
//     At least one of the three above signals should be present, and if more than
//     one is present, they should be consistent.
//   - CIRCUIT_FILE: Specifies the path to the circuit file to be processed.
//                   Optionally, can specify --function file instead (in
//                   which case circuit file is built on-the-fly).
//   - x1 = X1, x2 = X2, ...: The variable names and values for this Party’s input
//     NOTES:
//       1) Instead of having a list of VAR_NAME=VALUE, user can just specify a
//          list of values. In this case:
//            A) Role (Client vs. Server) must be determinable based on one
//               of the other methods (directly via --as_[server | client],
//               or if exactly one of --[connect | listen]_ip was provided)
//            B) Values correspond to the variables in the order they appear
//               in function description (LHS)
//       2) Instead of specifying inputs directly on command-line, user can do
//          one of the following:
//            A) Specify inputs via file (use --input_file instead of --input).
//               The input_file should have one input per line, with format:
//                 VAR_NAME=VALUE
//               or just:
//                 VALUE
//            B) Specify inputs via .function file. This option means
//               --circuit argument is not used, and the circuit will be
//               built on the fly from the --function file.
//   - CONNECTION_INFO: Specifies how parties communicate. This must take
//     one of two forms:
//      IP/PORT:  In this case, each party specifies an IP and PORT, via
//                command-line flags: --[connect | listen]_ip and --port.
//                IP can be omitted for Server (default is to listen on 0.0.0.0);
//                but Client must specify a --connect_ip, and both Server
//                and Client must specify a --port.
//      RabbitMQ: In this case, the IP/PORT of the RabbitMQ server should be
//                provided. Additionally, we require explicit info on the
//                present party's index (this info
//                could be gleaned from the connect/listen ip's if using the
//                non-rabbitmq sockets, but most be provided directly here):
//                  --self_index i --rabbitmq_ip IP --rabbitmq_port PORT
//                Finally, there are optional arguments that can be provided:
//                  --[no]rabbitmq_ssl_verify_peer
//                  --[no]rabbitmq_ssl_verify_hostname
//                  --rabbitmq_ssl_ca_cert_file FILENAME
//                  --rabbitmq_ssl_client_cert_file FILENAME
//                  --rabbitmq_ssl_client_key_file FILENAME
//                  --rabbitmq_use_ssl
//                  --rabbitmq_user USERNAME
//                  --rabbitmq_pwd PASSWORD
//                  --send_queuename QUEUENAME:
//                      This will label the Send queue to Partner i with the name
//                      'QUEUENAME' (no spaces or punctuation allowed.)
//                      If [_i] is *not* provided, then this party's Send queue
//                      to every Partner i will be labelled: j_QUEUENAME_i,
//                      where 'j' is the self-party index.
//                  --rec_queuename QUEUENAME:
//                      Ditto above, for the Receive queue.
//                      Also, if [_i] is *not* provided, this party's Receive
//                      queue from every Partner i will be labelled: i_QUEUENAME_j,
//                      where 'j' is the self-party index (note the location
//                      of self-index 'j' vs. other party index 'i' has been
//                      flip-flopped in comparison to how Send queue is handled;
//                      this is necessary for compatibility/symmetry between players.
//                  DEPRECATED/NOT_SUPPORTED: --queuename QUEUENAME:
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
//                   --[no]declare_send_queue:
//                      Sets the 'declare_send_queue_' flag of the RabbitMqSocket
//                      corresponding to Partner i (or to all partners, if [_i]
//                      is not present).
//                   --[no]declare_rec_queue:
//                      Ditto above, for 'declare_rec_queue_' flag.
//                   --[no]declare_queue:
//                      Ditto above, for 'declare_send_queue_' and 'declare_rec_queue_'.
//   - base_ot: Toggles between Paillier or DH based-OT. Should be one of:
//                { paillier, dh }
//              Default is Paillier.
//   - dh_group: Specifies the DH-group. Should be one of:
//                { dh, ec }
//               Only relevant if base_ot == dh. Default is dh.
//   - ID: (Optional) Specifies an arbitrary session id; currently, this is just
//         used to name the output file (so that output files do not overwrite
//         each other); if no --session_id is provided, will use a timestamp
//   - OUTPUT_FILENAME: (Optional) Output is written to:
//                        OutputFiles/two_party_mpc_as_party_[server | client]_XXX.output,
//                      where 'XXX' is 'OUTPUT_FILENAME' (if provided), otherwise
//                      --session_id (if provided), otherwise timestamp
//   - debug: (Optional) If present, must be one of: {debug, debug1, debug2}.
//            Prints extra debug info to terminal and/or output file.
// Example:
//   Server:
//  ./two_party_mpc.exe --circuit CircuitFiles/step_b.circuit --listen_ip localhost
//  --port 4444 --input \"1,2,2\"
//   Client:
//  ./two_party_mpc.exe --circuit CircuitFiles/step_b.circuit --connect_ip localhost
//  --port 4444 --input \"1,1,2,2\"
#include "two_party_mpc_cookie_socket.h"

#include "Crypto/MultiPartyComputation/Circuits/circuit_builder_utils.h"
#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"  // For OutputRecipient.
#include "Crypto/MultiPartyComputation/Circuits/gmw_circuit.h"
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"
#include "Crypto/ObliviousTransfer/oblivious_transfer_utils.h"
#include "FileReaderUtils/read_file_utils.h"
#include "MapUtils/map_utils.h"
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "MathUtils/formula_utils.h"  // For Formula.
#include "Networking/cookie_socket.h"
#include "global_utils.h"
#if (defined(USE_RABBITMQ))
#include "Networking/rabbitmq_socket.h"
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

static const char kCircuitDir[] = "CircuitFiles/";
static const char kOtBitsDir[] = "OtBitsFiles/CircuitByLevel/";
static int kDebugLevel = -1;
static bool kBlockingConnect = false;
static bool kPrintOutputToTerminal = false;
static bool kPrintOutputToTerminalOnly = false;

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

bool ParseArgs(
    int argc,
    const vector<string>& args,
    int* self_index,
    string* rabbitmq_username,
    string* rabbitmq_password,
    string* rabbitmq_ip,
    string* rabbitmq_server_queuename,
    string* rabbitmq_client_queuename,
    bool* rabbitmq_use_ssl,
    bool* rabbitmq_declare_send_queue,
    bool* rabbitmq_declare_rec_queue,
    bool* rabbitmq_ssl_verify_peer,
    bool* rabbitmq_ssl_verify_hostname,
    string* rabbitmq_ssl_ca_cert_file,
    string* rabbitmq_ssl_client_cert_file,
    string* rabbitmq_ssl_client_key_file,
    string* listen_ip,
    string* connect_ip,
    unsigned long* port,
    unsigned int* timeout,
    string* session_id,
    string* ot_filepath,
    string* outfile_path,
    string* outfile_id,
    string* circuit,
    string* function_file,
    string* inputs,
    bool* write_ot_to_disk,
    bool* run_as_server,
    bool* role_set,
    bool* use_elliptic_curve_dh,
    OTProtocol* base_ot,
    string* command) {
  *command = string(args[0]);
  // Start loop at '1' (argument 0 is the executable itself).
  for (int i = 1; i < argc; ++i) {
    string arg = args[i];
    *command += " " + arg;
    arg = Strip(arg, "%20");
    if (ToLowerCase(arg) == "--debug") {
      kDebugLevel = 0;
    } else if (ToLowerCase(arg) == "--debug1") {
      kDebugLevel = 1;
    } else if (ToLowerCase(arg) == "--debug2") {
      kDebugLevel = 2;
    } else if (ToLowerCase(arg) == "--color") {
      SetUseLogColors(true);
    } else if (arg == "--print") {
      kPrintOutputToTerminal = true;
    } else if (arg == "--print_only") {
      kPrintOutputToTerminal = true;
      kPrintOutputToTerminalOnly = true;
    } else if (ToLowerCase(arg) == "--far") {
      kBlockingConnect = true;
    } else if (ToLowerCase(arg) == "--as_client") {
      if (*role_set) {
        LOG_ERROR("Unable to determine role (client vs. server).");
        return false;
      }
      *run_as_server = false;
      *role_set = true;
    } else if (ToLowerCase(arg) == "--as_server") {
      if (*role_set) {
        LOG_ERROR("Unable to determine role (client vs. server).");
        return false;
      }
      *run_as_server = true;
      *role_set = true;
    } else if (arg == "--write_ot") {
      *write_ot_to_disk = true;
    } else if (arg == "--nowrite_ot") {
      *write_ot_to_disk = false;
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
    } else if (ToLowerCase(arg) == "--listen_ip") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--listen_ip'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *listen_ip = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (ToLowerCase(arg) == "--connect_ip") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--connect_ip'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *connect_ip = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (ToLowerCase(arg) == "--port") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--port'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      uint64_t tmp_port;
      if (!Stoi(
              ToLowerCase(StripAllEnclosingPunctuationAndWhitespace(args[i])),
              &tmp_port)) {
        LOG_ERROR("Unable to parse port as a numeric value: '" + args[i] + "'");
        return false;
      }
      *port = (long) tmp_port;
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
      uint64_t tmp_port;
      if (!Stoi(
              ToLowerCase(StripAllEnclosingPunctuationAndWhitespace(args[i])),
              &tmp_port)) {
        LOG_ERROR(
            "Unable to parse rabbitmq_port as a numeric value: '" + args[i] +
            "'");
        return false;
      }
      *port = (long) tmp_port;
    } else if (arg == "--send_queuename") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--send_queuename'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *rabbitmq_server_queuename =
          StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--rec_queuename") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--rec_queuename'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *rabbitmq_client_queuename =
          StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--rabbitmq_use_ssl") {
      *rabbitmq_use_ssl = true;
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
      *rabbitmq_declare_send_queue = declare;
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
      *rabbitmq_declare_rec_queue = declare;
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
      *rabbitmq_declare_send_queue = declare;
      *rabbitmq_declare_rec_queue = declare;
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
    } else if (ToLowerCase(arg) == "--timeout") {
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
    } else if (ToLowerCase(arg) == "--session_id") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--session_id'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *session_id = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (ToLowerCase(arg) == "--outfile_path") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--outfile_path'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *outfile_path = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (ToLowerCase(arg) == "--ot_filepath") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--ot_filepath'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *ot_filepath = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (ToLowerCase(arg) == "--outfile_id") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--outfile_id'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *outfile_id = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--circuit") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--circuit'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *circuit = StripAllEnclosingPunctuationAndWhitespace(args[i]);
    } else if (arg == "--function") {
      if (i == argc - 1) {
        LOG_ERROR("Expected argument after '--function'.");
        return false;
      }
      ++i;
      *command += " " + args[i];
      *function_file = StripAllEnclosingPunctuationAndWhitespace(args[i]);
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
    } else {
      LOG_ERROR("Unexpected command-line argument '" + arg + "'");
      return false;
    }
  }

  // Make sure inputs were provided.
  if (inputs->empty() && function_file->empty()) {
    return false;
  }

  // Make sure a circuit file or a function file was specified.
  if (circuit->empty() == function_file->empty()) {
    return false;
  }

  // Make sure circuit (or function) file exists.
  if (!circuit->empty()) {
    if (!FileExists(*circuit)) {
      // Try searching in kCircuitDir.
      const string temp = *circuit;
      *circuit = kCircuitDir + temp;
      if (!FileExists(*circuit)) {
        LOG_ERROR("Unable to find Circuit file '" + temp + "'");
        return false;
      }
    }
  } else {
    if (!FileExists(*function_file)) {
      // Try searching in kCircuitDir.
      const string temp = *function_file;
      *function_file = kCircuitDir + temp;
      if (!FileExists(*function_file)) {
        LOG_ERROR("Unable to find Circuit file '" + temp + "'");
        return false;
      }
    }
  }

  return true;
}

bool WriteOutput(
    const bool is_party_one,
    const string& command,
    const string& output_filename,
    const vector<Formula>& function,
    const vector<pair<string, DataType>>& party_one_input_types,
    const vector<pair<string, DataType>>& party_two_input_types,
    const vector<GenericValue>& input_values,
    const vector<pair<OutputRecipient, DataType>>& output_targets,
    const vector<GenericValue>& output) {
  CHECK(output.size() == output_targets.size());
  // Open output file.
  if (!CreateDir(GetDirectory(output_filename))) {
    LOG_ERROR("Unable to open output file '" + output_filename + "'");
    return false;
  }
  ofstream output_file;
  output_file.open(output_filename);
  if (!output_file.is_open()) {
    LOG_ERROR("Unable to open output file '" + output_filename + "'");
    return false;
  }

  // Write command.
  output_file << "Command:" << endl << command << endl << endl;

  // Write function.
  if (!function.empty()) {
    vector<vector<pair<string, DataType>>> input_types;
    input_types.push_back(party_one_input_types);
    input_types.push_back(party_two_input_types);
    output_file << "Circuit:" << endl
                << PrintFunction(
                       false,
                       input_types,
                       vector<pair<OutputRecipient, DataType>>(),
                       function)
                << endl;
  }

  // Write Party 1 input types (and values, if is_party_one is true).
  if (is_party_one) DCHECK(input_values.size() == party_one_input_types.size());
  output_file << endl
              << "Party 1 Inputs (" << party_one_input_types.size()
              << "):" << endl;
  for (size_t i = 0; i < party_one_input_types.size(); ++i) {
    output_file << party_one_input_types[i].first << "("
                << GetDataTypeString(party_one_input_types[i].second) << "):";
    if (is_party_one) {
      output_file << GetGenericValueString(input_values[i]);
    }
    output_file << endl;
  }

  // Write Party 2 input types (and values, if is_party_one is true).
  if (!is_party_one) DCHECK(input_values.size() == party_two_input_types.size());
  output_file << endl
              << "Party 2 Inputs (" << party_two_input_types.size()
              << "):" << endl;
  for (size_t i = 0; i < party_two_input_types.size(); ++i) {
    output_file << party_two_input_types[i].first << "("
                << GetDataTypeString(party_two_input_types[i].second) << "):";
    if (!is_party_one) {
      output_file << GetGenericValueString(input_values[i]);
    }
    output_file << endl;
  }

  // Write outputs.
  output_file << endl << "Outputs (" << output.size() << "):" << endl;
  for (size_t i = 0; i < output.size(); ++i) {
    const GenericValue& output_i = output[i];
    const OutputRecipient& who = output_targets[i].first;
    const string who_str =
        (who.all_ ? "A" : (who.none_ ? "N" : Join(who.to_, ",")));
    output_file << "(" << GetDataTypeString(output_targets[i].second) << ")["
                << who_str << "]:";
    // Only print output value if this party got it.
    // NOTE: We also print the case of NEITHER, as these will likely be used
    // in a later computation, and so parties will need to know the values of
    // their shares for these.
    if (who.all_ || who.none_ ||
        (is_party_one && ContainsKey((int) 0, who.to_)) ||
        (!is_party_one && ContainsKey((int) 1, who.to_))) {
      output_file << GetGenericValueString(output_i);
    }

    output_file << endl;

    if (kDebugLevel >= 2) {
      LOG_LINE();
      TLOG_INFO("Output " + Itoa(i) + ": " + GetGenericValueString(output_i));
    }
  }

  output_file.close();

  return true;
}

bool GetExistingOtBitsFilename(
    const bool is_server,
    const uint64_t& num_gates,
    const string& id,
    string* ot_bits_filename) {
  if (ot_bits_filename->empty()) {
    string filename_prefix =
        (is_server ? "server_ot_bits_for_" : "client_ot_bits_for_");
    if (!id.empty()) filename_prefix += id + "_";
    const string filename_suffix = "_gates.txt";

    // Search kOtBitsDir to see if it already has OT bits for this number
    // (or more) of gates; if so, return the name of that file.
    // UPDATE: This code is currently commented out, so that we don't allow
    // using files with *more* OT bits than necessary. I made this change
    // becuase OT is now sufficiently fast enough, and the intended use-case
    // narrow enough (i.e. only a few circuits being used) that the benefit
    // of using files with extra OT bits (saving time of generating new ones)
    // is outweighed by the benefit of having clarity on what OT bits files
    // are being used.
    /*
    vector<string> existing_ot_files;
    if (GetFilesInDirectory(false, kOtBitsDir, &existing_ot_files) &&
        !existing_ot_files.empty()) {
      uint64_t num_gates_to_use = 0;
      for (const string& ot_file : existing_ot_files) {
        if (!HasPrefixString(ot_file, filename_prefix) ||
            !HasSuffixString(ot_file, filename_suffix)) {
          continue;
        }
        const string num_gates_str = StripSuffixString(StripPrefixString(
            ot_file, filename_prefix), filename_suffix);
        uint64_t current_num_gates = 0;
        if (!IsNumeric(num_gates_str) || !Stoi(num_gates_str, &current_num_gates)) {
          continue;
        }
        if (num_gates <= current_num_gates && current_num_gates != 0 &&
            (num_gates_to_use == 0 || current_num_gates < num_gates_to_use)) {
          num_gates_to_use = current_num_gates;
        }
      }
      if (num_gates_to_use > 0) {
        *ot_bits_filename =
            string(kOtBitsDir) + filename_prefix +
            Itoa(num_gates_to_use) + filename_suffix;
        return true;
      }
    }
    */

    // Set name of the OT bits to file.
    *ot_bits_filename =
        string(kOtBitsDir) + filename_prefix + Itoa(num_gates) + filename_suffix;
  }

  return FileExists(*ot_bits_filename);
}

bool RunTwoPartyMpcAsPartyTwo(
    const bool write_ot_to_disk,
    const bool use_elliptic_curve_dh,
    const OTProtocol base_ot,
    const string& command,
    const string& ot_filepath,
    const string& output_filename,
    const string& session_id,
    const string& circuit,
    const vector<Formula>& function,
    const SocketParams& socket_params,
    const unsigned int timeout_secs,
    const vector<GenericValue>& inputs,
    const vector<pair<string, DataType>>& party_one_input_types,
    const vector<pair<string, DataType>>& party_two_input_types,
    const vector<pair<OutputRecipient, DataType>>& output_targets,
    vector<GenericValue>* outputs) {
  // Initialize a GmwClient, and set its socket to the appropriate IP and port.
  GmwClient<bool> gmw_client(socket_params, timeout_secs * 1000);

  // Set whether Connect() is blocking or not.
  if (kBlockingConnect) gmw_client.SetConnectNonBlocking(false);

  // Change default OT settings iff user specified non-default values.
  if (use_elliptic_curve_dh || base_ot != OTProtocol::PAILLIER) {
    gmw_client.SetOtParams(use_elliptic_curve_dh, base_ot);
  }

  // Initialize timers.
  Timer set_inputs_timer, load_circuit_timer, ot_timer, evaluate_timer;
  if (kDebugLevel >= 0) {
    gmw_client.SetActivateTimers(kDebugLevel);
    StartTimer(&set_inputs_timer);
  }

  // Set the Client's input.
  gmw_client.SetInput(inputs);

  if (kDebugLevel >= 0) {
    StopTimer(&set_inputs_timer);
    StartTimer(&load_circuit_timer);
  }

  // Load the circuit.
  if (!gmw_client.LoadCircuit(circuit)) {
    LOG_ERROR("Unable to load circuit: '" + circuit + "'");
    return false;
  }

  if (kDebugLevel >= 0) {
    StopTimer(&load_circuit_timer);
    StartTimer(&ot_timer);
  }

  // Read OT bits from file.
  //   - Get the name of an existing file, if it exists.
  const int64_t num_non_local_gates = gmw_client.GetNumNonLocalGates();
  gmw_client.SetOtBitsSeed(Itoa(num_non_local_gates) + session_id);
  string client_ot_bits_file = ot_filepath;
  GetExistingOtBitsFilename(
      false, num_non_local_gates, session_id, &client_ot_bits_file);
  if (!gmw_client.PrecomputeObliviousTransferBits(
          write_ot_to_disk ? client_ot_bits_file : "")) {
    LOG_ERROR("Unable to PrecomputeObliviousTransferBits.");
    if (kDebugLevel >= 2) {
      LOG_INFO(
          "Connection Stats:\n" + gmw_client.GetSocket()->PrintSocketStats());
    }
    return false;
  }

  if (kDebugLevel >= 0) {
    StopTimer(&ot_timer);
    StartTimer(&evaluate_timer);
  }

  // Perform GMW-circuit evaluation.
  if (!gmw_client.EvaluateCircuit()) {
    LOG_ERROR("Failed to Evaluate Circuit for Party 2.");
    if (kDebugLevel >= 2) {
      LOG_INFO(
          "Connection Stats:\n" + gmw_client.GetSocket()->PrintSocketStats());
    }
    return false;
  }

  if (kDebugLevel >= 0) {
    StopTimer(&evaluate_timer);
  }

  // Fetch circuit output.
  vector<GenericValue> output = gmw_client.GetOutputAsGenericValue();
  if (outputs != nullptr) {
    *outputs = gmw_client.GetOutputAsGenericValue();
  }

  // Write output file.
  if (!kPrintOutputToTerminalOnly && outputs == nullptr &&
      !WriteOutput(
          false,
          command,
          output_filename,
          function,
          party_one_input_types,
          party_two_input_types,
          inputs,
          output_targets,
          output)) {
    return false;
  }
  if (kPrintOutputToTerminal) {
    for (size_t i = 0; i < output.size(); ++i) {
      const GenericValue& output_i = output[i];
      const OutputRecipient& who = output_targets[i].first;
      const string who_str =
          (who.all_ ? "A" : (who.none_ ? "N" : Join(who.to_, ",")));
      cout << "(" << GetDataTypeString(output_targets[i].second) << ")["
           << who_str << "]:" << GetGenericValueString(output_i) << endl;
    }
  }

  // Print timer info.
  if (kDebugLevel >= 0) {
    const string timers_str =
        "\n  set_inputs_timer: " + GetElapsedTimeString(set_inputs_timer) +
        "\n  load_circuit_timer: " + GetElapsedTimeString(load_circuit_timer) +
        "\n  ot_timer: " + GetElapsedTimeString(ot_timer) +
        "\n  eval_timer: " + GetElapsedTimeString(evaluate_timer);
    const string timers = gmw_client.PrintTimers();

    if (kPrintOutputToTerminal || kPrintOutputToTerminalOnly) {
      LOG_LINE();
      TLOG_INFO("Timer Information:\nOuterTimers:" + timers_str + "\n" + timers);
      if (kDebugLevel >= 2) {
        TLOG_INFO(
            "Connection Stats:\n" + gmw_client.GetSocket()->PrintSocketStats());
      }
    }

    if (!kPrintOutputToTerminalOnly && outputs == nullptr) {
      ofstream output_file;
      output_file.open(output_filename, ofstream::out | ofstream::app);
      if (!output_file.is_open()) {
        LOG_ERROR("Unable to open output file '" + output_filename + "'");
        return false;
      }

      // Write Timers to file.
      output_file << endl
                  << "Timer Info:" << timers_str << endl
                  << timers << endl;

      // Print Socket (connection) info.
      if (kDebugLevel >= 2) {
        output_file << endl
                    << "Connection Stats:" << endl
                    << gmw_client.GetSocket()->PrintSocketStats() << endl;
      }
      output_file.close();
    }
  }

  return true;
}

bool RunTwoPartyMpcAsPartyOne(
    const bool write_ot_to_disk,
    const bool use_elliptic_curve_dh,
    const OTProtocol base_ot,
    const string& command,
    const string& ot_filepath,
    const string& output_filename,
    const string& session_id,
    const string& circuit,
    const vector<Formula>& function,
    const SocketParams& socket_params,
    const unsigned int timeout_secs,
    const vector<GenericValue>& inputs,
    const vector<pair<string, DataType>>& party_one_input_types,
    const vector<pair<string, DataType>>& party_two_input_types,
    const vector<pair<OutputRecipient, DataType>>& output_targets,
    vector<GenericValue>* outputs) {
  // Initialize a GmwServer, and set its socket to the appropriate IP and Port.
  GmwServer<bool> gmw_server(socket_params, timeout_secs * 1000);

  // Set whether Connect() is blocking or not.
  if (kBlockingConnect) gmw_server.SetConnectNonBlocking(false);

  // Change default OT settings iff user specified non-default values.
  if (use_elliptic_curve_dh || base_ot != OTProtocol::PAILLIER) {
    gmw_server.SetOtParams(use_elliptic_curve_dh, base_ot);
  }

  // Initialize timers.
  Timer set_inputs_timer, load_circuit_timer, ot_timer, evaluate_timer;
  if (kDebugLevel >= 0) {
    gmw_server.SetActivateTimers(kDebugLevel);
    StartTimer(&set_inputs_timer);
  }

  // Set the Server's input.
  gmw_server.SetInput(inputs);

  // Initialize timers.
  if (kDebugLevel >= 0) {
    StopTimer(&set_inputs_timer);
    StartTimer(&load_circuit_timer);
  }

  // Load the circuit.
  if (!gmw_server.LoadCircuit(circuit)) {
    LOG_ERROR("Unable to load circuit: '" + circuit + "'");
    return false;
  }

  if (kDebugLevel >= 0) {
    StopTimer(&load_circuit_timer);
    StartTimer(&ot_timer);
  }

  // Read OT bits from file.
  //   - Get the name of an existing file, if it exists.
  const int64_t num_non_local_gates = gmw_server.GetNumNonLocalGates();
  gmw_server.SetOtBitsSeed(Itoa(num_non_local_gates) + session_id);
  string server_ot_bits_file = ot_filepath;
  GetExistingOtBitsFilename(
      true, num_non_local_gates, session_id, &server_ot_bits_file);
  if (!gmw_server.PrecomputeObliviousTransferBits(
          write_ot_to_disk ? server_ot_bits_file : "")) {
    LOG_ERROR("Unable to PrecomputeObliviousTransferBits.");
    if (kDebugLevel >= 2) {
      LOG_INFO(
          "Connection Stats:\n" + gmw_server.GetSocket()->PrintSocketStats());
    }
    return false;
  }

  if (kDebugLevel >= 0) {
    StopTimer(&ot_timer);
    StartTimer(&evaluate_timer);
  }

  // Perform GMW-circuit evaluation.
  if (!gmw_server.EvaluateCircuit()) {
    LOG_ERROR("Failed to Evaluate Circuit as Party 1.");
    if (kDebugLevel >= 2) {
      LOG_INFO(
          "Connection Stats:\n" + gmw_server.GetSocket()->PrintSocketStats());
    }
    return false;
  }

  if (kDebugLevel >= 0) {
    StopTimer(&evaluate_timer);
  }

  // Fetch circuit output.
  vector<GenericValue> output = gmw_server.GetOutputAsGenericValue();
  if (outputs != nullptr) {
    *outputs = gmw_server.GetOutputAsGenericValue();
  }

  // Write output file.
  if (!kPrintOutputToTerminalOnly && outputs == nullptr &&
      !WriteOutput(
          true,
          command,
          output_filename,
          function,
          party_one_input_types,
          party_two_input_types,
          inputs,
          output_targets,
          output)) {
    return false;
  }
  if (kPrintOutputToTerminal) {
    for (size_t i = 0; i < output.size(); ++i) {
      const GenericValue& output_i = output[i];
      const OutputRecipient& who = output_targets[i].first;
      const string who_str =
          (who.all_ ? "A" : (who.none_ ? "N" : Join(who.to_, ",")));
      cout << "(" << GetDataTypeString(output_targets[i].second) << ")["
           << who_str << "]:" << GetGenericValueString(output_i) << endl;
    }
  }

  if (kDebugLevel >= 0) {
    const string timers_str =
        "\n  set_inputs_timer: " + GetElapsedTimeString(set_inputs_timer) +
        "\n  load_circuit_timer: " + GetElapsedTimeString(load_circuit_timer) +
        "\n  ot_timer: " + GetElapsedTimeString(ot_timer) +
        "\n  eval_timer: " + GetElapsedTimeString(evaluate_timer);
    const string timers = gmw_server.PrintTimers();

    if (kPrintOutputToTerminal || kPrintOutputToTerminalOnly) {
      LOG_LINE();
      TLOG_INFO("Timer Information:\nOuterTimers:" + timers_str + "\n" + timers);
      if (kDebugLevel >= 2) {
        TLOG_INFO(
            "Connection Stats:\n" + gmw_server.GetSocket()->PrintSocketStats());
      }
    }

    if (!kPrintOutputToTerminalOnly && outputs == nullptr) {
      ofstream output_file;
      output_file.open(output_filename, ofstream::out | ofstream::app);
      if (!output_file.is_open()) {
        LOG_ERROR("Unable to open output file '" + output_filename + "'");
        return false;
      }

      // Write Timers to file.
      output_file << endl
                  << "Timer Info:" << timers_str << endl
                  << timers << endl;

      // Print Socket (connection) info.
      if (kDebugLevel >= 2) {
        output_file << endl
                    << "Connection Stats:" << endl
                    << gmw_server.GetSocket()->PrintSocketStats() << endl;
      }

      output_file.close();
    }
  }

  return true;
}

bool ReadFunctionFile(
    const string& function_file,
    string* circuit_file,
    bool* run_as_party_one,
    vector<Formula>* function,
    vector<pair<OutputRecipient, DataType>>* output_targets,
    vector<GenericValue>* parsed_inputs,
    vector<vector<pair<string, DataType>>>* input_types) {
  // Apriori, we don't know if this Party 1 or Party 2. Pass in containers to
  // hold values from each party (we'll then look to see which containers were
  // filled in order to determine which party this is).
  vector<vector<GenericValue>> input_values;
  if (!ReadFunctionFile(
          false,
          function_file,
          circuit_file,
          function,
          &input_values,
          input_types,
          output_targets)) {
    LOG_ERROR("Failed to process function file: '" + function_file + "'");
    return false;
  }

  if (function->empty() || output_targets->empty() || input_types->empty()) {
    LOG_ERROR("Function file has missing metadata: '" + function_file + "'");
    return false;
  }

  // Copy inputs, if they were specified in the function file.
  if (input_values.size() == 2 && !input_values[0].empty() &&
      !input_values[1].empty()) {
    LOG_ERROR(
        "Invalid function file: Inputs can be specified for at most one party.");
    return false;
  }
  if (input_values.size() >= 1 && !input_values[0].empty()) {
    *run_as_party_one = true;
    *parsed_inputs = input_values[0];
  } else if (input_values.size() == 2 && !input_values[1].empty()) {
    *run_as_party_one = false;
    *parsed_inputs = input_values[1];
  }

  // Build Circuit File, if not present.
  if (circuit_file->empty()) {
    LOG_ERROR("Function file is missing 'Output:' block (specifying the name "
              "of the circuit file to write).");
    return false;
  }
  if (FileExists(*circuit_file)) {
    if (kDebugLevel >= 0) {
      LOG_INFO(
          "Circuit file '" + *circuit_file +
          "' already exists, will use "
          "it instead of generating a new one.");
    }
    return true;
  }
  // Try searching in kCircuitDir.
  const string temp = kCircuitDir + *circuit_file;
  if (FileExists(temp)) {
    *circuit_file = temp;
    if (kDebugLevel >= 0) {
      LOG_INFO(
          "Circuit file '" + *circuit_file +
          "' already exists, will use "
          "it instead of generating a new one.");
    }
    return true;
  }
  // Circuit file not found. Generate circuit, and write to file.
  if (kDebugLevel >= 0) {
    LOG_WARNING(
        "Circuit file '" + *circuit_file +
        "' not found. Will generate "
        " a new circuit using the function description in '" +
        function_file + "'. This may take some time...");
  }
  StandardCircuit<bool> circuit;
  if (!CircuitFromFunction(
          false, *input_types, *output_targets, *function, &circuit)) {
    LOG_ERROR(
        "Failed to construct and circuit described in function file: '" +
        function_file + "'");
    return false;
  }
  // Write circuit to file.
  circuit.WriteCircuitFile(*circuit_file);

  return true;
}

bool ParseInputs(
    const string& inputs_str,
    const vector<vector<pair<string, DataType>>>& input_types,
    bool* run_as_party_one,
    bool* var_names_present,
    vector<GenericValue>* parsed_inputs) {
  // Parse inputs_str.
  bool is_role_set = *var_names_present;
  int input_index = -1;
  *var_names_present = false;
  vector<string> inputs;
  Split(inputs_str, ",", &inputs);
  for (const string& input_i : inputs) {
    ++input_index;
    vector<string> input_i_parts;
    Split(input_i, "=", &input_i_parts);
    if (input_i_parts.size() != 2 &&
        (input_i_parts.size() != 1 || !is_role_set)) {
      LOG_ERROR(
          "Unable to parse --input:\n\t'" + Join(inputs, ",") +
          "': Role (party index) is not yet known, so input list must include "
          "variable names to determine whose input this belongs to.");
      return false;
    }

    // Determine variable type, either via a lookup based on its name, or
    // based on which input index it is.
    DataType var_type = DataType::UNKNOWN;
    if (input_i_parts.size() == 2) {
      *var_names_present = true;
      const string& var_name = input_i_parts[0];
      if ((!is_role_set || *run_as_party_one) && input_types.size() > 0) {
        for (const pair<string, DataType>& var_type_i : input_types[0]) {
          if (var_name == var_type_i.first) {
            if (is_role_set && !(*run_as_party_one)) {
              LOG_ERROR("Unable to determine role (Client vs. Server)");
              return false;
            }
            *run_as_party_one = true;
            is_role_set = true;
            var_type = var_type_i.second;
            break;
          }
        }
      }
      if ((!is_role_set || !(*run_as_party_one)) && input_types.size() > 1) {
        for (const pair<string, DataType>& var_type_i : input_types[1]) {
          if (var_name == var_type_i.first) {
            if (is_role_set && *run_as_party_one) {
              LOG_ERROR("Unable to determine role (Client vs. Server)");
              return false;
            }
            *run_as_party_one = false;
            is_role_set = true;
            var_type = var_type_i.second;
            break;
          }
        }
      }
    } else if (*run_as_party_one) {
      if (input_types.size() < 1 || (int) input_types[0].size() <= input_index) {
        LOG_ERROR("Unable to get DataType for input " + Itoa(input_index));
        return false;
      }
      var_type = input_types[0][input_index].second;
    } else {
      if (input_types.size() < 2 || (int) input_types[1].size() <= input_index) {
        LOG_ERROR("Unable to get DataType for input " + Itoa(input_index));
        return false;
      }
      var_type = input_types[1][input_index].second;
    }
    if (var_type == DataType::UNKNOWN) {
      LOG_ERROR(
          "Unable to parse --input:\n\t'" + Join(inputs, ",") +
          "': "
          "Unable to find variable type for input index " +
          Itoa(input_index));
      return false;
    }

    // Parse RHS: Variable Value.
    parsed_inputs->push_back(GenericValue());
    if (!ParseGenericValue(
            var_type, input_i_parts.back(), &parsed_inputs->back())) {
      LOG_ERROR(
          "Unable to parse --input argument: Unable to parse input " +
          Itoa(input_index) + " with value '" + input_i_parts.back() +
          "' as a " + GetDataTypeString(var_type) + ". From:\n\t'" +
          Join(inputs, ",") + "'");
      return false;
    }
  }

  return true;
}

bool ParseInputs(
    const string& inputs_str,
    const string& circuit,
    bool* run_as_party_one,
    bool* var_names_present,
    vector<Formula>* function,
    vector<pair<OutputRecipient, DataType>>* output_targets,
    vector<GenericValue>* parsed_inputs,
    vector<vector<pair<string, DataType>>>* input_types) {
  // Read circuit file to get two mappings of variable name to data type
  // (one for Party 1, one for Party 2).
  if (!ReadCircuitFileMetadata(circuit, function, input_types, output_targets)) {
    LOG_ERROR("Failed to read circuit metadata: '" + circuit + "'");
    return false;
  }
  if (function->empty() || output_targets->empty() || input_types->size() != 2) {
    LOG_ERROR("Circuit file has missing metadata: '" + circuit + "'");
    return false;
  }

  return ParseInputs(
      inputs_str,
      *input_types,
      run_as_party_one,
      var_names_present,
      parsed_inputs);
}

}  // namespace

int two_party_cookie_socket_nonmain(
    int argc,
    char**,
    const vector<CookieSocketParams>& cookie_sockets,
    vector<GenericValue>* outputs) {
  vector<string> args(argc);
  for (int i = 0; i < argc; ++i) {
    args[i] = args[i];
  }
  return two_party_cookie_socket_nonmain(args, cookie_sockets, outputs);
}

int two_party_cookie_socket_nonmain(
    int argc, char* argv[], const vector<CookieSocketParams>& cookie_sockets) {
  return two_party_cookie_socket_nonmain(argc, argv, cookie_sockets, nullptr);
}

int two_party_cookie_socket_nonmain(
    const vector<string>& args,
    const vector<CookieSocketParams>& cookie_sockets,
    vector<GenericValue>* outputs) {
  // Parse Command-line args.
  int self_party_index = -1;
  string circuit = "";
  string function_file = "";
  string inputs = "";
  string command = "";
  string ot_filepath = "";
  string session_id = "";
  string outfile_path = "";
  string outfile_id = "";
  string rabbitmq_username = "";
  string rabbitmq_password = "";
  string rabbitmq_ip = "";
  string rabbitmq_send_queuename = "";
  string rabbitmq_rec_queuename = "";
  string rabbitmq_ssl_ca_cert_file = "";
  string rabbitmq_ssl_client_cert_file = "";
  string rabbitmq_ssl_client_key_file = "";
  bool rabbitmq_use_ssl = false;
  bool rabbitmq_declare_send_queue = true;
  bool rabbitmq_declare_rec_queue = true;
  bool rabbitmq_ssl_verify_peer = false;
  bool rabbitmq_ssl_verify_hostname = false;
  string listen_ip = "";
  string connect_ip = "";
  bool run_as_party_one = true;
  bool role_set = false;
  unsigned long port = 0;
  unsigned int timeout = 0;
  bool write_ot_to_disk = true;
  bool use_elliptic_curve_dh = false;
  OTProtocol base_ot = OTProtocol::DIFFIE_HELLMAN;
  if (!ParseArgs(
          (int) args.size(),
          args,
          &self_party_index,
          &rabbitmq_username,
          &rabbitmq_password,
          &rabbitmq_ip,
          &rabbitmq_send_queuename,
          &rabbitmq_rec_queuename,
          &rabbitmq_use_ssl,
          &rabbitmq_declare_send_queue,
          &rabbitmq_declare_rec_queue,
          &rabbitmq_ssl_verify_peer,
          &rabbitmq_ssl_verify_hostname,
          &rabbitmq_ssl_ca_cert_file,
          &rabbitmq_ssl_client_cert_file,
          &rabbitmq_ssl_client_key_file,
          &listen_ip,
          &connect_ip,
          &port,
          &timeout,
          &session_id,
          &ot_filepath,
          &outfile_path,
          &outfile_id,
          &circuit,
          &function_file,
          &inputs,
          &write_ot_to_disk,
          &run_as_party_one,
          &role_set,
          &use_elliptic_curve_dh,
          &base_ot,
          &command) ||
      // Make sure either port information or CookieSockets were provided.
      (port == 0 && cookie_sockets.empty())) {
    LOG_ERROR(
        "Bad command-line arguments. Usage:\n\t."
        "/two_party_mpc.exe --circuit CIRCUIT_FILE "
        "--input \"x1 = X1, x2 = X2, ...\"\n\t"
        "[CONNECTION_INFO]\nWhere CONNECTION_INFO is either the ip/port"
        ", e.g.:\n\t"
        "--[listen|connect]_ip IP_0 --port PORT\n"
        "Or it is the ip and port of a running RabbitMQ server, "
        "in which case the present party's index should be specified, e.g.:\n\t"
        "--self_index [0 | 1] "
        "--rabbitmq_user USERNAME --rabbitmq_pass PASSWORD "
        "--rabbitmq_ip IP --rabbitmq_port PORT\n");
    return -1;
  }
  // If possible, determine if this is Client or Server based on which ip
  // (listen vs. connect) was provided (only possible if exactly one was provided).
  if (!listen_ip.empty() || !connect_ip.empty()) {
    const bool is_server = connect_ip.empty();
    if (role_set && is_server != run_as_party_one) {
      LOG_ERROR("Unable to determine role (client vs. server).");
      return -1;
    }
    run_as_party_one = is_server;
    role_set = true;
  }
  // Ditto, for use-case where user is using RabbitMq instead of TCP/IP.
  if (self_party_index >= 0) {
    run_as_party_one = self_party_index == 0;
    role_set = true;
    if (rabbitmq_rec_queuename.empty()) {
      rabbitmq_rec_queuename =
          run_as_party_one ? "client_to_server" : "server_to_client";
    }
    if (rabbitmq_send_queuename.empty()) {
      rabbitmq_send_queuename =
          run_as_party_one ? "server_to_client" : "client_to_server";
    }
  }
  // Ditto, for use-case where user is using CookieSocket.
  if (!cookie_sockets.empty() && cookie_sockets.size() > 2) {
    LOG_ERROR("Bad input.");
    return -1;
  }
  if (!role_set && !cookie_sockets.empty()) {
    // We identify the current party as the Client if:
    //   a) Only one CookieSocket is provided (since the vector of CookieSockets
    //      is supposed to have one for each party, with an empty one for self-
    //      index; then we allow a slight cheat by having the Client (who has
    //      self-index = 1) to not even have a slot in his vector for himself); OR
    //   b) The CookieSocket in index 1 is default/not-set.
    // We identify (b) if both the send_ and recv_ functions are null.
    const bool is_client = cookie_sockets.size() == 1 ||
        (cookie_sockets[1].functions_.send_ == nullptr &&
         cookie_sockets[1].functions_.recv_ == nullptr);
    run_as_party_one = !is_client;
    role_set = true;
  }
  // If no listen_ip provided, default to "0.0.0.0".
  if (listen_ip.empty()) listen_ip = "0.0.0.0";

  Timer outermost;
  if (kDebugLevel >= 0) StartTimer(&outermost);

  // Grab metadata from circuit (or function) file, and use it to parse inputs.
  vector<Formula> function;
  vector<GenericValue> parsed_inputs;
  vector<pair<OutputRecipient, DataType>> output_targets;
  vector<vector<pair<string, DataType>>> input_types;
  bool run_as_server = run_as_party_one;
  bool var_names_present = role_set;
  if (!function_file.empty()) {
    if (!ReadFunctionFile(
            function_file,
            &circuit,
            &run_as_server,
            &function,
            &output_targets,
            &parsed_inputs,
            &input_types)) {
      return -1;
    }
    if (inputs.empty() == parsed_inputs.empty()) {
      LOG_ERROR("Inputs should be specified in exactly one place: either in the "
                "function file, or via the --input command-line argument");
      return -1;
    }
    // If input values were not specified in the function file, populate them
    // from command-line args.
    if (parsed_inputs.empty() &&
        !ParseInputs(
            inputs,
            input_types,
            &run_as_server,
            &var_names_present,
            &parsed_inputs)) {
      return -1;
    }
  } else if (!ParseInputs(
                 inputs,
                 circuit,
                 &run_as_server,
                 &var_names_present,
                 &function,
                 &output_targets,
                 &parsed_inputs,
                 &input_types)) {
    return -1;
  }
  // Sanity-check a role was provided (and is consistent).
  if (!role_set && !var_names_present) {
    LOG_ERROR("Unable to determine role (client vs. server).");
    return -1;
  } else if (var_names_present) {
    if (role_set && run_as_party_one != run_as_server) {
      LOG_ERROR("Unable to determine role (client vs. server).");
      return -1;
    }
    run_as_party_one = run_as_server;
  }
  // Use default 'localhost' as ip, if none was provided.
  if (listen_ip.empty() && run_as_party_one) listen_ip = "localhost";
  if (connect_ip.empty() && !run_as_party_one) connect_ip = "localhost";
  if (input_types.empty()) input_types.resize(2);
  const vector<pair<string, DataType>>& party_one_input_types = input_types[0];
  const vector<pair<string, DataType>>& party_two_input_types = input_types[1];

  // Set session id, either via --session_id, or timestamp.
  string outfile_id_str = outfile_id.empty() ? session_id : outfile_id;
  if (outfile_id_str.empty()) {
    // Use timestamp.
    const string time = GetTime();
    vector<string> split_time;
    Split(time, ":", &split_time);
    const string formatted_time = Join(split_time, "_");
    outfile_id_str = formatted_time;
  }

  // Set output filename.
  const string output_path = outfile_path.empty() ? "OutputFiles" : outfile_path;
  const string alt_filename = string("two_party_mpc_as_party_") +
      (run_as_party_one ? "server_" : "client_") + outfile_id_str + ".output";
  const string output_file = outfile_id.empty() ? alt_filename : outfile_id;
  const string output_filename = output_path + "/" + output_file;

  // Set Connection info.
  SocketParams* socket_params;
  const bool using_rabbitmq_server = !rabbitmq_ip.empty();
  const bool using_cookie_socket = !cookie_sockets.empty();
  if (using_rabbitmq_server) {
#if (defined(USE_RABBITMQ))
    const string rabbitmq_send_queue = rabbitmq_send_queuename.empty() ?
        (run_as_party_one ? "server_to_client" : "client_to_server") :
        rabbitmq_send_queuename;
    const string rabbitmq_rec_queue = rabbitmq_rec_queuename.empty() ?
        (run_as_party_one ? "client_to_server" : "server_to_client") :
        rabbitmq_rec_queuename;
    RabbitMqSocketParams* p = new RabbitMqSocketParams();
    p->type_ = SocketType::RABBITMQ;
    p->is_default_ = false;
    p->socket_type_ = RabbitMqSocketType::TCP;
    p->declare_send_queue_ = rabbitmq_declare_send_queue;
    p->declare_rec_queue_ = rabbitmq_declare_rec_queue;
    p->send_queuename_ = rabbitmq_send_queue;
    p->rec_queuename_ = rabbitmq_rec_queue;
    p->username_ = rabbitmq_username;
    p->password_ = rabbitmq_password;
    p->server_ip_ = rabbitmq_ip;
    p->server_port_ = port;
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
    socket_params = p;
#else
    LOG_ERROR("Using RabbitMq socket type requires compiling with the "
              "-D USE_RABBITMQ flag.");
    return -1;
#endif
  } else if (using_cookie_socket) {
    socket_params = run_as_party_one ?
        new CookieSocketParams(cookie_sockets[1]) :
        new CookieSocketParams(cookie_sockets[0]);
  } else {
    TcpSocketParams* p = new TcpSocketParams();
    p->type_ = SocketType::OS_TCP;
    p->is_default_ = false;
    p->role_ = run_as_party_one ? SocketRole::SERVER : SocketRole::CLIENT;
    p->connect_ip_ = run_as_party_one ? "" : connect_ip;
    p->listen_ip_ = run_as_party_one ? listen_ip : "";
    p->port_ = port;
    socket_params = p;
  }

  // Run GMW as Server.
  if (run_as_party_one &&
      !RunTwoPartyMpcAsPartyOne(
          write_ot_to_disk,
          use_elliptic_curve_dh,
          base_ot,
          command,
          ot_filepath,
          output_filename,
          session_id,
          circuit,
          function,
          *socket_params,
          timeout,
          parsed_inputs,
          party_one_input_types,
          party_two_input_types,
          output_targets,
          outputs)) {
    delete socket_params;
    return -1;
    // Run GMW as Client.
  } else if (
      !run_as_party_one &&
      !RunTwoPartyMpcAsPartyTwo(
          write_ot_to_disk,
          use_elliptic_curve_dh,
          base_ot,
          command,
          ot_filepath,
          output_filename,
          session_id,
          circuit,
          function,
          *socket_params,
          timeout,
          parsed_inputs,
          party_one_input_types,
          party_two_input_types,
          output_targets,
          outputs)) {
    delete socket_params;
    return -1;
  }

  // Clean-up.
  delete socket_params;

  if (kDebugLevel >= 0) {
    StopTimer(&outermost);

    // Print outermost timer to terminal.
    if (kPrintOutputToTerminal || kPrintOutputToTerminalOnly) {
      LOG_INFO("Outermost time: " + GetElapsedTimeString(outermost));
    }

    // Write outermost timer to file.
    if (!kPrintOutputToTerminalOnly && outputs == nullptr) {
      ofstream output_file;
      output_file.open(output_filename, ofstream::out | ofstream::app);
      if (!output_file.is_open()) {
        LOG_ERROR("Unable to open output file '" + output_filename + "'");
        return false;
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

  return 0;
}

int two_party_cookie_socket_nonmain(
    const vector<string>& args,
    const vector<CookieSocketParams>& cookie_sockets) {
  return two_party_cookie_socket_nonmain(args, cookie_sockets, nullptr);
}
