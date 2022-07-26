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
// TODO(paul): The code below is generic, to handle arithmetic AND boolean
// circuits, and indeed more generally, circuits that have arbitrary
// GenericValue types on their wires. Since 100% of code today is only
// for the boolean case, and even if/when we support Arithmetic, there
// will only be two cases, it probably makes sense to have a boolean-only
// circuit evaluator (and later ditto for arithmetic); and then we can
// save circuit load and eval time, as well as simplify code/logic, greatly.
//
// TODO(paul): For the use-case where communication happens by-level (instead
// of by-gate), a communication optimization is to pack the OT bits into bytes.
// So e.g. instead of using a full byte to communicate a single Client OT bit
// (corresponding to 1 gate), we can now pack 8 gates' worth of Client OT bits
// into one byte. Similarly, in the Server's Obfuscated truth table response,
// it only requires 4 bits per gate; so we can pack two gates' worth of
// Obfuscated TT's into each byte.
//
// TODO(paul): Work/timing for Client vs. Server is different: Client does
// work at the beginning (to construct selection bits), then after sending
// those over, Client does nothing for awhile. Meanwhile, Server does nothing
// until the selection bits are received, then he does a bunch of work to
// construct the Obfuscated truth tables, and then once he returns those to
// Client, he is dormant again until he receives the next level's selection bits.
// In order to spread out a machine's work (and minimize idle time), we'd
// want each machine to be Server (and Client) with half of their partners.
// This is easy enough to achieve, but would require a fairly substantial
// code refactoring.
#include "gmw_circuit_by_gate.h"

#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"  // For OutputRecipient.
#include "Crypto/MultiPartyComputation/Circuits/gmw_circuit.h"
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"
#include "Crypto/ObliviousTransfer/oblivious_transfer_utils.h"
#include "Crypto/RandomNumberGeneration/deterministic_random_utils.h"
#include "Crypto/RandomNumberGeneration/random_utils.h"
#include "FileReaderUtils/read_file_utils.h"
#include "GenericUtils/char_casting_utils.h"
#include "GenericUtils/thread.h"
#include "GenericUtils/thread_utils.h"
#include "MapUtils/map_utils.h"
#include "MathUtils/constants.h"  // For slice
#include "MathUtils/data_structures.h"  // For GenericValue
#include "Networking/socket.h"
#include "Networking/socket_utils.h"
#include "global_utils.h"

#include <climits>  // For ULLONG_MAX, etc.
#include <cmath>
#include <fstream>
#include <map>
#include <memory>  // For unique_ptr.
#include <string>
#include <unistd.h>  // For usleep().
#include <vector>

using namespace crypto::random_number;
using namespace file_reader_utils;
using namespace map_utils;
using namespace math_utils;
using namespace networking;
using namespace string_utils;
using namespace test_utils;
using namespace std;

namespace crypto {
namespace multiparty_computation {

namespace {

static const int64_t kMaxReadFileBlockBytes = 256 * 1024 * 1024;  // 256Mb
static const int kMaxNumCharsInCircuitFileName = 16;
static const char kCircuitDir[] = "CircuitFiles/CircuitByGate/";
// Eliminates randomness, for the purpose of debugging.
// *** This flag should always be false for production code ***
static const char kDebugMode = false;

// Directory and filenames for the Paillier Cryptosystem public/private
// parameters that are used by the underlying Paillier OT protocols.
static const char kKeyNFile[] = "paillier_n_key.txt";
static const char kKeyGFile[] = "paillier_g_key.txt";
static const char kKeyLambdaFile[] = "paillier_lambda_key.txt";
static const char kKeyMuFile[] = "paillier_mu_key.txt";
// The fastest OT^n_1 protocol to run depends on the number of secrets n.
// Currently, (IKNP + PRG + Paillier) is fastest. See lengthy discussion
// of where the 612 number comes from by looking at the comment at
// the end of oblivious_transfer_utils_test.cpp/exe.
static const uint64_t kIkosIknpTogglePoint = 612;

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

bool AppendToFile(const string& filename, const string& line) {
  if (filename.empty()) {
    return true;
  }
  ofstream output_file;
  output_file.open(filename, ofstream::app);
  if (!output_file.is_open()) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }
  output_file << line << endl;
  output_file.close();
  return true;
}

// Grabs the next bit from server_randomness_, and updates current index.
bool GrabServerRandomBit(PartnerInfo& partner_info) {
  if (partner_info.server_randomness_.size() <=
      partner_info.server_randomness_current_byte_) {
    LOG_FATAL("Not enough server randomness generated. This should "
              "never happen.");
    return false;
  }

  const unsigned char value_byte =
      partner_info
          .server_randomness_[partner_info.server_randomness_current_byte_];
  const bool value =
      (value_byte >> partner_info.server_randomness_current_bit_) & 1;

  if (partner_info.server_randomness_current_bit_ == CHAR_BIT - 1) {
    partner_info.server_randomness_current_bit_ = 0;
    ++partner_info.server_randomness_current_byte_;
  } else {
    ++partner_info.server_randomness_current_bit_;
  }

  return value;
}

// Returns the number of non-local {Bool, Arith} gates that depends on the
// two parties indicated.
// OPTIONAL: Specify '-1' as the party_two index if you want to return the
// total number of non-local gates that depend on inputs from party_one
// (across/summed over all parties).
GateIndexDataType GetNumNonLocalGates(
    const int num_parties,
    const int party_one,
    const int party_two,
    const vector<GateIndexDataType>& num_gates_per_party_pairs) {
  if (party_two == -1) {
    GateIndexDataType to_return = 0;
    for (int i = 0; i < party_one; ++i) {
      to_return += GetNumNonLocalGates(
          num_parties, i, party_one, num_gates_per_party_pairs);
    }
    for (int i = party_one + 1; i < num_parties; ++i) {
      to_return += GetNumNonLocalGates(
          num_parties, party_one, i, num_gates_per_party_pairs);
    }
    return to_return;
  } else {
    const int pair_index = (party_one * (2 * num_parties - party_one - 1)) / 2 +
        party_two - party_one - 1;
    return num_gates_per_party_pairs[pair_index];
  }
}

bool WriteServerOtBitsToFile(
    const string& filename, const vector<ServerSecretPair>* secrets) {
  if (filename.empty()) {
    return false;
  }
  if (secrets->empty()) {
    return true;
  }

  if (!CreateDir(GetDirectory(filename))) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }

  ofstream output_file;
  output_file.open(filename, ofstream::binary);
  if (!output_file.is_open()) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }

  unsigned char to_print = 0;
  for (size_t i = 0; i < secrets->size(); ++i) {
    const ServerSecretPair& secret = (*secrets)[i];
    // Will pack OT bits for one bool gate (which is 1-out-of-4 OT, or
    // more precisely, two sets of 1-out-of-2 OT) into one byte.
    if (i % 2 == 0) {
      to_print = 0;
      if (secret.s0_[0]) to_print = (unsigned char) (to_print + 1);
      if (secret.s1_[0]) to_print = (unsigned char) (to_print + 2);
    } else {
      if (secret.s0_[0]) to_print = (unsigned char) (to_print + 4);
      if (secret.s1_[0]) to_print = (unsigned char) (to_print + 8);
      output_file << to_print;
    }
  }
  // Write last byte, if odd number of secrets.
  if ((secrets->size() % 2) == 1) {
    output_file << to_print;
  }

  output_file.close();
  return true;
}

bool WriteClientOtBitsToFile(
    const string& filename,
    const vector<ClientSelectionBitAndSecret>* selection_bits) {
  if (filename.empty()) {
    return false;
  }
  if (selection_bits->empty()) {
    return true;
  }

  if (!CreateDir(GetDirectory(filename))) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }

  ofstream output_file;
  output_file.open(filename, ofstream::binary);
  if (!output_file.is_open()) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }

  unsigned char to_print = 0;
  for (size_t i = 0; i < selection_bits->size(); ++i) {
    const ClientSelectionBitAndSecret& ot_bits = (*selection_bits)[i];
    // Will pack OT bits for one bool gate (which is 1-out-of-4 OT, or
    // more precisely, two sets of 1-out-of-2 OT) into one byte.
    if (i % 2 == 0) {
      to_print = 0;
      if (ot_bits.b_) to_print = (unsigned char) (to_print + 1);
      if (ot_bits.s_b_[0]) to_print = (unsigned char) (to_print + 2);
    } else {
      if (ot_bits.b_) to_print = (unsigned char) (to_print + 4);
      if (ot_bits.s_b_[0]) to_print = (unsigned char) (to_print + 8);
      output_file << to_print;
    }
  }
  // Write last byte, if odd number of secrets.
  if ((selection_bits->size() % 2) == 1) {
    output_file << to_print;
  }

  output_file.close();
  return true;
}

string ParseGlobalInputsFromFile(
    const string& filename,
    const int current_party_start_index,
    const vector<GlobalInputInfo>& all_parties_inputs,
    vector<GenericValue>* input) {
  ifstream input_file(filename.c_str());
  if (!input_file.is_open()) {
    return "-1";
  }

  int line_num = 0;
  size_t current_input_index = current_party_start_index - 1;
  string orig_line, line;
  while (getline(input_file, orig_line)) {
    line_num++;
    RemoveWindowsTrailingCharacters(&orig_line);
    line = RemoveAllWhitespace(orig_line);
    if (line.empty() || HasPrefixString(line, "#")) continue;
    ++current_input_index;

    // Grab DataType of this input from all_parties_inputs.
    if (current_input_index >= all_parties_inputs.size()) {
      return "Too many inputs.";
    }
    const GlobalInputInfo& input_info = all_parties_inputs[current_input_index];

    // Parse line. Two possible formats:
    //   (DataType) Value
    //   Value
    DataType input_type = input_info.type_;
    input->push_back(GenericValue());
    GenericValue& value = input->back();
    if (HasPrefixString(line, "(")) {
      // Split line into the DataType and Value parts.
      vector<string> parts;
      Split(line, ")", &parts);
      if (parts.size() != 2) {
        return "Unable to parse input: '" + line + "'";
      }
      // Parse DataType.
      input_type = StringToDataType(parts[0].substr(1));
      if (input_type == DataType::UNKNOWN) {
        LOG_ERROR(
            "Unable to parse '" + parts[0].substr(1) + "' as a valid DataType.");
      } else if (input_type != input_info.type_) {
        return "Unexpected DataType of global input";
      }
      // Parse Value.
      if (!ParseGenericValue(input_type, parts[1], &value)) {
        return (
            "Unable to parse '" + parts[1] + "' as a " +
            GetDataTypeString(input_type));
      }
    } else {
      // Parse Value.
      if (!ParseGenericValue(input_type, line, &value)) {
        return (
            "Unable to parse '" + line + "' as a " +
            GetDataTypeString(input_type));
      }
    }
  }
  input_file.close();

  return "";
}

bool ParseGlobalInputsFromString(
    const string& inputs_as_string,
    const int current_party_start_index,
    const vector<string>& var_names,
    const vector<GlobalInputInfo>& all_parties_inputs,
    vector<GenericValue>* input) {
  // First, determine if 'inputs_as_string' is a filename, or a string
  // representation of all inputs.
  if (inputs_as_string.find(",") == string::npos &&
      inputs_as_string.find("=") == string::npos) {
    const string ret_value = ParseGlobalInputsFromFile(
        inputs_as_string, current_party_start_index, all_parties_inputs, input);
    if (ret_value.empty()) {
      return true;
    }
    if (ret_value != "-1") {
      LOG_ERROR(ret_value);
      return false;
    }
  }

  // The fact that we reached here means 'inputs_as_string' represents
  // all inputs. Parse it.
  vector<string> inputs;
  Split(inputs_as_string, ",", &inputs);
  if (!var_names.empty() && inputs.size() != var_names.size()) {
    LOG_ERROR("Mismatching number of inputs");
    return false;
  }
  if (all_parties_inputs.size() < current_party_start_index + inputs.size()) {
    LOG_ERROR("Too many inputs.");
    return false;
  }
  input->resize(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    // Grab DataType for this input.
    const DataType input_type =
        all_parties_inputs[current_party_start_index + i].type_;
    vector<string> inputs_parts;
    Split(inputs[i], "=", &inputs_parts);
    if (inputs_parts.empty() || inputs_parts.size() > 2) {
      LOG_ERROR("Unexpected input: '" + inputs[i] + "'");
      return false;
    }
    GenericValue* value = &((*input)[i]);
    const string input_as_str = inputs_parts.back();
    if (inputs_parts.size() == 2) {
      if (var_names.empty()) {
        LOG_ERROR("Unable to use function_var_names_ to find input index "
                  "as it has not yet been initialized.");
        return false;
      }
      int64_t input_index = -1;
      for (int64_t j = 0; j < (int64_t) var_names.size(); ++j) {
        if (var_names[j] == inputs_parts[0]) {
          input_index = j;
          break;
        }
      }
      if (input_index < 0 || input_index >= (int64_t) inputs.size()) {
        LOG_ERROR(
            "Unable to find variable '" + inputs_parts[0] +
            "' in function_var_names_.");
        return false;
      }
      value = &((*input)[input_index]);
    }
    if (!ParseGenericValue(input_type, input_as_str, value)) {
      LOG_ERROR(
          "Unable to parse '" + input_as_str + "' as a " +
          GetDataTypeString(input_type));
      return false;
    }
  }

  return true;
}

// The operations that are computed as the NOT of another operation require
// one party (by convention, Party 0) to flip its output bit.
// Returns true if the input op is one of these operations (see top of
// gmw_circuit.h for a discussion).
bool OpRequiresBitFlip(const CircuitOperation op) {
  return (
      op == CircuitOperation::NAND || op == CircuitOperation::NOR ||
      op == CircuitOperation::EQ || op == CircuitOperation::LTE ||
      op == CircuitOperation::GTE);
}

// Callbacks for multi-threading.
//   - Thread 2/2.
struct ThreadTwoOfTwoCallbackParams {
  bool inputs_already_shared_;
  GmwByGate* party_;
  string inputs_as_string_;
  const vector<GenericValue>* inputs_;

  ThreadTwoOfTwoCallbackParams() {
    party_ = nullptr;
    inputs_as_string_ = "";
    inputs_ = nullptr;
  }

  ThreadTwoOfTwoCallbackParams(
      const bool inputs_already_shared,
      const string& inputs_as_string,
      GmwByGate* party,
      const vector<GenericValue>* inputs) {
    inputs_already_shared_ = inputs_already_shared;
    party_ = party;
    inputs_as_string_ = inputs_as_string;
    inputs_ = inputs;
  }
};
unsigned ThreadTwoOfTwoCallback(void* args) {
  ThreadTwoOfTwoCallbackParams* params = (ThreadTwoOfTwoCallbackParams*) args;
  if (params == nullptr || params->party_ == nullptr) {
    return 1;
  }

  // Read this Party's inputs into inputs_.
  if (params->inputs_as_string_.empty()) {
    if (!params->party_->ParseGlobalInputs(
            params->inputs_already_shared_, *(params->inputs_))) {
      return 1;
    }
  } else {
    if (!params->party_->ParseGlobalInputs(
            params->inputs_already_shared_, params->inputs_as_string_)) {
      return 1;
    }
  }
  // Exchange input (shares), and load [left | right]_inputs_ with these.
  if (params->inputs_already_shared_) {
    if (!params->party_->LoadGlobalInputShares()) {
      return 1;
    }
  } else {
    if (!params->party_->ExchangeGlobalInputs()) {
      return 1;
    }
  }

  // Read OT bits file.
  bool is_done = false;
  while (!is_done) {
    if (!params->party_->ReadOtBitsFile(&is_done)) {
      return 1;
    }
  }

  return 0;
}
//   - Thread 2/3.
// DEPRECATED: Not currently used.
/*
struct ThreadTwoOfThreeCallbackParams {
  bool inputs_already_shared_;
  GmwByGate * party_;
  string inputs_as_string_;
  const vector<GenericValue> * inputs_;

  ThreadTwoOfThreeCallbackParams() {
    party_ = nullptr;
    inputs_as_string_ = "";
    inputs_ = nullptr;
  }

  ThreadTwoOfThreeCallbackParams(
      const bool inputs_already_shared,
      const string & inputs_as_string,
      GmwByGate * party,
      const vector<GenericValue> * inputs) {
    inputs_already_shared_ = inputs_already_shared;
    party_ = party;
    inputs_as_string_ = inputs_as_string;
    inputs_ = inputs;
  }
};
unsigned ThreadTwoOfThreeCallback(void * args) {
  ThreadTwoOfThreeCallbackParams * params =
      (ThreadTwoOfThreeCallbackParams *)args;
  if (params == nullptr || params->party_ == nullptr) {
    return 1;
  }

  // Read this Party's inputs into inputs_.
  if (params->inputs_as_string_.empty()) {
    if (!params->party_->ParseGlobalInputs(
            params->inputs_already_shared_, *(params->inputs_))) {
      return 1;
    }
  }
  else {
    if (!params->party_->ParseGlobalInputs(
            params->inputs_already_shared_,
            params->inputs_as_string_)) {
      return 1;
    }
  }
  // Exchange input (shares), and load [left | right]_inputs_ with these.
  if (params->inputs_already_shared_) {
    if (!params->party_->LoadGlobalInputShares()) {
      return 1;
    }
  }
  else {
    if (!params->party_->ExchangeGlobalInputs()) {
      return 1;
    }
  }

  // Read OT bits file.
  bool is_done = false;
  while (!is_done) {
    if (!params->party_->ReadOtBitsFile(&is_done)) {
      return 1;
    }
  }

  return 0;
}
*/
//   - Thread 3/3.
struct ThreadThreeOfThreeCallbackParams {
  GmwByGate* party_;

  ThreadThreeOfThreeCallbackParams() { party_ = nullptr; }

  explicit ThreadThreeOfThreeCallbackParams(GmwByGate* party) { party_ = party; }
};
unsigned ThreadThreeOfThreeCallback(void* args) {
  ThreadThreeOfThreeCallbackParams* params =
      (ThreadThreeOfThreeCallbackParams*) args;
  if (params == nullptr || params->party_ == nullptr) {
    return 1;
  }

  bool is_done = false;
  while (!is_done) {
    if (!params->party_->EvaluateCircuit(true, true, &is_done)) {
      return 1;
    }
  }

  return 0;
}

}  // namespace

void GmwByGate::InitializeThreadStatus() {
  thread_status_.insert(
      make_pair(CircuitByGateTask::READ_CIRCUIT_FILE, ThreadStatus::UNSTARTED));
  thread_status_.insert(
      make_pair(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::UNSTARTED));
  thread_status_.insert(
      make_pair(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::UNSTARTED));
  thread_status_.insert(make_pair(
      CircuitByGateTask::EXCHANGE_GLOBAL_INPUTS, ThreadStatus::UNSTARTED));
  thread_status_.insert(
      make_pair(CircuitByGateTask::GENERATE_OT_BITS, ThreadStatus::UNSTARTED));
  thread_status_.insert(
      make_pair(CircuitByGateTask::READ_OT_BITS, ThreadStatus::UNSTARTED));
  thread_status_.insert(
      make_pair(CircuitByGateTask::SEND_GATE_BITS, ThreadStatus::UNSTARTED));
  thread_status_.insert(
      make_pair(CircuitByGateTask::RECEIVE_GATE_BITS, ThreadStatus::UNSTARTED));
}

bool GmwByGate::IsProgressBeingMade(
    const SleepReason reason, const ThreadStatus ot_reading_status) {
  switch (reason) {
    case SleepReason::EVAL_FOR_OT_BITS: {
      return (
          ot_reading_status == ThreadStatus::ACTIVE ||
          ot_reading_status == ThreadStatus::UNSTARTED);
    }
    default: {
      LOG_FATAL("Unsupported reason: " + Itoa(static_cast<int>(reason)));
      return false;
    }
  }

  // Code should never reach here.
  return false;
}

bool GmwByGate::ExchangeGlobalInputs() {
  // Make sure we're ready for this: fields have been initialized, etc.
  if (inputs_already_shared_ || self_party_index_ < 0 ||
      !circuit_.is_circuit_file_function_read_) {
    return false;
  }
  if (partners_.size() != circuit_.function_var_names_.size()) {
    return false;
  }

  if (debug_) {
    StartTimer(&exchange_global_inputs_timer_);
  }
  const int num_parties = (int) partners_.size();

  // Grab which indices (w.r.t. function fingerprint/LHS) this party's inputs
  // correspond to.
  int current_party_first_input_index = 0;
  for (int i = 0; i < self_party_index_; ++i) {
    current_party_first_input_index +=
        (int) circuit_.function_var_names_[i].size();
  }

  // First, generate random shares for each of self-inputs.
  if (input_.size() != circuit_.function_var_names_[self_party_index_].size()) {
    if (debug_) StopTimer(&exchange_global_inputs_timer_);
    return false;
  }
  const size_t num_self_inputs = input_.size();
  uint64_t total_input_bytes = 0;
  for (const GenericValue& input_i : input_) {
    total_input_bytes += GetValueNumBytes(input_i);
  }
  // Initialize each Send Buffer, to have the appropriate size.
  for (int i = 0; i < num_parties; ++i) {
    if (i == self_party_index_) {
      partners_[i].received_bytes_.reserve(total_input_bytes);
    } else {
      partners_[i].bytes_to_send_.reserve(total_input_bytes);
      partners_[i].partners_shares_of_my_inputs_.resize(input_.size());
    }
  }
  // Loop through self inputs.
  for (size_t i = 0; i < num_self_inputs; ++i) {
    const DataType input_i_type = input_[i].type_;
    const vector<unsigned char> input_i_byte_string =
        GetTwosComplementByteString(input_[i]);
    const size_t num_input_i_bytes = input_i_byte_string.size();
    vector<vector<unsigned char>> random_bytes_per_party(
        num_parties, vector<unsigned char>(num_input_i_bytes));
    // Loop through bytes of this input, generating random bytes to distribute
    // to each party.
    for (size_t j = 0; j < num_input_i_bytes; ++j) {
      unsigned char input_i_byte_j_self_share = input_i_byte_string[j];
      for (int k = 0; k < num_parties; ++k) {
        if (k == self_party_index_) {
          continue;
        }
        unsigned char random_byte = kDebugMode ? 0 : RandomByte();
        // For small DataTypes (less than 1 byte), the random mask should not
        // exceed the number of bits in the data type.
        if (j == 0 && IsSmallDataType(input_i_type)) {
          if (input_i_type == DataType::BOOL) random_byte &= 1;
          else if (input_i_type == DataType::INT2) {
            random_byte &= 3;
            // Since doing things in 2's complement, need to extend
            // the leading bit through the rest of the bits.
            const bool leading_bit_is_one = random_byte & 2;
            if (leading_bit_is_one) {
              random_byte =
                  (unsigned char) (random_byte + 252);  // 252 = 11111100.
            }
          } else if (input_i_type == DataType::UINT2) random_byte &= 3;
          else if (input_i_type == DataType::INT4) {
            random_byte &= 7;
            // Since doing things in 2's complement, need to extend
            // the leading bit through the rest of the bits.
            const bool leading_bit_is_one = random_byte & 8;
            if (leading_bit_is_one) {
              random_byte =
                  (unsigned char) (random_byte + 240);  // 240 = 11110000.
            }
          } else if (input_i_type == DataType::UINT4) {
            random_byte = (unsigned char) (random_byte & 7);
          }
        }
        random_bytes_per_party[k][j] = random_byte;
        if (!partners_[k].bytes_to_send_.Push(random_byte)) {
          LOG_ERROR("Send buffer full.");
          if (debug_) StopTimer(&exchange_global_inputs_timer_);
          return false;
        }
        input_i_byte_j_self_share =
            (unsigned char) (input_i_byte_j_self_share ^ random_byte);
      }
      // Now store self-input, XORed with all the random bytes.
      // First, if value is INT2 or INT4, the 'random_bytes' that got XORed
      // were constructed to be valid 2's complement representations (so that
      // the higher-bits were consistent with the sign of the value that the
      // actual (2 or 4) lower-order bits represent). However, after all the
      // XORing, input_i_byte_j_self_share may no longer be a valid
      // representation. Update the higher order bits accordingly.
      if (input_i_type == DataType::INT2) {
        if (input_i_byte_j_self_share & 2) {
          input_i_byte_j_self_share |= 252;  // 252 = 11111100.
        } else {
          input_i_byte_j_self_share &= 3;  // 3 = 00000011.
        }
      } else if (input_i_type == DataType::INT4) {
        if (input_i_byte_j_self_share & 8) {
          input_i_byte_j_self_share |= 240;  // 240 = 11110000.
        } else {
          input_i_byte_j_self_share &= 15;  // 15 = 00001111.
        }
      }
      if (!partners_[self_party_index_].received_bytes_.Push(
              input_i_byte_j_self_share)) {
        LOG_ERROR("Failed to store received byte.");
        if (debug_) StopTimer(&exchange_global_inputs_timer_);
        return false;
      }
    }
    // Update partners_shares_of_my_inputs_.
    for (int k = 0; k < num_parties; ++k) {
      if (k == self_party_index_) continue;
      if (!ParseGenericValueFromTwosComplementString(
              circuit_.inputs_[current_party_first_input_index + i].type_,
              random_bytes_per_party[k],
              &(partners_[k].partners_shares_of_my_inputs_[i]))) {
        LOG_ERROR("Failed to parse random bytes as Generic Value.");
        if (debug_) StopTimer(&exchange_global_inputs_timer_);
        return false;
      }
    }
  }

  // Partition Partners based on whether this party will be the Server or Client
  // for each of his connections (Servers will Receive first, then Send).
  for (const int i : partner_communication_order_) {
    if (i < self_party_index_) {
      // Send shares of own input to other Party.
      if (!SendToPartner(true, i, partners_[i].bytes_to_send_.size())) {
        LOG_ERROR("Failed to send Server's input shares to Client.");
        if (debug_) StopTimer(&exchange_global_inputs_timer_);
        return false;
      }

      // Listen for Partner's shares.
      if (!ReceiveFromPartner(true, i, 0, sizeof(int64_t))) {
        LOG_ERROR(
            "Unable to receive gate communication from Partner " + Itoa(i));
        if (debug_) StopTimer(&exchange_global_inputs_timer_);
        return false;
      }
    } else {
      // Listen for Partner's shares.
      if (!ReceiveFromPartner(true, i, 0, sizeof(int64_t))) {
        LOG_ERROR("Failed to get shares of Client's input");
        if (debug_) StopTimer(&exchange_global_inputs_timer_);
        return false;
      }

      // Send shares of own input to other Party.
      if (!SendToPartner(true, i, partners_[i].bytes_to_send_.size())) {
        LOG_ERROR("Failed to send Server's input shares to Client.");
        if (debug_) StopTimer(&exchange_global_inputs_timer_);
        return false;
      }
    }
  }

  // Now translate received bytes into actual values, to be stored in
  // [left | right]_input_values_.
  uint64_t current_global_input_index = 0;
  for (int i = 0; i < num_parties; ++i) {
    ReadWriteQueue<unsigned char>& received_bytes_i =
        partners_[i].received_bytes_;
    const size_t num_party_i_inputs = circuit_.function_var_names_[i].size();
    for (size_t input_i_j = 0; input_i_j < num_party_i_inputs; ++input_i_j) {
      const GlobalInputInfo& input_info_i_j =
          circuit_.inputs_[current_global_input_index];
      const DataType data_type_i_j = input_info_i_j.type_;
      const uint64_t num_bytes_i_j = GetValueNumBytes(data_type_i_j);
      vector<unsigned char> input_i_j_binary_string(num_bytes_i_j);
      for (size_t k = 0; k < num_bytes_i_j; ++k) {
        if (!received_bytes_i.Pop(&(input_i_j_binary_string[k]))) {
          if (debug_) StopTimer(&exchange_global_inputs_timer_);
          return false;
        }
      }
      GenericValue input_i_j_as_value;
      if (!ParseGenericValueFromTwosComplementString(
              data_type_i_j, input_i_j_binary_string, &input_i_j_as_value)) {
        LOG_ERROR(
            "Failed to parse input " + Itoa(input_i_j) + " from Party " +
            Itoa(i) + " as a value.");
        if (debug_) StopTimer(&exchange_global_inputs_timer_);
        return false;
      }
      // Load value to [left | right]_input_values_.
      if (!circuit_.ParseGlobalInput(input_info_i_j.to_, input_i_j_as_value)) {
        if (debug_) StopTimer(&exchange_global_inputs_timer_);
        return false;
      }
      ++current_global_input_index;
    }
    if (!received_bytes_i.empty()) {
      if (debug_) StopTimer(&exchange_global_inputs_timer_);
      return false;
    }
  }

  is_input_exchanged_done_ = true;
  if (debug_) StopTimer(&exchange_global_inputs_timer_);
  return true;
}

bool GmwByGate::LoadGlobalInputShares() {
  if (!inputs_already_shared_ || input_.size() != circuit_.inputs_.size()) {
    return false;
  }
  if (debug_) StartTimer(&load_global_inputs_timer_);
  for (size_t i = 0; i < input_.size(); ++i) {
    if (!circuit_.ParseGlobalInput(circuit_.inputs_[i].to_, input_[i])) {
      if (debug_) StopTimer(&load_global_inputs_timer_);
      return false;
    }
  }

  is_input_exchanged_done_ = true;
  if (debug_) StopTimer(&load_global_inputs_timer_);
  return true;
}

bool GmwByGate::SendToPartner(
    const int partner_index, const vector<unsigned char>& to_send) {
  uint64_t num_bytes = to_send.size();
  // Send bytes.
  if (SendReturnCode::SUCCESS !=
      partners_[partner_index].socket_->SendData(to_send.data(), num_bytes)) {
    LOG_ERROR("Failed to send communication to Partner " + Itoa(partner_index));
    return false;
  }

  return true;
}

bool GmwByGate::SendToPartner(
    const bool send_num_bytes,
    const int partner_index,
    const uint64_t& num_bytes) {
  // Determine if there are enough bytes in bytes_to_send_.
  if (partners_[partner_index].bytes_to_send_.size() < num_bytes) {
    return false;
  }

  // Move bytes from bytes_to_send_ to a vector for sending.
  vector<unsigned char> to_send(num_bytes);
  for (uint64_t i = 0; i < num_bytes; ++i) {
    if (!partners_[partner_index].bytes_to_send_.Pop(&(to_send[i]))) {
      return false;
    }
  }

  // Send bytes.
  if ((send_num_bytes &&
       !partners_[partner_index].socket_->SendDataNoFlush(
           (unsigned char*) &num_bytes, sizeof(int64_t))) ||
      SendReturnCode::SUCCESS !=
          partners_[partner_index].socket_->SendData(
              to_send.data(), num_bytes)) {
    LOG_ERROR("Failed to send communication to Partner " + Itoa(partner_index));
    return false;
  }

  return true;
}

bool GmwByGate::ReceiveFromPartner(
    const bool reset_connection,
    const int partner_index,
    const uint64_t& num_bytes,
    const int num_received_bytes_to_ignore) {
  if (num_bytes > 0 &&
      (num_bytes > INT_MAX || num_received_bytes_to_ignore >= (int) num_bytes)) {
    return false;
  }
  Socket* socket = partners_[partner_index].socket_.get();
  const bool is_cookie_socket = socket->GetSocketType() == SocketType::COOKIE;
  // SetListenReceiveDataCallback() requires non-const pointer to num bytes.
  uint64_t temp_num_bytes = num_bytes;
  int64_t num_second_comm_bytes = 0;
  set<ListenReturnCode> return_codes;
  if (num_bytes > 0) {
    socket->SetListenReceiveDataCallback(&ReceiveNumBytes, &temp_num_bytes);
    if (is_cookie_socket) {
      ListenParams params = socket->GetListenParams();
      params.receive_buffer_max_size_ = (int) num_bytes;
      socket->SetListenParams(params);
    }
  } else {
    if (is_cookie_socket) {
      ListenParams params = socket->GetListenParams();
      uint64_t num_first_comm_bytes = sizeof(int64_t);
      params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
      socket->SetListenParams(params);
      socket->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_first_comm_bytes);
      set<ListenReturnCode> return_codes = socket->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR("Failed to Receive bytes from Partner " + Itoa(partner_index));
        return false;
      }
      vector<char> received_data;
      if (socket->GetReceivedBytes().size() != 1) {
        LOG_FATAL("Unexpected number of Servers");
      }
      socket->SwapBuffer(0, &received_data);

      // Parse num_bytes in remainder of communication
      // (this value is represented by the first 8 bytes of the received data).
      num_second_comm_bytes = CharVectorToValue<int64_t>(received_data);

      // Now, listen for all of the secrets.
      if (num_second_comm_bytes > INT_MAX) {
        LOG_ERROR("Too many bytes to receive.");
      }
      params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
      socket->ResetForReceive();
      socket->SetListenParams(params);
      socket->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_second_comm_bytes);
    } else {
      socket->SetListenReceiveDataCallback(&ReceiveInt64Bytes);
    }
  }

  return_codes = socket->Listen(true);
  // Check for listening errors.
  if (return_codes.size() != 1 || socket->GetReceivedBytes().size() != 1) {
    LOG_ERROR("Failed to Receive bytes from Partner " + Itoa(partner_index));
    return false;
  }

  // Check if we received extra bytes on connection s.
  bool received_extra_bytes = false;
  if (return_codes.size() == 1 &&
      *(return_codes.begin()) ==
          networking::ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
    received_extra_bytes = true;
  }

  // Store Client's shares.
  const map<SocketIdentifier, ReceivedData>& received_schema_map =
      socket->GetReceivedBytes();
  if (received_schema_map.size() != 1) LOG_FATAL("Too many connections.");
  const ReceivedData& received_schema = received_schema_map.begin()->second;
  const size_t num_recd_bytes = received_schema.buffer_.empty() ?
      received_schema.num_received_bytes_ :
      received_schema.buffer_.size();
  if (num_bytes > 0 && num_recd_bytes < num_bytes) {
    return false;
  }
  const int actual_num_received_bytes_to_ignore =
      is_cookie_socket ? 0 : num_received_bytes_to_ignore;
  const uint64_t num_bytes_to_keep =
      (num_bytes > 0 ? num_bytes : num_recd_bytes) -
      actual_num_received_bytes_to_ignore;
  if (partners_[partner_index].received_bytes_.capacity() < 0 ||
      (size_t) partners_[partner_index].received_bytes_.capacity() <
          num_bytes_to_keep + partners_[partner_index].received_bytes_.size()) {
    partners_[partner_index].received_bytes_.reserve(
        num_bytes_to_keep + partners_[partner_index].received_bytes_.size());
  }

  const char* rec_buffer = received_schema.buffer_.empty() ?
      received_schema.char_buffer_ :
      received_schema.buffer_.data();
  for (size_t i = actual_num_received_bytes_to_ignore;
       i < actual_num_received_bytes_to_ignore + num_bytes_to_keep;
       ++i) {
    const unsigned char b = rec_buffer[i];
    if (!partners_[partner_index].received_bytes_.Push(b)) {
      LOG_ERROR(
          "Failed to store received byte from Partner " + Itoa(partner_index));
      return false;
    }
  }

  const uint64_t num_extra_bytes = (num_bytes <= 0) ?
      0 :
      (num_recd_bytes - actual_num_received_bytes_to_ignore - num_bytes);

  if ((num_extra_bytes == 0) == received_extra_bytes) {
    LOG_ERROR("Failed to Receive bytes from Partner " + Itoa(partner_index));
    return false;
  }

  std::vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(
        extra_bytes.data(),
        rec_buffer + actual_num_received_bytes_to_ignore + num_bytes_to_keep,
        num_extra_bytes);
  }

  if (!extra_bytes.empty() && !reset_connection) {
    LOG_ERROR("Unable to handle extra bytes received.");
    return false;
  }

  if (reset_connection && !socket->ResetForReceive(extra_bytes)) {
    LOG_ERROR("Failed to Receive bytes from Partner " + Itoa(partner_index));
    return false;
  }

  return true;
}

bool GmwByGate::EvaluateGate(
    const bool should_send,
    const bool should_receive,
    const bool is_mult_by_constant,
    const CircuitOperation op,
    const vector<char>& depends_on,
    const GenericValue& left,
    const GenericValue& right,
    bool* store_result,
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

  if (debug_) StartTimer(&evaluate_gate_timer_);

  // Log status, if appropriate.
  if (!excel_logging_file_.empty()) {
    const int percentage_done =
        (circuit_.num_gates_processed_ * 100) / circuit_.num_gates_;
    const int prev_percentage_done =
        ((circuit_.num_gates_processed_ - 1) * 100) / circuit_.num_gates_;
    if (circuit_.num_gates_processed_ == 0 ||
        percentage_done != prev_percentage_done) {
      AppendToFile(
          excel_logging_file_,
          "EVAL" + Itoa(circuit_.num_gates_processed_) + "/" +
              Itoa(circuit_.num_gates_) + "#");
    }
  }

  // Handle single-argument Boolean operators separately.
  if (op == CircuitOperation::IDENTITY || op == CircuitOperation::NOT) {
    const bool is_left_set = left.type_ != DataType::UNKNOWN;
    if (op == CircuitOperation::IDENTITY) {
      *output = is_left_set ? left : right;
      if (debug_) StopTimer(&evaluate_gate_timer_);
      return true;
    }
    // Operation is NOT.
    const bool value = is_left_set ?
        GetValue<bool>(*((const BoolDataType*) left.value_.get())) :
        GetValue<bool>(*((const BoolDataType*) right.value_.get()));
    output->type_ = DataType::BOOL;
    // Per convention, the first party (party index = 0) does the NOT, all
    // other Parties do ID.
    if (self_party_index_ == GetLowestDependentPartyIndex(depends_on)) {
      output->type_ = DataType::BOOL;
      output->value_.reset(new BoolDataType((bool) !value));
    } else {
      output->type_ = DataType::BOOL;
      output->value_.reset(new BoolDataType((bool) value));
    }
    if (debug_) StopTimer(&evaluate_gate_timer_);
    return true;
  }

  // Return, if present party not needed to compute gate.
  if (!GateDependsOn(self_party_index_, depends_on)) {
    *output = GenericValue(0);
    if (debug_) StopTimer(&evaluate_gate_timer_);
    return true;
  }

  // Handle locally computable gates separately.
  if (compute_gates_locally_ &&
      (op == CircuitOperation::XOR || op == CircuitOperation::EQ)) {
    const bool left_value =
        GetValue<bool>(*((const BoolDataType*) left.value_.get()));
    const bool right_value =
        GetValue<bool>(*((const BoolDataType*) right.value_.get()));
    if (op == CircuitOperation::XOR) {
      output->type_ = DataType::BOOL;
      output->value_.reset(new BoolDataType((bool) left_value != right_value));
    } else {
      // Operation is EQ. Per convention, the first party (party index = 0) does
      // the EQ, all other Parties do XOR.
      if (self_party_index_ == GetLowestDependentPartyIndex(depends_on)) {
        output->type_ = DataType::BOOL;
        output->value_.reset(new BoolDataType((bool) left_value == right_value));
      } else {
        output->type_ = DataType::BOOL;
        output->value_.reset(new BoolDataType((bool) left_value != right_value));
      }
    }
    if (debug_) StopTimer(&evaluate_gate_timer_);
    return true;
  } else if (
      compute_gates_locally_ &&
      (op == CircuitOperation::ADD || op == CircuitOperation::SUB)) {
    if (op == CircuitOperation::ADD) {
      *output = left + right;
    } else {
      *output = left - right;
    }
    if (debug_) StopTimer(&evaluate_gate_timer_);
    return true;
  } else if (compute_gates_locally_ && is_mult_by_constant) {
    *output = left * right;
    if (debug_) StopTimer(&evaluate_gate_timer_);
    return true;
  }

  // That we reached here means this gate (op) is not locally computable.
  // Thus, we'll need to exchange ot bits, compute obf TT, etc.
  // Proceed based on Gate type (Boolean gates use the OBF TT approach,
  // Arithmetic gates use Beaver's multiplication triples approach).
  bool to_return;
  if (IsBooleanOperation(op)) {
    bool temp = false;
    if (eval_by_gate_) {
      to_return = EvaluateNonLocalBooleanGate(
          should_send,
          should_receive,
          op,
          depends_on,
          GetValue<bool>(*((const BoolDataType*) left.value_.get())),
          GetValue<bool>(*((const BoolDataType*) right.value_.get())),
          &temp);
    } else {
      to_return = EvaluateNonLocalBooleanGatePrelim(
          should_send,
          should_receive,
          op,
          depends_on,
          GetValue<bool>(*((const BoolDataType*) left.value_.get())),
          GetValue<bool>(*((const BoolDataType*) right.value_.get())),
          store_result,
          &temp);
    }
    if (to_return) *output = GenericValue(temp);
  } else {
    to_return = EvaluateNonLocalArithmeticGate(
        should_send, should_receive, op, depends_on, left, right, output);
  }

  if (debug_) StopTimer(&evaluate_gate_timer_);
  return to_return;
}

bool GmwByGate::EvaluateLevel(
    const bool is_boolean_circuit,
    const bool should_send,
    const bool should_receive) {
  if (debug_) StartTimer(&evaluate_level_timer_);
  bool to_return;
  if (is_boolean_circuit) {
    to_return = EvaluateBooleanLevel(should_send, should_receive);
  } else {
    to_return = EvaluateArithmeticLevel(should_send, should_receive);
  }

  if (debug_) StopTimer(&evaluate_level_timer_);
  return to_return;
}

// N-wise computation of a gate (i.e. where we have N-choose-2 pairwise
// copies of the circuit, with each pair of Partners sharing values for
// the input wires of this gate) is made more complicated by the fact
// that:
//   1) Parties *share* the values on the input wires
//   2) The final output should be some combination of the N-choose-2
//      outputs of the circuit copies.
// Note that (1) is handled in the usual GMW way (obfuscated TT, etc.).
// However, (2) actally requires some alternate computations: the gate
// op may be different for one/each of the N-choose-2 copies, local
// values may be added, one party may want to flip its output bit, etc.
// This function handles the 'local' part of each output formula: that is,
// the parts of the output that this Party can compute just based on its
// input (shares).
// For a lengthy discussion on the logic for how each of the BooleanOperations
// are handled for N-Party circuit evaluation, see discussion in gmw_circuit.h.
bool GmwByGate::ComputeLocalValue(
    const int num_dependent_parties,
    const int lowest_party_index,
    const CircuitOperation op,
    const bool& left,
    const bool& right,
    bool* output) {
  const bool odd_number_parties = (num_dependent_parties % 2) == 1;
  switch (op) {
    case CircuitOperation::AND: {
      *output = false;
      if (odd_number_parties) {
        *output = left && right;
      }
      break;
    }
    case CircuitOperation::NAND: {
      *output = false;
      if (odd_number_parties) {
        *output = left && right;
      }
      break;
    }
    case CircuitOperation::OR: {
      *output = left != right;
      if (odd_number_parties) {
        *output ^= (left && right);
      }
      break;
    }
    case CircuitOperation::NOR: {
      *output = left != right;
      if (odd_number_parties) {
        *output ^= (left && right);
      }
      break;
    }
    case CircuitOperation::XOR: {
      *output = false;
      break;
    }
    case CircuitOperation::EQ: {
      *output = false;
      break;
    }
    case CircuitOperation::GT: {
      *output = left;
      if (odd_number_parties) {
        *output ^= (left && right);
      }
      break;
    }
    case CircuitOperation::GTE: {
      *output = right;
      if (odd_number_parties) {
        *output ^= (left && right);
      }
      break;
    }
    case CircuitOperation::LT: {
      *output = right;
      if (odd_number_parties) {
        *output ^= (left && right);
      }
      break;
    }
    case CircuitOperation::LTE: {
      *output = left;
      if (odd_number_parties) {
        *output ^= (left && right);
      }
      break;
    }
    default: {
      LOG_FATAL("Unsupported operation: " + Itoa(static_cast<int>(op)));
    }
  }
  // The operations that are computed as the NOT of another operation require
  // one party (by convention, the lowest participating party index) to flip
  // its output bit.
  if (OpRequiresBitFlip(op) && self_party_index_ == lowest_party_index) {
    *output = !(*output);
  }

  return true;
}

bool GmwByGate::EvaluateNonLocalBooleanGate(
    const bool should_send,
    const bool should_receive,
    const CircuitOperation op,
    const vector<char>& depends_on,
    const bool& left,
    const bool& right,
    bool* output) {
  const int num_parties = depends_on.empty() ? (int) partners_.size() :
                                               NumDependentParties(depends_on);
  const int lowest_party_index = GetLowestDependentPartyIndex(depends_on);
  const int highest_party_index = depends_on.empty() ?
      (int) partners_.size() - 1 :
      GetHighestDependentPartyIndex(depends_on);

  // First, generate the local computation required for this gate type.
  if (!ComputeLocalValue(
          num_parties, lowest_party_index, op, left, right, output)) {
    return false;
  }

  // Nothing else to do, if this party is the only one computing this gate.
  if (lowest_party_index == highest_party_index) {
    return true;
  }

  // Generate truth table, provided this Party will act as GMW 'Server'
  // for at least one Partner.
  TruthTableMask<bool> truth_table;
  if (self_party_index_ < highest_party_index) {
    for (int left_wire = 0; left_wire < 2; ++left_wire) {
      const bool left_to_use = left != (left_wire == 0 ? false : true);
      for (int right_wire = 0; right_wire < 2; ++right_wire) {
        const bool right_to_use = right != (right_wire == 0 ? false : true);
        bool* entry_to_set = (left_wire == 0 && right_wire == 0) ?
            &truth_table.first.first :
            (left_wire == 0 && right_wire == 1) ?
            &truth_table.first.second :
            (left_wire == 1 && right_wire == 0) ?
            &truth_table.second.first :
            (left_wire == 1 && right_wire == 1) ?
            &truth_table.second.second :
            // Will never happen, could've just ended the clause above, but
            // kept below line to make code above easier to read/understand.
            nullptr;
        // For N > 2 Players, each gate's input wire(s) are shared among all players,
        // and the gate evaluation is done peer-to-peer, where the actual pairwise
        // operation that the players perform is always AND, regardless of the
        // actual gate operation. Thus, this truth table is for AND.
        // See discussion in gmw_circuit.h for details.
        *entry_to_set = left_to_use && right_to_use;
      }
    }
  }

  // Send/Recieve OT Selection bits.
  vector<unsigned char> second_selection_bits;
  if (self_party_index_ > 0) second_selection_bits.resize(self_party_index_, 0);
  for (const int i : partner_communication_order_) {
    if (!GateDependsOn(i, depends_on)) continue;
    if (i < self_party_index_) {
      // Present party is Client: Send OT Selection bits.
      // Grab OT bits to send.
      SelectionBitAndValuePair<bool> selection_bits_for_partner_i;
      while (!partners_[i].client_ot_bits_.Pop(&selection_bits_for_partner_i)) {
        const ThreadStatus status =
            GetThreadStatus(CircuitByGateTask::READ_OT_BITS);
        if (!IsProgressBeingMade(SleepReason::EVAL_FOR_OT_BITS, status)) {
          // Check again that OT bits still not available.
          if (partners_[i].client_ot_bits_.Pop(&selection_bits_for_partner_i))
            break;
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR("Unable to get Client OT bits.");
          return false;
        }
        // That code reached here means the OT Parsing thread is active.
        // Wait for it to read ot bits for this gate.
        uint64_t sleep_time;
        if (!circuit_.evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR("Unable to get appropriate amount of time to sleep for.");
          return false;
        }
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        ot_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
      }
      circuit_.evaluate_gates_sleep_.Reset();

      // Compute what the selection bits should be (based on OT bits and
      // current wire values); then pack these selection bits into a single byte.
      unsigned char to_send_to_i = 0;
      if (selection_bits_for_partner_i.first.first != left) {
        to_send_to_i = (unsigned char) (to_send_to_i + 1);
      }
      if (selection_bits_for_partner_i.second.first != right) {
        to_send_to_i = (unsigned char) (to_send_to_i + (1 << 1));
      }
      // Store the selection secrets for later use (will be needed to decode the
      // obfuscated truth table that each Partner sends).
      if (selection_bits_for_partner_i.first.second) {
        second_selection_bits[i] =
            (unsigned char) (second_selection_bits[i] + 1);
      }
      if (selection_bits_for_partner_i.second.second) {
        second_selection_bits[i] =
            (unsigned char) (second_selection_bits[i] + (1 << 1));
      }
      if (partners_[i].bytes_to_send_.capacity() < 0 ||
          (size_t) partners_[i].bytes_to_send_.capacity() <
              partners_[i].bytes_to_send_.size() + 1) {
        partners_[i].bytes_to_send_.reserve(
            1 + partners_[i].bytes_to_send_.size());
      }
      if (!partners_[i].bytes_to_send_.Push(to_send_to_i)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR("Send buffer is full.");
        return false;
      }
      if (debug_) StartTimer(&send_selection_bits_timer_);
      if (should_send && !SendToPartner(false, i, 1)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR(
            "Unable to send gate (" + Itoa(circuit_.num_gates_processed_) +
            ") communication to Partner " + Itoa(i));
        if (debug_) StopTimer(&send_selection_bits_timer_);
        return false;
      }
      if (debug_) StopTimer(&send_selection_bits_timer_);
    } else {
      // Present party is Server: Receive OT Selection bits.
      // Receive selection bits from other Party.
      if (debug_) StartTimer(&receive_selection_bits_timer_);
      if (should_receive && !ReceiveFromPartner(true, i, 1, 0)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR(
            "Unable to receive gate (" + Itoa(circuit_.num_gates_processed_) +
            ") communication from Partner " + Itoa(i));
        if (debug_) StopTimer(&receive_selection_bits_timer_);
        return false;
      }
      if (debug_) StopTimer(&receive_selection_bits_timer_);
    }
  }

  // If this party is a Server for at least one partner, then receive
  // the relevant partners' (those partners for which present party is
  // the Server) OT selection bits, and use these to finalize the
  // Obf TT. Then send the Obf TT to (Client) partners.
  // Respectively, for all partners for which present partner is Client,
  // listen for Obf TT.
  for (const int i : partner_communication_order_) {
    if (!GateDependsOn(i, depends_on)) continue;
    if (i > self_party_index_) {
      // Present party is Server: Compute and Send Obf TT.
      // First, parse selection bits received from Client.
      unsigned char received_selection_bits;
      while (!partners_[i].received_bytes_.Pop(&received_selection_bits)) {
        // If 'should_receive' is true, received_bytes_ should have been populated in
        // the ReceiveFromPartner() call above.
        if (should_receive) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR(
              "Unable to receive gate (" + Itoa(circuit_.num_gates_processed_) +
              ") communication from Partner " + Itoa(i));
          return false;
        }
        uint64_t sleep_time = 0;
        if (!partners_[i].receive_communication_sleep_.GetSleepTime(
                &sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR(
              "Unable to get appropriate amount of time to sleep for "
              "(" +
              Itoa(sleep_time) + ")");
          return false;
        }
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        receive_selection_bit_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
      }
      partners_[i].receive_communication_sleep_.Reset();

      const bool first_selection_bit = received_selection_bits & 1;
      const bool second_selection_bit = received_selection_bits & (1 << 1);

      // Grab Server OT Bits.
      TruthTableMask<bool> server_ot_bits;
      while (!partners_[i].server_ot_bits_.Pop(&server_ot_bits)) {
        const ThreadStatus status =
            GetThreadStatus(CircuitByGateTask::READ_OT_BITS);
        if (!IsProgressBeingMade(SleepReason::EVAL_FOR_OT_BITS, status)) {
          // Check again that OT bits still not available.
          if (partners_[i].server_ot_bits_.Pop(&server_ot_bits)) break;
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR("Unable to get Server OT bits.");
          return false;
        }
        // That code reached here means the OT Parsing thread is active.
        // Wait for it to read ot bits for this gate.
        uint64_t sleep_time;
        if (!circuit_.evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR("Unable to get appropriate amount of time to sleep for.");
          return false;
        }
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        ot_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
      }
      circuit_.evaluate_gates_sleep_.Reset();

      // Construct Obfuscated Truth Table.
      const bool random_partner_bit =
          kDebugMode ? 0 : GrabServerRandomBit(partners_[i]);
      ObfuscatedTruthTable<bool> obfuscated_truth_table;
      ConstructObfuscatedTruthTable(
          first_selection_bit,
          second_selection_bit,
          random_partner_bit,
          server_ot_bits,
          truth_table,
          &obfuscated_truth_table);
      *output ^= random_partner_bit;

      // Load Obf TT to be sent to Partner (Client).
      unsigned char to_send = obfuscated_truth_table.first.first ? 1 : 0;
      if (obfuscated_truth_table.first.second) {
        to_send = (unsigned char) (to_send + (1 << 1));
      }
      if (obfuscated_truth_table.second.first) {
        to_send = (unsigned char) (to_send + (1 << 2));
      }
      if (obfuscated_truth_table.second.second) {
        to_send = (unsigned char) (to_send + (1 << 3));
      }
      if (partners_[i].bytes_to_send_.capacity() < 0 ||
          (size_t) partners_[i].bytes_to_send_.capacity() <
              partners_[i].bytes_to_send_.size() + 1) {
        partners_[i].bytes_to_send_.reserve(
            1 + partners_[i].bytes_to_send_.size());
      }
      if (!partners_[i].bytes_to_send_.Push(to_send)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR("Send buffer full.");
        return false;
      }

      // Send Obf TT to Partner, if appropriate.
      if (debug_) StartTimer(&send_obf_tt_timer_);
      if (should_send && !SendToPartner(false, i, 1)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR(
            "Unable to send gate (" + Itoa(circuit_.num_gates_processed_) +
            ") communication to Partner " + Itoa(i));
        if (debug_) StopTimer(&send_obf_tt_timer_);
        return false;
      }
      if (debug_) StopTimer(&send_obf_tt_timer_);
    } else {
      // Present party is Client: Receive Obf TT from Server, and XOR
      // it with final output share.
      if (debug_) StartTimer(&receive_obf_tt_timer_);
      if (should_receive && !ReceiveFromPartner(true, i, 1, 0)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR(
            "Unable to receive gate (" + Itoa(circuit_.num_gates_processed_) +
            ") communication from Partner " + Itoa(i));
        if (debug_) StopTimer(&receive_obf_tt_timer_);
        return false;
      }
      if (debug_) StopTimer(&receive_obf_tt_timer_);

      // Grab received bytes.
      unsigned char packed_obf_tt;
      while (!partners_[i].received_bytes_.Pop(&packed_obf_tt)) {
        // If 'should_receive' is true, received_bytes_ should have been populated in
        // the ReceiveFromPartner() call above.
        if (should_receive) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR(
              "Unable to receive gate (" + Itoa(circuit_.num_gates_processed_) +
              ") communication from Partner " + Itoa(i));
          return false;
        }
        uint64_t sleep_time = 0;
        if (!partners_[i].receive_communication_sleep_.GetSleepTime(
                &sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR(
              "Unable to get appropriate amount of time to sleep for "
              "(" +
              Itoa(sleep_time) + ")");
          return false;
        }
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        receive_obfuscated_truth_table_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
      }
      partners_[i].receive_communication_sleep_.Reset();

      // Parse received bytes as ObfuscatedTruthTable.
      ObfuscatedTruthTable<bool> obf_tt;
      obf_tt.first.first = packed_obf_tt & 1;
      obf_tt.first.second = packed_obf_tt & (1 << 1);
      obf_tt.second.first = packed_obf_tt & (1 << 2);
      obf_tt.second.second = packed_obf_tt & (1 << 3);

      // Extract the output value.
      const bool output_share_i = SelectValueFromObfuscatedTruthTable(
          (second_selection_bits[i] & 1),
          (second_selection_bits[i] & (1 << 1)),
          left,
          right,
          obf_tt);

      // Update final output share.
      *output ^= output_share_i;
    }
  }

  return true;
}

bool GmwByGate::EvaluateNonLocalBooleanGatePrelim(
    const bool,
    const bool,
    const CircuitOperation op,
    const vector<char>& depends_on,
    const bool& left,
    const bool& right,
    bool* store_result,
    bool* output) {
  const int num_parties = depends_on.empty() ? (int) partners_.size() :
                                               NumDependentParties(depends_on);
  const int lowest_party_index = GetLowestDependentPartyIndex(depends_on);
  const int highest_party_index = depends_on.empty() ?
      (int) partners_.size() - 1 :
      GetHighestDependentPartyIndex(depends_on);

  // First, generate the local computation required for this gate type.
  if (!ComputeLocalValue(
          num_parties, lowest_party_index, op, left, right, output)) {
    return false;
  }

  // Nothing else to do, if this party is the only one computing this gate.
  if (lowest_party_index == highest_party_index) {
    return true;
  }

  // That code reached here means that this is a gmw_gate for this party
  // (and at least one of his partners). Handle it as such.
  *store_result = false;  // The result will be written to output wires later.
  PrelimEvalInfoPerLevel& prelim_info =
      prelim_eval_info_[circuit_.num_curr_level_gates_processed_];
  prelim_info.left_right_wires_ = make_pair(left, right);

  // Generate truth table, provided this Party will act as GMW 'Server'
  // for at least one Partner.
  TruthTableMask<bool>& truth_table = prelim_info.truth_table_;
  if (self_party_index_ < highest_party_index) {
    for (int left_wire = 0; left_wire < 2; ++left_wire) {
      const bool left_to_use = left != (left_wire == 0 ? false : true);
      for (int right_wire = 0; right_wire < 2; ++right_wire) {
        const bool right_to_use = right != (right_wire == 0 ? false : true);
        bool* entry_to_set = (left_wire == 0 && right_wire == 0) ?
            &truth_table.first.first :
            (left_wire == 0 && right_wire == 1) ?
            &truth_table.first.second :
            (left_wire == 1 && right_wire == 0) ?
            &truth_table.second.first :
            (left_wire == 1 && right_wire == 1) ?
            &truth_table.second.second :
            // Will never happen, could've just ended the clause above, but
            // kept below line to make code above easier to read/understand.
            nullptr;
        // For N > 2 Players, each gate's input wire(s) are shared among all players,
        // and the gate evaluation is done peer-to-peer, where the actual pairwise
        // operation that the players perform is always AND, regardless of the
        // actual gate operation. Thus, this truth table is for AND.
        // See discussion in gmw_circuit.h for details.
        *entry_to_set = left_to_use && right_to_use;
      }
    }
  }

  // Prepare Selection bits.
  vector<unsigned char>& second_selection_bits =
      prelim_info.selection_bits_sent_;
  if (self_party_index_ > 0) {
    second_selection_bits.resize(self_party_index_, 0);
  }
  for (const int i : partner_communication_order_) {
    if (!GateDependsOn(i, depends_on)) continue;
    partners_[i].gmw_gates_this_level_.push_back(
        circuit_.num_curr_level_gates_processed_);
    if (i >= self_party_index_) continue;
    // Present party is Client: Send OT Selection bits.
    // Grab OT bits to send.
    SelectionBitAndValuePair<bool> selection_bits_for_partner_i;
    while (!partners_[i].client_ot_bits_.Pop(&selection_bits_for_partner_i)) {
      const ThreadStatus status =
          GetThreadStatus(CircuitByGateTask::READ_OT_BITS);
      if (!IsProgressBeingMade(SleepReason::EVAL_FOR_OT_BITS, status)) {
        // Check again that OT bits still not available.
        if (partners_[i].client_ot_bits_.Pop(&selection_bits_for_partner_i))
          break;
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR("Unable to get Client OT bits.");
        return false;
      }
      // That code reached here means the OT Parsing thread is active.
      // Wait for it to read ot bits for this gate.
      uint64_t sleep_time;
      if (!circuit_.evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
          // usleep throws error is sleeping more than 1 second
          sleep_time > 1000000) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR("Unable to get appropriate amount of time to sleep for.");
        return false;
      }
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
      ot_sleep_time_ += sleep_time;
      usleep((useconds_t) sleep_time);
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
    }
    circuit_.evaluate_gates_sleep_.Reset();

    // Compute what the selection bits should be (based on OT bits and
    // current wire values); then pack these selection bits into a single byte.
    unsigned char to_send_to_i = 0;
    if (selection_bits_for_partner_i.first.first != left) {
      to_send_to_i = (unsigned char) (to_send_to_i + 1);
    }
    if (selection_bits_for_partner_i.second.first != right) {
      to_send_to_i = (unsigned char) (to_send_to_i + (1 << 1));
    }
    // Store the selection secrets for later use (will be needed to decode the
    // obfuscated truth table that each Partner sends).
    if (selection_bits_for_partner_i.first.second) {
      second_selection_bits[i] = (unsigned char) (second_selection_bits[i] + 1);
    }
    if (selection_bits_for_partner_i.second.second) {
      second_selection_bits[i] =
          (unsigned char) (second_selection_bits[i] + (1 << 1));
    }
    if (partners_[i].bytes_to_send_.capacity() < 0 ||
        (size_t) partners_[i].bytes_to_send_.capacity() <
            partners_[i].bytes_to_send_.size() + 1) {
      partners_[i].bytes_to_send_.reserve(
          1 + partners_[i].bytes_to_send_.size());
    }
    if (!partners_[i].bytes_to_send_.Push(to_send_to_i)) {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      LOG_ERROR("Send buffer is full.");
      return false;
    }
  }

  return true;
}

bool GmwByGate::EvaluateBooleanLevel(
    const bool should_send, const bool should_receive) {
  // Send/Receive selection bits.
  for (const int i : partner_communication_order_) {
    if (partners_[i].gmw_gates_this_level_.empty()) continue;
    if (i < self_party_index_) {
      // Present party is Client: Send OT Selection bits.
      if (debug_) StartTimer(&send_selection_bits_timer_);
      if (should_send &&
          !SendToPartner(false, i, partners_[i].gmw_gates_this_level_.size())) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR(
            "Unable to send level (" + Itoa(circuit_.num_levels_processed_) +
            ") communication to Partner " + Itoa(i));
        if (debug_) StopTimer(&send_selection_bits_timer_);
        return false;
      }
      if (debug_) StopTimer(&send_selection_bits_timer_);
    } else {
      // Present party is Server: Receive OT Selection bits.
      if (debug_) StartTimer(&receive_selection_bits_timer_);
      if (should_receive &&
          !ReceiveFromPartner(
              true, i, partners_[i].gmw_gates_this_level_.size(), 0)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR(
            "Unable to receive level (" + Itoa(circuit_.num_levels_processed_) +
            ") communication from Partner " + Itoa(i));
        if (debug_) StopTimer(&receive_selection_bits_timer_);
        return false;
      }
      if (debug_) StopTimer(&receive_selection_bits_timer_);
    }
  }

  // If this party is a Server (for at least one partner), then use the
  // received OT selection bits from their partners, and use these to
  // finalize the Obf TT. Then send the Obf TT to (Client) partners.
  // Respectively, for all partners for which present partner is Client,
  // listen for Obf TT.
  const GateIndexDataType num_gates_this_level =
      circuit_.num_gates_per_level_[circuit_.num_levels_processed_];
  // Maintain a map from <gate index, output value>. We'll update this map
  // each time the present party has a gmw gate with a partner.
  map<GateIndexDataType, bool> gate_to_value;
  for (const int i : partner_communication_order_) {
    const GateIndexDataType num_gmw_gates =
        (GateIndexDataType) partners_[i].gmw_gates_this_level_.size();
    if (i <= self_party_index_ || num_gmw_gates == 0) continue;
    // Go through each gate on this level and parse received selection bit,
    // and then update obfuscated tt appropriately, and push to send buffer.
    GateIndexDataType gmw_gate_index = 0;
    for (GateIndexDataType gate_i = 0; gate_i < num_gates_this_level; ++gate_i) {
      if (gmw_gate_index >= num_gmw_gates) break;
      if (gate_i != partners_[i].gmw_gates_this_level_[gmw_gate_index]) continue;
      ++gmw_gate_index;
      unsigned char received_selection_bits;
      while (!partners_[i].received_bytes_.Pop(&received_selection_bits)) {
        // If 'should_receive' is true, received_bytes_ should have been populated in
        // the ReceiveFromPartner() call above.
        if (should_receive) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR(
              "Unable to receive ot bits for level (" +
              Itoa(circuit_.num_levels_processed_) +
              ") communication from Partner " + Itoa(i));
          return false;
        }
        uint64_t sleep_time = 0;
        if (!partners_[i].receive_communication_sleep_.GetSleepTime(
                &sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR(
              "Unable to get appropriate amount of time to sleep for "
              "(" +
              Itoa(sleep_time) + ")");
          return false;
        }
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        receive_selection_bit_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
      }
      partners_[i].receive_communication_sleep_.Reset();

      const bool first_selection_bit = received_selection_bits & 1;
      const bool second_selection_bit = received_selection_bits & (1 << 1);

      // Grab Server OT Bits.
      TruthTableMask<bool> server_ot_bits;
      while (!partners_[i].server_ot_bits_.Pop(&server_ot_bits)) {
        const ThreadStatus status =
            GetThreadStatus(CircuitByGateTask::READ_OT_BITS);
        if (!IsProgressBeingMade(SleepReason::EVAL_FOR_OT_BITS, status)) {
          // Check again that OT bits still not available.
          if (partners_[i].server_ot_bits_.Pop(&server_ot_bits)) break;
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR("Unable to get Server OT bits.");
          return false;
        }
        // That code reached here means the OT Parsing thread is active.
        // Wait for it to read ot bits for this gate.
        uint64_t sleep_time;
        if (!circuit_.evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR("Unable to get appropriate amount of time to sleep for.");
          return false;
        }
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        ot_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
      }
      circuit_.evaluate_gates_sleep_.Reset();

      // Construct Obfuscated Truth Table.
      const bool random_partner_bit =
          kDebugMode ? 0 : GrabServerRandomBit(partners_[i]);
      ObfuscatedTruthTable<bool> obfuscated_truth_table;
      ConstructObfuscatedTruthTable(
          first_selection_bit,
          second_selection_bit,
          random_partner_bit,
          server_ot_bits,
          prelim_eval_info_[gate_i].truth_table_,
          &obfuscated_truth_table);

      // Store output.
      bool* curr_value = FindOrNull(gate_i, gate_to_value);
      if (curr_value == nullptr) {
        const bool orig_local_value =
            GetValue<bool>(*((const BoolDataType*) prelim_eval_info_[gate_i]
                                 .local_value_.value_.get()));
        gate_to_value.insert(
            make_pair(gate_i, orig_local_value ^ random_partner_bit));
      } else {
        *curr_value ^= random_partner_bit;
      }

      // Load Obf TT to be sent to Partner (Client).
      unsigned char to_send = obfuscated_truth_table.first.first ? 1 : 0;
      if (obfuscated_truth_table.first.second) {
        to_send = (unsigned char) (to_send + (1 << 1));
      }
      if (obfuscated_truth_table.second.first) {
        to_send = (unsigned char) (to_send + (1 << 2));
      }
      if (obfuscated_truth_table.second.second) {
        to_send = (unsigned char) (to_send + (1 << 3));
      }
      if (partners_[i].bytes_to_send_.capacity() < 0 ||
          (size_t) partners_[i].bytes_to_send_.capacity() <
              partners_[i].bytes_to_send_.size() + 1) {
        partners_[i].bytes_to_send_.reserve(
            1 + partners_[i].bytes_to_send_.size());
      }
      if (!partners_[i].bytes_to_send_.Push(to_send)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR("Send buffer full.");
        return false;
      }
    }
  }

  // Send/Receive obfuscated truth table.
  for (const int i : partner_communication_order_) {
    if (partners_[i].gmw_gates_this_level_.empty()) continue;
    if (i < self_party_index_) {
      // Present party is Client: Receive Obf TT from Server.
      if (debug_) StartTimer(&receive_obf_tt_timer_);
      if (should_receive &&
          !ReceiveFromPartner(
              true, i, partners_[i].gmw_gates_this_level_.size(), 0)) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR(
            "Unable to receive level (" + Itoa(circuit_.num_levels_processed_) +
            ") communication from Partner " + Itoa(i));
        if (debug_) StopTimer(&receive_obf_tt_timer_);
        return false;
      }
      if (debug_) StopTimer(&receive_obf_tt_timer_);
    } else {
      // Send Obf TT to Partner, if appropriate.
      if (debug_) StartTimer(&send_obf_tt_timer_);
      if (should_send &&
          !SendToPartner(false, i, partners_[i].gmw_gates_this_level_.size())) {
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
        LOG_ERROR(
            "Unable to send level (" + Itoa(circuit_.num_levels_processed_) +
            ") communication to Partner " + Itoa(i));
        if (debug_) StopTimer(&send_obf_tt_timer_);
        return false;
      }
      if (debug_) StopTimer(&send_obf_tt_timer_);
    }
  }

  // If this party is a Client (for at least one partner), then use the
  // received Obfuscated truth tables from their partners, and use these to
  // finalize this party's output for this gate.
  for (const int i : partner_communication_order_) {
    const GateIndexDataType num_gmw_gates =
        (GateIndexDataType) partners_[i].gmw_gates_this_level_.size();
    if (i >= self_party_index_ || num_gmw_gates == 0) continue;
    // Go through each gate on this level and parse received Obf TT,
    // and then update output appropriately.
    GateIndexDataType gmw_gate_index = 0;
    for (GateIndexDataType gate_i = 0; gate_i < num_gates_this_level; ++gate_i) {
      if (gmw_gate_index >= num_gmw_gates) break;
      if (gate_i != partners_[i].gmw_gates_this_level_[gmw_gate_index]) continue;
      ++gmw_gate_index;
      // Grab received bytes.
      unsigned char packed_obf_tt;
      while (!partners_[i].received_bytes_.Pop(&packed_obf_tt)) {
        // If 'should_receive' is true, received_bytes_ should have been populated in
        // the ReceiveFromPartner() call above.
        if (should_receive) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR(
              "Unable to receive obf tt for level (" +
              Itoa(circuit_.num_levels_processed_) +
              ") communication from Partner " + Itoa(i));
          return false;
        }
        uint64_t sleep_time = 0;
        if (!partners_[i].receive_communication_sleep_.GetSleepTime(
                &sleep_time) ||
            // usleep throws error is sleeping more than 1 second
            sleep_time > 1000000) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          LOG_ERROR(
              "Unable to get appropriate amount of time to sleep for "
              "(" +
              Itoa(sleep_time) + ")");
          return false;
        }
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
        receive_obfuscated_truth_table_sleep_time_ += sleep_time;
        usleep((useconds_t) sleep_time);
        SetThreadStatus(
            CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
      }
      partners_[i].receive_communication_sleep_.Reset();

      // Parse received bytes as ObfuscatedTruthTable.
      ObfuscatedTruthTable<bool> obf_tt;
      obf_tt.first.first = packed_obf_tt & 1;
      obf_tt.first.second = packed_obf_tt & (1 << 1);
      obf_tt.second.first = packed_obf_tt & (1 << 2);
      obf_tt.second.second = packed_obf_tt & (1 << 3);

      // Extract the output value.
      const unsigned char second_selection_bits =
          prelim_eval_info_[gate_i].selection_bits_sent_[i];
      const bool output_share_i = SelectValueFromObfuscatedTruthTable(
          (second_selection_bits & 1),
          (second_selection_bits & (1 << 1)),
          prelim_eval_info_[gate_i].left_right_wires_.first,
          prelim_eval_info_[gate_i].left_right_wires_.second,
          obf_tt);

      // Store final output share.
      bool* curr_value = FindOrNull(gate_i, gate_to_value);
      if (curr_value == nullptr) {
        const bool orig_local_value =
            GetValue<bool>(*((const BoolDataType*) prelim_eval_info_[gate_i]
                                 .local_value_.value_.get()));
        gate_to_value.insert(
            make_pair(gate_i, orig_local_value ^ output_share_i));
      } else {
        *curr_value ^= output_share_i;
      }
    }
  }

  // Store all outputs.
  for (const pair<const GateIndexDataType, bool>& output_i : gate_to_value) {
    GenericValue temp(output_i.second);
    circuit_.StoreOutputValue(
        true, prelim_eval_info_[output_i.first].output_wires_, temp);
  }

  return true;
}

bool GmwByGate::EvaluateNonLocalArithmeticGate(
    const bool,
    const bool,
    const CircuitOperation,
    const vector<char>&,
    const GenericValue&,
    const GenericValue&,
    GenericValue*) {
  // TODO(paul): Implement this (for ADD, SUB, and MULT only).
  return false;
}
bool GmwByGate::EvaluateArithmeticLevel(const bool, const bool) {
  // TODO(paul): Implement this (for ADD, SUB, and MULT only).
  return false;
}

bool GmwByGate::SetupOtParams(const int party) {
  // Determine how many gates (of each {Bool, Arith} type) this pair of parties
  // should engage in OT for (i.e. gate is non-local, and depends on inputs from both).
  const GateIndexDataType num_mutual_non_local_bool_gates = GetNumNonLocalGates(
      (int) partners_.size(),
      min(party, self_party_index_),
      max(party, self_party_index_),
      circuit_.num_non_local_boolean_gates_per_party_pairs_);
  const GateIndexDataType num_mutual_non_local_arith_gates = GetNumNonLocalGates(
      (int) partners_.size(),
      min(party, self_party_index_),
      max(party, self_party_index_),
      circuit_.num_non_local_arithmetic_gates_per_party_pairs_);

  // The factor of '2' is because we need 1-out-of-4 OT for each
  // gate, as opposed to 1-out-of-2.
  const uint64_t num_secrets =
      2 * (num_mutual_non_local_bool_gates + num_mutual_non_local_arith_gates);
  const string lower =
      party < self_party_index_ ? Itoa(party) : Itoa(self_party_index_);
  const string upper =
      party > self_party_index_ ? Itoa(party) : Itoa(self_party_index_);
  const string paillier_n_file =
      ot_bits_dir_ + lower + "_" + upper + "_" + kKeyNFile;
  const string paillier_g_file =
      ot_bits_dir_ + lower + "_" + upper + "_" + kKeyGFile;
  const string paillier_mu_file =
      ot_bits_dir_ + lower + "_" + upper + "_" + kKeyMuFile;
  const string paillier_lambda_file =
      ot_bits_dir_ + lower + "_" + upper + "_" + kKeyLambdaFile;

  if (party > self_party_index_) {
    OTProtocolCombo ot_to_use;
    partners_[party].server_ot_params_.reset(
        new ServerIKNPOTExtensionParams());
    ot_to_use = (base_ot_ == OTProtocol::PAILLIER) ?
        OTProtocolCombo::IKNP_FROM_PRG_FROM_PAILLIER :
        OTProtocolCombo::IKNP_FROM_PRG_FROM_DIFFIE_HELLMAN;
    if (!SetServerOTParams(
            debug_,
            true,
            OTParamsSetup(
                ot_to_use,
                num_secrets,
                1,
                paillier_n_file,
                paillier_g_file,
                paillier_lambda_file,
                paillier_mu_file,
                elliptic_curve_based_dh_,
                nullptr,
                128 / CHAR_BIT,  // We use AES-128 for PRG
                128 /
                    CHAR_BIT,  // Use k = 128 bits for RO security parameter 'k'
                nullptr,
                nullptr,
                partners_[party].socket_.release(),
                num_threads_),
            partners_[party].server_ot_params_.get())) {
      DLOG_ERROR("Unable to setup OT Parameters.");
      return false;
    }
  } else {
    OTProtocolCombo ot_to_use;
    partners_[party].client_ot_params_.reset(
        new ClientIKNPOTExtensionParams());
    ot_to_use = (base_ot_ == OTProtocol::PAILLIER) ?
        OTProtocolCombo::IKNP_FROM_PRG_FROM_PAILLIER :
        OTProtocolCombo::IKNP_FROM_PRG_FROM_DIFFIE_HELLMAN;
    if (!SetClientOTParams(
            debug_,
            true,
            OTParamsSetup(
                ot_to_use,
                "",
                num_secrets,
                1,
                elliptic_curve_based_dh_,
                nullptr,
                128 / CHAR_BIT,  // We use AES-128 for PRG
                128 /
                    CHAR_BIT,  // Use k = 128 bits for RO security parameter 'k'
                nullptr,
                nullptr,
                partners_[party].socket_.release(),
                num_threads_),
            partners_[party].client_ot_params_.get())) {
      DLOG_ERROR("Unable to setup OT Parameters.");
      return false;
    }
  }

  return true;
}

bool GmwByGate::GenerateOtBits(const map<int, GateIndexDataType>& partners) {
  if (debug_) StartTimer(&generate_ot_bits_timer_);
  int num_done = -1;
  for (const pair<const int, GateIndexDataType>& pair_i : partners) {
    ++num_done;
    const int i = pair_i.first;
    const GateIndexDataType& num_non_local_gates = pair_i.second;
    if (num_non_local_gates == 0) continue;
    // Log status, if appropriate.
    if (!excel_logging_file_.empty()) {
      AppendToFile(
          excel_logging_file_,
          "OT" + Itoa(num_done) + "/" + Itoa(partners.size()) + "#");
    }

    //   - Setup OT Parameters (based on number of non-local gates).
    if (!SetupOtParams(i)) {
      if (debug_) StopTimer(&generate_ot_bits_timer_);
      return false;
    }

    // Split logic based on whether this party is Server or Client.
    if (i < self_party_index_) {
      // First, generate randomness for Obf. TT, and store in ot_params.
      vector<unsigned char> randomness;
      if (kDebugMode) {
        randomness.resize(num_non_local_gates, 0);
      } else {
        RandomBytes(num_non_local_gates, &randomness);
      }
      vector<ClientSelectionBitAndSecret>* selection_bits =
          &(partners_[i].client_ot_selection_bits_and_output_secret_);
      selection_bits->clear();
      selection_bits->reserve(num_non_local_gates * 2);
      for (uint64_t j = 0; j < num_non_local_gates; ++j) {
        const unsigned char random_byte = randomness[j];
        selection_bits->push_back(ClientSelectionBitAndSecret());
        selection_bits->back().b_ = random_byte & 1;
        selection_bits->push_back(ClientSelectionBitAndSecret());
        selection_bits->back().b_ = random_byte & (1 << 1);
      }

      // Engage in OT protocol.
      partners_[i].client_ot_params_->selection_bits_and_output_secret_ =
          selection_bits;
      if (!ClientOT(partners_[i].client_ot_params_.get())) {
        LOG_ERROR("Failed to generate OT protocol with partner " + Itoa(i));
        if (debug_) StopTimer(&generate_ot_bits_timer_);
        return false;
      }
      // OT protocol can generate extra randomness. The extra randmoness isn't
      // harmful, but for clarity, just keep the OT bits required.
      partners_[i].client_ot_params_->selection_bits_and_output_secret_->resize(
          num_non_local_gates * 2);

      // Write OT bits to file.
      if (write_ot_to_file_) {
        if (!WriteClientOtBitsToFile(
                partners_[i].ot_bits_file_, selection_bits)) {
          LOG_ERROR("Failed to write OT bits for partner " + Itoa(i));
          if (debug_) StopTimer(&generate_ot_bits_timer_);
          return false;
        }
      } else {
        SelectionBitAndValuePair<bool> selection_bits_to_add;
        for (size_t gate = 0; gate < selection_bits->size(); ++gate) {
          const ClientSelectionBitAndSecret& ot_bits = (*selection_bits)[gate];
          // Will pack OT bits for one bool gate (which is 1-out-of-4 OT, or
          // more precisely, two sets of 1-out-of-2 OT) into one byte.
          if (gate % 2 == 0) {
            selection_bits_to_add.first.first = ot_bits.b_;
            selection_bits_to_add.first.second = ot_bits.s_b_[0];
          } else {
            selection_bits_to_add.second.first = ot_bits.b_;
            selection_bits_to_add.second.second = ot_bits.s_b_[0];
            if (!partners_[i].client_ot_bits_.Push(selection_bits_to_add)) {
              LOG_ERROR("Failed to write OT bits for partner " + Itoa(i));
              if (debug_) StopTimer(&generate_ot_bits_timer_);
              return false;
            }
          }
        }
        // Finish last one, if relevant
        if (selection_bits->size() % 2 != 0) {
          selection_bits_to_add.second.first = false;
          selection_bits_to_add.second.second = false;
          if (!partners_[i].client_ot_bits_.Push(selection_bits_to_add)) {
            LOG_ERROR("Failed to write OT bits for partner " + Itoa(i));
            if (debug_) StopTimer(&generate_ot_bits_timer_);
            return false;
          }
        }
      }

      // Reset connection to partner, which was temporarily released for the OT protocol.
      partners_[i].socket_.reset(
          partners_[i].client_ot_params_->connection_to_server_.release());
    } else {
      // First, generate randomness for Obf. TT, and store in ot_params.
      vector<unsigned char> randomness;
      if (kDebugMode) {
        randomness.resize(num_non_local_gates, 0);
      } else {
        RandomBytes(num_non_local_gates, &randomness);
      }
      vector<ServerSecretPair>* secrets = &(partners_[i].server_ot_secrets_);
      secrets->clear();
      secrets->reserve(num_non_local_gates * 2);
      for (uint64_t j = 0; j < num_non_local_gates; ++j) {
        const unsigned char random_byte = randomness[j];
        secrets->push_back(ServerSecretPair(1));
        ServerSecretPair& secret = secrets->back();
        secret.s0_.back() = random_byte & 1;
        secret.s1_.back() = (random_byte >> 1) & 1;
        secrets->push_back(ServerSecretPair(1));
        ServerSecretPair& next_secret = secrets->back();
        next_secret.s0_.back() = (random_byte >> 2) & 1;
        next_secret.s1_.back() = (random_byte >> 3) & 1;
      }

      // Engage in OT protocol.
      partners_[i].server_ot_params_->secrets_ = secrets;
      if (!ServerOT(partners_[i].server_ot_params_.get())) {
        LOG_ERROR("Failed to generate OT protocol with partner " + Itoa(i));
        if (debug_) StopTimer(&generate_ot_bits_timer_);
        return false;
      }
      // OT protocol can generate extra randomness. The extra randmoness isn't
      // harmful, but for clarity, just keep the OT bits required.
      partners_[i].server_ot_params_->secrets_->resize(num_non_local_gates * 2);

      // Write OT bits to file.
      if (write_ot_to_file_) {
        if (!WriteServerOtBitsToFile(partners_[i].ot_bits_file_, secrets)) {
          LOG_ERROR("Failed to write OT bits for partner " + Itoa(i));
          if (debug_) StopTimer(&generate_ot_bits_timer_);
          return false;
        }
      } else {
        TruthTableMask<bool> mask;
        for (size_t gate = 0; gate < secrets->size(); ++gate) {
          const ServerSecretPair& secret = (*secrets)[gate];
          // Will pack OT bits for one bool gate (which is 1-out-of-4 OT, or
          // more precisely, two sets of 1-out-of-2 OT) into one byte.
          if (gate % 2 == 0) {
            mask.first.first = secret.s0_[0];
            mask.first.second = secret.s1_[0];
          } else {
            mask.second.first = secret.s0_[0];
            mask.second.second = secret.s1_[0];
            if (!partners_[i].server_ot_bits_.Push(mask)) {
              LOG_ERROR("Failed to write OT bits for partner " + Itoa(i));
              if (debug_) StopTimer(&generate_ot_bits_timer_);
              return false;
            }
          }
        }
        // Write last byte, if odd number of secrets.
        if ((secrets->size() % 2) == 1) {
          mask.second.first = false;
          mask.second.second = false;
          if (!partners_[i].server_ot_bits_.Push(mask)) {
            LOG_ERROR("Failed to write OT bits for partner " + Itoa(i));
            if (debug_) StopTimer(&generate_ot_bits_timer_);
            return false;
          }
        }
      }

      // Reset connection to partner, which was temporarily released for the OT protocol.
      partners_[i].socket_.reset(
          partners_[i].server_ot_params_->connection_to_client_.release());
    }
  }

  // Log status, if appropriate.
  if (!excel_logging_file_.empty()) {
    AppendToFile(
        excel_logging_file_,
        "OT" + Itoa(partners.size()) + "/" + Itoa(partners.size()) + "#");
  }

  is_ot_bits_gen_done_ = true;
  if (!write_ot_to_file_) is_read_ot_bits_done_ = true;
  if (debug_) StopTimer(&generate_ot_bits_timer_);
  return true;
}

bool GmwByGate::ParseGlobalInputs(
    const bool all_parties_inputs,
    const string& inputs_as_string,
    const vector<math_utils::GenericValue>& inputs) {
  if (debug_) StartTimer(&parse_global_inputs_timer_);
  SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::ACTIVE);

  // Grab which indices (w.r.t. function fingerprint/LHS) this party's inputs
  // correspond to.
  int current_party_first_input_index = 0;
  if (!all_parties_inputs) {
    for (int i = 0; i < self_party_index_; ++i) {
      current_party_first_input_index +=
          (int) circuit_.function_var_names_[i].size();
    }
  }

  // Set (expected) size.
  const size_t num_expected_inputs = all_parties_inputs ?
      circuit_.inputs_.size() :
      circuit_.function_var_names_[self_party_index_].size();
  input_.reserve(num_expected_inputs);

  if (inputs_as_string.empty()) {
    for (const GenericValue& value : inputs) {
      input_.push_back(value);
    }
  } else {
    vector<string> var_names;
    if (all_parties_inputs) {
      for (const vector<string>& party_i_inputs : circuit_.function_var_names_) {
        for (const string& party_i_input_j : party_i_inputs) {
          var_names.push_back(party_i_input_j);
        }
      }
    } else if (
        self_party_index_ >= 0 &&
        circuit_.function_var_names_.size() > (size_t) self_party_index_) {
      var_names = circuit_.function_var_names_[self_party_index_];
    }
    if (!ParseGlobalInputsFromString(
            inputs_as_string,
            current_party_first_input_index,
            var_names,
            circuit_.inputs_,
            &input_)) {
      SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
      if (debug_) StopTimer(&parse_global_inputs_timer_);
      return false;
    }
  }

  // Sanity-Check the number of values parsed matches the number of
  // expected inputs for this party.
  if (input_.size() != num_expected_inputs) {
    SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::FAILED);
    if (debug_) StopTimer(&parse_global_inputs_timer_);
    return false;
  }

  is_parse_input_file_done_ = true;
  SetThreadStatus(CircuitByGateTask::PARSE_INPUTS, ThreadStatus::DONE);
  if (debug_) StopTimer(&parse_global_inputs_timer_);
  return true;
}

bool GmwByGate::ReadCircuitFile(
    const bool parse_function_formula, bool* is_done) {
  return circuit_.ReadCircuitFile(parse_function_formula, this, is_done);
}

bool GmwByGate::ReadOtBitsFile(bool* is_done) {
  // Return if already done.
  if (is_read_ot_bits_done_) {
    SetThreadStatus(CircuitByGateTask::READ_OT_BITS, ThreadStatus::DONE);
    if (is_done != nullptr) *is_done = true;
    return true;
  }

  if (debug_) StartTimer(&load_ot_bits_timer_);
  SetThreadStatus(CircuitByGateTask::READ_OT_BITS, ThreadStatus::ACTIVE);

  // Allocate memory for reading bytes.
  const GateIndexDataType num_non_local_bool_gates = GetNumNonLocalGates(
      (int) partners_.size(),
      self_party_index_,
      -1,
      circuit_.num_non_local_boolean_gates_per_party_pairs_);
  const GateIndexDataType num_non_local_arith_gates = GetNumNonLocalGates(
      (int) partners_.size(),
      self_party_index_,
      -1,
      circuit_.num_non_local_arithmetic_gates_per_party_pairs_);

  int64_t block_size =
      min(kMaxReadFileBlockBytes,
          (int64_t) (num_non_local_bool_gates + num_non_local_arith_gates));
  if (is_done != nullptr &&
      read_ot_bits_thread_num_tasks_until_context_switch_ > 0 &&
      read_ot_bits_thread_num_tasks_until_context_switch_ < block_size) {
    block_size = read_ot_bits_thread_num_tasks_until_context_switch_;
  }
  char* memblock = new char[block_size];
  if (!memblock) {
    LOG_ERROR(
        "Unable to allocate enough memory (" + Itoa(block_size) +
        " bytes) for the circuit file");
    SetThreadStatus(CircuitByGateTask::READ_OT_BITS, ThreadStatus::FAILED);
    if (debug_) StopTimer(&load_ot_bits_timer_);
    return false;
  }

  bool finished_reading = true;

  // Loop over all partners, setting [client | server]_ot_bits_ from the bits
  // read from file.
  for (int party = 0; party < (int) partners_.size(); ++party) {
    if (party == self_party_index_) {
      continue;
    }

    const uint64_t num_expected_bytes =
        GetNumNonLocalGates(
            (int) partners_.size(),
            min(self_party_index_, party),
            max(self_party_index_, party),
            circuit_.num_non_local_boolean_gates_per_party_pairs_) +
        GetNumNonLocalGates(
            (int) partners_.size(),
            min(self_party_index_, party),
            max(self_party_index_, party),
            circuit_.num_non_local_arithmetic_gates_per_party_pairs_);

    // Nothing to do for this partner if there are no non-local gates.
    if (num_expected_bytes == 0) continue;

    // Open ot_bits file file.
    ifstream file(partners_[party].ot_bits_file_, ios::in | ios::binary);
    if (!file.is_open()) {
      SetThreadStatus(CircuitByGateTask::READ_OT_BITS, ThreadStatus::FAILED);
      LOG_ERROR(
          "Unable to open circuit file: '" + partners_[party].ot_bits_file_ +
          "'");
      delete[] memblock;
      if (debug_) StopTimer(&load_ot_bits_timer_);
      return false;
    }
    file.seekg(partners_[party].ot_bits_file_next_char_, ios::beg);

    // Will read bytes from the OT file into the current memblock,
    // where the number of bytes read is:
    //   a) All remaining bytes
    //   b) kMaxReadFileBlockBytes
    //   c) read_ot_bits_thread_num_tasks_until_context_switch_
    // In case (b), we should keep reading more bytes after reading the block.
    // Otherwise, should proceed to next party.
    uint64_t num_bytes_read = 0;
    while (partners_[party].ot_bits_file_next_char_ < num_expected_bytes &&
           (read_ot_bits_thread_num_tasks_until_context_switch_ < 0 ||
            (uint64_t) read_ot_bits_thread_num_tasks_until_context_switch_ >
                num_bytes_read)) {
      // Read block of bytes.
      const int64_t remaining_bytes =
          num_expected_bytes - partners_[party].ot_bits_file_next_char_;
      int64_t current_block_size = min(remaining_bytes, block_size);
      file.read(memblock, current_block_size);
      partners_[party].ot_bits_file_next_char_ += current_block_size;
      num_bytes_read += current_block_size;

      // Parse bytes as OT bits.
      if (party < self_party_index_) {
        // Current party will act as the Client for this partner. Parse OT bytes
        // as selection bits.
        for (int64_t i = 0; i < current_block_size; ++i) {
          const char current_byte = memblock[i];
          SelectionBitAndValuePair<bool> selection_bits;
          selection_bits.first.first = current_byte & 1;
          selection_bits.first.second = current_byte & (1 << 1);
          selection_bits.second.first = current_byte & (1 << 2);
          selection_bits.second.second = current_byte & (1 << 3);
          if (!partners_[party].client_ot_bits_.Push(selection_bits)) {
            SetThreadStatus(
                CircuitByGateTask::READ_OT_BITS, ThreadStatus::FAILED);
            LOG_ERROR(
                "Unable to store OT selection bits for partner " + Itoa(party));
            file.close();
            delete[] memblock;
            if (debug_) StopTimer(&load_ot_bits_timer_);
            return false;
          }
        }
      } else {
        // Current party will act as the Server for this partner. Parse OT bytes
        // as obfuscated TT bits.
        for (int64_t i = 0; i < current_block_size; ++i) {
          const char current_byte = memblock[i];
          TruthTableMask<bool> mask;
          mask.first.first = current_byte & 1;
          mask.first.second = current_byte & (1 << 1);
          mask.second.first = current_byte & (1 << 2);
          mask.second.second = current_byte & (1 << 3);
          if (!partners_[party].server_ot_bits_.Push(mask)) {
            SetThreadStatus(
                CircuitByGateTask::READ_OT_BITS, ThreadStatus::FAILED);
            LOG_ERROR("Unable to store OT mask for partner " + Itoa(party));
            file.close();
            delete[] memblock;
            if (debug_) StopTimer(&load_ot_bits_timer_);
            return false;
          }
        }
      }
    }
    file.close();
    finished_reading &=
        (partners_[party].ot_bits_file_next_char_ == num_expected_bytes);
  }

  delete[] memblock;

  if (finished_reading) {
    SetThreadStatus(CircuitByGateTask::READ_OT_BITS, ThreadStatus::DONE);
    is_read_ot_bits_done_ = true;
    if (is_done != nullptr) *is_done = true;
  } else {
    if (is_done != nullptr) {
      SetThreadStatus(CircuitByGateTask::READ_OT_BITS, ThreadStatus::PAUSED);
      *is_done = false;
    } else {
      SetThreadStatus(CircuitByGateTask::READ_OT_BITS, ThreadStatus::FAILED);
      if (debug_) StopTimer(&load_ot_bits_timer_);
      return false;
    }
  }

  if (debug_) StopTimer(&load_ot_bits_timer_);
  return true;
}

bool GmwByGate::EvaluateCircuit(
    const bool should_send, const bool should_receive, bool* is_done) {
  // Return if already done.
  if (is_evaluate_circuit_done_) {
    SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::DONE);
    if (is_done != nullptr) *is_done = true;
    return true;
  }

  if (debug_) StartTimer(&evaluate_circuit_timer_);
  SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);

  // First check things that need to happen before evaluation starts
  // (Number of Gates, Global Input Mappings, Global Input Values) are done.
  while (!is_circuit_file_metadata_done_ || !is_ot_bits_gen_done_ ||
         !is_parse_input_file_done_ || !is_input_exchanged_done_) {
    if (is_done != nullptr) {
      *is_done = false;
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::PAUSED);
      if (debug_) StopTimer(&evaluate_circuit_timer_);
      return true;
    }
    // Sanity-check progress is being made on the things not yet done that
    // we are waiting for.
    if (!is_circuit_file_metadata_done_) {
      const ThreadStatus* status =
          FindOrNull(CircuitByGateTask::READ_CIRCUIT_FILE, thread_status_);
      if (status == nullptr || *status != ThreadStatus::ACTIVE) {
        // Re-check is_circuit_file_metadata_done_, on the off-chance this
        // has been set to true since the check in the while loop condition.
        if (!is_circuit_file_metadata_done_) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          const int status_int =
              status == nullptr ? -1 : static_cast<int>(*status);
          LOG_ERROR(
              "Circuit File reading thread is not active: " + Itoa(status_int));
          if (debug_) StopTimer(&evaluate_circuit_timer_);
          return false;
        }
      }
    }
    if (!is_ot_bits_gen_done_) {
      const ThreadStatus* status =
          FindOrNull(CircuitByGateTask::GENERATE_OT_BITS, thread_status_);
      if (status == nullptr || *status != ThreadStatus::ACTIVE) {
        // Re-check is_ot_bits_gen_done_, on the off-chance this
        // has been set to true since the check in the while loop condition.
        if (!is_ot_bits_gen_done_) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          const int status_int =
              status == nullptr ? -1 : static_cast<int>(*status);
          LOG_ERROR("OT Generation thread is not active: " + Itoa(status_int));
          if (debug_) StopTimer(&evaluate_circuit_timer_);
          return false;
        }
      }
    }
    if (!is_parse_input_file_done_ || !is_input_exchanged_done_) {
      const ThreadStatus* parse_inputs_status =
          FindOrNull(CircuitByGateTask::PARSE_INPUTS, thread_status_);
      const ThreadStatus* exchange_inputs_status =
          FindOrNull(CircuitByGateTask::EXCHANGE_GLOBAL_INPUTS, thread_status_);
      if (parse_inputs_status == nullptr || exchange_inputs_status == nullptr ||
          (*parse_inputs_status != ThreadStatus::ACTIVE &&
           *exchange_inputs_status != ThreadStatus::ACTIVE)) {
        // Re-check if inputs have been exchanged, on the off-chance this
        // has been set to true since the check in the while loop condition.
        if (!is_parse_input_file_done_ || !is_input_exchanged_done_) {
          SetThreadStatus(
              CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
          const int status_int = parse_inputs_status == nullptr ?
              -1 :
              static_cast<int>(*parse_inputs_status);
          LOG_ERROR(
              "Circuit File reading thread is not active: " + Itoa(status_int));
          if (debug_) StopTimer(&evaluate_circuit_timer_);
          return false;
        }
      }
    }
    uint64_t sleep_time;
    if (!circuit_.evaluate_gates_sleep_.GetSleepTime(&sleep_time) ||
        // usleep throws error is sleeping more than 1 second
        sleep_time > 1000000) {
      SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::FAILED);
      LOG_ERROR("Unable to get appropriate amount of time to sleep for.");
      if (debug_) StopTimer(&evaluate_circuit_timer_);
      return false;
    }
    SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ASLEEP);
    evaluate_circuit_sleep_time_ += sleep_time;
    usleep((useconds_t) sleep_time);
    SetThreadStatus(CircuitByGateTask::EVALUATE_CIRCUIT, ThreadStatus::ACTIVE);
  }

  // Use circuit_.evaluate_gates_timer_ for time for evaluating the gates.
  if (debug_) StopTimer(&evaluate_circuit_timer_);
  return circuit_.EvaluateCircuit(
      eval_by_gate_,
      should_send,
      should_receive,
      this,
      &EvaluateGateFunctionPointer,
      &EvaluateLevelFunctionPointer,
      is_done);
}

bool GmwByGate::PrintOutputs(
    const bool print_output,
    const bool print_metadata,
    const bool print_timers,
    const bool print_socket_info,
    const string& prefix,
    const string& suffix,
    const string& filename) {
  streambuf* temp;
  ofstream output_file;
  if (filename.empty()) {
    ostream* tmp = GetLogStream();
    temp = tmp == nullptr ? cout.rdbuf() : tmp->rdbuf();
  } else {
    // Open output file.
    if (!CreateDir(GetDirectory(filename))) {
      LOG_ERROR("Unable to create directory for output file '" + filename + "'");
      return false;
    }
    output_file.open(filename);
    if (!output_file.is_open()) {
      LOG_ERROR("Unable to open output file '" + filename + "'");
      return false;
    }
    temp = output_file.rdbuf();
  }
  ostream out(temp);

  // Write prefix.
  if (!prefix.empty()) out << prefix;

  if (print_timers) {
    out << PrintTimerInfo() << endl;
  }

  if (print_socket_info) {
    out << endl << "Connection Info:" << endl;
    for (const PartnerInfo& partner : partners_) {
      if (partner.socket_ != nullptr) {
        out << "Partner " << partner.id_.Print() << ":" << endl;
        out << partner.socket_->PrintSocketStats();
      }
    }
    out << endl << "End Connection Info." << endl;
  }

  if (print_metadata) {
    // Write function.
    if (circuit_.function_description_.empty()) {
      // Default use of DoAll() is to *not* parse the function description
      // (to save time). Since user wants this info in the output file
      // (since print_metadata is true), we need to go ahead and process it now.
      vector<vector<pair<string, DataType>>> input_var_types;
      vector<pair<OutputRecipient, DataType>> output_types;
      if (!ReadCircuitByGateMetadata(
              circuit_.circuit_filename_,
              &circuit_.function_description_,
              &input_var_types,
              &output_types)) {
        return false;
      }
    }
    out << "Circuit:" << endl;
    out << PrintFunction(
        false,
        circuit_.function_var_names_,
        vector<pair<OutputRecipient, DataType>>(),
        circuit_.function_description_);
    out << endl;

    // Write Self-inputs used.
    out << endl << "Self-Inputs Used (" << input_.size() << "):" << endl;
    vector<string> var_names;
    if (!inputs_already_shared_) {
      var_names = circuit_.function_var_names_[self_party_index_];
    } else {
      for (const vector<string>& party_i_inputs : circuit_.function_var_names_) {
        for (const string& party_i_input_j : party_i_inputs) {
          var_names.push_back(party_i_input_j);
        }
      }
    }
    if (var_names.size() != input_.size()) {
      LOG_ERROR("Mismatching number of self-inputs.");
      return false;
    }
    for (size_t i = 0; i < input_.size(); ++i) {
      out << var_names[i] << ": " << GetGenericValueString(input_[i]) << endl;
    }
  }

  // Write outputs.
  if (print_output) {
    const size_t num_outputs = party_outputs_.size();
    out << endl << "Outputs (" << num_outputs << "):" << endl;
    for (size_t i = 0; i < num_outputs; ++i) {
      const GenericValue& output_i = party_outputs_[i];
      const OutputRecipient& who = circuit_.output_designations_[i].first;
      const string who_str =
          (who.all_ ? "A" : (who.none_ ? "N" : Join(who.to_, ",")));
      out << "(" << GetDataTypeString(circuit_.output_designations_[i].second)
          << ")[" << who_str << "]:";
      // Print output, whether or not it represents the actual output, or just
      // this party's share of the output. There is a trade-off here between
      // a potentially confusing output if caller doesn't realize they are
      // viewing an output *share* as opposed to the output itself, but we
      // go ahead and print it anyway (as opposed to e.g. printing nothing) since:
      //   a) We have also just printed the OutputRecipient, so the caller
      //      can directly check on the same line if the output is a share or not;
      //   b) If the output (share) is to be used in a later computation, the
      //      caller will need to know the value.
      // This is why the following line is commented out.
      //if (who.all_ || ContainsKey(self_party_index_, who.to_))
      out << GetGenericValueString(output_i);

      out << endl;
    }
  }

  // Write suffix.
  if (!suffix.empty()) out << suffix;

  if (!filename.empty()) output_file.close();

  return true;
}

string GmwByGate::PrintTimerInfo() const {
  string to_return = "";
  const int meaningful_ms = 1;
  vector<string> non_meaningful_timers;

  const int64_t do_all_time = GetElapsedTime(do_all_timer_) / 1000;
  if (do_all_time / 1000 > 0 || do_all_time % 1000 > meaningful_ms) {
    to_return +=
        "  do_all_timer_ (" + test_utils::FormatTime(do_all_time) + "):\n";
  } else {
    non_meaningful_timers.push_back("do_all_timer_");
  }
  const int64_t main_thread_time = GetElapsedTime(main_thread_timer_) / 1000;
  if (main_thread_time / 1000 > 0 || main_thread_time % 1000 > meaningful_ms) {
    to_return += "    main_thread_timer_ (" +
        test_utils::FormatTime(main_thread_time) + "):\n";
  } else {
    non_meaningful_timers.push_back("main_thread_timer_");
  }

  const int64_t parse_global_inputs_time =
      GetElapsedTime(parse_global_inputs_timer_) / 1000;
  if (parse_global_inputs_time / 1000 > 0 ||
      parse_global_inputs_time % 1000 > meaningful_ms) {
    to_return += "      parse_global_inputs_timer_: " +
        test_utils::FormatTime(parse_global_inputs_time) + "\n";
  } else {
    non_meaningful_timers.push_back("parse_global_inputs_timer_");
  }
  const int64_t load_global_inputs_time =
      GetElapsedTime(load_global_inputs_timer_) / 1000;
  if (load_global_inputs_time / 1000 > 0 ||
      load_global_inputs_time % 1000 > meaningful_ms) {
    to_return += "      load_global_inputs_timer_: " +
        test_utils::FormatTime(load_global_inputs_time) + "\n";
  } else {
    non_meaningful_timers.push_back("load_global_inputs_timer_");
  }
  const int64_t generate_ot_bits_time =
      GetElapsedTime(generate_ot_bits_timer_) / 1000;
  if (generate_ot_bits_time / 1000 > 0 ||
      generate_ot_bits_time % 1000 > meaningful_ms) {
    to_return += "      generate_ot_bits_timer_: " +
        test_utils::FormatTime(generate_ot_bits_time) + "\n";
  } else {
    non_meaningful_timers.push_back("generate_ot_bits_timer_");
  }
  const int64_t load_ot_bits_time = GetElapsedTime(load_ot_bits_timer_) / 1000;
  if (load_ot_bits_time / 1000 > 0 || load_ot_bits_time % 1000 > meaningful_ms) {
    to_return += "      load_ot_bits_timer_: " +
        test_utils::FormatTime(load_ot_bits_time) + "\n";
  } else {
    non_meaningful_timers.push_back("load_ot_bits_timer_");
  }
  const int64_t send_initial_sync_time =
      GetElapsedTime(send_initial_sync_timer_) / 1000;
  if (send_initial_sync_time / 1000 > 0 ||
      send_initial_sync_time % 1000 > meaningful_ms) {
    to_return += "      send_initial_sync_timer_: " +
        test_utils::FormatTime(send_initial_sync_time) + "\n";
  } else {
    non_meaningful_timers.push_back("send_initial_sync_timer_");
  }
  const int64_t receive_initial_sync_time =
      GetElapsedTime(receive_initial_sync_timer_) / 1000;
  if (receive_initial_sync_time / 1000 > 0 ||
      receive_initial_sync_time % 1000 > meaningful_ms) {
    to_return += "      receive_initial_sync_timer_: " +
        test_utils::FormatTime(receive_initial_sync_time) + "\n";
  } else {
    non_meaningful_timers.push_back("receive_initial_sync_timer_");
  }
  const int64_t exchange_global_inputs_time =
      GetElapsedTime(exchange_global_inputs_timer_) / 1000;
  if (exchange_global_inputs_time / 1000 > 0 ||
      exchange_global_inputs_time % 1000 > meaningful_ms) {
    to_return += "      exchange_global_inputs_timer_: " +
        test_utils::FormatTime(exchange_global_inputs_time) + "\n";
  } else {
    non_meaningful_timers.push_back("exchange_global_inputs_timer_");
  }
  const int64_t evaluate_circuit_time =
      GetElapsedTime(evaluate_circuit_timer_) / 1000;
  if (evaluate_circuit_time / 1000 > 0 ||
      evaluate_circuit_time % 1000 > meaningful_ms) {
    to_return += "      evaluate_circuit_timer_: " +
        test_utils::FormatTime(evaluate_circuit_time) + "\n";
  } else {
    non_meaningful_timers.push_back("evaluate_circuit_timer_");
  }
  const int64_t evaluate_level_time =
      GetElapsedTime(evaluate_level_timer_) / 1000;
  if (evaluate_level_time / 1000 > 0 ||
      evaluate_level_time % 1000 > meaningful_ms) {
    to_return += "      evaluate_level_timer_: " +
        test_utils::FormatTime(evaluate_level_time) + "\n";
  } else {
    non_meaningful_timers.push_back("evaluate_level_timer_");
  }
  const int64_t evaluate_gate_time = GetElapsedTime(evaluate_gate_timer_) / 1000;
  if (evaluate_gate_time / 1000 > 0 ||
      evaluate_gate_time % 1000 > meaningful_ms) {
    to_return += "      evaluate_gate_timer_: " +
        test_utils::FormatTime(evaluate_gate_time) + "\n";
  } else {
    non_meaningful_timers.push_back("evaluate_gate_timer_");
  }
  const int64_t send_selection_bits_time =
      GetElapsedTime(send_selection_bits_timer_) / 1000;
  if (send_selection_bits_time / 1000 > 0 ||
      send_selection_bits_time % 1000 > meaningful_ms) {
    to_return += "        send_selection_bits_timer_: " +
        test_utils::FormatTime(send_selection_bits_time) + "\n";
  } else {
    non_meaningful_timers.push_back("send_selection_bits_timer_");
  }
  const int64_t receive_selection_bits_time =
      GetElapsedTime(receive_selection_bits_timer_) / 1000;
  if (receive_selection_bits_time / 1000 > 0 ||
      receive_selection_bits_time % 1000 > meaningful_ms) {
    to_return += "        receive_selection_bits_timer_: " +
        test_utils::FormatTime(receive_selection_bits_time) + "\n";
  } else {
    non_meaningful_timers.push_back("receive_selection_bits_timer_");
  }
  const int64_t send_obf_tt_time = GetElapsedTime(send_obf_tt_timer_) / 1000;
  if (send_obf_tt_time / 1000 > 0 || send_obf_tt_time % 1000 > meaningful_ms) {
    to_return += "        send_obf_tt_timer_: " +
        test_utils::FormatTime(send_obf_tt_time) + "\n";
  } else {
    non_meaningful_timers.push_back("send_obf_tt_timer_");
  }
  const int64_t receive_obf_tt_time =
      GetElapsedTime(receive_obf_tt_timer_) / 1000;
  if (receive_obf_tt_time / 1000 > 0 ||
      receive_obf_tt_time % 1000 > meaningful_ms) {
    to_return += "        receive_obf_tt_timer_: " +
        test_utils::FormatTime(receive_obf_tt_time) + "\n";
  } else {
    non_meaningful_timers.push_back("receive_obf_tt_timer_");
  }
  const int64_t exchange_outputs_time =
      GetElapsedTime(exchange_outputs_timer_) / 1000;
  if (exchange_outputs_time / 1000 > 0 ||
      exchange_outputs_time % 1000 > meaningful_ms) {
    to_return += "        exchange_outputs_timer_: " +
        test_utils::FormatTime(exchange_outputs_time) + "\n";
  } else {
    non_meaningful_timers.push_back("exchange_outputs_timer_");
  }

  // Print list of "non-meaningful" timers.
  if (!non_meaningful_timers.empty()) {
    to_return += "  Timers with negligible time (< 1ms):\n    " +
        Join(non_meaningful_timers, "\n    ") + "\n";
  }

  // Print Sleep Timers.
  to_return += "  Sleep Times:\n";
  to_return +=
      "    send_sleep_time_: " + test_utils::FormatTime(send_sleep_time_) + "\n";
  to_return +=
      "    ot_sleep_time_: " + test_utils::FormatTime(ot_sleep_time_) + "\n";
  to_return += "    receive_selection_bit_sleep_time_: " +
      test_utils::FormatTime(receive_selection_bit_sleep_time_) + "\n";
  to_return += "    receive_obfuscated_truth_table_sleep_time_: " +
      test_utils::FormatTime(receive_obfuscated_truth_table_sleep_time_) + "\n";
  to_return += "    evaluate_circuit_sleep_time_: " +
      test_utils::FormatTime(evaluate_circuit_sleep_time_) + "\n";

  if (to_return.empty()) {
    return "";
  }
  return "GmwByGate Timers:\n" + to_return + "\n" + circuit_.PrintTimerInfo();
}

bool GmwByGate::SetupPartnerInfo(
    const int num_parties, const vector<SocketParams*>& connection_properties) {
  partners_.resize(num_parties);

  // Log status, if appropriate.
  if (!excel_logging_file_.empty()) {
    AppendToFile(excel_logging_file_, "INIT0/" + Itoa(num_parties - 1) + "#");
  }

  for (int i = 0; i < num_parties; ++i) {
    if (i == self_party_index_) continue;
    PartnerInfo& partner_i = partners_[i];
    partner_i.id_.id_ = i;

    if (i < self_party_index_) {
      SocketParams* params_i = connection_properties[i];
      CreateSocket(*params_i, &partner_i.socket_);
      if (timeout_ms_ > 0) {
        partner_i.socket_->SetClientTimeout(timeout_ms_);
      }
    } else {
      SocketParams* params_i = connection_properties[i];
      CreateSocket(*params_i, &partner_i.socket_);
      if (timeout_ms_ > 0) {
        partner_i.socket_->SetServerTimeout(timeout_ms_);
      }
    }
  }

  return true;
}

// Sync with each partner:
//   - Establish connection
//   - Agree on function being run:
//        - circuit name
//        - session_id
//        - each party's index (i.e. what inputs they will be providing)
//   - Agree if OT bits need to be generated
bool GmwByGate::InitialSync(map<int, GateIndexDataType>* ot_partners) {
  const int init_sync_num_bytes =
      kMaxNumCharsInCircuitFileName + sizeof(uint64_t) + (2 * sizeof(int)) + 1;
  const string circuit_file = StripSuffixString(
      GetFileName(circuit_.circuit_filename_), ".circuit_by_gate");
  const string circuit_file_prefix =
      circuit_file.length() > kMaxNumCharsInCircuitFileName ?
      circuit_file.substr(0, kMaxNumCharsInCircuitFileName) :
      circuit_file;
  vector<unsigned char> to_send(
      circuit_file_prefix.begin(), circuit_file_prefix.end());
  // Reserve space
  to_send.reserve(kMaxNumCharsInCircuitFileName + sizeof(uint64_t));
  to_send.resize(kMaxNumCharsInCircuitFileName, 0);
  if (!ValueToByteString<uint64_t>(true, session_id_, &to_send)) {
    return false;
  }
  for (const int party : partner_communication_order_) {
    if (party == self_party_index_) {
      continue;
    }
    vector<unsigned char> to_send_i = to_send;
    to_send_i.reserve(init_sync_num_bytes);
    if (!ValueToByteString<int>(true, self_party_index_, &to_send_i)) {
      return false;
    }
    if (!ValueToByteString<int>(true, party, &to_send_i)) {
      return false;
    }
    to_send_i.push_back(ContainsKey(party, *ot_partners) ? 1 : 0);

    // Send/recieve initial sync info.
    if (party < self_party_index_) {
      // Send shares of own input to other Party.
      if (debug_) {
        StartTimer(&send_initial_sync_timer_);
      }
      if (!SendToPartner(party, to_send_i)) {
        LOG_ERROR(
            "Failed to send Server's initial sync data to Partner " +
            Itoa(party));
        if (debug_) {
          StopTimer(&send_initial_sync_timer_);
        }
        return false;
      }
      if (debug_) {
        StopTimer(&send_initial_sync_timer_);
      }

      // Listen for Partner's shares.
      if (debug_) {
        StartTimer(&receive_initial_sync_timer_);
      }
      if (!ReceiveFromPartner(true, party, init_sync_num_bytes, 0)) {
        LOG_ERROR(
            "Unable to receive initial sync communication from "
            "Partner " +
            Itoa(party));
        if (debug_) {
          StopTimer(&receive_initial_sync_timer_);
        }
        return false;
      }
      if (debug_) {
        StopTimer(&receive_initial_sync_timer_);
      }
    } else {
      // Ditto, for all Partners who will be Client.
      if (debug_) {
        StartTimer(&receive_initial_sync_timer_);
      }
      if (!ReceiveFromPartner(true, party, init_sync_num_bytes, 0)) {
        LOG_ERROR(
            "Unable to receive initial sync communication from "
            "Partner " +
            Itoa(party));
        if (debug_) {
          StopTimer(&receive_initial_sync_timer_);
        }
        return false;
      }
      if (debug_) {
        StopTimer(&receive_initial_sync_timer_);
      }

      // Send shares of own input to other Party.
      if (debug_) {
        StartTimer(&send_initial_sync_timer_);
      }
      if (!SendToPartner(party, to_send_i)) {
        LOG_ERROR(
            "Failed to send Server's initial sync data to Partner " +
            Itoa(party));
        if (debug_) {
          StopTimer(&send_initial_sync_timer_);
        }
        return false;
      }
      if (debug_) {
        StopTimer(&send_initial_sync_timer_);
      }
    }

    // Sanity-check received bytes match.
    vector<unsigned char> rec_i(init_sync_num_bytes);
    for (size_t k = 0; k < init_sync_num_bytes; ++k) {
      if (!partners_[party].received_bytes_.Pop(&(rec_i[k]))) {
        LOG_ERROR(
            "Failed to parse Initial Sync communication with partner " +
            Itoa(party));
        return false;
      }
    }
    // First, extract the first kMaxNumCharsInCircuitFileName bytes, which
    // should match the circuit file.
    const string rec_circuit_filename(
        rec_i.begin(), rec_i.begin() + kMaxNumCharsInCircuitFileName);
    const size_t filename_length = circuit_file_prefix.length();
    const string rec_circuit_prefix =
        filename_length < kMaxNumCharsInCircuitFileName ?
        rec_circuit_filename.substr(0, filename_length) :
        rec_circuit_filename;
    if (rec_circuit_prefix != circuit_file_prefix) {
      LOG_ERROR("Mismatching circuit name for Partner " + Itoa(party));
      return false;
    }
    for (size_t j = filename_length; j < kMaxNumCharsInCircuitFileName; ++j) {
      if (rec_i[j] != 0) {
        LOG_ERROR("Mismatching circuit name for Partner " + Itoa(party));
        return false;
      }
    }
    // Next, check that session_ids match.
    const uint64_t session_id =
        ByteStringToValue<uint64_t>(kMaxNumCharsInCircuitFileName, rec_i);
    if (session_id != session_id_) {
      LOG_ERROR("Mismatching session_id for Partner " + Itoa(party));
      return false;
    }
    // Next, check that party indices match.
    const int other_party = ByteStringToValue<int>(
        kMaxNumCharsInCircuitFileName + sizeof(uint64_t), rec_i);
    const int self_party = ByteStringToValue<int>(
        kMaxNumCharsInCircuitFileName + sizeof(uint64_t) + sizeof(int), rec_i);
    if (other_party != party || self_party != self_party_index_) {
      LOG_ERROR(
          "Mismatching party index (" + Itoa(self_party_index_) + ", " +
          Itoa(party) + ") vs. received (" + Itoa(self_party) + ", " +
          Itoa(other_party) + ")");
      return false;
    }
    // Finally, determine if the partner needs to generate OT bits.
    if (rec_i.back()) {
      // Get number of mutually-dependent non-local gates.
      const GateIndexDataType num_mutual_non_local_bool_gates =
          GetNumNonLocalGates(
              (int) partners_.size(),
              min(party, self_party_index_),
              max(party, self_party_index_),
              circuit_.num_non_local_boolean_gates_per_party_pairs_);
      const GateIndexDataType num_mutual_non_local_arith_gates =
          GetNumNonLocalGates(
              (int) partners_.size(),
              min(party, self_party_index_),
              max(party, self_party_index_),
              circuit_.num_non_local_arithmetic_gates_per_party_pairs_);
      ot_partners->insert(make_pair(
          party,
          num_mutual_non_local_bool_gates + num_mutual_non_local_arith_gates));
    }

    // Log status, if appropriate.
    if (!excel_logging_file_.empty()) {
      const int num_processed = party < self_party_index_ ? party + 1 : party;
      AppendToFile(
          excel_logging_file_,
          "INIT" + Itoa(num_processed) + "/" + Itoa(partners_.size() - 1) + "#");
    }
  }

  return true;
}

bool GmwByGate::InitialSync() {
  // Establish communication order with each partner.
  const int num_parties = (int) partners_.size();
  partner_communication_order_.resize(num_parties - 1);
  int offset = 0;
  for (size_t i = 0; i < partner_communication_order_.size(); ++i) {
    // We have parties talk to someone on their left, then someone on their right,
    // (or vice-versa), and then proceed to the next set of left/right parties.
    // So a 'round' will represent a party talking to both someone on their
    // left and right.
    const size_t round = i / 2 + 1;
    const size_t coset_rep = self_party_index_ % (round * 2);
    const bool talk_to_lower_index_first = coset_rep >= round;
    if (i % 2 == 0) {
      ++offset;
      if (talk_to_lower_index_first) {
        const int mod_index = self_party_index_ - offset;
        partner_communication_order_[i] =
            mod_index < 0 ? (mod_index + num_parties) : mod_index;
      } else {
        const int mod_index = self_party_index_ + offset;
        partner_communication_order_[i] =
            mod_index >= num_parties ? (mod_index - num_parties) : mod_index;
      }
    } else if (talk_to_lower_index_first) {
      const int mod_index = self_party_index_ + offset;
      partner_communication_order_[i] =
          mod_index >= num_parties ? (mod_index - num_parties) : mod_index;
    } else {
      const int mod_index = self_party_index_ - offset;
      partner_communication_order_[i] =
          mod_index < 0 ? (mod_index + num_parties) : mod_index;
    }
  }

  // Determine if (and how many) OT bits already exists for each partner.
  map<int, GateIndexDataType> ot_partners;
  // Iterate over partners with smaller index than current party.
  for (int i = 0; i < self_party_index_; ++i) {
    // Get number of mutually-dependent non-local gates.
    const GateIndexDataType num_mutual_non_local_bool_gates =
        GetNumNonLocalGates(
            (int) partners_.size(),
            i,
            self_party_index_,
            circuit_.num_non_local_boolean_gates_per_party_pairs_);
    const GateIndexDataType num_mutual_non_local_arith_gates =
        GetNumNonLocalGates(
            (int) partners_.size(),
            i,
            self_party_index_,
            circuit_.num_non_local_arithmetic_gates_per_party_pairs_);

    // Set ot_bits_file_.
    const string middle = "_ot_bits_" + Itoa(num_mutual_non_local_arith_gates) +
        "_arith_" + Itoa(num_mutual_non_local_bool_gates) + "_bool_";
    const string filename = ot_bits_dir_ + "client" + middle + Itoa(i) + "_" +
        Itoa(self_party_index_) + ".ot";
    partners_[i].ot_bits_file_ = filename;

    // Check if the file already exists: if so, nothing to do; if not, indicate
    // (by adding partner index to 'ot_partners') that OT bits need to be generated
    // and writen to file.
    if (!FileExists(filename)) {
      ot_partners.insert(make_pair(
          i,
          num_mutual_non_local_bool_gates + num_mutual_non_local_arith_gates));
    }

    // Reserve space in client_ot_bits_ for the OT bits.
    // TODO(paul): This assumes all gates are boolean. To support Arithmetic,
    // I'll need to update things to parse bytes a la Beaver's triples.
    partners_[i].client_ot_bits_.reserve(circuit_.num_gates_);
  }
  // Iterate over partners with larger index than current party.
  for (int i = self_party_index_ + 1; i < (int) partners_.size(); ++i) {
    // Get number of mutually-dependent non-local gates.
    const GateIndexDataType num_mutual_non_local_bool_gates =
        GetNumNonLocalGates(
            (int) partners_.size(),
            self_party_index_,
            i,
            circuit_.num_non_local_boolean_gates_per_party_pairs_);
    const GateIndexDataType num_mutual_non_local_arith_gates =
        GetNumNonLocalGates(
            (int) partners_.size(),
            self_party_index_,
            i,
            circuit_.num_non_local_arithmetic_gates_per_party_pairs_);

    // Set ot_bits_file_.
    const string middle = "_ot_bits_" + Itoa(num_mutual_non_local_arith_gates) +
        "_arith_" + Itoa(num_mutual_non_local_bool_gates) + "_bool_";
    const string filename = ot_bits_dir_ + "server" + middle +
        Itoa(self_party_index_) + "_" + Itoa(i) + ".ot";
    partners_[i].ot_bits_file_ = filename;

    // Check if the file already exists: if so, nothing to do; if not, indicate
    // (by adding partner index to 'ot_partners') that OT bits need to be generated
    // and writen to file.
    if (!FileExists(filename)) {
      ot_partners.insert(make_pair(
          i,
          num_mutual_non_local_bool_gates + num_mutual_non_local_arith_gates));
    }

    // Reserve space in server_ot_bits_ for the OT bits.
    // TODO(paul): This assumes all gates are boolean. To support Arithmetic,
    // I'll need to update things to parse bytes a la Beaver's triples.
    partners_[i].server_ot_bits_.reserve(circuit_.num_gates_);

    // This logic is a bit out of place here, but fits in nicely, since
    // I'm already in a loop for which present Party will act as the Server,
    // plus I already have variables for number of non-local Bool, Arith gates.
    const uint64_t num_server_random_bits_needed =
        num_mutual_non_local_bool_gates + num_mutual_non_local_arith_gates;
    const uint64_t num_server_random_bytes_needed =
        (num_server_random_bits_needed / CHAR_BIT) +
        ((num_server_random_bits_needed % CHAR_BIT == 0) ? 0 : 1);
    partners_[i].server_randomness_.resize(num_server_random_bytes_needed, 0);
    if (!kDebugMode) {
      RandomBytes(
          num_server_random_bytes_needed,
          partners_[i].server_randomness_.data());
    }
  }

  // Sync with each partner:
  //   - Establish connection
  //   - Agree on function being run:
  //        - circuit name
  //        - each party's index (i.e. what inputs they will be providing)
  //        - session_id
  //   - Agree if OT bits need to be generated
  if (!InitialSync(&ot_partners)) {
    return false;
  }

  //   - Generate OT Bits with each partner necessary.
  if (!GenerateOtBits(ot_partners)) {
    return false;
  }

  return true;
}

bool GmwByGate::ExchangeOutputShares() {
  if (debug_) {
    StartTimer(&exchange_outputs_timer_);
  }
  const int num_parties = (int) partners_.size();
  const size_t num_outputs = circuit_.global_outputs_.size();
  // First, loop over all outputs and all Partners, and prepare to send own
  // output shares to each Partner who should get the output in the clear.
  // Also, count how many bytes this party should expect from every Partner
  // (based on which outputs this party should get in the clear).
  int num_bytes_to_receive = 0;
  vector<vector<unsigned char>> xored_outputs(num_outputs);
  vector<uint64_t> bytes_to_each_party(num_parties, 0);
  for (size_t i = 0; i < num_outputs; ++i) {
    vector<unsigned char>& output_i_as_bytes = xored_outputs[i];
    output_i_as_bytes = GetTwosComplementByteString(circuit_.global_outputs_[i]);
    if (circuit_.output_designations_[i].first.all_ ||
        ContainsKey(
            self_party_index_, circuit_.output_designations_[i].first.to_)) {
      num_bytes_to_receive += (int) output_i_as_bytes.size();
    }
    for (int party = 0; party < num_parties; ++party) {
      if (party == self_party_index_) continue;
      // Determine if this Partner is entitled the output.
      if (circuit_.output_designations_[i].first.none_ ||
          (!circuit_.output_designations_[i].first.all_ &&
           !ContainsKey(party, circuit_.output_designations_[i].first.to_))) {
        continue;
      }
      bytes_to_each_party[party] += output_i_as_bytes.size();
    }
  }

  // Setup Send buffers with the bytes to send to each partner.
  for (int party = 0; party < num_parties; ++party) {
    if (party == self_party_index_) {
      continue;
    }
    if (partners_[party].bytes_to_send_.capacity() < 0 ||
        (size_t) partners_[party].bytes_to_send_.capacity() <
            bytes_to_each_party[party] +
                partners_[party].bytes_to_send_.size()) {
      partners_[party].bytes_to_send_.reserve(
          bytes_to_each_party[party] + partners_[party].bytes_to_send_.size());
    }
    for (size_t i = 0; i < num_outputs; ++i) {
      // Determine if this Partner is entitled the output.
      if (circuit_.output_designations_[i].first.none_ ||
          (!circuit_.output_designations_[i].first.all_ &&
           !ContainsKey(party, circuit_.output_designations_[i].first.to_))) {
        continue;
      }
      const vector<unsigned char>& output_i_as_bytes = xored_outputs[i];
      for (const unsigned char output_byte : output_i_as_bytes) {
        if (!partners_[party].bytes_to_send_.Push(output_byte)) {
          LOG_ERROR("Send buffer full.");
          if (debug_) {
            StopTimer(&exchange_outputs_timer_);
          }
          return false;
        }
      }
    }
  }

  // Send/Receive output shares to each Partner. Split behavior based on
  // whether this party acts as Client or Server.
  for (const int i : partner_communication_order_) {
    if (i < self_party_index_) {
      // Send shares of own output to other Party.
      const uint64_t num_bytes_to_send = partners_[i].bytes_to_send_.size();
      if (num_bytes_to_send > 0) {
        if (!SendToPartner(false, i, num_bytes_to_send)) {
          LOG_ERROR("Failed to send Server's output shares to Client.");
          if (debug_) {
            StopTimer(&exchange_outputs_timer_);
          }
          return false;
        }
      }

      // Listen for Partner's output shares, if relevant.
      if (num_bytes_to_receive > 0) {
        if (!ReceiveFromPartner(true, i, num_bytes_to_receive, 0)) {
          LOG_ERROR(
              "Unable to receive gate communication from Partner " + Itoa(i));
          if (debug_) {
            StopTimer(&exchange_outputs_timer_);
          }
          return false;
        }
      }
    } else {
      // Listen for Partner's output shares, if relevant.
      if (num_bytes_to_receive > 0) {
        if (!ReceiveFromPartner(true, i, num_bytes_to_receive, 0)) {
          LOG_ERROR("Failed to get shares of Client's output");
          if (debug_) {
            StopTimer(&exchange_outputs_timer_);
          }
          return false;
        }
      }

      // Send shares of own output to other Party.
      const uint64_t num_bytes_to_send = partners_[i].bytes_to_send_.size();
      if (num_bytes_to_send > 0) {
        if (!SendToPartner(false, i, num_bytes_to_send)) {
          LOG_ERROR("Failed to send Server's output shares to Client.");
          if (debug_) {
            StopTimer(&exchange_outputs_timer_);
          }
          return false;
        }
      }
    }
  }

  // Now translate received bytes into actual values.
  party_outputs_.clear();
  party_outputs_.resize(num_outputs);
  for (size_t output = 0; output < num_outputs; ++output) {
    vector<unsigned char>& xored_output = xored_outputs[output];
    const DataType type = circuit_.output_designations_[output].second;
    // If this party is supposed to get this output in the clear, go through
    // all Partners' shared outputs and XOR them.
    if (circuit_.output_designations_[output].first.all_ ||
        ContainsKey(
            self_party_index_,
            circuit_.output_designations_[output].first.to_)) {
      const size_t num_bytes_in_this_output = GetValueNumBytes(type);
      for (int i = 0; i < num_parties; ++i) {
        if (i == self_party_index_) {
          continue;
        }
        ReadWriteQueue<unsigned char>& received_bytes_i =
            partners_[i].received_bytes_;
        vector<unsigned char> output_as_binary_string(num_bytes_in_this_output);
        for (size_t k = 0; k < num_bytes_in_this_output; ++k) {
          if (!received_bytes_i.Pop(&(output_as_binary_string[k]))) {
            if (debug_) {
              StopTimer(&exchange_outputs_timer_);
            }
            return false;
          }
          // TODO(paul): This assumes Parties share the outputs in Z_2. If this
          // is not the case (e.g. outputs are shared in Z_N), then will have
          // to update the formula below for combining shares.
          xored_output[k] =
              (unsigned char) (xored_output[k] ^ output_as_binary_string[k]);
        }
      }
    }
    // If value is INT2 or INT4, the values that got XORed into xored_output
    // were constructed to be valid 2's complement representations (so that
    // the higher-bits were consistent with the sign of the value that the
    // actual (2 or 4) lower-order bits represent. However, after all the
    // XORing, xored_output may no longer be a valid representation.
    // Update the higher order bits accordingly.
    if (type == DataType::INT2) {
      if (xored_output[0] & 2) {
        xored_output[0] |= 252;  // 252 = 11111100.
      } else {
        xored_output[0] &= 3;  // 3 = 00000011.
      }
    } else if (type == DataType::INT4) {
      if (xored_output[0] & 8) {
        xored_output[0] |= 240;  // 240 = 11110000.
      } else {
        xored_output[0] &= 15;  // 15 = 00001111.
      }
    }

    if (!ParseGenericValueFromTwosComplementString(
            type, xored_output, &(party_outputs_[output]))) {
      LOG_ERROR("Failed to parse output " + Itoa(output));
      if (debug_) {
        StopTimer(&exchange_outputs_timer_);
      }
      return false;
    }
  }

  if (debug_) {
    StopTimer(&exchange_outputs_timer_);
  }
  return true;
}

bool GmwByGate::DoAll(
    const int num_parties,
    const vector<SocketParams*>& connection_properties,
    const string& inputs_as_string,
    const vector<GenericValue>& inputs,
    const string&) {
  if (debug_) {
    StartTimer(&do_all_timer_);
  }
  if (self_party_index_ < 0) {
    LOG_ERROR("(Self) Party index not set. This must be done before "
              "engaging in GMW. Can set it either in constructor to "
              "GmwByGate(), or via SetSelfPartyIndex()");
    if (debug_) {
      StopTimer(&do_all_timer_);
    }
    return false;
  }

  // The number of parties is ordinarily the size of 'connection_properties',
  // since the latter is created by having each party's port stored in the
  // associated index position of 'connection_properties'. The only possible
  // exception is if the self-party index is the max, since 'connection_properties'
  // may not have an entry for himself, and so it will be one too small.
  const int actual_num_parties = num_parties < 0 ?
      max(1 + self_party_index_, (int) connection_properties.size()) :
      num_parties;

  // Set partner connection info.
  if (!SetupPartnerInfo(actual_num_parties, connection_properties)) {
    if (debug_) {
      StopTimer(&do_all_timer_);
    }
    LOG_ERROR("Failed to set up partner info.");
    return false;
  }

  bool read_ot_bits_is_done = false;
  bool read_circuit_file_is_done = false;
  bool evaluate_gates_is_done = false;

  // Regardless of number of threads, some tasks must be done first, by one
  // thread. Do those (Read circuit file metadata, Generate OT bits) now.
  //   - Read Circuit File metadata.
  if (!ReadCircuitFile(false, &read_circuit_file_is_done)) {
    if (debug_) {
      StopTimer(&do_all_timer_);
    }
    LOG_ERROR("Failed to read circuit file.");
    return false;
  }
  is_circuit_file_metadata_done_ = true;

  //   - Initial Sync with all Partners, to agree on circuit/function being run,
  //     each party's role (which inputs they provide), generate OT bits, etc.
  if (!InitialSync()) {
    if (debug_) {
      StopTimer(&do_all_timer_);
    }
    LOG_ERROR("Failed initial sync.");
    return false;
  }

  // For remaining tasks, parallelize based on number of (system) threads available.
  if (debug_) {
    StartTimer(&main_thread_timer_);
  }
  if (num_threads_ == 1) {
    // Read this Party's inputs into input_.
    if (!ParseGlobalInputs(inputs_already_shared_, inputs_as_string, inputs)) {
      if (debug_) {
        StopTimer(&do_all_timer_);
        StopTimer(&main_thread_timer_);
      }
      LOG_ERROR("Failed to parse global inputs.");
      return false;
    }
    // Exchange input (shares), and load [left | right]_inputs_ with these.
    if (inputs_already_shared_) {
      if (!LoadGlobalInputShares()) {
        if (debug_) {
          StopTimer(&do_all_timer_);
          StopTimer(&main_thread_timer_);
        }
        LOG_ERROR("Failed to load global input shares.");
        return false;
      }
    } else {
      if (!ExchangeGlobalInputs()) {
        if (debug_) {
          StopTimer(&do_all_timer_);
          StopTimer(&main_thread_timer_);
        }
        LOG_ERROR("Failed to exchange global inputs.");
        return false;
      }
    }
    // Cycle through reading gate info (from circuit file), reading ot bits,
    // and evaluating gates.
    while (!read_circuit_file_is_done || !read_ot_bits_is_done ||
           !evaluate_gates_is_done) {
      if (!ReadCircuitFile(false, &read_circuit_file_is_done) ||
          !ReadOtBitsFile(&read_ot_bits_is_done) ||
          !EvaluateCircuit(true, true, &evaluate_gates_is_done)) {
        if (debug_) {
          StopTimer(&do_all_timer_);
          StopTimer(&main_thread_timer_);
        }
        LOG_ERROR("Failed to do stuff.");
        return false;
      }
    }
  } else if (num_threads_ == 2) {
    InitializeThreadStatus();

    // Start 'Thread B', which is responsible for:
    //   - Reading global inputs
    //   - Exchanging global inputs with each partner
    //   - Reading OT bits
    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    unique_ptr<ThreadParams> thread_b(CreateThreadParams());
    // Start the thread for reading the inputs file.
    ThreadTwoOfTwoCallbackParams params(
        inputs_already_shared_, inputs_as_string, this, &inputs);
    t->StartThread((void*) &ThreadTwoOfTwoCallback, &params, thread_b.get());

    // Now, the main thread ('Thread A') cycles through its tasks:
    //   - Read Circuit File (gate info)
    //   - Evaluate Gates (includes sending/receiving gate communications).
    while (!read_circuit_file_is_done || !evaluate_gates_is_done) {
      if (!ReadCircuitFile(false, &read_circuit_file_is_done) ||
          !EvaluateCircuit(true, true, &evaluate_gates_is_done)) {
        if (debug_) {
          StopTimer(&do_all_timer_);
          StopTimer(&main_thread_timer_);
        }
        LOG_ERROR("Failed to read or evaluate circuit.");
        return false;
      }
    }

    // The fact that we reached here means evaluate_gates_is_done is true, which
    // means circuit evaluation is complete, which also implies Thread B has
    // completed all of its tasks. So calling WaitForThread() is extraneous,
    // but we do it anyway for keeping true to the standard thread template:
    //   CreateThread, StartThread, WaitForThread.
    t->WaitForThread(thread_b.get());
    if (!thread_b->exit_code_set_ || thread_b->exit_code_ != 0) {
      LOG_ERROR(
          "Thread B aborted with exit code: " + Itoa(thread_b->exit_code_));
      if (debug_) {
        StopTimer(&do_all_timer_);
        StopTimer(&main_thread_timer_);
      }
      return false;
    }
  } else if (num_threads_ >= 3) {
    InitializeThreadStatus();

    // Start 'Thread B', which is responsible for:
    //   - Reading global inputs
    //   - Exchanging global inputs with each partner
    //   - Reading OT bits
    unique_ptr<Thread> t;
    CreateThreadMaster(&t);
    unique_ptr<ThreadParams> thread_b(CreateThreadParams());
    // Start the thread for reading the inputs file.
    ThreadTwoOfTwoCallbackParams params(
        inputs_already_shared_, inputs_as_string, this, &inputs);
    t->StartThread((void*) &ThreadTwoOfTwoCallback, &params, thread_b.get());

    // Start 'Thread C', which is responsible for:
    //   - Evaluate Gates (includes sending/receiving gate communications).
    unique_ptr<ThreadParams> thread_c(CreateThreadParams());
    // Start the thread for reading the circuit file.
    ThreadThreeOfThreeCallbackParams c_params(this);
    t->StartThread(
        (void*) &ThreadThreeOfThreeCallback, &c_params, thread_c.get());

    // Now, the main thread ('Thread A') cycles through its tasks:
    //   - Read Circuit File (gate info)
    while (!read_circuit_file_is_done) {
      if (!ReadCircuitFile(false, &read_circuit_file_is_done)) {
        if (debug_) {
          StopTimer(&do_all_timer_);
          StopTimer(&main_thread_timer_);
        }
        LOG_ERROR("Failed to read circuit file.");
        return false;
      }
    }

    t->WaitForThread(thread_b.get());
    if (!thread_b->exit_code_set_ || thread_b->exit_code_ != 0) {
      LOG_ERROR(
          "Thread B aborted with exit code: " + Itoa(thread_b->exit_code_));
      if (debug_) {
        StopTimer(&do_all_timer_);
        StopTimer(&main_thread_timer_);
      }
      return false;
    }
    t->WaitForThread(thread_c.get());
    if (!thread_c->exit_code_set_ || thread_c->exit_code_ != 0) {
      LOG_ERROR(
          "Thread B aborted with exit code: " + Itoa(thread_c->exit_code_));
      if (debug_) {
        StopTimer(&do_all_timer_);
        StopTimer(&main_thread_timer_);
      }
      return false;
    }
  } else {
    LOG_ERROR("Unexpected number of threads: " + Itoa(num_threads_));
    return false;
  }

  if (debug_) {
    StopTimer(&main_thread_timer_);
  }

  // Exchange Output shares.
  if (!ExchangeOutputShares()) {
    if (debug_) {
      StopTimer(&do_all_timer_);
    }
    LOG_ERROR("Failed to exchange output shares.");
    return false;
  }

  if (debug_) {
    StopTimer(&do_all_timer_);
  }

  return true;
}

}  // namespace multiparty_computation
}  // namespace crypto
