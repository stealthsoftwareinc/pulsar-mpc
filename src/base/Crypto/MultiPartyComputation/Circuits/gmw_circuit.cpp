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
// TODO(paul): There is a lot of duplicate code below, e.g. where the
// Server/Client code is virtually identical. Consider factoring out
// the common parts to reduce redundancy.
// TODO(paul): We waste a lot of bytes (8*depth) by communicating the number
// of bytes that Server/Client should expect from the other at each round.
// But this info isn’t necessary, since they know exactly how many bytes to
// expect (based on circuit, and number of non-local gates per level).
// So change the way this communication is done, to *not* communicate the number of bytes

#include "gmw_circuit.h"

#include "Crypto/MultiPartyComputation/Circuits/circuit_utils.h"  // For OutputRecipient.
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit.h"
#include "Crypto/ObliviousTransfer/oblivious_transfer_utils.h"
#include "Crypto/RandomNumberGeneration/deterministic_random_utils.h"
#include "Crypto/RandomNumberGeneration/random_utils.h"
#include "FileReaderUtils/read_file_utils.h"
#include "GenericUtils/char_casting_utils.h"
#include "MapUtils/map_utils.h"
#include "MathUtils/constants.h"  // For slice
#include "MathUtils/data_structures.h"  // For GenericValue
#include "Networking/socket.h"
#include "Networking/socket_utils.h"
#include "global_utils.h"

#include <fstream>
#include <map>
#include <memory>  // For unique_ptr.
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

// Anonymous namespace for helper functions.
namespace {

// Directory and filenames for the Paillier Cryptosystem public/private
// parameters that are used by the underlying Paillier OT protocols.
static const char kPaillierDir[] = "Crypto/MultiPartyComputation/Demos/";
static const char kPaillierFilesDir[] = "InputFiles/";
static const char kKeyNFile[] = "paillier_n_key.txt";
static const char kKeyGFile[] = "paillier_g_key.txt";
static const char kKeyLambdaFile[] = "paillier_lambda_key.txt";
static const char kKeyMuFile[] = "paillier_mu_key.txt";

// Checks if 'return_codes' is one of a handful of common failure reasons, and
// if so, returns a targeted error message for these. Otherwise, returns the
// number of return codes, and their string representations.
string GetBadListenReturnCodeMessage(const set<ListenReturnCode>& return_codes) {
  const size_t num_return_codes = return_codes.size();

  if (num_return_codes == 0) {
    return "No Listen Return Code.";
  }

  if (num_return_codes == 1 &&
      *return_codes.begin() == ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
    return "Received unexpected number of bytes.\nThis likely means "
           "Client and "
           "Server are not in-sync\nin terms of what step of the MPC "
           "protocol "
           "they are currently at.\nBe sure both parties both "
           "have/don't have "
           "the requisite OT files.";
  }

  string return_code_str =
      "Listen Return Codes (" + Itoa(num_return_codes) + "):";
  for (const ListenReturnCode& code_i : return_codes) {
    return_code_str += " " + GetListenReturnCodeString(code_i);
  }

  return return_code_str;
}

// Packs a vector of ObfuscatedTruthTable (which itself contains 4
// slice values) into one vector (of type unsigned char); in the expected way.
// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == slice. However, we are forced to use a
// function template becuase code will not compile otherwise, since id doesn't
// know that instantiations where value_t == bool will never be realized.
template<typename value_t>
bool PackFormatOneObfuscatedTruthTable(
    const vector<ObfuscatedTruthTable<value_t>>& obf_truth_tables,
    vector<unsigned char>* packed_obfuscated_truth_tables) {
  packed_obfuscated_truth_tables->clear();
  packed_obfuscated_truth_tables->resize(
      obf_truth_tables.size() * 4 * sizeof(slice));
  slice* insert_slice = (slice*) packed_obfuscated_truth_tables->data();
  for (uint64_t i = 0; i < obf_truth_tables.size(); ++i) {
    const ObfuscatedTruthTable<value_t>& tt_i = obf_truth_tables[i];
    *insert_slice = (slice) tt_i.first.first;
    ++insert_slice;
    *insert_slice = (slice) tt_i.first.second;
    ++insert_slice;
    *insert_slice = (slice) tt_i.second.first;
    ++insert_slice;
    *insert_slice = (slice) tt_i.second.second;
    ++insert_slice;
  }

  return true;
}

// Packs a vector of ObfuscatedTruthTable (which itself contains 4
// bits) into one vector (of type unsigned char): Since a single
// ObfuscatedTruthTable fits into 4 bits, we can (and do) pack two of them
// into each byte; i.e. the first element of packed_obfuscated_truth_tables
// will hold the first two ObfuscatedTruthTables in obf_truth_tables.
// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == bool. However, we are forced to use a
// function template becuase code will not compile otherwise, since id doesn't
// know that instantiations where value_t == slice will never be realized.
template<typename value_t>
bool PackFormatTwoObfuscatedTruthTable(
    const vector<ObfuscatedTruthTable<value_t>>& obf_truth_tables,
    vector<unsigned char>* packed_obfuscated_truth_tables) {
  const uint64_t num_truth_tables = obf_truth_tables.size();
  const int num_tt_per_byte = CHAR_BIT / 4;
  const uint64_t num_bytes = num_truth_tables / num_tt_per_byte +
      (num_truth_tables % num_tt_per_byte == 0 ? 0 : 1);

  packed_obfuscated_truth_tables->clear();
  packed_obfuscated_truth_tables->resize(num_bytes, (unsigned char) 0);
  for (uint64_t i = 0; i < num_truth_tables; ++i) {
    const ObfuscatedTruthTable<value_t>& tt_i = obf_truth_tables[i];
    unsigned char& output_byte =
        (*packed_obfuscated_truth_tables)[i / num_tt_per_byte];
    if (tt_i.first.first) {
      output_byte = output_byte |
          (unsigned char) (1 << (CHAR_BIT - 1 - 4 * (i % num_tt_per_byte)));
    }
    if (tt_i.first.second) {
      output_byte = output_byte |
          (unsigned char) (1 << (CHAR_BIT - 2 - 4 * (i % num_tt_per_byte)));
    }
    if (tt_i.second.first) {
      output_byte = output_byte |
          (unsigned char) (1 << (CHAR_BIT - 3 - 4 * (i % num_tt_per_byte)));
    }
    if (tt_i.second.second) {
      output_byte = output_byte |
          (unsigned char) (1 << (CHAR_BIT - 4 - 4 * (i % num_tt_per_byte)));
    }
  }

  return true;
}

// Unpacks a vector of ObfuscatedTruthTable (which itself contains 4
// bits) from a vector (of type unsigned char): Since a single
// ObfuscatedTruthTable fits into 4 bits, we can (and do) pack two of them
// into each byte; i.e. the first byte of received_data will hold
// two obfuscated_truth_tables.
bool UnpackFormatTwoObfuscatedTruthTable(
    const vector<char>& received_data,
    const bool is_cookie_socket,
    vector<ObfuscatedTruthTable<bool>>* obfuscated_truth_tables) {
  // The first bytes of received data represent the number of bytes
  // in (the rest of) it (this was used to know when to stop listening
  // during network communication).
  const int offset = is_cookie_socket ? 0 : sizeof(uint64_t);

  const uint64_t num_received_bytes = received_data.size() - offset;
  const int num_tt_per_byte = CHAR_BIT / 4;
  const uint64_t num_truth_tables = num_received_bytes * num_tt_per_byte;

  obfuscated_truth_tables->clear();
  obfuscated_truth_tables->resize(
      num_truth_tables, ObfuscatedTruthTable<bool>());
  for (uint64_t i = 0; i < num_received_bytes; ++i) {
    const unsigned char byte_i = (unsigned char) received_data[offset + i];
    for (int j = 0; j < num_tt_per_byte; ++j) {
      ObfuscatedTruthTable<bool>& tt_ij =
          (*obfuscated_truth_tables)[i * num_tt_per_byte + j];
      tt_ij.first.first = (byte_i >> (CHAR_BIT - 4 * j - 1)) & 1;
      tt_ij.first.second = (byte_i >> (CHAR_BIT - 4 * j - 2)) & 1;
      tt_ij.second.first = (byte_i >> (CHAR_BIT - 4 * j - 3)) & 1;
      tt_ij.second.second = (byte_i >> (CHAR_BIT - 4 * j - 4)) & 1;
    }
  }

  return true;
}

// Unpacks the Client's selection bits for a given level.
// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == bool. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == slice will never be realized.
template<typename value_t>
bool UnpackFormatTwoSelectionBits(
    const uint64_t& offset,
    const vector<char>& received_selection_bits,
    vector<pair<unsigned char, unsigned char>>* client_selection_bits) {
  // The first sizeof(uint64_t) bytes of received_selection_bits were used
  // to communicate the size of the rest of the buffer.
  const uint64_t num_bytes = received_selection_bits.size() - offset;
  const int num_pairs_per_byte = CHAR_BIT / 2;

  client_selection_bits->clear();
  // Each byte contributes 4 (= CHAR_BIT / 2) pairs of selection bits.
  const uint64_t num_pairs = num_bytes * num_pairs_per_byte;
  client_selection_bits->resize(num_pairs);

  for (uint64_t i = 0; i < num_bytes; ++i) {
    const unsigned char byte_i =
        (unsigned char) received_selection_bits[offset + i];
    for (int j = 0; j < num_pairs_per_byte; ++j) {
      pair<unsigned char, unsigned char>& pair_ij =
          (*client_selection_bits)[i * num_pairs_per_byte + j];
      pair_ij.first = (unsigned char) ((byte_i >> (CHAR_BIT - 1 - j * 2)) & 1);
      pair_ij.second = (unsigned char) ((byte_i >> (CHAR_BIT - 2 - j * 2)) & 1);
    }
  }
  return true;
}

// The callback function used by Socket to determine when a single byte
// from the other party has been received.
bool ReceiveOtherPartyHasOtBits(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data == nullptr || stats == nullptr) {
    LOG_FATAL("Null input to ReceiveOtherPartyHasOtBits().");
  }
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceiveOtherPartyHasOtBits(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // Keep waiting, if nothing received yet.
  if (num_recd_bytes == 0) {
    return true;
  }

  // We've received the 1 expected byte.
  // Alert Socket to stop listening on this connection
  // (set the return code to be OK if exactly 1 byte was read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > 1) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

// The callback function used by Socket to determine if all of the expected
// bytes of the other party's shares have been received.
template<typename value_t>
bool ReceiveInputShares(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data == nullptr || stats == nullptr) {
    LOG_FATAL("Null input to ReceiveInputShares().");
  }
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceiveInputShares(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // The first bytes sent are the number of inputs (uint64_t) to expect.
  // Return (will keep Listening) if these haven't been received yet.
  if (num_recd_bytes < sizeof(uint64_t)) {
    return true;
  }

  const char* rec_buffer = buffer.empty() ? data->char_buffer_ : buffer.data();
  const uint64_t num_inputs = ByteStringToValue<uint64_t>(
      sizeof(uint64_t), (const unsigned char*) rec_buffer);

  // Return (will keep listening) if not all the expected bytes have been received.
  if (num_recd_bytes < sizeof(uint64_t) + num_inputs * sizeof(value_t)) {
    return true;
  }

  // We've received enough bytes. Alert Socket to stop listening on this connection
  // (set the return code to be OK if the exact number of expected bytes were read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > sizeof(uint64_t) + num_inputs * sizeof(value_t)) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

// The callback function used by Socket to determine if all of the expected
// bytes of the other party's shares have been received.
bool ReceiveFormatOneOutputShares(
    const SocketIdentifier& socket_it,
    ReceivedData* data,
    SocketStats* stats,
    void* not_used) {
  return ReceiveInputShares<slice>(socket_it, data, stats, not_used);
}

// The callback function used by Socket to determine if all of the expected
// bytes of the other party's shares have been received.
bool ReceiveFormatTwoOutputShares(
    const SocketIdentifier& socket_it,
    ReceivedData* data,
    SocketStats* stats,
    void* not_used) {
  return ReceiveInputShares<unsigned char>(socket_it, data, stats, not_used);
}

// The callback function used by Socket to determine if all of the expected
// bytes of the Client's selection bits (for a given Circuit level) have been
// received.
bool ReceiveSelectionBits(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data == nullptr || stats == nullptr) {
    LOG_FATAL("Null input to ReceiveSelectionBits().");
  }
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceiveSelectionBits(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // The first bytes sent are the number of inputs (uint64_t) to expect.
  // Return (will keep Listening) if these haven't been received yet.
  if (num_recd_bytes < sizeof(uint64_t)) {
    return true;
  }

  const char* rec_buffer = buffer.empty() ? data->char_buffer_ : buffer.data();
  const uint64_t num_bytes = ByteStringToValue<uint64_t>(
      sizeof(uint64_t), (const unsigned char*) rec_buffer);

  // Return (will keep listening) if not all the expected bytes have been received.
  if (num_recd_bytes < sizeof(uint64_t) + num_bytes) {
    return true;
  }

  // We've received enough bytes. Alert Socket to stop listening on this connection
  // (set the return code to be OK if the exact number of expected bytes were read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > sizeof(uint64_t) + num_bytes) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

// The callback function used by Socket to determine if all of the expected
// bytes of the Server's obfuscated truth tables (for a given circuit level)
// have been received.
bool ReceiveObfuscatedTruthTable(
    const SocketIdentifier&, ReceivedData* data, SocketStats* stats, void*) {
  if (data == nullptr || stats == nullptr) {
    LOG_FATAL("Null input to ReceiveObfuscatedTruthTable().");
  }
  if (data->is_receiving_data_) {
    LOG_FATAL("Synchronization problem in ReceiveObfuscatedTruthTable(). "
              "This should never happen.");
  }

  const vector<char>& buffer = data->buffer_;
  const size_t num_recd_bytes =
      buffer.empty() ? data->num_received_bytes_ : buffer.size();

  // The first bytes sent are the number of inputs (uint64_t) to expect.
  // Return (will keep Listening) if these haven't been received yet.
  if (num_recd_bytes < sizeof(uint64_t)) {
    return true;
  }

  const char* rec_buffer = buffer.empty() ? data->char_buffer_ : buffer.data();
  const uint64_t num_bytes = ByteStringToValue<uint64_t>(
      sizeof(uint64_t), (const unsigned char*) rec_buffer);

  // Return (will keep listening) if not all the expected bytes have been received.
  if (num_recd_bytes < sizeof(uint64_t) + num_bytes) {
    return true;
  }

  // We've received enough bytes. Alert Socket to stop listening on this connection
  // (set the return code to be OK if the exact number of expected bytes were read;
  // otherwise alert that there was an ERROR.).
  if (num_recd_bytes > sizeof(uint64_t) + num_bytes) {
    stats->abort_listening_with_code_.insert(
        ListenReturnCode::RECEIVED_UNEXPECTED_BYTES);
  } else {
    stats->abort_listening_with_code_.insert(ListenReturnCode::OK);
  }

  return true;
}

// Copies the 'value' to each of the input wires in the provided set.
template<typename value_t>
bool SetInputsForWires(
    const value_t& value,
    set<WireLocation> wires,
    StandardCircuit<value_t>* circuit) {
  const bool is_format_one = circuit->format_ == CircuitFormat::UNKNOWN ?
      circuit->IsCircuitFormatOne() :
      circuit->format_ == CircuitFormat::FORMAT_ONE;
  for (const WireLocation& loc : wires) {
    const GateLocation& output_wire_loc = loc.loc_;

    // A negative level for the output wire either indicates that
    // this is a global output wire (in which case the location index
    // should be non-negative) or that the output wire location was
    // not set (an error).
    if (output_wire_loc.level_ < 0) {
      if (output_wire_loc.index_ < 0) {
        DLOG_ERROR("Unable to SetInputsForWires(): "
                   "Output wire's location not set.");
        return false;
      }
      // This is a global output wire.
      // Resize circuit->outputs_as_[bits | slice]_ if necessary.
      if (is_format_one) {
        if ((int64_t) circuit->outputs_as_slice_.size() <=
            output_wire_loc.index_) {
          circuit->outputs_as_slice_.resize(output_wire_loc.index_ + 1);
        }
        circuit->outputs_as_slice_[output_wire_loc.index_] = (slice) value;
      } else {
        if ((int64_t) circuit->outputs_as_bits_.size() <=
            output_wire_loc.index_) {
          circuit->outputs_as_bits_.resize(output_wire_loc.index_ + 1);
        }
        circuit->outputs_as_bits_[output_wire_loc.index_] =
            (unsigned char) value;
      }
    } else {
      // This is an internal wire. Copy the output value to the appropriate
      // input wire.
      if ((int64_t) circuit->levels_.size() <= output_wire_loc.level_ ||
          (int64_t) circuit->levels_[output_wire_loc.level_].gates_.size() <=
              output_wire_loc.index_) {
        DLOG_ERROR(
            "Unable to SetInputsForWires(): "
            "Output wire's location is not valid (" +
            Itoa(output_wire_loc.level_) + ", " + Itoa(output_wire_loc.index_) +
            ").");
        return false;
      }
      StandardGate<value_t>& output_gate =
          circuit->levels_[output_wire_loc.level_]
              .gates_[output_wire_loc.index_];
      if (loc.is_left_) {
        output_gate.left_input_set_ = true;
        output_gate.left_input_ = value;
      } else {
        output_gate.right_input_set_ = true;
        output_gate.right_input_ = value;
      }
    }
  }

  return true;
}

}  // namespace

void ConstructObfuscatedTruthTable(
    const bool first_selection_bit,
    const bool second_selection_bit,
    const bool servers_output_share,
    const TruthTableMask<bool>& server_ot_bits,
    const TruthTableMask<bool>& truth_table,
    ObfuscatedTruthTable<bool>* obfuscated_truth_table) {
  // Mask the truth table with server's pregenerated random bits,
  // in a manner determined by client's provided selection bits.
  // See formulas in Discussion item (4) at top of the .h file.
  const int first_first_sum = (int) servers_output_share +
      (int) truth_table.first.first +
      (int) (!first_selection_bit && server_ot_bits.first.first) +
      (int) (first_selection_bit && server_ot_bits.first.second) +
      (int) (!second_selection_bit && server_ot_bits.second.first) +
      (int) (second_selection_bit && server_ot_bits.second.second);
  obfuscated_truth_table->first.first = first_first_sum % 2 == 1;
  const int first_second_sum = (int) servers_output_share +
      (int) truth_table.first.second +
      (int) (!first_selection_bit && server_ot_bits.first.first) +
      (int) (first_selection_bit && server_ot_bits.first.second) +
      (int) (second_selection_bit && server_ot_bits.second.first) +
      (int) (!second_selection_bit && server_ot_bits.second.second);
  obfuscated_truth_table->first.second = first_second_sum % 2 == 1;
  const int second_first_sum = (int) servers_output_share +
      (int) truth_table.second.first +
      (int) (first_selection_bit && server_ot_bits.first.first) +
      (int) (!first_selection_bit && server_ot_bits.first.second) +
      (int) (!second_selection_bit && server_ot_bits.second.first) +
      (int) (second_selection_bit && server_ot_bits.second.second);
  obfuscated_truth_table->second.first = second_first_sum % 2 == 1;
  const int second_second_sum = (int) servers_output_share +
      (int) truth_table.second.second +
      (int) (first_selection_bit && server_ot_bits.first.first) +
      (int) (!first_selection_bit && server_ot_bits.first.second) +
      (int) (second_selection_bit && server_ot_bits.second.first) +
      (int) (!second_selection_bit && server_ot_bits.second.second);
  obfuscated_truth_table->second.second = second_second_sum % 2 == 1;
}

bool SelectValueFromObfuscatedTruthTable(
    const bool first_secret,
    const bool second_secret,
    const bool left_wire,
    const bool right_wire,
    const ObfuscatedTruthTable<bool>& tt) {
  // See formula in part (4) of Discussion in .h file.
  const int sum = (int) first_secret + (int) second_secret +
      (int) (tt.first.first && !left_wire && !right_wire) +
      (int) (tt.first.second && !left_wire && right_wire) +
      (int) (tt.second.first && left_wire && !right_wire) +
      (int) (tt.second.second && left_wire && right_wire);
  return sum % 2;
}
bool SelectValueFromObfuscatedTruthTable(
    const bool first_secret,
    const bool second_secret,
    const ObfuscatedTruthTable<bool>& tt) {
  // See formula in part (4) of Discussion in .h file.
  const int sum = (int) first_secret + (int) second_secret +
      (int) (tt.first.first) + (int) (tt.first.second) +
      (int) (tt.second.first) + (int) (tt.second.second);
  return sum % 2;
}

template<typename value_t>
bool GmwServer<value_t>::SetupSocket(
    const SocketParams& params, const uint64_t& ms) {
  CreateSocket(params, &socket_);
  if (ms > 0) {
    socket_->SetServerTimeout(ms);
  }
  return true;
}

template<typename value_t>
bool GmwClient<value_t>::SetupSocket(
    const SocketParams& params, const uint64_t& ms) {
  CreateSocket(params, &socket_);
  if (ms > 0) {
    socket_->SetClientTimeout(ms);
  }
  return true;
}

template<typename value_t>
bool GmwServer<value_t>::DetermineWhetherToRunOtProtocol(
    const bool self_has_ot_bits_file, bool* need_to_run_ot_protocol) {
  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  // Listen for Client's input.
  if (is_cookie_socket) {
    ListenParams params = socket_->GetListenParams();
    uint64_t num_bytes = 1;
    params.receive_buffer_max_size_ = (int) num_bytes;
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
  } else {
    socket_->SetListenReceiveDataCallback(&ReceiveOtherPartyHasOtBits);
  }
  const set<ListenReturnCode> return_codes = socket_->Listen();
  if (return_codes.size() != 1 ||
      *(return_codes.begin()) != ListenReturnCode::OK) {
    LOG_ERROR(
        "Failed to determine if ot protocol should be run. "
        "Socket Error Message:\n" +
        socket_->GetErrorMessage() + "\n" +
        GetBadListenReturnCodeMessage(return_codes));
    return false;
  }

  // Parse Client's response.
  const map<SocketIdentifier, ReceivedData>& received_schema_map =
      socket_->GetReceivedBytes();

  if (received_schema_map.size() != 1) {
    LOG_FATAL("Too many connections.");
  }
  const vector<char>& received_data =
      received_schema_map.begin()->second.buffer_;
  const size_t num_recd_bytes = received_data.empty() ?
      received_schema_map.begin()->second.num_received_bytes_ :
      received_data.size();
  if (num_recd_bytes != 1) {
    LOG_ERROR("Failed to determine if ot protocol should be run: "
              "Unexpected response from other party.");
    return false;
  }
  const char* rec_buffer = received_data.empty() ?
      received_schema_map.begin()->second.char_buffer_ :
      received_data.data();
  const bool other_has_ot_bits_file = rec_buffer[0] == (char) 1;
  socket_->ResetForReceive();

  // Now send self_has_ot_bits_file to other party.
  // Should only be one socket, use it.
  const unsigned char to_send = self_has_ot_bits_file ? (char) 1 : (char) 0;
  if (SendReturnCode::SUCCESS != socket_->SendData(&to_send, 1)) {
    LOG_ERROR("Failed to send initial communication to Client.");
    return false;
  }

  *need_to_run_ot_protocol = !self_has_ot_bits_file || !other_has_ot_bits_file;

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::DetermineWhetherToRunOtProtocol(
    const bool self_has_ot_bits_file, bool* need_to_run_ot_protocol) {
  // Send self_has_ot_bits_file to other party.
  const unsigned char to_send = self_has_ot_bits_file ? (char) 1 : (char) 0;
  if (SendReturnCode::SUCCESS != socket_->SendData(&to_send, 1)) {
    LOG_ERROR("Failed to send initial communication to Server.");
    return false;
  }

  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's input.
  if (is_cookie_socket) {
    ListenParams params = socket_->GetListenParams();
    uint64_t num_bytes = 1;
    params.receive_buffer_max_size_ = (int) num_bytes;
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
  } else {
    socket_->SetListenReceiveDataCallback(&ReceiveOtherPartyHasOtBits);
  }
  const set<ListenReturnCode> return_codes = socket_->Listen();
  bool received_extra_bytes = false;
  if (return_codes.size() != 1 ||
      *(return_codes.begin()) != ListenReturnCode::OK) {
    // If Server thinks OT protocol needs to be run, the received communication
    // may include not only the (expected) byte indicating so, but also the
    // first bytes of the OT Protocol.
    // In this case, Client may have received more bytes than expected.
    if (return_codes.size() == 1 &&
        *(return_codes.begin()) == ListenReturnCode::RECEIVED_UNEXPECTED_BYTES) {
      received_extra_bytes = true;
    } else {
      LOG_ERROR(
          "Failed to determine if ot protocol should be run. "
          "Socket Error Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  }

  // Parse Server's response.
  const map<SocketIdentifier, ReceivedData>& received_schema_map =
      socket_->GetReceivedBytes();
  if (received_schema_map.size() != 1) LOG_FATAL("Too many connections.");
  const vector<char>& received_data =
      received_schema_map.begin()->second.buffer_;
  const size_t num_recd_bytes = received_data.empty() ?
      received_schema_map.begin()->second.num_received_bytes_ :
      received_data.size();
  if (received_data.size() < 1) {
    LOG_ERROR("Failed to determine if ot protocol should be run: "
              "Unexpected response from other party.");
    return false;
  }
  const char* rec_buffer = received_data.empty() ?
      received_schema_map.begin()->second.char_buffer_ :
      received_data.data();
  const bool other_has_ot_bits_file = received_data[0] == (char) 1;

  // Save any extra bytes (which represent the *next* part of the communication
  // between Sender and Receiver).
  const uint64_t num_extra_bytes = num_recd_bytes - 1;
  if ((num_extra_bytes == 0) == received_extra_bytes) {
    DLOG_ERROR("Detected extra bytes received, but none found.");
    return false;
  }
  vector<char> extra_bytes;
  if (received_extra_bytes) {
    extra_bytes.resize(num_extra_bytes);
    memcpy(extra_bytes.data(), rec_buffer + 1, num_extra_bytes);
  }
  if (!socket_->ResetForReceive(extra_bytes)) {
    DLOG_ERROR("Unable to save extra bytes for the next communication.");
    return false;
  }

  *need_to_run_ot_protocol = !self_has_ot_bits_file || !other_has_ot_bits_file;

  return true;
}

template<typename value_t>
void GmwServer<value_t>::PrecomputeObliviousTransferBits(
    const bool is_format_one,
    const uint64_t& num_non_local_gates,
    const vector<unsigned char>& seed,
    Timer* server_generate_ot_secrets_timer,
    vector<TruthTableMask<value_t>>* output) {
  if (num_non_local_gates == 0) {
    return;
  }
  if (server_generate_ot_secrets_timer != nullptr) {
    StartTimer(server_generate_ot_secrets_timer);
  }

  output->clear();
  output->resize(num_non_local_gates, TruthTableMask<value_t>());

  // Generate the random bits (slices) for each gate (this is just
  // 4 random bits (slices)).
  vector<unsigned char> randomness;
  if (seed.empty()) {
    if (is_format_one) {
      RandomBytes(num_non_local_gates * 4 * sizeof(slice), &randomness);
    } else {
      RandomBytes(1 + (num_non_local_gates * 4) / CHAR_BIT, &randomness);
    }
  } else {
    ClearRandomSeed();
    if (is_format_one) {
      RandomBytes(seed, num_non_local_gates * 4 * sizeof(slice), &randomness);
    } else {
      RandomBytes(seed, 1 + (num_non_local_gates * 4) / CHAR_BIT, &randomness);
    }
  }
  uint64_t current_randomness_index = 0;
  int current_bit_shift = 0;
  if (is_format_one) {
    for (uint64_t i = 0; i < num_non_local_gates; ++i) {
      TruthTableMask<value_t>& mask_for_gate_i = (*output)[i];
      mask_for_gate_i.first.first =
          (value_t) * ((slice*) &randomness[current_randomness_index]);
      current_randomness_index += sizeof(slice);
      mask_for_gate_i.first.second =
          (value_t) * ((slice*) &randomness[current_randomness_index]);
      current_randomness_index += sizeof(slice);
      mask_for_gate_i.second.first =
          (value_t) * ((slice*) &randomness[current_randomness_index]);
      current_randomness_index += sizeof(slice);
      mask_for_gate_i.second.second =
          (value_t) * ((slice*) &randomness[current_randomness_index]);
      current_randomness_index += sizeof(slice);
    }
  } else {
    for (uint64_t i = 0; i < num_non_local_gates; ++i) {
      TruthTableMask<value_t>& mask_for_gate_i = (*output)[i];
      const unsigned char random_byte = randomness[current_randomness_index];
      mask_for_gate_i.first.first =
          (value_t) ((random_byte >> current_bit_shift) & 1);
      ++current_bit_shift;
      mask_for_gate_i.first.second =
          (value_t) ((random_byte >> current_bit_shift) & 1);
      ++current_bit_shift;
      mask_for_gate_i.second.first =
          (value_t) ((random_byte >> current_bit_shift) & 1);
      ++current_bit_shift;
      mask_for_gate_i.second.second =
          (value_t) ((random_byte >> current_bit_shift) & 1);
      if (current_bit_shift == CHAR_BIT - 1) {
        ++current_randomness_index;
        current_bit_shift = 0;
      } else {
        ++current_bit_shift;
      }
    }
  }

  if (server_generate_ot_secrets_timer != nullptr) {
    StopTimer(server_generate_ot_secrets_timer);
  }
}

template<typename value_t>
bool GmwServer<value_t>::PrecomputeObliviousTransferBits(
    const bool is_format_one,
    const uint64_t& num_non_local_gates,
    const vector<unsigned char>& seed,
    Timer* server_generate_ot_secrets_timer,
    Timer* server_generate_ot_masks_timer,
    Timer* ot_protocol_timer,
    ServerOTParams* ot_params,
    vector<TruthTableMask<value_t>>* output) {
  // Generate random bits (slices): 4 values for each gate.
  if (num_non_local_gates == 0) {
    return true;
  }
  PrecomputeObliviousTransferBits(
      is_format_one,
      num_non_local_gates,
      seed,
      server_generate_ot_secrets_timer,
      output);

  if (server_generate_ot_masks_timer != nullptr) {
    StartTimer(server_generate_ot_masks_timer);
  }

  // Format 1 circuits have packed bits_per_slice bits onto each wire,
  // while Format 2 circuits have wires representing a single bit (the
  // least significant bit of the wire's slice value). In the former
  // case, we need OT's for all of the bits_per_slice bits on each
  // wire; while in the latter case, we just need OT for the one bit.
  const int bits_per_wire = is_format_one ? CHAR_BIT * sizeof(slice) : 1;

  // Create a temporary storage container to hold the Server's OT bits for
  // the actual OT protocol (i.e. will put the generated random bits in
  // ot_params->secrets_); we don't need this container beyond the scope of
  // this function, as the secret pairs generated will be stored in 'output'.
  vector<ServerSecretPair> temp_secrets(
      num_non_local_gates * bits_per_wire * 2, ServerSecretPair());
  ot_params->secrets_ = &temp_secrets;

  // Engage in the 2-party 1-out-of-4 OT protocol with the Client
  // to exchange one secret bit (slice) per gate. More precisely,
  // we do 1-out-of-4 OT via two 1-out-of-2 OT's (so Client actually
  // learns 2 out of 4 values, but ultimately the way these secrets
  // are combined will ensure the Client effectively only knows 1 of 4).
  // First, copy TruthTableMask for each gate to ot_params->secrets_.
  int64_t ot_bit_index = 0;
  for (TruthTableMask<value_t>& mask : *output) {
    // Unpack the first secret_pair, currently represented as a slice pair,
    // into (bits_per_wire) secret pairs.
    for (int i = 0; i < bits_per_wire; ++i) {
      // Grab the i^th bit of each secret in the first secret pair.
      const bool first_secret_pair_secret_zero_bit_i = is_format_one ?
          ((mask.first.first >> (bits_per_wire - 1 - i)) & 1) :
          mask.first.first;
      const bool first_secret_pair_secret_one_bit_i = is_format_one ?
          ((mask.first.second >> (bits_per_wire - 1 - i)) & 1) :
          mask.first.second;
      // Add this bit to the set of OT secrets to be transferred.
      ServerSecretPair& first_secret_pair_bit_i =
          (*ot_params->secrets_)[ot_bit_index + i];
      first_secret_pair_bit_i.s0_.push_back(
          first_secret_pair_secret_zero_bit_i ? 1 : 0);
      first_secret_pair_bit_i.s1_.push_back(
          first_secret_pair_secret_one_bit_i ? 1 : 0);
    }
    ot_bit_index += bits_per_wire;
    // Unpack the second secret_pair, currently represented as a slice pair,
    // into (bits_per_wire) secret pairs.
    for (int i = 0; i < bits_per_wire; ++i) {
      // Grab the i^th bit of each secret in the second secret pair.
      const bool second_secret_pair_secret_zero_bit_i = is_format_one ?
          ((mask.second.first >> (bits_per_wire - 1 - i)) & 1) :
          mask.second.first;
      const bool second_secret_pair_secret_one_bit_i = is_format_one ?
          ((mask.second.second >> (bits_per_wire - 1 - i)) & 1) :
          mask.second.second;
      // Add this bit to the set of OT secrets to be transferred.
      ServerSecretPair& second_secret_pair_bit_i =
          (*ot_params->secrets_)[ot_bit_index + i];
      second_secret_pair_bit_i.s0_.push_back(
          second_secret_pair_secret_zero_bit_i ? 1 : 0);
      second_secret_pair_bit_i.s1_.push_back(
          second_secret_pair_secret_one_bit_i ? 1 : 0);
    }
    ot_bit_index += bits_per_wire;
  }

  // Sanity-Check that the expected number of secret pairs were generated.
  if (ot_params->secrets_->size() != output->size() * 2 * bits_per_wire) {
    LOG_FATAL("Unexpected secrets size.");
  }

  // Engage in the OT protocol.
  if (server_generate_ot_masks_timer != nullptr) {
    StopTimer(server_generate_ot_masks_timer);
  }
  if (ot_protocol_timer != nullptr) {
    StartTimer(ot_protocol_timer);
  }
  if (!ServerOT(ot_params)) {
    LOG_ERROR("Failed to transfer precomputed OT bits.");
    return false;
  }
  if (ot_protocol_timer != nullptr) {
    StopTimer(ot_protocol_timer);
  }

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::PrecomputeObliviousTransferBits() {
  return PrecomputeObliviousTransferBits("");
}

template<typename value_t>
bool GmwServer<value_t>::PrecomputeObliviousTransferBits(
    const string& ot_bits_filename) {
  // First, determine if we need to generate OT bits: If both Client
  // and Server already have OT bits (files), then we can skip the
  // OT protocol that generates the precomputed bits, and just load them.
  const bool ot_bits_exist =
      !ot_bits_filename.empty() && FileExists(ot_bits_filename);
  bool need_to_generate_ot_bits =
      true;  // Default value will be overwritten/ignored.
  if (!DetermineWhetherToRunOtProtocol(
          ot_bits_exist, &need_to_generate_ot_bits)) {
    LOG_ERROR("Failed to communicate with Client.");
    return false;
  }

  if (!need_to_generate_ot_bits) {
    return LoadObliviousTransferBits(ot_bits_filename);
  }

  // Log a warning that OT bits need to be generated, to warn user this
  // will add time to the circuit evaluation.
  // NOTE: Overload 'timer_level_' as a sign of whether to do this logging
  // or not, i.e. if we are in debug mode or not.
  if (circuit_.timer_level_ >= 0) {
    LOG_WARNING("OT bits need to be generated; this may take some time...");
  }

  // Make sure circuit fields for number of (non-local) gates is set.
  if (circuit_.size_ <= 0 || circuit_.num_non_local_gates_ == -1) {
    LOG_FATAL("The size_ and/or num_non_local_gates_ fields not set. "
              "This is no longer a supported use-case.");
  }

  if (compute_gates_locally_ && circuit_.num_non_local_gates_ < 0) {
    LOG_FATAL("num_non_local_gates_ should be set.");
  }
  const int64_t num_gmw_gates =
      compute_gates_locally_ ? circuit_.num_non_local_gates_ : circuit_.size_;

  if (num_gmw_gates == 0) {
    return true;
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  // Setup ot_params_, if not done already.
  if (ot_params_ == nullptr) {
    // Depending on the circuit Format (1 vs 2), we either are treating each
    // wire as representing a boolean value (bit) for Format 2, or a slice-
    // packed value (Format 1). For the former, we need only 1-out-of-4 OT,
    // but for the latter, we need (1-out-of-4) * bits_per_slice.
    const int bits_per_wire = is_format_one ? CHAR_BIT * sizeof(slice) : 1;
    // The factor of '2' is because we need 1-out-of-4 OT for each
    // gate, as opposed to 1-out-of-2; the factor of 'bits_per_wire'
    // is because (for Format 1 circuits) we pack this many secret pairs
    // into each gate, basically we have one secret pair for each of the
    // bits in the slice for this gate (since a gate actually is operating
    // on bit-slices, not bits, and its doing its operation on
    // bits_per_slice values in parallel).
    const uint64_t num_secrets = num_gmw_gates * 2 * bits_per_wire;
    // Grab Paillier Cryptosystem public/secret parameters, if they have
    // already been generated. Since we're acting as the Server, but
    // IKNP flip-flops Server/Client, we need the GmwServer to have
    // the secret keys (for Paillier OT, the Receiver has secret keys); so
    // we use the Paillier Cryptosystem files associated to the Server.
    string file_prefix = "";
    if (!self_party_.name_.empty()) file_prefix = self_party_.name_ + "_";
    else if (self_party_.id_ != -1) file_prefix = Itoa(self_party_.id_) + "_";
    const string paillier_n_file =
        string(kPaillierFilesDir) + file_prefix + kKeyNFile;
    const string paillier_g_file =
        string(kPaillierFilesDir) + file_prefix + kKeyGFile;
    const string paillier_mu_file =
        string(kPaillierFilesDir) + file_prefix + kKeyMuFile;
    const string paillier_lambda_file =
        string(kPaillierFilesDir) + file_prefix + kKeyLambdaFile;
    // Use default OT Params settings: IKNP + PRG + Paillier, to get:
    //   OT^m_s <- OT^128_m <- OT^128_512
    // for security parameter for IKNP 128 bits and size of Paillier
    // cryptosystem 512 bits, s = bits_per_slice = CHAR_BIT * sizeof(slice),
    // and m = 2 * bits_per_slice * |C|, where |C| = num_gmw_gates.
    // Note that the factor of 2 is due to 1-out-of-4 OT done at each gate,
    // and the factor of bits_per_slice is because each gate is actually
    // represents (bits_per_slice) simultaneous (i.e. in parallel) gates.
    OTProtocolCombo ot_to_use = (base_ot_ == OTProtocol::PAILLIER) ?
        OTProtocolCombo::IKNP_FROM_PRG_FROM_PAILLIER :
        OTProtocolCombo::IKNP_FROM_PRG_FROM_DIFFIE_HELLMAN;
    ot_params_.reset(new ServerIKNPOTExtensionParams());
    if (!SetServerOTParams(
            true,
            OTParamsSetup(
                ot_to_use,
                num_secrets,
                1,  // Secrets are one bit of a bit-slice (cannot pack them, as we
                // need to use (bits_per_slice) selection bits.
                paillier_n_file,
                paillier_g_file,
                paillier_lambda_file,
                paillier_mu_file,
                elliptic_curve_based_dh_,
                nullptr,
                128 / CHAR_BIT,  // We use AES-128 for PRG
                128 /
                    CHAR_BIT),  // Use k = 128 bits for RO security parameter 'k'
            ot_params_.get())) {
      DLOG_ERROR("Unable to setup OT Parameters.");
      return false;
    }
  }
  if (ot_params_->connection_to_client_ == nullptr) {
    ot_params_->connection_to_client_.reset(socket_.release());
  }

  // Generate random bit (slices) that will be used to obfuscate the
  // truth table of each gate. Also engages in the 2-Party OT protocol
  // to transfer them to the Client.
  const bool use_timers = circuit_.timer_level_ >= 1;
  vector<TruthTableMask<value_t>> mask_values;
  if (!PrecomputeObliviousTransferBits(
          is_format_one,
          num_gmw_gates,
          ot_bits_prg_seed_,
          (use_timers ? &circuit_.server_generate_ot_secrets_timer_ : nullptr),
          (use_timers ? &circuit_.server_generate_ot_masks_timer_ : nullptr),
          (use_timers ? &circuit_.ot_protocol_timer_ : nullptr),
          ot_params_.get(),
          &mask_values)) {
    return false;
  }
  // Take back ownership of connection.
  if (socket_ == nullptr) {
    socket_.reset(ot_params_->connection_to_client_.release());
  }

  // Write mask_values to file, if appropriate.
  if (use_timers) {
    StartTimer(&circuit_.write_ot_bits_timer_);
  }
  if (!ot_bits_filename.empty() &&
      !WriteObliviousTransferBitsToFile(ot_bits_filename, mask_values)) {
    LOG_ERROR("Unable to write Server's OT bits to file.");
    return false;
  }
  if (use_timers) {
    StopTimer(&circuit_.write_ot_bits_timer_);
  }

  // Store the random bit (slices) generated above in the relevant
  // gate of the circuit_; also generate random shares for each
  // output wire that the Server will hold.
  return LoadPrecomputedBitsIntoCircuit(mask_values);
}

template<typename value_t>
bool GmwClient<value_t>::PrecomputeObliviousTransferBits(
    const bool compute_gates_locally,
    const vector<unsigned char>& seed,
    const StandardCircuit<value_t>& circuit,
    Timer* client_generate_ot_selection_bits_timer,
    Timer* client_store_ot_bits_timer,
    Timer* ot_protocol_timer,
    ClientOTParams* ot_params,
    map<GateLocation, SelectionBitAndValuePair<value_t>>* output) {
  if (compute_gates_locally && circuit.num_non_local_gates_ < 0) {
    LOG_FATAL("num_non_local_gates_ should be set.");
  }
  const int64_t num_gmw_gates =
      compute_gates_locally ? circuit.num_non_local_gates_ : circuit.size_;

  if (num_gmw_gates == 0) {
    return true;
  }

  if (client_generate_ot_selection_bits_timer != nullptr) {
    StartTimer(client_generate_ot_selection_bits_timer);
  }

  const bool is_format_one = circuit.format_ == CircuitFormat::UNKNOWN ?
      circuit.IsCircuitFormatOne() :
      circuit.format_ == CircuitFormat::FORMAT_ONE;

  // Format 1 circuits have packed bits_per_slice bits onto each wire,
  // while Format 2 circuits have wires representing a single bit (the
  // least significant bit of the wire's slice value). In the former
  // case, we need OT's for all of the bits_per_slice bits on each
  // wire; while in the latter case, we just need OT for the one bit.
  const int bits_per_wire = is_format_one ? CHAR_BIT * sizeof(slice) : 1;

  output->clear();
  // Create a storage container for ot_params->selection_bits_and_output_secret_.
  // We only need this for the scope of the present function, since the
  // relevant secrets will be stored in 'output'.
  vector<ClientSelectionBitAndSecret> temp_selection_bits_and_secrets(
      num_gmw_gates * bits_per_wire * 2);
  ot_params->selection_bits_and_output_secret_ =
      &temp_selection_bits_and_secrets;

  // For each (non-locally computed) gate, engage in 1-out-of-4 OT with Server.
  // In particular: Generate (a pair of) random selection bits (slices) for each
  // (non-locally computed) gate.
  // We will generate all the requiste randomness needed once.
  vector<unsigned char> randomness;
  if (seed.empty()) {
    if (is_format_one) {
      RandomBytes(num_gmw_gates * 2 * sizeof(slice), &randomness);
    } else {
      RandomBytes(1 + (num_gmw_gates * 2) / CHAR_BIT, &randomness);
    }
  } else {
    ClearRandomSeed();
    if (is_format_one) {
      RandomBytes(seed, num_gmw_gates * 2 * sizeof(slice), &randomness);
    } else {
      RandomBytes(seed, 1 + (num_gmw_gates * 2) / CHAR_BIT, &randomness);
    }
  }
  int64_t current_ot_index = 0;
  uint64_t current_randomness_index = 0;
  int current_bit_shift = 0;
  for (int64_t level = 0; level < (int64_t) circuit.levels_.size(); ++level) {
    const StandardCircuitLevel<value_t>& current_level = circuit.levels_[level];
    for (int64_t gate = 0; gate < (int64_t) current_level.gates_.size();
         ++gate) {
      const StandardGate<value_t>& current_gate = current_level.gates_[gate];
      // No need to generate OT bits if gate is to be computed locally.
      if (compute_gates_locally && current_gate.IsLocallyComputable()) {
        continue;
      }

      SelectionBitAndValuePair<value_t>& gate_output =
          output
              ->insert(make_pair(
                  GateLocation(level, gate),
                  SelectionBitAndValuePair<value_t>()))
              .first->second;
      OTPair<value_t>& first_pair = gate_output.first;
      OTPair<value_t>& second_pair = gate_output.second;

      // Generate selection bits (slices) for this gate.
      if (is_format_one) {
        first_pair.first =
            (value_t) * ((slice*) &randomness[current_randomness_index]);
        current_randomness_index += sizeof(slice);
        second_pair.first =
            (value_t) * ((slice*) &randomness[current_randomness_index]);
        current_randomness_index += sizeof(slice);
      } else {
        const unsigned char random_byte = randomness[current_randomness_index];
        first_pair.first = (value_t) ((random_byte >> current_bit_shift) & 1);
        ++current_bit_shift;
        second_pair.first = (value_t) ((random_byte >> current_bit_shift) & 1);
        if (current_bit_shift == CHAR_BIT - 1) {
          ++current_randomness_index;
          current_bit_shift = 0;
        } else {
          ++current_bit_shift;
        }
      }

      // Copy selection bits to ot_params, for OT protocol.
      // NOTE: Each selection_bit_slice actually represents bits_per_wire
      // selection bits. Copy each bit separately.
      // First copy the selection bits for the first selection_bit_slice.
      for (int i = 0; i < bits_per_wire; ++i) {
        (*ot_params->selection_bits_and_output_secret_)[current_ot_index + i] =
            ClientSelectionBitAndSecret(
                is_format_one ?
                    ((first_pair.first >> (bits_per_wire - 1 - i)) & 1) :
                    first_pair.first);
      }
      current_ot_index += bits_per_wire;
      // Now copy the selection bits for the second selection_bit_slice.
      for (int i = 0; i < bits_per_wire; ++i) {
        (*ot_params->selection_bits_and_output_secret_)[current_ot_index + i] =
            ClientSelectionBitAndSecret(
                (is_format_one ?
                     ((second_pair.first >> (bits_per_wire - 1 - i)) & 1) :
                     second_pair.first));
      }
      current_ot_index += bits_per_wire;
    }
  }

  // Make sure the expected number of OT ClientSelectionBitAndSecret pairs
  // were generated: For each (non-locally computed) gate, we require
  //   2 * bits_per_wire
  // selection bits.
  if (ot_params->selection_bits_and_output_secret_->size() !=
      output->size() * 2 * bits_per_wire) {
    LOG_FATAL("Bad selection bit size");
  }

  // Engage in 1-out-of-4 OT (which is actually two sets of 1-out-of-2 OT)
  // with Server.
  if (client_generate_ot_selection_bits_timer != nullptr) {
    StopTimer(client_generate_ot_selection_bits_timer);
  }
  if (ot_protocol_timer != nullptr) {
    StartTimer(ot_protocol_timer);
  }
  if (!ClientOT(ot_params)) {
    LOG_ERROR("Failed to transfer precomputed OT bits.");
    return false;
  }
  if (ot_protocol_timer != nullptr) {
    StopTimer(ot_protocol_timer);
  }
  if (client_store_ot_bits_timer != nullptr) {
    StartTimer(client_store_ot_bits_timer);
  }

  // Need to translate the received secrets back into SelectionBitAndValuePair
  // (i.e. need to pack bits_per_wire secrets into a single secret slice),
  // and then store this in the appropriate entry of output.
  int64_t non_local_gate_index = 0;
  for (int64_t level = 0; level < (int64_t) circuit.levels_.size(); ++level) {
    const StandardCircuitLevel<value_t>& current_level = circuit.levels_[level];
    for (int64_t gate = 0; gate < (int64_t) current_level.gates_.size();
         ++gate) {
      const StandardGate<value_t>& current_gate = current_level.gates_[gate];

      // Ensure an entry for this gate exists in output.
      typename map<GateLocation, SelectionBitAndValuePair<value_t>>::iterator
          gate_ot_bits_itr = output->find(GateLocation(level, gate));
      if (gate_ot_bits_itr == output->end()) {
        // It's okay that no OT bits were generated for this gate *if*
        // this gate is to be computed locally; otherwise, it's an error.
        if (!compute_gates_locally || !current_gate.IsLocallyComputable()) {
          DLOG_ERROR(
              "Expected to generate OT bits for gate (" + Itoa(level) + ", " +
              Itoa(gate) + "), but none found.");
          return false;
        }
        continue;
      } else if (compute_gates_locally && current_gate.IsLocallyComputable()) {
        DLOG_ERROR(
            "Unexpected selection bits found for local gate: " + Itoa(gate) +
            " on level " + Itoa(level));
        return false;
      }

      // Copy ot results to output.
      SelectionBitAndValuePair<value_t>& gate_output = gate_ot_bits_itr->second;
      // Copy first secret bit (slice) for this gate.
      value_t& first_secret = gate_output.first.second;
      first_secret = (value_t) 0;
      for (int i = 0; i < bits_per_wire; ++i) {
        const vector<unsigned char>& first_secret_bit_i =
            (*ot_params->selection_bits_and_output_secret_)
                [2 * non_local_gate_index * bits_per_wire + i]
                    .s_b_;
        if (first_secret_bit_i.size() != 1)
          LOG_FATAL("Bad first secret bit size");
        if (first_secret_bit_i[0] != (unsigned char) 0) {
          if (is_format_one)
            first_secret += ((value_t) 1) << (bits_per_wire - 1 - i);
          else first_secret = (value_t) 1;
        }
      }
      // Copy second secret bit (slice) for this gate.
      value_t& second_secret = gate_output.second.second;
      second_secret = (value_t) 0;
      for (int i = 0; i < bits_per_wire; ++i) {
        const vector<unsigned char>& second_secret_bit_i =
            (*ot_params->selection_bits_and_output_secret_)
                [2 * non_local_gate_index * bits_per_wire + bits_per_wire + i]
                    .s_b_;
        if (second_secret_bit_i.size() != 1)
          LOG_FATAL("Bad first secret bit size");
        if (second_secret_bit_i[0] != (unsigned char) 0) {
          if (is_format_one)
            second_secret += ((value_t) 1) << (bits_per_wire - 1 - i);
          else second_secret = (value_t) 1;
        }
      }
      ++non_local_gate_index;
    }
  }

  if (client_store_ot_bits_timer != nullptr) {
    StopTimer(client_store_ot_bits_timer);
  }

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::PrecomputeObliviousTransferBits() {
  return PrecomputeObliviousTransferBits("");
}

template<typename value_t>
bool GmwClient<value_t>::PrecomputeObliviousTransferBits(
    const string& ot_bits_filename) {
  // First, determine if we need to generate OT bits: If both Client
  // and Server already have OT bits (files), then we can skip the
  // OT protocol that generates the precomputed bits, and just load them.
  const bool ot_bits_exist =
      !ot_bits_filename.empty() && FileExists(ot_bits_filename);
  bool need_to_generate_ot_bits = true;
  if (!DetermineWhetherToRunOtProtocol(
          ot_bits_exist, &need_to_generate_ot_bits)) {
    LOG_ERROR("Failed to communicate with Server.");
    return false;
  }

  if (!need_to_generate_ot_bits) {
    return LoadObliviousTransferBits(ot_bits_filename);
  }

  // Log a warning that OT bits need to be generated, to warn user this
  // will add time to the circuit evaluation.
  // NOTE: Overload 'timer_level_' as a sign of whether to do this logging
  // or not, i.e. if we are in debug mode or not.
  if (circuit_.timer_level_ >= 0) {
    LOG_WARNING("OT bits need to be generated; this may take some time...");
  }

  if (compute_gates_locally_ && circuit_.num_non_local_gates_ < 0) {
    LOG_FATAL("num_non_local_gates_ should be set.");
  }
  const int64_t num_gmw_gates =
      compute_gates_locally_ ? circuit_.num_non_local_gates_ : circuit_.size_;

  if (num_gmw_gates == 0) {
    return true;
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  // Setup ot_params_, if not done already.
  if (ot_params_ == nullptr) {
    // Depending on the circuit Format (1 vs 2), we either are treating each
    // wire as representing a boolean value (bit) for Format 2, or a slice-
    // packed value (Format 1). For the former, we need only 1-out-of-4 OT,
    // but for the latter, we need (1-out-of-4) * bits_per_slice.
    const int bits_per_wire = is_format_one ? CHAR_BIT * sizeof(slice) : 1;
    // The factor of '2' is because we need 1-out-of-4 OT for each
    // gate, as opposed to 1-out-of-2; the factor of 'bits_per_wire'
    // is because (for Format 1 circuits) we pack this many secret pairs
    // into each gate, basically we have one secret pair for each of the
    // bits in the slice for this gate (since a gate actually is operating
    // on bit-slices, not bits, and its doing its operation on
    // bits_per_slice values in parallel).
    const uint64_t num_secrets = num_gmw_gates * 2 * bits_per_wire;
    // Grab Paillier Cryptosystem public/secret parameters, if they have
    // already been generated. Since we're acting as the Client, but
    // IKNP flip-flops Server/Client, we need the GmwClient to have
    // the public keys (for Paillier OT, the Sender has public keys),
    // and in particular we use the Paillier Cryptosystem of the GmwServer.
    string file_prefix = "";
    if (!other_party_.name_.empty()) file_prefix = other_party_.name_ + "_";
    else if (other_party_.id_ != -1) file_prefix = Itoa(other_party_.id_) + "_";
    const string paillier_n_file =
        string(kPaillierFilesDir) + file_prefix + kKeyNFile;
    const string paillier_g_file =
        string(kPaillierFilesDir) + file_prefix + kKeyGFile;
    const string paillier_mu_file =
        string(kPaillierFilesDir) + file_prefix + kKeyMuFile;
    const string paillier_lambda_file =
        string(kPaillierFilesDir) + file_prefix + kKeyLambdaFile;
    // Use default OT Params settings: IKNP + PRG + Paillier, to get:
    //   OT^m_s <- OT^128_m <- OT^128_512
    // for security parameter for IKNP 128 bits and size of Paillier
    // cryptosystem 512 bits, s = bits_per_slice = CHAR_BIT * sizeof(slice),
    // and m = 2 * bits_per_slice * |C|, where |C| = num_gmw_gates.
    // Note that the factor of 2 is due to 1-out-of-4 OT done at each gate,
    // and the factor of bits_per_slice is because each gate is actually
    // represents (bits_per_slice) simultaneous (i.e. in parallel) gates.
    const OTProtocolCombo ot_to_use = (base_ot_ == OTProtocol::PAILLIER) ?
        OTProtocolCombo::IKNP_FROM_PRG_FROM_PAILLIER :
        OTProtocolCombo::IKNP_FROM_PRG_FROM_DIFFIE_HELLMAN;
    ot_params_.reset(new ClientIKNPOTExtensionParams());
    if (!SetClientOTParams(
            true,
            OTParamsSetup(
                ot_to_use,
                "",
                num_secrets,
                1,  // Secrets are one bit of a bit-slice (cannot pack them, as we
                // need to use (bits_per_slice) selection bits.
                elliptic_curve_based_dh_,
                nullptr,
                128 / CHAR_BIT,  // We use AES-128 for PRG
                128 /
                    CHAR_BIT),  // Use k = 128 bits for RO security parameter 'k'
            ot_params_.get())) {
      DLOG_ERROR("Unable to setup OT Parameters.");
      return false;
    }
  }
  if (ot_params_->connection_to_server_ == nullptr) {
    ot_params_->connection_to_server_.reset(socket_.release());
  }

  const bool use_timers = circuit_.timer_level_ >= 1;
  if (!PrecomputeObliviousTransferBits(
          compute_gates_locally_,
          ot_bits_prg_seed_,
          circuit_,
          (use_timers ? &circuit_.client_generate_ot_selection_bits_timer_ :
                        nullptr),
          (use_timers ? &circuit_.client_store_ot_bits_timer_ : nullptr),
          (use_timers ? &circuit_.ot_protocol_timer_ : nullptr),
          ot_params_.get(),
          &ot_bits_)) {
    return false;
  }
  // Take back ownership of connection.
  if (socket_ == nullptr) {
    socket_.reset(ot_params_->connection_to_server_.release());
  }

  if (circuit_.timer_level_ >= 1) {
    StartTimer(&circuit_.write_ot_bits_timer_);
  }

  const bool return_value = ot_bits_filename.empty() ||
      WriteObliviousTransferBitsToFile(ot_bits_filename);

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.write_ot_bits_timer_);
  }

  return return_value;
}

template<typename value_t>
bool GmwServer<value_t>::WriteObliviousTransferBitsToFile(
    const string& filename,
    const vector<ObfuscatedTruthTable<value_t>>& mask_values) {
  if (filename.empty()) {
    return true;
  }

  if (!CreateDir(GetDirectory(filename))) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }
  ofstream output_file;
  output_file.open(filename);
  if (!output_file.is_open()) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }

  for (const ObfuscatedTruthTable<value_t>& mask_value : mask_values) {
    output_file << mask_value.first.first << "," << mask_value.first.second
                << "," << mask_value.second.first << ","
                << mask_value.second.second << endl;
  }

  output_file.close();

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::LoadObliviousTransferBits(const string& filename) {
  if (circuit_.timer_level_ >= 1) {
    StartTimer(&circuit_.load_ot_bits_timer_);
  }
  // Read bits from file.
  ifstream input_file(filename.c_str());
  if (!input_file.is_open()) {
    LOG_ERROR("Unable to find input file '" + filename + "'.");
    return false;
  }

  vector<TruthTableMask<value_t>> mask_values;
  // Go through input OT bits file, picking out four values per line.
  string orig_line, line;
  int64_t line_num = 0;
  while (getline(input_file, orig_line)) {
    ++line_num;
    RemoveWindowsTrailingCharacters(&orig_line);
    line = RemoveAllWhitespace(orig_line);
    if (line.empty() || HasPrefixString(line, "#")) continue;

    vector<string> values;
    Split(line, ",", &values);

    if (values.size() != 4) {
      LOG_ERROR("Bad format on line " + Itoa(line_num) + ": '" + line + "'");
      return false;
    }

    mask_values.push_back(TruthTableMask<value_t>());
    TruthTableMask<value_t>& mask = mask_values.back();
    if (!Stoi(values[0], &mask.first.first) ||
        !Stoi(values[1], &mask.first.second) ||
        !Stoi(values[2], &mask.second.first) ||
        !Stoi(values[3], &mask.second.second)) {
      LOG_ERROR(
          "Unable to parse '" + orig_line + "' in file '" + filename +
          "' as a list of 4 numeric values.");
      return false;
    }
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.load_ot_bits_timer_);
  }

  // Load bits onto the relevant wires.
  return LoadPrecomputedBitsIntoCircuit(mask_values);
}

template<typename value_t>
bool GmwClient<value_t>::WriteObliviousTransferBitsToFile(
    const string& filename) {
  if (filename.empty()) {
    return true;
  }

  if (circuit_.timer_level_ >= 1) {
    StartTimer(&circuit_.write_ot_bits_timer_);
  }

  if (!CreateDir(GetDirectory(filename))) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }
  ofstream output_file;
  output_file.open(filename);
  if (!output_file.is_open()) {
    LOG_ERROR("Unable to open output file '" + filename + "'");
    return false;
  }

  for (const pair<const GateLocation, SelectionBitAndValuePair<value_t>>&
           gate_loc_and_ot_bits : ot_bits_) {
    const SelectionBitAndValuePair<value_t>& gate_ot_bits =
        gate_loc_and_ot_bits.second;
    output_file << gate_ot_bits.first.first << "," << gate_ot_bits.first.second
                << "," << gate_ot_bits.second.first << ","
                << gate_ot_bits.second.second << endl;
  }

  output_file.close();

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.write_ot_bits_timer_);
  }

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::LoadObliviousTransferBits(const string& filename) {
  // Make sure circuit fields for number of (non-local) gates is set.
  if (circuit_.size_ <= 0 || circuit_.num_non_local_gates_ == -1) {
    LOG_FATAL("The size_ and/or num_non_local_gates_ fields not set. "
              "This is no longer a supported use-case.");
  }

  const int64_t num_non_local_gates =
      compute_gates_locally_ ? circuit_.num_non_local_gates_ : circuit_.size_;

  // Read bits from file.
  ifstream input_file(filename.c_str());
  if (!input_file.is_open()) {
    LOG_ERROR("Unable to find input file '" + filename + "'.");
    return false;
  }

  ot_bits_.clear();

  // Go through input file, picking out four values per line (representing
  // (b, s_b), (c, t_c); see notation/comments in oblivious_transfer_utils.h).
  string orig_line, line;
  GateLocation current_location(0, 0);
  int64_t line_num = 0;
  bool current_location_is_valid = true;
  while (getline(input_file, orig_line)) {
    if (!current_location_is_valid) {
      /*
      LOG_WARNING("File with OT bits '" + filename +
                  "' has more bits (lines) than are required (" +
                  Itoa(num_non_local_gates) + "). We'll just use the first " +
                  Itoa(num_non_local_gates) + " lines of the file.");
      */
      break;
    }
    ++line_num;
    RemoveWindowsTrailingCharacters(&orig_line);
    line = RemoveAllWhitespace(orig_line);
    if (line.empty() || HasPrefixString(line, "#")) continue;

    // Split line into the 4 values.
    vector<string> line_parts;
    Split(line, ",", &line_parts);
    if (line_parts.size() != 4) {
      LOG_ERROR(
          "Unable to LoadObliviousTransferBits(): Line " + Itoa(line_num) +
          " has wrong number of values.");
      return false;
    }

    // Sanity-check we have enough gates in the circuit to assign this line to.
    StandardGate<value_t>* current_gate = nullptr;
    do {
      if (!circuit_.IsValidGateLocation(current_location)) {
        LOG_FATAL("Unable to LoadObliviousTransferBits().");
      }
      current_gate = &circuit_.levels_[current_location.level_]
                          .gates_[current_location.index_];
    } while (current_gate != nullptr && compute_gates_locally_ &&
             current_gate->IsLocallyComputable() &&
             circuit_.GetNextGateLocation(&current_location));

    // Sanity-check the last call to GetNextGateLocation in the do/while loop
    // above was successful.
    if (current_gate != nullptr && compute_gates_locally_ &&
        current_gate->IsLocallyComputable()) {
      // All of the conditions in the while loop are true, but yet we broke
      // from it, so the last one (GetNextGateLocation()) must have returned
      // false. This means all gates have gotten ot bits.
      /*
      DLOG_WARNING("File with OT bits '" + filename +
                   "' has more bits (lines) than are required (" +
                   Itoa(num_non_local_gates) + "). We'll just use the first " +
                   Itoa(num_non_local_gates) + " lines of the file.");
      */
      break;
    }

    if (current_gate == nullptr ||
        !circuit_.IsValidGateLocation(current_location)) {
      LOG_FATAL("Unable to LoadObliviousTransferBits().");
    }

    SelectionBitAndValuePair<value_t>& ot_bits =
        ot_bits_
            .insert(
                make_pair(current_location, SelectionBitAndValuePair<value_t>()))
            .first->second;
    for (int i = 0; i < 4; ++i) {
      value_t* value = i == 0 ? &ot_bits.first.first :
          i == 1              ? &ot_bits.first.second :
          i == 2              ? &ot_bits.second.first :
          i == 3              ? &ot_bits.second.second :
                                nullptr;
      if (!Stoi(line_parts[i], value)) {
        LOG_ERROR(
            "Unable to parse value " + Itoa(i + 1) + " on line " +
            Itoa(line_num) + " as a numeric value.");
        return false;
      }
    }
    current_location_is_valid = circuit_.GetNextGateLocation(&current_location);
  }

  if (num_non_local_gates < 0 ||
      ot_bits_.size() != (size_t) num_non_local_gates) {
    LOG_ERROR(
        "Not enough ot bits provided in file '" + filename + " (" +
        Itoa(ot_bits_.size()) + " found, " + Itoa(num_non_local_gates) +
        " required)");
    return false;
  }

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::LoadPrecomputedBitsIntoCircuit(
    const vector<TruthTableMask<value_t>>& mask_values) {
  if (circuit_.timer_level_ >= 1) {
    StartTimer(&circuit_.server_load_ot_bits_to_gate_masks_timer_);
  }

  // Make sure circuit fields for number of (non-local) gates is set.
  if (circuit_.size_ <= 0 || circuit_.num_non_local_gates_ == -1) {
    LOG_FATAL("The size_ and/or num_non_local_gates_ fields not set. "
              "This is no longer a supported use-case.");
  }

  // Make sure enough mask values were provided: there should be either
  // one for *every* gate, or one for every non-local gate.
  const uint64_t num_required =
      compute_gates_locally_ ? circuit_.num_non_local_gates_ : circuit_.size_;
  if (mask_values.size() != num_required) {
    if (mask_values.size() < num_required) {
      LOG_ERROR(
          "Wrong number of OT Mask values provided: "
          "mask_values.size(): " +
          Itoa(mask_values.size()) + ", circuit_.size_: " +
          Itoa(circuit_.size_) + ", circuit_.num_non_local_gates_: " +
          Itoa(circuit_.num_non_local_gates_));
      return false;
    } else {
      /*
      DLOG_WARNING("File with OT bits has more bits (" +
                   Itoa(mask_values.size()) + ") than are required (" +
                   Itoa(num_required) + "). We'll just use the first " +
                   Itoa(num_required) + " lines of the file.");
      */
    }
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  int mask_index = 0;
  for (StandardCircuitLevel<value_t>& level : circuit_.levels_) {
    for (StandardGate<value_t>& gate : level.gates_) {
      if (compute_gates_locally_ && gate.IsLocallyComputable()) continue;

      // Generate a random output share for this gate.
      const value_t output_share =
          is_format_one ? (value_t) RandomSlice() : (value_t) RandomBit();
      // Store output_share to gate's output wire.
      gate.output_value_ = output_share;

      // Set the input values for all gates the output wire leads to.
      if (!SetInputsForWires(
              output_share, gate.output_wire_locations_, &circuit_)) {
        return false;
      }

      // Copy mask_values to this gate's mask_.
      if (gate.mask_set_) {
        LOG_ERROR(
            "Gate " + Itoa(gate.loc_.index_) + " on level " +
            Itoa(gate.loc_.level_) + " already had its truth table mask set.");
        return false;
      }
      const TruthTableMask<value_t>& mask = mask_values[mask_index];
      gate.mask_.first.first = mask.first.first;
      gate.mask_.first.second = mask.first.second;
      gate.mask_.second.first = mask.second.first;
      gate.mask_.second.second = mask.second.second;
      gate.mask_set_ = true;
      mask_index++;
    }
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.server_load_ot_bits_to_gate_masks_timer_);
  }

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::ExchangeInputShares() {
  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  if (is_format_one) {
    return ExchangeFormatOneInputShares();
  } else {
    return ExchangeFormatTwoInputShares();
  }
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == slice. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == bool will never be realized.
template<typename value_t>
bool GmwServer<value_t>::ExchangeFormatOneInputShares() {
  servers_shares_of_servers_input_as_slice_.clear();
  servers_shares_of_clients_input_as_slice_.clear();

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = socket_->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(uint64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get (shares of) Client's input. Socket Error "
          "Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (socket_->GetReceivedBytes().size() != 1) {
      LOG_FATAL("Unexpected number of Servers");
    }
    socket_->SwapBuffer(0, &received_data);

    // Parse num_inputs and secret_size (the first 16 bytes of the received data).
    const uint64_t num_inputs = ByteStringToValue<uint64_t>(received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes =
        num_inputs * (is_format_one ? sizeof(slice) : 1);
    params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
    socket_->ResetForReceive();
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_second_comm_bytes);
    return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get (shares of) Client's input. Socket Error "
          "Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    // Listen for Client's shares.
    socket_->SetListenReceiveDataCallback(
        is_format_one ? &ReceiveInputShares<slice> :
                        &ReceiveInputShares<unsigned char>);
    const set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get (shares of) Client's input. Socket Error "
          "Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  }

  // Store Client's shares.
  const map<SocketIdentifier, ReceivedData>& received_data_map =
      socket_->GetReceivedBytes();
  if (received_data_map.size() != 1) {
    LOG_FATAL("unexpected number of connections");
  }
  const ReceivedData& received_data = received_data_map.begin()->second;

  // Skip over the first sizeof(uint64_t) bytes that were received
  // (these were only included to signal when to stop listening).
  const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
  const char* rec_buffer = received_data.buffer_.empty() ?
      received_data.char_buffer_ :
      received_data.buffer_.data();
  const uint64_t num_bytes_received = received_data.buffer_.empty() ?
      received_data.num_received_bytes_ :
      received_data.buffer_.size();
  servers_shares_of_clients_input_as_slice_ = ByteStringToValueVector<slice>(
      buffer_offset, num_bytes_received, (const unsigned char*) rec_buffer);
  socket_->ResetForReceive();

  // Randomly generate a share for each of Server's inputs.
  const size_t num_server_inputs = input_as_slice_.size();
  servers_shares_of_servers_input_as_slice_.resize(num_server_inputs, 0);
  vector<slice> clients_shares_of_servers_input(num_server_inputs, 0);
  for (size_t i = 0; i < num_server_inputs; ++i) {
    const slice& input_value = input_as_slice_[i];
    const slice random_slice = RandomSlice();
    servers_shares_of_servers_input_as_slice_[i] = random_slice ^ input_value;
    clients_shares_of_servers_input[i] = random_slice;
  }

  // Send shares of Server's own input to Client.
  // Should only be one socket, use it.
  vector<unsigned char> to_send;
  if (!ValueToByteString<size_t>(num_server_inputs, &to_send)) {
    LOG_ERROR("Failed to send Server's input shares to Client.");
    return false;
  }
  vector<unsigned char> bytes_to_send;
  if (!ValueVectorToByteString<slice>(
          clients_shares_of_servers_input, &bytes_to_send)) {
    LOG_ERROR("Failed to send Server's input shares to Client.");
    return false;
  }
  if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
      SendReturnCode::SUCCESS !=
          socket_->SendData(bytes_to_send.data(), bytes_to_send.size())) {
    LOG_ERROR("Failed to send Server's input shares to Client.");
    return false;
  }

  return true;
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == bool. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == slice will never be realized.
template<typename value_t>
bool GmwServer<value_t>::ExchangeFormatTwoInputShares() {
  servers_shares_of_servers_input_as_generic_value_.clear();
  servers_shares_of_clients_input_as_generic_value_.clear();

  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  if (is_cookie_socket) {
    ListenParams params = socket_->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(int64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get shares of Client's input" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (socket_->GetReceivedBytes().size() != 1) {
      LOG_FATAL("Unexpected number of Servers");
    }
    socket_->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    uint64_t num_bytes = ByteStringToValue<uint64_t>(received_data);

    // Now, listen for all of the secrets.
    if (num_bytes > INT_MAX) LOG_FATAL("Too many bytes.");
    params.receive_buffer_max_size_ = (int) num_bytes;
    socket_->ResetForReceive();
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
    return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get shares of Client's input" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    // Listen for Client's shares.
    socket_->SetListenReceiveDataCallback(&ReceiveBigEndianInt64Bytes);
    set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get shares of Client's input" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  }

  // Store Client's shares.
  if (socket_->GetReceivedBytes().size() != 1)
    LOG_FATAL("Too many connections.");
  const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
  socket_->CopyBuffer(
      0,
      buffer_offset,
      (vector<char>*) &servers_shares_of_clients_input_as_generic_value_);
  socket_->ResetForReceive();

  // Randomly generate a share for each of Server's inputs.
  vector<unsigned char> clients_shares_of_servers_input;
  // There are two options for generating randomness here, both work but have
  // different trade-offs in terms of optimizing running time:
  //   1) Generate randomness as it is needed
  //   2) Generate all randomness at once:
  //        a) Determine (via pre-processing input_as_generic_value_) exactly
  //           how much randomness is needed by looking at the data types of
  //           all inputs
  //        b) Pick a suitable upper-bound (e.g. 64-bit int) for all the input
  //           data types
  // The issue with (1) is that it may be slower to call RandomBytes() several
  // times, rather than just once. The issue with (2) is that we don't a-priori
  // know how much randomness to generate, since we don't know the data-types
  // of the inputs. (2a) could be done to resolve this, but this also reduces
  // efficiency (extra loop required); while (2b) has the dual issues of
  // potentially generating too much randomness (if many data types have size
  // much less than 64-bits), or too little randomness (for e.g. string and
  // perhaps double data types).
  // We go with option (2a), because knowing the total number of bytes across
  // all of the Server's inputs will be useful information anyway (e.g. to
  // size [servers | clients]_shares_of_servers_input_).
  const uint64_t num_server_inputs = input_as_generic_value_.size();
  uint64_t total_input_bytes = 0;
  for (const GenericValue& input_i : input_as_generic_value_) {
    total_input_bytes += GetValueNumBytes(input_i);
  }
  servers_shares_of_servers_input_as_generic_value_.resize(total_input_bytes);
  clients_shares_of_servers_input.resize(total_input_bytes);
  server_input_index_to_server_shares_index_.clear();
  server_input_index_to_server_shares_index_.resize(num_server_inputs);
  uint64_t current_server_shares_index = 0;
  // Loop through Server's inputs.
  for (size_t i = 0; i < num_server_inputs; ++i) {
    server_input_index_to_server_shares_index_[i] = current_server_shares_index;
    vector<unsigned char> input_i_byte_string =
        GetTwosComplementByteString(input_as_generic_value_[i]);
    const size_t num_input_i_bytes = input_i_byte_string.size();
    // Loop through bytes of Server's current input.
    for (size_t j = 0; j < num_input_i_bytes; ++j) {
      const unsigned char input_i_byte_j = input_i_byte_string[j];
      const unsigned char random_byte = RandomByte();
      servers_shares_of_servers_input_as_generic_value_
          [current_server_shares_index] = input_i_byte_j ^ random_byte;
      clients_shares_of_servers_input[current_server_shares_index] = random_byte;
      ++current_server_shares_index;
    }
  }

  // Send shares of Server's own input to Client.
  // Should only be one socket, use it.
  vector<unsigned char> to_send;
  if (!ValueToByteString<uint64_t>(total_input_bytes, &to_send)) {
    LOG_ERROR("Failed to send Server's input shares to Client.");
    return false;
  }
  if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
      SendReturnCode::SUCCESS !=
          socket_->SendData(
              clients_shares_of_servers_input.data(), total_input_bytes)) {
    LOG_ERROR("Failed to send Server's input shares to Client.");
    return false;
  }

  // Generate or listen for client's schema.
  if (circuit_.input_types_.size() >= 2 && !circuit_.input_types_[1].empty()) {
    client_input_index_to_client_shares_index_.clear();
    client_input_index_to_client_shares_index_.resize(
        circuit_.input_types_[1].size());
    uint64_t current_client_shares_index = 0;
    for (size_t i = 0; i < circuit_.input_types_[1].size(); ++i) {
      client_input_index_to_client_shares_index_[i] =
          current_client_shares_index;
      current_client_shares_index +=
          GetValueNumBytes(circuit_.input_types_[1][i].second);
    }
  } else {
    // Listen for 'schema' of Client's shares (mapping Client input index
    // to the index within the received byte array of Client's input values);
    // this will directly populate client_input_index_to_client_shares_index_.
    const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
    if (is_cookie_socket) {
      ListenParams params = socket_->GetListenParams();
      uint64_t num_first_comm_bytes = sizeof(int64_t);
      params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_first_comm_bytes);
      set<ListenReturnCode> return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get shares of Client's input" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
      vector<char> received_data;
      if (socket_->GetReceivedBytes().size() != 1)
        LOG_FATAL("Unexpected number of Servers");
      socket_->SwapBuffer(0, &received_data);

      // Parse num_secrets and secret_size (the first 16 bytes of the received data).
      uint64_t num_bytes = ByteStringToValue<uint64_t>(received_data);

      // Now, listen for all of the secrets.
      if (num_bytes > INT_MAX) LOG_FATAL("Too many bytes.");
      params.receive_buffer_max_size_ = (int) num_bytes;
      socket_->ResetForReceive();
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
      return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Client's input. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    } else {
      socket_->SetListenReceiveDataCallback(&ReceiveBigEndianInt64Bytes);
      set<ListenReturnCode> return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Client's input. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }

    // Store Client's schema.
    const map<SocketIdentifier, ReceivedData>& received_schema_map =
        socket_->GetReceivedBytes();
    if (received_schema_map.size() != 1) LOG_FATAL("Too many connections.");
    const ReceivedData& received_data = received_schema_map.begin()->second;

    // Skip over the first sizeof(uint64_t) bytes that were received
    // (these were only included to signal when to stop listening).
    const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
    const char* rec_buffer = received_data.buffer_.empty() ?
        received_data.char_buffer_ :
        received_data.buffer_.data();
    const uint64_t num_bytes_received = received_data.buffer_.empty() ?
        received_data.num_received_bytes_ :
        received_data.buffer_.size();
    client_input_index_to_client_shares_index_ =
        ByteStringToValueVector<uint64_t>(
            buffer_offset,
            num_bytes_received,
            (const unsigned char*) rec_buffer);
    socket_->ResetForReceive();
  }

  // Send Server's own schema to Client, if Client can't compute it himself.
  if (circuit_.input_types_.empty() || circuit_.input_types_[0].empty()) {
    // Send Server's schema to Client.
    // Should only be one socket, use it.
    const uint64_t num_server_input_bytes = num_server_inputs * sizeof(uint64_t);
    vector<unsigned char> to_send;
    if (!ValueToByteString<uint64_t>(num_server_input_bytes, &to_send)) {
      LOG_ERROR("Failed to send Server's input schema to Client.");
      return false;
    }
    vector<unsigned char> bytes_to_send;
    if (!ValueVectorToByteString<uint64_t>(
            server_input_index_to_server_shares_index_, &bytes_to_send)) {
      LOG_ERROR("Failed to send Client's input shares to Server.");
      return false;
    }
    if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
        SendReturnCode::SUCCESS !=
            socket_->SendData(bytes_to_send.data(), bytes_to_send.size())) {
      LOG_ERROR("Failed to send Server's input schema to Client.");
      return false;
    }
  }

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::ExchangeInputShares() {
  if (input_as_slice_.empty() == input_as_generic_value_.empty()) {
    LOG_ERROR("Unable to ExchangeInputShares: Input has not been set.");
    return false;
  }

  if (!input_as_slice_.empty()) {
    return ExchangeFormatOneInputShares();
  } else {
    return ExchangeFormatTwoInputShares();
  }
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == slice. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == bool will never be realized.
template<typename value_t>
bool GmwClient<value_t>::ExchangeFormatOneInputShares() {
  clients_shares_of_clients_input_as_slice_.clear();
  clients_shares_of_servers_input_as_slice_.clear();

  // Randomly generate a share for each of Client's inputs.
  const size_t num_client_inputs = input_as_slice_.size();
  clients_shares_of_clients_input_as_slice_.resize(num_client_inputs);
  vector<slice> servers_shares_of_clients_input(num_client_inputs, 0);
  for (size_t i = 0; i < num_client_inputs; ++i) {
    const slice& input_value = input_as_slice_[i];
    const slice random_slice = RandomSlice();
    clients_shares_of_clients_input_as_slice_[i] = random_slice ^ input_value;
    servers_shares_of_clients_input[i] = random_slice;
  }

  // Send shares of Client's own input to Server.
  vector<unsigned char> to_send;
  if (!ValueToByteString<uint64_t>(num_client_inputs, &to_send)) {
    LOG_ERROR("Failed to send Client's input shares to Server.");
    return false;
  }
  vector<unsigned char> bytes_to_send;
  if (!ValueVectorToByteString<slice>(
          servers_shares_of_clients_input, &bytes_to_send)) {
    LOG_ERROR("Failed to send Client's input shares to Server.");
    return false;
  }
  if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
      SendReturnCode::SUCCESS !=
          socket_->SendData(bytes_to_send.data(), bytes_to_send.size())) {
    LOG_ERROR("Failed to send Client's input shares to Server.");
    return false;
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = socket_->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(uint64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get (shares of) Client's input. Socket Error "
          "Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (socket_->GetReceivedBytes().size() != 1) {
      LOG_FATAL("Unexpected number of Servers");
    }
    socket_->SwapBuffer(0, &received_data);

    // Parse num_inputs and secret_size (the first 16 bytes of the received data).
    const uint64_t num_inputs = ByteStringToValue<uint64_t>(received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes =
        num_inputs * (is_format_one ? sizeof(slice) : 1);
    params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
    socket_->ResetForReceive();
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_second_comm_bytes);
    return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get (shares of) Client's input. Socket Error "
          "Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    // Listen for Server's shares.
    socket_->SetListenReceiveDataCallback(
        is_format_one ? &ReceiveInputShares<slice> :
                        &ReceiveInputShares<unsigned char>);
    const set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get (shares of) Server's input. Socket Error "
          "Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  }

  // Store Server's shares.
  const map<SocketIdentifier, ReceivedData>& received_data_map =
      socket_->GetReceivedBytes();
  if (received_data_map.size() != 1) LOG_FATAL("Too many connections.");
  const ReceivedData& received_data = received_data_map.begin()->second;

  // Skip over the first sizeof(uint64_t) bytes that were received
  // (these were only included to signal when to stop listening).
  const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
  const char* rec_buffer = received_data.buffer_.empty() ?
      received_data.char_buffer_ :
      received_data.buffer_.data();
  const uint64_t num_bytes_received = received_data.buffer_.empty() ?
      received_data.num_received_bytes_ :
      received_data.buffer_.size();
  clients_shares_of_servers_input_as_slice_ = ByteStringToValueVector<slice>(
      buffer_offset, num_bytes_received, (const unsigned char*) rec_buffer);
  socket_->ResetForReceive();

  return true;
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == bool. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == slice will never be realized.
template<typename value_t>
bool GmwClient<value_t>::ExchangeFormatTwoInputShares() {
  clients_shares_of_clients_input_as_generic_value_.clear();
  clients_shares_of_servers_input_as_generic_value_.clear();

  // Randomly generate a share for each of Client's inputs.
  vector<unsigned char> servers_shares_of_clients_input;
  const uint64_t num_client_inputs = input_as_generic_value_.size();
  uint64_t total_input_bytes = 0;
  for (const GenericValue& input_i : input_as_generic_value_) {
    total_input_bytes += GetValueNumBytes(input_i);
  }
  clients_shares_of_clients_input_as_generic_value_.resize(total_input_bytes);
  servers_shares_of_clients_input.resize(total_input_bytes);
  client_input_index_to_client_shares_index_.clear();
  client_input_index_to_client_shares_index_.resize(num_client_inputs);
  uint64_t current_client_shares_index = 0;
  // Loop through Client's inputs.
  for (size_t i = 0; i < num_client_inputs; ++i) {
    client_input_index_to_client_shares_index_[i] = current_client_shares_index;
    vector<unsigned char> input_i_byte_string =
        GetTwosComplementByteString(input_as_generic_value_[i]);
    const size_t num_input_i_bytes = input_i_byte_string.size();
    // Loop through bytes of Client's current input.
    for (size_t j = 0; j < num_input_i_bytes; ++j) {
      const unsigned char input_i_byte_j = input_i_byte_string[j];
      const unsigned char random_byte = RandomByte();
      clients_shares_of_clients_input_as_generic_value_
          [current_client_shares_index] = input_i_byte_j ^ random_byte;
      servers_shares_of_clients_input[current_client_shares_index] = random_byte;
      ++current_client_shares_index;
    }
  }

  // Send shares of Client's own input to Server.
  // Should only be one socket, use it.
  vector<unsigned char> to_send;
  if (!ValueToByteString<uint64_t>(total_input_bytes, &to_send)) {
    LOG_ERROR("Failed to send Client's input shares to Server.");
    return false;
  }
  if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
      SendReturnCode::SUCCESS !=
          socket_->SendData(
              servers_shares_of_clients_input.data(), total_input_bytes)) {
    LOG_ERROR("Failed to send Client's input shares to Server.");
    return false;
  }

  // Listen for Server's shares.
  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  if (is_cookie_socket) {
    ListenParams params = socket_->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(int64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get shares of Client's input" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (socket_->GetReceivedBytes().size() != 1) {
      LOG_FATAL("Unexpected number of Servers");
    }
    socket_->SwapBuffer(0, &received_data);

    // Parse num_secrets and secret_size (the first 16 bytes of the received data).
    uint64_t num_bytes = ByteStringToValue<uint64_t>(received_data);

    // Now, listen for all of the secrets.
    if (num_bytes > INT_MAX) LOG_FATAL("Too many bytes.");
    params.receive_buffer_max_size_ = (int) num_bytes;
    socket_->ResetForReceive();
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
    return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get (shares of) Server's input. Socket Error "
          "Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  } else {
    socket_->SetListenReceiveDataCallback(&ReceiveBigEndianInt64Bytes);
    set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to get (shares of) Server's input. Socket Error "
          "Message:\n" +
          socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  }

  // Store Server's shares.
  if (socket_->GetReceivedBytes().size() != 1)
    LOG_FATAL("Too many connections.");
  const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
  socket_->CopyBuffer(
      0,
      buffer_offset,
      (vector<char>*) &clients_shares_of_servers_input_as_generic_value_);
  socket_->ResetForReceive();

  // Send Client's schema to Server, if Server can't locally compute it.
  if (circuit_.input_types_.size() < 2 || circuit_.input_types_[1].empty()) {
    // Should only be one socket, use it.
    const uint64_t num_client_input_bytes = num_client_inputs * sizeof(uint64_t);
    vector<unsigned char> to_send;
    if (!ValueToByteString<uint64_t>(num_client_input_bytes, &to_send)) {
      LOG_ERROR("Failed to send Client's input schema to Server.");
      return false;
    }
    vector<unsigned char> bytes_to_send;
    if (!ValueVectorToByteString<uint64_t>(
            client_input_index_to_client_shares_index_, &bytes_to_send)) {
      LOG_ERROR("Failed to send Client's input shares to Server.");
      return false;
    }
    if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
        SendReturnCode::SUCCESS !=
            socket_->SendData(bytes_to_send.data(), bytes_to_send.size())) {
      LOG_ERROR("Failed to send Client's input schema to Server.");
      return false;
    }
  }

  // Generate server's schema (if input_types_ info is present).
  // Otherwise, receive schema from Server.
  if (!circuit_.input_types_.empty() && !circuit_.input_types_[0].empty()) {
    server_input_index_to_server_shares_index_.clear();
    server_input_index_to_server_shares_index_.resize(
        circuit_.input_types_[0].size());
    uint64_t current_server_shares_index = 0;
    for (size_t i = 0; i < circuit_.input_types_[0].size(); ++i) {
      server_input_index_to_server_shares_index_[i] =
          current_server_shares_index;
      current_server_shares_index +=
          GetValueNumBytes(circuit_.input_types_[0][i].second);
    }
  } else {
    // Listen for 'schema' of Server's shares (mapping Server input index
    // to the index within the received byte array of Server's input values);
    // this will directly populate client_input_index_to_client_shares_index_.
    const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
    if (is_cookie_socket) {
      ListenParams params = socket_->GetListenParams();
      uint64_t num_first_comm_bytes = sizeof(int64_t);
      params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_first_comm_bytes);
      set<ListenReturnCode> return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get shares of Client's input" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
      vector<char> received_data;
      if (socket_->GetReceivedBytes().size() != 1) {
        LOG_FATAL("Unexpected number of Servers");
      }
      socket_->SwapBuffer(0, &received_data);

      // Parse num_secrets and secret_size (the first 16 bytes of the received data).
      uint64_t num_bytes = ByteStringToValue<uint64_t>(received_data);

      // Now, listen for all of the secrets.
      if (num_bytes > INT_MAX) LOG_FATAL("Too many bytes.");
      params.receive_buffer_max_size_ = (int) num_bytes;
      socket_->ResetForReceive();
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(&ReceiveNumBytes, &num_bytes);
      return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Server's input. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    } else {
      socket_->SetListenReceiveDataCallback(&ReceiveBigEndianInt64Bytes);
      set<ListenReturnCode> return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Server's input. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }

    // Store Server's schema.
    const map<SocketIdentifier, ReceivedData>& received_schema_map =
        socket_->GetReceivedBytes();
    if (received_schema_map.size() != 1) LOG_FATAL("Too many connections.");
    const ReceivedData& received_data = received_schema_map.begin()->second;

    // Skip over the first sizeof(uint64_t) bytes that were received
    // (these were only included to signal when to stop listening).
    const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
    const char* rec_buffer = received_data.buffer_.empty() ?
        received_data.char_buffer_ :
        received_data.buffer_.data();
    const uint64_t num_bytes_received = received_data.buffer_.empty() ?
        received_data.num_received_bytes_ :
        received_data.buffer_.size();
    server_input_index_to_server_shares_index_ =
        ByteStringToValueVector<uint64_t>(
            buffer_offset,
            num_bytes_received,
            (const unsigned char*) rec_buffer);
    socket_->ResetForReceive();
  }

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::ExchangeOutputShares() {
  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;
  if ((is_format_one && circuit_.outputs_as_slice_.empty()) ||
      (!is_format_one && circuit_.outputs_as_bits_.empty())) {
    LOG_ERROR("Unable to ExchangeOutputShares: Output has not been set.");
    return false;
  }

  // Get mapping from output wire index to output value (index, bit index).
  vector<pair<uint64_t, uint64_t>> output_wire_to_output_index_and_bit;
  if (!is_format_one &&
      !GetOutputWireIndexToGenericValueIndex(
          circuit_.output_designations_, &output_wire_to_output_index_and_bit)) {
    LOG_ERROR("Unable to map output wires to output values.");
    return false;
  }

  const uint64_t num_output_wires = is_format_one ?
      circuit_.outputs_as_slice_.size() :
      circuit_.outputs_as_bits_.size();

  // Setup the (shares of) Server's own output to send to Client.
  // Only send shares for which the Client is supposed to learn the output:
  // OutputRecipient.all_ or OutputRecipient.to_ includes `1'.
  vector<slice> format_one_outputs_to_share;
  vector<unsigned char> format_two_outputs_to_share;
  if (is_format_one) {
    if (circuit_.output_designations_.empty()) {
      // No target destinations provided. Default is to let each party have
      // every output.
      format_one_outputs_to_share = circuit_.outputs_as_slice_;
    } else {
      if (num_output_wires != circuit_.output_designations_.size()) {
        LOG_FATAL("Mismatching number of output wires.");
      }
      for (uint64_t output_index = 0; output_index < num_output_wires;
           ++output_index) {
        if (circuit_.output_designations_[output_index].first.all_ ||
            ContainsKey(
                (int) 1,
                circuit_.output_designations_[output_index].first.to_)) {
          format_one_outputs_to_share.push_back(
              circuit_.outputs_as_slice_[output_index]);
        }
      }
    }
  } else {
    if (circuit_.output_designations_.empty()) {
      // No target destinations provided. Default is to let each party have
      // every output.
      format_two_outputs_to_share = circuit_.outputs_as_bits_;
    } else {
      if (num_output_wires != output_wire_to_output_index_and_bit.size()) {
        LOG_FATAL("Mismatching number of output wires.");
      }
      for (uint64_t wire_index = 0; wire_index < num_output_wires;
           ++wire_index) {
        const uint64_t output_index =
            output_wire_to_output_index_and_bit[wire_index].first;
        if (output_index >= circuit_.output_designations_.size()) {
          LOG_FATAL("Mismatching number of output wires.");
        }
        if (circuit_.output_designations_[output_index].first.all_ ||
            ContainsKey(
                (int) 1,
                circuit_.output_designations_[output_index].first.to_)) {
          format_two_outputs_to_share.push_back(
              circuit_.outputs_as_bits_[wire_index]);
        }
      }
    }
  }

  // Compute which shares Client will send (based on output_designations_).
  vector<uint64_t> output_indices_received;
  if (!circuit_.output_designations_.empty()) {
    if (is_format_one) {
      for (uint64_t output_index = 0; output_index < num_output_wires;
           ++output_index) {
        if (circuit_.output_designations_[output_index].first.all_ ||
            ContainsKey(
                (int) 0,
                circuit_.output_designations_[output_index].first.to_)) {
          output_indices_received.push_back(output_index);
        }
      }
    } else {
      for (uint64_t wire_index = 0; wire_index < num_output_wires;
           ++wire_index) {
        const uint64_t output_index =
            output_wire_to_output_index_and_bit[wire_index].first;
        if (circuit_.output_designations_[output_index].first.all_ ||
            ContainsKey(
                (int) 0,
                circuit_.output_designations_[output_index].first.to_)) {
          output_indices_received.push_back(wire_index);
        }
      }
    }
  } else {
    if (is_format_one) {
      for (uint64_t output_index = 0; output_index < num_output_wires;
           ++output_index) {
        output_indices_received.push_back(output_index);
      }
    } else {
      for (uint64_t wire_index = 0; wire_index < num_output_wires;
           ++wire_index) {
        output_indices_received.push_back(wire_index);
      }
    }
  }

  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (output_indices_received.size() > 0) {
    if (is_cookie_socket) {
      // First, learn the number of secrets and the secret size.
      ListenParams params = socket_->GetListenParams();
      uint64_t num_first_comm_bytes = sizeof(uint64_t);
      params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_first_comm_bytes);
      set<ListenReturnCode> return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Client's input. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
      vector<char> received_data;
      if (socket_->GetReceivedBytes().size() != 1) {
        LOG_FATAL("Unexpected number of Servers");
      }
      socket_->SwapBuffer(0, &received_data);

      // Parse num_inputs and secret_size (the first 16 bytes of the received data).
      const uint64_t num_inputs = ByteStringToValue<uint64_t>(received_data);

      // Now, listen for all of the secrets.
      uint64_t num_second_comm_bytes =
          num_inputs * (is_format_one ? sizeof(slice) : 1);
      params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
      socket_->ResetForReceive();
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_second_comm_bytes);
      return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Client's input. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    } else {
      // Listen for Client's shares.
      socket_->SetListenReceiveDataCallback(
          is_format_one ? &ReceiveFormatOneOutputShares :
                          &ReceiveFormatTwoOutputShares);
      const set<ListenReturnCode> return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Client's output. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }

    // Store Client's shares.
    const map<SocketIdentifier, ReceivedData>& received_data_map =
        socket_->GetReceivedBytes();
    if (received_data_map.size() != 1) LOG_FATAL("Too many connections.");
    const ReceivedData& received_data = received_data_map.begin()->second;
    const size_t num_recd_bytes = received_data.buffer_.empty() ?
        received_data.num_received_bytes_ :
        received_data.buffer_.size();

    // Skip over the first sizeof(uint64_t) bytes that were received
    // (these were only included to signal when to stop listening).
    const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
    const char* rec_buffer = received_data.buffer_.empty() ?
        received_data.char_buffer_ :
        received_data.buffer_.data();
    const uint64_t num_bytes_received = received_data.buffer_.empty() ?
        received_data.num_received_bytes_ :
        received_data.buffer_.size();
    if (is_format_one) {
      const vector<slice> format_one_clients_shares =
          ByteStringToValueVector<slice>(
              buffer_offset,
              num_bytes_received,
              (const unsigned char*) rec_buffer);
      socket_->ResetForReceive();

      // Set final output shares by XOR'ing own shares with received Client's shares.
      if (format_one_clients_shares.size() != output_indices_received.size()) {
        LOG_ERROR("Mismatching number of outputs from Server.");
        return false;
      }
      for (size_t i = 0; i < format_one_clients_shares.size(); ++i) {
        const uint64_t output_index = output_indices_received[i];
        if (output_index >= num_output_wires) {
          LOG_ERROR(
              "Unexpected output index (" + Itoa(output_index) +
              ") is greater than the number of output wires (" +
              Itoa(num_output_wires));
          return false;
        }
        circuit_.outputs_as_slice_[output_index] ^= format_one_clients_shares[i];
      }
    } else {
      // Set final output shares by XOR'ing own shares with received Client's shares.
      if (num_recd_bytes != buffer_offset + output_indices_received.size()) {
        LOG_ERROR("Mismatching number of outputs from Server.");
        return false;
      }
      for (size_t i = buffer_offset; i < num_recd_bytes; ++i) {
        const uint64_t output_index = output_indices_received[i - buffer_offset];
        if (output_index >= num_output_wires) {
          LOG_ERROR(
              "Unexpected output index (" + Itoa(output_index) +
              ") is greater than the number of output wires (" +
              Itoa(num_output_wires));
          return false;
        }
        circuit_.outputs_as_bits_[output_index] =
            circuit_.outputs_as_bits_[output_index] ^
            ((const unsigned char*) (rec_buffer))[i];
      }

      socket_->ResetForReceive();
    }
  }

  // Send shares of Server's output to Client.
  const uint64_t num_format_one_outputs_to_share =
      format_one_outputs_to_share.size();
  if (num_format_one_outputs_to_share > 0) {
    // Should only be one socket, use it.
    vector<unsigned char> to_send;
    if (!ValueToByteString<uint64_t>(
            num_format_one_outputs_to_share, &to_send)) {
      LOG_ERROR("Failed to send Server's output shares to Client.");
      return false;
    }
    vector<unsigned char> bytes_to_send;
    if (!ValueVectorToByteString<slice>(
            format_one_outputs_to_share, &bytes_to_send)) {
      LOG_ERROR("Failed to send Client's input shares to Server.");
      return false;
    }
    if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
        SendReturnCode::SUCCESS !=
            socket_->SendData(bytes_to_send.data(), bytes_to_send.size())) {
      LOG_ERROR("Failed to send Server's output shares to Client.");
      return false;
    }
  }
  const uint64_t num_format_two_outputs_to_share =
      format_two_outputs_to_share.size();
  if (num_format_two_outputs_to_share > 0) {
    // Should only be one socket, use it.
    vector<unsigned char> to_send;
    if (!ValueToByteString<uint64_t>(
            num_format_two_outputs_to_share, &to_send)) {
      LOG_ERROR("Failed to send Server's output shares to Client.");
      return false;
    }
    if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
        SendReturnCode::SUCCESS !=
            socket_->SendData(
                format_two_outputs_to_share.data(),
                num_format_two_outputs_to_share)) {
      LOG_ERROR("Failed to send Server's output shares to Client.");
      return false;
    }
  }

  return (is_format_one || circuit_.ConvertOutputs());
}

template<typename value_t>
bool GmwClient<value_t>::ExchangeOutputShares() {
  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  if ((is_format_one && circuit_.outputs_as_slice_.empty()) ||
      (!is_format_one && circuit_.outputs_as_bits_.empty())) {
    LOG_ERROR("Unable to ExchangeOutputShares: Output has not been set.");
    return false;
  }

  // Get mapping from output wire index to output value (index, bit index).
  vector<pair<uint64_t, uint64_t>> output_wire_to_output_index_and_bit;
  if (!is_format_one &&
      !GetOutputWireIndexToGenericValueIndex(
          circuit_.output_designations_, &output_wire_to_output_index_and_bit)) {
    LOG_ERROR("Unable to map output wires to output values.");
    return false;
  }

  const uint64_t num_output_wires = is_format_one ?
      circuit_.outputs_as_slice_.size() :
      circuit_.outputs_as_bits_.size();

  // Send shares of Client's own output to Server.
  // Only send shares for which the Server is supposed to learn the output:
  // OutputRecipient.all_ or OutputRecipient.to_ includes `1'.
  vector<slice> format_one_outputs_to_share;
  vector<unsigned char> format_two_outputs_to_share;
  if (is_format_one) {
    if (circuit_.output_designations_.empty()) {
      // No target destinations provided. Default is to let each party have
      // every output.
      format_one_outputs_to_share = circuit_.outputs_as_slice_;
    } else {
      if (num_output_wires != circuit_.output_designations_.size()) {
        LOG_FATAL("Mismatching number of output wires.");
      }
      for (uint64_t output_index = 0; output_index < num_output_wires;
           ++output_index) {
        if (circuit_.output_designations_[output_index].first.all_ ||
            ContainsKey(
                (int) 0,
                circuit_.output_designations_[output_index].first.to_)) {
          format_one_outputs_to_share.push_back(
              circuit_.outputs_as_slice_[output_index]);
        }
      }
    }
  } else {
    if (circuit_.output_designations_.empty()) {
      // No target destinations provided. Default is to let each party have
      // every output.
      format_two_outputs_to_share = circuit_.outputs_as_bits_;
    } else {
      if (num_output_wires != output_wire_to_output_index_and_bit.size()) {
        LOG_FATAL("Mismatching number of output wires.");
      }
      for (uint64_t wire_index = 0; wire_index < num_output_wires;
           ++wire_index) {
        const uint64_t output_index =
            output_wire_to_output_index_and_bit[wire_index].first;
        if (output_index >= circuit_.output_designations_.size()) {
          LOG_FATAL("Mismatching number of output wires.");
        }
        if (circuit_.output_designations_[output_index].first.all_ ||
            ContainsKey(
                (int) 0,
                circuit_.output_designations_[output_index].first.to_)) {
          format_two_outputs_to_share.push_back(
              circuit_.outputs_as_bits_[wire_index]);
        }
      }
    }
  }

  const uint64_t num_format_one_outputs_to_share =
      format_one_outputs_to_share.size();
  if (num_format_one_outputs_to_share > 0) {
    vector<unsigned char> to_send;
    if (!ValueToByteString<uint64_t>(
            num_format_one_outputs_to_share, &to_send)) {
      LOG_ERROR("Failed to send Client's output shares to Server.");
      return false;
    }
    vector<unsigned char> bytes_to_send;
    if (!ValueVectorToByteString<slice>(
            format_one_outputs_to_share, &bytes_to_send)) {
      LOG_ERROR("Failed to send Client's input shares to Server.");
      return false;
    }

    if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
        SendReturnCode::SUCCESS !=
            socket_->SendData(bytes_to_send.data(), bytes_to_send.size())) {
      LOG_ERROR("Failed to send Client's output shares to Server.");
      return false;
    }
  }
  const uint64_t num_format_two_outputs_to_share =
      format_two_outputs_to_share.size();
  if (num_format_two_outputs_to_share > 0) {
    vector<unsigned char> to_send;
    if (!ValueToByteString<uint64_t>(
            num_format_two_outputs_to_share, &to_send)) {
      LOG_ERROR("Failed to send Client's output shares to Server.");
      return false;
    }
    if (!socket_->SendDataNoFlush(to_send.data(), to_send.size()) ||
        SendReturnCode::SUCCESS !=
            socket_->SendData(
                format_two_outputs_to_share.data(),
                format_two_outputs_to_share.size())) {
      LOG_ERROR("Failed to send Client's output shares to Server.");
      return false;
    }
  }

  // Compute which shares Server will send (based on output_designations_).
  vector<uint64_t> output_indices_received;
  if (!circuit_.output_designations_.empty()) {
    if (is_format_one) {
      for (uint64_t output_index = 0; output_index < num_output_wires;
           ++output_index) {
        if (circuit_.output_designations_[output_index].first.all_ ||
            ContainsKey(
                (int) 1,
                circuit_.output_designations_[output_index].first.to_)) {
          output_indices_received.push_back(output_index);
        }
      }
    } else {
      for (uint64_t wire_index = 0; wire_index < num_output_wires;
           ++wire_index) {
        const uint64_t output_index =
            output_wire_to_output_index_and_bit[wire_index].first;
        if (circuit_.output_designations_[output_index].first.all_ ||
            ContainsKey(
                (int) 1,
                circuit_.output_designations_[output_index].first.to_)) {
          output_indices_received.push_back(wire_index);
        }
      }
    }
  } else {
    if (is_format_one) {
      for (uint64_t output_index = 0; output_index < num_output_wires;
           ++output_index) {
        output_indices_received.push_back(output_index);
      }
    } else {
      for (uint64_t wire_index = 0; wire_index < num_output_wires;
           ++wire_index) {
        output_indices_received.push_back(wire_index);
      }
    }
  }

  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  // Listen for Server's returned secrets.
  if (output_indices_received.size() > 0) {
    if (is_cookie_socket) {
      // First, learn the number of secrets and the secret size.
      ListenParams params = socket_->GetListenParams();
      uint64_t num_first_comm_bytes = sizeof(uint64_t);
      params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_first_comm_bytes);
      set<ListenReturnCode> return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Client's input. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
      vector<char> received_data;
      if (socket_->GetReceivedBytes().size() != 1) {
        LOG_FATAL("Unexpected number of Servers");
      }
      socket_->SwapBuffer(0, &received_data);

      // Parse num_inputs and secret_size (the first 16 bytes of the received data).
      const uint64_t num_inputs = ByteStringToValue<uint64_t>(received_data);

      // Now, listen for all of the secrets.
      uint64_t num_second_comm_bytes =
          num_inputs * (is_format_one ? sizeof(slice) : 1);
      params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
      socket_->ResetForReceive();
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_second_comm_bytes);
      return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Client's input. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    } else {
      // Listen for Server's shares.
      socket_->SetListenReceiveDataCallback(
          is_format_one ? &ReceiveFormatOneOutputShares :
                          &ReceiveFormatTwoOutputShares);
      const set<ListenReturnCode> return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to get (shares of) Server's output. Socket Error "
            "Message:\n" +
            socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }

    // Store Server's shares.
    const map<SocketIdentifier, ReceivedData>& received_data_map =
        socket_->GetReceivedBytes();
    if (received_data_map.size() != 1) LOG_FATAL("Too many connections.");
    const ReceivedData& received_data = received_data_map.begin()->second;
    const size_t num_recd_bytes = received_data.buffer_.empty() ?
        received_data.num_received_bytes_ :
        received_data.buffer_.size();

    const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
    const char* rec_buffer = received_data.buffer_.empty() ?
        received_data.char_buffer_ :
        received_data.buffer_.data();
    const uint64_t num_bytes_received = received_data.buffer_.empty() ?
        received_data.num_received_bytes_ :
        received_data.buffer_.size();
    if (is_format_one) {
      // Skip over the first sizeof(uint64_t) bytes that were received
      // (these were only included to signal when to stop listening).
      const vector<slice> servers_shares = ByteStringToValueVector<slice>(
          buffer_offset, num_bytes_received, (const unsigned char*) rec_buffer);
      socket_->ResetForReceive();

      // Set final output shares by XOR'ing own shares with received Server's shares.
      if (servers_shares.size() != output_indices_received.size()) {
        LOG_ERROR("Mismatching number of outputs from Server.");
        return false;
      }
      for (size_t i = 0; i < servers_shares.size(); ++i) {
        const uint64_t output_index = output_indices_received[i];
        if (output_index >= num_output_wires) {
          LOG_ERROR(
              "Unexpected output index (" + Itoa(output_index) +
              ") is greater than the number of output wires (" +
              Itoa(num_output_wires));
          return false;
        }
        circuit_.outputs_as_slice_[output_index] ^= servers_shares[i];
      }
    } else {
      // Set final output shares by XOR'ing own shares with received Server's shares.
      if (num_recd_bytes != buffer_offset + output_indices_received.size()) {
        LOG_ERROR("Mismatching number of outputs from Server.");
        return false;
      }
      for (size_t i = buffer_offset; i < num_recd_bytes; ++i) {
        const uint64_t output_index = output_indices_received[i - buffer_offset];
        if (output_index >= num_output_wires) {
          LOG_ERROR(
              "Unexpected output index (" + Itoa(output_index) +
              ") is greater than the number of output wires (" +
              Itoa(num_output_wires));
          return false;
        }
        circuit_.outputs_as_bits_[output_index] =
            circuit_.outputs_as_bits_[output_index] ^
            ((const unsigned char*) rec_buffer)[i];
      }
      socket_->ResetForReceive();
    }
  }

  return (is_format_one || circuit_.ConvertOutputs());
}

template<typename value_t>
bool GmwServer<value_t>::SetInputsForNextLevel(const size_t& level_index) {
  if (circuit_.levels_.size() <= level_index) LOG_FATAL("Level index too high.");
  const StandardCircuitLevel<value_t>& level = circuit_.levels_[level_index];
  for (size_t gate_index = 0; gate_index < level.gates_.size(); ++gate_index) {
    const value_t& output_value = level.gates_[gate_index].output_value_;
    if (!SetInputsForWires(
            output_value,
            level.gates_[gate_index].output_wire_locations_,
            &circuit_)) {
      return false;
    }
  }

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::LoadInputsToCircuit() {
  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;
  if (is_format_one) {
    if (circuit_.inputs_as_slice_locations_.size() != 2) {
      LOG_FATAL("Input not set");
    }
    if (circuit_.inputs_as_slice_locations_[0].empty() &&
        circuit_.inputs_as_slice_locations_[1].empty() &&
        circuit_.constant_slice_input_.empty()) {
      LOG_FATAL("All inputs empty.");
    }
    return LoadFormatOneInputsToCircuit();
  } else {
    if (circuit_.inputs_as_generic_value_locations_.size() != 2) {
      LOG_FATAL("Input not set");
    }
    if (circuit_.inputs_as_generic_value_locations_[0].empty() &&
        circuit_.inputs_as_generic_value_locations_[1].empty() &&
        circuit_.constant_zero_input_.empty() &&
        circuit_.constant_one_input_.empty()) {
      LOG_FATAL("All inputs empty.");
    }
    return LoadFormatTwoInputsToCircuit();
  }
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == slice. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == bool will never be realized.
template<typename value_t>
bool GmwServer<value_t>::LoadFormatOneInputsToCircuit() {
  // Make sure we have an actual input everywhere it is needed
  // (we allow inequality here, to allow for unused inputs of the parties).
  if (circuit_.inputs_as_slice_locations_[1].size() >
          servers_shares_of_clients_input_as_slice_.size() ||
      circuit_.inputs_as_slice_locations_[0].size() >
          servers_shares_of_servers_input_as_slice_.size()) {
    LOG_FATAL("Mismatching inputs to LoadFormatOneInputsToCircuit().");
  }

  // Update 'circuit' by setting values on the input wires, for inputs coming
  // from the other Party (i.e. the Client).
  for (size_t i = 0; i < circuit_.inputs_as_slice_locations_[1].size(); ++i) {
    const set<WireLocation>& wires = circuit_.inputs_as_slice_locations_[1][i];
    const slice& input_value = servers_shares_of_clients_input_as_slice_[i];
    for (const WireLocation& location : wires) {
      StandardGate<value_t>& current_gate =
          circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
      if (!ContainsKey(1, current_gate.depends_on_))
        LOG_FATAL("Missing gate info.");
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

  // Update 'circuit' by setting values on the input wires, for inputs coming
  // from self (i.e., from Server).
  for (size_t i = 0; i < circuit_.inputs_as_slice_locations_[0].size(); ++i) {
    const set<WireLocation>& wires = circuit_.inputs_as_slice_locations_[0][i];
    const slice& input_value = servers_shares_of_servers_input_as_slice_[i];
    for (const WireLocation& location : wires) {
      StandardGate<value_t>& current_gate =
          circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
      if (!ContainsKey(0, current_gate.depends_on_))
        LOG_FATAL("Missing gate info.");
      // NOTE: If compute_gates_locally_ is true, we need to load values on wires
      // specially for input wires to gates that are computed locally; see
      // DISCUSSION item (2) regarding locally evaluating gates, at top of gmw_circuit.h.
      const slice input_value_to_use =
          (compute_gates_locally_ && current_gate.IsLocallyComputable() &&
           !ContainsKey(1, current_gate.depends_on_)) ?
          input_as_slice_[i] :
          input_value;
      if (location.is_left_) {
        if (current_gate.left_input_set_) {
          LOG_FATAL(
              "Gate at level " + Itoa(location.loc_.level_) + " and index " +
              Itoa(location.loc_.index_) +
              " has had its left wire set "
              "multiple times.");
        }
        current_gate.left_input_ = input_value_to_use;
        current_gate.left_input_set_ = true;
      } else {
        if (current_gate.right_input_set_) {
          LOG_FATAL(
              "Gate at level " + Itoa(location.loc_.level_) + " and index " +
              Itoa(location.loc_.index_) +
              " has had its right wire set "
              "multiple times.");
        }
        current_gate.right_input_ = input_value_to_use;
        current_gate.right_input_set_ = true;
      }
    }
  }

  // Update 'circuit' by setting values on the input wires, for constant inputs.
  for (const pair<const slice, set<WireLocation>>& value_and_loc :
       circuit_.constant_slice_input_) {
    const set<WireLocation>& wires = value_and_loc.second;
    const slice& input_value = value_and_loc.first;
    for (const WireLocation& location : wires) {
      StandardGate<value_t>& current_gate =
          circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
      if (current_gate.depends_on_.size() >= 1) {
        LOG_FATAL("Missing gate info.");
      }
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

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == bool. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == slice will never be realized.
template<typename value_t>
bool GmwServer<value_t>::LoadFormatTwoInputsToCircuit() {
  // Update 'circuit' by setting values on the input wires, for inputs coming
  // from the other Party (i.e. the Client).
  const uint64_t num_client_inputs =
      client_input_index_to_client_shares_index_.size();
  for (size_t input_index = 0;
       input_index < circuit_.inputs_as_generic_value_locations_[1].size();
       ++input_index) {
    const vector<set<WireLocation>>& input_to_wires =
        circuit_.inputs_as_generic_value_locations_[1][input_index];
    if (input_index >= num_client_inputs) {
      LOG_FATAL(Itoa(input_index) + ", " + Itoa(num_client_inputs));
    }
    // Find the location within servers_shares_of_clients_input_as_generic_value_
    // where this input is stored.
    const uint64_t& current_input_first_byte_index =
        client_input_index_to_client_shares_index_[input_index];
    const uint64_t current_input_last_byte_index =
        (input_index == num_client_inputs - 1) ?
        servers_shares_of_clients_input_as_generic_value_.size() - 1 :
        client_input_index_to_client_shares_index_[input_index + 1] - 1;
    const size_t num_bits = input_to_wires.size();
    const bool has_remainder_bits = num_bits % CHAR_BIT != 0;
    const size_t input_num_bytes =
        num_bits / CHAR_BIT + (has_remainder_bits ? 1 : 0);
    if (current_input_first_byte_index + input_num_bytes - 1 >
        current_input_last_byte_index) {
      LOG_FATAL(
          Itoa(current_input_first_byte_index) + ", " + Itoa(num_bits) + ", " +
          Itoa(current_input_last_byte_index));
    }
    // Loop through servers_shares_of_clients_input_as_generic_value_ backwards,
    // since it will be easier to process bit '0' first, etc.
    uint64_t bit_index = 0;
    for (int64_t byte_index = (int64_t) input_num_bytes - 1; byte_index >= 0;
         --byte_index) {
      // Get the appropriate byte from this input.
      const unsigned char current_input_byte_as_string =
          servers_shares_of_clients_input_as_generic_value_
              [current_input_first_byte_index + byte_index];
      const int num_bits_this_byte = (byte_index == 0 && has_remainder_bits) ?
          num_bits % CHAR_BIT :
          CHAR_BIT;
      for (int j = 0; j < num_bits_this_byte; ++j) {
        const bool input_value = (current_input_byte_as_string >> j) & 1;

        // Now loop through all wires that use this input bit, loading those
        // wires with the current input value.
        const set<WireLocation>& wires = input_to_wires[bit_index];
        for (const WireLocation& location : wires) {
          StandardGate<value_t>& current_gate =
              circuit_.levels_[location.loc_.level_]
                  .gates_[location.loc_.index_];
          if (!ContainsKey(1, current_gate.depends_on_))
            LOG_FATAL("Missing gate info.");
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
        ++bit_index;
      }
    }
  }

  // Update 'circuit' by setting values on the input wires, for inputs coming
  // from self (i.e., from Server).
  const uint64_t num_server_inputs =
      server_input_index_to_server_shares_index_.size();
  for (size_t input_index = 0;
       input_index < circuit_.inputs_as_generic_value_locations_[0].size();
       ++input_index) {
    const vector<set<WireLocation>>& input_to_wires =
        circuit_.inputs_as_generic_value_locations_[0][input_index];
    if (input_index >= num_server_inputs) {
      LOG_FATAL(Itoa(input_index) + ", " + Itoa(num_server_inputs));
    }
    // We may also need the Server's original (non-secret-shared) value.
    const GenericValue& orig_input = input_as_generic_value_[input_index];

    // Find the location within servers_shares_of_servers_input_as_generic_value_
    // where this input is stored.
    const uint64_t& current_input_first_byte_index =
        server_input_index_to_server_shares_index_[input_index];
    const uint64_t current_input_last_byte_index =
        (input_index == num_server_inputs - 1) ?
        servers_shares_of_servers_input_as_generic_value_.size() - 1 :
        server_input_index_to_server_shares_index_[input_index + 1] - 1;
    const size_t num_bits = input_to_wires.size();
    const bool has_remainder_bits = num_bits % CHAR_BIT != 0;
    const size_t input_num_bytes =
        num_bits / CHAR_BIT + (has_remainder_bits ? 1 : 0);
    if (current_input_first_byte_index + input_num_bytes - 1 >
        current_input_last_byte_index) {
      LOG_FATAL(
          Itoa(input_index) + ", " + Itoa(current_input_first_byte_index) +
          ", " + Itoa(num_bits) + ", " + Itoa(current_input_last_byte_index));
    }
    // Loop through servers_shares_of_servers_input_as_generic_value_ backwards,
    // since it will be easier to process bit '0' first, etc.
    uint64_t bit_index = 0;
    for (int64_t byte_index = (int64_t) input_num_bytes - 1; byte_index >= 0;
         --byte_index) {
      // Get the appropriate byte from this input.
      const unsigned char current_input_byte_as_string =
          servers_shares_of_servers_input_as_generic_value_
              [current_input_first_byte_index + byte_index];
      const int num_bits_this_byte = (byte_index == 0 && has_remainder_bits) ?
          num_bits % CHAR_BIT :
          CHAR_BIT;
      for (int j = 0; j < num_bits_this_byte; ++j) {
        const bool input_value = (current_input_byte_as_string >> j) & 1;
        // We may also need the Client's original (non-secret-shared) value;
        // grab that now.
        bool orig_input_value = false;
        if (compute_gates_locally_) {
          const bool orig_input_bit = GetBit(bit_index, orig_input);
          orig_input_value = orig_input_bit;
        }

        // Now loop through all wires that use this input bit, loading those
        // wires with the current input value.
        const set<WireLocation>& wires = input_to_wires[bit_index];
        for (const WireLocation& location : wires) {
          StandardGate<value_t>& current_gate =
              circuit_.levels_[location.loc_.level_]
                  .gates_[location.loc_.index_];
          if (!ContainsKey(0, current_gate.depends_on_))
            LOG_FATAL("Missing gate info.");
          // NOTE: If compute_gates_locally_ is true, we need to load values on wires
          // specially for input wires to gates that are computed locally; see
          // DISCUSSION item (2) regarding locally evaluating gates, at top of gmw_circuit.h.
          const bool input_value_to_use =
              (compute_gates_locally_ && current_gate.IsLocallyComputable() &&
               !ContainsKey(1, current_gate.depends_on_)) ?
              orig_input_value :
              input_value;
          if (location.is_left_) {
            if (current_gate.left_input_set_) {
              LOG_FATAL(
                  "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                  Itoa(location.loc_.index_) +
                  " has had its left wire set "
                  "multiple times.");
            }
            current_gate.left_input_ = input_value_to_use;
            current_gate.left_input_set_ = true;
          } else {
            if (current_gate.right_input_set_) {
              LOG_FATAL(
                  "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                  Itoa(location.loc_.index_) +
                  " has had its right wire set "
                  "multiple times.");
            }
            current_gate.right_input_ = input_value_to_use;
            current_gate.right_input_set_ = true;
          }
        }
        ++bit_index;
      }
    }
  }

  // Update 'circuit' by setting values on the input wires, for constant inputs.
  for (const WireLocation location : circuit_.constant_zero_input_) {
    StandardGate<value_t>& current_gate =
        circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
    if (current_gate.depends_on_.size() >= 1) {
      LOG_FATAL("Missing gate info.");
    }
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
  for (const WireLocation& location : circuit_.constant_one_input_) {
    StandardGate<value_t>& current_gate =
        circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
    if (current_gate.depends_on_.size() >= 1) {
      LOG_FATAL("Missing gate info.");
    }
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
bool GmwServer<value_t>::EvaluateCircuit() {
  // Start timer.
  if (circuit_.timer_level_ >= 0) {
    StartTimer(&circuit_.evaluate_circuit_overall_timer_);
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  // Resize outputs_as_[slice | bits]_ here (if we know ahead of time how many output
  // gates there are) to avoid having to resize() outputs_as_[slice | bits]_ every
  // time a new output gate is encountered.
  if (circuit_.num_output_wires_ > 0) {
    if (is_format_one) {
      circuit_.outputs_as_slice_.resize(circuit_.num_output_wires_);
    } else {
      circuit_.outputs_as_bits_.resize(circuit_.GetNumberOutputBits());
    }
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StartTimer(&circuit_.exchange_inputs_timer_);
  }

  // Get (shares) of Client's input, and send (shares) of its own
  // input_as_[slice | generic_value]_.
  // This will populate servers_shares_of_[servers | clients]_input_as_slice_ or
  // servers_shares_of_[servers | clients]_input_as_generic_value_ (depending
  // on whether inputs were specifed using Format 1 or 2), as well as (for Format
  // 2) the mappings [client | server]_input_index_to_[client | server]_shares_index_.
  if (!ExchangeInputShares()) {
    LOG_ERROR("Failed to EvaluateCircuit(): "
              "Server Failed to ExchangeInputShares with Client.");
    return false;
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.exchange_inputs_timer_);
    StartTimer(&circuit_.load_inputs_timer_);
  }

  // Load (Server and Client) input (shares) onto input wires.
  if (!LoadInputsToCircuit()) {
    LOG_ERROR("Failed to EvaluateCircuit() for GmwServer: Couldn't "
              "load input.");
    return false;
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.load_inputs_timer_);
    StartTimer(&circuit_.evaluate_circuit_only_timer_);
  }

  // Iterate through each Level of the circuit, engaging in the GMW protocol
  // for that level.
  for (size_t level = 0; level < circuit_.levels_.size(); ++level) {
    if (!EvaluateLevel(level)) {
      LOG_ERROR("Unable to EvaluateLevel " + Itoa(level));
      return false;
    }
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.evaluate_circuit_only_timer_);
    StartTimer(&circuit_.exchange_outputs_timer_);
  }

  // Get outputs in the clear (instead of Server's secret share of them).
  if (!ExchangeOutputShares()) {
    LOG_ERROR("Unable to exchange final output shares with Client.");
    return false;
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.exchange_outputs_timer_);
    StartTimer(&circuit_.write_outputs_timer_);
  }

  // Write output shares to file.
  if (!WriteOutputToFile()) {
    LOG_ERROR("Unable to write output to file.");
    return false;
  }

  // Close Connection to Client.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.write_outputs_timer_);
    socket_info_ = socket_->GetSocketStats().Print(
        true, circuit_.timer_level_ > 1, true, circuit_.timer_level_ > 1, true);
    StartTimer(&circuit_.close_connection_timer_);
  }
  socket_->Reset(false);

  // Stop timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.close_connection_timer_);
    StopTimer(&circuit_.evaluate_circuit_overall_timer_);
  }

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::LoadInputsToCircuit() {
  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  if (is_format_one) {
    if (circuit_.inputs_as_slice_locations_.size() != 2) {
      LOG_FATAL("Input not set");
    }
    if (circuit_.inputs_as_slice_locations_[0].empty() &&
        circuit_.inputs_as_slice_locations_[1].empty() &&
        circuit_.constant_slice_input_.empty()) {
      LOG_FATAL("All inputs empty.");
    }
    return LoadFormatOneInputsToCircuit();
  } else {
    if (circuit_.inputs_as_generic_value_locations_.size() != 2) {
      LOG_FATAL("Input not set");
    }
    if (circuit_.inputs_as_generic_value_locations_[0].empty() &&
        circuit_.inputs_as_generic_value_locations_[1].empty() &&
        circuit_.constant_zero_input_.empty() &&
        circuit_.constant_one_input_.empty()) {
      LOG_FATAL("All inputs empty.");
    }
    return LoadFormatTwoInputsToCircuit();
  }
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == slice. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == bool will never be realized.
template<typename value_t>
bool GmwClient<value_t>::LoadFormatOneInputsToCircuit() {
  // Make sure we have an actual input everywhere it is needed
  // (we allow inequality here, to allow for unused inputs of the parties).
  if (circuit_.inputs_as_slice_locations_[0].size() >
          clients_shares_of_servers_input_as_slice_.size() ||
      circuit_.inputs_as_slice_locations_[1].size() >
          clients_shares_of_clients_input_as_slice_.size()) {
    LOG_FATAL("Mismatching inputs to LoadInputsToCircuit().");
  }

  // Update circuit_ by setting values on the input wires, for inputs coming
  // from Server.
  for (size_t i = 0; i < circuit_.inputs_as_slice_locations_[0].size(); ++i) {
    const set<WireLocation>& wires = circuit_.inputs_as_slice_locations_[0][i];
    const slice& input_value = clients_shares_of_servers_input_as_slice_[i];
    for (const WireLocation& location : wires) {
      StandardGate<value_t>& current_gate =
          circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
      if (!ContainsKey(0, current_gate.depends_on_))
        LOG_FATAL("Missing gate info.");
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

  // Update circuit_ by setting values on the input wires, for inputs coming
  // from Client.
  for (size_t i = 0; i < circuit_.inputs_as_slice_locations_[1].size(); ++i) {
    const set<WireLocation>& wires = circuit_.inputs_as_slice_locations_[1][i];
    const slice& input_value = clients_shares_of_clients_input_as_slice_[i];
    for (const WireLocation& location : wires) {
      StandardGate<value_t>& current_gate =
          circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
      if (!ContainsKey(1, current_gate.depends_on_))
        LOG_FATAL("Missing gate info.");
      // NOTE: If compute_gates_locally_ is true, we need to load values on wires
      // specially for input wires to gates that are computed locally; see
      // DISCUSSION item (2) regarding locally evaluating gates, at top of gmw_circuit.h.
      const slice input_value_to_use =
          (compute_gates_locally_ && current_gate.IsLocallyComputable() &&
           !ContainsKey(0, current_gate.depends_on_)) ?
          input_as_slice_[i] :
          input_value;
      if (location.is_left_) {
        if (current_gate.left_input_set_) {
          LOG_FATAL(
              "Gate at level " + Itoa(location.loc_.level_) + " and index " +
              Itoa(location.loc_.index_) +
              " has had its left wire set "
              "multiple times.");
        }
        current_gate.left_input_ = input_value_to_use;
        current_gate.left_input_set_ = true;
      } else {
        if (current_gate.right_input_set_) {
          LOG_FATAL(
              "Gate at level " + Itoa(location.loc_.level_) + " and index " +
              Itoa(location.loc_.index_) +
              " has had its right wire set "
              "multiple times.");
        }
        current_gate.right_input_ = input_value_to_use;
        current_gate.right_input_set_ = true;
      }
    }
  }

  // Update circuit_ by setting values on the input wires, for constant inputs.
  for (const pair<const slice, set<WireLocation>>& value_and_loc :
       circuit_.constant_slice_input_) {
    const set<WireLocation>& wires = value_and_loc.second;
    const slice& input_value = value_and_loc.first;
    for (const WireLocation& location : wires) {
      StandardGate<value_t>& current_gate =
          circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
      if (current_gate.depends_on_.size() >= 1) {
        LOG_FATAL("Missing gate info.");
      }
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

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == bool. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == slice will never be realized.
template<typename value_t>
bool GmwClient<value_t>::LoadFormatTwoInputsToCircuit() {
  // Update 'circuit' by setting values on the input wires, for inputs coming
  // from self (i.e., from Client).
  const uint64_t num_client_inputs =
      client_input_index_to_client_shares_index_.size();
  for (size_t input_index = 0;
       input_index < circuit_.inputs_as_generic_value_locations_[1].size();
       ++input_index) {
    const vector<set<WireLocation>>& input_to_wires =
        circuit_.inputs_as_generic_value_locations_[1][input_index];
    if (input_index >= num_client_inputs) {
      LOG_FATAL(Itoa(input_index) + ", " + Itoa(num_client_inputs));
    }
    // We may also need the Client's original (non-secret-shared) value.
    const GenericValue& orig_input = input_as_generic_value_[input_index];
    // Find the location within clients_shares_of_clients_input_as_generic_value_
    // where this input is stored.
    const uint64_t& current_input_first_byte_index =
        client_input_index_to_client_shares_index_[input_index];
    const uint64_t current_input_last_byte_index =
        (input_index == num_client_inputs - 1) ?
        clients_shares_of_clients_input_as_generic_value_.size() - 1 :
        client_input_index_to_client_shares_index_[input_index + 1] - 1;
    const size_t num_bits = input_to_wires.size();
    const bool has_remainder_bits = num_bits % CHAR_BIT != 0;
    const size_t input_num_bytes =
        num_bits / CHAR_BIT + (has_remainder_bits ? 1 : 0);
    if (current_input_first_byte_index + input_num_bytes - 1 >
        current_input_last_byte_index) {
      LOG_FATAL(
          Itoa(input_index) + ", " + Itoa(current_input_first_byte_index) +
          ", " + Itoa(num_bits) + ", " + Itoa(current_input_last_byte_index));
    }
    // Loop through clients_shares_of_clients_input_as_generic_value_ backwards,
    // since it will be easier to process bit '0' first, etc.
    uint64_t bit_index = 0;
    for (int64_t byte_index = (int64_t) input_num_bytes - 1; byte_index >= 0;
         --byte_index) {
      // Get the appropriate byte from this input.
      const unsigned char current_input_byte_as_string =
          clients_shares_of_clients_input_as_generic_value_
              [current_input_first_byte_index + byte_index];
      const int num_bits_this_byte = (byte_index == 0 && has_remainder_bits) ?
          num_bits % CHAR_BIT :
          CHAR_BIT;
      for (int j = 0; j < num_bits_this_byte; ++j) {
        const bool input_value = (current_input_byte_as_string >> j) & 1;
        // We may also need the Client's original (non-secret-shared) value;
        // grab that now.
        bool orig_input_value = false;
        if (compute_gates_locally_) {
          const bool orig_input_bit = GetBit(bit_index, orig_input);
          orig_input_value = orig_input_bit;
        }

        // Now loop through all wires that use this input bit, loading those
        // wires with the current input value.
        const set<WireLocation>& wires = input_to_wires[bit_index];
        for (const WireLocation& location : wires) {
          StandardGate<value_t>& current_gate =
              circuit_.levels_[location.loc_.level_]
                  .gates_[location.loc_.index_];
          if (!ContainsKey(1, current_gate.depends_on_))
            LOG_FATAL("Missing gate info.");
          // NOTE: If compute_gates_locally_ is true, we need to load values on wires
          // specially for input wires to gates that are computed locally; see
          // DISCUSSION item (2) regarding locally evaluating gates, at top of gmw_circuit.h.
          const bool input_value_to_use =
              (compute_gates_locally_ && current_gate.IsLocallyComputable() &&
               !ContainsKey(0, current_gate.depends_on_)) ?
              orig_input_value :
              input_value;
          if (location.is_left_) {
            if (current_gate.left_input_set_) {
              LOG_FATAL(
                  "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                  Itoa(location.loc_.index_) +
                  " has had its left wire set "
                  "multiple times.");
            }
            current_gate.left_input_ = input_value_to_use;
            current_gate.left_input_set_ = true;
          } else {
            if (current_gate.right_input_set_) {
              LOG_FATAL(
                  "Gate at level " + Itoa(location.loc_.level_) + " and index " +
                  Itoa(location.loc_.index_) +
                  " has had its right wire set "
                  "multiple times.");
            }
            current_gate.right_input_ = input_value_to_use;
            current_gate.right_input_set_ = true;
          }
        }
        ++bit_index;
      }
    }
  }

  // Update 'circuit' by setting values on the input wires, for inputs coming
  // from the other Party (i.e. the Server).
  const uint64_t num_server_inputs =
      server_input_index_to_server_shares_index_.size();
  for (size_t input_index = 0;
       input_index < circuit_.inputs_as_generic_value_locations_[0].size();
       ++input_index) {
    const vector<set<WireLocation>>& input_to_wires =
        circuit_.inputs_as_generic_value_locations_[0][input_index];
    if (input_index >= num_server_inputs) {
      LOG_FATAL(Itoa(input_index) + ", " + Itoa(num_server_inputs));
    }
    // Find the location within clients_shares_of_servers_input_as_generic_value_
    // where this input is stored.
    const uint64_t& current_input_first_byte_index =
        server_input_index_to_server_shares_index_[input_index];
    const uint64_t current_input_last_byte_index =
        (input_index == num_server_inputs - 1) ?
        clients_shares_of_servers_input_as_generic_value_.size() - 1 :
        server_input_index_to_server_shares_index_[input_index + 1] - 1;
    const size_t num_bits = input_to_wires.size();
    const bool has_remainder_bits = num_bits % CHAR_BIT != 0;
    const size_t input_num_bytes =
        num_bits / CHAR_BIT + (has_remainder_bits ? 1 : 0);
    if (current_input_first_byte_index + input_num_bytes - 1 >
        current_input_last_byte_index) {
      LOG_FATAL(
          Itoa(current_input_first_byte_index) + ", " + Itoa(num_bits) + ", " +
          Itoa(current_input_last_byte_index));
    }
    // Loop through clients_shares_of_servers_input_as_generic_value_ backwards,
    // since it will be easier to process bit '0' first, etc.
    uint64_t bit_index = 0;
    for (int64_t byte_index = (int64_t) input_num_bytes - 1; byte_index >= 0;
         --byte_index) {
      // Get the appropriate byte from this input.
      const unsigned char current_input_byte_as_string =
          clients_shares_of_servers_input_as_generic_value_
              [current_input_first_byte_index + byte_index];
      const int num_bits_this_byte = (byte_index == 0 && has_remainder_bits) ?
          num_bits % CHAR_BIT :
          CHAR_BIT;
      for (int j = 0; j < num_bits_this_byte; ++j) {
        const bool input_value = (current_input_byte_as_string >> j) & 1;

        // Now loop through all wires that use this input bit, loading those
        // wires with the current input value.
        const set<WireLocation>& wires = input_to_wires[bit_index];
        for (const WireLocation& location : wires) {
          StandardGate<value_t>& current_gate =
              circuit_.levels_[location.loc_.level_]
                  .gates_[location.loc_.index_];
          if (!ContainsKey(0, current_gate.depends_on_))
            LOG_FATAL("Missing gate info.");
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
        ++bit_index;
      }
    }
  }

  // Update 'circuit' by setting values on the input wires, for constant inputs.
  for (const WireLocation location : circuit_.constant_zero_input_) {
    StandardGate<value_t>& current_gate =
        circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
    if (current_gate.depends_on_.size() >= 1) {
      LOG_FATAL("Missing gate info.");
    }
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

  for (const WireLocation& location : circuit_.constant_one_input_) {
    StandardGate<value_t>& current_gate =
        circuit_.levels_[location.loc_.level_].gates_[location.loc_.index_];
    bool input_value = true;  // Input coming from constant_one_input_.
    if (current_gate.depends_on_.size() >= 1) {
      LOG_FATAL("Missing gate info.");
    } else if (current_gate.depends_on_.empty()) {
      // Per convention, in the special case that this constant input is a global
      // output, the Client should set input to '0' (Server will set input to '1').
      input_value = false;
    }
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

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::EvaluateCircuit() {
  // Start timer.
  if (circuit_.timer_level_ >= 0) {
    StartTimer(&circuit_.evaluate_circuit_overall_timer_);
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  // Resize outputs_as_[slice | bits]_ here (if we know ahead of time how many output
  // gates there are) to avoid having to resize() outputs_as_[slice | bits]_ every
  // time a new output gate is encountered.
  if (circuit_.num_output_wires_ > 0) {
    if (is_format_one) {
      circuit_.outputs_as_slice_.resize(circuit_.num_output_wires_);
    } else {
      circuit_.outputs_as_bits_.resize(circuit_.GetNumberOutputBits());
    }
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StartTimer(&circuit_.exchange_inputs_timer_);
  }

  // Get (shares) of Server's input, and send (shares) of its own
  // input_as_[slice | generic_value]_.
  // This will populate clients_shares_of_[servers | clients]_input_as_slice_ or
  // clients_shares_of_[servers | clients]_input_as_generic_value_ (depending
  // on whether inputs were specifed using Format 1 or 2), as well as (for Format
  // 2) the mappings [client | server]_input_index_to_[client | server]_shares_index_.
  if (!ExchangeInputShares()) {
    LOG_ERROR("Failed to EvaluateCircuit(): "
              "Client Failed to ExchangeInputShares with Server.");
    return false;
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.exchange_inputs_timer_);
    StartTimer(&circuit_.load_inputs_timer_);
  }

  // Load (Server and Client) input (shares) onto input wires.
  if (!LoadInputsToCircuit()) {
    LOG_ERROR("Failed to EvaluateCircuit() for GmwClient: Couldn't "
              "load input.");
    return false;
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.load_inputs_timer_);
    StartTimer(&circuit_.evaluate_circuit_only_timer_);
  }

  // Iterate through each Level of the circuit, engaging in the GMW protocol
  // for that level.
  for (size_t level = 0; level < circuit_.levels_.size(); ++level) {
    if (!EvaluateLevel(level)) {
      LOG_ERROR("Unable to EvaluateLevel " + Itoa(level));
      return false;
    }
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.evaluate_circuit_only_timer_);
    StartTimer(&circuit_.exchange_outputs_timer_);
  }

  // Get outputs in the clear (instead of Server's secret share of them).
  if (!ExchangeOutputShares()) {
    LOG_ERROR("Unable to exchange final output shares with Client.");
    return false;
  }

  // Update timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.exchange_outputs_timer_);
    StartTimer(&circuit_.write_outputs_timer_);
  }

  // Write output shares to file.
  if (!WriteOutputToFile()) {
    LOG_ERROR("Unable to write output to file.");
    return false;
  }

  // Close Connection with Server.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.write_outputs_timer_);
    socket_info_ = socket_->GetSocketStats().Print(
        true, circuit_.timer_level_ > 1, true, circuit_.timer_level_ > 1, true);
    StartTimer(&circuit_.close_connection_timer_);
  }
  if (!socket_->Disconnect()) {
    return false;
  }

  // Stop timers.
  if (circuit_.timer_level_ >= 0) {
    StopTimer(&circuit_.close_connection_timer_);
    StopTimer(&circuit_.evaluate_circuit_overall_timer_);
  }

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::EvaluateLevel(const size_t& level) {
  if (circuit_.timer_level_ >= 1) {
    StartTimer(&circuit_.server_evaluate_level_timer_);
    StartTimer(&circuit_.server_awaiting_selection_bits_timer_);
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  bool no_bytes_received = false;
  // Listen for Client's selection bits.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = socket_->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(uint64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to communicate with Client on level " + Itoa(level) +
          ". Socket Error Message:\n" + socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (socket_->GetReceivedBytes().size() != 1) {
      LOG_FATAL("Unexpected number of Servers");
    }
    socket_->SwapBuffer(0, &received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes = ByteStringToValue<uint64_t>(received_data);
    if (num_second_comm_bytes == 0) {
      no_bytes_received = true;
    } else {
      if (num_second_comm_bytes > INT_MAX) LOG_FATAL("Too many bytes.");
      params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
      socket_->ResetForReceive();
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_second_comm_bytes);
      return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to communicate with Client on level " + Itoa(level) +
            ". Socket Error Message:\n" + socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  } else {
    // Get Client's selection bits (slices) for the truth tables of the gates
    // on this level.
    socket_->SetListenReceiveDataCallback(&ReceiveSelectionBits);
    const set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to communicate with Client on level " + Itoa(level) +
          ". Socket Error Message:\n" + socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.server_awaiting_selection_bits_timer_);
    StartTimer(&circuit_.server_computing_gates_timer_);
  }

  // Use client's selection bits (slices) plus Server's own inputs to
  // generate the truth tables for each gate at the current level;
  // populate obfuscated_truth_tables with the results.
  const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
  vector<ObfuscatedTruthTable<value_t>> server_response;
  if (no_bytes_received) {
    vector<char> tmp_empty(0);
    if (!EvaluateLevel(level, buffer_offset, tmp_empty, &server_response)) {
      LOG_ERROR("Unable to EvaluateLevel() " + Itoa(level));
      return false;
    }
  } else {
    // Store Client's selection bits.
    const map<SocketIdentifier, ReceivedData>& received_data_map =
        socket_->GetReceivedBytes();
    if (received_data_map.size() != 1) LOG_FATAL("Too many connections.");
    const ReceivedData& received_data = received_data_map.begin()->second;
    const size_t num_recd_bytes = received_data.buffer_.empty() ?
        received_data.num_received_bytes_ :
        received_data.buffer_.size();

    if (num_recd_bytes < buffer_offset) {
      LOG_ERROR("Unable to EvaluateLevel() " + Itoa(level));
      return false;
    }
    if (!EvaluateLevel(
            level, buffer_offset, received_data.buffer_, &server_response)) {
      LOG_ERROR("Unable to EvaluateLevel() " + Itoa(level));
      return false;
    }
  }

  socket_->ResetForReceive();

  // Construct a data structure to hold the ObfuscatedTruthTables.
  vector<unsigned char> packed_obfuscated_truth_tables;
  if (is_format_one) {
    // NOTE: There are two options here:
    //   1) Call SendData() repeatedly (4 times per gate)
    //   2) Merge all truth tables into a single storage container, and send that
    // (1) is cleaner in terms of code, and avoids creating the temporary
    // storage container (which takes time to create, as well as requiring
    // additional RAM to store in memory); but, it may add latency due to
    // multiple calls (4 * num gates) to SendData, rather than a single one.
    // Since RAM is unlikely to be an issue, and since the extra time due
    // to multiple calls to SendData() likely outweighs the extra time due
    // to creating the single storage container, we opt for (2).
    if (!PackFormatOneObfuscatedTruthTable(
            server_response, &packed_obfuscated_truth_tables)) {
      return false;
    }
  } else {
    if (!PackFormatTwoObfuscatedTruthTable(
            server_response, &packed_obfuscated_truth_tables)) {
      return false;
    }
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.server_computing_gates_timer_);
    StartTimer(&circuit_.server_sending_server_mask_timer_);
  }

  // Send obfuscated truth tables of each gate back to Client.
  const uint64_t num_bytes = packed_obfuscated_truth_tables.size();
  // Should only be one socket, use it.
  vector<unsigned char> to_send;
  if (!ValueToByteString<uint64_t>(num_bytes, &to_send)) {
    LOG_ERROR(
        "Failed to send the number of gates in the Server's response "
        "for level " +
        Itoa(level));
    return false;
  }
  if (!socket_->SendDataNoFlush(to_send.data(), to_send.size())) {
    LOG_ERROR(
        "Failed to send the number of gates in the Server's response "
        "for level " +
        Itoa(level));
    return false;
  }
  if (SendReturnCode::SUCCESS !=
      socket_->SendData(packed_obfuscated_truth_tables.data(), num_bytes)) {
    LOG_ERROR("Failed to send Server's response for level " + Itoa(level));
    return false;
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.server_sending_server_mask_timer_);
    StartTimer(&circuit_.server_updating_output_wires_timer_);
  }

  // Go through each gate in this level, writing the values on each
  // gate's output wire to all the input wires in output_wire_locations_.
  if (!SetInputsForNextLevel(level)) {
    return false;
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.server_updating_output_wires_timer_);
    StopTimer(&circuit_.server_evaluate_level_timer_);
  }

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::EvaluateLevel(
    const size_t& level,
    const uint64_t& buffer_offset,
    const vector<char>& received_selection_bits,
    vector<ObfuscatedTruthTable<value_t>>* server_response) {
  if (circuit_.levels_.size() <= level) LOG_FATAL("Level index too high.");

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  vector<pair<slice, slice>> format_one_client_selection_slices;
  vector<pair<unsigned char, unsigned char>> format_two_client_selection_bits;
  if (is_format_one) {
    // Skip over the first sizeof(uint64_t) bytes that were received
    // (these were only included to signal when to stop listening).
    format_one_client_selection_slices =
        CharVectorToSlicePairVector(buffer_offset, received_selection_bits);
  } else {
    if (!UnpackFormatTwoSelectionBits<value_t>(
            buffer_offset,
            received_selection_bits,
            &format_two_client_selection_bits)) {
      return false;
    }
  }

  vector<StandardGate<value_t>>& server_gates = circuit_.levels_[level].gates_;

  // Go through all gates at this level, evaluating the gate, which means:
  //   1) For locally-computable gates, just compute them, and set the
  //      value on output_value_ (this value will later be loaded onto
  //      all the output wires, when SetInputsForNextLevel() is called)
  //   2) For GMW gates, Create the ObfuscatedTruthTable for the gate (the
  //      output_value_ on the gate was set at the outset, as just a random
  //      value, and the ObfuscatedTruthTable uses this to encode the actual
  //      output), and use client's selection slices to populate server_response
  const size_t num_gmw_gates = is_format_one ?
      format_one_client_selection_slices.size() :
      format_two_client_selection_bits.size();
  server_response->resize(num_gmw_gates, ObfuscatedTruthTable<value_t>());
  size_t gmw_gate_index = 0;
  for (StandardGate<value_t>& current_gate : server_gates) {
    if (compute_gates_locally_ && current_gate.IsLocallyComputable()) {
      if (ContainsKey(1, current_gate.depends_on_) &&
          !ContainsKey(0, current_gate.depends_on_)) {
        // Gate depends only on Client (Party 1). Use convention C0.
        current_gate.output_value_ = (value_t) 0;
      } else {
        // *Not* in case C0 where input depends only on Client. Since this is
        // Server's code, all other cases (C0 w/ input depending on Server,
        // and C1-C5) all dictate Server should evaluate this gate locally.
        if (!IsInputWiresSet(
                current_gate.left_input_set_,
                current_gate.right_input_set_,
                current_gate.type_)) {
          LOG_FATAL(
              "Unable to evaluate gate at level " + Itoa(level) + " and index " +
              Itoa(current_gate.loc_.index_) +
              ", as its input wires have not been set.");
        }
        if (!crypto::multiparty_computation::EvaluateGate(&current_gate)) {
          return false;
        }
      }
    } else {
      // This is a GMW gate.
      if (gmw_gate_index >= num_gmw_gates) LOG_FATAL("Too many gates.");
      if (is_format_one) {
        // Get the Client's masked selection bits for this gate.
        const pair<slice, slice>& clients_inputs =
            format_one_client_selection_slices[gmw_gate_index];

        if (!EvaluateFormatOneGate(
                clients_inputs,
                &current_gate,
                &((*server_response)[gmw_gate_index]))) {
          LOG_ERROR(
              "Unable to EvaluateLevel() at gate " +
              Itoa(current_gate.loc_.index_));
          return false;
        }
      } else {
        // Get the Client's masked selection bits for this gate.
        const pair<unsigned char, unsigned char>& clients_inputs =
            format_two_client_selection_bits[gmw_gate_index];

        if (!EvaluateFormatTwoGate(
                clients_inputs,
                &current_gate,
                &((*server_response)[gmw_gate_index]))) {
          LOG_ERROR(
              "Unable to EvaluateLevel() at gate " +
              Itoa(current_gate.loc_.index_));
          return false;
        }
      }
      ++gmw_gate_index;
    }
  }

  // Sanity check all gmw outputs were used.
  if (gmw_gate_index != num_gmw_gates) {
    // Since selection bits are packed into bytes, if the number of selection bits
    // is not divisible by CHAR_BIT, then it's possible the last bits were junk.
    // This is fine, just ignore them.
    if (is_format_one || (gmw_gate_index * 2) % CHAR_BIT == 0 ||
        (gmw_gate_index +
         ((CHAR_BIT - ((gmw_gate_index * 2) % CHAR_BIT)) / 2)) !=
            num_gmw_gates) {
      LOG_FATAL(
          "Unexpected number of gates: " + Itoa(is_format_one) + ", " +
          Itoa(gmw_gate_index) + ", " + Itoa(num_gmw_gates));
    } else {
      server_response->resize(gmw_gate_index);
    }
  }

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::EvaluateLevel(const size_t& level) {
  if (circuit_.timer_level_ >= 1) {
    StartTimer(&circuit_.client_evaluate_level_timer_);
    StartTimer(&circuit_.client_preparing_selection_bits_timer_);
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  // Prepare the selection bits (slices) to use for the 1-4 OT of the
  // truth table for each gate on this level.
  vector<unsigned char> packed_selection_bits;
  if (!GenerateSelectionSlices(level, &packed_selection_bits)) {
    LOG_ERROR(
        "Unable to generate Client's selection (slices) for level " +
        Itoa(level));
    return false;
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.client_preparing_selection_bits_timer_);
    StartTimer(&circuit_.client_sending_selection_bits_timer_);
  }

  // Send selection bits/slices to Server.
  const uint64_t num_bytes = packed_selection_bits.size();
  vector<unsigned char> to_send;
  if (!ValueToByteString<uint64_t>(num_bytes, &to_send)) {
    LOG_ERROR(
        "Failed to send number of selection (slices) to Server for "
        "level " +
        Itoa(level));
    return false;
  }
  if (!socket_->SendDataNoFlush(to_send.data(), to_send.size())) {
    LOG_ERROR(
        "Failed to send number of selection (slices) to Server for "
        "level " +
        Itoa(level));
    return false;
  }
  if (SendReturnCode::SUCCESS !=
      socket_->SendData(packed_selection_bits.data(), num_bytes)) {
    LOG_ERROR(
        "Failed to send selection bit (slices) "
        "to Server for level " +
        Itoa(level));
    return false;
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.client_sending_selection_bits_timer_);
    StartTimer(&circuit_.client_awaiting_server_mask_timer_);
  }

  const bool is_cookie_socket = socket_->GetSocketType() == SocketType::COOKIE;
  bool no_bytes_received = false;
  // Listen for Server's returned secrets.
  if (is_cookie_socket) {
    // First, learn the number of secrets and the secret size.
    ListenParams params = socket_->GetListenParams();
    uint64_t num_first_comm_bytes = sizeof(uint64_t);
    params.receive_buffer_max_size_ = (int) num_first_comm_bytes;
    socket_->SetListenParams(params);
    socket_->SetListenReceiveDataCallback(
        &ReceiveNumBytes, &num_first_comm_bytes);
    set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to communicate with Server on level " + Itoa(level) +
          ". Socket Error Message:\n" + socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
    vector<char> received_data;
    if (socket_->GetReceivedBytes().size() != 1) {
      LOG_FATAL("Unexpected number of Servers");
    }
    socket_->SwapBuffer(0, &received_data);

    // Now, listen for all of the secrets.
    uint64_t num_second_comm_bytes = ByteStringToValue<uint64_t>(received_data);
    if (num_second_comm_bytes == 0) {
      no_bytes_received = true;
    } else {
      if (num_second_comm_bytes > INT_MAX) LOG_FATAL("Too many bytes.");
      params.receive_buffer_max_size_ = (int) num_second_comm_bytes;
      socket_->ResetForReceive();
      socket_->SetListenParams(params);
      socket_->SetListenReceiveDataCallback(
          &ReceiveNumBytes, &num_second_comm_bytes);
      return_codes = socket_->Listen();
      if (return_codes.size() != 1 ||
          *(return_codes.begin()) != ListenReturnCode::OK) {
        LOG_ERROR(
            "Failed to communicate with Server on level " + Itoa(level) +
            ". Socket Error Message:\n" + socket_->GetErrorMessage() + "\n" +
            GetBadListenReturnCodeMessage(return_codes));
        return false;
      }
    }
  } else {
    // Listen for Server's response (obfuscated truth tables for each gate).
    socket_->SetListenReceiveDataCallback(&ReceiveObfuscatedTruthTable);
    const set<ListenReturnCode> return_codes = socket_->Listen();
    if (return_codes.size() != 1 ||
        *(return_codes.begin()) != ListenReturnCode::OK) {
      LOG_ERROR(
          "Failed to communicate with Server on level " + Itoa(level) +
          ". Socket Error Message:\n" + socket_->GetErrorMessage() + "\n" +
          GetBadListenReturnCodeMessage(return_codes));
      return false;
    }
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.client_awaiting_server_mask_timer_);
    StartTimer(&circuit_.client_computing_gates_timer_);
  }

  // Retrieve the appropriate entry from each obfuscated truth table, and
  // store value in appropriate wire.
  vector<ObfuscatedTruthTable<slice>> format_one_server_response;
  vector<ObfuscatedTruthTable<bool>> format_two_server_response;
  if (!no_bytes_received) {
    const map<SocketIdentifier, ReceivedData>& received_data_map =
        socket_->GetReceivedBytes();
    if (received_data_map.size() != 1) LOG_FATAL("Too many connections.");
    const ReceivedData& received_data = received_data_map.begin()->second;

    const uint64_t buffer_offset = is_cookie_socket ? 0 : sizeof(uint64_t);
    if (is_format_one) {
      // Skip over the first sizeof(uint64_t) bytes that were received
      // (these were only included to signal when to stop listening).
      format_one_server_response =
          CharVectorToPairSlicePairVector(buffer_offset, received_data.buffer_);
    } else {
      if (!UnpackFormatTwoObfuscatedTruthTable(
              received_data.buffer_,
              is_cookie_socket,
              &format_two_server_response)) {
        return false;
      }
    }
  }
  socket_->ResetForReceive();

  // Select the appropriate entry from each obfuscated truth table, and
  // perform the relevant XOR to obtain the Client's output shares for
  // each gate on this level.
  vector<slice> format_one_output_shares;
  vector<unsigned char> format_two_output_shares;
  if (is_format_one) {
    if (!format_one_server_response.empty() &&
        !GetFormatOneOutputWireSharesFromTruthTables(
            level, format_one_server_response, &format_one_output_shares)) {
      LOG_ERROR("Unable to parse server response for level " + Itoa(level));
      return false;
    }
  } else {
    if (!format_two_server_response.empty() &&
        !GetFormatTwoOutputWireSharesFromTruthTables(
            level, format_two_server_response, &format_two_output_shares)) {
      LOG_ERROR("Unable to parse server response for level " + Itoa(level));
      return false;
    }
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.client_computing_gates_timer_);
    StartTimer(&circuit_.client_updating_output_wires_timer_);
  }

  // Update circuit_: both the output_value_ of the appropriate gate, as
  // well as the values on each of the input wires that this gate outputs to
  // (in the gate's output_wire_locations_).
  if (!LoadOutputWireShares(
          level, format_one_output_shares, format_two_output_shares)) {
    LOG_ERROR("Unable to load output shares for level " + Itoa(level));
    return false;
  }

  if (circuit_.timer_level_ >= 1) {
    StopTimer(&circuit_.client_updating_output_wires_timer_);
    StopTimer(&circuit_.client_evaluate_level_timer_);
  }

  return true;
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == slice. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == bool will never be realized.
template<typename value_t>
bool GmwServer<value_t>::EvaluateFormatOneGate(
    const pair<slice, slice>& client_selection_slices,
    StandardGate<value_t>* server_gate,
    ObfuscatedTruthTable<value_t>* obfuscated_truth_table) {
  // Make sure gate's input wires have been set.
  if (!IsInputWiresSet(
          server_gate->left_input_set_,
          server_gate->right_input_set_,
          server_gate->type_)) {
    LOG_ERROR(
        "Unable to EvaluateGate() at level " + Itoa(server_gate->loc_.level_) +
        " and index " + Itoa(server_gate->loc_.index_) +
        ": Input wire values not set.");
    return false;
  }

  // Get truth table for the gate (given server's shares of the left/right
  // input wires).
  StandardGate<slice> all_possible_inputs;
  all_possible_inputs.type_ = server_gate->type_;
  all_possible_inputs.left_input_set_ = true;
  // 1-in-1-out gates (NOT and IDENTITY) only expect one input wire to be set.
  all_possible_inputs.right_input_set_ =
      (server_gate->type_ == BooleanOperation::NOT ||
       server_gate->type_ == BooleanOperation::IDENTITY) ?
      false :
      true;
  ObfuscatedTruthTable<slice> truth_table;
  for (int left_wire = 0; left_wire < 2; ++left_wire) {
    all_possible_inputs.left_input_ = (slice) server_gate->left_input_ ^
        (left_wire == 0 ? (slice) 0 : ~((slice) 0));
    for (int right_wire = 0; right_wire < 2; ++right_wire) {
      all_possible_inputs.right_input_ = (slice) server_gate->right_input_ ^
          (right_wire == 0 ? (slice) 0 : ~((slice) 0));
      if (!crypto::multiparty_computation::EvaluateGate(&all_possible_inputs)) {
        LOG_FATAL("Unable to Evaluate Gate.");
      }
      // Set appropriate entry of the 2x2 truth table.
      slice* entry_to_set = (left_wire == 0 && right_wire == 0) ?
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
      *entry_to_set = all_possible_inputs.output_value_;
    }
  }

  const TruthTableMask<slice>& gate_mask = server_gate->mask_;
  const slice& servers_share = server_gate->output_value_;
  // Mask the truth table with server's pregenerated random bits (slices),
  // in a manner determined by client's provided selection bits (slices).
  // See formulas in Discussion item (4) at top of the .h file.
  obfuscated_truth_table->first.first = servers_share ^ truth_table.first.first ^
      (~(client_selection_slices.first) & gate_mask.first.first) ^
      (client_selection_slices.first & gate_mask.first.second) ^
      (~(client_selection_slices.second) & gate_mask.second.first) ^
      (client_selection_slices.second & gate_mask.second.second);
  obfuscated_truth_table->first.second = servers_share ^
      truth_table.first.second ^
      (~(client_selection_slices.first) & gate_mask.first.first) ^
      (client_selection_slices.first & gate_mask.first.second) ^
      (client_selection_slices.second & gate_mask.second.first) ^
      (~(client_selection_slices.second) & gate_mask.second.second);
  obfuscated_truth_table->second.first = servers_share ^
      truth_table.second.first ^
      (client_selection_slices.first & gate_mask.first.first) ^
      (~(client_selection_slices.first) & gate_mask.first.second) ^
      (~(client_selection_slices.second) & gate_mask.second.first) ^
      (client_selection_slices.second & gate_mask.second.second);
  obfuscated_truth_table->second.second = servers_share ^
      truth_table.second.second ^
      (client_selection_slices.first & gate_mask.first.first) ^
      (~(client_selection_slices.first) & gate_mask.first.second) ^
      (client_selection_slices.second & gate_mask.second.first) ^
      (~(client_selection_slices.second) & gate_mask.second.second);

  return true;
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == bool. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == slice will never be realized.
template<typename value_t>
bool GmwServer<value_t>::EvaluateFormatTwoGate(
    const pair<unsigned char, unsigned char>& client_selection_bits,
    StandardGate<value_t>* server_gate,
    ObfuscatedTruthTable<value_t>* obfuscated_truth_table) {
  // Make sure gate's input wires have been set.
  if (!IsInputWiresSet(
          server_gate->left_input_set_,
          server_gate->right_input_set_,
          server_gate->type_)) {
    LOG_ERROR(
        "Unable to EvaluateGate() at level " + Itoa(server_gate->loc_.level_) +
        " and index " + Itoa(server_gate->loc_.index_) +
        ": Input wire values not set.");
    return false;
  }

  // Get truth table for the gate (given server's shares of the left/right
  // input wires).
  StandardGate<bool> all_possible_inputs;
  all_possible_inputs.type_ = server_gate->type_;
  all_possible_inputs.left_input_set_ = true;
  // 1-in-1-out gates (NOT and IDENTITY) only expect one input wire to be set.
  all_possible_inputs.right_input_set_ =
      (server_gate->type_ == BooleanOperation::NOT ||
       server_gate->type_ == BooleanOperation::IDENTITY) ?
      false :
      true;
  TruthTableMask<bool> truth_table;
  for (int left_wire = 0; left_wire < 2; ++left_wire) {
    all_possible_inputs.left_input_ =
        server_gate->left_input_ != (left_wire == 0 ? false : true);
    for (int right_wire = 0; right_wire < 2; ++right_wire) {
      all_possible_inputs.right_input_ =
          server_gate->right_input_ != (right_wire == 0 ? false : true);
      if (!crypto::multiparty_computation::EvaluateGate(&all_possible_inputs)) {
        LOG_FATAL("Unable to Evaluate Gate.");
      }
      // Set appropriate entry of the 2x2 truth table.
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
      *entry_to_set = all_possible_inputs.output_value_;
    }
  }

  ConstructObfuscatedTruthTable(
      client_selection_bits.first,
      client_selection_bits.second,
      server_gate->output_value_,
      server_gate->mask_,
      truth_table,
      (ObfuscatedTruthTable<bool>*) obfuscated_truth_table);

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::LoadOutputWire(
    const bool is_format_one,
    const value_t& value,
    StandardGate<value_t>* gate) {
  gate->output_value_ = value;

  // Set the input wire values for all gates for which this gate's output wire
  // leads to.
  for (const WireLocation& input_wire_location : gate->output_wire_locations_) {
    const bool is_left_input = input_wire_location.is_left_;
    const int64_t to_level = input_wire_location.loc_.level_;
    const int64_t to_index = input_wire_location.loc_.index_;

    // A negative level for the output wire either indicates that
    // this is a global output wire (in which case the location index
    // should be non-negative) or that the output wire location was
    // not set (an error).
    if (to_level < 0) {
      if (to_index < 0) {
        LOG_ERROR(
            "Unable to LoadOutputWire(): Gate " + Itoa(gate->loc_.index_) +
            " on level " + Itoa(gate->loc_.level_) +
            " has not set the location of its output_wire_.");
        return false;
      }
      // This is a global output wire. Resize circuit->outputs_as_[slice | bits]_ if necessary.
      if (is_format_one &&
          (int64_t) circuit_.outputs_as_slice_.size() <= to_index) {
        circuit_.outputs_as_slice_.resize(to_index + 1);
      } else if (
          !is_format_one &&
          (int64_t) circuit_.outputs_as_bits_.size() <= to_index) {
        circuit_.outputs_as_bits_.resize(to_index + 1);
      }
      if (is_format_one) {
        circuit_.outputs_as_slice_[to_index] = value;
      } else {
        circuit_.outputs_as_bits_[to_index] = (unsigned char) value;
      }
    } else {
      // This is an internal wire. Copy the output value to the appropriate
      // input wire.
      if (!circuit_.IsValidGateLocation(input_wire_location.loc_)) {
        LOG_FATAL(
            "Gate at level " + Itoa(gate->loc_.level_) + " and index " +
            Itoa(gate->loc_.index_) + " specifies its output gate as level " +
            Itoa(to_level) + " and index " + Itoa(to_index) +
            ", which does not exist.");
      }
      StandardGate<value_t>& target_gate =
          circuit_.levels_[to_level].gates_[to_index];
      if (is_left_input) {
        if (target_gate.left_input_set_) {
          LOG_FATAL(
              "Attempting to set left input wire at level " + Itoa(to_level) +
              " and level " + Itoa(to_index) + ", which has already been set.");
        }
        target_gate.left_input_ = value;
        target_gate.left_input_set_ = true;
      } else {
        if (target_gate.right_input_set_) {
          LOG_FATAL(
              "Attempting to set right input wire at level " + Itoa(to_level) +
              " and level " + Itoa(to_index) + ", which has already been set.");
        }
        target_gate.right_input_ = value;
        target_gate.right_input_set_ = true;
      }
    }
  }

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::GenerateSelectionSlices(
    const size_t& level_index, vector<unsigned char>* packed_selection_bits) {
  if (circuit_.levels_.size() <= level_index) {
    LOG_FATAL("Bad input to GenerateSelectionSlices.");
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  packed_selection_bits->clear();

  const StandardCircuitLevel<value_t>& level = circuit_.levels_[level_index];
  const size_t& num_gates = level.gates_.size();

  int num_free_bits = 0;
  for (size_t i = 0; i < num_gates; ++i) {
    const StandardGate<value_t>& current_gate = level.gates_[i];
    const bool is_local_gate =
        compute_gates_locally_ && current_gate.IsLocallyComputable();
    const SelectionBitAndValuePair<value_t>* selection_bits =
        FindOrNull(GateLocation(level_index, i), ot_bits_);
    // There are no selection bits for this gate. This may be fine (if
    // gate can be computed locally by Client).
    if (selection_bits == nullptr) {
      if (!is_local_gate) {
        LOG_ERROR(
            "Unable to find precomputed selection bits for gate " + Itoa(i) +
            " on level " + Itoa(level_index));
        return false;
      }
      continue;
    } else if (is_local_gate) {
      DLOG_ERROR(
          "Unexpected selection bits found for local gate: " + Itoa(i) +
          " on level " + Itoa(level_index));
      return false;
    }

    // The first part of each pair is the Client's (secret) selection bits
    // b for this gate, the second is the Server's (random) secrets s_b.
    // As per GMW+Beaver protocol, Client sends Server: b + r (and from the
    // second pair, (c + s)), where r (resp. s) represents the Client's
    // value (share) of the left (resp. right) input wire to this gate.
    if (is_format_one) {
      uint64_t current_size = packed_selection_bits->size();
      packed_selection_bits->resize(current_size + 2 * sizeof(slice));
      slice* insert_first_slice =
          (slice*) ((packed_selection_bits->data()) + current_size);
      *insert_first_slice =
          selection_bits->first.first ^ current_gate.left_input_;
      slice* insert_second_slice =
          (slice*) ((packed_selection_bits->data()) + current_size + sizeof(slice));
      *insert_second_slice =
          selection_bits->second.first ^ current_gate.right_input_;
    } else {
      if (num_free_bits == 0) {
        packed_selection_bits->push_back((unsigned char) 0);
        num_free_bits = CHAR_BIT;
      }
      unsigned char& current_selection_byte = packed_selection_bits->back();
      if (selection_bits->first.first != current_gate.left_input_) {
        current_selection_byte =
            current_selection_byte | (unsigned char) (1 << (num_free_bits - 1));
      }
      --num_free_bits;
      if (selection_bits->second.first != current_gate.right_input_) {
        current_selection_byte =
            current_selection_byte | (unsigned char) (1 << (num_free_bits - 1));
      }
      --num_free_bits;
    }
  }

  return true;
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == slice. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == bool will never be realized.
template<typename value_t>
bool GmwClient<value_t>::GetFormatOneOutputWireSharesFromTruthTables(
    const size_t& level_index,
    const vector<ObfuscatedTruthTable<slice>>& server_response,
    vector<slice>* output_shares) {
  if (circuit_.levels_.size() <= level_index) {
    LOG_FATAL("Bad input to GetF1OutputWireSharesFromTruthTables.");
  }

  output_shares->clear();
  const StandardCircuitLevel<value_t>& level = circuit_.levels_[level_index];
  const size_t& num_gates = level.gates_.size();
  if (server_response.size() > num_gates) {
    LOG_FATAL("Bad input to GetF1OutputWireSharesFromTruthTables.");
  }

  int64_t gate_index = -1;
  for (const ObfuscatedTruthTable<slice>& tt : server_response) {
    SelectionBitAndValuePair<value_t>* selection_bits = nullptr;
    do {
      ++gate_index;
      selection_bits =
          FindOrNull(GateLocation(level_index, gate_index), ot_bits_);
    } while (gate_index < (int64_t) num_gates && selection_bits == nullptr);

    if (gate_index >= (int64_t) num_gates || selection_bits == nullptr) {
      LOG_FATAL("Not enough gates to evaluate in "
                "GetF1OutputWireSharesFromTruthTables()");
    }

    // Get the gate (has the server's input values, and the gate type).
    const StandardGate<value_t>& current_gate = level.gates_[gate_index];

    // Read the appropriate entry of the truth table, and de-obfuscate using
    // the Client's knowledge of the Server's (random) secrets.
    const slice& first_secret = selection_bits->first.second;
    const slice& second_secret = selection_bits->second.second;
    const slice& left_wire = current_gate.left_input_;
    const slice& right_wire = current_gate.right_input_;
    // See formula in part (4) of Discussion in .h file.
    output_shares->push_back(
        first_secret ^ second_secret ^
        (tt.first.first & ~(left_wire) & ~(right_wire)) ^
        (tt.first.second & ~(left_wire) & (right_wire)) ^
        (tt.second.first & (left_wire) & ~(right_wire)) ^
        (tt.second.second & (left_wire) & (right_wire)));
  }

  return true;
}

// NOTE: Even though this function is templated, in reality it will only
// ever be called with value_t == bool. However, we are forced to use a
// function template becuase code will not compile otherwise, since it doesn't
// know that instantiations where value_t == slice will never be realized.
template<typename value_t>
bool GmwClient<value_t>::GetFormatTwoOutputWireSharesFromTruthTables(
    const size_t& level_index,
    const vector<ObfuscatedTruthTable<bool>>& server_response,
    vector<unsigned char>* output_shares) {
  if (circuit_.levels_.size() <= level_index) {
    LOG_FATAL("Bad input to GetF2OutputWireSharesFromTruthTables.");
  }

  output_shares->clear();
  const StandardCircuitLevel<value_t>& level = circuit_.levels_[level_index];
  const size_t& num_gates = level.gates_.size();
  // We allow server_response to be 1 too big, because we packed truth tables
  // into bytes, and since two fit in a byte, we may have one extra one if
  // num_gates is odd.
  const int num_tt_per_byte = CHAR_BIT / 4;
  if (server_response.size() > num_gates +
          (num_gates % num_tt_per_byte == 0 ?
               0 :
               num_tt_per_byte - num_gates % num_tt_per_byte)) {
    LOG_FATAL("Bad input to GetF2OutputWireSharesFromTruthTables.");
  }

  int64_t gate_index = -1;
  for (uint64_t i = 0; i < server_response.size(); ++i) {
    const ObfuscatedTruthTable<bool>& tt_i = server_response[i];
    SelectionBitAndValuePair<value_t>* selection_bits = nullptr;
    do {
      ++gate_index;
      selection_bits =
          FindOrNull(GateLocation(level_index, gate_index), ot_bits_);
    } while (gate_index < (int64_t) num_gates && selection_bits == nullptr);

    // This truth table is not needed. Make sure that the only reason it
    // exists is due to the way Truth Tables get packed into bytes
    // (otherwise, it's an error that too many truth table bits were sent).
    if (gate_index == (int64_t) num_gates) {
      if (i % num_tt_per_byte == 0 ||
          i + (num_tt_per_byte - (i % num_tt_per_byte)) !=
              server_response.size()) {
        LOG_FATAL("Not enough gates to evaluate in "
                  "GetF2OutputWireSharesFromTruthTables()");
      }
      break;
    }

    // Get the gate (has the server's input values, and the gate type).
    const StandardGate<value_t>& current_gate = level.gates_[gate_index];

    // Deobfuscate the relevant entry of the obfuscated truth table.
    const bool output_value_i = SelectValueFromObfuscatedTruthTable(
        selection_bits->first.second,
        selection_bits->second.second,
        current_gate.left_input_,
        current_gate.right_input_,
        tt_i);

    output_shares->push_back(output_value_i);
  }

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::LoadOutputWireShares(
    const size_t& level_index,
    const vector<slice>& outputs_as_slice,
    const vector<unsigned char>& outputs_as_bits) {
  if (level_index >= circuit_.levels_.size()) {
    LOG_FATAL("Bad input to LoadOutputWireShares.");
  }

  const bool is_format_one = circuit_.format_ == CircuitFormat::UNKNOWN ?
      circuit_.IsCircuitFormatOne() :
      circuit_.format_ == CircuitFormat::FORMAT_ONE;

  const size_t num_gmw_outputs =
      is_format_one ? outputs_as_slice.size() : outputs_as_bits.size();

  StandardCircuitLevel<value_t>& level = circuit_.levels_[level_index];
  if (num_gmw_outputs > level.gates_.size()) {
    LOG_FATAL("Bad input to LoadOutputWireShares.");
  }

  // Go through all gates at this level, setting the value on its output
  // wire, in one of two ways:
  //   1) Based on outputs[i], for the appropriate 'i'
  //   2) Based on local computation of the gate output, if possible.
  size_t gmw_output_index = 0;
  for (StandardGate<value_t>& current_gate : level.gates_) {
    if (compute_gates_locally_ && current_gate.IsLocallyComputable()) {
      // See DISCUSSION item (2) regarding locally evaluating gates, at top of gmw_circuit.h.
      // regarding our convention for how locally computable gates are handled.
      if (ContainsKey(0, current_gate.depends_on_) &&
          !ContainsKey(1, current_gate.depends_on_)) {
        // Gate depends only on Server (Party 0). Use convention C0.
        current_gate.output_value_ = (value_t) 0;
      } else if (
          current_gate.depends_on_.size() == 2 &&
          current_gate.type_ == BooleanOperation::NOT) {
        // Gate is NOT. Apply Convention C2.
        if (current_gate.left_input_set_ == current_gate.right_input_set_) {
          LOG_FATAL("1-input gate must have one input set.");
        }
        current_gate.output_value_ = current_gate.left_input_set_ ?
            current_gate.left_input_ :
            current_gate.right_input_;
      } else if (
          current_gate.depends_on_.size() == 2 &&
          current_gate.type_ == BooleanOperation::EQ) {
        // Gate is EQ. Apply Convention C3.
        if (!current_gate.left_input_set_ || !current_gate.right_input_set_) {
          LOG_FATAL("2-input gate must have both inputs set.");
        }
        current_gate.output_value_ =
            current_gate.left_input_ ^ current_gate.right_input_;
      } else {
        // In case C0 (depends on Client) or C1 (C4 and C5 not supported here),
        // so Client should evaluate this gate locally.
        // First, make sure input wire values are set.
        const bool is_single_input_gate =
            current_gate.type_ == BooleanOperation::IDENTITY ||
            current_gate.type_ == BooleanOperation::NOT;
        if ((is_single_input_gate &&
             (current_gate.left_input_set_ == current_gate.right_input_set_)) ||
            (!is_single_input_gate &&
             (!current_gate.left_input_set_ ||
              !current_gate.right_input_set_))) {
          LOG_FATAL(
              "Unable to evaluate gate at level " + Itoa(level_index) +
              " and index " + Itoa(current_gate.loc_.index_) +
              ", as its input wires have not been set: (" +
              Itoa(current_gate.left_input_set_) + ", " +
              Itoa(current_gate.left_input_set_) + ")");
        }
        if (!crypto::multiparty_computation::EvaluateGate(&current_gate)) {
          return false;
        }
      }
      if (!LoadOutputWire(
              is_format_one, current_gate.output_value_, &current_gate)) {
        return false;
      }
    } else {
      if (gmw_output_index >= num_gmw_outputs) {
        LOG_FATAL(
            "Bad number of gates on level " + Itoa(level_index) + ": " +
            Itoa(gmw_output_index) + " vs. " + Itoa(num_gmw_outputs));
      }
      if (is_format_one) {
        if (!LoadOutputWire(
                is_format_one,
                (value_t) outputs_as_slice[gmw_output_index],
                &current_gate)) {
          return false;
        }
      } else {
        if (!LoadOutputWire(
                is_format_one,
                (value_t) outputs_as_bits[gmw_output_index] == (unsigned char) 1,
                &current_gate)) {
          return false;
        }
      }
      ++gmw_output_index;
    }
  }

  // Sanity check all gmw outputs were used.
  if (gmw_output_index != num_gmw_outputs) LOG_FATAL("Bad number of gates.");

  return true;
}

template<typename value_t>
bool GmwServer<value_t>::WriteOutputToFile() {
  if (output_filename_.empty()) {
    return true;
  }

  if (!CreateDir(GetDirectory(output_filename_))) {
    LOG_ERROR("Unable to open output file '" + output_filename_ + "'");
    return false;
  }
  ofstream output_file;
  output_file.open(output_filename_);
  if (!output_file.is_open()) {
    LOG_ERROR("Unable to open output file '" + output_filename_ + "'");
    return false;
  }

  if (!circuit_.outputs_as_generic_value_.empty()) {
    for (const GenericValue& output_value : circuit_.outputs_as_generic_value_) {
      output_file << GetGenericValueString(output_value) << endl;
    }
  } else {
    for (const slice& output_value : circuit_.outputs_as_slice_) {
      output_file << ToBinaryString(output_value) << endl;
    }
  }

  output_file.close();

  return true;
}

template<typename value_t>
bool GmwClient<value_t>::WriteOutputToFile() {
  if (output_filename_.empty()) {
    return true;
  }

  if (!CreateDir(GetDirectory(output_filename_))) {
    LOG_ERROR("Unable to open output file '" + output_filename_ + "'");
    return false;
  }
  ofstream output_file;
  output_file.open(output_filename_);
  if (!output_file.is_open()) {
    LOG_ERROR("Unable to open output file '" + output_filename_ + "'");
    return false;
  }

  if (!circuit_.outputs_as_generic_value_.empty()) {
    for (const GenericValue& output_value : circuit_.outputs_as_generic_value_) {
      output_file << GetGenericValueString(output_value) << endl;
    }
  } else {
    for (const slice& output_value : circuit_.outputs_as_slice_) {
      output_file << ToBinaryString(output_value) << endl;
    }
  }

  output_file.close();

  return true;
}

// Explicit instantiations of the template types that will be needed for all
// templates (i.e. the types that 'value_t' will assume).
// (These declarations are necessary to have template definitions in the
// present .cpp file (instead of the .h), and not encounter link errors...).
template class GmwServer<bool>;
template class GmwServer<slice>;
template class GmwClient<bool>;
template class GmwClient<slice>;

}  // namespace multiparty_computation
}  // namespace crypto
