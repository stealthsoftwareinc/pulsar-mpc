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

#include "cookie_socket.h"

#include "global_utils.h"
#include <climits>
#include <set>
#include <unistd.h>  // For usleep

using namespace std;

namespace networking {

bool CookieSocket::Initialize() {
  is_initialized_ = true;
  return true;
}

void CookieSocket::SocketSleep(const long long int& sleep_micro_sec) {
  usleep((unsigned int) sleep_micro_sec);
}

void CookieSocket::SocketSetSocketParams(const SocketParams& params) {
  const CookieSocketParams* cookie_params = (const CookieSocketParams*) &params;
  functions_ = cookie_params->functions_;
}

// Currently, SocketSelect() is called in three places:
//   1) In ThreadListen()
//   2) In CheckConnectStatus()
//   3) In SendBlob()
// We assume that (2) never happens for CookieSocket, and hence only
// support (1) and (3) here.
// We identify (1) iff 'write_sockets' is null, and (3) iff 'read_sockets'
// is null, which is consistent with all current use-cases of SocketSelect()
// (with the exception of (2) above, in which case 'read_sockets' is also
// null, but again, we assume code will never reach here for that case).
int CookieSocket::SocketSelect(
    const SocketIdentifier&,
    const uint64_t&,
    const uint64_t&,
    set<SocketIdentifier>* read_sockets,
    set<SocketIdentifier>* write_sockets,
    set<SocketIdentifier>*) {
  // Test if this was called as per use-case (1) (see comment above).
  if (read_sockets != nullptr && write_sockets == nullptr) {
    // select() here is just supposed to return when there are bytes to read.
    // Since the actual reading of those bytes (in SocketReceive()) is
    // blocking, we go ahead and return here, and rely on SocketReceive()
    // to do the right thing.
    read_sockets->insert(SocketGetReceiveSocketId());
    return 1;
    // Test if this was called as per use-case (3) (see comment above).
  } else if (read_sockets == nullptr && write_sockets != nullptr) {
    write_sockets->insert(SocketGetSendSocketId());
    return 1;
  }

  // Unexpected use-case. Return error.
  LOG_ERROR("Unsupported call to SocketSelect().");
  return -1;
}

ssize_t CookieSocket::SocketSend(
    const SocketIdentifier&,
    const char* buffer,
    const size_t& num_chars_in_buffer) {
  return functions_.send_(cookie_, buffer, num_chars_in_buffer);
}

ssize_t CookieSocket::SocketReceive(
    const SocketIdentifier&, const size_t& max_rec_bytes, char* rec_buffer) {
  return functions_.recv_(cookie_, rec_buffer, max_rec_bytes);
}
}  // namespace networking
