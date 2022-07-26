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

#ifndef JNI_COOKIE_SOCKET_H
#define JNI_COOKIE_SOCKET_H

#include "socket.h"

namespace networking {

typedef ssize_t CookieSocketSendFunction(
    void* cookie, const void* buf, size_t len);

typedef ssize_t CookieSocketRecvFunction(void* cookie, void* buf, size_t len);

struct CookieSocketFunctions {
  CookieSocketSendFunction* send_;
  CookieSocketRecvFunction* recv_;

  CookieSocketFunctions() {
    send_ = nullptr;
    recv_ = nullptr;
  }
  CookieSocketFunctions(
      CookieSocketSendFunction* send, CookieSocketRecvFunction* recv) {
    send_ = send;
    recv_ = recv;
  }
};

struct CookieSocketParams : public SocketParams {
  // The following holds the HANDLES (fn ptrs) to send/recv.
  CookieSocketFunctions functions_;
  // The following is the 'cookie' to use.
  void* cookie_;

  CookieSocketParams() : functions_() { cookie_ = nullptr; }
  CookieSocketParams(const CookieSocketParams& other) {
    is_default_ = other.is_default_;
    type_ = other.type_;
    cookie_ = other.cookie_;
    functions_ = other.functions_;
  }
};

class CookieSocket : public Socket {
public:
  CookieSocket(void* const cookie, const CookieSocketFunctions functions) :
      cookie_(cookie),
      functions_(functions) {
    role_ = SocketRole::NEITHER;
    socket_type_ = SocketType::COOKIE;
    Initialize();
  }
  CookieSocket(const CookieSocket& other) :
      CookieSocket(other.cookie_, other.functions_) {}

  ~CookieSocket() noexcept { CloseSocket(); }
  // Virtual constructor (creation).
  CookieSocket* create() const {
    return new CookieSocket(nullptr, CookieSocketFunctions());
  }
  // Virtual constructor (copying).
  CookieSocket* clone() const { return new CookieSocket(*this); }

private:
  void* cookie_;
  CookieSocketFunctions functions_;

  // Override inherited Socket::Initialize().
  bool Initialize();

  // Override inherited Socket::SocketSetSocketParams().
  void SocketSetSocketParams(const SocketParams& params);

  // Override inherited Socket::SocketSetupClientSocket().
  bool SocketSetupClientSocket() { return true; }
  // Override inherited Socket::SocketSetupServerSocket().
  bool SocketSetupServerSocket() { return true; }

  // Override inherited Socket::SocketGetClientSocketId().
  // Note: Wherever SocketGetClientSocketId() is used, it is for *receiving* data;
  // thus, return the recv_ function.
  SocketIdentifier SocketGetClientSocketId() {
    return SocketIdentifier((void*) functions_.recv_);
  }
  // Override inherited Socket::SocketGetServerSocketId().
  // Note: Wherever SocketGetServerSocketId() is used, it is for *sending* data;
  // thus, return the send_ function.
  SocketIdentifier SocketGetServerSocketId() {
    return SocketIdentifier((void*) functions_.send_);
  }
  // Override inherited Socket::SocketGetReceiveSocketId().
  SocketIdentifier SocketGetReceiveSocketId() {
    return SocketIdentifier((void*) functions_.recv_);
  }
  // Override inherited Socket::SocketGetSendSocketId().
  SocketIdentifier SocketGetSendSocketId() {
    return SocketIdentifier((void*) functions_.send_);
  }

  // Override inherited Socket::SocketIsClientSocket().
  bool SocketIsClientSocket(const SocketIdentifier&) {
    return functions_.recv_ != nullptr;
  }
  // Override inherited Socket::SocketIsServerSocket().
  bool SocketIsServerSocket(const SocketIdentifier&) {
    return functions_.send_ != nullptr;
  }

  // Override inherited Socket::SocketGetLocalHost().
  // This should never be called for JNI.
  bool SocketGetLocalHost(std::string*) { return false; }
  // Override inherited Socket::SocketGetWithinNetworkIP().
  // This should never be called for JNI.
  bool SocketGetWithinNetworkIP(std::string*) { return false; }

  // Override inherited Socket::SocketSet[ | Client | Server]SocketOption().
  bool SocketSetSocketOption(const SocketIdentifier&, const int, const int) {
    return true;
  }
  bool SocketSetClientSocketOption(const int, const int) { return true; }
  bool SocketSetServerSocketOption(const int, const int) { return true; }
  bool SocketSetTlsSocketOption(const SocketIdentifier&, const int) {
    return true;
  }
  bool SocketSetNonBlockingSocket(const bool, const SocketIdentifier&) {
    return true;
  }

  // Override inherited Socket::SocketReceive().
  ssize_t SocketReceive(
      const SocketIdentifier& s, const size_t& max_rec_bytes, char* rec_buffer);

  // Override inherited Socket::SocketSend().
  ssize_t SocketSend(
      const SocketIdentifier& s,
      const char* buffer,
      const size_t& num_chars_in_buffer);

  // Override inherited Socket::SocketBind.
  // Nothing to do for JNI, which should handle this behind-the-scenes.
  bool SocketBind() { return true; }

  // Override inherited Socket::SocketSelect.
  int SocketSelect(
      const SocketIdentifier& s,
      const uint64_t& timeout_secs,
      const uint64_t& timeout_micro_secs,
      std::set<SocketIdentifier>* read_sockets,
      std::set<SocketIdentifier>* write_sockets,
      std::set<SocketIdentifier>* error_sockets);

  // Override inherited Socket::SocketServerListen.
  bool SocketServerListen() { return false; }

  // Override inherited Socket::SocketClientConnect().
  bool SocketClientConnect() { return functions_.recv_ != nullptr; }

  // Override inherited Socket::SocketOpenNewConnection().
  bool SocketOpenNewConnection(SocketIdentifier*) { return false; }

  // Override inherited Socket::SocketShutdownConnection().
  // Connection is handled externally. Just return.
  bool SocketShutdownConnection(const SocketIdentifier&) { return true; }
  // Override inherited Socket::SocketCloseClientSocket.
  // Connection is handled externally. Just return.
  bool SocketCloseClientSocket(const bool) { return true; }
  // Override inherited Socket::SocketCloseServerSocket.
  // Connection is handled externally. Just return.
  bool SocketCloseServerSocket() { return true; }

  // Override inherited Socket::SocketSleep().
  void SocketSleep(const long long int& sleep_micro_sec);

  // Override inherited Socket::SocketIsClientSocketInSet.
  bool SocketIsClientSocketInSet(const std::set<SocketIdentifier>&) {
    // This is only called:
    //   1) In Listen(), where it is used to identify errors on the Client Socket;
    //   2) Within CheckConnectStatus()
    // Since CookieSocket shouldn't support either of those, simply return false.
    return false;
  }
  // Override inherited Socket::SocketIsServerSocketInSet.
  bool SocketIsServerSocketInSet(const std::set<SocketIdentifier>&) {
    // This is only called within Listen(), and is used to identify:
    //   1) Errors on the Server socket;
    //   2) New Connection requests.
    // Since CookieSocket shouldn't support either of those, simply return false.
    return false;
  }

  // Override inherited Socket::SocketGetLastError().
  int SocketGetLastError() { return -1; }
  // Override inherited Socket::SocketGetSocketError.
  int SocketGetSocketError(const SocketIdentifier&) { return -1; }
  int SocketGetClientSocketError() { return -1; }
  int SocketGetServerSocketError() { return -1; }
  // Override inherited Socket::SocketSocketErrorCode().
  int SocketSocketErrorCode() { return -1; }
  // Override inherited Socket::SocketSocketWouldBlockCode().
  int SocketSocketWouldBlockCode() { return -1; }
  // Override inherited Socket::SocketSocketInProgressCode().
  int SocketSocketInProgressCode() { return -1; }
  // Override inherited Socket::SocketSocketConnectResetCode().
  int SocketSocketConnectResetCode() { return -1; }
  // Override inherited Socket::SocketSocketConnectionAbortedCode().
  int SocketSocketConnectionAbortedCode() { return -1; }
  // Override inherited Socket::SocketSocketConnectionRefusedCode().
  int SocketSocketConnectionRefusedCode() { return -1; }
  // Override inherited Socket::SocketSocketUnavailableCode().
  int SocketSocketUnavailableCode() { return -1; }
  // Override inherited Socket::SocketSocketIntUseCode().
  int SocketSocketIntUseCode() { return -1; }
  // Override inherited Socket::SocketGetSocketLayerCode().
  int SocketGetSocketLayerCode() { return -1; }
  // Override inherited Socket::SocketGetSocketTcpCode().
  int SocketGetSocketTcpCode() { return -1; }
  // Override inherited Socket::SocketGetSocketTcpNoDelayCode().
  int SocketGetSocketTcpNoDelayCode() { return -1; }
  // Override inherited Socket::SocketGetSocketReusePortCode().
  int SocketGetSocketReusePortCode() { return -1; }
  // Override inherited Socket::SocketSocketOpAlreadyCode().
  int SocketSocketOpAlreadyCode() { return -1; }
};

}  // namespace networking

#endif
