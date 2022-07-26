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
//   Helper functions to define generic Sockets, so that caller doesn't
//   need to worry about what OS they're on.

#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include "Networking/socket.h"

#include <memory>  // For unique_ptr.

namespace networking {

// Creates a socket of the appropriate SocketType.
// NOTE 1: This is the most general API available; probably you should
// use the SocketType-specific APIs below. For example:
//   - send_queue, rec_queue, username, password only relevant for
//     type = RABBITMQ socket.
//   - cookie, send_handle, recv_handle only relevant for type = COOKIE socket.
// NOTE 2: Socket is created on the heap; caller is responsible for
// maintaining it (e.g. calling delete).
extern void CreateSocket(
    const SocketType type,
    const SocketRole role,
    const std::string& username,
    const std::string& password,
    const std::string& send_queue,
    const std::string& rec_queue,
    const std::string& ip,
    const unsigned long& port,
    void* const cookie,
    void* const send_handle,
    void* const recv_handle,
    std::unique_ptr<Socket>* s);
// Same as above, for specifying all params in a single SocketParams object.
// The SocketParams object must have the appropriate instantiatied type, as
// determined by the params.type_ field (e.g. TcpSocketParams).
extern void CreateSocket(const SocketParams& params, std::unique_ptr<Socket>* s);
// Creates a OS_TCP socket.
inline void CreateSocket(
    const SocketRole role,
    const std::string& ip,
    const unsigned long& port,
    std::unique_ptr<Socket>* s) {
  CreateSocket(
      SocketType::OS_TCP,
      role,
      "",
      "",
      "",
      "",
      ip,
      port,
      nullptr,
      nullptr,
      nullptr,
      s);
}
// Similar to above, but specifies a specific SocketRole (only SERVER or CLIENT).
inline void CreateSocket(
    const bool is_server,
    const std::string& username,
    const std::string& password,
    const std::string& send_queue,
    const std::string& rec_queue,
    const std::string& ip,
    const unsigned long& port,
    std::unique_ptr<Socket>* s) {
  if (is_server)
    CreateSocket(
        SocketType::OS_TCP,
        SocketRole::SERVER,
        username,
        password,
        send_queue,
        rec_queue,
        ip,
        port,
        nullptr,
        nullptr,
        nullptr,
        s);
  else
    CreateSocket(
        SocketType::OS_TCP,
        SocketRole::CLIENT,
        username,
        password,
        send_queue,
        rec_queue,
        ip,
        port,
        nullptr,
        nullptr,
        nullptr,
        s);
}
// Same as above, for OS_TCP socket.
inline void CreateSocket(
    const bool is_server,
    const std::string& ip,
    const unsigned long& port,
    std::unique_ptr<Socket>* s) {
  CreateSocket(is_server, "", "", "", "", ip, port, s);
}

// CreateSocketNoTimeout behaves exactly like CreateSocket,
// with the only difference that it sets the listen and connect
// timeout parameters to never time out.
void CreateSocketNoTimeout(
    const SocketType type,
    const SocketRole role,
    const std::string& username,
    const std::string& password, /* For RabbitMQ only */
    const std::string& send_queue,
    const std::string& rec_queue, /* For RabbitMQ only */
    const std::string& ip,
    const unsigned long& port,
    void* const cookie,
    void* const send_handle,
    void* const recv_handle,
    std::unique_ptr<Socket>* s);
// Alternate APIs with default behavior (use TCP sockets).
void CreateSocketNoTimeout(
    const SocketParams& params, std::unique_ptr<Socket>* s);
void CreateSocketNoTimeout(
    const bool is_server,
    const unsigned long& port,
    const std::string& ip,
    std::unique_ptr<Socket>* s);

}  // namespace networking
#endif
