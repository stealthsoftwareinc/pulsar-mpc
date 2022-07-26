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

#include "socket_utils.h"
#include "LoggingUtils/logging_utils.h"
#include "Networking/cookie_socket.h"
#include "Networking/socket.h"
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
#include "Networking/windows_socket.h"
#else
#include "Networking/linux_socket.h"
#endif
#if (defined(USE_RABBITMQ))
#include "Networking/rabbitmq_socket.h"
#endif
#include "StringUtils/string_utils.h"

#include <memory>  // For unique_ptr

using namespace string_utils;
using namespace std;

namespace networking {

static const char kLocalHostKeyword[] = "localhost";
static const char kNetworkIpKeyword[] = "network";
static const string DEFAULT_SERVER_LISTEN_IP = "0.0.0.0";

namespace {
void ParseIpKeyword(
    const SocketRole& role, const string& ip, unique_ptr<Socket>* s) {
  string actual_ip = ip;
  if (ip == string(kLocalHostKeyword)) {
    (*s)->GetLocalHost(&actual_ip);
  } else if (ip == string(kNetworkIpKeyword)) {
    (*s)->GetWithinNetworkIP(&actual_ip);
  }
  if (actual_ip != ip) {
    if (role == SocketRole::SERVER) {
      (*s)->SetListenIp(actual_ip);
    }
    if (role == SocketRole::CLIENT) {
      (*s)->SetConnectIp(actual_ip);
    }
  }
}
}  // namespace

void CreateSocket(
    const SocketType type,
    const SocketRole role,
    const string& username,
    const string& password, /* For RabbitMQ only */
    const string& send_queue,
    const string& rec_queue, /* For RabbitMQ only */
    const string& ip,
    const unsigned long& port,
    void* const cookie,
    void* const send_handle,
    void* const recv_handle,
    unique_ptr<Socket>* s) {
  // If user specified empty string for ip, use DEFAULT_SERVER_LISTEN_IP.
  const string ip_to_use =
      (ip.empty() && role == SocketRole::SERVER) ? DEFAULT_SERVER_LISTEN_IP : ip;
  // Now call appropriate Socket() constructor, based on SocketType.
  if (type == SocketType::RABBITMQ) {
#if (defined(USE_RABBITMQ))
    *s = unique_ptr<RabbitMqSocket>(new RabbitMqSocket(
        send_queue, rec_queue, username, password, ip_to_use, port));
#else
    LOG_FATAL("RabbitMq not supported. Compile with -D USE_RABBITMQ "
              "to include RabbitMQ library support.");
    LOG_INFO(
        "Dummy message (never printed) to avoid compiler warnings "
        "about unused variables username: '" +
        username + "', password: '" + password + "', send_queue: '" +
        send_queue + "', rec_queue: '" + rec_queue + "'");
#endif
    ParseIpKeyword(SocketRole::CLIENT, ip, s);
  } else if (type == SocketType::OS_TCP) {
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
    *s = unique_ptr<WindowsSocket>(new WindowsSocket(role, ip_to_use, port));
#else
    *s = unique_ptr<LinuxSocket>(new LinuxSocket(role, ip_to_use, port));
#endif
    ParseIpKeyword(role, ip, s);
  } else if (type == SocketType::COOKIE) {
    CookieSocketFunctions handles(
        (CookieSocketSendFunction*) send_handle,
        (CookieSocketRecvFunction*) recv_handle);
    *s = unique_ptr<CookieSocket>(new CookieSocket(cookie, handles));
  } else {
    LOG_FATAL("Unsupported Socket Type: " + Itoa(static_cast<int>(type)));
  }
}

void CreateSocketNoTimeout(
    const SocketType type,
    const SocketRole role,
    const string& username,
    const string& password, /* For RabbitMQ only */
    const string& send_queue,
    const string& rec_queue, /* For RabbitMQ only */
    const string& ip,
    const unsigned long& port,
    void* const cookie,
    void* const send_handle,
    void* const recv_handle,
    unique_ptr<Socket>* s) {
  CreateSocket(
      type,
      role,
      username,
      password,
      send_queue,
      rec_queue,
      ip,
      port,
      cookie,
      send_handle,
      recv_handle,
      s);
  ConnectParams connect_params = (*s)->GetConnectParams();
  connect_params.num_retries_ = -1;
  (*s)->SetConnectParams(connect_params);
  networking::ListenParams listen_params = (*s)->GetListenParams();
  listen_params.select_timeout_ms_ = 0;
  (*s)->SetListenParams(listen_params);
}

void CreateSocket(const SocketParams& params, unique_ptr<Socket>* s) {
  // Now call appropriate Socket() constructor, based on SocketType.
  const SocketType type = params.type_;
  if (type == SocketType::RABBITMQ) {
#if (defined(USE_RABBITMQ))
    const RabbitMqSocketParams* r_params = (RabbitMqSocketParams*) &params;
    *s = unique_ptr<RabbitMqSocket>(new RabbitMqSocket(
        r_params->send_queuename_,
        r_params->rec_queuename_,
        r_params->username_,
        r_params->password_,
        r_params->server_ip_,
        r_params->server_port_));
    (*s)->SocketSetSocketParams(params);
    ParseIpKeyword(SocketRole::CLIENT, r_params->server_ip_, s);
#else
    LOG_FATAL("RabbitMq not supported. Compile with -D USE_RABBITMQ "
              "to include RabbitMQ library support.");
#endif
  } else if (type == SocketType::OS_TCP) {
    const TcpSocketParams* tcp_params = (TcpSocketParams*) &params;
    const string& ip = tcp_params->role_ == SocketRole::CLIENT ?
        tcp_params->connect_ip_ :
        tcp_params->listen_ip_;
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
    *s = unique_ptr<WindowsSocket>(
        new WindowsSocket(tcp_params->role_, ip, tcp_params->port_));
#else
    *s = unique_ptr<LinuxSocket>(
        new LinuxSocket(tcp_params->role_, ip, tcp_params->port_));
#endif
    ParseIpKeyword(tcp_params->role_, ip, s);
  } else if (type == SocketType::COOKIE) {
    const CookieSocketParams* cookie_params = (CookieSocketParams*) &params;
    *s = unique_ptr<CookieSocket>(
        new CookieSocket(cookie_params->cookie_, cookie_params->functions_));
  } else {
    LOG_FATAL("Unsupported Socket Type: " + Itoa(static_cast<int>(type)));
  }
}

void CreateSocketNoTimeout(const SocketParams& params, unique_ptr<Socket>* s) {
  CreateSocket(params, s);
  ConnectParams connect_params = (*s)->GetConnectParams();
  connect_params.num_retries_ = -1;
  (*s)->SetConnectParams(connect_params);
  networking::ListenParams listen_params = (*s)->GetListenParams();
  listen_params.select_timeout_ms_ = 0;
  (*s)->SetListenParams(listen_params);
}

void CreateSocketNoTimeout(
    const bool is_server,
    const unsigned long& port,
    const string& ip,
    unique_ptr<Socket>* s) {
  CreateSocketNoTimeout(
      SocketType::OS_TCP,
      is_server ? SocketRole::SERVER : SocketRole::CLIENT,
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

}  // namespace networking
