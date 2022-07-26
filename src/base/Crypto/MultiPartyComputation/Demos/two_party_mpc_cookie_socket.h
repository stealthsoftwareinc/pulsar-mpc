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
#ifndef TWO_PARTY_MPC_COOKIE_SOCKET
#define TWO_PARTY_MPC_COOKIE_SOCKET

#include "MathUtils/data_structures.h"  // For GenericValue
#include "Networking/cookie_socket.h"  // For CookieSocketParams.

#include <vector>

extern int two_party_cookie_socket_nonmain(
    int argc,
    char* argv[],
    const std::vector<networking::CookieSocketParams>& cookie_sockets);
extern int two_party_cookie_socket_nonmain(
    const std::vector<std::string>& args,
    const std::vector<networking::CookieSocketParams>& cookie_sockets);
// Same as above, but puts the final output in 'outputs' (instead of writing
// them to file, and/or displaying them on terminal output, as per command-line
// options).
extern int two_party_cookie_socket_nonmain(
    int argc,
    char* argv[],
    const std::vector<networking::CookieSocketParams>& cookie_sockets,
    std::vector<math_utils::GenericValue>* outputs);
extern int two_party_cookie_socket_nonmain(
    const std::vector<std::string>& args,
    const std::vector<networking::CookieSocketParams>& cookie_sockets,
    std::vector<math_utils::GenericValue>* outputs);

#endif
