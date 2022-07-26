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

#include "mutex.h"

#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__)
#include "GenericUtils/windows_mutex.h"
#else
#include "GenericUtils/linux_mutex.h"
#endif

#include <memory>  // For unique_ptr

using namespace std;

// Nothing to do here for Mutex functions, as all fns in Mutex are currently
// pure abstract (implementations are in inheriting classes, e.g. WindowsMutex).
void InitializeMutex(unique_ptr<Mutex>* m, const int32_t& max_wait_ms) {
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
  *m = unique_ptr<WindowsMutex>(new WindowsMutex(max_wait_ms));
#else
  *m = unique_ptr<LinuxMutex>(new LinuxMutex(max_wait_ms));
#endif
}

Mutex* CreateNewMutex(const int32_t& max_wait_ms) {
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
  return new WindowsMutex(max_wait_ms);
#else
  return new LinuxMutex(max_wait_ms);
#endif
}
