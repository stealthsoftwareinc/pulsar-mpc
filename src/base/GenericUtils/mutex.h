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
//   Mutex template class; for actual implementations, see:
//     - windows_mutex_utils: For Windows Mutex
//     - linux_mutex_utils:   For Linux Mutex
// Discussion:
//   MinGW does not support <mutex>, so for Windows builds, I need to use
//   another mutex source. This class provides a (system-agnostic) wrapper
//   to mutex, so that calling code can use the wrapper, and meanwhile
//   system-specific inheriting classes will instantiate the actual code,
//   and the build will determine which system is on and consequently
//   which instantiation to use.

#ifndef MUTEX_H
#define MUTEX_H

#include <cstdint>  // For int64_t.
#include <memory>  // For unique_ptr.

class Mutex {
public:
  // Creates a Mutex with the appropriate settings for member fields.
  Mutex() { max_wait_ms_ = -1; }
  explicit Mutex(int64_t max_wait_ms) { max_wait_ms_ = max_wait_ms; }
  virtual void GrabLock() = 0;
  virtual void ReleaseLock() = 0;

protected:
  int64_t max_wait_ms_;  // Use negative value for 'INFINITE'
};

// Creates a Mutex of the appropriate type, based on Operating System.
// Note that the created 'Mutex' has generic type Mutex (as opposed to
// the (OS-) specific type of the inheriting class).
// Common usage:
//     unique_ptr<Mutex> m;
//     InitializeMutex(&m);
// The following also allows specification of a maximum wait time.
extern void InitializeMutex(
    std::unique_ptr<Mutex>* m, const int32_t& max_wait_ms);
// Same as above, without specification of max_wait_ms
// (default is -1, which means no limit, i.e. wait indefinitely).
inline void InitializeMutex(std::unique_ptr<Mutex>* m) {
  InitializeMutex(m, -1);
}

// Creates a Mutex of the appropriate type, based on Operating System.
// Note that the created 'Mutex' has generic type Mutex (as opposed to
// the (OS-) specific type of the inheriting class).
// The following also allows specification of a maximum wait time.
extern Mutex* CreateNewMutex(const int32_t& max_wait_ms);
// Same as above, without specification of max_wait_ms
// (default is -1, which means no limit, i.e. wait indefinitely).
inline Mutex* CreateNewMutex() { return CreateNewMutex((int32_t) -1); }

#endif
