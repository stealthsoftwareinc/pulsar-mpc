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
// Description: Thread instantiation for Linux.

#ifndef LINUX_THREAD_H
#define LINUX_THREAD_H

#include "GenericUtils/thread.h"
#include <memory>  // For unique_ptr
#include <thread>

// A data structure for holding parameters for a thread.
struct LinuxThreadParams : public ThreadParams {
  std::thread::id thread_id_;
  std::unique_ptr<std::thread> thread_handle_;
};

class LinuxThread : public Thread {
public:
  // Override inherited StartThread().
  // 'params' should be a pointer to a LinuxThreadParams object.
  void StartThread(void* fn, void* args, ThreadParams* params);
  // Override inherited WaitForThread().
  // 'params' should be a pointer to a LinuxThreadParams object.
  void WaitForThread(ThreadParams* params);
};

#endif
