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

#include "linux_thread.h"

#include "global_utils.h"

#include <memory>  // For unique_ptr
#include <thread>

using namespace string_utils;
using namespace std;

void LinuxThread::StartThread(
    void* fn, void* args, ThreadParams* thread_params) {
  // Cast the input args into the appropriate types.
  void (*fn_ptr)(void*);
  fn_ptr = (void (*)(void*)) fn;
  LinuxThreadParams* params = (LinuxThreadParams*) thread_params;

  // Create (and start) the thread.
  params->thread_handle_ = unique_ptr<thread>(new thread(fn_ptr, args));
  params->thread_id_ = params->thread_handle_->get_id();
  params->thread_index_set_ = true;
}

void LinuxThread::WaitForThread(ThreadParams* params) {
  LinuxThreadParams* linux_params = (LinuxThreadParams*) params;
  linux_params->thread_handle_->join();
  // WARNING: This will make it seem like the function that this thread
  // called *always* succeeded, since Linux/C++ has no way of fetching
  // the return code.
  // TODO: Determine how to set exit_code_ validly; this probably requires
  // using C++19 async/future.
  params->exit_code_ = 0;
  params->exit_code_set_ = true;
}
