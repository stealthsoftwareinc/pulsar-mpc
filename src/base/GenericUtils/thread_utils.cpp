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

#include "thread_utils.h"

#include "thread.h"
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__)
#include "GenericUtils/windows_thread.h"
#else
#include "GenericUtils/linux_thread.h"
#endif

#include <memory>  // For unique_ptr
#include <vector>

using namespace std;

void CreateThreadMaster(unique_ptr<Thread>* t) {
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
  *t = unique_ptr<WindowsThread>(new WindowsThread());
#else
  *t = unique_ptr<LinuxThread>(new LinuxThread());
#endif
}

ThreadParams* CreateThreadParams() {
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
  return new WindowsThreadParams();
#else
  return new LinuxThreadParams();
#endif
  return nullptr;
}

void CreateVectorOfThreadParams(
    const size_t& num_threads, vector<unique_ptr<ThreadParams>>* thread_ids) {
  // Create the thread_ids vector, and each of its elements, on the heap.
#if defined(WINDOWS) || defined(__WIN32__) || defined(__WIN64__) || \
    defined(_WIN32) || defined(_WIN64)
  for (size_t i = 0; i < num_threads; ++i) {
    thread_ids->push_back(
        unique_ptr<WindowsThreadParams>(new WindowsThreadParams()));
  }
#else
  for (size_t i = 0; i < num_threads; ++i) {
    thread_ids->push_back(
        unique_ptr<LinuxThreadParams>(new LinuxThreadParams()));
  }
#endif

  // Fill the thread_index_ (w.r.t. 'thread_ids') of each thread.
  for (size_t i = 0; i < num_threads; ++i) {
    (*thread_ids)[i]->thread_index_ = i;
    (*thread_ids)[i]->thread_index_set_ = true;
  }
}
