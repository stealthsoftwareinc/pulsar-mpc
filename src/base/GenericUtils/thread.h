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
//   Thread template class; for actual implementations, see:
//     - windows_thread: For Windows Threads
//     - linux_thread:   For Linux Threads
//
// DISCUSSION:
//   Originally, I couldn't get threads to work on Windows:
//     - MinGW doesn't support mutex (#include <mutex> fails)
//     - MinGW doesn't support thread (#include <thread> fails)
//     - The experimental version of MinGW that I downloaded to support PThread
//       isn't working; perhaps because I cannot use 2 different MinGW libs at
//       the same time; or perhaps because the latter version is missing things
//       it needs. In any case, I can't get code using pthread.h to compile, as
//       it fails at the linking stage (#include <pthread.h> fails to link)
//
//   Here were some workarounds I tried:
//     a) Use Win32 threading, either directly via CreateThreadMaster(), or
//        indirectly (MinGW's API to Win32 threading) via _beginthreadex
//     b) Use PThreads. This has one major disadvantage: PThreads have no
//        concept of "this", the class self reference. This means that either:
//          i) The ThreadListen() function must be static; which in particular
//             means all of this class' member variables that ThreadListen()
//             uses (which is almost all of them) must be made static
//         ii) The PThread must be created in the main() function, where the
//             particular instance of this class was created, and then we can
//             use the solution in
//               http://stackoverflow.com/questions/1151582/pthread-function-from-a-class
//             to have the PThread call that instance's ThreadListen()
//        If choosing the PThread solution, probably (i) is better than (ii),
//        so-as not to force all use-cases to create the listening PThread.
//     c) Use someone's wrapper of PThreads, which allows using the basic
//        std::thread class. See
//          http://stackoverflow.com/questions/
//            6783512/c11-threading-on-windows/8464622#8464622
//        and
//          https://sourceforge.net/projects/mingw-w64/files/
//            Toolchains%20targetting%20Win64/Personal%20Builds/rubenvb/
//            gcc-4.7-experimental-stdthread/
//
//   In the end, I was able to get threads to work on Windows via option (a),
//   in particular using _beginthreadex plus the Windows.h functions
//   WaitForSingleObject() and GetExitCodeThread().

#ifndef THREAD_H
#define THREAD_H

#include <cstddef>

// Structure to hold fields that identify a running thread. This structure
// is left mostly empty (abstract) here; the inheriting structures (e.g.
// WindowsThreadParams) will fill out the structure. We introduce this base
// struct simply as a convenience to not have to write void* when referencing
// ThreadParams in a generic way.
struct ThreadParams {
  // Thread index (w.r.t. the threads the main thread has started).
  // Typically the main thread stores all threads in a vector<ThreadParams*>
  // (via a call to CreateVectorOfThreadParams()), and then this index
  // holds the index w.r.t. this vector.
  size_t thread_index_;
  // Whether the thread_index_ field has been set (and hence if it can be used).
  bool thread_index_set_;

  // The return value of the Callback function that the thread ran.
  int exit_code_;
  // Whether the value in exit_code_ has been set (and hence if it can be used).
  bool exit_code_set_;

  ThreadParams() {
    exit_code_set_ = false;
    thread_index_set_ = false;
  }
};

class Thread {
public:
  // Starts a thread to perform a task (call a function).
  // 'fn' should be a function pointer to a function that returns an
  // unsigned (int) and takes in as arguments a (void) pointer;
  // 'args' should be the (void) pointer that will be used as the arguments
  // passed in to 'fn';
  // 'params' should be a pointer to object (struct) that will be used to
  // describe the thread (e.g. for a WindowsThread instantiation of this
  // class, 'params' will be a pointer to WindowsThreadParams).
  virtual void StartThread(void* fn, void* args, ThreadParams* params) = 0;
  // Instructs the main thread to BLOCK until the thread indicated by 'params'
  // has completed.
  // 'params' should be a pointer to object (struct) that will be used to
  // describe the thread (e.g. for a WindowsThread instantiation of this
  // class, 'params' will be a pointer to WindowsThreadParams).
  virtual void WaitForThread(ThreadParams* params) = 0;

  virtual ~Thread() = default;
};

#endif
