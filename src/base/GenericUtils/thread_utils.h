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
//   Wrapper functions to create Thread* to the appropriate thread type
//   (WindowsThread vs. LinuxThread, etc.) for the running OS.

#ifndef THREAD_UTILS_H
#define THREAD_UTILS_H

#include "thread.h"

#include <cstddef>  // For size_t
#include <memory>  // For unique_ptr
#include <vector>

// Creates a Thread of the appropriate type, based on Operating System.
// Note that this 'Thread' is of type GenericUtils/Thread, i.e. it is
// not a system thread; in particular, it need not represent a single
// thread, but rather a Class object that will spawn/manage threads.
// The caller takes ownership over the created Thread.
// Common usage:
//     unique_ptr<Thread> t;
//     CreateThreadMaster(&t);
extern void CreateThreadMaster(std::unique_ptr<Thread>* t);

// Creates and returns a [Windows | Linux]ThreadParams on the heap.
// NOTE: caller takes ownership of the returned params; common usage is:
//   unique_ptr<ThreadParams> params(CreateThreadParams());
extern ThreadParams* CreateThreadParams();

// Creates a (pointer to a) vector that contains (pointers to) thread ids
// of all the running threads. The ids are not available at this time;
// this just initiates the storage vector, with the appropriate
// inheriting structure of ThreadParams.
// NOTE: caller takes ownership of the thread_ids pointer, as well as
// the pointers to each of the ThreadParams (all of which are created
// on the heap).
extern void CreateVectorOfThreadParams(
    const size_t& num_threads,
    std::vector<std::unique_ptr<ThreadParams>>* thread_ids);

#endif
