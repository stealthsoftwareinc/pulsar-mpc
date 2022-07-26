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

#include "circuit_utils.h"

#include "GenericUtils/mutex.h"
#include "MathUtils/data_structures.h"  // For GenericValue.
#include "TestUtils/timer_utils.h"  // For SleepTimer.
#include "global_utils.h"

// The following is needed so we can foward-declare/instantiate
// ReadWriteQueue with template-type 'Gate'. There is no circular-
// dependency, since the inclusion here is in the .cpp file
// (and because we only need the definition of the 'Gate' structure
// in the .h file of standard_circuit_by_gate, so we don't need to
// include standard_circuit_by_gate.o when compiling the present file/class).
#include "Crypto/MultiPartyComputation/Circuits/standard_circuit_by_gate.h"

#include <unistd.h>  // For usleep.

using namespace math_utils;
using namespace string_utils;
using namespace test_utils;
using namespace std;

namespace crypto {
namespace multiparty_computation {

template<typename value_t>
bool ReadWriteQueue<value_t>::Push(const bool safe, const value_t& value) {
  // Sanity-check value can be added.
  if (max_size_ <= 0) return false;
  // Grab lock.
  if (safe) mutex_->GrabLock();
  if (num_pushed_ - num_popped_ >= (uint64_t) max_size_) {
    if (safe) mutex_->ReleaseLock();
    return false;
  }

  // Add value to queue_, growing queue_ if necessary.
  if (push_index_ < 0 || queue_.size() < (size_t) push_index_) {
    LOG_FATAL("This should never happen.");
  } else if (queue_.size() == (size_t) push_index_) {
    queue_.push_back(value);
  } else {
    queue_[push_index_] = value;
  }

  // Update push_index_ and num_pushed.
  ++num_pushed_;
  if (safe) mutex_->ReleaseLock();
  if (push_index_ == max_size_ - 1) push_index_ = 0;
  else ++push_index_;

  return true;
}

template<typename value_t>
bool ReadWriteQueue<value_t>::PushOrSleep(
    const bool safe, const value_t& value, SleepTimer* timer) {
  while (!Push(safe, value)) {
    if (max_size_ <= 0 || timer == nullptr) return false;
    uint64_t sleep_time;
    if (!timer->GetSleepTime(&sleep_time)) return false;
    usleep((useconds_t) sleep_time);
  }

  if (timer != nullptr) timer->Reset();
  return true;
}

template<typename value_t>
bool ReadWriteQueue<value_t>::Pop(const bool safe, value_t* value) {
  // Grab lock.
  if (safe) mutex_->GrabLock();

  // Sanity-check value can be popped.
  if (num_popped_ >= num_pushed_) {
    if (safe) mutex_->ReleaseLock();
    return false;
  }

  // Extract value.
  *value = queue_[pop_index_];

  // Update pop_index_ and num_popped.
  ++num_popped_;
  if (safe) mutex_->ReleaseLock();
  if (pop_index_ == max_size_ - 1) pop_index_ = 0;
  else ++pop_index_;

  return true;
}

template<typename value_t>
bool ReadWriteQueue<value_t>::PopOrSleep(
    const bool safe, value_t* value, SleepTimer* timer) {
  while (!Pop(safe, value)) {
    if (max_size_ <= 0 || timer == nullptr) return false;
    uint64_t sleep_time;
    if (!timer->GetSleepTime(&sleep_time)) return false;
    usleep((useconds_t) sleep_time);
  }

  if (timer != nullptr) timer->Reset();
  return true;
}

// Explicit instantiations of all currently supported template types for
// the ReadWriteQueue container (i.e. the types that 'value_t' will assume).
// (These declarations are necessary to have template definitions in the
// present .cpp file (instead of the .h), and not encounter link errors...).
template class ReadWriteQueue<GenericValue>;
template class ReadWriteQueue<Gate>;
template class ReadWriteQueue<unsigned char>;
template class ReadWriteQueue<pair<OTPair<bool>, OTPair<bool>>>;

}  // namespace multiparty_computation
}  // namespace crypto
