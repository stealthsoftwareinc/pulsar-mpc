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
//
// Discussion: This file provides the Linux-specific implementation of the
// RandomBit(), RandomByte() and RandomBytes() functions in random_utils.h.

#include "random_utils.h"

#include "GenericUtils/char_casting_utils.h"
#include "MathUtils/constants.h"  // For slice
#include "global_utils.h"

#include <cstring>  // For memset.
#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <pthread.h>
#include <vector>

using namespace math_utils;
using namespace string_utils;
using namespace std;

namespace crypto {
namespace random_number {

static pthread_once_t kPthreadOnceInit = PTHREAD_ONCE_INIT;
static pthread_key_t kPthreadKey;
static const int kNumSeedBytes = 16;

struct PthreadKeyInfo {
  aes128_ctx ctx_;
  unsigned char ctr_[kNumSeedBytes];
};

static void OnceInit() {
  if (pthread_key_create(&kPthreadKey, free) != 0) {
    LOG_FATAL("Unable to create pthread.");
  }
}

void RandomBytes(const uint64_t& num_bytes, unsigned char* buffer) {
  if (pthread_once(&kPthreadOnceInit, OnceInit) != 0) {
    LOG_FATAL("Unable to initialize pthread.");
  }

  PthreadKeyInfo* p = (PthreadKeyInfo*) pthread_getspecific(kPthreadKey);

  if (p == nullptr) {
    p = (PthreadKeyInfo*) malloc(sizeof(*p));
    if (p == nullptr) LOG_FATAL("Unable to allocate memory for pthread");
    if (pthread_setspecific(kPthreadKey, p) != 0) {
      LOG_FATAL("Unable to set pthread key.");
    }

    // Generate a seed for Nettle from /dev/urandom
    FILE* f = fopen("/dev/urandom", "rb");
    if (f == nullptr || fread(p->ctr_, kNumSeedBytes, 1, f) != 1) {
      LOG_FATAL("Unable to get random bytes from /dev/urandom");
    }
    fclose(f);

    aes128_set_encrypt_key(&p->ctx_, p->ctr_);
    memset(p->ctr_, 0, kNumSeedBytes);
  }

  memset(buffer, 0, num_bytes);
  uint64_t num_bytes_needed = num_bytes;
  while (num_bytes_needed > 0) {
    uint64_t n = num_bytes_needed <= UINT_MAX ?
        num_bytes_needed :
        UINT_MAX / kNumSeedBytes * kNumSeedBytes;

#if defined AWS_LINUX
    ctr_crypt(
        &p->ctx_,
        (nettle_crypt_func*) aes128_encrypt,
        kNumSeedBytes,
        p->ctr_,
        n,
        buffer,
        buffer);
#else
    ctr_crypt(
        &p->ctx_,
        (nettle_cipher_func*) aes128_encrypt,
        kNumSeedBytes,
        p->ctr_,
        n,
        buffer,
        buffer);
#endif
    buffer += n;
    num_bytes_needed -= n;
  }
}

}  // namespace random_number
}  // namespace crypto
