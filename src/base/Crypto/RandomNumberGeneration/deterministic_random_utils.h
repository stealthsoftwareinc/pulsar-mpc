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
//   Utils for deterministic (with seed) random number generators.
//
// NOTE 0: These RNG's are implemented using streaming encryption (i.e. CTR mode).
// In particular, they first (once-and-for-all) seed the encryption function,
// and then they generate 'random' numbers by calling the (seeded) encryption
// function on a deterministic sequence of inputs, e.g. {0, 1, 2, ...}.
//
// NOTE 1: These random number generators are NOT cryptographically-secure, and
// should not be used in any production code that requires a cryptographic PRG!!!
// Indeed, most of a cryptographically-secure alternative exists for most of
// the below functions in random_utils.h (indeed, the function API's are
// basically identical, right up to the name of the function, except that
// here the first argument is the seed, and in random_utils.h, there is no seed).
//
// NOTE 2: This Library is NOT thread-safe for many reasons. Mainly, it uses
// ctr_crypt, which has a nonce, and the nonce gets updated every time
// ctr_crypt is called. Having multi-thread access wouldn't make sense,
// because the order of the calls would effect the deterministic random
// numbers being generated, and effectively make them no longer deterministic,
// thus removing the whole point of these tools. So use for single-thread
// applications only (and, by the above NOTE, for testing only also).
#ifndef DETERMINISTIC_RANDOM_UTILS_H
#define DETERMINISTIC_RANDOM_UTILS_H

#include "MathUtils/constants.h"  // For slice

#include <vector>

namespace crypto {
namespace random_number {

// Resets global flag, so that next call to RandomBytes(seed) will regenerate
// the seed (Useful to call just before calling RandomBytes, in case different
// program runs/threads are synced).
extern void ClearRandomSeed();

// Returns a random bit (true for '1' or false for '0').
// NOTE: Wasteful. This will actually call RandomBytes() to get a random byte,
// and then use one of the bits of that random byte.
// Instead of using this API, if you need to generate multiple (say 'N') random
// bits, consider calling RandomBytes() (N / CHAR_BIT) times, and then using
// the bits of those bytes; see oblivious_transfer_utils.cpp for an example.
extern bool RandomBit(const std::vector<unsigned char>& seed);

// Returns a random byte (as an unsigned char).
extern unsigned char RandomByte(const std::vector<unsigned char>& seed);

// Appends 'num_bytes' random bytes to the end of 'buffer'.
extern void RandomBytes(
    const std::vector<unsigned char>& seed,
    const uint64_t& num_bytes,
    std::vector<unsigned char>* buffer);
// Same as above, with different API (array instead of vector).
// NOTE: buffer should have 'num_bytes' already allocated (e.g. if calling this
// from a vector<unsigned char> foo by using foo.data(), then foo should have
// already been resized with room for num_bytes; although, in this case,
// probably should've just used above API and simply pass in &foo, and then
// user shoud *not* resize foo first).
extern void RandomBytes(
    const std::vector<unsigned char>& seed,
    const uint64_t& num_bytes,
    unsigned char* buffer);

// Returns a random slice.
extern math_utils::slice RandomSlice(const std::vector<unsigned char>& seed);
// Returns a random 32-bit number.
extern uint32_t Random32BitInt(const std::vector<unsigned char>& seed);
// Same as above, for 64-bit (unsigned) value.
extern uint64_t Random64BitInt(const std::vector<unsigned char>& seed);
// Same as above, for 16-bit (unsigned) value.
extern unsigned short RandomShortInt(const std::vector<unsigned char>& seed);

// Returns a random integer in Z_n (n = 'modulus'); i.e. a random value in [0..n].
extern bool RandomInModulus(
    const std::vector<unsigned char>& seed,
    const uint32_t& modulus,
    uint32_t* random);
extern bool RandomInModulus(
    const std::vector<unsigned char>& seed,
    const uint64_t& modulus,
    uint64_t* random);
// Same as above, with different API (returns value instead of bool).
extern uint32_t RandomInModulus(
    const std::vector<unsigned char>& seed, const uint32_t& modulus);
extern uint64_t RandomInModulus(
    const std::vector<unsigned char>& seed, const uint64_t& modulus);

}  // namespace random_number
}  // namespace crypto
#endif
