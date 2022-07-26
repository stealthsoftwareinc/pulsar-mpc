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
// Discussion:
// Functions for Linux-specific Encryption toolkit, primarily Encryption/Decryption functions.
// This file has no corresponding .h file, but rather, it provides (system-
// dependent) implementation of the external functions in aes_utils.h.
//
// NOTE: This file is currently unimplemented. The functions here implement the
// corresponding PlatformAes128[En | De]crypt() functions in aes_utils.h, and they
// are only needed for when EncryptionPlatform::PLATFORM is specified as the
// platform, which is not currently done for any active production code.
//
// TODO(PHB): If the EncryptionPlatform::PLATFORM option ever becomes something
// that is utilized in production code, the functions in this file will have
// to be implemented for real.

#include "aes_utils.h"

#include "global_utils.h"

using namespace string_utils;
using namespace std;

namespace crypto {
namespace encryption {

// =========================== PlatformAes128Encrypt ===========================
void PlatformAes128Encrypt(
    const unsigned char*,
    const uint32_t,
    const unsigned char*,
    const uint32_t,
    unsigned char*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Encrypt is not currently available.");
}

void PlatformAes128Encrypt(
    const uint32_t,
    const unsigned char*,
    const uint32_t*,
    const unsigned char*,
    const uint32_t*,
    unsigned char*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Encrypt is not currently available.");
}

void PlatformAes128Encrypt(
    const uint32_t,
    const unsigned char*,
    const uint32_t,
    const unsigned char*,
    const uint32_t,
    unsigned char*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Encrypt is not currently available.");
}

void PlatformAes128Encrypt(
    const uint32_t,
    const uint32_t,
    const unsigned char*,
    const uint32_t*,
    const unsigned char*,
    const uint32_t*,
    unsigned char*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Encrypt is not currently available.");
}

void PlatformAes128Encrypt(
    const uint32_t,
    const unsigned char*,
    const uint32_t,
    unsigned char*,
    const uint32_t,
    unsigned char*,
    uint32_t*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Encrypt is not currently available.");
}

void PlatformAes128Encrypt(
    const uint32_t,
    const uint32_t*,
    const unsigned char*,
    const uint32_t*,
    unsigned char*,
    const uint32_t,
    unsigned char*,
    uint32_t*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Encrypt is not currently available.");
}
// ========================== END PlatformAes128Encrypt =========================

// ============================ PlatformAes128Decrypt ===========================
void PlatformAes128Decrypt(
    const unsigned char*,
    const uint32_t,
    const unsigned char*,
    const uint32_t,
    unsigned char*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Decrypt is not currently available.");
}

void PlatformAes128Decrypt(
    const uint32_t,
    const unsigned char*,
    const uint32_t*,
    const unsigned char*,
    const uint32_t*,
    unsigned char*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Decrypt is not currently available.");
}

void PlatformAes128Decrypt(
    const bool,
    const uint32_t,
    const unsigned char*,
    const uint32_t,
    const unsigned char*,
    const uint32_t,
    unsigned char*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Decrypt is not currently available.");
}

void PlatformAes128Decrypt(
    const uint32_t,
    const bool,
    const uint32_t,
    const unsigned char*,
    const uint32_t*,
    const unsigned char*,
    const uint32_t*,
    unsigned char*,
    const EncryptionMode) {
  LOG_FATAL(
      "Linux-Specific implementation of Aes128Decrypt is not currently available.");
}
// ========================== END PlatformAes128Decrypt =========================

}  // namespace encryption
}  // namespace crypto
