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

#include <Crypto/MultiPartyComputation/Demos/n_party_mpc_by_gate_cookie_socket.h>
#include <Crypto/MultiPartyComputation/Demos/two_party_mpc_cookie_socket.h>
#include <GenericUtils/init_utils.h>
#include <LoggingUtils/logging_utils.h>
#include <MathUtils/data_structures.h>
#include <Networking/cookie_socket.h>
#include <Networking/socket.h>
#include <algorithm>
#include <cstring>
#include <functional>
#include <jni.h>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

using jstringArray = jobjectArray;

struct Cookie {
  JNIEnv * env;
  jobject obj;
  jmethodID jniSend;
  jmethodID jniRecv;
  jobject channel;
};

static ssize_t cookieSend(
  void * const cookie,
  void const * const buf,
  size_t const len
) {
  using len_type = std::remove_cv<decltype(len)>::type;
  using ret_type = ssize_t;
  Cookie const * const c{static_cast<Cookie const *>(cookie)};
  unsigned char const * b{static_cast<unsigned char const *>(buf)};
  len_type n = len;
  while (n > 0) {
    using kt =
      std::common_type<
        std::make_unsigned<len_type>::type,
        std::make_unsigned<jsize>::type,
        std::size_t
      >::type
    ;
    jsize const k{
      static_cast<jsize>(
        std::min({
          static_cast<kt>(n),
          static_cast<kt>(std::numeric_limits<jsize>::max()),
          static_cast<kt>(std::numeric_limits<std::size_t>::max())
        })
      )
    };
    // "Leaking" x1 is okay when an error occurs, as it will be
    // collected when we return control to Java shortly afterward.
    jbyteArray const x1{c->env->NewByteArray(k)};
    if (x1 == nullptr) {
      return -1;
    }
    void * const x3{c->env->GetPrimitiveArrayCritical(x1, nullptr)};
    if (x3 == nullptr) {
      return -1;
    }
    std::memcpy(x3, b, static_cast<std::size_t>(k));
    c->env->ReleasePrimitiveArrayCritical(x1, x3, 0);
    c->env->CallVoidMethod(
      c->obj,
      c->jniSend,
      c->channel,
      x1
    );
    if (c->env->ExceptionCheck() != JNI_FALSE) {
      return -1;
    }
    c->env->DeleteLocalRef(static_cast<jobject>(x1));
    b += k;
    n -= static_cast<len_type>(k);
  }
  return static_cast<ret_type>(len);
}

static ssize_t cookieRecv(
  void * const cookie,
  void * const buf,
  size_t const len
) {
  using len_type = std::remove_cv<decltype(len)>::type;
  using ret_type = ssize_t;
  Cookie const * const c{static_cast<Cookie const *>(cookie)};
  unsigned char * b{static_cast<unsigned char *>(buf)};
  len_type n = len;
  while (n > 0) {
    using kt =
      std::common_type<
        std::make_unsigned<len_type>::type,
        std::make_unsigned<jsize>::type,
        std::size_t
      >::type
    ;
    jsize const k{
      static_cast<jsize>(
        std::min({
          static_cast<kt>(n),
          static_cast<kt>(std::numeric_limits<jsize>::max()),
          static_cast<kt>(std::numeric_limits<std::size_t>::max())
        })
      )
    };
    // "Leaking" x1 is okay when an error occurs, as it will be
    // collected when we return control to Java shortly afterward.
    jbyteArray const x1{c->env->NewByteArray(k)};
    if (x1 == nullptr) {
      return -1;
    }
    c->env->CallVoidMethod(
      c->obj,
      c->jniRecv,
      c->channel,
      x1
    );
    if (c->env->ExceptionCheck() != JNI_FALSE) {
      return -1;
    }
    void * const x3{c->env->GetPrimitiveArrayCritical(x1, nullptr)};
    if (x3 == nullptr) {
      return -1;
    }
    std::memcpy(b, x3, static_cast<std::size_t>(k));
    c->env->ReleasePrimitiveArrayCritical(x1, x3, 0);
    c->env->DeleteLocalRef(static_cast<jobject>(x1));
    b += k;
    n -= static_cast<len_type>(k);
  }
  return static_cast<ret_type>(len);
}

// std::vector<T>(n) for any nonnegative integer n of any type.
template<class T, class U>
static std::vector<T> make_vector(
  U const n
) {
  using V = std::vector<T>;
  if (
    static_cast<typename std::make_unsigned<U>::type>(n) >
    std::numeric_limits<typename V::size_type>::max()
  ) {
    throw std::overflow_error{"size_type overflow"};
  }
  return V(static_cast<typename V::size_type>(n));
}

namespace {

void log_argv(std::vector<std::string> const & argv) {
  std::string s = "calling nonmain:";
  for (std::string const & arg : argv) {
    s += ' ';
    s += arg;
  }
  LOG_INFO(s);
}

} // namespace

extern "C" JNIEXPORT jint JNICALL
Java_com_stealthsoftwareinc_bmc_MpcTask_jniCall(
  JNIEnv * const env,
  jobject const obj,
  jint const func,
  jobjectArray const args,
  jobjectArray const channels,
  jstringArray const results,
  jstringArray const log
) {

  try {

    jclass const cls{env->GetObjectClass(obj)};
    if (cls == nullptr) {
      return -1;
    }

    jmethodID const jniSetErrorMethod{
      env->GetMethodID(
        cls,
        "jniSetError",
        "(Ljava/lang/String;)V"
      )
    };
    if (jniSetErrorMethod == nullptr) {
      return -1;
    }
    auto const jniSetError{
      [=](std::string const & s) {
        jthrowable const e{env->ExceptionOccurred()};
        env->ExceptionClear();
        jstring const t{env->NewStringUTF(s.c_str())};
        env->ExceptionClear();
        env->CallVoidMethod(obj, jniSetErrorMethod, t);
        if (e != nullptr) {
          env->ExceptionClear();
          env->Throw(e);
        }
      }
    };

    jmethodID const jniSend{
      env->GetMethodID(
        cls,
        "jniSend",
        "(Lcom/stealthsoftwareinc/bmc/MpcTask$Channel;[B)V"
      )
    };
    if (jniSend == nullptr) {
      jniSetError(
        "failed to look up jniSend"
      );
      return -1;
    }

    jmethodID const jniRecv{
      env->GetMethodID(
        cls,
        "jniRecv",
        "(Lcom/stealthsoftwareinc/bmc/MpcTask$Channel;[B)V"
      )
    };
    if (jniRecv == nullptr) {
      jniSetError(
        "failed to look up jniRecv"
      );
      return -1;
    }

    jsize const argsLength{env->GetArrayLength(args)};
    if (argsLength > std::numeric_limits<jsize>::max() - 1) {
      jniSetError("jsize overflow");
      return -1;
    }
    auto argVec{make_vector<std::string>(argsLength + 1)};
    for (jsize i{0}; i != argsLength; ++i) {
      jobject const x1{env->GetObjectArrayElement(args, i)};
      if (x1 == nullptr) {
        jniSetError(
          "args contains a null"
        );
        return -1;
      }
      jstring const x2{static_cast<jstring>(x1)};
      char const * const x3{env->GetStringUTFChars(x2, nullptr)};
      if (x3 == nullptr) {
        jniSetError(
          "GetStringUTFChars failed"
        );
        return -1;
      }
      auto const x4{
        std::unique_ptr<
          char const,
          std::function<void (char const *)>
        >(
          x3,
          [=](char const *) {
            env->ReleaseStringUTFChars(x2, x3);
          }
        )
      };
      argVec[i + 1] = x3;
    }

    jsize const partyCount{env->GetArrayLength(channels)};
    if (partyCount < 2) {
      jniSetError(
        "partyCount < 2"
      );
      return -1;
    }

    jsize partyIndex{partyCount};
    auto cookies{make_vector<Cookie>(partyCount)};
    auto cookieSockets{make_vector<networking::CookieSocketParams>(partyCount)};
    for (jsize i{0}; i != partyCount; ++i) {
      cookieSockets[i].type_ = networking::SocketType::COOKIE;
      jobject const channel{env->GetObjectArrayElement(channels, i)};
      if (channel == nullptr) {
        if (partyIndex != partyCount) {
          jniSetError(
            "channels contains more than one null"
          );
          return -1;
        }
        partyIndex = i;
      } else {
        cookies[i].env = env;
        cookies[i].obj = obj;
        cookies[i].jniSend = jniSend;
        cookies[i].jniRecv = jniRecv;
        cookies[i].channel = channel;
        cookieSockets[i].cookie_ = &cookies[i];
        cookieSockets[i].functions_.send_ = &cookieSend;
        cookieSockets[i].functions_.recv_ = &cookieRecv;
      }
    }
    if (partyIndex == partyCount) {
      jniSetError(
        "channels does not contain a null"
      );
      return -1;
    }

    static std::mutex mutex;
    std::lock_guard<std::mutex> lock{mutex};

    // A std::stringstream that copies itself to log[0] on destruction
    // if log is not a null pointer.
    class Logger {
      JNIEnv * const env;
      jstringArray const log;
    public:
      std::stringstream stream;
      Logger(
        JNIEnv * const env,
        jstringArray const log
      ) :
        env{env},
        log{log},
        stream{}
      {
      }
      Logger(
        Logger const &
      ) = delete;
      Logger & operator =(
        Logger const &
      ) = delete;
      ~Logger(
      ) {
        if (log != nullptr) {
          jthrowable const e{env->ExceptionOccurred()};
          env->ExceptionClear();
          jstring x1;
          try {
            x1 = env->NewStringUTF(stream.str().c_str());
          } catch (...) {
            x1 = nullptr;
          }
          env->ExceptionClear();
          jobject const x2 = static_cast<jobject>(x1);
          env->SetObjectArrayElement(log, 0, x2);
          if (e != nullptr) {
            env->ExceptionClear();
            env->Throw(e);
          }
        }
      }
    } logger{env, log};
    if (log == nullptr) {
      SetLogStream(nullptr);
    } else {
      SetUseLogColors(false);
      SetLogStream(&logger.stream);
    }

    int const funcNPartyMpcByGate{0};
    int const funcTwoPartyMpc{1};

    std::vector<math_utils::GenericValue> outputs;

    switch (func) {

      case funcNPartyMpcByGate: {
        argVec[0] = "n_party_cookie_socket_nonmain";
        log_argv(argVec);
        int const s{
          n_party_cookie_socket_nonmain(
            argVec,
            cookieSockets,
            &outputs
          )
        };
        if (s != 0) {
          jniSetError(
            "n_party_cookie_socket_nonmain failed"
          );
          return -1;
        }
      } break;

      case funcTwoPartyMpc: {
        argVec[0] = "two_party_cookie_socket_nonmain";
        log_argv(argVec);
        int const s{
          two_party_cookie_socket_nonmain(
            argVec,
            cookieSockets,
            &outputs
          )
        };
        if (s != 0) {
          jniSetError(
            "two_party_cookie_socket_nonmain failed"
          );
          return -1;
        }
      } break;

      default: {
        jniSetError(
          "unknown func"
        );
        return -1;
      } break;

    }

    std::string x1;
    for (decltype(outputs.size()) i{0}; i != outputs.size(); ++i) {
      if (i != 0) {
        x1 += ',';
      }
      x1 += GetGenericValueString(outputs[i]);
    }
    jstring const x2{env->NewStringUTF(x1.c_str())};
    if (x2 == nullptr) {
      return -1;
    }
    env->SetObjectArrayElement(results, 0, x2);

    return 0;

  } catch (...) {
    return -1;
  }

}
