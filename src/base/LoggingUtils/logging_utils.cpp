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
// Discussion:
//   Logging Utility functions. To turn on/off the "D" logging options,
//   specify:
//      -D debug
//   on the command line; if no '-D debug' command-line argument is present,
//   the default is to ignore "D"-prefixes, e.g. DLOG_INFO.

#include "logging_utils.h"

#include "GenericUtils/init_utils.h"  // For GetVerbosity(), GetMsTimeStr().

#include <atomic>
#include <iostream>  // For cout
#include <sstream>  // For ostringstream (for converting __LINE__ to string).
#include <string>

using namespace std;

#ifdef debug
#define IS_DEBUG 1
#else
#define IS_DEBUG 0
#endif

namespace {
// The following is copy-pasted from read_file_utils.cpp, but put here to
// avoid including that (larger) file.
string GetFileName(const string& filepath) {
  size_t last_dir = filepath.find_last_of("/");
  if (last_dir == string::npos) {
    // Windows may use '\' instead of '/'. Check for that as well.
    last_dir = filepath.find_last_of("\\");
    if (last_dir == string::npos) return filepath;
  }
  if (last_dir == filepath.length() - 1) return "";
  return filepath.substr(last_dir + 1);
}
}  // namespace

static std::atomic<std::ostream*> kLogStream(&std::cout);
std::ostream* GetLogStream() { return kLogStream; }
void SetLogStream(std::ostream* s) { kLogStream = s; }

// ANSI color codes. If you don't want colors, you can do one of two
// things to turn them off:
//   1) (Compile-Time): Compile with command-line option: -DCOLOR_OFF
//   2) (Run-Time): Run program with command-line option --nlog_color
#ifdef COLOR_OFF
#define COUT_BLACK ""
#define COUT_RED ""
#define COUT_GREEN ""
#define COUT_ORANGE ""
#define COUT_BLUE ""
#define COUT_PURPLE ""
#define COUT_CYAN ""
#define COUT_GRAY ""
#define COUT_WHITE ""
#else
#define COUT_BLACK "\033[0m"
#define COUT_RED "\033[0;31m"
#define COUT_GREEN "\033[0;32m"
#define COUT_ORANGE "\033[0;33m"
#define COUT_BLUE "\033[0;34m"
#define COUT_PURPLE "\033[0;35m"
#define COUT_CYAN "\033[0;36m"
#define COUT_GRAY "\033[0;37m"
#define COUT_WHITE "\033[1;37m"
#endif

static bool kIsColorSet = false;

static char kColorBlack[] = COUT_BLACK;
static char kColorRed[] = COUT_RED;
static char kColorGreen[] = COUT_GREEN;
static char kColorOrange[] = COUT_ORANGE;
static char kColorBlue[] = COUT_BLUE;
static char kColorPurple[] = COUT_PURPLE;
static char kColorCyan[] = COUT_CYAN;
static char kColorGray[] = COUT_GRAY;
static char kColorWhite[] = COUT_WHITE;

// The following function is necessary to allow command-line flag --nlog_color
// to turn off logging colors.
void SetColors() {
  if (kIsColorSet) return;
  kIsColorSet = true;
  if (GetUseLogColors()) return;
  // User specified --nlog_colors on command-line. Turn off colors.
  kColorBlack[0] = 0;
  kColorRed[0] = 0;
  kColorGreen[0] = 0;
  kColorOrange[0] = 0;
  kColorBlue[0] = 0;
  kColorPurple[0] = 0;
  kColorCyan[0] = 0;
  kColorGray[0] = 0;
  kColorWhite[0] = 0;
}

void LOG_LINE() {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    *log_stream << endl;
  }
}

void LOG_INFO(const string& message) {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    SetColors();
    *log_stream << kColorGreen << "INFO: " << kColorBlack << message << endl;
  }
}
void TLOG_INFO(const string& message) {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    SetColors();
    *log_stream << kColorGreen << GetMsTimeStr() << " INFO: " << kColorBlack
                << message << endl;
  }
}
void DLOG_INFO(const string& message) {
  if (IS_DEBUG) LOG_INFO(message);
}
void TDLOG_INFO(const string& message) {
  if (IS_DEBUG) TLOG_INFO(message);
}

void LOG_WARNING(const string& message) {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    SetColors();
    *log_stream << endl
                << kColorOrange << "WARNING: " << kColorBlack << message << endl;
  }
}
void TLOG_WARNING(const string& message) {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    SetColors();
    *log_stream << endl
                << kColorOrange << GetMsTimeStr() << " WARNING: " << kColorBlack
                << message << endl;
  }
}
void DLOG_WARNING(const string& message) {
  if (IS_DEBUG) LOG_WARNING(message);
}
void DTLOG_WARNING(const string& message) { DTLOG_WARNING(message); }

void VLOG(const int level, const string& message) {
  if (level >= GetVerbosity()) LOG_INFO(message);
}
void VTLOG(const int level, const string& message) {
  if (level >= GetVerbosity()) TLOG_INFO(message);
}

void LogError(
    const string& filename,
    const size_t& line,
    const string& function_name,
    const string& message) {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    const string ending =
        function_name.empty() ? "" : (" (" + function_name + ")");
    SetColors();
    *log_stream << endl
                << kColorRed << "ERROR in " << GetFileName(filename) << ", line "
                << line << ending << ":\n"
                << kColorBlack << message << endl;
  }
}

void TLogError(
    const string& filename,
    const size_t& line,
    const string& function_name,
    const string& message) {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    const string ending =
        function_name.empty() ? "" : (" (" + function_name + ")");
    SetColors();
    *log_stream << endl
                << kColorRed << GetMsTimeStr() << " ERROR in "
                << GetFileName(filename) << ", line " << line << ending << ":"
                << endl
                << kColorBlack << message << endl;
  }
}

void DLogError(
    const string& filename,
    const size_t& line,
    const string& function_name,
    const string& message) {
  if (IS_DEBUG) LogError(filename, line, function_name, message);
}

void DTLogError(
    const string& filename,
    const size_t& line,
    const string& function_name,
    const string& message) {
  if (IS_DEBUG) TLogError(filename, line, function_name, message);
}

void LogFatal(
    const string& filename,
    const size_t& line,
    const string& function_name,
    const string& message) {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    const string ending =
        function_name.empty() ? "" : (" (" + function_name + ")");
    SetColors();
    if (!message.empty()) {
      *log_stream << endl
                  << kColorPurple << "FATAL ERROR in " << GetFileName(filename)
                  << ", line " << line << ending << ":" << endl
                  << kColorBlack << message << endl;
    } else {
      *log_stream << endl
                  << kColorPurple << "FATAL ERROR in " << GetFileName(filename)
                  << ", line " << line << ending << "." << kColorBlack << endl;
    }
  }
  throw "LOG_FATAL '" + message + "'";
}

void TLogFatal(
    const string& filename,
    const size_t& line,
    const string& function_name,
    const string& message) {
  std::ostream* const log_stream = kLogStream;
  if (log_stream != nullptr) {
    const string ending =
        function_name.empty() ? "" : (" (" + function_name + ")");
    SetColors();
    if (!message.empty()) {
      *log_stream << endl
                  << kColorPurple << GetMsTimeStr() << " FATAL ERROR in "
                  << GetFileName(filename) << ", line " << line << ending << ":"
                  << endl
                  << kColorBlack << message << endl;
    } else {
      *log_stream << endl
                  << kColorPurple << GetMsTimeStr() << " FATAL ERROR in "
                  << GetFileName(filename) << ", line " << line << ending << "."
                  << kColorBlack << endl;
    }
  }
  throw "LOG_FATAL '" + message + "'";
}

void DLogFatal(
    const string& filename,
    const size_t& line,
    const string& function_name,
    const string& message) {
  if (IS_DEBUG) LogFatal(filename, line, function_name, message);
}

void DTLogFatal(
    const string& filename,
    const size_t& line,
    const string& function_name,
    const string& message) {
  if (IS_DEBUG) TLogFatal(filename, line, function_name, message);
}

void Check(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input,
    const string& message) {
  if (!input) LogFatal(filename, line, function_name, message);
}

void TCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input,
    const string& message) {
  if (!input) TLogFatal(filename, line, function_name, message);
}

void DCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input,
    const string& message) {
  if (message.empty()) {
    if (IS_DEBUG) Check(filename, line, function_name, input, message);
  } else {
    Check(filename, line, function_name, input, IS_DEBUG ? message : "");
  }
}
void DTCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input,
    const string& message) {
  if (message.empty()) {
    if (IS_DEBUG) TCheck(filename, line, function_name, input, message);
  } else {
    TCheck(filename, line, function_name, input, IS_DEBUG ? message : "");
  }
}
