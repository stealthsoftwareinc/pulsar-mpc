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
//   Logging Utility functions. Messages are characterized as follows:
//   1) There are 4 levels of logging:
//        a) INFO:    General information that may be useful, but doesn't
//                    reflect anything unusual or problematic.
//        b) WARNING: Something unusual occured. Code should proceed as
//                    usual, but a warning message is printed.
//        c) ERROR:   Something unexpected happened. Code will still
//                    proceed as usual, but error message is printed
//        d) FATAL:   Prints the error message and terminates the program
//      Note that the only difference between (a), (b), and (c) is how the
//      message is printed to the terminal (font color and log preamble).
//   2) CHECK: Use this to evaluate the input expression, and do nothing
//      if true; but if false, call LOG_FATAL on the message.
//   3) For each of the above types (CHECK, LOG_[INFO | WARNING | ERROR]),
//      you can prepend 'D' to indicate the check/logging should only be
//      done when compiling in debug mode.

#ifndef LOGGING_UTILS_H
#define LOGGING_UTILS_H

#include <iostream>
#include <string>

// Functions for getting and setting the log stream. The default is
// std::cout. You can set it to null to disable logging.
extern std::ostream* GetLogStream();
extern void SetLogStream(std::ostream*);

// Use global namespace, so we don't need to preface each LOG command with a
// namespace (and don't need 'using namespace ...' at the top of each file).
extern void LOG_INFO(const std::string& message);
extern void LOG_WARNING(const std::string& message);
// Prints an empty line to terminal (useful if you want a blank line before
// using e.g. LOG_INFO(), since prepending "\n" as part of the input 'message'
// won't work (the 'LOG_INFO' text will print before the '\n' does).
extern void LOG_LINE();

// Logging with verbosity.
extern void VLOG(const int level, const std::string& message);

// Same as above, also prints time.
extern void TLOG_INFO(const std::string& message);
extern void TLOG_WARNING(const std::string& message);
extern void VTLOG(const int level, const std::string& message);

// Debug versions of the above: Only prints message to terminal if program
// was compiled in debug mode (compile with -D debug or -Ddebug to turn on
// debugging, or -Dndebug or -D ndebug to turn it off; default is 'on').
extern void DLOG_INFO(const std::string& message);
extern void DLOG_WARNING(const std::string& message);

// Same as above, also prints time.
extern void DTLOG_INFO(const std::string& message);
extern void DTLOG_WARNING(const std::string& message);

// Functions called by the Macros defined at the bottom of this file:
//   - [T | D | DT]LOG_ERROR
//   - [T | D | DT]LOG_FATAL
//   - [T | D | DT]CHECK
extern void LogError(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const std::string& message);
inline void LogError(
    const std::string& filename,
    const size_t& line,
    const std::string& message) {
  LogError(filename, line, "", message);
}
extern void TLogError(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const std::string& message);
inline void TLogError(
    const std::string& filename,
    const size_t& line,
    const std::string& message) {
  TLogError(filename, line, "", message);
}
extern void DLogError(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const std::string& message);
inline void DLogError(
    const std::string& filename,
    const size_t& line,
    const std::string& message) {
  DLogError(filename, line, "", message);
}
extern void DTLogError(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const std::string& message);
inline void DTLogError(
    const std::string& filename,
    const size_t& line,
    const std::string& message) {
  DTLogError(filename, line, "", message);
}
extern void LogFatal(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const std::string& message);
inline void LogFatal(
    const std::string& filename,
    const size_t& line,
    const std::string& message) {
  LogFatal(filename, line, "", message);
}
extern void TLogFatal(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const std::string& message);
inline void TLogFatal(
    const std::string& filename,
    const size_t& line,
    const std::string& message) {
  TLogFatal(filename, line, "", message);
}
extern void DLogFatal(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const std::string& message);
inline void DLogFatal(
    const std::string& filename,
    const size_t& line,
    const std::string& message) {
  DLogFatal(filename, line, "", message);
}
extern void DTLogFatal(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const std::string& message);
inline void DTLogFatal(
    const std::string& filename,
    const size_t& line,
    const std::string& message) {
  DTLogFatal(filename, line, "", message);
}
// NOTE: There are four possible settings you may want for CHECK:
//   a) Always check, always print message
//   b) Always check, print message if debug mode
//   c) Always check, never print message
//   d) Check iff debug mode, print message if debug mode
//   e) Check iff debug mode, never print message
// For (a) and (c), use the appropriate CHECK() api. For (e), use the bottom
// DCHECK() api. Then there was a choice of whether to make the top DCHECK
// api do (b) or (d); I went with (b), as I think this is the more useful case.
extern void Check(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input,
    const std::string& message);
inline void Check(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input) {
  Check(filename, line, function_name, input, "");
}
inline void CheckTwo(
    const std::string& filename,
    const size_t& line,
    const bool input,
    const std::string& message) {
  Check(filename, line, "", input, message);
}
inline void CheckTwo(
    const std::string& filename, const size_t& line, const bool input) {
  Check(filename, line, "", input, "");
}
extern void TCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input,
    const std::string& message);
inline void TCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input) {
  TCheck(filename, line, function_name, input, "");
}
inline void TCheckTwo(
    const std::string& filename,
    const size_t& line,
    const bool input,
    const std::string& message) {
  TCheck(filename, line, "", input, message);
}
inline void TCheckTwo(
    const std::string& filename, const size_t& line, const bool input) {
  TCheck(filename, line, "", input, "");
}
extern void DCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input,
    const std::string& message);
inline void DCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input) {
  DCheck(filename, line, function_name, input, "");
}
inline void DCheckTwo(
    const std::string& filename,
    const size_t& line,
    const bool input,
    const std::string& message) {
  DCheck(filename, line, "", input, message);
}
inline void DCheckTwo(
    const std::string& filename, const size_t& line, const bool input) {
  DCheck(filename, line, "", input, "");
}
extern void DTCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input,
    const std::string& message);
inline void DTCheck(
    const std::string& filename,
    const size_t& line,
    const std::string& function_name,
    const bool input) {
  DTCheck(filename, line, function_name, input, "");
}
inline void DTCheckTwo(
    const std::string& filename,
    const size_t& line,
    const bool input,
    const std::string& message) {
  DTCheck(filename, line, "", input, message);
}
inline void DTCheckTwo(
    const std::string& filename, const size_t& line, const bool input) {
  DTCheck(filename, line, "", input, "");
}

// Macros to pass the File, Line Number, and Function name (if supported)
// to logging.
// NOTE: Macro resolution, required below, takes a non-trivial amount of time
// (~0.2 seconds per 1Million calls). While this isn't likely to be a problem
// for LOG_ERROR() or LOG_FATAL(), since these only occur when an error occurs,
// this *CAN* be a problem for [DT]CHECK, since that is called even when no
// error occurs. Thus, in places that require high-performance and will be
// called many (>10k) times, don't use [DT]CHECK; prefer instead
// "if(...) {[DT]LOG_FATAL(...);}" blocks, which behave equivalently to [DT]CHECK,
// but only incur the macro-resolution overhead when there is an error.
#ifdef __func__
#define LOG_ERROR(message) LogError(__FILE__, __LINE__, __func__, message)
#define TLOG_ERROR(message) TLogError(__FILE__, __LINE__, __func__, message)
#define DLOG_ERROR(message) DLogError(__FILE__, __LINE__, __func__, message)
#define DTLOG_ERROR(message) DTLogError(__FILE__, __LINE__, __func__, message)
#define LOG_FATAL(message) LogFatal(__FILE__, __LINE__, __func__, message)
#define TLOG_FATAL(message) TLogFatal(__FILE__, __LINE__, __func__, message)
#define DLOG_FATAL(message) DLogFatal(__FILE__, __LINE__, __func__, message)
#define DTLOG_FATAL(message) DTLogFatal(__FILE__, __LINE__, __func__, message)
// The following trick allows the definition of multiple functions (macros)
// called 'CHECK', with the appropriate one being called based on the
// number of input parameters.
#define CHECK1(input) Check(__FILE__, __LINE__, __func__, input)
#define CHECK2(input, message) \
  Check(__FILE__, __LINE__, __func__, input, message)
#define CHECK_MACRO(_1, _2, NAME, ...) NAME
#define CHECK(...) CHECK_MACRO(__VA_ARGS__, CHECK2, CHECK1)(__VA_ARGS__)
#define TCHECK1(input) TCheck(__FILE__, __LINE__, __func__, input)
#define TCHECK2(input, message) \
  TCheck(__FILE__, __LINE__, __func__, input, message)
#define TCHECK_MACRO(_1, _2, NAME, ...) NAME
#define TCHECK(...) TCHECK_MACRO(__VA_ARGS__, TCHECK2, TCHECK1)(__VA_ARGS__)
#define DCHECK1(input) DCheck(__FILE__, __LINE__, __func__, input)
#define DCHECK2(input, message) \
  DCheck(__FILE__, __LINE__, __func__, input, message)
#define DCHECK_MACRO(_1, _2, NAME, ...) NAME
#define DCHECK(...) DCHECK_MACRO(__VA_ARGS__, DCHECK2, DCHECK1)(__VA_ARGS__)
#define DTCHECK1(input) DTCheck(__FILE__, __LINE__, __func__, input)
#define DTCHECK2(input, message) \
  DTCheck(__FILE__, __LINE__, __func__, input, message)
#define DTCHECK_MACRO(_1, _2, NAME, ...) NAME
#define DTCHECK(...) DTCHECK_MACRO(__VA_ARGS__, DTCHECK2, DTCHECK1)(__VA_ARGS__)
#else
#define LOG_ERROR(message) LogError(__FILE__, __LINE__, message)
#define TLOG_ERROR(message) TLogError(__FILE__, __LINE__, message)
#define DLOG_ERROR(message) DLogError(__FILE__, __LINE__, message)
#define DTLOG_ERROR(message) DTLogError(__FILE__, __LINE__, message)
#define LOG_FATAL(message) LogFatal(__FILE__, __LINE__, message)
#define TLOG_FATAL(message) TLogFatal(__FILE__, __LINE__, message)
#define DLOG_FATAL(message) DLogFatal(__FILE__, __LINE__, message)
#define DTLOG_FATAL(message) DTLogFatal(__FILE__, __LINE__, message)
// The following trick allows the definition of multiple functions (macros)
// called 'CHECK', with the appropriate one being called based on the
// number of input parameters.
#define CHECK1(input) CheckTwo(__FILE__, __LINE__, input)
#define CHECK2(input, message) CheckTwo(__FILE__, __LINE__, input, message)
#define CHECK_MACRO(_1, _2, NAME, ...) NAME
#define CHECK(...) CHECK_MACRO(__VA_ARGS__, CHECK2, CHECK1)(__VA_ARGS__)
#define TCHECK1(input) TCheckTwo(__FILE__, __LINE__, input)
#define TCHECK2(input, message) TCheckTwo(__FILE__, __LINE__, input, message)
#define TCHECK_MACRO(_1, _2, NAME, ...) NAME
#define TCHECK(...) TCHECK_MACRO(__VA_ARGS__, TCHECK2, TCHECK1)(__VA_ARGS__)
#define DCHECK1(input) DCheckTwo(__FILE__, __LINE__, input)
#define DCHECK2(input, message) DCheckTwo(__FILE__, __LINE__, input, message)
#define DCHECK_MACRO(_1, _2, NAME, ...) NAME
#define DCHECK(...) DCHECK_MACRO(__VA_ARGS__, DCHECK2, DCHECK1)(__VA_ARGS__)
#define DTCHECK1(input) DTCheckTwo(__FILE__, __LINE__, input)
#define DTCHECK2(input, message) DTCheckTwo(__FILE__, __LINE__, input, message)
#define DTCHECK_MACRO(_1, _2, NAME, ...) NAME
#define DTCHECK(...) DTCHECK_MACRO(__VA_ARGS__, DTCHECK2, DTCHECK1)(__VA_ARGS__)
#endif

#endif
