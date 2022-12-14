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
//   This file defines variables and functions that get initialized
//   via a call to InitMain(), which is the first thing that all
//   programs should do (i.e. InitMain() should be the first line
//   inside the 'int main()' function).
//   For example, this sets:
//     - Verbosity (log) level
//     - Endianness (Big vs. Little)

#ifndef INIT_UTILS_H
#define INIT_UTILS_H

#include <string>

enum class SYSTEM_ENDIAN {
  UNKNOWN,
  BIG,  // E.g. (uint32_t) 1 = 00000000 00000000 00000000 00000001
  LITTLE,  // E.g. (uint32_t) 1 = 00000001 00000000 00000000 00000000
};

extern SYSTEM_ENDIAN endianness;
extern int verbosity_level;
extern int num_cores;

extern SYSTEM_ENDIAN GetEndianness();
extern int GetVerbosity();
extern void SetVerbosity(const int level);
extern int GetNumCores();
extern bool GetUseLogColors();
extern void SetUseLogColors(const bool use_colors);

// Returns the current time in format:
//   WEEKDAY MONTH DATE HH:MM:SS YYYY
// e.g.:
//   Wed Nov 25 17:25:43 2015
// NOTE: Compiling on some systems (e.g. Cygwin/MinGW) causes issues with
// localtime() not reporting the local time, but GMT time.
extern std::string GetDateAndTime();
// Same as above, but just for the time in HH:MM:SS.ms format.
extern std::string GetTime();
// Same as above, but gives the current time in milliseconds (this is only
// really useful if printing out time in two different places, and you can
// compare those times to each other; i.e. a single time by itself may be
// meaningless/useless).
extern std::string GetMsTimeStr();
extern long long int GetMsTime();
// Same as above, for microseconds.
extern std::string GetMicroTimeStr();
extern long long int GetMicroTime();

// Call the following at the start of every int main() function.
// NOTE: We pass the first argument by reference, so that global command-line
// arguments can be removed in InitMain().
extern bool InitMain(int& argc, char* argv[]);
inline bool InitMain() {
  int temp_argc = 1;
  return InitMain(temp_argc, nullptr);
}

// Same as above, for xxx_test.cpp.
extern bool InitTestMain(int& argc, char* argv[]);
inline bool InitTestMain() {
  int temp_argc = 1;
  return InitTestMain(temp_argc, nullptr);
}

#endif
