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

#include "test_utils.h"

#include "GenericUtils/init_utils.h"  // For GetUseLogColors().
#include "StringUtils/string_utils.h"
#include "TestUtils/timer_utils.h"

#include <chrono>
#include <iostream>
#include <set>
#include <string>

using namespace string_utils;
using namespace std;
using namespace std::chrono;

static uint32_t kNumSuccessfulTests = 0;
static uint32_t kNumFailedTests = 0;

namespace test_utils {

static Timer kTotalTime;

static bool kIsColorToggleSet = false;

static char kColorBlack[] = "\033[0m";
static char kColorRed[] = "\033[0;31m";
static char kColorGreen[] = "\033[0;32m";
static char kTerminalPromptUp[] = "\033[1A";
static char kTerminalPromptHome[] = "\033[K";

// The following function is necessary to allow command-line flag --nlog_color
// to turn off logging colors.
void SetColors() {
  if (kIsColorToggleSet) return;
  kIsColorToggleSet = true;
  if (GetUseLogColors()) return;
  // User specified --nlog_colors on command-line. Turn off colors.
  kColorBlack[0] = 0;
  kColorRed[0] = 0;
  kColorGreen[0] = 0;
  kTerminalPromptUp[0] = 0;
  kTerminalPromptHome[0] = 0;
}

uint32_t GetNumFailedTests() { return kNumFailedTests; }
uint32_t GetNumPassedTests() { return kNumSuccessfulTests; }

void TestFunction(
    const bool erase_testing_message,
    const string& function_name,
    bool (*function_ptr)(void*),
    void* args,
    set<string>* failed_tests) {
  SetColors();

  // Print "Testing function_name..." message.
  cout << "[Testing " + function_name + "...]" << endl;

  // Perform test.
  Timer t;
  StartTimer(&t);
  const bool success = (*function_ptr)(args);
  StopTimer(&t);
  const int64_t test_time = GetElapsedTime(t);
  kTotalTime.elapsed_time_ += chrono::microseconds(test_time);

  // Print test result.
  if (success) {
    // Move terminal cursor, so that the "Testing function_name..." message gets
    // overwritten by the "PASSED/FAILED" message.
    // UPDATE: Sometimes the function being run outputs something, and then the
    // wrong line gets overwritten; so only do this if test.cpp explicitly says to.
    if (erase_testing_message) cout << kTerminalPromptUp;
    kNumSuccessfulTests++;
    cout << kColorGreen << "[PASSED: " << function_name;
  } else {
    kNumFailedTests++;
    cout << kColorRed << "[FAILED: " << function_name;
    if (failed_tests != nullptr) failed_tests->insert(function_name);
  }
  // Print test time.
  cout << " (" << FormatTime(test_time / 1000) << ")]";

  // Reset color to black, and overwrite the rest of the line.
  cout << kTerminalPromptHome << kColorBlack << endl;
}

void TestFunction(
    const bool erase_testing_message,
    const string& function_name,
    bool (*function_ptr)(const void*),
    const void* args,
    set<string>* failed_tests) {
  SetColors();

  // Print "Testing function_name..." message.
  cout << "[Testing " + function_name + "...]" << endl;

  // Perform test.
  Timer t;
  StartTimer(&t);
  const bool success = (*function_ptr)(args);
  StopTimer(&t);
  const int64_t test_time = GetElapsedTime(t);
  kTotalTime.elapsed_time_ += chrono::microseconds(test_time);

  // Print test result.
  if (success) {
    // Move terminal cursor, so that the "Testing function_name..." message gets
    // overwritten by the "PASSED/FAILED" message.
    // UPDATE: Sometimes the function being run outputs something, and then the
    // wrong line gets overwritten; so only do this if test.cpp explicitly says to.
    if (erase_testing_message) cout << kTerminalPromptUp;
    kNumSuccessfulTests++;
    cout << kColorGreen << "[PASSED: " << function_name;
  } else {
    kNumFailedTests++;
    cout << kColorRed << "[FAILED: " << function_name;
    if (failed_tests != nullptr) failed_tests->insert(function_name);
  }
  // Print test time.
  cout << " (" << FormatTime(test_time / 1000) << ")]";

  // Reset color to black, and overwrite the rest of the line.
  cout << kTerminalPromptHome << kColorBlack << endl;
}

void TestFunction(
    const bool erase_testing_message,
    const string& function_name,
    bool (*function_ptr)(),
    set<string>* failed_tests) {
  // Print "Testing function_name..." message.
  cout << "[Testing " + function_name + "...]" << endl;

  // Perform test.
  Timer t;
  StartTimer(&t);
  const bool success = (*function_ptr)();
  StopTimer(&t);
  const int64_t test_time = GetElapsedTime(t);
  kTotalTime.elapsed_time_ += chrono::microseconds(test_time);

  // Print test result.
  if (success) {
    // Move terminal cursor, so that the "Testing function_name..." message gets
    // overwritten by the "PASSED/FAILED" message.
    // UPDATE: Sometimes the function being run outputs something, and then the
    // wrong line gets overwritten; so only do this if test.cpp explicitly says to.
    if (erase_testing_message) cout << kTerminalPromptUp;
    kNumSuccessfulTests++;
    cout << kColorGreen << "[PASSED: " << function_name;
  } else {
    kNumFailedTests++;
    cout << kColorRed << "[FAILED: " << function_name;
    if (failed_tests != nullptr) failed_tests->insert(function_name);
  }
  // Print test time.
  cout << " (" << FormatTime(test_time / 1000) << ")]";

  // Reset color to black, and overwrite the rest of the line.
  cout << kTerminalPromptHome << kColorBlack << endl;
}

void TestFunction(
    const string& function_name,
    bool (*function_ptr)(void*),
    void* args,
    set<string>* failed_tests) {
  TestFunction(true, function_name, function_ptr, args, failed_tests);
}

void TestFunction(
    const string& function_name,
    bool (*function_ptr)(const void*),
    const void* args,
    set<string>* failed_tests) {
  TestFunction(true, function_name, function_ptr, args, failed_tests);
}

void TestFunction(
    const string& function_name,
    bool (*function_ptr)(),
    set<string>* failed_tests) {
  TestFunction(true, function_name, function_ptr, failed_tests);
}

void TestFunction(const string& function_name, bool (*function_ptr)()) {
  TestFunction(function_name, function_ptr, nullptr);
}

void TestFunction(
    const string& function_name, bool (*function_ptr)(void*), void* args) {
  TestFunction(function_name, function_ptr, args, nullptr);
}

void TestFunction(
    const string& function_name,
    bool (*function_ptr)(const void*),
    const void* args) {
  TestFunction(function_name, function_ptr, args, nullptr);
}

void PrintTestStats(const set<string>& failed_tests) {
  SetColors();
  if (kNumFailedTests == 0) {
    cout << endl
         << kColorGreen << "All Tests (" << kNumSuccessfulTests << ") Passed ("
         << GetElapsedTimeString(kTotalTime) << ")!" << kColorBlack << endl
         << endl;
  } else {
    cout << endl
         << kColorGreen << kNumSuccessfulTests << " Tests Passed" << kColorBlack
         << endl;
    string failed_test_list =
        failed_tests.empty() ? "" : (": " + Join(failed_tests, ", "));
    cout << kColorRed << kNumFailedTests << " Tests Failed" << failed_test_list
         << kColorBlack << endl
         << "Total Test Time: " << GetElapsedTimeString(kTotalTime) << endl
         << endl;
  }
}

void PrintTestStats() { PrintTestStats(set<string>()); }

bool AllTestsPassed() {
  PrintTestStats();
  return kNumFailedTests == 0;
}

}  // namespace test_utils
