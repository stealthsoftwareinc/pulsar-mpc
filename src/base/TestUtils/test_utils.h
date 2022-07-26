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

// Description: Helper functions for Unit Tests.

#include <chrono>  // For std::chrono:: microseconds, timepoint, system_clock, etc.
#include <set>
#include <string>

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

namespace test_utils {

// Use this in unit tests. It will first print out a message to terminal:
//   Testing FUNCTION_NAME...
// Then it will perform the test, so that function_ptr should be a bool function
// that returns true if it passes. Upon completion of the test function, will
// print either:
//   PASSED: FUNCTION_NAME
// or:
//   FAILED: FUNCTION_NAME
// and also the amount of time the test took.
// NOTE: It is assumed the underlying function (in function_ptr) does *not*
// print any output to terminal; in particular, this function overwrites the
// original "Testing FUNCTION_NAME..." with "[PASSED | FAILED]: FUNCTION_NAME"
// in order to keep the terminal output cleaner; but this overwriting is
// performed by moving the terminal cursor up, and so anything printed in
// between (by the function_ptr) will screw up the expected cursor position.
extern void TestFunction(
    const std::string& function_name, bool (*function_ptr)());
// Same as above, but on failure adds the function name to the provided set.
extern void TestFunction(
    const std::string& function_name,
    bool (*function_ptr)(),
    std::set<std::string>* failed_tests);
// Same as above, with API for flag for erasing the "Testing 'TestName' ..." line.
extern void TestFunction(
    const bool erase_testing_message,
    const std::string& function_name,
    bool (*function_ptr)(),
    std::set<std::string>* failed_tests);
// Same as above, but the function callback can have arguments.
extern void TestFunction(
    const std::string& function_name, bool (*function_ptr)(void*), void* args);
// Same as above, but for const args.
extern void TestFunction(
    const std::string& function_name,
    bool (*function_ptr)(const void*),
    const void* args);
// Same as above, but the function callback can have arguments, and failed
// functions get added to the provided set.
extern void TestFunction(
    const std::string& function_name,
    bool (*function_ptr)(void*),
    void* args,
    std::set<std::string>* failed_tests);
// Same as above, but for const args.
extern void TestFunction(
    const std::string& function_name,
    bool (*function_ptr)(const void*),
    const void* args,
    std::set<std::string>* failed_tests);
// Same as above, with API for flag for erasing the "Testing 'TestName' ..." line.
extern void TestFunction(
    const bool erase_testing_message,
    const std::string& function_name,
    bool (*function_ptr)(void*),
    void* args,
    std::set<std::string>* failed_tests);
// Same as above, for const args.
extern void TestFunction(
    const bool erase_testing_message,
    const std::string& function_name,
    bool (*function_ptr)(const void*),
    const void* args,
    std::set<std::string>* failed_tests);

// Returns the (global) number of passed (resp. failed) tests (so far).
extern uint32_t GetNumPassedTests();
extern uint32_t GetNumFailedTests();

// If the unit tests were run using TestFunction(), then a counter kept track
// of how many tests were run. This will then print out an "All Tests Pass!"
// message, which include the number of tests that passed. Further, the total
// amount of time for all tests to run will be printed.
extern void PrintTestStats();
// Same as above, but prints out the names of all the failed tests.
extern void PrintTestStats(const std::set<std::string>& failed_tests);

// Calls PrintTestStats(), and then returns true iff all tests pass.
extern bool AllTestsPassed();

}  // namespace test_utils

#endif
