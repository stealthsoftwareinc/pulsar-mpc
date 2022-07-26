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

#include "string_utils.h"

#include "LoggingUtils/logging_utils.h"

#include <cfloat>  // For DBL_MIN
#include <climits>  // For CHAR_BIT, INT_MAX, LONG_MAX, etc.
#include <cmath>  // For HUGE_VAL
#include <cstdio>
#include <cstdlib>  // For strtol, atof.
#include <cstring>  // For memcpy
#include <limits>  // For numeric_limits.
#include <locale>  // For std::locale, std::tolower, and std::toupper.
#include <set>
#include <sstream>  // For Itoa (uses ostringstream).
#include <string>
#include <tuple>  // For pair.
#include <vector>

using namespace std;

namespace string_utils {

// Returns true if input is a string of length one, representing one
// of the 10 digits (0-9); returns false otherwise.
bool IsStringDigit(const string& input) {
  if (input.length() != 1) {
    return false;
  }
  return (
      input == "0" || input == "1" || input == "2" || input == "3" ||
      input == "4" || input == "5" || input == "6" || input == "7" ||
      input == "8" || input == "9");
}
// Same as above, for char.
bool IsStringDigit(const char input) {
  return (
      input == '0' || input == '1' || input == '2' || input == '3' ||
      input == '4' || input == '5' || input == '6' || input == '7' ||
      input == '8' || input == '9');
}

// Returns true if input is the exponent part of scientific notation,
// e.g. "E+01"; returns false otherwise.
bool IsScientificNotation(const string& input) {
  if (input.length() < 2) {
    return false;
  }
  if (input.substr(0, 1) != "E" && input.substr(0, 1) != "e") {
    return false;
  }
  string rest = input.substr(1);
  for (unsigned int i = 0; i < rest.length(); ++i) {
    if (i == 0 && (rest.substr(i, 1) == "+" || rest.substr(i, 1) == "-")) {
      continue;
    }
    if (!IsStringDigit(rest.substr(i, 1))) {
      return false;
    }
  }
  return true;
}

bool IsAllDigits(const string& input) {
  for (string::const_iterator itr = input.begin(); itr != input.end(); ++itr) {
    if (!IsStringDigit(*itr)) {
      return false;
    }
  }
  return true;
}

// Returns true if str is a string representation of zero (e.g. "0" or "0.0").
bool IsZeroString(const string& input) {
  if (input.empty()) {
    return false;
  }
  const string str = input.substr(0, 1) == "-" ? input.substr(1) : input;
  if (str == "0.0" || str == "0") {
    return true;
  }

  // None of the simple cases above were true, but str may still represent
  // zero, e.g. "0.0000". Instead of testing for every possible length of
  // trailing zeros, we split the string around a decimal point, and test
  // if all characters on either side are '0'.
  vector<string> decimal_parts;
  Split(str, ".", &decimal_parts);
  if (decimal_parts.size() > 2) {
    return false;
  }
  const string& part_one = decimal_parts[0];
  for (unsigned int i = 0; i < part_one.length(); ++i) {
    if (part_one.substr(i, 1) != "0") {
      return false;
    }
  }
  // No decimal, return true.
  if (decimal_parts.size() == 1) {
    return true;
  }

  // Check that all text after decimal are zeros, with one exception that
  // it may be in scientific notation, e.g. 0.00E+00
  const string& part_two = decimal_parts[1];
  for (unsigned int i = 0; i < part_two.length(); ++i) {
    if (part_two.substr(i, 1) == "E" || part_two.substr(i, 1) == "e") {
      return IsScientificNotation(part_two.substr(i));
    }
    if (part_two.substr(i, 1) != "0") {
      return false;
    }
  }

  return true;
}

bool IsNumeric(const string& input) {
  string str = input;

  // Strip enclosing parentheses, and leading plus/minus signs.
  while (HasPrefixString(str, "+") || HasPrefixString(str, "-") ||
         (HasPrefixString(str, "(") && HasSuffixString(str, ")"))) {
    if (HasPrefixString(str, "+") || HasPrefixString(str, "-")) {
      str = str.substr(1);
    } else {
      str = StripPrefixString(str, "(");
      str = StripSuffixString(str, ")");
    }
  }

  // Handle corner-cases
  if (str.empty() || str == "." || str == "+" || str == "-") {
    return false;
  }

  const bool is_hex = HasPrefixString(str, "0x");
  if (is_hex) str = StripPrefixString(str, "0x");

  // Iterate through all characters of string, returning false if any non-digit
  // is encountered, unless the non-digit is a decimal or scientific notation
  // or hex character.
  bool has_decimal = false;
  for (unsigned int i = 0; i < str.length(); ++i) {
    const char current = str.at(i);

    // Handle potential decimal.
    if (current == '.') {
      if (is_hex) {
        // Decimals not allowed for hex.
        return false;
      } else if (has_decimal) {
        // A decimal was already found, so this is the second.
        return false;
      }
      has_decimal = true;
      continue;
    }

    // Handle scientific notation.
    if (current == 'E' || current == 'e') {
      if (is_hex) continue;
      return IsScientificNotation(str.substr(i));
    }

    // Handle valid hex characters.
    if (is_hex) {
      if (current == 'A' || current == 'a' || current == 'B' || current == 'b' ||
          current == 'C' || current == 'c' || current == 'D' || current == 'd' ||
          current == 'E' || current == 'e' || current == 'F' || current == 'f') {
        continue;
      }
    }

    // Return false for any non-numeric character.
    if (!IsStringDigit(current)) {
      return false;
    }
  }
  return true;
}

bool IsScientificNotation(const string& input, double* value) {
  if (!IsNumeric(input)) {
    return false;
  }

  // First check for "e", e.g. "1.43e-10".
  size_t e_pos = input.find("e");
  if (e_pos != string::npos) {
    if (e_pos == 0 || e_pos == input.length() - 1) {
      return false;
    }
    const string first_half = input.substr(0, e_pos);
    if (IsNumeric(first_half) && IsScientificNotation(input.substr(e_pos))) {
      if (value != nullptr) {
        Stod(input, value);
      }
      return true;
    }
    return false;
  }

  // Also check for "E", e.g. "1.43E10"
  size_t E_pos = input.find("E");
  if (E_pos != string::npos) {
    if (E_pos == 0 || E_pos == input.length() - 1) {
      return false;
    }
    const string first_half = input.substr(0, E_pos);
    const string second_half = input.substr(E_pos + 1);
    if (IsNumeric(first_half) && IsScientificNotation(input.substr(E_pos))) {
      if (value != nullptr) {
        Stod(input, value);
      }
      return true;
    }
    return false;
  }

  return false;
}

bool IsScientificNotationWithSign(const string& input, double* value) {
  size_t e_pos = input.find("e");
  size_t E_pos = input.find("E");
  size_t plus_pos = input.find("+");
  size_t neg_pos = input.find("-");
  const bool exactly_one_e = (e_pos != string::npos && E_pos == string::npos) ||
      (e_pos == string::npos && E_pos != string::npos);
  const bool exactly_one_sign =
      (plus_pos != string::npos && neg_pos == string::npos) ||
      (plus_pos == string::npos && neg_pos != string::npos);
  if (!exactly_one_e || !exactly_one_sign) {
    return false;
  }
  const size_t exp_pos = e_pos == string::npos ? E_pos : e_pos;
  const size_t sign_pos = plus_pos == string::npos ? neg_pos : plus_pos;
  if (sign_pos != exp_pos + 1) {
    return false;
  }
  return IsScientificNotation(input, value);
}

void RemoveScientificNotationInternal(pair<string, string>* suffix) {
  const string& input = suffix->second;
  string output = input;
  size_t e_pos = input.find("e");
  size_t E_pos = input.find("E");
  if (e_pos == string::npos && E_pos == string::npos) {
    suffix->first = output;
    suffix->second = "";
    return;
  }
  // Find first occurrence of "e" or "E".
  const size_t exp_pos = e_pos == string::npos ? E_pos :
      E_pos == string::npos                    ? e_pos :
      e_pos < E_pos                            ? e_pos :
                                                 E_pos;

  // If "e" is the first character of the input string, it cannot represent
  // scientific notation. Look for other potential instances further along
  // in the string.
  if (exp_pos == 0) {
    suffix->first = input.substr(0, 1);
    suffix->second = input.substr(1);
    return;
  }
  // Ditto for last character, except no more possible matches beyond.
  if (exp_pos == input.length() - 1) {
    suffix->first = output;
    suffix->second = "";
    return;
  }

  // Check that character after the "e" is either a digit or "+/-" sign.
  const string& next_char = input.substr(exp_pos + 1, 1);
  if (next_char != "+" && next_char != "-" && !IsStringDigit(next_char)) {
    suffix->first = input.substr(0, exp_pos + 1);
    suffix->second = input.substr(exp_pos + 1);
    return;
  }

  // Check that character before the "e" is either a digit or decimal.
  const string& prev_char = input.substr(exp_pos - 1, 1);
  if (prev_char != "." && !IsStringDigit(prev_char)) {
    suffix->first = input.substr(0, exp_pos + 1);
    suffix->second = input.substr(exp_pos + 1);
    return;
  }

  // Current "e" indeed is scientific notation (probably, still have potential
  // corner case, e.g. "Hi. E-Mail is good.", which after removing whitespace,
  // has hit ".E-"; so we need to further make sure that there is at least one
  // digit before and after the "e".

  // Find starting position (first digit of scientific notation).
  bool has_digit_before = false;
  bool has_decimal_before = false;
  size_t sci_notation_begin = exp_pos - 1;
  while (true) {
    const string current_char = input.substr(sci_notation_begin, 1);
    if (current_char == ".") {
      // Check if we've already seen a decimal.
      if (has_decimal_before) {
        break;
      }
      has_decimal_before = true;
      if (sci_notation_begin == 0) {
        break;
      }
      sci_notation_begin -= 1;
      continue;
    }
    if (IsStringDigit(current_char)) {
      has_digit_before = true;
      if (sci_notation_begin == 0) {
        break;
      }
      sci_notation_begin -= 1;
      continue;
    } else {
      break;
    }
  }
  // We went one further than the start position, increment back to start.
  sci_notation_begin += 1;

  // Can rule out scientific notation if there wasn't a digit preceding the "e".
  if (has_digit_before == false) {
    suffix->first = input.substr(0, exp_pos + 1);
    suffix->second = input.substr(exp_pos + 1);
    return;
  }

  // Now find ending position (last digit of exponent of scientific notation).
  bool has_digit_after = false;
  bool has_pos_sign_after = false;
  size_t sci_notation_end = exp_pos + 1;
  while (true) {
    if (sci_notation_end >= input.length()) {
      break;
    }
    const string current_char = input.substr(sci_notation_end, 1);
    if (current_char == "+" || current_char == "-") {
      // Check that we are at the very next position after the "e".
      if (sci_notation_end != exp_pos + 1) break;
      if (current_char == "+") {
        has_pos_sign_after = true;
      }
      sci_notation_end += 1;
      continue;
    }
    if (IsStringDigit(current_char)) {
      has_digit_after = true;
      sci_notation_end += 1;
      continue;
    } else {
      break;
    }
  }
  // We went one further than the start position, increment back to start.
  sci_notation_end -= 1;

  // Can rule out scientific notation if there wasn't a digit following the "e".
  if (has_digit_after == false) {
    suffix->first = input.substr(0, exp_pos + 1);
    suffix->second = input.substr(exp_pos + 1);
    return;
  }

  // This string *does* represent scientific notation. Convert it to a double
  // and back to a string (no longer in scientific notation), then prepend the
  // prefix, and send the suffix for additional checking.
  const string prefix =
      sci_notation_begin == 0 ? "" : input.substr(0, sci_notation_begin);
  const string base =
      input.substr(sci_notation_begin, exp_pos - sci_notation_begin);
  const string exp = has_pos_sign_after ?
      input.substr(exp_pos + 2, sci_notation_end - (exp_pos + 1)) :
      input.substr(exp_pos + 1, sci_notation_end - exp_pos);
  const string suffix_str = input.substr(sci_notation_end + 1);

  // Sanity-check prefix and suffix of "e" can be parsed as a double.
  double base_value;
  if (!Stod(base, &base_value)) {
    suffix->first = output;
    suffix->second = "";
    return;
  }

  suffix->first = prefix + base + "*10^(" + exp + ")";
  suffix->second = suffix_str;
  return;
}

string RemoveScientificNotation(const string& input) {
  pair<string, string> suffix = make_pair<string, string>("", "");
  suffix.second = input;
  string to_return = "";
  while (!suffix.second.empty()) {
    RemoveScientificNotationInternal(&suffix);
    to_return += suffix.first;
  }
  return to_return;
}

// ============================= CONCATENATE =================================
string StrCat(const string& str1, const string& str2) { return str1 + str2; }

string StrCat(const string& str1, const string& str2, const string& str3) {
  return str1 + str2 + str3;
}

string StrCat(
    const string& str1,
    const string& str2,
    const string& str3,
    const string& str4) {
  return str1 + str2 + str3 + str4;
}

string StrCat(
    const string& str1,
    const string& str2,
    const string& str3,
    const string& str4,
    const string& str5) {
  return str1 + str2 + str3 + str4 + str5;
}

string StrCat(
    const string& str1,
    const string& str2,
    const string& str3,
    const string& str4,
    const string& str5,
    const string& str6) {
  return str1 + str2 + str3 + str4 + str5 + str6;
}
// =========================== END CONCATENATE ===============================

// ============================== NUMERIC ====================================
bool Stoi(const string& str, bool* i) {
  if (str.empty()) return false;
  if (str == "0" || ToLowerCase(str) == "false") {
    *i = false;
    return true;
  } else if (str == "1" || ToLowerCase(str) == "true") {
    *i = true;
    return true;
  }

  return false;
}
bool Stoi(const char* input, const unsigned int num_bytes, bool* i) {
  if (num_bytes != 1) {
    return false;
  }
  const char value = input[0];
  if (value == '0') {
    *i = false;
    return true;
  } else if (value == '1') {
    *i = true;
    return true;
  }
  return false;
}

bool Stoi(const string& str, int8_t* i) {
  if (str.empty()) {
    return false;
  }
  char* last_char;
  // C does not have a strtoi function. Use the strtol function.
  auto temp = strtol(str.c_str(), &last_char, 10);
  // Test that value was in the range of 'long'.
  if ((temp == std::numeric_limits<int32_t>::max() ||
       temp == std::numeric_limits<int32_t>::min()) &&
      errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (temp == 0) {
    string to_compare = "";
    for (size_t i = 0; i < str.length(); ++i) {
      to_compare += "0";
    }
    if (str != to_compare) {
      return false;
    }
  }
  // strtol ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (&str.back() + 1)) {
    return false;
  }
  // Make sure that temp is within the bounds of 'char' (since it is a long).
  if (temp > std::numeric_limits<int8_t>::max() ||
      temp < std::numeric_limits<int8_t>::min()) {
    return false;
  }
  *i = (char) temp;
  return true;
}
bool Stoi(const char* input, const unsigned int num_bytes, int8_t* i) {
  if (num_bytes > sizeof(char)) {
    return false;
  }
  char* last_char;
  // C does not have a strtoi function. Use the strtol function.
  auto temp = strtol(input, &last_char, 10);
  // Test that value was in the range of 'long'.
  if ((temp == std::numeric_limits<int32_t>::max() ||
       temp == std::numeric_limits<int32_t>::min()) &&
      errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (temp == 0) {
    for (unsigned int i = 0; i < num_bytes; ++i) {
      if (input[i] != '0') {
        return false;
      }
    }
  }
  // strtol ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (input + num_bytes)) {
    return false;
  }
  // Make sure that temp is within the bounds of 'char' (since it is a long).
  if (temp > std::numeric_limits<int8_t>::max() ||
      temp < std::numeric_limits<int8_t>::min()) {
    return false;
  }
  *i = (char) temp;
  return true;
}

bool Stoi(const string& str, uint8_t* i) {
  if (str.empty()) {
    return false;
  }
  char* last_char;
  // C does not have a strtoi function. Use the strtoul function.
  auto temp = strtoul(str.c_str(), &last_char, 10);
  // strtoul happily converts negative values to their unsigned equivalent
  // (e.g. -1 -> std::numeric_limits<uint32_t>::max()). Stoi should reject such conversions.
  if (str.find("-") != string::npos) {
    return false;
  }
  // Test that value was in the range of 'long'.
  if (temp == std::numeric_limits<uint32_t>::max() && errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (temp == 0) {
    string to_compare = "";
    for (size_t i = 0; i < str.length(); ++i) {
      to_compare += "0";
    }
    if (str != to_compare) {
      return false;
    }
  }
  // strtoul ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (&str.back() + 1)) {
    return false;
  }
  // Make sure that temp is within the bounds of 'unsigned char' (since it is a long).
  if (temp > std::numeric_limits<uint8_t>::max()) {
    return false;
  }
  *i = (unsigned char) temp;
  return true;
}
bool Stoi(const char* input, const unsigned int num_bytes, uint8_t* i) {
  // strtoul happily converts negative values to their unsigned equivalent
  // (e.g. -1 -> ULONG_MAX). Stoi should reject such conversions; explicitly
  // check for leading negative sign.
  if (num_bytes == 0 || num_bytes > sizeof(unsigned char) || input[0] == '-') {
    return false;
  }
  char* last_char;
  // C does not have a strtoi function. Use the strtoul function.
  auto temp = strtoul(input, &last_char, 10);
  // Test that value was in the range of 'long'.
  if (temp == std::numeric_limits<uint32_t>::max() && errno == ERANGE) {
    return false;
  }
  // strtoul returns '0' for unparsable strings. Handle such cases.
  if (temp == 0) {
    for (unsigned int i = 0; i < num_bytes; ++i) {
      if (input[i] != '0') {
        return false;
      }
    }
  }
  // strtoul ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (input + num_bytes)) {
    return false;
  }
  // Make sure that temp is within the bounds of 'char' (since it is a long).
  if (temp > std::numeric_limits<uint8_t>::max()) {
    return false;
  }
  *i = (unsigned char) temp;
  return true;
}

bool Stoi(const string& str, int16_t* i) {
  char* last_char;
  // C does not have a strtoi function. Use the strtol function.
  auto temp = strtol(str.c_str(), &last_char, 10);
  // Test that value was in the range of 'long'.
  if ((temp == std::numeric_limits<int32_t>::max() ||
       temp == std::numeric_limits<int32_t>::min()) &&
      errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (temp == 0) {
    string to_compare = "";
    for (size_t i = 0; i < str.length(); ++i) {
      to_compare += "0";
    }
    if (str != to_compare) {
      return false;
    }
  }
  // strtol ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (&str.back() + 1)) {
    return false;
  }
  // Make sure that temp is within the bounds of 'short' (since it is a long).
  if (temp > std::numeric_limits<int16_t>::max() ||
      temp < std::numeric_limits<int16_t>::min()) {
    return false;
  }
  *i = (int16_t) temp;
  return true;
}
bool Stoi(const char* input, const unsigned int num_bytes, int16_t* i) {
  if (num_bytes > sizeof(int16_t)) {
    return false;
  }
  char* last_char;
  // C does not have a strtoi function. Use the strtol function.
  auto temp = strtol(input, &last_char, 10);
  // Test that value was in the range of 'long'.
  if ((temp == std::numeric_limits<int32_t>::max() ||
       temp == std::numeric_limits<int32_t>::min()) &&
      errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (temp == 0) {
    for (unsigned int i = 0; i < num_bytes; ++i) {
      if (input[i] != '0') {
        return false;
      }
    }
  }
  // strtol ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (input + num_bytes)) {
    return false;
  }
  // Make sure that temp is within the bounds of 'short' (since it is a long).
  if (temp > std::numeric_limits<int16_t>::max() ||
      temp < std::numeric_limits<int16_t>::min()) {
    return false;
  }
  *i = (int16_t) temp;
  return true;
}

bool Stoi(const string& str, uint16_t* i) {
  char* last_char;
  // C does not have a strtoi function. Use the strtoul function.
  auto temp = strtoul(str.c_str(), &last_char, 10);
  // strtoul happily converts negative values to their unsigned equivalent
  // (e.g. -1 -> ULONG_MAX). Stoi should reject such conversions.
  if (str.find("-") != string::npos) {
    return false;
  }
  // Test that value was in the range of 'long'.
  if (temp == std::numeric_limits<uint32_t>::max() && errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (temp == 0) {
    string to_compare = "";
    for (size_t i = 0; i < str.length(); ++i) {
      to_compare += "0";
    }
    if (str != to_compare) {
      return false;
    }
  }
  // strtoul ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (&str.back() + 1)) {
    return false;
  }
  // Make sure that temp is within the bounds of 'short' (since it is a long).
  if (temp > std::numeric_limits<uint16_t>::max()) {
    return false;
  }
  *i = (uint16_t) temp;
  return true;
}
bool Stoi(const char* input, const unsigned int num_bytes, uint16_t* i) {
  // strtoul happily converts negative values to their unsigned equivalent
  // (e.g. -1 -> ULONG_MAX). Stoi should reject such conversions; explicitly
  // check for leading negative sign.
  if (num_bytes == 0 || num_bytes > sizeof(uint16_t) || input[0] == '-') {
    return false;
  }
  char* last_char;
  // C does not have a strtoi function. Use the strtoul function.
  auto temp = strtoul(input, &last_char, 10);
  // Test that value was in the range of 'long'.
  if (temp == std::numeric_limits<uint32_t>::max() && errno == ERANGE) {
    return false;
  }
  // strtoul returns '0' for unparsable strings. Handle such cases.
  if (temp == 0) {
    for (unsigned int i = 0; i < num_bytes; ++i) {
      if (input[i] != '0') {
        return false;
      }
    }
  }
  // strtoul ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (input + num_bytes)) {
    return false;
  }
  // Make sure that temp is within the bounds of 'short' (since it is a long).
  if (temp > std::numeric_limits<uint16_t>::max()) {
    return false;
  }
  *i = (uint16_t) temp;
  return true;
}

bool Stoi(const string& str, int32_t* i) {
  if (str.empty()) {
    return false;
  }

  char* last_char;
  *i = (int32_t) strtol(str.c_str(), &last_char, 10);
  int64_t foo = strtol(str.c_str(), &last_char, 10);
  int64_t bar = (int64_t) *i;
  if (foo != bar) {
    return false;
  }
  // Test that value was in the range of 'long'.
  if ((*i == std::numeric_limits<int32_t>::max() ||
       *i == std::numeric_limits<int32_t>::min()) &&
      errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (*i == 0) {
    string to_compare = "";
    for (size_t j = 0; j < str.length(); ++j) {
      to_compare += "0";
    }
    if (str != to_compare) {
      return false;
    }
  }
  // strtol ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (&str.back() + 1)) {
    return false;
  }
  // Make sure that *i is within the bounds of 'int' (since it is a long).
  if (*i > std::numeric_limits<int32_t>::max() ||
      *i < std::numeric_limits<int32_t>::min()) {
    return false;
  }
  return true;
}
bool Stoi(const char* input, const unsigned int num_bytes, int32_t* i) {
  if (num_bytes > sizeof(int32_t)) {
    return false;
  }
  char* last_char;
  // C does not have a strtoi function. Use the strtol function.
  *i = (int32_t) strtol(input, &last_char, 10);
  // Test that value was in the range of 'long'.
  if ((*i == std::numeric_limits<int32_t>::max() ||
       *i == std::numeric_limits<int32_t>::min()) &&
      errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (*i == 0) {
    for (unsigned int j = 0; j < num_bytes; ++j) {
      if (input[j] != '0') {
        return false;
      }
    }
  }
  // strtol ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (input + num_bytes)) {
    return false;
  }
  // Make sure that *i is within the bounds of 'int' (since it is a long).
  if (*i > std::numeric_limits<int32_t>::max() ||
      *i < std::numeric_limits<int32_t>::min()) {
    return false;
  }
  return true;
}

bool Stoi(const string& str, uint32_t* i) {
  if (str.empty()) {
    return false;
  }

  char* last_char;
  *i = (uint32_t) strtoul(str.c_str(), &last_char, 10);
  uint64_t foo = strtoul(str.c_str(), &last_char, 10);
  uint64_t bar = (uint64_t) *i;
  if (foo != bar) {
    return false;
  }
  // strtoul happily converts negative values to their unsigned equivalent
  // (e.g. -1 -> ULONG_MAX). Stoi should reject such conversions.
  if (str.find("-") != string::npos) {
    return false;
  }
  // Test that value was in the range of 'long'.
  if (*i == std::numeric_limits<uint32_t>::max() && errno == ERANGE) {
    return false;
  }
  // strtol returns '0' for unparsable strings. Handle such cases.
  if (*i == 0) {
    string to_compare = "";
    for (size_t j = 0; j < str.length(); ++j) {
      to_compare += "0";
    }
    if (str != to_compare) {
      return false;
    }
  }
  // strtoul ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (&str.back() + 1)) {
    return false;
  }
  // Make sure that *i is within the bounds of 'uint' (since it is a long).
  if (*i > std::numeric_limits<uint32_t>::max()) {
    return false;
  }
  return true;
}
bool Stoi(const char* input, const unsigned int num_bytes, uint32_t* i) {
  // strtoul happily converts negative values to their unsigned equivalent
  // (e.g. -1 -> ULONG_MAX). Stoi should reject such conversions; explicitly
  // check for leading negative sign.
  if (num_bytes == 0 || num_bytes > sizeof(uint32_t) || input[0] == '-') {
    return false;
  }
  char* last_char;
  // C does not have a strtoi function. Use the strtoul function.
  *i = (uint32_t) strtoul(input, &last_char, 10);
  // Test that value was in the range of 'long'.
  if (*i == std::numeric_limits<uint32_t>::max() && errno == ERANGE) {
    return false;
  }
  // strtoul returns '0' for unparsable strings. Handle such cases.
  if (*i == 0) {
    for (unsigned int j = 0; j < num_bytes; ++j) {
      if (input[j] != '0') {
        return false;
      }
    }
  }
  // strtoul ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (input + num_bytes)) {
    return false;
  }
  // Make sure that *i is within the bounds of 'uint' (since it is a long).
  if (*i > std::numeric_limits<uint32_t>::max()) {
    return false;
  }
  return true;
}

bool Stoi(const string& str, int64_t* i) {
  if (str.empty()) {
    return false;
  }

  errno = 0;
  if (sscanf(str.c_str(), "%lld", (long long*) i) != 1) {
    return false;
  }
  // Test that value was in the range of 'long long'.
  if (errno == ERANGE || *i > std::numeric_limits<int64_t>::max() ||
      *i < std::numeric_limits<int64_t>::min()) {
    errno = 0;
    return false;
  }
  return true;
}
bool Stoi(const char* input, const unsigned int num_bytes, int64_t* i) {
  if (num_bytes > sizeof(int64_t)) {
    return false;
  }
  errno = 0;
  if (sscanf(input, "%lld", (long long*) i) != 1) {
    return false;
  }
  // Test that value was in the range of 'long long'.
  if (errno == ERANGE || *i > std::numeric_limits<int64_t>::max() ||
      *i < std::numeric_limits<int64_t>::min()) {
    errno = 0;
    return false;
  }
  return true;
}

bool Stoi(const string& str, uint64_t* i) {
  // sscanf will convert negative values to the appropriate unsigned
  // value (e.g. interpretting the byte(s) (bits) as an unsigned
  // representation). Manually check no negative sign.
  if (str.empty()) {
    return false;
  }

  if (str.find("-") != string::npos) {
    return false;
  }
  errno = 0;
  if (sscanf(str.c_str(), "%llu", (unsigned long long*) i) != 1) {
    return false;
  }
  // Test that value was in the range of 'long long'.
  if (errno == ERANGE) {
    errno = 0;
    return false;
  }
  return true;
}
bool Stoi(const char* input, const unsigned int num_bytes, uint64_t* i) {
  // sscanf happily converts negative values to their unsigned equivalent
  // (e.g. -1 -> ULONG_MAX). Stoi should reject such conversions; explicitly
  // check for leading negative sign.
  if (num_bytes == 0 || num_bytes > sizeof(uint64_t) || input[0] == '-') {
    return false;
  }
  errno = 0;
  if (sscanf(input, "%llu", (unsigned long long*) i) != 1) {
    return false;
  }
  // Test that value was in the range of 'long long'.
  if (errno == ERANGE) {
    errno = 0;
    return false;
  }
  return true;
}

bool Stod(const string& str, double* d) {
  if (str.empty()) return false;
  // Handle fractions, if necessary.
  size_t fraction = str.find("/");
  if (fraction != string::npos && fraction != str.length()) {
    const string numerator = str.substr(0, fraction);
    const string denominator = str.substr(fraction + 1);
    // Only one fraction symbol '/' allowed.
    if (numerator.find("/") != string::npos ||
        denominator.find("/") != string::npos) {
      return false;
    }
    double num, denom;
    if (!Stod(numerator, &num) || !Stod(denominator, &denom)) {
      return false;
    }
    *d = num / denom;
    return true;
  }

  if (!IsNumeric(str)) {
    return false;
  }

  // Handle Zero.
  if (IsZeroString(str)) {
    *d = 0.0;
    return true;
  }

  // No fraction symbol.
  char* last_char;
  *d = strtod(str.c_str(), &last_char);
  // strtod returns '0.0' for unparsable strings. Since we already checked all
  // valid representations of zero (in IsZeroString() above), any time d is
  // zero it is an error.
  if (*d == 0.0) {
    return false;
  }
  // Test that value did not cause underflow.
  if (abs(*d) <= DBL_MIN) {
    return false;
  }
  // Test that value did not cause overflow.
  if ((*d == HUGE_VAL || *d == -HUGE_VAL) && errno == ERANGE) {
    return false;
  }
  // strtol ignores non-numeric characters that may appear at the end of str;
  // but we want Stoi to return false for these. Use last_char to detect this.
  if (!last_char || last_char != (&str.back() + 1)) {
    return false;
  }
  return true;
}

bool Stod(const string& str, long double* d) {
  if (str.empty()) return false;
  // Handle fractions, if necessary.
  size_t fraction = str.find("/");
  if (fraction != string::npos && fraction != str.length()) {
    const string numerator = str.substr(0, fraction);
    const string denominator = str.substr(fraction + 1);
    // Only one fraction symbol '/' allowed.
    if (numerator.find("/") != string::npos ||
        denominator.find("/") != string::npos) {
      return false;
    }
    long double num, denom;
    if (!Stod(numerator, &num) || !Stod(denominator, &denom)) {
      return false;
    }
    *d = num / denom;
    return true;
  }

  if (!IsNumeric(str)) {
    return false;
  }

  // Handle Zero.
  if (IsZeroString(str)) {
    *d = 0.0;
    return true;
  }

  // No fraction symbol.
  errno = 0;
  sscanf(str.c_str(), "%Lf", d);
  // Since we already checked all valid representations of zero via IsZeroString()
  // above, any time d is zero it is an error.
  if (*d == 0.0) {
    return false;
  }
  // Test that value did not cause underflow.
  if (abs(*d) <= DBL_MIN) {
    return false;
  }
  // Test that value did not cause overflow.
  if (errno == ERANGE || *d == HUGE_VALL || *d == -HUGE_VALL) {
    errno = 0;
    return false;
  }
  return true;
}

bool Stof(const string& str, float* f) {
  // Handle fractions, if necessary.
  size_t fraction = str.find("/");
  if (fraction != string::npos && fraction != str.length()) {
    const string numerator = str.substr(0, fraction);
    const string denominator = str.substr(fraction + 1);
    // Only one fraction symbol '/' allowed.
    if (numerator.find("/") != string::npos ||
        denominator.find("/") != string::npos) {
      return false;
    }
    float num, denom;
    if (!Stof(numerator, &num) || !Stof(denominator, &denom)) {
      return false;
    }
    *f = num / denom;
    return true;
  }

  if (!IsNumeric(str)) {
    return false;
  }

  // Handle Zero.
  if (IsZeroString(str)) {
    *f = 0.0;
    return true;
  }

  // No fraction symbol.
  errno = 0;
  sscanf(str.c_str(), "%f", f);
  // Since we already checked all valid representations of zero via IsZeroString()
  // above, any time d is zero it is an error.
  if (*f == 0.0) {
    return false;
  }
  // Test that value did not cause underflow.
  if (abs(*f) <= DBL_MIN) {
    return false;
  }
  // Test that value did not cause overflow.
  if (errno == ERANGE || *f == HUGE_VALF || *f == -HUGE_VALF) {
    errno = 0;
    return false;
  }
  return true;
}

bool BinaryStringToValue(const string& str, uint8_t* i) {
  const size_t string_size = str.size();
  const size_t container_bytes =
      string_size / CHAR_BIT + (string_size % CHAR_BIT == 0 ? 0 : 1);
  if (container_bytes > sizeof(unsigned char)) {
    return false;
  }

  // Iterate through the binary representation (starting at the least
  // significant bit), incrementing 'i' as we go.
  *i = 0;
  int current_bit = 0;
  for (string::const_reverse_iterator rit = str.rbegin(); rit != str.rend();
       ++rit) {
    if (*rit == '1') {
      *i = static_cast<unsigned char>(*i + (1 << current_bit));
    } else if (*rit != '0') {
      return false;
    }
    current_bit++;
  }
  return true;
}

bool TwosComplementStringToValue(const string& str, int8_t* i) {
  if (str.size() < 2) {
    return false;
  }
  unsigned char abs_value;
  if (!BinaryStringToValue(str.substr(1), &abs_value)) {
    return false;
  }
  if (str.substr(0, 1) == "1") {
    *i =
        static_cast<char>(std::numeric_limits<int8_t>::min() + (char) abs_value);
  } else {
    *i = (char) abs_value;
  }
  return true;
}

bool BinaryStringToValue(const string& str, uint16_t* i) {
  const size_t string_size = str.size();
  const size_t container_bytes =
      string_size / CHAR_BIT + (string_size % CHAR_BIT == 0 ? 0 : 1);
  if (container_bytes > sizeof(uint16_t)) {
    return false;
  }

  // Iterate through the binary representation (starting at the least
  // significant bit), incrementing 'i' as we go.
  *i = 0;
  int current_bit = 0;
  for (string::const_reverse_iterator rit = str.rbegin(); rit != str.rend();
       ++rit) {
    if (*rit == '1') {
      *i = static_cast<uint16_t>(*i + (1 << current_bit));
    } else if (*rit != '0') {
      return false;
    }
    current_bit++;
  }
  return true;
}

bool TwosComplementStringToValue(const string& str, int16_t* i) {
  if (str.size() < 2) {
    return false;
  }
  uint16_t abs_value;
  if (!BinaryStringToValue(str.substr(1), &abs_value)) {
    return false;
  }
  if (str.substr(0, 1) == "1") {
    *i = static_cast<int16_t>(std::numeric_limits<int16_t>::min() + abs_value);
  } else {
    *i = (int16_t) abs_value;
  }
  return true;
}

bool BinaryStringToValue(const string& str, uint32_t* i) {
  const size_t string_size = str.size();
  const size_t container_bytes =
      string_size / CHAR_BIT + (string_size % CHAR_BIT == 0 ? 0 : 1);
  if (container_bytes > sizeof(uint32_t)) {
    return false;
  }

  // Iterate through the binary representation (starting at the least
  // significant bit), incrementing 'i' as we go.
  *i = 0;
  int current_bit = 0;
  for (string::const_reverse_iterator rit = str.rbegin(); rit != str.rend();
       ++rit) {
    if (*rit == '1') {
      *i = static_cast<uint32_t>(*i + (1UL << current_bit));
    } else if (*rit != '0') {
      return false;
    }
    current_bit++;
  }
  return true;
}

bool TwosComplementStringToValue(const string& str, int32_t* i) {
  if (str.size() < 2) {
    return false;
  }
  uint32_t abs_value;
  if (!BinaryStringToValue(str.substr(1), &abs_value)) {
    return false;
  }
  if (str.substr(0, 1) == "1") {
    *i = std::numeric_limits<int32_t>::min() + abs_value;
  } else {
    *i = (int32_t) abs_value;
  }
  return true;
}

bool BinaryStringToValue(const string& str, uint64_t* i) {
  const size_t string_size = str.size();
  const size_t container_bytes =
      string_size / CHAR_BIT + (string_size % CHAR_BIT == 0 ? 0 : 1);
  if (container_bytes > sizeof(uint64_t)) {
    return false;
  }

  // Iterate through the binary representation (starting at the least
  // significant bit), incrementing 'i' as we go.
  *i = 0;
  int current_bit = 0;
  for (string::const_reverse_iterator rit = str.rbegin(); rit != str.rend();
       ++rit) {
    if (*rit == '1') {
      *i += uint64_t{1} << current_bit;
    } else if (*rit != '0') {
      return false;
    }
    current_bit++;
  }
  return true;
}

bool TwosComplementStringToValue(const string& str, int64_t* i) {
  if (str.size() < 2) {
    return false;
  }
  uint64_t abs_value;
  if (!BinaryStringToValue(str.substr(1), &abs_value)) {
    return false;
  }
  if (str.substr(0, 1) == "1") {
    *i = std::numeric_limits<int64_t>::min() + abs_value;
  } else {
    *i = (int64_t) abs_value;
  }
  return true;
}

void BinaryStringToCharVector(const string& str, vector<char>* output) {
  if (output == nullptr) LOG_FATAL("Null input to BinaryStringToCharVector.");
  const size_t num_bits = str.size();
  const size_t remainder_bits = num_bits % CHAR_BIT;
  const size_t bytes_needed =
      num_bits / CHAR_BIT + (remainder_bits == 0 ? 0 : 1);
  const size_t orig_size = output->size();
  output->resize(orig_size + bytes_needed);
  const size_t num_bits_first_block =
      remainder_bits == 0 ? CHAR_BIT : remainder_bits;
  for (size_t i = 0; i < bytes_needed; ++i) {
    string current_bits = "";
    if (i == 0) {
      current_bits = str.substr(0, num_bits_first_block);
    } else {
      current_bits =
          str.substr(num_bits_first_block + CHAR_BIT * (i - 1), CHAR_BIT);
    }
    char current_byte = 0;
    const size_t num_current_bits = current_bits.size();
    for (size_t j = 0; j < num_current_bits; ++j) {
      if (current_bits[num_current_bits - 1 - j] == '1') {
        current_byte = static_cast<char>(current_byte + (1 << j));
      }
    }
    (*output)[orig_size + i] = current_byte;
  }
}

void BinaryStringToCharVector(const string& str, vector<unsigned char>* output) {
  if (output == nullptr) LOG_FATAL("Null input to BinaryStringToCharVector.");
  const size_t num_bits = str.size();
  const size_t remainder_bits = num_bits % CHAR_BIT;
  const size_t bytes_needed =
      num_bits / CHAR_BIT + (remainder_bits == 0 ? 0 : 1);
  const size_t orig_size = output->size();
  output->resize(orig_size + bytes_needed);
  const size_t num_bits_first_block =
      remainder_bits == 0 ? CHAR_BIT : remainder_bits;
  for (size_t i = 0; i < bytes_needed; ++i) {
    string current_bits = "";
    if (i == 0) {
      current_bits = str.substr(0, num_bits_first_block);
    } else {
      current_bits =
          str.substr(num_bits_first_block + CHAR_BIT * (i - 1), CHAR_BIT);
    }
    unsigned char current_byte = 0;
    const size_t num_current_bits = current_bits.size();
    for (size_t j = 0; j < num_current_bits; ++j) {
      if (current_bits[num_current_bits - 1 - j] == '1') {
        current_byte = static_cast<unsigned char>(current_byte + (1 << j));
      }
    }
    (*output)[orig_size + i] = current_byte;
  }
}

string CharVectorToBinaryString(
    const bool print_byte_spaces, const vector<unsigned char>& input) {
  string to_return = "";
  for (size_t i = 0; i < input.size(); ++i) {
    const unsigned char current_byte = input[i];
    for (size_t j = 0; j < CHAR_BIT; ++j) {
      if (current_byte & (1 << (CHAR_BIT - 1 - j))) {
        to_return += "1";
      } else {
        to_return += "0";
      }
    }
    if (print_byte_spaces && i != input.size() - 1) to_return += " ";
  }

  return to_return;
}

string CharVectorToBinaryString(
    const bool print_byte_spaces,
    const unsigned char* input,
    const int num_bytes) {
  string to_return = "";
  for (int i = 0; i < num_bytes; ++i) {
    const unsigned char current_byte = *(input + i);
    for (size_t j = 0; j < CHAR_BIT; ++j) {
      if (current_byte & (1 << (CHAR_BIT - 1 - j))) {
        to_return += "1";
      } else {
        to_return += "0";
      }
    }
    if (print_byte_spaces && i != num_bytes - 1) to_return += " ";
  }

  return to_return;
}

string CharVectorToBinaryString(
    const bool print_byte_spaces, const vector<char>& input) {
  string to_return = "";
  for (size_t i = 0; i < input.size(); ++i) {
    const char current_byte = input[i];
    for (size_t j = 0; j < CHAR_BIT; ++j) {
      if (current_byte & (1 << (CHAR_BIT - 1 - j))) {
        to_return += "1";
      } else {
        to_return += "0";
      }
    }
    if (print_byte_spaces && i != input.size() - 1) to_return += " ";
  }

  return to_return;
}

string CharVectorToBinaryString(
    const bool print_byte_spaces, const char* input, const int num_bytes) {
  string to_return = "";
  for (int i = 0; i < num_bytes; ++i) {
    const char current_byte = *(input + i);
    for (size_t j = 0; j < CHAR_BIT; ++j) {
      if (current_byte & (1 << (CHAR_BIT - 1 - j))) {
        to_return += "1";
      } else {
        to_return += "0";
      }
    }
    if (print_byte_spaces && i != num_bytes - 1) to_return += " ";
  }

  return to_return;
}

string Itoa(const bool b) { return b ? "1" : "0"; }

// NOTE: For 'i' of type char or unsigned char, ostringstream will attempt
// to interpret 'i' as an ASCII character, instead of printing out the
// numeric value.  Thus, we force appropriate behavior (printing out the
// numeric value) by casting 'i' as a short datatype.
string Itoa(const int8_t i) { return Itoa(static_cast<int16_t>(i)); }
string Itoa(const uint8_t i) { return Itoa(static_cast<uint16_t>(i)); }

string Itoa(const int16_t i) {
  std::ostringstream s;
  s << i;
  return s.str();
}

string Itoa(const uint16_t i) {
  std::ostringstream s;
  s << i;
  return s.str();
}

string Itoa(const int32_t& l) {
  std::ostringstream s;
  s << l;
  return s.str();
}

string Itoa(const uint32_t& l) {
  std::ostringstream s;
  s << l;
  return s.str();
}

string Itoa(const int64_t& l) {
  std::ostringstream s;
  s << l;
  return s.str();
}

string Itoa(const uint64_t& l) {
  std::ostringstream s;
  s << l;
  return s.str();
}

string Itoa(const float& f) {
  std::ostringstream s;
  s << f;
  return s.str();
}

string Itoa(const float& f, const int precision) {
  if (precision <= 0) {
    return Itoa(f);
  }
  std::ostringstream s;
  s.precision(precision);
  s << fixed << f;
  return s.str();
}

string Itoa(const double& d) {
  std::ostringstream s;
  s << d;
  return s.str();
}

string Itoa(const double& d, const int precision) {
  if (precision <= 0) {
    return Itoa(d);
  }
  std::ostringstream s;
  s.precision(precision);
  s << fixed << d;
  return s.str();
}

double ParseDouble(const char* input, const int start_byte) {
  double d;
  memcpy(&d, &input[start_byte], sizeof(double));
  return d;
}

float ParseFloat(const char* input, const int start_byte) {
  float f;
  memcpy(&f, &input[start_byte], sizeof(float));
  return f;
}

int ParseInt(const char* input, const int start_byte) {
  int i;
  memcpy(&i, &input[start_byte], sizeof(int));
  return i;
  //return static_cast<int>(input[start_byte]);
}
// ============================ END NUMERIC ==================================

// =============================== STRIP =====================================
bool HasPrefixString(const string& input, const string& to_match) {
  if (to_match.empty()) {
    return true;
  }
  if (input.empty() || input.length() < to_match.length()) {
    return false;
  }
  return input.substr(0, to_match.length()) == to_match;
}

bool StripPrefixString(
    const string& input, const string& to_match, string* output) {
  if (output == NULL) {
    return false;
  }
  if (to_match.empty() || input.empty()) {
    output->assign(input);
    return false;
  }
  if (HasPrefixString(input, to_match)) {
    output->assign(input.substr(to_match.length()));
    return true;
  }
  output->assign(input);
  return false;
}

string StripPrefixString(const string& input, const string& to_match) {
  string temp;
  StripPrefixString(input, to_match, &temp);
  return temp;
}

bool HasSuffixString(const string& input, const string& to_match) {
  if (to_match.empty()) {
    return true;
  }
  if (input.empty() || input.length() < to_match.length()) {
    return false;
  }
  return input.substr(input.length() - to_match.length()) == to_match;
}

bool StripSuffixString(
    const string& input, const string& to_match, string* output) {
  if (output == NULL) {
    return false;
  }
  if (to_match.empty() || input.empty()) {
    output->assign(input);
    return false;
  }
  if (HasSuffixString(input, to_match)) {
    output->assign(input.substr(0, input.length() - to_match.length()));
    return true;
  }
  output->assign(input);
  return false;
}

string StripSuffixString(const string& input, const string& to_match) {
  string temp;
  StripSuffixString(input, to_match, &temp);
  return temp;
}

void RemoveLeadingWhitespace(const string& input, string* output) {
  if (output == NULL) {
    return;
  }

  int first_non_whitespace_index = -1;
  for (unsigned int i = 0; i < input.length(); ++i) {
    const char c = input[i];
    if (!::isspace(c)) {
      first_non_whitespace_index = i;
      break;
    }
  }

  if (first_non_whitespace_index >= 0) {
    *output = input.substr(first_non_whitespace_index);
  } else {
    *output = "";
  }
}

string RemoveLeadingWhitespace(const string& input) {
  string output;
  RemoveLeadingWhitespace(input, &output);
  return output;
}

void RemoveTrailingWhitespace(const string& input, string* output) {
  if (output == NULL) {
    return;
  }

  int last_non_whitespace_index = -1;
  for (int i = (int) (input.length() - 1); i >= 0; --i) {
    const char c = input[i];
    if (!::isspace(c)) {
      last_non_whitespace_index = i + 1;
      break;
    }
  }

  if (last_non_whitespace_index > 0) {
    *output = input.substr(0, last_non_whitespace_index);
  } else {
    *output = "";
  }
}

string RemoveTrailingWhitespace(const string& input) {
  string output;
  RemoveTrailingWhitespace(input, &output);
  return output;
}

void RemoveExtraWhitespace(const string& input, string* output) {
  if (output == NULL) {
    return;
  }
  bool seen_non_whitespace = false;
  bool prev_was_space = false;
  output->clear();
  for (unsigned int i = 0; i < input.length(); ++i) {
    const char c = input[i];
    if (::isspace(c)) {
      // Keep space only if not a leading (prefix) space and
      // not a consecutive space.
      if (seen_non_whitespace && !prev_was_space) {
        (*output) += c;
      }
      prev_was_space = true;
    } else {
      (*output) += c;
      seen_non_whitespace = true;
      prev_was_space = false;
    }
  }

  // It's possible there remains one trailing whitespace character.
  // If so, remove it now.
  const size_t final_pos = output->length() - 1;
  if (::isspace((*output)[final_pos])) {
    output->erase(final_pos);
  }
}

string RemoveExtraWhitespace(const string& input) {
  string output;
  RemoveExtraWhitespace(input, &output);
  return output;
}

void RemoveAllWhitespace(const string& input, string* output) {
  if (output == NULL) {
    return;
  }
  output->clear();
  for (unsigned int i = 0; i < input.length(); ++i) {
    const char c = input[i];
    if (!::isspace(c)) (*output) += c;
  }
}

string RemoveAllWhitespace(const string& input) {
  string output;
  RemoveAllWhitespace(input, &output);
  return output;
}

void Strip(const string& input, const string& to_match, string* output) {
  if (output == NULL || to_match.empty() || input.length() < to_match.length()) {
    return;
  }
  output->assign(input);
  size_t itr = input.find(to_match);
  while (itr != string::npos) {
    output->erase(itr, itr + to_match.length());
    itr = output->find(to_match);
  }
}

string Strip(const string& input, const string& to_match) {
  string to_return;
  Strip(input, to_match, &to_return);
  return to_return;
}

string StripQuotes(const string& input) {
  if (!HasPrefixString(input, "\"") || !HasSuffixString(input, "\"")) {
    return input;
  }
  return StripPrefixString(StripSuffixString(input, "\""), "\"");
}

string StripSingleQuotes(const string& input) {
  if (!HasPrefixString(input, "'") || !HasSuffixString(input, "'")) {
    return input;
  }
  return StripPrefixString(StripSuffixString(input, "'"), "'");
}

string StripBrackets(const string& input) {
  if (!HasPrefixString(input, "[") || !HasSuffixString(input, "]")) {
    return input;
  }
  return StripPrefixString(StripSuffixString(input, "]"), "[");
}

string StripAngleBrackets(const string& input) {
  if (!HasPrefixString(input, "<") || !HasSuffixString(input, ">")) {
    return input;
  }
  return StripPrefixString(StripSuffixString(input, ">"), "<");
}

string StripBraces(const string& input) {
  if (!HasPrefixString(input, "{") || !HasSuffixString(input, "}")) {
    return input;
  }
  return StripPrefixString(StripSuffixString(input, "}"), "{");
}

string StripParentheses(const string& input) {
  if (!HasPrefixString(input, "(") || !HasSuffixString(input, ")")) {
    return input;
  }
  return StripPrefixString(StripSuffixString(input, ")"), "(");
}

string StripAllEnclosingPunctuation(const string& input) {
  return StripBrackets(
      StripParentheses(StripBraces(StripSingleQuotes(StripQuotes(input)))));
}

string StripAllEnclosingPunctuationAndWhitespace(const string& input) {
  return StripAllEnclosingPunctuation(RemoveAllWhitespace(input));
}

// ============================= END STRIP ===================================

// ============================ JOIN and SPLIT ===============================
// Vector of Chars.
bool Join(const vector<char>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  bool first_element_is_empty_char = false;
  for (const char& itr : input) {
    if (output->empty() && !first_element_is_empty_char) {
      output->assign(&itr, 1);
      if (itr == '\0') first_element_is_empty_char = true;
    } else {
      (*output) += delimiter + itr;
    }
  }
  return true;
}
string Join(const vector<char>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}
// Vector of Strings.
bool Join(const vector<string>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  bool first_element_is_empty_str = false;
  for (const string& itr : input) {
    if (output->empty() && !first_element_is_empty_str) {
      output->assign(itr);
      if (itr == "") first_element_is_empty_str = true;
    } else {
      (*output) += delimiter + itr;
    }
  }
  return true;
}
string Join(const vector<string>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}
// Vector of Integers.
bool Join(const vector<int>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  for (const int& itr : input) {
    if (output->empty()) {
      output->assign(Itoa(itr));
    } else {
      (*output) += delimiter + Itoa(itr);
    }
  }
  return true;
}
string Join(const vector<int>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}
// Vector of Doubles.
bool Join(const vector<double>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  for (const double& itr : input) {
    if (output->empty()) {
      output->assign(Itoa(itr));
    } else {
      (*output) += delimiter + Itoa(itr);
    }
  }
  return true;
}
string Join(const vector<double>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}
// Vector of Booleans.
bool Join(const vector<bool>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  for (const bool& itr : input) {
    if (output->empty()) {
      output->assign(Itoa(itr));
    } else {
      (*output) += delimiter + Itoa(itr);
    }
  }
  return true;
}
string Join(const vector<bool>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}
// Set of Strings.
bool Join(const set<string>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  bool first_element_is_empty_str = false;
  for (const string& itr : input) {
    if (output->empty() && !first_element_is_empty_str) {
      output->assign(itr);
      if (itr == "") first_element_is_empty_str = true;
    } else {
      (*output) += delimiter + itr;
    }
  }
  return true;
}
string Join(const set<string>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}
// Set of Integers.
bool Join(const set<int>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  for (const int& itr : input) {
    if (output->empty()) {
      output->assign(Itoa(itr));
    } else {
      (*output) += delimiter + Itoa(itr);
    }
  }
  return true;
}
string Join(const set<int>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}
// Set of Doubles.
bool Join(const set<double>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  for (const double& itr : input) {
    if (output->empty()) {
      output->assign(Itoa(itr));
    } else {
      (*output) += delimiter + Itoa(itr);
    }
  }
  return true;
}
string Join(const set<double>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}
// Set of Booleans.
bool Join(const set<bool>& input, const string& delimiter, string* output) {
  if (output == NULL) {
    return false;
  }
  output->clear();
  for (const bool& itr : input) {
    if (output->empty()) {
      output->assign(Itoa(itr));
    } else {
      (*output) += delimiter + Itoa(itr);
    }
  }
  return true;
}
string Join(const set<bool>& input, const string& delimiter) {
  string to_return;
  Join(input, delimiter, &to_return);
  return to_return;
}

bool Split(
    const string& input,
    const string& delimiter,
    const bool skip_empty,
    vector<string>* output) {
  // Nothing to do if empty input or delimiter.
  if (input.empty() || delimiter.empty()) {
    return true;
  }

  // Sanity check output is not null.
  if (output == nullptr) {
    return false;
  }

  // For optimization, reserve space.
  const size_t input_size = input.size();
  output->reserve(input_size);

  // Iterate through input, splitting at each instance of the delimiter.
  size_t pos = input.find(delimiter);
  size_t prev_pos = 0;
  const size_t delimiter_length = delimiter.length();
  while (pos != string::npos) {
    if (pos == prev_pos) {
      if (!skip_empty) output->push_back("");
    } else {
      output->push_back(input.substr(prev_pos, pos - prev_pos));
    }
    prev_pos = pos + delimiter_length;
    pos = input.find(delimiter, prev_pos);
  }

  // Store final suffix.
  if (input_size == prev_pos) {
    if (!skip_empty) output->push_back("");
  } else {
    output->push_back(input.substr(prev_pos));
  }

  return true;
}

bool Split(
    const string& input,
    const set<string>& delimiters,
    const bool skip_empty,
    vector<string>* output) {
  // Nothing to do if empty input or delimiter.
  if (input.empty() || delimiters.empty()) {
    return true;
  }

  // Sanity check output is not null.
  if (output == nullptr) {
    return false;
  }

  // For optimization, reserve space.
  const size_t input_size = input.size();
  output->reserve(input_size);

  // Iterate through input, splitting at first found delimiter.
  string split_delimiter;
  size_t split_pos, pos;
  size_t prev_pos = 0;
  while (true) {
    split_delimiter = "";
    split_pos = input_size;
    for (const string& delimiter : delimiters) {
      pos = input.find(delimiter, prev_pos);
      // It's possible more than one of the delimiters match, e.g. if
      // some delimiters are prefixes of others, or even if they
      // have any overlapping characters, or even if they don't.
      // For example, input "foobar" will match: "foo", "bar", "ob",
      // "fo", etc. We use the convention that we'll take the earliest
      // occurring match, and in case of multiple matches from this
      // position (as in "fo" and "foo" for the example above), we'll take
      // whichever matches first (since we're iterating through the set of
      // delimiters, this will be whichever is lexicographically first).
      if (pos != string::npos && pos < split_pos) {
        split_pos = pos;
        split_delimiter = delimiter;
      }
    }
    // No delimiter found. Break.
    if (split_delimiter.empty()) break;
    if (split_pos == prev_pos) {
      if (!skip_empty) output->push_back("");
    } else {
      output->push_back(input.substr(prev_pos, split_pos - prev_pos));
    }
    prev_pos = split_pos + split_delimiter.length();
  }

  // Store final suffix.
  if (input_size == prev_pos) {
    if (!skip_empty) output->push_back("");
  } else {
    output->push_back(input.substr(prev_pos));
  }

  return true;
}

bool Split(
    const string& input,
    const set<char>& delimiters,
    const bool skip_empty,
    vector<string>* output) {
  // Nothing to do if empty input or delimiter.
  if (input.empty() || delimiters.empty()) {
    return true;
  }

  // Sanity check output is not null.
  if (output == nullptr) {
    return false;
  }

  // For optimization, reserve space.
  output->reserve(input.size());

  // Iterate through input one character at a time, splitting at any delimiter.
  string current_token;
  for (string::const_iterator itr = input.begin(); itr != input.end(); ++itr) {
    // Check if current character is a delimiter.
    if (delimiters.find(*itr) != delimiters.end()) {
      // Current character is a delimiter.
      // Write current_token to output.
      if (current_token.empty() && !skip_empty) {
        output->push_back("");
      } else if (!current_token.empty()) {
        output->push_back(current_token);
      }
      current_token = "";
    } else {
      // Current character is not a delimiter. Append it to current_token.
      current_token += *itr;
    }
  }

  // Store final token.
  if (!current_token.empty()) {
    output->push_back(current_token);
  }

  return true;
}

bool Split(
    const string& input,
    const string& delimiter,
    const bool skip_empty,
    set<string>* output) {
  // Nothing to do if empty input or delimiter.
  if (input.empty() || delimiter.empty()) {
    return true;
  }

  // Sanity check output is not null.
  if (output == nullptr) {
    return false;
  }

  // Iterate through input, splitting at each instance of the delimiter.
  size_t pos = input.find(delimiter);
  size_t prev_pos = 0;
  const size_t delimiter_length = delimiter.length();
  while (pos != string::npos) {
    if (pos == prev_pos) {
      if (!skip_empty) output->insert("");
    } else {
      output->insert(input.substr(prev_pos, pos - prev_pos));
    }
    prev_pos = pos + delimiter_length;
    pos = input.find(delimiter, prev_pos);
  }

  // Store final suffix.
  if (input.size() == prev_pos) {
    if (!skip_empty) output->insert("");
  } else {
    output->insert(input.substr(prev_pos));
  }

  return true;
}

bool Split(
    const string& input,
    const set<string>& delimiters,
    const bool skip_empty,
    set<string>* output) {
  // Nothing to do if empty input or delimiter.
  if (input.empty() || delimiters.empty()) {
    return true;
  }

  // Sanity check output is not null.
  if (output == nullptr) {
    return false;
  }

  // Iterate through input, splitting at first found delimiter.
  const size_t input_size = input.size();
  string split_delimiter;
  size_t split_pos, pos;
  size_t prev_pos = 0;
  while (true) {
    split_delimiter = "";
    split_pos = input_size;
    for (const string& delimiter : delimiters) {
      pos = input.find(delimiter, prev_pos);
      // It's possible more than one of the delimiters match, e.g. if
      // some delimiters are prefixes of others, or even if they
      // have any overlapping characters, or even if they don't.
      // For example, input "foobar" will match: "foo", "bar", "ob",
      // "fo", etc. We use the convention that we'll take the earliest
      // occurring match, and in case of multiple matches from this
      // position (as in "fo" and "foo" for the example above), we'll take
      // whichever matches first (since we're iterating through the set of
      // delimiters, this will be whichever is lexicographically first).
      if (pos != string::npos && pos < split_pos) {
        split_pos = pos;
        split_delimiter = delimiter;
      }
    }
    // No delimiter found. Break.
    if (split_delimiter.empty()) break;
    if (split_pos == prev_pos) {
      if (!skip_empty) output->insert("");
    } else {
      output->insert(input.substr(prev_pos, split_pos - prev_pos));
    }
    prev_pos = split_pos + split_delimiter.length();
  }

  // Store final suffix.
  if (input_size == prev_pos) {
    if (!skip_empty) output->insert("");
  } else {
    output->insert(input.substr(prev_pos));
  }

  return true;
}

bool Split(
    const string& input,
    const set<char>& delimiters,
    const bool skip_empty,
    set<string>* output) {
  // Nothing to do if empty input or delimiter.
  if (input.empty() || delimiters.empty()) {
    return true;
  }

  // Sanity check output is not null.
  if (output == nullptr) {
    return false;
  }

  // Iterate through input one character at a time, splitting at any delimiter.
  string current_token;
  for (string::const_iterator itr = input.begin(); itr != input.end(); ++itr) {
    // Check if current character is a delimiter.
    if (delimiters.find(*itr) != delimiters.end()) {
      // Current character is a delimiter.
      // Write current_token to output.
      if (current_token.empty() && !skip_empty) {
        output->insert("");
      } else if (!current_token.empty()) {
        output->insert(current_token);
      }
      current_token = "";
    } else {
      // Current character is not a delimiter. Append it to current_token.
      current_token += *itr;
    }
  }

  // Store final token.
  if (!current_token.empty()) {
    output->insert(current_token);
  }

  return true;
}
// ========================== END JOIN and SPLIT =============================

// ============================ MISCELLANEOUS ================================
int CountOccurrences(const string& value, const char target) {
  int count = 0;
  for (unsigned int i = 0; i < value.length(); ++i) {
    if (value[i] == target) ++count;
  }
  return count;
}

int CountOccurrences(const string& value, const string& target) {
  if (target.empty()) {
    return 0;
  }

  int count = 0;
  size_t found_pos = value.find(target);
  string tail = value;
  while (found_pos != string::npos) {
    ++count;
    tail = tail.substr(found_pos + target.length());
    found_pos = tail.find(target);
  }
  return count;
}

string Replace(
    const string& orig, const string& target, const string& replace_with) {
  // Early abort if possible.
  if (target.empty() || orig.find(target) == string::npos) {
    return orig;
  }

  string to_return = "";
  size_t start_pos = 0;
  while (start_pos < orig.length()) {
    size_t found_pos = orig.find(target, start_pos);
    if (found_pos == string::npos) {
      to_return += orig.substr(start_pos);
      return to_return;
    }
    to_return += orig.substr(start_pos, found_pos - start_pos) + replace_with;
    start_pos = found_pos + target.size();
  }

  // Code can reach here if the original string terminated in 'target'.
  return to_return;
}

string ToLowerCase(const string& input) {
  locale loc;
  string output = "";
  for (string::size_type i = 0; i < input.length(); ++i) {
    output += tolower(input[i], loc);
  }
  return output;
}

string ToUpperCase(const string& input) {
  locale loc;
  string output = "";
  for (string::size_type i = 0; i < input.length(); ++i) {
    output += toupper(input[i], loc);
  }
  return output;
}

bool EqualsIgnoreCase(const string& one, const string& two) {
  return ToLowerCase(one) == ToLowerCase(two);
}

// ========================== END MISCELLANEOUS ==============================

}  // namespace string_utils
