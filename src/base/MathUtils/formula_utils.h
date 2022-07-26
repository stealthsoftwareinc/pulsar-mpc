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
// Description:
// Utilility structures and functions for handling mathematical expressions.

#ifndef FORMULA_UTILS_H
#define FORMULA_UTILS_H

#include "data_structures.h"

namespace math_utils {

static bool kPrintDatatype = false;

// A generic structure that can represent a constant value, a variable,
// a term in an expression, or a full expression (formula). Structure:
//   - If op_.type_ == BOOLEAN && op_.gate_op_ = BooleanOperation::IDENTITY, then exactly
//     value_ should be set (either as a STRING for variables, or a NUMERIC
//     DataType for constants) and subterm_one_ and subterm_two_ should both be NULL
//   - For any other operation op_, value_ is ignored, and either one or
//     both of {subterm_one_, subterm_two_} should be set
// Example:
//   abs(2x^2 + 3x - x!)
// Then:
//   Outermost Formula abs(2x^2 + 3x - x!):
//     op_ = ABS, subterm_one_ = &A
//   Formula A (2x^2 + 3x - x!):
//     op_ = ADD, subterm_one_ = &B, subterm_two_ = &C
//   Formula B (2x^2 + 3x):
//     op_ = ADD, subterm_one_ = &D, subterm_two_ = &E
//   Formula C (-x!):
//     op_ = MULT, subterm_one_ = &F, subterm_two_ = &G
//   Formula D (2x^2):
//     op_ = MULT, subterm_one_ = &H, subterm_two_ = &I
//   Formula E (3x):
//     op_ = MULT, subterm_one_ = &J, subterm_two_ = &K
//   Formula F (-1):
//     op_ = IDENTITY, value_ = -1
//   Formula G (x!):
//     op_ = FACTORIAL, subterm_one_ = &L
//   Formula H (2):
//     op_ = IDENTITY, value_ = 2
//   Formula I (x^2):
//     op_ = POW, subterm_one_ = &M, subterm_two_ = &N
//   Formula J (3):
//     op_ = IDENTITY, value_ = 3
//   Formula K (x):
//     op_ = IDENTITY, value_ = "x" (STRING)
//   Formula L (x):
//     op_ = IDENTITY, value_ = "x" (STRING)
//   Formula M (x):
//     op_ = IDENTITY, value_ = "x" (STRING)
//   Formula N (^2):
//     op_ = IDENTITY, value_ = 2
struct Formula {
  // The operation to apply to the value (e.g. 'IDENTITY' or 'ABS').
  OperationHolder op_;

  // This field is populated iff op_ is BooleanOperation::IDENTITY, which is
  // the convention for identifying contants and/or variables in the formula.
  // It indicates the value of this term: can be a STRINGXXX if it is a variable,
  // or a numeric type for a constant.
  GenericValue value_;

  // More complicated equations can be handled by recursively combining Formulas.
  // NOTE: (Pointers to) Formulas coming from subterms should *always* be created
  // on the heap: This is becuase sometimes they need to be (in case we want to
  // generate an expression locally in a function, and use it outside, which would
  // be impossible if pointing to an Formula on the stack); and since sometimes
  // they need to be on the heap, we require that they are always on the heap, so
  // that we're not left with the bad scenario where user doesn't know if they
  // need to call 'delete' on the subterms (since there is no way in C++ to
  // determine if a pointer is heap or stack, see:
  // stackoverflow.com/questions/3230420/how-to-know-if-a-pointer-points-to-the-heap-or-the-stack
  std::unique_ptr<Formula> subterm_one_;
  std::unique_ptr<Formula> subterm_two_;

  Formula() {
    subterm_one_ = nullptr;
    subterm_two_ = nullptr;
  }
  // ========================== Rule of 5 Functions ============================
  // Copy Constructor.
  Formula(const Formula& other) {
    op_ = other.op_;
    value_ = other.value_;
    if (other.subterm_one_ != nullptr) {
      subterm_one_ = std::unique_ptr<Formula>(new Formula());
      subterm_one_->clone(*other.subterm_one_);
    }
    if (other.subterm_two_ != nullptr) {
      subterm_two_ = std::unique_ptr<Formula>(new Formula());
      subterm_two_->clone(*other.subterm_two_);
    }
  }
  // Move Constructor.
  Formula(Formula&& other) noexcept {
    op_ = other.op_;
    value_ = other.value_;
    if (other.subterm_one_ != nullptr) {
      subterm_one_ = std::move(other.subterm_one_);
    }
    if (other.subterm_two_ != nullptr) {
      subterm_two_ = std::move(other.subterm_two_);
    }
  }
  // Copy-Assignment.
  Formula& operator=(const Formula& other) {
    Formula temp(other);  // Re-use copy-constructor.
    *this = std::move(temp);  // Re-use move-assignment.
    return *this;
  }
  // Move-Assignment.
  Formula& operator=(Formula&& other) noexcept {
    op_ = other.op_;
    value_ = other.value_;
    if (other.subterm_one_ != nullptr) {
      subterm_one_ = std::move(other.subterm_one_);
    }
    if (other.subterm_two_ != nullptr) {
      subterm_two_ = std::move(other.subterm_two_);
    }
    return *this;
  }

  // Destructor.
  ~Formula() noexcept {}

  // Deep-Copy from other.
  void clone(const Formula& other) {
    op_ = other.op_;
    value_ = other.value_;
    if (other.subterm_one_ != nullptr) {
      subterm_one_ = std::unique_ptr<Formula>(new Formula());
      subterm_one_->clone(*other.subterm_one_);
    }
    if (other.subterm_two_ != nullptr) {
      subterm_two_ = std::unique_ptr<Formula>(new Formula());
      subterm_two_->clone(*other.subterm_two_);
    }
  }
};

// Returns the string representation of 'term' (considers term.op_
// and term.term_title_).
extern std::string GetFormulaString(
    const bool print_datatype, const Formula& formula);
// Same as above, but with print datatype set to kPrintDatatype.
inline std::string GetFormulaString(const Formula& formula) {
  return GetFormulaString(kPrintDatatype, formula);
}

// Returns true if the formula is empty (i.e. was initialized via the
// default constructor, but no fields were set).
extern bool IsEmptyFormula(const Formula& exp);

// Returns the number of terms in the formula. More precisely, this gives
// the number of "leaf terms" in the formula tree.
extern uint64_t CountLeafFormulaTerms(const Formula& formula);
// Returns the number of terms in the formula tree. This counts the overall
// size of the formula tree, so all terms ("leaf" terms as well as non-leaf).
// For example, for formula representing:
//   x + y
// Then CountLeafFormulaTerms would return 2, while CountAllFormulaTerms returns 3.
extern uint64_t CountAllFormulaTerms(const Formula& formula);

// Parses a string representation of an expression to an Formula.
// Input:
//   - reduce_formula: If the input string has constants that can be simplified
//                     (e.g. 2^3), then setting this to 'true' perfoms such math.
//                     More precisely, calls ReduceFormula() before returning.
//   - clean_input: ParseFormula() will call itself recursively, on substrings
//                  of 'term_str'. It will need term_str to be cleaned
//                  (whitespace removed, etc.), and can either do the cleaning
//                  at the outset, or assume that the input has already been
//                  cleaned (each recursive need not re-clean).
//                  Set this to 'true' if 'term_str' should be cleaned.
//   - term_str:    The input to parse as a Formula.
//   - enforce_var_names: If this is true, all items in 'term_str' must either
//                        be valid punctuation (e.g. a parentheses), a valid
//                        operator (e.g. "+"), or a valid variable name, as
//                        specified by 'var_names'. If a substring fails to
//                        match any of these, returns false. Otherwise,
//                        treat the unrecognized string as a variable name
//                        (even if it is not present in var_names).
//   - var_names:   A set of all variable names. This can be empty (and cause
//                  no problems) if 'term_str' contains no variables, or if
//                  enforce_var_names is 'false'.
extern bool ParseFormula(
    const bool reduce_formula,
    const bool clean_input,
    const std::string& term_str,
    const bool enforce_var_names,
    const std::set<std::string>& var_names,
    Formula* formula,
    std::string* error_msg);
// Same as above, with reduce_formula defaulted to 'true'.
inline bool ParseFormula(
    const bool clean_input,
    const std::string& term_str,
    const bool enforce_var_names,
    const std::set<std::string>& var_names,
    Formula* formula,
    std::string* error_msg) {
  return ParseFormula(
      true,
      clean_input,
      term_str,
      enforce_var_names,
      var_names,
      formula,
      error_msg);
}
// Same as above, with vector instead of set.
inline bool ParseFormula(
    const bool clean_input,
    const std::string& term_str,
    const bool enforce_var_names,
    const std::vector<std::string>& var_names,
    Formula* formula,
    std::string* error_msg) {
  std::set<std::string> names;
  for (const std::string& var_name : var_names)
    names.insert(var_name);
  return ParseFormula(
      clean_input, term_str, enforce_var_names, names, formula, error_msg);
}
// Same as above, using "x" as the default variable.
inline bool ParseFormula(
    const std::string& term_str,
    const bool enforce_var_names,
    Formula* formula,
    std::string* error_msg) {
  std::set<std::string> var_names;
  if (enforce_var_names) {
    var_names.insert("x");
  }
  return ParseFormula(
      true, term_str, enforce_var_names, var_names, formula, error_msg);
}
// Same as above, using "x" as the default variable.
inline bool ParseFormula(
    const std::string& term_str, Formula* formula, std::string* error_msg) {
  std::set<std::string> var_names;
  var_names.insert("x");
  return ParseFormula(true, term_str, true, var_names, formula, error_msg);
}
// Same as above, don't store error message.
inline bool ParseFormula(const std::string& term_str, Formula* formula) {
  std::string temp = "";
  return ParseFormula(term_str, formula, &temp);
}

// Reduces the input formula (in-place) by reducing/computing any math
// that can be done. For example, input formula: (2^3)x would reduce to 8x.
extern void ReduceFormula(Formula* formula);

// Returns a copy of the input formula.
extern Formula CopyFormula(const Formula& formula);
// Same as above, with different API.
extern void CopyFormula(const Formula& formula, Formula* new_formula);

// Evaluates the given formula (by substituting each instance of a variable
// string with its corresponding value, as determined by 'var_values'. Populates
// 'value' with the answer. Also, if vars_seen is not null, keeps track of
// which Keys of 'var_values' were seen/used.
extern bool EvaluateFormula(
    const Formula& formula,
    const std::map<std::string, GenericValue>& var_values,
    GenericValue* value,
    std::set<std::string>* vars_seen,
    std::string* error_msg);
// Same as above, but doesn't keep track of which variables it saw.
inline bool EvaluateFormula(
    const Formula& formula,
    const std::map<std::string, GenericValue>& var_values,
    GenericValue* value,
    std::string* error_msg) {
  return EvaluateFormula(formula, var_values, value, nullptr, error_msg);
}
// Same as above, but for just one variable.
inline bool EvaluateFormula(
    const Formula& formula,
    const std::string& var_string,
    const GenericValue& var_value,
    GenericValue* value,
    std::string* error_msg) {
  std::map<std::string, GenericValue> vars;
  vars.insert(make_pair(var_string, var_value));
  return EvaluateFormula(formula, vars, value, error_msg);
}
// Same as above, but for a constant formula (no variables).
inline bool EvaluateConstantFormula(
    const Formula& formula, GenericValue* value, std::string* error_msg) {
  std::map<std::string, GenericValue> empty_vars;
  return EvaluateFormula(formula, empty_vars, value, error_msg);
}

}  // namespace math_utils
#endif
