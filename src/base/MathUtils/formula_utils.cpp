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

#include "formula_utils.h"

#include "GenericUtils/char_casting_utils.h"  // For ValueToByteString.
#include "MapUtils/map_utils.h"  // For FindOrInsert().
#include "MathUtils/constants.h"  // For slice.
#include "global_utils.h"

#include <memory>  // For unique_ptr.
#include <set>
#include <string>
#include <vector>

using namespace map_utils;
using namespace math_utils;
using namespace string_utils;
using namespace std;

namespace math_utils {

namespace {

struct StackParameters {
  const Formula* formula_;
  OperationHolder op_;

  StackParameters(const Formula* formula) { formula_ = formula; }

  StackParameters(const OperationHolder& op) {
    op_ = op;
    formula_ = nullptr;
  }
};

}  // namespace

struct GetFormulaStringStack {
  string str_;
  const Formula* formula_;

  GetFormulaStringStack(const string& input) {
    str_ = input;
    formula_ = nullptr;
  }

  GetFormulaStringStack(const Formula* input) {
    str_ = "";
    formula_ = input;
  }
};

void GetFormulaString(
    const bool print_datatype, vector<GetFormulaStringStack>* stack) {
  const Formula& formula = *(stack->back().formula_);
  stack->pop_back();

  // Toggle based on operation type.
  if (formula.op_.type_ == OperationType::BOOLEAN &&
      formula.op_.gate_op_ == BooleanOperation::IDENTITY) {
    stack->push_back(GetFormulaStringStack(
        GetGenericValueString(print_datatype, formula.value_)));
    // 1-term Operations.
  } else if (IsSingleInputOperation(formula.op_)) {
    if (formula.subterm_one_ == nullptr) {
      LOG_FATAL("Unable to perform evaluation: subterm_one_ is null");
    }
    if (formula.subterm_two_ != nullptr) {
      LOG_FATAL("Unable to perform evaluation: subterm_two_ is non-null");
    }
    string prefix = "";
    string suffix = "";
    if (formula.op_.type_ == OperationType::BOOLEAN) {
      prefix = "NOT(";
      suffix = ")";
    } else if (formula.op_.arithmetic_op_ == ArithmeticOperation::ABS) {
      prefix = "|";
      suffix = "|";
    } else if (formula.op_.arithmetic_op_ == ArithmeticOperation::FLIP_SIGN) {
      prefix = "-(";
      suffix = ")";
    } else if (formula.op_.arithmetic_op_ == ArithmeticOperation::FACTORIAL) {
      prefix = "(";
      suffix = ")!";
    } else if (formula.op_.arithmetic_op_ == ArithmeticOperation::SQRT) {
      prefix = "sqrt(";
      suffix = ")";
    }
    stack->push_back(GetFormulaStringStack(suffix));
    stack->push_back(GetFormulaStringStack(formula.subterm_one_.get()));
    stack->push_back(GetFormulaStringStack(prefix));
    // 2-term Operations.
  } else {
    if (formula.subterm_one_ == nullptr || formula.subterm_two_ == nullptr) {
      LOG_FATAL(
          "Unexpected null subterm for op " + GetOpString(formula.op_.gate_op_));
    }
    // Some 2-term operations should be expressed as:
    //    OP(x, y)
    // Rather than:
    //    x OP y
    // Handle these operations differently.
    if (formula.op_.type_ == OperationType::ARITHMETIC &&
        (formula.op_.arithmetic_op_ == ArithmeticOperation::MIN ||
         formula.op_.arithmetic_op_ == ArithmeticOperation::MAX ||
         formula.op_.arithmetic_op_ == ArithmeticOperation::ARGMIN ||
         formula.op_.arithmetic_op_ == ArithmeticOperation::ARGMAX ||
         formula.op_.arithmetic_op_ == ArithmeticOperation::ARGMIN_INTERNAL ||
         formula.op_.arithmetic_op_ == ArithmeticOperation::ARGMAX_INTERNAL ||
         formula.op_.arithmetic_op_ == ArithmeticOperation::INNER_PRODUCT ||
         formula.op_.arithmetic_op_ == ArithmeticOperation::VEC)) {
      const string op_name =
          formula.op_.arithmetic_op_ == ArithmeticOperation::VEC ?
          "vec(" :
          formula.op_.arithmetic_op_ == ArithmeticOperation::INNER_PRODUCT ?
          "inner_product(" :
          formula.op_.arithmetic_op_ == ArithmeticOperation::MIN ?
          "min(" :
          formula.op_.arithmetic_op_ == ArithmeticOperation::MAX ?
          "max(" :
          formula.op_.arithmetic_op_ == ArithmeticOperation::ARGMIN ?
          "argmin(" :
          formula.op_.arithmetic_op_ == ArithmeticOperation::ARGMAX ?
          "argmax(" :
          formula.op_.arithmetic_op_ == ArithmeticOperation::ARGMIN_INTERNAL ?
          "argmin_internal(" :
          formula.op_.arithmetic_op_ == ArithmeticOperation::ARGMAX_INTERNAL ?
          "argmax_internal(" :
          "NA";
      stack->push_back(GetFormulaStringStack(")"));
      stack->push_back(GetFormulaStringStack(formula.subterm_two_.get()));
      stack->push_back(GetFormulaStringStack(", "));
      stack->push_back(GetFormulaStringStack(formula.subterm_one_.get()));
      stack->push_back(GetFormulaStringStack(op_name));
    } else {
      const string op_str = formula.op_.type_ == OperationType::MATH ?
          GetOpString(formula.op_.math_op_) :
          formula.op_.type_ == OperationType::BOOLEAN ?
          GetOpString(formula.op_.gate_op_) :
          formula.op_.type_ == OperationType::ARITHMETIC ?
          GetOpString(formula.op_.arithmetic_op_) :
          GetOpString(formula.op_.comparison_op_);
      stack->push_back(GetFormulaStringStack(")"));
      stack->push_back(GetFormulaStringStack(formula.subterm_two_.get()));
      stack->push_back(GetFormulaStringStack(")" + op_str + "("));
      stack->push_back(GetFormulaStringStack(formula.subterm_one_.get()));
      stack->push_back(GetFormulaStringStack("("));
    }
  }
}
void GetFormulaString(vector<GetFormulaStringStack>* stack) {
  GetFormulaString(kPrintDatatype, stack);
}

string GetFormulaString(const bool print_datatype, const Formula& formula) {
  string to_return = "";
  vector<GetFormulaStringStack> stack(1, GetFormulaStringStack(&formula));

  while (!stack.empty()) {
    GetFormulaStringStack current = stack.back();

    if (stack.back().formula_ == nullptr) {
      to_return += stack.back().str_;
      stack.pop_back();
    } else {
      GetFormulaString(print_datatype, &stack);
    }
  }

  return to_return;
}

bool IsEmptyFormula(const Formula& exp) {
  return exp.op_.type_ == OperationType::UNKNOWN;
}

void CountFormulaTerms(
    const bool all_terms, const Formula& formula, uint64_t* to_return) {
  if (formula.subterm_one_ != nullptr) {
    CountFormulaTerms(all_terms, *(formula.subterm_one_.get()), to_return);
  }
  if (formula.subterm_two_ != nullptr) {
    CountFormulaTerms(all_terms, *(formula.subterm_two_.get()), to_return);
  }
  if ((formula.subterm_one_ == nullptr && formula.subterm_two_ == nullptr) ||
      all_terms) {
    ++(*to_return);
  }
}

uint64_t CountLeafFormulaTerms(const Formula& formula) {
  if (IsEmptyFormula(formula)) return 0;
  uint64_t to_return = 0;
  CountFormulaTerms(false, formula, &to_return);
  return to_return;
}
uint64_t CountAllFormulaTerms(const Formula& formula) {
  if (IsEmptyFormula(formula)) return 0;
  uint64_t to_return = 0;
  CountFormulaTerms(true, formula, &to_return);
  return to_return;
}

// Used as a local variable to avoid recursion.
// The string term_ denotes the formula to be represented, and it will
// eventually be parsed/stored by the object pointed to by formula_.
struct ParseFormulaRecursionStack {
  string term_;
  Formula* formula_;

  ParseFormulaRecursionStack(const string& term, Formula* formula) {
    term_ = term;
    formula_ = formula;
  }
};

// Used as a local variable to avoid recursion. This is used in parsing
// a formula, and is used for operations that may have more than two
// arguments (ADD, SUB, MULT, DIV, MIN, MAX). Conceptually, we view
// this multi-valued operation as a tree, where each node is an operation,
// and at the leafs, there are two values sitting under them (so all values/
// inputs sit below a leaf operation). For example:
//   x1 + x2 - x3 + x4 - x5
// could be expressed as:
//   (x1 + x2) - (x3 - (x4 - x5))
// which as a tree of operations would look like:
/*                  SUB
                  /     \
                ADD     SUB
               /   \   /   \
              x1   x2 x3   SUB
                          /   \
                         x4   x5
*/
struct NodeStackState {
  bool sign_;  // Which op this node is (ADD vs SUB; or MULT vs DIV).
  bool is_leaf_;
  int toggle_;  // SUB and DIV will toggle all operations below them;
      // see e.g. example above where the op "on the right"
      // of x3 (i.e. the parent op) is SUB, even though in
      // the original expression it is '+'.
  int num_left_;  // How many values appear to the "left" of this node
  int num_right_;  // How many values appear to the "right" of this node
  Formula* formula_;

  NodeStackState(
      const bool sign,
      const bool is_leaf,
      const int toggle,
      const int num_left,
      const int num_right,
      Formula* formula) {
    sign_ = sign;
    is_leaf_ = is_leaf;
    toggle_ = toggle;
    num_left_ = num_left;
    num_right_ = num_right;
    formula_ = formula;
  }
};

bool ParseFormula(
    const bool enforce_var_names,
    const set<string>& var_names,
    string* error_msg,
    vector<ParseFormulaRecursionStack>* stack) {
  // Grab the current piece of the formula to process, and remove it from stack.
  const string term_str = stack->back().term_;
  Formula* formula = stack->back().formula_;
  stack->pop_back();

  // Try parsing as a 2-term BooleanOperation.
  BooleanOperation op = BooleanOperation::UNKNOWN;
  string first_term = "";
  string second_term = "";
  if (!GetBooleanTerms(term_str, &first_term, &second_term, &op)) {
    *error_msg += "Failed to GetBooleanTerms()\n";
    return false;
  }
  if (op != BooleanOperation::UNKNOWN) {
    if (first_term.empty() || second_term.empty()) {
      *error_msg += "Found operation '" + GetOpString(op) +
          "', but nothing on the left or right of it";
      return false;
    }
    formula->op_.type_ = OperationType::BOOLEAN;
    formula->op_.gate_op_ = op;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    formula->subterm_two_ = unique_ptr<Formula>(new Formula());
    stack->push_back(
        ParseFormulaRecursionStack(first_term, formula->subterm_one_.get()));
    stack->push_back(
        ParseFormulaRecursionStack(second_term, formula->subterm_two_.get()));
    return true;
  }

  // Try parsing term as a 2-term ComparisonOperation.
  ComparisonOperation comp_op = ComparisonOperation::UNKNOWN;
  first_term = "";
  second_term = "";
  if (!GetComparisonTerms(term_str, &first_term, &second_term, &comp_op)) {
    *error_msg += "Failed to GetComparisonTerms()\n";
    return false;
  }
  if (comp_op != ComparisonOperation::UNKNOWN) {
    if (first_term.empty() || second_term.empty()) {
      *error_msg += "Found operation '" + GetOpString(comp_op) +
          "', but nothing on the left or right of it";
      return false;
    }
    formula->op_.type_ = OperationType::COMPARISON;
    formula->op_.comparison_op_ = comp_op;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    formula->subterm_two_ = unique_ptr<Formula>(new Formula());
    stack->push_back(
        ParseFormulaRecursionStack(first_term, formula->subterm_one_.get()));
    stack->push_back(
        ParseFormulaRecursionStack(second_term, formula->subterm_two_.get()));
    return true;
  }

  // Try to split formula into a SUM of terms. For example:
  //   (2x + 1)(x - 1) - x(2 + x)(x - 1) + ((x + 1)(x - 1)) * sqrt(2x)
  // Would be split as:
  //   (2x + 1)(x - 1),
  //   -x(2 + x)(x - 1) + ((x + 1)(x - 1)) * sqrt(2x)
  vector<pair<string, int>> terms;
  if (!GetAdditiveTerms(term_str, "", &terms)) {
    *error_msg += "Failed to GetAdditiveTerms()\n";
    return false;
  }
  int num_terms = (int) terms.size();
  if (num_terms > 1) {
    int current_index = 0;
    const int num_right = num_terms / 2;
    vector<NodeStackState> node_stack(
        1,
        NodeStackState(
            false, false, 0, num_terms - num_right, num_right, formula));
    while (!node_stack.empty()) {
      NodeStackState current_node = node_stack.back();
      node_stack.pop_back();

      // Handle termination condition (Leaf node).
      if (current_node.is_leaf_) {
        stack->push_back(ParseFormulaRecursionStack(
            terms[current_index].first, current_node.formula_));
        ++current_index;
        continue;
      }

      // Not a leaf node; so this node will have two children. Create
      // sub-formulas for them.
      const bool is_original_minus =
          terms[current_node.toggle_ + current_node.num_left_ - 1].second == 1;
      current_node.formula_->op_.type_ = OperationType::ARITHMETIC;
      current_node.formula_->op_.arithmetic_op_ =
          (is_original_minus == current_node.sign_) ? ArithmeticOperation::ADD :
                                                      ArithmeticOperation::SUB;
      current_node.formula_->subterm_one_ = unique_ptr<Formula>(new Formula());
      current_node.formula_->subterm_two_ = unique_ptr<Formula>(new Formula());

      // Handle right sub-tree
      if (current_node.num_right_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_two_.get()));
      } else {
        const int num_right_children = current_node.num_right_ / 2;
        node_stack.push_back(NodeStackState(
            (is_original_minus != current_node.sign_),
            false,
            current_node.toggle_ + current_node.num_left_,
            current_node.num_right_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_two_.get()));
      }

      // Handle left sub-tree
      if (current_node.num_left_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_one_.get()));
      } else {
        const int num_right_children = current_node.num_left_ / 2;
        node_stack.push_back(NodeStackState(
            current_node.sign_,
            false,
            current_node.toggle_,
            current_node.num_left_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_one_.get()));
      }
    }
    return true;
  }

  // Primary formula is not the sum of two (or more) terms. Try splitting it
  // into MULTIPLICATIVE terms.
  terms.clear();
  if (!GetMultiplicativeTerms(term_str, "", &terms)) {
    *error_msg += "Failed to GetMultTerms()\n";
    return false;
  }
  num_terms = (int) terms.size();
  if (num_terms > 1) {
    int current_index = 0;
    const int num_right = num_terms / 2;
    vector<NodeStackState> node_stack(
        1,
        NodeStackState(
            false, false, 0, num_terms - num_right, num_right, formula));
    while (!node_stack.empty()) {
      NodeStackState current_node = node_stack.back();
      node_stack.pop_back();

      // Handle termination condition (Leaf node).
      if (current_node.is_leaf_) {
        stack->push_back(ParseFormulaRecursionStack(
            terms[current_index].first, current_node.formula_));
        ++current_index;
        continue;
      }

      // Not a leaf node; so this node will have two children. Create
      // sub-formulas for them.
      const bool is_original_div =
          terms[current_node.toggle_ + current_node.num_left_ - 1].second == 1;
      current_node.formula_->op_.type_ = OperationType::ARITHMETIC;
      current_node.formula_->op_.arithmetic_op_ =
          (is_original_div == current_node.sign_) ? ArithmeticOperation::MULT :
                                                    ArithmeticOperation::DIV;
      current_node.formula_->subterm_one_ = unique_ptr<Formula>(new Formula());
      current_node.formula_->subterm_two_ = unique_ptr<Formula>(new Formula());

      // Handle right sub-tree
      if (current_node.num_right_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_two_.get()));
      } else {
        const int num_right_children = current_node.num_right_ / 2;
        node_stack.push_back(NodeStackState(
            (is_original_div != current_node.sign_),
            false,
            current_node.toggle_ + current_node.num_left_,
            current_node.num_right_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_two_.get()));
      }

      // Handle left sub-tree
      if (current_node.num_left_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_one_.get()));
      } else {
        const int num_right_children = current_node.num_left_ / 2;
        node_stack.push_back(NodeStackState(
            current_node.sign_,
            false,
            current_node.toggle_,
            current_node.num_left_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_one_.get()));
      }
    }
    return true;
  }

  // Primary formula is not the product of two (or more) terms. Try splitting it
  // around '^' into base, exponent.
  terms.clear();
  if (!GetExponentTerms(term_str, "", &terms)) {
    *error_msg += "Failed to GetExponentTerms()\n";
    return false;
  }
  if (terms.size() > 1) {
    if (terms.size() > 2) {
      *error_msg += "Multiple exponent symbols found.\n";
      return false;
    }
    formula->op_.type_ = OperationType::ARITHMETIC;
    formula->op_.arithmetic_op_ = ArithmeticOperation::POW;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    formula->subterm_two_ = unique_ptr<Formula>(new Formula());
    stack->push_back(
        ParseFormulaRecursionStack(terms[0].first, formula->subterm_one_.get()));
    stack->push_back(
        ParseFormulaRecursionStack(terms[1].first, formula->subterm_two_.get()));
    return true;
  }

  // Check if the term is a special function.
  if (HasPrefixString(term_str, "ABS(") || HasPrefixString(term_str, "Abs(") ||
      HasPrefixString(term_str, "abs(")) {
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found ABS operation, but no closing parentheses: '" +
          term_str + "'\n";
      return false;
    }
    formula->op_.type_ = OperationType::ARITHMETIC;
    formula->op_.arithmetic_op_ = ArithmeticOperation::ABS;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    stack->push_back(ParseFormulaRecursionStack(
        term_str.substr(4, term_str.length() - 5), formula->subterm_one_.get()));
    return true;
  } else if (HasPrefixString(term_str, "|")) {
    if (!HasSuffixString(term_str, "|")) {
      *error_msg += "Found ABS operation, but no closing parentheses: '" +
          term_str + "'\n";
      return false;
    }
    formula->op_.type_ = OperationType::ARITHMETIC;
    formula->op_.arithmetic_op_ = ArithmeticOperation::ABS;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    stack->push_back(ParseFormulaRecursionStack(
        term_str.substr(1, term_str.length() - 2), formula->subterm_one_.get()));
    return true;
  } else if (
      HasPrefixString(term_str, "NOT(") || HasPrefixString(term_str, "Not(") ||
      HasPrefixString(term_str, "not(")) {
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found NOT operation, but no closing parentheses: '" +
          term_str + "'\n";
      return false;
    }
    formula->op_.type_ = OperationType::BOOLEAN;
    formula->op_.gate_op_ = BooleanOperation::NOT;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    stack->push_back(ParseFormulaRecursionStack(
        term_str.substr(4, term_str.length() - 5), formula->subterm_one_.get()));
    return true;
  } else if (
      HasPrefixString(term_str, "SQRT(") || HasPrefixString(term_str, "Sqrt(") ||
      HasPrefixString(term_str, "sqrt(")) {
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found SQRT operation, but no closing parentheses: '" +
          term_str + "'\n";
      return false;
    }
    formula->op_.type_ = OperationType::ARITHMETIC;
    formula->op_.arithmetic_op_ = ArithmeticOperation::SQRT;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    stack->push_back(ParseFormulaRecursionStack(
        term_str.substr(5, term_str.length() - 6), formula->subterm_one_.get()));
    return true;
  } else if (
      HasPrefixString(term_str, "VEC(") || HasPrefixString(term_str, "Vec(") ||
      HasPrefixString(term_str, "vec(")) {
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found VEC operation, but no closing parentheses: '" +
          term_str + "'\n";
      return false;
    }
    terms.clear();
    if (!GetArgumentTerms(
            term_str.substr(4, term_str.length() - 5), "", &terms)) {
      *error_msg += "Failed to GetArgumentTerms()\n";
      return false;
    }
    if (terms.size() <= 1) {
      *error_msg += "Found VEC operation, but couldn't decipher arguments: '" +
          term_str + "'\n";
      return false;
    }
    num_terms = (int) terms.size();
    int current_index = 0;
    const int num_right = num_terms / 2;
    vector<NodeStackState> node_stack(
        1,
        NodeStackState(
            false, false, 0, num_terms - num_right, num_right, formula));
    while (!node_stack.empty()) {
      NodeStackState current_node = node_stack.back();
      node_stack.pop_back();

      // Handle termination condition (Leaf node).
      if (current_node.is_leaf_) {
        stack->push_back(ParseFormulaRecursionStack(
            terms[current_index].first, current_node.formula_));
        ++current_index;
        continue;
      }

      // Not a leaf node; so this node will have two children. Create
      // sub-formulas for them.
      current_node.formula_->op_.type_ = OperationType::ARITHMETIC;
      current_node.formula_->op_.arithmetic_op_ = ArithmeticOperation::VEC;
      current_node.formula_->subterm_one_ = unique_ptr<Formula>(new Formula());
      current_node.formula_->subterm_two_ = unique_ptr<Formula>(new Formula());

      // Handle right sub-tree
      if (current_node.num_right_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_two_.get()));
      } else {
        const int num_right_children = current_node.num_right_ / 2;
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            false,
            current_node.toggle_ + current_node.num_left_,
            current_node.num_right_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_two_.get()));
      }

      // Handle left sub-tree
      if (current_node.num_left_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_one_.get()));
      } else {
        const int num_right_children = current_node.num_left_ / 2;
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            false,
            current_node.toggle_,
            current_node.num_left_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_one_.get()));
      }
    }
    return true;
  } else if (
      HasPrefixString(term_str, "MIN(") || HasPrefixString(term_str, "Min(") ||
      HasPrefixString(term_str, "min(") || HasPrefixString(term_str, "MAX(") ||
      HasPrefixString(term_str, "Max(") || HasPrefixString(term_str, "max(")) {
    const bool is_max = HasPrefixString(term_str, "MAX(") ||
        HasPrefixString(term_str, "Max(") || HasPrefixString(term_str, "max(");
    const string op_str = is_max ? "MAX" : "MIN";
    const ArithmeticOperation min_max_op =
        is_max ? ArithmeticOperation::MAX : ArithmeticOperation::MIN;
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found " + op_str +
          " operation, but no closing parentheses: '" + term_str + "'\n";
      return false;
    }
    terms.clear();
    if (!GetArgumentTerms(
            term_str.substr(4, term_str.length() - 5), "", &terms)) {
      *error_msg += "Failed to GetArgumentTerms()\n";
      return false;
    }
    if (terms.size() <= 1) {
      *error_msg += "Found " + op_str +
          " operation, but couldn't decipher arguments: '" + term_str + "'\n";
      return false;
    }
    num_terms = (int) terms.size();
    int current_index = 0;
    const int num_right = num_terms / 2;
    vector<NodeStackState> node_stack(
        1,
        NodeStackState(
            false, false, 0, num_terms - num_right, num_right, formula));
    while (!node_stack.empty()) {
      NodeStackState current_node = node_stack.back();
      node_stack.pop_back();

      // Handle termination condition (Leaf node).
      if (current_node.is_leaf_) {
        stack->push_back(ParseFormulaRecursionStack(
            terms[current_index].first, current_node.formula_));
        ++current_index;
        continue;
      }

      // Not a leaf node; so this node will have two children. Create
      // sub-formulas for them.
      current_node.formula_->op_.type_ = OperationType::ARITHMETIC;
      current_node.formula_->op_.arithmetic_op_ = min_max_op;
      current_node.formula_->subterm_one_ = unique_ptr<Formula>(new Formula());
      current_node.formula_->subterm_two_ = unique_ptr<Formula>(new Formula());

      // Handle right sub-tree
      if (current_node.num_right_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_two_.get()));
      } else {
        const int num_right_children = current_node.num_right_ / 2;
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            false,
            current_node.toggle_ + current_node.num_left_,
            current_node.num_right_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_two_.get()));
      }

      // Handle left sub-tree
      if (current_node.num_left_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_one_.get()));
      } else {
        const int num_right_children = current_node.num_left_ / 2;
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            false,
            current_node.toggle_,
            current_node.num_left_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_one_.get()));
      }
    }
    return true;
  } else if (
      HasPrefixString(term_str, "ARGMIN(") ||
      HasPrefixString(term_str, "Argmin(") ||
      HasPrefixString(term_str, "argmin(") ||
      HasPrefixString(term_str, "ARGMAX(") ||
      HasPrefixString(term_str, "Argmax(") ||
      HasPrefixString(term_str, "argmax(")) {
    const bool is_max = HasPrefixString(term_str, "ARGMAX(") ||
        HasPrefixString(term_str, "Argmax(") ||
        HasPrefixString(term_str, "argmax(");
    const string op_str = is_max ? "ARGMAX" : "ARGMIN";
    const ArithmeticOperation min_max_op =
        is_max ? ArithmeticOperation::ARGMAX : ArithmeticOperation::ARGMIN;
    const ArithmeticOperation inner_min_max_op = is_max ?
        ArithmeticOperation::ARGMAX_INTERNAL :
        ArithmeticOperation::ARGMIN_INTERNAL;
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found " + op_str +
          " operation, but no closing parentheses: '" + term_str + "'\n";
      return false;
    }
    terms.clear();
    if (!GetArgumentTerms(
            term_str.substr(7, term_str.length() - 8), "", &terms)) {
      *error_msg += "Failed to GetArgumentTerms()\n";
      return false;
    }
    if (terms.size() <= 1) {
      *error_msg += "Found " + op_str +
          " operation, but couldn't decipher arguments: '" + term_str + "'\n";
      return false;
    }
    num_terms = (int) terms.size();
    int current_index = 0;
    // NOTE: If there are only two terms, handling this operation is straightforward.
    // If there are more than one terms, we handle this in the usual way; namely,
    // by writing it as a nested expression of two-term arguments, e.g.:
    //   ARGMIN(a, b, c, d, e) = ARGMIN(ARGMIN(a,  b), ARGMIN(c, ARGMIN(d, e)))
    // Notice however that this nesting is not quite this simplistic, since
    // e.g. when doing: ARGMIN(c, ARGMIN(d, e)), this a priori would look like:
    //   ARGMIN(c, (0, 1)),
    // since ARGMIN(d, e) spits out a characteristic vector (as opposed to the
    // *value* of the min). Thus, we'd either need special logic to recast
    // (0, 1) as a value (by doing an inner-product with (d, e)), or we need
    // to have ARGMIN perpetuate the min as well as the characteristic vector.
    // But, the final ARGMIN just should output the characteristic vector (not
    // the min). To distinguish these, we introduce a new "ARGMIN_INTERNAL"
    // operator, which is like the concatenation of MIN with ARGMIN: It outputs
    // both the minimum value and the characteristic value. Thus, for more
    // than two arguments for ARGMIN/ARGMAX, we parse this by making the outer-
    // most operation ARGMIN/ARGMAX, and all the inner nested arguments are
    // ARGMIN_INTERNAL/ARGMAX_INTERNAL.
    bool is_outermost_op = true;
    const int num_right = num_terms - 1;
    vector<NodeStackState> node_stack(
        1,
        NodeStackState(
            false, false, 0, num_terms - num_right, num_right, formula));
    while (!node_stack.empty()) {
      NodeStackState current_node = node_stack.back();
      node_stack.pop_back();

      // Handle termination condition (Leaf node).
      if (current_node.is_leaf_) {
        stack->push_back(ParseFormulaRecursionStack(
            terms[current_index].first, current_node.formula_));
        ++current_index;
        is_outermost_op = false;
        continue;
      }

      // Not a leaf node; so this node will have two children. Create
      // sub-formulas for them.
      current_node.formula_->op_.type_ = OperationType::ARITHMETIC;
      current_node.formula_->op_.arithmetic_op_ =
          is_outermost_op ? min_max_op : inner_min_max_op;
      current_node.formula_->subterm_one_ = unique_ptr<Formula>(new Formula());
      current_node.formula_->subterm_two_ = unique_ptr<Formula>(new Formula());
      is_outermost_op = false;

      // Handle right sub-tree
      if (current_node.num_right_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_two_.get()));
      } else {
        const int num_right_children = current_node.num_right_ / 2;
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            false,
            current_node.toggle_ + current_node.num_left_,
            current_node.num_right_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_two_.get()));
      }

      // Handle left sub-tree
      if (current_node.num_left_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_one_.get()));
      } else {
        const int num_right_children = current_node.num_left_ / 2;
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            false,
            current_node.toggle_,
            current_node.num_left_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_one_.get()));
      }
    }
    return true;
  } else if (
      HasPrefixString(term_str, "ARGMIN_INTERNAL(") ||
      HasPrefixString(term_str, "Argmin_Internal(") ||
      HasPrefixString(term_str, "argmin_internal(") ||
      HasPrefixString(term_str, "ARGMAX_INTERNAL(") ||
      HasPrefixString(term_str, "Argmax_Internal(") ||
      HasPrefixString(term_str, "argmax_internal(")) {
    const bool is_max = HasPrefixString(term_str, "ARGMAX") ||
        HasPrefixString(term_str, "Argmax") ||
        HasPrefixString(term_str, "argmax");
    const string op_str = is_max ? "ARGMAX_INTERNAL" : "ARGMIN_INTERNAL";
    const ArithmeticOperation min_max_op = is_max ?
        ArithmeticOperation::ARGMAX_INTERNAL :
        ArithmeticOperation::ARGMIN_INTERNAL;
    const ArithmeticOperation inner_min_max_op = is_max ?
        ArithmeticOperation::ARGMAX_INTERNAL :
        ArithmeticOperation::ARGMIN_INTERNAL;
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found " + op_str +
          " operation, but no closing parentheses: '" + term_str + "'\n";
      return false;
    }
    terms.clear();
    if (!GetArgumentTerms(
            term_str.substr(16, term_str.length() - 17), "", &terms)) {
      *error_msg += "Failed to GetArgumentTerms()\n";
      return false;
    }
    if (terms.size() <= 1) {
      *error_msg += "Found " + op_str +
          " operation, but couldn't decipher arguments: '" + term_str + "'\n";
      return false;
    }
    num_terms = (int) terms.size();
    int current_index = 0;
    // NOTE: If there are only two terms, handling this operation is straightforward.
    // If there are more than one terms, we handle this in the usual way; namely,
    // by writing it as a nested expression of two-term arguments, e.g.:
    //   ARGMIN(a, b, c, d, e) = ARGMIN(ARGMIN(a,  b), ARGMIN(c, ARGMIN(d, e)))
    // Notice however that this nesting is not quite this simplistic, since
    // e.g. when doing: ARGMIN(c, ARGMIN(d, e)), this a priori would look like:
    //   ARGMIN(c, (0, 1)),
    // since ARGMIN(d, e) spits out a characteristic vector (as opposed to the
    // *value* of the min). Thus, we'd either need special logic to recast
    // (0, 1) as a value (by doing an inner-product with (d, e)), or we need
    // to have ARGMIN perpetuate the min as well as the characteristic vector.
    // But, the final ARGMIN just should output the characteristic vector (not
    // the min). To distinguish these, we introduce a new "ARGMIN_INTERNAL"
    // operator, which is like the concatenation of MIN with ARGMIN: It outputs
    // both the minimum value and the characteristic value. Thus, for more
    // than two arguments for ARGMIN/ARGMAX, we parse this by making the outer-
    // most operation ARGMIN/ARGMAX, and all the inner nested arguments are
    // ARGMIN_INTERNAL/ARGMAX_INTERNAL.
    bool is_outermost_op = true;
    const int num_right = num_terms - 1;
    vector<NodeStackState> node_stack(
        1,
        NodeStackState(
            false, false, 0, num_terms - num_right, num_right, formula));
    while (!node_stack.empty()) {
      NodeStackState current_node = node_stack.back();
      node_stack.pop_back();

      // Handle termination condition (Leaf node).
      if (current_node.is_leaf_) {
        stack->push_back(ParseFormulaRecursionStack(
            terms[current_index].first, current_node.formula_));
        ++current_index;
        is_outermost_op = false;
        continue;
      }

      // Not a leaf node; so this node will have two children. Create
      // sub-formulas for them.
      current_node.formula_->op_.type_ = OperationType::ARITHMETIC;
      current_node.formula_->op_.arithmetic_op_ =
          is_outermost_op ? min_max_op : inner_min_max_op;
      current_node.formula_->subterm_one_ = unique_ptr<Formula>(new Formula());
      current_node.formula_->subterm_two_ = unique_ptr<Formula>(new Formula());
      is_outermost_op = false;

      // Handle right sub-tree
      if (current_node.num_right_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_two_.get()));
      } else {
        const int num_right_children = current_node.num_right_ / 2;
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            false,
            current_node.toggle_ + current_node.num_left_,
            current_node.num_right_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_two_.get()));
      }

      // Handle left sub-tree
      if (current_node.num_left_ == 1) {
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            true,
            0 /* Ignored */,
            0,
            0,
            current_node.formula_->subterm_one_.get()));
      } else {
        const int num_right_children = current_node.num_left_ / 2;
        node_stack.push_back(NodeStackState(
            false /* Ignored */,
            false,
            current_node.toggle_,
            current_node.num_left_ - num_right_children,
            num_right_children,
            current_node.formula_->subterm_one_.get()));
      }
    }
    return true;
  } else if (
      HasPrefixString(term_str, "IP(") || HasPrefixString(term_str, "Ip(") ||
      HasPrefixString(term_str, "ip(") ||
      HasPrefixString(term_str, "INNER_PRODUCT(") ||
      HasPrefixString(term_str, "Inner_Product(") ||
      HasPrefixString(term_str, "Inner_product(") ||
      HasPrefixString(term_str, "inner_product(")) {
    const int prefix_length = term_str.substr(2, 1) == "(" ? 2 : 13;
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found POW operation, but no closing parentheses: '" +
          term_str + "'\n";
      return false;
    }
    terms.clear();
    if (!GetArgumentTerms(
            term_str.substr(
                1 + prefix_length, term_str.length() - 2 - prefix_length),
            "",
            &terms)) {
      *error_msg += "Failed to GetArgumentTerms()\n";
      return false;
    }
    if (terms.size() != 2) {
      *error_msg += "Found POW operation, with " + Itoa(terms.size()) +
          " arguments: '" + term_str + "'\n";
      return false;
    }
    formula->op_.type_ = OperationType::ARITHMETIC;
    formula->op_.arithmetic_op_ = ArithmeticOperation::INNER_PRODUCT;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    formula->subterm_two_ = unique_ptr<Formula>(new Formula());
    stack->push_back(
        ParseFormulaRecursionStack(terms[0].first, formula->subterm_one_.get()));
    stack->push_back(
        ParseFormulaRecursionStack(terms[1].first, formula->subterm_two_.get()));
    return true;
  } else if (
      HasPrefixString(term_str, "POW(") || HasPrefixString(term_str, "Pow(") ||
      HasPrefixString(term_str, "pow(")) {
    if (!HasSuffixString(term_str, ")")) {
      *error_msg += "Found POW operation, but no closing parentheses: '" +
          term_str + "'\n";
      return false;
    }
    terms.clear();
    if (!GetArgumentTerms(
            term_str.substr(4, term_str.length() - 5), "", &terms)) {
      *error_msg += "Failed to GetArgumentTerms()\n";
      return false;
    }
    if (terms.size() != 2) {
      *error_msg += "Found POW operation, with " + Itoa(terms.size()) +
          " arguments: '" + term_str + "'\n";
      return false;
    }
    formula->op_.type_ = OperationType::ARITHMETIC;
    formula->op_.arithmetic_op_ = ArithmeticOperation::POW;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    formula->subterm_two_ = unique_ptr<Formula>(new Formula());
    stack->push_back(
        ParseFormulaRecursionStack(terms[0].first, formula->subterm_one_.get()));
    stack->push_back(
        ParseFormulaRecursionStack(terms[1].first, formula->subterm_two_.get()));
    return true;
  }

  // Primary formula has only one term. Try to parse.

  // Check factorial first, since it is the unique time a formula may
  // start with '(' but not end in ')', as in e.g. (n - 1)!.
  if (HasSuffixString(term_str, "!")) {
    if (term_str.length() < 2) {
      *error_msg +=
          "Found FACTORIAL ('!') operation, but term is empty otherwise";
      return false;
    }
    formula->op_.type_ = OperationType::ARITHMETIC;
    formula->op_.arithmetic_op_ = ArithmeticOperation::FACTORIAL;
    formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    // Check if character before '!' is a closing parenthesis.
    if (term_str.substr(term_str.length() - 2, 1) == ")") {
      if (!HasPrefixString(term_str, "(")) {
        *error_msg += "Found closing parentheses before factorial sign, but no "
                      "open parentheses at the start: '" +
            term_str + "'\n";
        return false;
      }
      stack->push_back(ParseFormulaRecursionStack(
          term_str.substr(1, term_str.length() - 3),
          formula->subterm_one_.get()));
    } else {
      stack->push_back(ParseFormulaRecursionStack(
          term_str.substr(0, term_str.length() - 1),
          formula->subterm_one_.get()));
    }
    return true;
  }

  // Check for extraneous extra enclosing grouping symbols.
  // Notice we stop short of the end of kGroupingSymbols, because we don't want
  // to strip extraneous || value signs (since these should have been accounted
  // for above, and also because they are not simply a grouping symbol, and so
  // the meaning of the formula will change if you simply strip them away).
  string stripped;
  if (!StripEnclosingGroupingSymbols(term_str, &stripped)) {
    *error_msg += "Failed to StripEnclosingGroupingSymbols()\n";
    return false;
  }
  if (stripped.length() < term_str.length()) {
    stack->push_back(ParseFormulaRecursionStack(stripped, formula));
    return true;
  }

  // Check for leading negative sign.
  if (HasPrefixString(term_str, "-")) {
    GenericValue value;
    if (ParseIfInteger(true, term_str.substr(1), &value) ||
        ParseIfDouble(true, term_str.substr(1), &value)) {
      formula->op_.type_ = OperationType::BOOLEAN;
      formula->op_.gate_op_ = BooleanOperation::IDENTITY;
      formula->value_ = value;
      return true;
    } else {
      formula->op_.type_ = OperationType::ARITHMETIC;
      formula->op_.arithmetic_op_ = ArithmeticOperation::FLIP_SIGN;
      formula->subterm_one_ = unique_ptr<Formula>(new Formula());
      stack->push_back(ParseFormulaRecursionStack(
          term_str.substr(1), formula->subterm_one_.get()));
      return true;
    }
  }

  // If we've made it here, there is no more reduction that can be done.
  // Check to see if it is a variable name.
  if (var_names.find(term_str) != var_names.end()) {
    formula->op_.type_ = OperationType::BOOLEAN;
    formula->op_.gate_op_ = BooleanOperation::IDENTITY;
    // Squeeze the variable name into as few as characters as possible.
    // Note that this doesn't really matter: the DataType of the variable
    // is irrelevant; i.e. it just holds the name of the variable; in
    // particular, even if this variable represents a STRING, the
    // specific DataType (as in STRINGXX) is NOT specified by the Formula,
    // i.e. the STRINGXX DataType used for the variable is NOT the same
    // thing as the STRINGXX DataType that this variable's value will be.
    const size_t length = term_str.length();
    if (length > 128) {
      *error_msg += "Variable name too big to fit in all STRINGXX DataTypes: " +
          Itoa(length) + "\n";
      return false;
    }
    formula->value_ = GenericValue(term_str);
    return true;
  }

  // Check if this term is a coefficient followed by a variable name, e.g. "2x".
  for (const string& var_name : var_names) {
    if (HasSuffixString(term_str, var_name)) {
      const string non_var = StripSuffixString(term_str, var_name);
      if (ParseIfInteger(false, non_var, nullptr) ||
          ParseIfDouble(false, non_var, nullptr)) {
        formula->op_.type_ = OperationType::ARITHMETIC;
        formula->op_.arithmetic_op_ = ArithmeticOperation::MULT;
        formula->subterm_one_ = unique_ptr<Formula>(new Formula());
        formula->subterm_one_->op_.type_ = OperationType::BOOLEAN;
        formula->subterm_one_->op_.gate_op_ = BooleanOperation::IDENTITY;
        if (!ParseIfInteger(false, non_var, &(formula->subterm_one_->value_)) &&
            !ParseIfDouble(false, non_var, &(formula->subterm_one_->value_))) {
          *error_msg +=
              "This should never happen, as above condition should have failed.\n";
          return false;
        }
        formula->subterm_two_ = unique_ptr<Formula>(new Formula());
        stack->push_back(
            ParseFormulaRecursionStack(var_name, formula->subterm_two_.get()));
        return true;
      }
    }
  }

  // Not a variable name. Try to parse as a numeric value; return false if not.
  GenericValue value;
  if (ParseIfInteger(false, term_str, &formula->value_) ||
      ParseIfDouble(false, term_str, &formula->value_)) {
    formula->op_.type_ = OperationType::BOOLEAN;
    formula->op_.gate_op_ = BooleanOperation::IDENTITY;
    return true;
  }

  // Failed to parse this term. If enforce_var_names is true, return false.
  // Otherwise, just treat this term as a variable name.
  if (enforce_var_names) {
    *error_msg += "Unrecognized term '" + term_str +
        "' was not found among variable names.\n";
    return false;
  }
  if (term_str.length() > 128) {
    *error_msg += "Variable name too big to fit in all STRINGXX DataTypes: " +
        Itoa(term_str.length()) + "\n";
    return false;
  }
  formula->op_.type_ = OperationType::BOOLEAN;
  formula->op_.gate_op_ = BooleanOperation::IDENTITY;
  formula->value_ = GenericValue(term_str);

  return true;
}

string ExpandFormula(
    const bool is_sum,
    const int start_index,
    const int end_index,
    const string& index_name,
    const string& input) {
  if (input.empty() || start_index < 0 || end_index < 0 ||
      start_index > end_index) {
    LOG_FATAL("Bad indices for \\sum or \\product");
  }

  // Search input string for variables marked with the index subscript.
  const string to_match = "}_" + index_name;
  string suffix = input;
  vector<pair<string, string>> parts;
  size_t match_pos = suffix.find(to_match);
  while (match_pos != string::npos) {
    const string prefix = suffix.substr(0, match_pos);
    const size_t var_start_pos = prefix.rfind("{");
    if (var_start_pos == string::npos || var_start_pos == match_pos - 1) {
      LOG_FATAL("Bad indices for \\sum or \\product");
    }
    parts.push_back(make_pair(
        prefix.substr(0, var_start_pos),
        prefix.substr(var_start_pos + 1, match_pos - var_start_pos - 1)));
    suffix = suffix.substr(match_pos + to_match.length());
    match_pos = suffix.find(to_match);
  }
  if (!suffix.empty()) {
    parts.push_back(make_pair(suffix, ""));
  }

  // Expand the expression, explicitly writing out all of the
  // (1 + end_index - start_index) terms, and replacing "{var}_index_name"
  // with var_i and each occurrence of 'index_name' with 'i' for each
  // i in [start_index, end_index].
  string to_return = "";
  for (int i = start_index; i <= end_index; ++i) {
    to_return += "(";
    for (const pair<string, string>& part : parts) {
      to_return += Replace(part.first, index_name, Itoa(i));
      if (!part.second.empty()) {
        to_return += part.second + Itoa(i);
      }
    }
    to_return += ")";
    if (i < end_index) to_return += is_sum ? "+" : "*";
  }

  return to_return;
}

bool ExpandSumOrProduct(
    const size_t& start_pos, const string& type, string* input) {
  // Parse Index variable name and start index value.
  string suffix = input->substr(start_pos + 3 + type.length());
  const size_t eq_pos = suffix.find("=");
  const size_t close_pos = suffix.find("}");
  if (eq_pos == string::npos || eq_pos == 0 || close_pos == string::npos ||
      eq_pos + 1 >= close_pos) {
    LOG_FATAL("Bad usage of \\" + type);
  }
  if (suffix.substr(close_pos + 1, 1) != "^" ||
      suffix.substr(close_pos + 2, 1) != "{") {
    LOG_FATAL("Bad usage of \\" + type);
  }
  const string index_name = suffix.substr(0, eq_pos);
  int start_index;
  if (!Stoi(suffix.substr(eq_pos + 1, close_pos - eq_pos - 1), &start_index)) {
    LOG_FATAL(
        "Bad usage of \\" + type + ": Unable to parse start index: '" +
        suffix.substr(eq_pos + 1, close_pos - eq_pos - 1) + "'");
  }

  // Parse end index value.
  suffix = suffix.substr(close_pos + 3);
  const size_t final_close_pos = suffix.find("}");
  int end_index;
  if (final_close_pos == string::npos || final_close_pos == 0 ||
      suffix.substr(final_close_pos + 1, 1) != "(" ||
      !Stoi(suffix.substr(0, final_close_pos), &end_index)) {
    if (final_close_pos == string::npos || final_close_pos == 0 ||
        suffix.substr(final_close_pos + 1, 1) != "(") {
      LOG_FATAL("Bad usage of \\" + type);
    } else {
      LOG_FATAL(
          "Bad usage of \\" + type + ": Unable to parse end index: '" +
          suffix.substr(0, final_close_pos) + "'");
    }
  }

  // Find closing parentheses, and split out formula lying inside the
  // \sum (or \product) from the rest of the formula lying outside.
  suffix = suffix.substr(final_close_pos + 1);
  size_t end_pos;
  if (!GetClosingSymbol(suffix, make_pair('(', ')'), &end_pos) ||
      end_pos == string::npos || end_pos == 0) {
    LOG_FATAL("Bad usage of \\" + type);
  }
  string expanded_str = ExpandFormula(
      type == "sum",
      start_index,
      end_index,
      index_name,
      suffix.substr(1, end_pos - 1));

  // Update final formula, as:
  //    (formula before the \sum or \product) + (expanded \sum or \product) +
  //    (formula after the \sum or \product)
  *input = input->substr(0, start_pos) + "(" + expanded_str + ")" +
      suffix.substr(end_pos + 1);

  return true;
}

bool ExpandSumAndProduct(string* input) {
  size_t sum_pos = input->find("\\sum_{");
  size_t product_pos = input->find("\\product_{");
  if (sum_pos == string::npos && product_pos == string::npos) return false;

  // Expand around first keyword (\sum or \product) that appears.
  if (product_pos == string::npos ||
      (sum_pos != string::npos && sum_pos < product_pos)) {
    return ExpandSumOrProduct(sum_pos, "sum", input);
  }
  return ExpandSumOrProduct(product_pos, "product", input);
}

bool ParseFormula(
    const bool reduce_formula,
    const bool clean_input,
    const string& term_str,
    const bool enforce_var_names,
    const set<string>& var_names,
    Formula* formula,
    string* error_msg) {
  string current_term_str = term_str;
  if (clean_input) {
    // Remove all whitespace.
    string term_str_cleaned = RemoveAllWhitespace(term_str);

    // Replace all scientific notation with actual numbers, e.g.
    //   5.1e-2 -> 5.1 * 0.01
    term_str_cleaned = RemoveScientificNotation(term_str_cleaned);

    // Replace all instances of "+-", which can appear if user e.g. wanted
    // to add a negative value, which simply "-".
    current_term_str = Replace(term_str_cleaned, "+-", "-");

    // Replace all implicit multiplication with explicity symbol, i.e.:
    //   ")(" -> ")*("
    current_term_str = Replace(current_term_str, ")(", ")*(");

    // Replace all \sum and \product terms with the sum/product expanded out.
    bool keep_reducing = true;
    while (keep_reducing) {
      keep_reducing = ExpandSumAndProduct(&current_term_str);
    }
  }

  vector<ParseFormulaRecursionStack> stack;
  stack.push_back(ParseFormulaRecursionStack(current_term_str, formula));
  string local_error_msg = "";
  string* error_msg_ptr = error_msg == nullptr ? &local_error_msg : error_msg;
  while (!stack.empty()) {
    if (!ParseFormula(enforce_var_names, var_names, error_msg_ptr, &stack)) {
      LOG_ERROR(
          "Failed to parse (cleaned) formula: \n" + current_term_str +
          "\nError message:\n" + *error_msg_ptr);
      return false;
    }
  }

  if (reduce_formula) ReduceFormula(formula);

  return true;
}

void ReduceFormula(Formula* formula) {
  if (formula == nullptr) return;

  // Reduce left/right children formulas.
  ReduceFormula(formula->subterm_one_.get());
  ReduceFormula(formula->subterm_two_.get());

  // Now reduce present formula, if possible.
  if (formula->subterm_one_ != nullptr &&
      formula->subterm_one_->op_.type_ == OperationType::BOOLEAN &&
      formula->subterm_one_->op_.gate_op_ == BooleanOperation::IDENTITY &&
      IsNumericDataType(formula->subterm_one_->value_) &&
      formula->subterm_two_ != nullptr &&
      formula->subterm_two_->op_.type_ == OperationType::BOOLEAN &&
      formula->subterm_two_->op_.gate_op_ == BooleanOperation::IDENTITY &&
      IsNumericDataType(formula->subterm_two_->value_)) {
    if (!MergeValuesViaOperator(
            formula->op_,
            formula->subterm_one_->value_,
            formula->subterm_two_->value_,
            &(formula->value_))) {
      LOG_FATAL(
          "Failed to combine (" +
          GetGenericValueString(formula->subterm_one_->value_) +
          GetOpString(formula->op_) +
          GetGenericValueString(formula->subterm_two_->value_) + ")");
    }
    formula->op_.type_ = OperationType::BOOLEAN;
    formula->op_.gate_op_ = BooleanOperation::IDENTITY;
    formula->subterm_one_.reset(nullptr);
    formula->subterm_two_.reset(nullptr);
  }
}

void CopyFormula(const Formula& formula, Formula* new_formula) {
  new_formula->op_ = formula.op_;
  new_formula->value_ = formula.value_;

  if (formula.subterm_one_ != nullptr) {
    new_formula->subterm_one_ = unique_ptr<Formula>(new Formula());
    CopyFormula(*formula.subterm_one_, new_formula->subterm_one_.get());
  }
  if (formula.subterm_two_ != nullptr) {
    new_formula->subterm_two_ = unique_ptr<Formula>(new Formula());
    CopyFormula(*formula.subterm_two_, new_formula->subterm_two_.get());
  }
}

Formula CopyFormula(const Formula& formula) {
  Formula to_return;
  CopyFormula(formula, &to_return);
  return to_return;
}

bool EvaluateFormula(
    const map<string, GenericValue>& var_values,
    set<string>* vars_seen,
    string* error_msg,
    vector<GenericValue>* values,
    vector<StackParameters>* evaluate_stack) {
  string junk_err_msg = "";
  string* error_msg_ptr = (error_msg == nullptr) ? &junk_err_msg : error_msg;

  const StackParameters current = evaluate_stack->back();
  evaluate_stack->pop_back();

  // Test if this is a "leaf" term: each subterm has already been (recursively)
  // evaluated, so just need to combine its subformulas with the operation.
  if (current.formula_ == nullptr) {
    if (current.op_.type_ == OperationType::BOOLEAN &&
        (current.op_.gate_op_ == BooleanOperation::IDENTITY ||
         current.op_.gate_op_ == BooleanOperation::UNKNOWN)) {
      *error_msg_ptr += "Unexpected Identity operation in the call stack.\n";
      return false;
    } else if (IsDoubleInputOperation(current.op_)) {
      if (values->size() < 2) {
        *error_msg_ptr += "Not enough computed values to complete the op.\n";
        return false;
      }
      const GenericValue value_two = values->back();
      values->pop_back();
      const GenericValue value_one = values->back();
      values->pop_back();
      values->push_back(GenericValue());
      GenericValue& combined = values->back();
      if (!MergeValuesViaOperator(
              current.op_, value_one, value_two, &combined)) {
        *error_msg_ptr += "Filed to merge " + GetGenericValueString(value_one) +
            " and " + GetGenericValueString(value_two) + " via " +
            GetOpString(current.op_);
        return false;
      }
      return true;
    } else if (IsSingleInputOperation(current.op_)) {
      if (values->empty()) {
        *error_msg_ptr += "Not enough computed values to complete the op.\n";
        return false;
      }
      const GenericValue value_one = values->back();
      values->pop_back();
      values->push_back(GenericValue());
      GenericValue& combined = values->back();
      if (!ApplyOperator(current.op_, value_one, &combined)) {
        *error_msg_ptr += "Filed to apply operator " + GetOpString(current.op_) +
            " to value " + GetGenericValueString(value_one);
        return false;
      }
      return true;
    } else {
      *error_msg_ptr += "Unexpected op: " + GetOpString(current.op_) + ".\n";
      return false;
    }
    return true;
  }

  // The fact that we made it here means that we were not able to evaluate
  // this term, which either means this is a leaf value, or that it has
  // subformulas that need to be evaluated first.
  //   - Self-Operation.
  const Formula& formula = *(current.formula_);
  if (formula.op_.type_ == OperationType::BOOLEAN &&
      formula.op_.gate_op_ == BooleanOperation::IDENTITY) {
    const GenericValue& value = formula.value_;
    if (IsNumericDataType(value)) {
      values->push_back(value);
      return true;
    } else if (IsStringDataType(value)) {
      const string value_str = GetGenericValueString(value);
      map<string, GenericValue>::const_iterator itr = var_values.find(value_str);
      if (itr == var_values.end()) {
        *error_msg_ptr += "ERROR: Failed to evaluate formula '" +
            GetFormulaString(formula) + "': Could not find var name '" +
            value_str + "' in var_values.\n";
        return false;
      }
      values->push_back(itr->second);
      if (vars_seen != nullptr) vars_seen->insert(itr->first);
      return true;
    } else {
      *error_msg_ptr += "ERROR: Unrecognized GenericValue type: " +
          Itoa(static_cast<int>(value.type_)) + "\n";
      return false;
    }

    //   - 2-Term Operations.
  } else if (IsDoubleInputOperation(formula.op_)) {
    if (formula.subterm_one_ == nullptr || formula.subterm_two_ == nullptr) {
      *error_msg_ptr +=
          "Unable to perform add/mult/pow: one of the subterms is null.";
      return false;
    }
    evaluate_stack->push_back(StackParameters(formula.op_));
    evaluate_stack->push_back(StackParameters(formula.subterm_two_.get()));
    evaluate_stack->push_back(StackParameters(formula.subterm_one_.get()));
    return true;
    //   - 1-Term Operations.
  } else if (IsSingleInputOperation(formula.op_)) {
    if (formula.subterm_one_ == nullptr) {
      *error_msg_ptr += "Unable to perform evaluation: subterm_one_ is null";
      return false;
    }
    if (formula.subterm_two_ != nullptr) {
      *error_msg_ptr += "Unable to perform evaluation: subterm_two_ is non-null";
      return false;
    }
    evaluate_stack->push_back(StackParameters(formula.op_));
    evaluate_stack->push_back(StackParameters(formula.subterm_one_.get()));
    return true;
  }

  *error_msg_ptr += "Unsupported operation: " + GetOpString(formula.op_);
  return false;
}

bool EvaluateFormula(
    const Formula& formula,
    const map<string, GenericValue>& var_values,
    GenericValue* value,
    set<string>* vars_seen,
    string* error_msg) {
  vector<StackParameters> evaluate_stack(1, StackParameters(&formula));
  vector<GenericValue> values;
  while (!evaluate_stack.empty()) {
    if (!EvaluateFormula(
            var_values, vars_seen, error_msg, &values, &evaluate_stack)) {
      return false;
    }
  }

  if (values.size() != 1) {
    *error_msg += "Unexpected number of values: " + Itoa(values.size()) + "\n";
    return false;
  }

  *value = values[0];

  return true;
}

}  // namespace math_utils
