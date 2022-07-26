#
# Copyright (C) 2021 Stealth Software Technologies, Inc.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#

#
# This function may be called by sst_install_utility, so we need to be
# careful to only use utilities that are always available and to write
# the code so that it behaves correctly under errexit suspension.
#

sst_expect_argument_count() {
  local bad
  bad=1
  local regex_number
  regex_number='^(0|[1-9][0-9]*)$'
  local regex_rangemin
  regex_rangemin='^(0|[1-9][0-9]*)-$'
  local regex_range
  regex_range='^(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$'
  local count
  local arg
  local min
  local max

  if (($# < 2)); then
    sst_barf 'bad argument count to sst_expect_argument_count itself: %s (expected 2-)' "$#"
  fi
  count=$1

  if [[ ! "$count" =~ $regex_number ]]; then
    sst_barf 'bad argument count syntax: "%s"' "$count"
  fi

  shift
  for arg; do
    if [[ "$arg" =~ $regex_number ]]; then
      if (($arg == $count)); then
        bad=0
      fi
    elif [[ "$arg" =~ $regex_rangemin ]]; then
      if ((${BASH_REMATCH[1]} <= $count)); then
        bad=0
      fi
    elif [[ "$arg" =~ $regex_range ]]; then
      min=${BASH_REMATCH[1]}
      max=${BASH_REMATCH[2]}
      if ((min > max)); then
        sst_barf 'bad argument count predicate syntax: "%s"' $arg
      fi
      if ((min <= count && count <= max)); then
        bad=0
      fi
    else
      sst_barf 'bad argument count syntax: "%s"' "$arg"
    fi
  done

  if ((bad)); then
    sst_barf 'bad argument count: %s (expected %s)' "$count" "$*"
  fi

}; readonly -f sst_expect_argument_count
