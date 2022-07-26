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

sst_expect_at_most_one_call() {

  local i
  local v
  local x

  # We need to look upward by two during the lazily loaded call.
  if [[ "${FUNCNAME[1]}" == "$FUNCNAME" ]]; then
    i=2
  else
    i=1
  fi
  readonly i

  if [[ "${FUNCNAME[i]}" == main ]]; then
    sst_barf '%s must only be called within a function' "$FUNCNAME"
  fi

  sst_expect_argument_count $# 0-1

  if (($# < 1)); then
    v=$(sst_underscore_slug "${FUNCNAME[i]}")_has_already_been_called
  else
    sst_expect_basic_identifier "$1"
    v=$1
  fi
  readonly v

  eval "x=\${$v+x}"
  if [[ "$x" ]]; then
    sst_barf '%s has already been called' "${FUNCNAME[i]}"
  fi

  eval "readonly $v=x"

}; readonly -f sst_expect_at_most_one_call
