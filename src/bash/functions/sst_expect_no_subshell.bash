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

sst_expect_no_subshell() {

  local f

  sst_expect_argument_count $# 0-1

  if [[ "$BASHPID" != "$$" ]]; then

    if [[ $# == 1 ]]; then
      f=$1
    elif [[ "${FUNCNAME[1]}" == "${FUNCNAME[0]}" ]]; then
      f=${FUNCNAME[2]}
    else
      f=${FUNCNAME[1]}
    fi
    readonly f

    if [[ "$f" == - ]]; then
      sst_barf '%s' "expected no subshell"
    else
      sst_barf '%s' "$f must not be called in a subshell"
    fi

  fi

}; readonly -f sst_expect_no_subshell
