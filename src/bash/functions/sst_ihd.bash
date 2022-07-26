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

sst_ihd() {

  local adjust_n
  local n

  sst_expect_argument_count $# 0-1

  if (($# == 1)); then
    n=$1
    # TODO: sst_expect_integer "$n"
    if ((n < 0)); then
      adjust_n=1
    else
      adjust_n=0
    fi
  else
    n=0
    adjust_n=1
  fi
  readonly n
  readonly adjust_n

  awk -v n=$n -v adjust_n=$adjust_n '
    {
      if ($0 != "") {
        if (!have_indent) {
          if (adjust_n) {
            x = $0
            sub(/[^ ].*/, "", x)
            n += length(x)
          }
          for (i = 0; i < n; ++i) {
            indent = indent " "
          }
          have_indent = 1
        }
        if (substr($0, 1, n) == indent) {
          $0 = substr($0, n + 1)
        }
      }
      print
    }
  ' || return

}; readonly -f sst_ihd
