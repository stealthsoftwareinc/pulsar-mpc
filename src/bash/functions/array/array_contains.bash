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
# array_contains <result> <array> <value>
#
# If <array> is unset, it will be considered to be an empty array
# instead of producing an unbound variable error.
#

array_contains() {

  #
  # Before Bash 4.4, "${x[@]}" causes an error when x is an empty array
  # and set -u is enabled. The workaround is to write ${x[@]+"${x[@]}"}
  # instead. See <https://stackoverflow.com/q/7577052>.
  #

  if (($# == 3)); then
    sst_expect_basic_identifier "$1"
    sst_expect_basic_identifier "$2"
    eval '
      local r'$1$2'=0
      local x'$1$2'
      for x'$1$2' in ${'$2'[@]+"${'$2'[@]}"}; do
        if [[ "$x'$1$2'" == "$3" ]]; then
          r'$1$2'=1
          break
        fi
      done
      '$1'=$r'$1$2'
    '
  else
    sst_expect_argument_count $# 3
  fi

}; readonly -f array_contains
