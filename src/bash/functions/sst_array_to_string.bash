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

sst_array_to_string() {

  local -r sst_regex='^(0|[1-9][0-9]*)$'

  local sst_xs
  local sst_xis
  local sst_xs_size
  local sst_space
  local sst_i
  local sst_xi
  local sst_x

  sst_expect_argument_count $# 1

  sst_xs=$1

  sst_expect_basic_identifier "$sst_xs"

  eval sst_xis="(\${$sst_xs[@]+\"\${!$sst_xs[@]}\"})"

  eval sst_xs_size="\${$sst_xs[@]+\${#$sst_xs[@]}}"

  printf '('
  sst_space=
  for ((sst_i = 0; sst_i != sst_xs_size; ++sst_i)); do
    sst_xi=${sst_xis[sst_i]}
    eval sst_x="\${$sst_xs[\$sst_xi]}"
    if [[ ! "$sst_xi" =~ $sst_regex ]]; then
      sst_xi=$(sst_quote <<<"$sst_xi")
    fi
    sst_x=$(sst_quote <<<"$sst_x")
    printf '%s[%s]=%s' "$sst_space" "$sst_xi" "$sst_x"
    sst_space=' '
  done
  printf ')\n'

}; readonly -f sst_array_to_string
