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

sst_array_cmp() {

  local -r sst_ir='^(0|[1-9][0-9]*)$'

  local sst_xs
  local sst_ys
  local sst_xis
  local sst_yis
  local sst_xs_size
  local sst_ys_size
  local sst_min
  local sst_i
  local sst_xi
  local sst_yi
  local sst_x
  local sst_y

  sst_expect_argument_count $# 2

  sst_xs=$1
  sst_ys=$2

  sst_expect_basic_identifier "$sst_xs"
  sst_expect_basic_identifier "$sst_ys"

  eval sst_xis="(\${$sst_xs[@]+\"\${!$sst_xs[@]}\"})"
  eval sst_yis="(\${$sst_ys[@]+\"\${!$sst_ys[@]}\"})"

  eval sst_xs_size="\${$sst_xs[@]+\${#$sst_xs[@]}}"
  eval sst_ys_size="\${$sst_ys[@]+\${#$sst_ys[@]}}"

  if ((sst_xs_size < sst_ys_size)); then
    sst_min=$sst_xs_size
  else
    sst_min=$sst_ys_size
  fi

  for ((sst_i = 0; sst_i != sst_min; ++sst_i)); do
    sst_xi=${sst_xis[sst_i]}
    sst_yi=${sst_yis[sst_i]}
    if [[ "$sst_xi" =~ $sst_ir && "$sst_yi" =~ $sst_ir ]]; then
      ((sst_xi < sst_yi)) && printf '%s\n' -1 && return
      ((sst_xi > sst_yi)) && printf '%s\n'  1 && return
    else
      [[ "$sst_xi" < "$sst_yi" ]] && printf '%s\n' -1 && return
      [[ "$sst_xi" > "$sst_yi" ]] && printf '%s\n'  1 && return
    fi
  done
  ((sst_xs_size < sst_ys_size)) && printf '%s\n' -1 && return
  ((sst_xs_size > sst_ys_size)) && printf '%s\n'  1 && return
  for ((sst_i = 0; sst_i != sst_min; ++sst_i)); do
    sst_xi=${sst_xis[sst_i]}
    sst_yi=${sst_yis[sst_i]}
    eval sst_x="\${$sst_xs[\$sst_xi]}"
    eval sst_y="\${$sst_ys[\$sst_yi]}"
    [[ "$sst_x" < "$sst_y" ]] && printf '%s\n' -1 && return
    [[ "$sst_x" > "$sst_y" ]] && printf '%s\n'  1 && return
  done
  printf '%s\n'  0

}; readonly -f sst_array_cmp
