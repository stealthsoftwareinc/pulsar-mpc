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

sst_array_from_zterm() {

  sst_expect_argument_count $# 1-

  sst_expect_basic_identifier "$1"

  if (($# == 1)); then
    eval '

      local '$1'_list
      local '$1'_script

      '$1'_script=$sst_root_tmpdir/$FUNCNAME.$$.script
      readonly '$1'_script

      if [[ ! -f "$'$1'_script" ]]; then
        sst_ihs <<<"
          set -e
          q=\\'\''
          for x; do
            x=\$q\${x//\$q/\$q\\\\\$q\$q}\$q
            printf \"%s\\\\n\" \"\$x\"
          done
        " >"$'$1'_script"
      fi

      '$1'_list=$(xargs -0 bash "$'$1'_script")
      readonly '$1'_list

      eval '$1'="($'$1'_list)"

    '
  else
    eval '

      local '$1'_fifo
      local '$1'_pid

      '$1'_fifo=$sst_root_tmpdir/$FUNCNAME.$$.fifo
      readonly '$1'_fifo

      rm -f "$'$1'_fifo"
      mkfifo "$'$1'_fifo"

      shift
      "$@" <&0 >"$'$1'_fifo" &
      '$1'_pid=$!
      readonly '$1'_pid

      sst_array_from_zterm '$1' <"$'$1'_fifo"

      wait $'$1'_pid

    '
  fi

}; readonly -f sst_array_from_zterm
