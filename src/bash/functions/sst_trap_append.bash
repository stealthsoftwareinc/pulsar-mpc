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
# sst_trap_append <arg> <sigspec>...
#

sst_trap_append() {

  local arg
  local sigspec
  local x

  case $# in
    0 | 1)
      sst_barf 'invalid argument count: %d' $#
    ;;
  esac

  arg=$1
  readonly arg
  shift

  for sigspec; do

    x=$(trap -p -- "$sigspec")

    case $x in
      ?*)
        eval "set -- $x"
        shift $(($# - 2))
        x=$1$'\n'$arg
      ;;
      *)
        x=$arg
      ;;
    esac

    trap -- "$x" "$sigspec"

  done

}; readonly -f sst_trap_append
