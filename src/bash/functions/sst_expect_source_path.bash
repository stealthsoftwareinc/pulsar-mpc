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

sst_expect_source_path() {

  local e
  local x

  for x; do

    e=

    case $x in

      "")
        e='Source paths must not be empty'
      ;;

      *[!-+./0-9A-Z_a-z]*)
        e='Source paths must only contain [-+./0-9A-Z_a-z] characters'
      ;;

      /*)
        e='Source paths must not begin with a / character'
      ;;

      */)
        e='Source paths must not end with a / character'
      ;;

      *//*)
        e='Source paths must not contain repeated / characters'
      ;;

      . | ./* | */./* | */.)
        e='Source paths must not contain any . components'
      ;;

      .. | ../* | */../* | */..)
        e='Source paths must not contain any .. components'
      ;;

      -* | */-*)
        e='Source path components must not begin with a - character'
      ;;

    esac

    if [[ "$e" != "" ]]; then
      x=$(sst_jq_quote "$x")
      sst_barf "$e: $x"
    fi

  done

}; readonly -f sst_expect_source_path
