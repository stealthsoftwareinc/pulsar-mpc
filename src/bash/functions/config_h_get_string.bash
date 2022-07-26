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

config_h_get_string() {

  local config
  local macro
  local main

  case $# in
    2)
    ;;
    *)
      sst_barf 'invalid argument count: %d' $#
    ;;
  esac

  config=$1
  readonly config
  expect_safe_path "$config"

  macro=$2
  readonly macro
  sst_expect_basic_identifier "$macro"

  main=config_h_get_string-$macro-$$.c
  readonly main

  cat >$main <<EOF
#include "$config"
#include <stdio.h>
#include <stdlib.h>
int (main)(
  void
) {
  static char const * const x = $macro;
  if (printf("%s\\n", x) >= 0) {
    if (fflush(stdout) == 0) {
      return EXIT_SUCCESS;
    }
  }
  return EXIT_FAILURE;
}
EOF

  cc -o $main.exe $main

  ./$main.exe

  rm $main.exe $main

}; readonly -f config_h_get_string
