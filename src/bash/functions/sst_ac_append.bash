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

# TODO: After autogen_ac_append is eventually removed, the
# quoted-by-default convention will be gone and we can remove the
# printing of "[" and "]" in this function, as well as removing the
# opening "[" and the trailing "]" in the start and finish functions.

sst_ac_append() {

  if [[ ! "${autogen_ac_start_has_been_called+x}" ]]; then
    sst_barf 'autogen_ac_start has not been called'
  fi

  if [[ "${autogen_ac_finish_has_been_called+x}" ]]; then
    sst_barf 'autogen_ac_finish has been called'
  fi

  sst_expect_argument_count $# 0

  printf ']\n' >>$autogen_ac_file
  cat >>$autogen_ac_file
  printf '[\n' >>$autogen_ac_file

}; readonly -f sst_ac_append
