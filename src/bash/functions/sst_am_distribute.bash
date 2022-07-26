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

sst_am_distribute() {

  local i
  local n
  local path
  # Bash >=4.2: declare -g sst_am_distribute_i
  # Bash >=4.2: declare -g sst_am_distribute_seen

  sst_expect_no_subshell

  # n should be hardcoded to an integer value between 1 and k+1
  # inclusive, where k is the number of the highest numbered
  # GATBPS_DISTFILES_k target in build-aux/gatbps.am.
  n=100
  readonly n

  for path; do
    sst_expect_source_path "$path"
    if [[ ! -f $path && ! -d $path && -e $path ]]; then
      path=$(sst_smart_quote $path)
      sst_barf \
        "path must either exist as a file," \
        "exist as a directory, or not exist: $path" \
      ;
    fi
    if [[ "${sst_am_distribute_seen= }" == *" $path "* ]]; then
      continue
    fi
    sst_am_distribute_seen+="$path "
    i=${sst_am_distribute_i-0}
    sst_am_var_add GATBPS_DISTFILES_$i $path
    sst_am_distribute_i=$(((i + 1) % n))
  done

}; readonly -f sst_am_distribute
