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

sst_am_var_add_unique_file() {

  local path
  # Bash >=4.2: declare -g -A sst_am_var_value
  # Bash >=4.2: declare -g -A sst_am_var_value_files
  local var

  sst_expect_argument_count $# 1-

  var=$1
  readonly var
  sst_expect_basic_identifier "$var"

  if [[ "${sst_am_var_value[$var]-}" == "" ]]; then
    sst_am_var_set $var
  fi

  shift
  for path; do
    sst_expect_source_path "$path"
    sst_expect_file $path
    if [[ "${sst_am_var_value_files[$var]= }" == *" $path "* ]]; then
      continue
    fi
    sst_am_var_value_files[$var]+="$path "
    sst_am_var_value[$var]+="$path "
    sst_am_append <<<"$var += $path"
  done

}; readonly -f sst_am_var_add_unique_file
