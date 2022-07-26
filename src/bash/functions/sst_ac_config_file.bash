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

sst_ac_config_file() {

  local file
  # Bash >=4.2: declare -g sst_ac_config_file_seen
  local target

  for file; do

    sst_expect_source_path "$file"

    if [[ $file == *.im.in ]]; then
      target=${file%.im.in}
    elif [[ $file == *.in ]]; then
      target=${file%.in}
    elif [[ $file == *.im ]]; then
      target=${file%.im}
    elif [[ -f $file.im.in ]]; then
      target=$file
      file=$file.im.in
    elif [[ -f $file.in ]]; then
      target=$file
      file=$file.in
    elif [[ -f $file.im ]]; then
      target=$file
      file=$file.im
    else
      sst_barf "can't figure out how to process %s" $file
    fi

    sst_expect_file $file

    if [[ "${sst_ac_config_file_seen= }" == *" $target "* ]]; then
      continue
    fi

    if [[ $file == *.im.in ]]; then
      sst_ac_append <<<"GATBPS_CONFIG_FILE([$target.im])"
      sst_ac_append <<<"GATBPS_CONFIG_LATER([$target])"
    elif [[ $file == *.in ]]; then
      sst_ac_append <<<"GATBPS_CONFIG_FILE([$target])"
    elif [[ $file == *.im ]]; then
      sst_ac_append <<<"GATBPS_CONFIG_LATER([$target])"
    fi

    sst_ac_config_file_seen+="$file "

  done

}; readonly -f sst_ac_config_file
