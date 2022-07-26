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

sst_expect_ag_json_helper() {

  local handler
  local json
  local p_target
  local x

  sst_expect_no_subshell sst_expect_ag_json

  sst_expect_argument_count $# 2-3

  p_target=$1
  readonly p_target
  if [[ "$p_target" != - ]]; then
    sst_expect_basic_identifier "$p_target"
  fi

  json=$2
  readonly json
  sst_expect_source_path "$json"
  sst_expect_extension $json .ag.json

  if (($# == 2)); then
    # The first call will always come in through the automatic function
    # loader, in which case the calling function is actually two frames
    # upward, not one. Plus one since we're in a helper function.
    if [[ "${FUNCNAME[2]}" == "${FUNCNAME[1]}" ]]; then
      handler=${FUNCNAME[3]}
    else
      handler=${FUNCNAME[2]}
    fi
  else
    handler=$3
  fi
  readonly handler
  sst_expect_basic_identifier "$handler"

  jq_expect_object . $json

  sst_jq_get_string $json .handler x
  if [[ "$x" != $handler ]]; then
    x=$(sst_jq_quote "$x")
    sst_barf "$json: .handler: expected \"$handler\" but got $x"
  fi

  sst_am_distribute $json

  printf '%s\n' ${json%.ag.json}

}; readonly -f sst_expect_ag_json_helper

sst_expect_ag_json() {

  sst_expect_ag_json_helper "$@" >"$sst_root_tmpdir/$FUNCNAME.target"
  if [[ "$1" != - ]]; then
    eval $1='$(cat "$sst_root_tmpdir/$FUNCNAME.target")'
  fi

}; readonly -f sst_expect_ag_json
