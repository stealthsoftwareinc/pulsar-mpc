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

sst_ag_process_leaf_helper() {

  local child
  local child_slug
  local children
  local children_nodist
  local leaf
  local leaves
  # Bash >=4.2: declare -g sst_ag_process_leaf_seen
  local target
  local target_slug

  sst_expect_argument_count $# 3

  target=$1
  readonly target
  sst_expect_source_path "$target"

  leaf=$2
  readonly leaf
  sst_expect_source_path "$leaf"

  sst_expect_basic_identifier "$3"

  target_slug=$(sst_underscore_slug $target)
  readonly target_slug

  children=${target_slug}_children
  readonly children

  children_nodist=${children}_nodist
  readonly children_nodist

  leaves=${target_slug}_leaves
  readonly leaves

  if [[ $leaf == *.phony.@(ag|ac|am) ]]; then
    child=
    sst_${leaf##*.}_include $leaf
  elif [[ $leaf == *.@(ag|ac|am) ]]; then
    child=${leaf%%.@(ag|ac|am)}
    if [[ "${sst_ag_process_leaf_seen= }" == *" $child "* ]]; then
      child=
    else
      child_slug=$(sst_underscore_slug $child)
      sst_${leaf##*.}_include $leaf
      sst_am_var_add_unique_word $children_nodist $child
      sst_am_var_add_unique_word $leaves "\$(${child_slug}_leaves)"
      # TODO: sst_am_var_add_unique_word $target/clean $child/clean
    fi
  elif [[ $leaf == *.@(im.in|in|im) ]]; then
    child=${leaf%%.@(im.in|in|im)}
    if [[ "${sst_ag_process_leaf_seen= }" == *" $child "* ]]; then
      child=
    else
      child_slug=$(sst_underscore_slug $child)
      sst_ac_config_file $leaf
      sst_am_var_add_unique_word $children_nodist $child
      sst_am_var_add_unique_word $leaves "\$(${child_slug}_leaves)"
      # TODO: sst_am_var_add_unique_word $target/clean $child/clean
    fi
  elif [[ $leaf == *.m4 ]]; then
    child=${leaf%%.m4}
    if [[ "${sst_ag_process_leaf_seen= }" == *" $child "* ]]; then
      child=
    else
      child_slug=$(sst_underscore_slug $child)
      sst_am_distribute $leaf
      sst_ac_append <<<"GATBPS_M4([$child])"
      sst_am_var_add_unique_word $children_nodist $child
      sst_am_var_add_unique_word $leaves "\$(${child_slug}_leaves)"
      # TODO: sst_am_var_add_unique_word $target/clean $child/clean
    fi
  else
    child=$leaf
    if [[ "${sst_ag_process_leaf_seen= }" == *" $child "* ]]; then
      child=
    else
      sst_am_distribute $leaf
      sst_am_var_add_unique_word $children $child
      sst_am_var_add_unique_word $leaves $leaf
    fi
  fi

  if [[ "$child" != "" ]]; then
    sst_ag_process_leaf_seen+="$child "
  fi

  printf '%s\n' $child

}; readonly -f sst_ag_process_leaf_helper

sst_ag_process_leaf() {
  sst_ag_process_leaf_helper "$@" >"$sst_root_tmpdir"/$FUNCNAME.child
  eval $3='$(cat "$sst_root_tmpdir"/$FUNCNAME.child)'
}; readonly -f sst_ag_process_leaf
