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

sst_test() {

  local checks
  local code
  local expected_output
  local expected_output_op
  local expected_status
  local output
  local pass
  local prelude
  local regex
  local script
  local script_file
  local shows
  local status
  local x
  local y

  expected_status=0
  expected_output_op=:
  expected_output=
  regex='^(0|[1-9][0-9]*)((:|=)(.*))?$'
  if [[ $# != 0 && "$1" =~ $regex ]]; then
    expected_status=${BASH_REMATCH[1]}
    expected_output_op=${BASH_REMATCH[3]:-:}
    expected_output=${BASH_REMATCH[4]-}
    shift
  fi

  if [[ $# == 0 ]]; then
    sst_barf "<code> must be given"
  fi
  code=$(tr '\n' ' ' <<<"$1" | sst_csf)
  sst_csf code
  regex='^(.*); *$'
  if [[ "$code" =~ $regex ]]; then
    code=${BASH_REMATCH[1]}
  fi
  readonly code
  shift

  checks=
  shows=
  if [[ $# != 0 ]]; then
    checks=$(tr '\n' ' ' <<<"$1" | sst_csf)
    sst_csf checks
    readonly checks
    shift
    for x; do
      shows+=' '$(sst_quote "$x")
    done
  fi
  readonly checks
  readonly shows

  prelude=$(sst_quote "$sst_root/prelude.bash")
  readonly prelude

  script='
    set -e || exit $?
    . '"$prelude"'
    '"$code"'
    {
      sst_test_status=$?
      '"$checks"'
    } || {
      sst_test_show=('"$shows"')
      sst_test_fail "$@"
    }
    (exit $sst_test_status) && :
  '
  readonly script

  x="test: ({ $code; }; $checks) exits with status $expected_status"
  if [[ "$expected_output_op" != : || "$expected_output" != "" ]]; then
    y=$(sst_quote "$expected_output")
    case $expected_output_op in
      :) y="that contains $y" ;;
      =) y="that is exactly $y" ;;
      *) sst_barf "missing case" ;;
    esac
    x+=" and produces output $y"
  fi
  x+=" ..."
  printf '%s' "$x"

  script_file=$sst_root_tmpdir/$FUNCNAME.$BASHPID.script
  readonly script_file

  cat <<<"$script" >"$script_file"
  status=0
  output=$(sh "$script_file" 2>&1 | sst_csf) || status=$?
  sst_csf output
  readonly status
  readonly output

  pass=
  if [[ $status == $expected_status ]]; then
    case $expected_output_op in
      :)
        if [[ "$output" == *"$expected_output"* ]]; then
          pass=1
        fi
      ;;
      =)
        if [[ "$output" == "$expected_output" ]]; then
          pass=1
        fi
      ;;
      *)
        sst_barf "missing case"
      ;;
    esac
  fi
  readonly pass

  if ((pass)); then
    printf '%s\n' " pass"
  else
    printf '%s\n' " fail" "  status: $status" "$output"
    exit 1
  fi

}; readonly -f sst_test
