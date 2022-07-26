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

sst_jq_get_strings_helper() {

  local filter
  local json
  local script
  local var

  json=$1
  readonly json

  filter=$2
  readonly filter

  var=$3
  readonly var

  printf '
    %s=()
    %s_error=()
  ' "$var" "$var"

  script='
    .[0]
    | ('"$filter"')
    | if . == null then
        "'$var'+=(" + ("" | @sh) + ")"
      elif type == "string" then
        "'$var'+=(" + (. | @sh) + ")"
      elif type == "array" then
        if length == 0 then
          "'$var'+=(" + ("" | @sh) + ")"
        else
          to_entries
          | .[]
          | if .value == null then
              "'$var'+=(" + ("" | @sh) + ")"
            elif (.value | type) == "string" then
              "'$var'+=(" + (.value | @sh) + ")"
            else
              "'$var'_error+=(\"["
                + (.key | tostring)
                + "]: expected string\")"
            end
        end
      else
        "'$var'_error+=(\": expected strings\")"
      end
  '
  readonly script

  if [[ "$json" == - ]]; then
    jq -r -s " $script"
  elif [[ "$json" == [/A-Za-z0-9._-]* ]]; then
    jq -r -s " $script" <"$json"
  else
    jq -r -s " $script" <<<"$json"
  fi

}; readonly -f sst_jq_get_strings_helper

sst_jq_get_strings() {

  sst_expect_argument_count $# 3

  sst_expect_basic_identifier "$3"

  local ${3}_code
  local ${3}_error
  eval '
    '$3'_code=$(sst_jq_get_strings_helper "$@")
    eval "$'$3'_code"
  '
  readonly ${3}_code
  readonly ${3}_error

  local display
  local error
  local filter
  local json

  json=$1
  readonly json

  filter=$2
  readonly filter

  eval 'error=${'$3'_error-}'
  readonly error

  if [[ "$error" ]]; then
    if [[ "$json" == - ]]; then
      display='<stdin>'
    elif [[ "$json" == [/A-Za-z0-9._-]* ]]; then
      display=$json
    else
      display=$(sst_quote "$json")
    fi
    readonly display
    sst_barf 'jq: %s: %s%s' "$display" "$filter" "$error"
  fi

}; readonly -f sst_jq_get_strings
