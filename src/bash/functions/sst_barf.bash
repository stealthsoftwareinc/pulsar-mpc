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

#
# This function may be called by sst_install_utility, so we need to be
# careful to only use utilities that are always available and to write
# the code so that it behaves correctly under errexit suspension.
#

sst_barf() {

  local file
  local func
  local i
  local line
  local x

  if [[ ! "${sst_root_tmpdir+x}" ]]; then
    # We were called by the prelude before sst_root_tmpdir was ready.
    printf '%s' "$0: error: " >&2
  elif mkdir "$sst_root_tmpdir"/sst_barf_leaf &>/dev/null; then
    # We were called by the leaf barfing subshell.
    printf '%s' "$0: error: " >&2
  else
    # We were called by a non-leaf barfing subshell.
    printf '%s' "  up: " >&2
  fi

  sst_join "$@" >&2

  # Print the stack trace.
  i=0
  while x=$(caller $i); do
    i=$((i + 1))

    # Peel off the line number.
    while [[ "$x" == [[:blank:]]* ]]; do x=${x#?}; done
    line=${x%%[[:blank:]]*}
    x=${x#"$line"}

    # Peel off the function name.
    while [[ "$x" == [[:blank:]]* ]]; do x=${x#?}; done
    func=${x%%[[:blank:]]*}
    x=${x#"$func"}

    # Peel off the file name.
    while [[ "$x" == [[:blank:]]* ]]; do x=${x#?}; done
    file=${x%%[[:blank:]]*}
    x=${x#"$file"}

    # Skip the lazy function loading functions and the lazy utility
    # installation functions, but allow any prelude helper functions.
    if [[ "${file##*/}" == prelude.bash ]]; then
      if [[ "$func" != source && "$func" != sst_prelude_* ]]; then
        continue
      fi
    fi

    # Skip the utility wrapper functions.
    if [[ "${file##*/}" == sst_install_utility.bash ]]; then
      if [[ "$func" != sst_install_utility ]]; then
        continue
      fi
    fi

    printf '    at %s(%s:%s)\n' "$func" "$file" "$line" >&2

  done

  # Exit with status sst_barf_status if it's set properly.
  if [[ "${sst_barf_status+x}" ]]; then
    x='^(0|[1-9][0-9]{0,2})$'
    if [[ "$sst_barf_status" =~ $x ]]; then
      if ((sst_barf_status <= 255)); then
        exit $sst_barf_status
      fi
    fi
    printf '  warning: ignoring invalid sst_barf_status value: %s\n' \
           "$sst_barf_status" >&2
  fi

  exit 1

}; readonly -f sst_barf
