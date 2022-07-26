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

sst_install_utility() {

  # Bash >=4.2: declare -g -A sst_utility_overrides
  # Bash >=4.2: declare -g -A sst_utility_prefixes
  # Bash >=4.2: declare -g -A sst_utility_programs
  # Bash >=4.2: declare -g -A sst_utility_suffixes
  # Bash >=4.2: declare -g -A sst_utility_seen

  local override
  local utility

  if (($# == 0)); then
    return
  fi

  #
  # Allow environment variable overrides. For example, allow the GIT
  # environment variable to override the git utility.
  #

  for utility; do
    if [[ ! "${sst_utility_seen[$utility]+x}" ]]; then
      override=$(sst_environment_slug <<<"$utility")
      eval override=\${$override-}
      if [[ "$override" ]]; then
        sst_utility_overrides[$utility]=$override
        sst_utility_programs[$utility]=
      fi
    fi
  done

  #
  # Install any utilities that haven't already been installed or
  # overridden by environment variables.
  #

  sst_get_distro >/dev/null
  eval sst_${sst_distro}_install_utility '"$@"'

  #
  # Define any wrapper functions that haven't already been defined.
  #
  # It's important that these wrapper functions behave nicely regardless
  # of whether set -e is enabled, as idioms that temporarily suspend the
  # set -e state, like "utility || s = $?" or "if utility; then", should
  # continue to behave as expected.
  #

  for utility; do
    if [[ ! "${sst_utility_seen[$utility]+x}" ]]; then
      eval '
        '"$utility"'() {
          if [[ "${sst_utility_overrides['$utility']+x}" ]]; then
            eval " ${sst_utility_overrides['$utility']}" '\''"$@"'\''
          else
            eval " ${sst_utility_prefixes['$utility']} \
                   command \
                   ${sst_utility_programs['$utility']} \
                   ${sst_utility_suffixes['$utility']}" '\''"$@"'\''
          fi
        }; readonly -f '"$utility"'
      '
      sst_utility_seen[$utility]=x
    fi
  done

}; readonly -f sst_install_utility
