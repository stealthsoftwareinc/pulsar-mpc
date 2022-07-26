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

sst_cygwin_install_raw() {

  local package
  local packages=
  local q
  # Bash >=4.2: declare -g -A sst_cygwin_install_raw_seen

  for package; do

    # Skip this package if we've already seen it.
    if [[ "${sst_cygwin_install_raw_seen[$package]+x}" ]]; then
      continue
    fi
    sst_cygwin_install_raw_seen[$package]=

    # Skip this package if it's already installed.
    q=$(cygcheck -c "$package" | sed -n '/OK$/p') || return
    if [[ "${q:+x}" ]]; then
      continue
    fi

    packages+=${packages:+,}$(sst_quote "$package")

  done

  if [[ "${packages:+x}" ]]; then
    sst_barf 'missing packages: %s' "$packages"
  fi

}; readonly -f sst_cygwin_install_raw
