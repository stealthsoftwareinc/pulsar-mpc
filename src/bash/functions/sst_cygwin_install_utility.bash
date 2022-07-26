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

sst_cygwin_install_utility() {

  local i
  local package
  local -A packages
  local program
  # Bash >=4.2: declare -g -A sst_cygwin_install_utility_seen
  local utility

  # Filter out any utilities that we've already seen.
  for ((i = 0; i != $#; ++i)); do
    if [[ ! "${sst_cygwin_install_utility_seen[$1]+x}" ]]; then
      sst_cygwin_install_utility_seen[$1]=
      set x "$@" "$1"
      shift
    fi
    shift
  done

  for utility; do

    case $utility in

      (c89)
        program=c89
        package=gcc-core
      ;;

      (c99)
        program=c99
        package=gcc-core
      ;;

      (cat)
        program=cat
        package=coreutils
      ;;

      (cc)
        program=cc
        package=gcc-core
      ;;

      (gawk)
        program=gawk
        package=gawk
      ;;

      (git)
        program=git
        package=git
      ;;

      (gpg1)
        program=gpg
        package=gnupg
      ;;

      (gpg2)
        program=gpg2
        package=gnupg2
      ;;

      (jq)
        program=jq
        package=jq
      ;;

      (make)
        program=make
        package=make
      ;;

      (mv)
        program=mv
        package=coreutils
      ;;

      (ssh)
        program=ssh
        package=openssh
      ;;

      (ssh-keygen)
        program=ssh-keygen
        package=openssh
      ;;

      (sshpass)
        program=sshpass
        package=sshpass
      ;;

      (tar)
        program=tar
        package=tar
      ;;

      (*)
        sst_barf 'missing install info for %s' "$FUNCNAME:$utility"
      ;;

    esac

    sst_utility_prefixes[$utility]=
    sst_utility_programs[$utility]=$program
    sst_utility_suffixes[$utility]=

    if ! type -f "$program" &>/dev/null; then
      packages[$package]=
    fi

  done

  sst_cygwin_install_raw "${!packages[@]}"

}; readonly -f sst_cygwin_install_utility
