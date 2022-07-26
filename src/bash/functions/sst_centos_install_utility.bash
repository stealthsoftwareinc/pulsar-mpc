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

sst_centos_install_utility() {

  # Bash >=4.2: declare -g -A sst_utility_prefixes
  # Bash >=4.2: declare -g -A sst_utility_programs
  # Bash >=4.2: declare -g -A sst_utility_suffixes

  local distro_version
  local package
  local -A packages
  local program
  local utility

  if (($# == 0)); then
    return
  fi

  distro_version=$(sst_get_distro_version)
  readonly distro_version

  for utility; do
    if [[ "${sst_utility_programs[$utility]+x}" == "" ]]; then
      case $utility:$distro_version in

        ('' \
        | c89:6 \
        | c89:7 \
        | c89:8 \
        )
          program=c89
          package=gcc
        ;;

        ('' \
        | c99:6 \
        | c99:7 \
        | c99:8 \
        )
          program=c99
          package=gcc
        ;;

        ('' \
        | cat:6 \
        | cat:7 \
        | cat:8 \
        )
          program=cat
          package=coreutils
        ;;

        ('' \
        | cc:6 \
        | cc:7 \
        | cc:8 \
        )
          program=cc
          package=gcc
        ;;

        ('' \
        | gawk:6 \
        | gawk:7 \
        | gawk:8 \
        )
          program=gawk
          package=gawk
        ;;

        ('' \
        | git:6 \
        | git:7 \
        )
          program=git
          package=git
        ;;

        ('' \
        | git:8 \
        )
          program=git
          package=git-core
        ;;

        ('' \
        | gpg2:6 \
        | gpg2:7 \
        | gpg2:8 \
        )
          program=gpg2
          package=gnupg2
        ;;

        ('' \
        | jq:6 \
        | jq:7 \
        | jq:8 \
        )
          program=jq
          package=jq
        ;;

        ('' \
        | make:6 \
        | make:7 \
        | make:8 \
        )
          program=make
          package=make
        ;;

        ('' \
        | mv:6 \
        | mv:7 \
        | mv:8 \
        )
          program=mv
          package=coreutils
        ;;

        ('' \
        | ssh:6 \
        | ssh:7 \
        | ssh:8 \
        )
          program=ssh
          package=openssh-clients
        ;;

        ('' \
        | ssh-keygen:6 \
        | ssh-keygen:7 \
        | ssh-keygen:8 \
        )
          program=ssh-keygen
          package=openssh
        ;;

        ('' \
        | sshpass:6 \
        | sshpass:7 \
        | sshpass:8 \
        )
          program=sshpass
          package=sshpass
        ;;

        ('' \
        | tar:6 \
        | tar:7 \
        | tar:8 \
        )
          program=tar
          package=tar
        ;;

        (*)
          sst_barf 'missing install info for %s' "$FUNCNAME:$utility:$distro_version"
        ;;

      esac
      sst_utility_prefixes[$utility]=
      sst_utility_programs[$utility]=$program
      sst_utility_suffixes[$utility]=

      if ! type -f "$program" &>/dev/null; then
        packages[$package]=
      fi

    fi
  done

  sst_centos_install_raw "${!packages[@]}"

}; readonly -f sst_centos_install_utility
