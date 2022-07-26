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

sst_ubuntu_install_utility() {

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
        | c89:16.04 \
        | c89:18.04 \
        | c89:20.04 \
        )
          program=c89
          package=gcc
        ;;

        ('' \
        | c99:16.04 \
        | c99:18.04 \
        | c99:20.04 \
        )
          program=c99
          package=gcc
        ;;

        ('' \
        | cat:16.04 \
        | cat:18.04 \
        | cat:20.04 \
        )
          program=cat
          package=coreutils
        ;;

        ('' \
        | cc:16.04 \
        | cc:18.04 \
        | cc:20.04 \
        )
          program=cc
          package=gcc
        ;;

        ('' \
        | gawk:16.04 \
        | gawk:18.04 \
        | gawk:20.04 \
        )
          program=gawk
          package=gawk
        ;;

        ('' \
        | git:16.04 \
        | git:18.04 \
        | git:20.04 \
        )
          program=git
          package=git
        ;;

        ('' \
        | gpg1:16.04 \
        )
          program=gpg
          package=gnupg
        ;;

        ('' \
        | gpg1:18.04 \
        | gpg1:20.04 \
        )
          program=gpg1
          package=gnupg1
        ;;

        ('' \
        | gpg2:16.04 \
        | gpg2:18.04 \
        | gpg2:20.04 \
        )
          program=gpg2
          package=gnupg2
        ;;

        ('' \
        | jq:16.04 \
        | jq:18.04 \
        | jq:20.04 \
        )
          program=jq
          package=jq
        ;;

        ('' \
        | make:16.04 \
        | make:18.04 \
        | make:20.04 \
        )
          program=make
          package=make
        ;;

        ('' \
        | mv:16.04 \
        | mv:18.04 \
        | mv:20.04 \
        )
          program=mv
          package=coreutils
        ;;

        ('' \
        | ssh:16.04 \
        | ssh:18.04 \
        | ssh:20.04 \
        )
          program=ssh
          package=openssh-client
        ;;

        ('' \
        | ssh-keygen:16.04 \
        | ssh-keygen:18.04 \
        | ssh-keygen:20.04 \
        )
          program=ssh-keygen
          package=openssh-client
        ;;

        ('' \
        | sshpass:16.04 \
        | sshpass:18.04 \
        | sshpass:20.04 \
        )
          program=sshpass
          package=sshpass
        ;;

        ('' \
        | tar:16.04 \
        | tar:18.04 \
        | tar:20.04 \
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

  sst_ubuntu_install_raw "${!packages[@]}"

}; readonly -f sst_ubuntu_install_utility
