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

#-----------------------------------------------------------------------
# Guidelines
#-----------------------------------------------------------------------
#
# * Any helper functions defined directly in the prelude should be named
#   sst_prelude_* in order to cooperate with the stack tracing omissions
#   performed by sst_barf.
#

#-----------------------------------------------------------------------
# Bootstrapping
#-----------------------------------------------------------------------
#
# Bootstrap into the PATH-resolved bash. Unset SST_BASH_BOOTSTRAP so we
# don't trick other prelude-using scripts into thinking they've already
# bootstrapped.
#
# This section is written in portable shell to ensure it works properly
# in any shell.
#

case ${SST_BASH_BOOTSTRAP+x}y$# in
  y0) SST_BASH_BOOTSTRAP= exec bash - "$0" ;;
  y*) SST_BASH_BOOTSTRAP= exec bash - "$0" "$@" ;;
esac
unset SST_BASH_BOOTSTRAP

#-----------------------------------------------------------------------
# Locale
#-----------------------------------------------------------------------
#
# Use the C locale by default. This is the best approach, as most code
# is written with the C locale in mind, and other locales tend to break
# such code in strange, subtle ways. The locale affects the behavior of
# many fundamental programs, like awk, grep, sed, and the current shell
# instance itself. When the caller knows better, they can freely adjust
# LC_ALL and the other locale variables as they see fit.
#
# This section is written in portable shell to ensure it works properly
# in arbitrarily old versions of Bash.
#

case ${LC_ALL+x} in
  ?*)
    sst_old_LC_ALL=$LC_ALL
  ;;
esac
readonly sst_old_LC_ALL

LC_ALL=C
export LC_ALL

#-----------------------------------------------------------------------
# Outdated Bash detection
#-----------------------------------------------------------------------
#
# Check that we're running in a sufficiently new version of Bash.
#
# This section is written in portable shell to ensure it works properly
# in arbitrarily old versions of Bash.
#

case ${BASH_VERSION-} in
  4.[1-9]* | [5-9]* | [1-9][0-9]*)
    :
  ;;
  *)
    sst_x="$0: error: bash 4.1 or newer is required."
    sst_x=$sst_x' Your Bash version is too old'
    case ${BASH_VERSION+x} in
      ?*) sst_x=$sst_x' (Bash '$BASH_VERSION').' ;;
      '') sst_x=$sst_x' (the BASH_VERSION variable is not even set).' ;;
    esac
    if command -v sw_vers >/dev/null 2>&1; then
      sst_x=$sst_x' It looks like you'\''re on macOS, in which case the'
      sst_x=$sst_x' plain "bash" command may be mapped to the operating'
      sst_x=$sst_x' system copy of Bash (the /bin/bash file), which may'
      sst_x=$sst_x' be quite old.'
      sst_x=$sst_x' Please install a newer copy of Bash using Homebrew,'
      sst_x=$sst_x' MacPorts, or some other means.'
      sst_x=$sst_x' You can check which copy of Bash the plain "bash"'
      sst_x=$sst_x' command is mapped to by running "command -v bash",'
      sst_x=$sst_x' and you can check which version it is by running'
      sst_x=$sst_x' "bash --version".'
    fi
    printf '%s\n' "$sst_x" >&2
    exit 1
  ;;
esac

#-----------------------------------------------------------------------
# Blank slating
#-----------------------------------------------------------------------

unset sst_root_tmpdir

#-----------------------------------------------------------------------
# Error handling
#-----------------------------------------------------------------------

set -E -e -u -o pipefail || exit
trap exit ERR

#-----------------------------------------------------------------------

#
# Ensure that Bash's POSIX compatibility mode is disabled. This mode has
# no purpose for us, as we're intentionally using Bash, not merely using
# Bash as a realization of the POSIX shell. Failing to ensure this mode
# is disabled can lead to inconvenient behavior, such as the ability to
# use "-" characters in function names being disabled.
#

set +o posix

shopt -s \
  dotglob \
  extglob \
  globstar \
  nullglob \
;

#-----------------------------------------------------------------------
# sst_root
#-----------------------------------------------------------------------

if [[ "$BASH_SOURCE" != */* ]]; then
  sst_root=$PWD
else
  sst_root=${BASH_SOURCE%/*}/
  if [[ "$sst_root" != /* ]]; then
    sst_root=$PWD/$sst_root
  fi
fi
if [[ "$sst_root" == */ ]]; then
  sst_root+=.
fi
readonly sst_root

#-----------------------------------------------------------------------
# Automatic function loading
#-----------------------------------------------------------------------

for sst_file in "$sst_root"/functions/**/*.bash; do
  sst_name=${sst_file##*/}
  sst_name=${sst_name%.bash}
  sst_file=\'${sst_file//\'/\'\\\'\'}\'
  eval '
    '"$sst_name"'() {
      . '"$sst_file"'
      "$FUNCNAME" "$@"
    }
  '
done

unset sst_file
unset sst_name

#-----------------------------------------------------------------------
# Global associative array declarations
#-----------------------------------------------------------------------
#
# We support Bash 4.1, which does not support declare -g, so ideally
# we'd like to use declare -A to declare any global associative arrays
# in any function file that needs them. However, our automatic function
# loading mechanism loads function files in function scope, not in the
# global scope, so these declarations wouldn't be in the global scope.
# As a workaround, we declare all global associative arrays here.
#

declare -A sst_am_var_value
declare -A sst_am_var_value_files
declare -A sst_centos_install_raw_seen
declare -A sst_cygwin_install_raw_seen
declare -A sst_cygwin_install_utility_seen
declare -A sst_ubuntu_install_raw_seen
declare -A sst_utility_overrides
declare -A sst_utility_prefixes
declare -A sst_utility_programs
declare -A sst_utility_seen
declare -A sst_utility_suffixes

#-----------------------------------------------------------------------
# ERR forwarding
#-----------------------------------------------------------------------
#
# Overwrite the ERR trap to call sst_barf instead of just exiting.
#

trap '
  sst_s=$?
  sst_x="command exited with status $sst_s: $BASH_COMMAND"
  sst_barf "$sst_x" || :
  printf '\''%s\n'\'' "$0: error: $sst_x" >&2 || :
  exit $sst_s
' ERR

#-----------------------------------------------------------------------
# Automatic utility installation
#-----------------------------------------------------------------------

for sst_x in \
  c89 \
  c99 \
  cat \
  cc \
  gawk \
  git \
  gpg1 \
  gpg2 \
  jq \
  make \
  mv \
  ssh \
  ssh-keygen \
  sshpass \
  tar \
; do
  eval '
    '"$sst_x"'() {
      local i
      for ((i = 1; i < ${#FUNCNAME[@]}; ++i)); do
        if [[ "${FUNCNAME[i]}" == sst_install_utility ]]; then
          command "$FUNCNAME" "$@"
          return
        fi
      done
      sst_install_utility "$FUNCNAME" || return
      "$FUNCNAME" "$@"
    }
  '
done
unset sst_x

#-----------------------------------------------------------------------

trap '

  sst_trap_entry_status=$?

' EXIT

#-----------------------------------------------------------------------
# sst_rundir
#-----------------------------------------------------------------------
#
# Set sst_rundir to an absolute path to the directory from which the
# script was run.
#

readonly sst_rundir="$PWD"

# DEPRECATED
readonly rundir="$sst_rundir"

#-----------------------------------------------------------------------

#
# If we're running in a disposable GitLab CI environment and
# CI_BUILDS_DIR is writable, set TMPDIR to CI_BUILDS_DIR. This improves
# the chance of being able to mount TMPDIR-based paths into containers,
# as the job itself might be running in a container with CI_BUILDS_DIR
# identity-mounted into it.
#

if [[ "${CI_DISPOSABLE_ENVIRONMENT+x}" && -w "$CI_BUILDS_DIR" ]]; then
  TMPDIR=$CI_BUILDS_DIR
  export TMPDIR
fi

#
# We want to provide the calling script with an absolute path to an
# empty directory that it can use for temporary files. However, this
# prelude and other preludes that wrap this prelude also need to use
# temporary files, so name collisions are a problem. To fix this, each
# prelude uses its temporary directory as needed, and before returning
# to the calling script (which may be a wrapping prelude), creates an
# empty temporary subdirectory for the calling script to use.
#

if sst_tmpdir=$(mktemp -d); then
  if [[ "$sst_tmpdir" != /* ]]; then
    sst_tmpdir=$PWD/$sst_tmpdir
  fi
else
  sst_tmpdir=${TMPDIR:-/tmp}
  if [[ "$sst_tmpdir" != /* ]]; then
    sst_tmpdir=$PWD/$sst_tmpdir
  fi
  mkdir -p "$sst_tmpdir"
  n=10
  while ((n-- > 0)); do
    d=$(tr -d -c a-zA-Z0-9 </dev/urandom | head -c 10) || :
    d=$sst_tmpdir/tmp${d:+.$d}.$BASHPID.$RANDOM
    mkdir "$d" || continue
    sst_tmpdir=$d
    break
  done
  if ((n < 0)); then
    sst_barf 'failed to construct sst_tmpdir'
  fi
fi
chmod 700 "$sst_tmpdir"

# Only set sst_root_tmpdir after the directory is ready, otherwise
# sst_barf may try to use it prematurely.
sst_root_tmpdir=$sst_tmpdir
readonly sst_root_tmpdir

sst_trap_append 'rm -f -r "$sst_root_tmpdir" || :' EXIT

#-----------------------------------------------------------------------
# sst_is0atty
#-----------------------------------------------------------------------

if test -t 0; then
  sst_is0atty=1
else
  sst_is0atty=
fi
readonly sst_is0atty

#-----------------------------------------------------------------------

#
# This section is DEPRECATED. Archivist runners will eventually be
# completely replaced by decentralized keys.
#

#
# Determine whether we're running on an archivist runner.
#

if test -f /archivist.gitlab-username; then
  archivist=true
else
  archivist=false
fi
readonly archivist

case $archivist in
  true)
    u=$(cat /archivist.gitlab-username)
    docker login \
      --username "$u" \
      --password-stdin \
      registry.stealthsoftwareinc.com \
      </archivist.gitlab-password \
    ;
    unset u
  ;;
esac

#-----------------------------------------------------------------------

#
# Make sure "apt-get -y" is fully noninteractive when we're running
# noninteractively on Debian. See "man 7 debconf" (after running
# "apt-get install debconf-doc") or view it online at
# <https://manpages.debian.org/debconf.7>.
#

if ((!sst_is0atty)); then
  export DEBIAN_FRONTEND=noninteractive
fi

#
# Log in to the GitLab Container Registry, if possible.
#

if [[ "${CI_REGISTRY+x}" != "" ]]; then
  if command -v docker >/dev/null; then
    docker login \
      --username "$CI_REGISTRY_USER" \
      --password-stdin \
      "$CI_REGISTRY" \
      <<<"$CI_REGISTRY_PASSWORD" \
      >/dev/null \
    ;
  fi
fi

#
# Set up our SSH credentials as specified by the SSH_SECRET_KEY and
# SSH_PASSPHRASE environment variables.
#
# If SSH_SECRET_KEY is unset or empty, no setup is performed. Otherwise,
# SSH_SECRET_KEY should be either the text of a secret key or a path to
# a secret key file, and SSH_PASSPHRASE should be the passphrase of the
# key. If the key has no passphrase, SSH_PASSPHRASE should be unset or
# empty.
#
# SSH_SECRET_KEY and SSH_PASSPHRASE can also be overridden by setting
# SSH_SECRET_KEY_VAR and SSH_PASSPHRASE_VAR to the names of different
# environment variables to use. For example, if your secret key is in
# MY_KEY, you can set SSH_SECRET_KEY_VAR=MY_KEY to use it. It may be
# unclear why you'd want to do this instead of just directly setting
# SSH_SECRET_KEY=$MY_KEY. Either approach will work, but the indirect
# approach is sometimes convenient for certain environments that may
# have challenging overriding behavior, such as GitLab CI.
#

readonly SSH_SECRET_KEY_VAR
if [[ "${SSH_SECRET_KEY_VAR-}" ]]; then
  sst_expect_basic_identifier "$SSH_SECRET_KEY_VAR"
  eval 'sst_x=${'$SSH_SECRET_KEY_VAR'-}'
  if [[ "$sst_x" ]]; then
    SSH_SECRET_KEY=$sst_x
  fi
fi
readonly SSH_SECRET_KEY

readonly SSH_PASSPHRASE_VAR
if [[ "${SSH_PASSPHRASE_VAR-}" ]]; then
  sst_expect_basic_identifier "$SSH_PASSPHRASE_VAR"
  eval 'sst_x=${'$SSH_PASSPHRASE_VAR'-}'
  if [[ "$sst_x" ]]; then
    SSH_PASSPHRASE=$sst_x
  fi
fi
readonly SSH_PASSPHRASE

if [[ "${SSH_SECRET_KEY-}" == "" ]]; then

  if [[ "${SSH_PASSPHRASE-}" != "" ]]; then
    sst_warn 'SSH_PASSPHRASE is set without SSH_SECRET_KEY'
  fi

else

  cat <<'EOF' >"$sst_tmpdir"/ssh_config
IdentitiesOnly yes
PasswordAuthentication no
PreferredAuthentications publickey
StrictHostKeyChecking no
UserKnownHostsFile /dev/null
EOF
  chmod 400 "$sst_tmpdir"/ssh_config

  if [[ "$SSH_SECRET_KEY" == ----* ]]; then
    cat <<<"$SSH_SECRET_KEY" >"$sst_tmpdir"/ssh_secret_key
  else
    cat <"$SSH_SECRET_KEY" >"$sst_tmpdir"/ssh_secret_key
  fi
  chmod 400 "$sst_tmpdir"/ssh_secret_key

  if [[ "${SSH_PASSPHRASE-}" == "" ]]; then

    sst_install_utility ssh ssh-keygen

    if ! ssh-keygen -y -f "$sst_tmpdir"/ssh_secret_key >/dev/null; then
      sst_barf 'invalid SSH_SECRET_KEY'
    fi

  else

    cat <<<"$SSH_PASSPHRASE" >"$sst_tmpdir"/ssh_passphrase
    chmod 400 "$sst_tmpdir"/ssh_passphrase

    sst_install_utility ssh ssh-keygen sshpass

    x=$(sst_quote "$sst_tmpdir"/ssh_passphrase)
    sst_utility_suffixes[sshpass]+=' -f '$x
    sst_utility_suffixes[sshpass]+=' -P assphrase'

    if ! sshpass \
         ssh-keygen -y -f "$sst_tmpdir"/ssh_secret_key >/dev/null; then
      sst_barf 'invalid SSH_SECRET_KEY or SSH_PASSPHRASE'
    fi

  fi

  x1=$(sst_quote "$sst_tmpdir"/ssh_config)
  x2=$(sst_quote "$sst_tmpdir"/ssh_secret_key)
  sst_utility_suffixes[ssh]+=' -F '$x1
  sst_utility_suffixes[ssh]+=' -o IdentityFile='$x2

  if [[ "${SSH_PASSPHRASE-}" != "" ]]; then
    sst_utility_suffixes[ssh]=" \
      ${sst_utility_suffixes[sshpass]} \
      ${sst_utility_programs[ssh]} \
      ${sst_utility_suffixes[ssh]} \
    "
    sst_utility_programs[ssh]=${sst_utility_programs[sshpass]}
    sst_utility_prefixes[ssh]+=${sst_utility_prefixes[sshpass]}
  fi

  #
  # Set and export GIT_SSH_COMMAND instead of prepending it to
  # ${sst_utility_prefixes[git]} so that git commands run by other
  # scripts will also use our SSH credentials. Note that git does not
  # necessarily need to be installed here, as we're simply setting an
  # environment variable that git will use if it is in fact installed.
  #

  export GIT_SSH_COMMAND=" \
    ${sst_utility_prefixes[ssh]} \
    command \
    ${sst_utility_programs[ssh]} \
    ${sst_utility_suffixes[ssh]} \
  "

fi

#
# Set up our GPG credentials as specified by the GPG_SECRET_KEY and
# GPG_PASSPHRASE environment variables.
#
# If GPG_SECRET_KEY is unset or empty, no setup is performed. Otherwise,
# GPG_SECRET_KEY should be either the text of a secret key or a path to
# a secret key file, and GPG_PASSPHRASE should be the passphrase of the
# key. If the key has no passphrase, GPG_PASSPHRASE should be unset or
# empty.
#
# GPG_SECRET_KEY and GPG_PASSPHRASE can also be overridden by setting
# GPG_SECRET_KEY_VAR and GPG_PASSPHRASE_VAR to the names of different
# environment variables to use. The behavior and rationale for these
# overrides are the same as for the analogous SSH_* overrides.
#

if [[ "${GPG_SECRET_KEY_VAR-}" != "" ]]; then
  sst_expect_basic_identifier "$GPG_SECRET_KEY_VAR"
  eval GPG_SECRET_KEY=\$$GPG_SECRET_KEY_VAR
fi

if [[ "${GPG_PASSPHRASE_VAR-}" != "" ]]; then
  sst_expect_basic_identifier "$GPG_PASSPHRASE_VAR"
  eval GPG_PASSPHRASE=\$$GPG_PASSPHRASE_VAR
fi

if [[ "${GPG_SECRET_KEY-}" == "" ]]; then

  if [[ "${GPG_PASSPHRASE-}" != "" ]]; then
    sst_warn 'GPG_PASSPHRASE is set without GPG_SECRET_KEY'
  fi

else

  sst_install_utility git gpg2

  mkdir "$sst_tmpdir"/gpg_home
  chmod 700 "$sst_tmpdir"/gpg_home

  x=$(sst_quote "$sst_tmpdir"/gpg_home)
  sst_utility_suffixes[gpg2]+=' --batch'
  sst_utility_suffixes[gpg2]+=' --homedir '$x
  sst_utility_suffixes[gpg2]+=' --no-tty'
  sst_utility_suffixes[gpg2]+=' --quiet'

  #
  # The --pinentry-mode option was added in GnuPG 2.1, so we can't use
  # it in GnuPG 2.0.x. The exact commit in the GnuPG Git repository is
  # b786f0e12b93d8d61eea18c934f5731fe86402d3.
  #

  x=$(gpg2 --version | sed -n '1s/^[^0-9]*//p')
  if [[ "$x" != 2.0* ]]; then
    sst_utility_suffixes[gpg2]+=' --pinentry-mode loopback'
  fi

  if [[ "$GPG_SECRET_KEY" == ----* ]]; then
    cat <<<"$GPG_SECRET_KEY" >"$sst_tmpdir"/gpg_secret_key
  else
    cat <"$GPG_SECRET_KEY" >"$sst_tmpdir"/gpg_secret_key
  fi
  chmod 400 "$sst_tmpdir"/gpg_secret_key
  gpg2 --import "$sst_tmpdir"/gpg_secret_key

  if [[ "${GPG_PASSPHRASE-}" != "" ]]; then
    cat <<<"$GPG_PASSPHRASE" >"$sst_tmpdir"/gpg_passphrase
    chmod 400 "$sst_tmpdir"/gpg_passphrase
    x=$(sst_quote "$sst_tmpdir"/gpg_passphrase)
    sst_utility_suffixes[gpg2]+=' --passphrase-file='$x
  fi

  cat <<EOF >"$sst_tmpdir"/gpg_program
#! /bin/sh -
case \$# in
  0) ${sst_utility_prefixes[gpg2]} \
     ${sst_utility_programs[gpg2]} \
     ${sst_utility_suffixes[gpg2]}      ; exit \$? ;;
  *) ${sst_utility_prefixes[gpg2]} \
     ${sst_utility_programs[gpg2]} \
     ${sst_utility_suffixes[gpg2]} "\$@"; exit \$? ;;
esac
EOF
  chmod +x "$sst_tmpdir"/gpg_program
  x=$(sst_quote "$sst_tmpdir"/gpg_program)
  sst_utility_suffixes[git]+=' -c gpg.program='$x

  r='[0-9A-Fa-f]'
  r="[ 	]*$r$r$r$r"
  r="$r$r$r$r$r$r$r$r$r$r"
  x=$(gpg2 --fingerprint | sed -n '
    /'"$r"'/ {
      s/.*\('"$r"'\).*/\1/
      s/[ 	]//g
      p
      q
    }
  ')
  sst_utility_suffixes[git]+=' -c user.signingKey=0x'$x
  sst_utility_suffixes[git]+=' -c commit.gpgSign=true'
  sst_utility_suffixes[git]+=' -c tag.gpgSign=true'

fi

#
# Set up our Git name and email.
#
# These variables can be overridden by using the standard GIT_AUTHOR_*
# and GIT_COMMITTER_* environment variables. For more information, see
# "man git-commit" and "man git-commit-tree", or view them online at
# <https://git-scm.com/docs/git-commit> and
# <https://git-scm.com/docs/git-commit-tree>.
#
# GIT_AUTHOR_* and GIT_COMMITTER_* can be further overridden by setting
# GIT_AUTHOR_*_VAR and GIT_COMMITTER_*_VAR to the names of different
# environment variables to use. The behavior and rationale for these
# overrides are the same as for the analogous SSH_* overrides.
#

for x in \
  GIT_AUTHOR_DATE \
  GIT_AUTHOR_EMAIL \
  GIT_AUTHOR_NAME \
  GIT_COMMITTER_DATE \
  GIT_COMMITTER_EMAIL \
  GIT_COMMITTER_NAME \
; do

  #
  # Override $x with ${x}_VAR if it's set.
  #

  eval y=\${${x}_VAR+x}
  if [[ "$y" != "" ]]; then
    eval y=\${${x}_VAR}
    sst_expect_basic_identifier "$y"
    eval $x=\$$y
  fi

  #
  # Ensure that $x is exported if it's set.
  #

  eval y=\${$x+x}
  if [[ "$y" != "" ]]; then
    export $x
  fi

done

#
# If we're in a GitLab CI job, fill in various unset GIT_* environment
# variables using the job information.
#

if [[ "${CI_JOB_URL-}" != "" ]]; then
  if [[ "${GIT_AUTHOR_EMAIL+x}" == "" ]]; then
    export GIT_AUTHOR_EMAIL="$GITLAB_USER_EMAIL"
  fi
  if [[ "${GIT_AUTHOR_NAME+x}" == "" ]]; then
    export GIT_AUTHOR_NAME="$GITLAB_USER_NAME"
  fi
  if [[ "${GIT_COMMITTER_EMAIL+x}" == "" ]]; then
    export GIT_COMMITTER_EMAIL=""
  fi
  if [[ "${GIT_COMMITTER_NAME+x}" == "" ]]; then
    export GIT_COMMITTER_NAME="$CI_JOB_URL"
  fi
fi

#
# Create an empty temporary subdirectory for the calling script to use.
#

readonly sst_tmpdir="$sst_tmpdir"/x
mkdir "$sst_tmpdir"

# DEPRECATED
readonly tmpdir="$sst_tmpdir"
