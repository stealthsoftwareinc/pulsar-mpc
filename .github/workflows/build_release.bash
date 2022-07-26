#! /bin/sh -
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
# This script uses the SST Bash library to bootstrap from /bin/sh into
# bash. See the Bash library > Bootstrapping section of the SST manual
# for more information.
#

#-----------------------------------------------------------------------
# Load the prelude
#-----------------------------------------------------------------------

case $0 in /*) x=$0 ;; *) x=./$0 ;; esac
r='\(.*/\)'
x=`expr "$x" : "$r"`. || exit $?
set -e || exit $?
. "$x/../../src/bash/prelude.bash"

#-----------------------------------------------------------------------

main() {

  declare    version
  declare    x

  ./configure

  version=$(sh build-aux/gatbps-gen-version.sh)
  readonly version

  for x in \
    pulsar-mpc-$version-android.tar.xz \
    pulsar-mpc-$version.aar \
  ; do
    make -j 2 $x
    gpg2 -b $x
  done

  cat <<<"$GPG_PUBLIC_KEY" >pulsar-mpc-gpg-key.pub

}; readonly -f main

#-----------------------------------------------------------------------

main "$@"
