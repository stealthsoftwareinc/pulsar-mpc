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

sst_find_dist_archive() {

  local -r dir="$sst_root_tmpdir/$FUNCNAME.$BASHPID"
  local archive
  local n
  local s
  local similar
  local wc_x
  local wc_y
  local x
  local y

  sst_expect_argument_count $# 0

  for archive in *.tar.gz; do

    # (Re)create our temporary directory.
    rm -f -r "$dir"
    mkdir "$dir"

    # Extract the archive into our temporary directory.
    (cd "$dir" && tar xz) <"$archive"

    # The archive should contain exactly one root entity.
    n=$(cd "$dir" && find . '!' -name . -prune -print | grep -c /)
    if ((n != 1)); then
      continue
    fi

    # The root entity should be a directory.
    s=0
    test -d "$dir"/* || s=$?
    if ((s == 1)); then
      continue
    fi
    if ((s != 0)); then
      sst_barf 'test -d failed'
    fi

    # The directory should contain a few files that match our own. We
    # avoid using the cmp utility because it's not available on some
    # systems (e.g., on the centos:8 Docker image). The wc utility
    # should be good enough.
    for x in configure.ac Makefile.am; do
      similar=0
      for y in "$dir"/*/"$x"; do
        wc_x=$(wc <"$x")
        wc_y=$(wc <"$y")
        if [[ "$wc_x" == "$wc_y" ]]; then
          similar=1
        fi
      done
      if ((!similar)); then
        continue 2
      fi
    done

    # We found it.
    rm -f -r "$dir"
    printf '%s\n' "$archive"
    return

  done

  sst_barf 'distribution archive not found'

}; readonly -f sst_find_dist_archive
