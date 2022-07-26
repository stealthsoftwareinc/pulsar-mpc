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

sst_ajh_download() {

  local dir
  local ff
  local tt
  local x1
  local x2
  local x3
  local x4

  case $# in
    1)
    ;;
    *)
      sst_barf 'invalid argument count: %d' $#
    ;;
  esac

  dir=$1
  readonly dir

  for x1 in $dir/**/*.ag.json; do

    sst_expect_ag_json x2 "$x1"
    x3=$(basename $x2)
    x4=$(sst_underscore_slug $x3)

    tt=$(jq .type $x1)

    case $tt in

      null)

        autogen_ac_append <<EOF

]m4_define(
  [${x4}_urls_default],
  [[ ]dnl
[$dir/local/$x3 ]dnl
EOF

        jq -r '
          .urls[]
          | gsub("\\$"; "$][$][")
          | "['\'\\\\\'\''" + . + "'\'\\\\\'\'' ]dnl"
        ' $x1 | autogen_ac_append

        autogen_ac_append <<EOF
])[

case $][{${x4}_urls+x} in
  "")
    ${x4}_urls=']${x4}_urls_default['
  ;;
esac
readonly ${x4}_urls

]AC_ARG_VAR(
  [${x4}_urls],
  [
    the URLs from which to download the
    $x3
    file (default:
    ${x4}_urls=']${x4}_urls_default[')
  ])[

]GATBPS_WGET(
  [$x2],
  [
    [\$(${x4}_urls)],
  ],
  [
EOF

        jq -r '
          .hashes | to_entries[] | "    [" + .key + ":" + .value + "],"
        ' $x1 | autogen_ac_append

        autogen_ac_append <<EOF
  ],
  [clean])[

EOF

      ;;

      \"copy\")

        ff=$(jq -r .file $x1)

        autogen_ac_append <<EOF

]GATBPS_CP(
  [$x2],
  [$ff],
  [file],
  [clean])[

EOF

      ;;

      *)

        sst_barf 'unknown type: %s' "$tt"

      ;;

    esac

  done

}; readonly -f sst_ajh_download
