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

sst_ajh_java_program_wrapper() {

  local ag_json
  local class
  local jar
  local jar_base
  local schema
  local src
  local wrapper
  local x

  for ag_json; do

    sst_expect_ag_json wrapper "$ag_json"

    sst_jq_get_string $ag_json class

    sst_jq_get_string $ag_json jar

    sst_jq_get_string $ag_json src

    if [[ "$src" == "" ]]; then
      src=$sst_root_tmpdir/$FUNCNAME.src
      if [[ ! -f "$src" ]]; then
        sst_ihs <<<'
          #! /bin/sh -

          #
          # We use -ea in default_javaflags because it'\''s a good default approach:
          # slower code with more diagnostics is often preferable to faster code
          # with fewer diagnostics. When we really do want to go as fast as
          # possible, we can use -da in JAVAFLAGS.
          #
          # We export CLASSPATH because this allows it to be overridden by using
          # -cp in JAVAFLAGS. We could accomplish the same thing by using -cp in
          # default_javaflags, but exporting CLASSPATH is better because it
          # doesn'\''t have any quoting concerns.
          #

          case $JAVA in "")
            JAVA=java
          esac
          readonly JAVA

          x=
          x=$x'\'' -ea'\''
          default_javaflags=$x
          readonly default_javaflags

          readonly JAVAFLAGS

          x=
          x="$x $JAVA"
          x="$x -XshowSettings:property"
          x="$x -version"
          x="$x 2>&1"
          x=`eval "$x"` || exit $?
          case $x in *"path.separator = ;"*)
            path_separator=";"
          ;; *)
            path_separator=:
          esac
          readonly path_separator

          case $CLASSPATH in ?*)
            CLASSPATH=$CLASSPATH$path_separator
          esac
          case $USE_BUILD_TREE in ?*)
            x='\''{@}abs_builddir{@}/%jar%.build_tree_classpath'\''
            CLASSPATH=$CLASSPATH`cat "$x"` || exit $?
          ;; *)
            x='\''{@}javadir{@}/%jar_base%.classpath'\''
            CLASSPATH=$CLASSPATH`cat "$x"` || exit $?
          esac
          case $path_separator in ";")
            CLASSPATH=`cygpath -l -p -w -- "$CLASSPATH"` || exit $?
          esac
          readonly CLASSPATH
          export CLASSPATH

          x=
          x="$x $JAVA"
          x="$x $default_javaflags"
          x="$x $JAVAFLAGS"
          x="$x "'\''%class%'\''
          case $# in 0)
            :
          ;; *)
            x="$x \"\$@\""
          esac
          eval exec "$x"
        ' >"$src"
      fi
    else
      sst_expect_source_path "$src"
    fi

    jar_base=${jar##*/}

    sed "
      s|%class%|$class|g
      s|%jar%|$jar|g
      s|%jar_base%|$jar_base|g
    " <"$src" >$wrapper.im.in

    chmod +x $wrapper.im.in

    sst_ac_config_file $wrapper.im.in

    # TODO: Use some sst_am_var_add_* function that verifies that
    # $wrapper either exists as a file or doesn't exist, and does
    # deduplication?
    sst_am_var_add bin_SCRIPTS $wrapper

  done

}; readonly -f sst_ajh_java_program_wrapper
