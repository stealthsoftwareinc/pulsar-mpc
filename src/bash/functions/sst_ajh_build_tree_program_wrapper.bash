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

sst_ajh_build_tree_program_wrapper() {

  local ag_json
  local wrappee
  local wrapper

  for ag_json; do

    sst_expect_ag_json wrapper "$ag_json"

    sst_jq_get_string $ag_json wrappee
    if [[ "$wrappee" == "" ]]; then
      wrappee=$wrapper.wrappee/${wrapper##*/}
    else
      sst_expect_source_path "$wrappee"
    fi

    sst_mkdir_p_only $wrapper.im

    sst_ihs <<<"
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

      USE_BUILD_TREE=1
      readonly USE_BUILD_TREE
      export USE_BUILD_TREE

      wrappee='{@}abs_builddir{@}/$wrappee'
      readonly wrappee

      case \$# in
        0) exec \"\$wrappee\" ;;
        *) exec \"\$wrappee\" \"\$@\" ;;
      esac
    " >$wrapper.im

    chmod +x $wrapper.im

    sst_ac_config_file $wrapper.im

    sst_am_distribute $wrapper.im

    # TODO: Use some sst_am_var_add_* function that verifies that
    # $wrapper either exists as a file or doesn't exist, and does
    # deduplication?
    sst_am_var_add noinst_SCRIPTS $wrapper

  done

}; readonly -f sst_ajh_build_tree_program_wrapper
