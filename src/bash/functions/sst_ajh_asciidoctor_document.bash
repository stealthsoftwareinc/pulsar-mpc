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

sst_ajh_asciidoctor_document() {

  local adoc
  local ag_json
  local child
  local clean_rule
  local distribute
  local html
  local imagesdir
  local prefix
  local s
  local slug
  local tar_file
  local tar_file_slug
  local tarname
  local x
  local y

  for ag_json; do

    sst_expect_ag_json html "$ag_json"
    sst_expect_extension $ag_json .html.ag.json

    slug=$(sst_underscore_slug $html)

    adoc=${html%.html}.adoc
    sst_expect_any_file $adoc{,.ag.json,.ag,.ac,.am,.im.in,.in,.im}

    prefix=$(sst_get_prefix $ag_json)
    if [[ "$prefix" == "" ]]; then
      sst_barf 'document must have its own subdirectory: %s' $ag_json
    fi

    sst_jq_get_string "$ag_json" .tarname tarname
    if [[ ! "$tarname" ]]; then
      tarname=${html%/*}
      tarname=${tarname##*/}
    fi

    tar_file=$(sst_get_prefix ${prefix%/})$tarname.tar
    tar_file_slug=$(sst_underscore_slug $tar_file)

    sst_jq_get_string_or_null .clean_rule $ag_json clean_rule
    case $clean_rule in
      '' | mostlyclean | clean | distclean | maintainer-clean)
        :
      ;;
      *)
        sst_barf '%s: .clean_rule: invalid value' $ag_json
      ;;
    esac

    sst_jq_get_boolean_or_null .distribute $ag_json distribute
    if [[ "$distribute" == true ]]; then
      distribute=1
    else
      distribute=
    fi

    sst_jq_get_string_or_null .imagesdir $ag_json imagesdir
    if [[ "$imagesdir" == "" ]]; then
      imagesdir=images
    else
      sst_expect_source_path "$imagesdir"
    fi

    sst_am_var_add_unique_word ${slug}_children $prefix$imagesdir

    sst_am_append <<EOF

#-----------------------------------------------------------------------
# $html
#-----------------------------------------------------------------------

$prefix$imagesdir:
	\$(AM_V_at)\$(MKDIR_P) \$@

EOF

    if ((distribute)); then
      sst_am_distribute $html
      if [[ "$clean_rule" != "" ]]; then
        sst_warn '%s: ignoring clean_rule because distribute is true' $ag_json
      fi
      clean_rule=maintainer-clean
    elif [[ "$clean_rule" == "" ]]; then
      clean_rule=mostlyclean
    fi

    for x in $prefix**.im.in $prefix**; do
      x=${x%/}
      sst_expect_source_path "$x"
      if [[ ! -f $x ]]; then
        continue
      fi
      if [[ $x == $ag_json || $x == $html ]]; then
        continue
      fi
      sst_ag_process_leaf $html $x child
    done

    if ((distribute)); then
      sst_ihs <<<"
        $html: \$(${slug}_leaves)
        $html\$(${slug}_disable_wrapper_recipe):
        	\$(GATBPS_at)\$(MAKE) \\
        	  \$(${slug}_children) \\
        	  \$(${slug}_children_nodist) \\
        	;
      " | sst_am_append
    else
      sst_ihs <<<"
        $html: \$(${slug}_children)
        $html: \$(${slug}_children_nodist)
        $html\$(${slug}_disable_wrapper_recipe):
      " | sst_am_append
    fi

    sst_am_append <<EOF
	\$(AM_V_at)rm -f -r \\
	  \$@ \\
	  \$@\$(TSUF)* \\
	  $prefix$imagesdir/diag-* \\
	;
	\$(AM_V_at){ \\
	  flags='-a imagesdir=$imagesdir '; \\
	  \$(SHELL) - \\
	    '\$(srcdir)'/build-aux/echo.sh -q -- \\
	    \$(ASCIIDOCTOR_FLAGS) \\
	    >\$@\$(TSUF) \\
	  || exit \$\$?; \\
	  flags=\$\$flags\`cat \$@\$(TSUF)\` || exit \$\$?; \\
	  rm -f -r \$@\$(TSUF)*; \\
	  \$(MAKE) \\
	    ${slug}_disable_wrapper_recipe=/x \\
	    ASCIIDOCTOR_FLAGS="\$\$flags" \\
	    \$@ \\
	  || exit \$\$?; \\
	}

$html/clean: FORCE
	-rm -f -r \\
	  \$(@D) \\
	  \$(@D)\$(TSUF)* \\
	  $prefix$imagesdir/diag-* \\
	;

$clean_rule-local: $html/clean

$tar_file: $html
	\$(AM_V_at)rm -f -r \$@ \$@\$(TSUF)*
	\$(AM_V_at)\$(MKDIR_P) \$@\$(TSUF)1/$tarname
	\$(AM_V_at)cp $html \$@\$(TSUF)1/$tarname
	@{ \\
	  xs=; \\
	  for ext in \\
	    .css \\
	    .gif \\
	    .jpg \\
	    .js \\
	    .png \\
	    .svg \\
	  ; do \\
	    xs="\$\$xs "\` \\
	      find $prefix. -name "*\$\$ext" -type f \\
	    \` || exit \$\$?; \\
	  done; \\
	  for x in \$\$xs; do \\
	    y=\$\${x#$prefix./}; \\
	    case \$\$y in \\
	      */*) \\
	        d=\$\${y%/*}; \\
	        \$(AM_V_P) && echo \$(MKDIR_P) \\
	          \$@\$(TSUF)1/$tarname/\$\$d \\
	        ; \\
	        \$(MKDIR_P) \\
	          \$@\$(TSUF)1/$tarname/\$\$d \\
	        || exit \$\$?; \\
	      ;; \\
	      *) \\
	        d=.; \\
	      ;; \\
	    esac; \\
	    \$(AM_V_P) && echo cp \\
	      \$\$x \\
	      \$@\$(TSUF)1/$tarname/\$\$d \\
	    ; \\
	    cp \\
	      \$\$x \\
	      \$@\$(TSUF)1/$tarname/\$\$d \\
	    || exit \$\$?; \\
	  done; \\
	}
	\$(AM_V_at)(cd \$@\$(TSUF)1 && \$(TAR) c $tarname) >\$@\$(TSUF)2
	\$(AM_V_at)mv -f \$@\$(TSUF)2 \$@

${tar_file_slug}_leaves = \$(${slug}_leaves)

$tar_file/clean: FORCE
$tar_file/clean: $html/clean
	-rm -f -r \$(@D) \$(@D)\$(TSUF)*

mostlyclean-local: $tar_file/clean

#-----------------------------------------------------------------------
EOF

    # Distribute any images generated by Asciidoctor Diagram.
    if ((distribute)); then
      autogen_am_var_append EXTRA_DIST $prefix$imagesdir
    fi

  done

}; readonly -f sst_ajh_asciidoctor_document
