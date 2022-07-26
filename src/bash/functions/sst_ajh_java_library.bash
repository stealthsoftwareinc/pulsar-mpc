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

sst_ajh_java_library() {

  local ag
  local built_jardeps
  local child
  local dst
  local dst_slug
  local ext
  local jardep
  local jardeps
  local java_build_tree_cp
  local java_cp
  local java_cps
  local java_slug
  local java_target_slug
  local javac_cp
  local javac_cps
  local javadoc_slug
  local leaf
  local maven_sourcepath
  local noinst
  local package
  local package_dir
  local slug
  local sourcepath
  local x
  local xs
  local y
  local y3

  java_cps='@CLASSPATH_SEPARATOR_RAW_LATER@'
  readonly java_cps

  javac_cps='$(CLASSPATH_SEPARATOR)'
  readonly javac_cps

  for ag; do

    expect_safe_path "$ag"
    case $ag in
      *.jar.ag.json)
      ;;
      *)
        sst_barf 'expected *.jar.ag.json: %s' $ag
      ;;
    esac

    jq_expect_object . $ag

    jq_expect_string .dst $ag
    dst=$(jq -r .dst $ag)
    expect_safe_path "$dst"
    case $dst in
      *.jar)
      ;;
      *)
        sst_barf '%s: .dst: expected *.jar: %s' $ag $dst
      ;;
    esac

    dst_slug=$(sst_underscore_slug $dst)

    jq_expect_string_or_null .slug $ag
    slug=$(jq -r '.slug | select(.)' $ag)
    readonly slug

    case $slug in
      "")
        java_target_slug=java-main
        java_slug=java
        javadoc_slug=javadoc
      ;;
      *)
        java_target_slug=java-$slug
        java_slug=java_$slug
        javadoc_slug=javadoc_$slug
      ;;
    esac
    readonly java_target_slug
    readonly java_slug
    readonly javadoc_slug

    jq_expect_strings_or_null .jardeps $ag
    jardeps=$(jq -r '.jardeps | select(.) | .[]' $ag)
    readonly jardeps

    jq_expect_strings_or_null .built_jardeps $ag
    built_jardeps=$(jq -r '.built_jardeps | select(.) | .[]' $ag)
    readonly built_jardeps

    javac_cp=
    java_cp="{@}javadir{@}/${dst##*/}"
    java_build_tree_cp="{@}abs_builddir{@}/$dst"
    for jardep in $jardeps; do
      if [[ "$jardep" == *:* ]]; then
        x=${jardep%%:*}
        y=${jardep#*:}
      elif [[ "$jardep" == '{@}'* ]]; then
        x=$jardep
        y=
      else
        x=
        y=$jardep
      fi
      if [[ "$x" != '' ]]; then
        x=${x//'{@}'/}
        javac_cp+="$javac_cps\$($x)"
        java_cp+="$java_cps{@}$x{@}"
        java_build_tree_cp+="$java_cps{@}$x{@}"
      fi
      if [[ "$y" != '' ]]; then
        if [[ '' \
          || "$y" == */* \
          || -f "$y".ag \
          || -f "$y".ag.json \
          || -f "$y".ac \
          || -f "$y".am \
        ]]; then
          sst_ihs <<<"
            install-$java_target_slug-jardeps-targets: $y
            install-$java_target_slug-jardeps: \\
              install-$java_target_slug-jardeps-$y
            install-$java_target_slug-jardeps-$y: FORCE $y
          " | sst_am_append
          if [[ "$x" != '' ]]; then
            sst_ihs <<<"
              	if test -f \$($x); then \\
              	  :; \\
              	else \\
              	  ( \$(NORMAL_INSTALL) ) || exit \$\$?; \\
              	  \$(MKDIR_P) '\$(DESTDIR)\$(javadir)' || exit \$\$?; \\
              	  \$(INSTALL_DATA) $y '\$(DESTDIR)\$(javadir)' || exit \$\$?; \\
              	fi;
            " | sst_am_append
          else
            sst_ihs <<<"
              	@\$(NORMAL_INSTALL)
              	\$(MKDIR_P) '\$(DESTDIR)\$(javadir)'
              	\$(INSTALL_DATA) $y '\$(DESTDIR)\$(javadir)'
            " | sst_am_append
          fi
        fi
        javac_cp+="$javac_cps$y"
        java_build_tree_cp+="$java_cps{@}abs_builddir{@}/$y"
        y=${y##*/}
        javac_cp+="$javac_cps\$(javadir)/$y"
        javac_cp+="$javac_cps/usr/local/share/java/$y"
        javac_cp+="$javac_cps/usr/share/java/$y"
        java_cp+="$java_cps{@}javadir{@}/$y"
        java_cp+="$java_cps/usr/local/share/java/$y"
        java_cp+="$java_cps/usr/share/java/$y"
        java_build_tree_cp+="$java_cps{@}javadir{@}/$y"
        java_build_tree_cp+="$java_cps/usr/local/share/java/$y"
        java_build_tree_cp+="$java_cps/usr/share/java/$y"
      fi
    done

    for y in $built_jardeps; do
      javac_cp+="$javac_cps$y"
      java_build_tree_cp+="$java_cps{@}abs_builddir{@}/$y"
      y=${y##*/}
      java_cp+="$java_cps{@}javadir{@}/$y"
      java_cp+="$java_cps/usr/local/share/java/$y"
      java_cp+="$java_cps/usr/share/java/$y"
      java_build_tree_cp+="$java_cps{@}javadir{@}/$y"
      java_build_tree_cp+="$java_cps/usr/local/share/java/$y"
      java_build_tree_cp+="$java_cps/usr/share/java/$y"
    done

    printf '%s\n' "$java_cp" >$dst.classpath.im.in
    printf '%s\n' "$java_build_tree_cp" >$dst.build_tree_classpath.im.in

    jq_expect_string '.sourcepath' $ag
    sourcepath=$(jq -r '.sourcepath' $ag)
    expect_safe_path "$sourcepath"

    sst_jq_get_string "$ag" .maven_sourcepath maven_sourcepath
    readonly maven_sourcepath
    if [[ "$maven_sourcepath" != "" ]]; then
      sst_expect_source_path "$maven_sourcepath"
    fi

    package=$(jq -r .package $ag)
    readonly package

    package_dir=$(echo $package | sed 's|\.|/|g')
    readonly package_dir

    noinst=$(jq -r 'select(.noinst == true) | "x"' $ag)
    readonly noinst

    autogen_ac_append <<EOF

]GATBPS_CONFIG_FILE([$dst.classpath.im])[
]GATBPS_CONFIG_LATER([$dst.classpath])[

]GATBPS_CONFIG_FILE([$dst.build_tree_classpath.im])[
]GATBPS_CONFIG_LATER([$dst.build_tree_classpath])[

EOF

    case $slug in
      ?*)
        autogen_ac_append <<EOF

]GATBPS_JAVA([$slug])[

EOF
      ;;
    esac

    sst_am_append <<EOF
${java_slug}_CLASSPATH = $javac_cp
${java_slug}_dep =
$dst: $built_jardeps
${java_target_slug}: $dst.classpath
${java_target_slug}: $dst.build_tree_classpath
${java_slug}_dst = $dst
${java_slug}_nested =
${java_slug}_noinst = $noinst
${java_slug}_package = $package
${java_slug}_sourcepath = $sourcepath
${java_slug}_src =
${javadoc_slug}_src =
jar_classpath_files += $dst.classpath
EOF

    sst_am_append <<EOF

install-$java_target_slug-jardeps-targets: FORCE
install-$java_target_slug-jardeps: FORCE
install-java-jardeps-targets: FORCE
install-java-jardeps: FORCE

.PHONY: install-$java_target_slug-jardeps-targets
.PHONY: install-$java_target_slug-jardeps
.PHONY: install-java-jardeps-targets
.PHONY: install-java-jardeps

install-java-jardeps-targets: install-$java_target_slug-jardeps-targets

install-java-jardeps: install-$java_target_slug-jardeps
EOF

    xs=$(jq -r 'select(.dep) | .dep[]' $ag)
    for x in $xs; do
      sst_am_append <<EOF
${java_slug}_dep += $x
EOF
    done

    for x in $sourcepath/$package_dir/**/; do
      sst_ihs <<<"
        ${java_slug}_nested += $x*\\\$\$*.class
      " | sst_am_append
    done

    ext='@(.ag|.ac|.am|.im.in|.in|.im|.m4|)'
    for leaf in $sourcepath/$package_dir/**/*.java$ext; do

      sst_expect_source_path "$leaf"

      sst_ag_process_leaf $dst/src $leaf child

      if [[ "$child" == "" ]]; then
        continue
      fi

      if [[ "$maven_sourcepath" != "" ]]; then
        x=${child/#$sourcepath/$maven_sourcepath}
        sst_ac_append <<<"GATBPS_CP([$x], [$child])"
        sst_am_append <<<"maven-prep: $x"
      fi

      y3=${child/%.java/.class}

      autogen_ac_append <<EOF

]GATBPS_JAVA_CLASS(
  [$y3],
  [mostlyclean])[

EOF

      sst_ihs <<<"
        ${java_slug}_src += $y3
      " | sst_am_append

      sst_ihs <<<"
        ${javadoc_slug}_src += $child
      " | sst_am_append

    done

  done

}; readonly -f sst_ajh_java_library
