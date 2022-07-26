dnl
dnl Copyright (C) 2021 Stealth Software Technologies, Inc.
dnl
dnl Permission is hereby granted, free of charge, to any person
dnl obtaining a copy of this software and associated documentation
dnl files (the "Software"), to deal in the Software without
dnl restriction, including without limitation the rights to use,
dnl copy, modify, merge, publish, distribute, sublicense, and/or
dnl sell copies of the Software, and to permit persons to whom the
dnl Software is furnished to do so, subject to the following
dnl conditions:
dnl
dnl The above copyright notice and this permission notice shall be
dnl included in all copies or substantial portions of the Software.
dnl
dnl THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
dnl EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
dnl OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
dnl NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
dnl HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
dnl WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
dnl FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
dnl OTHER DEALINGS IN THE SOFTWARE.
dnl

dnl---------------------------------------------------------------------

AC_INIT(
  [[PULSAR-MPC]],
  m4_esyscmd_s([
    sh build-aux/gatbps-gen-version.sh
  ])m4_if(m4_sysval, [0], [], [m4_fatal([gatbps-gen-version.sh failed])]),
  [[pulsar-mpc@stealthsoftwareinc.com]],
  [[pulsar-mpc]])

dnl---------------------------------------------------------------------

m4_include([build-aux/gatbps.ac])

dnl---------------------------------------------------------------------
dnl Program checks
dnl---------------------------------------------------------------------

GATBPS_PROG_GIT

dnl---------------------------------------------------------------------

[

]gatbps_check_macros[ || 'exit' "${?}"

]GATBPS_DEFINE_VERSION(
  [AC_],
  [PACKAGE_VERSION])[

]GATBPS_DEFINE_DATE(
  [AC_],
  [PACKAGE_DATE],
  m4_esyscmd_s([
    'sh' '-' 'build-aux/gatbps-gen-date.sh'
  ])m4_if(m4_sysval, [0], [], [m4_fatal([gatbps-gen-date.sh failed])]))[

]AC_CONFIG_AUX_DIR([build-aux])[
]AC_CONFIG_MACRO_DIR([m4])[
]AC_CONFIG_MACRO_DIRS([m4])[
]AC_CONFIG_SRCDIR([src/base/global_utils.h])[

]AM_INIT_AUTOMAKE([
  -Wall
  foreign
  nostdinc
  subdir-objects
  tar-ustar
])[

]DEFINE_ALL[

]LT_INIT([win32-dll])[

]dnl begin_includes
[

]m4_include([build-aux/autogen.ac])[
]m4_include([lib/libbmc_la.ac])[

]dnl end_includes
[

]dnl begin_targets
[

]GATBPS_CONFIG_FILE(
  [build-aux/INPUT_FILTER.sh])[

]GATBPS_CONFIG_FILE(
  [build-aux/PACKAGE_STRING.df])[

]GATBPS_CONFIG_FILE(
  [src/aar/pulsar-mpc/build.gradle])[

]dnl end_targets
[

]GATBPS_CONFIG_FILE_SUBST[
]GATBPS_CONFIG_LATER_SUBST[
]GATBPS_CP_SUBST[
]GATBPS_DOCKER_BUILD_SUBST[
]GATBPS_GIT_ARCHIVE_SUBST[
]GATBPS_GIT_BUNDLE_SUBST[
]GATBPS_GIT_CLONE_SUBST[
]GATBPS_WGET_SUBST[

]AC_CONFIG_FILES([Makefile])[
]AC_CONFIG_HEADERS([include/src/config.h])[

]AC_OUTPUT[

]
