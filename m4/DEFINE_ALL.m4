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
AC_DEFUN([DEFINE_ALL], [[{

#
# The block that contains this comment is the expansion of the
# DEFINE_ALL macro.
#]dnl
m4_ifdef(
  [DEFINE_ALL_HAS_BEEN_CALLED],
  [gatbps_fatal([
    DEFINE_ALL has already been called
  ])],
  [m4_define([DEFINE_ALL_HAS_BEEN_CALLED])])[]dnl
m4_if(
  m4_eval([$# != 0]),
  [1],
  [gatbps_fatal([
    DEFINE_ALL requires exactly 0 arguments
    ($# ]m4_if([$#], [1], [[was]], [[were]])[ given)
  ])])[]dnl
[

]dnl begin_prerequisites
[

]AC_REQUIRE([DEFINE_android_ndk_linux_x86_64_zip])[
]AC_REQUIRE([DEFINE_gmp_tar_any])[
]AC_REQUIRE([DEFINE_nettle_tar_any])[
]AC_REQUIRE([DEFINE_rabbitmq_c_tar_any])[

]dnl end_prerequisites
[

]dnl begin_prerequisites
[

]AC_REQUIRE([DEFINE_AR])[
]AC_REQUIRE([DEFINE_AWK])[
]AC_REQUIRE([DEFINE_CC])[
]AC_REQUIRE([DEFINE_CXX])[
]AC_REQUIRE([DEFINE_DOCKER])[
]AC_REQUIRE([DEFINE_GREP])[
]AC_REQUIRE([DEFINE_LN_S])[
]AC_REQUIRE([DEFINE_MAKEINFO])[
]AC_REQUIRE([DEFINE_MKDIR_P])[
]AC_REQUIRE([DEFINE_OPENSSL])[
]AC_REQUIRE([DEFINE_RANLIB])[
]AC_REQUIRE([DEFINE_SED])[
]AC_REQUIRE([DEFINE_WGET])[

]dnl end_prerequisites
[

]dnl begin_prerequisites
[

]AC_REQUIRE([DEFINE_WITH_AES_NI])[
]AC_REQUIRE([DEFINE_WITH_AES_NI_OR_DIE])[
]AC_REQUIRE([DEFINE_WITH_JNI])[
]AC_REQUIRE([DEFINE_WITH_JNI_OR_DIE])[

]dnl end_prerequisites
[

]dnl begin_prerequisites
[

]AC_REQUIRE([DEFINE_HAVE_AES_NI])[
]AC_REQUIRE([DEFINE_HAVE_CFLAG_MAES])[
]AC_REQUIRE([DEFINE_HAVE_CFLAG_MSSE4_1])[
]AC_REQUIRE([DEFINE_HAVE_CXXFLAG_MAES])[
]AC_REQUIRE([DEFINE_HAVE_CXXFLAG_MSSE4_1])[
]AC_REQUIRE([DEFINE_HAVE_JNI])[

]dnl end_prerequisites
[

]dnl begin_prerequisites
[

]AC_REQUIRE([DEFINE_LIB_CFLAGS])[
]AC_REQUIRE([DEFINE_LIB_CXXFLAGS])[
]AC_REQUIRE([DEFINE_LIB_LDFLAGS])[

]dnl end_prerequisites
[

]AC_REQUIRE([DEFINE_AT])[
]AC_REQUIRE([DEFINE_CFLAGS])[
]AC_REQUIRE([DEFINE_CPPFLAGS])[
]AC_REQUIRE([DEFINE_CXXFLAGS])[
]AC_REQUIRE([DEFINE_EXEEXT])[
]AC_REQUIRE([DEFINE_EXE_CFLAGS])[
]AC_REQUIRE([DEFINE_EXE_LDFLAGS])[
]AC_REQUIRE([DEFINE_DOCKER_BUILD_FLAGS])[
]AC_REQUIRE([DEFINE_EXE_CXXFLAGS])[

:;}]])[]dnl
