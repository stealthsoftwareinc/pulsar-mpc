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

AC_DEFUN_ONCE([DEFINE_HAVE_CFLAG_MAES], [[{

]AC_BEFORE([$0], [DEFINE_CFLAGS])[

]GATBPS_SOFT_REQUIRE([DEFINE_HAVE_CFLAG_MSSE])[
]GATBPS_SOFT_REQUIRE([DEFINE_HAVE_CFLAG_MSSE2])[
]GATBPS_SOFT_REQUIRE([DEFINE_WITH_AES_NI])[
]GATBPS_SOFT_REQUIRE([DEFINE_WITH_SSE])[
]GATBPS_SOFT_REQUIRE([DEFINE_WITH_SSE2])[

]GATBPS_CHECK_CFLAG(
  [CFLAGS += -maes (compile 1)],
  [HAVE_CFLAG_MAES_COMPILE_1],
  [-maes],
  [1
    && ]GATBPS_SOFT_VAR([HAVE_CFLAG_MSSE])[
    && ]GATBPS_SOFT_VAR([HAVE_CFLAG_MSSE2])[
    && ]GATBPS_SOFT_VAR([WITH_AES_NI])[
    && ]GATBPS_SOFT_VAR([WITH_SSE])[
    && ]GATBPS_SOFT_VAR([WITH_SSE2])[
  ])[

]m4_pushdef(
  [prologue],
  [[[
    #include <emmintrin.h> // SSE2
    #include <wmmintrin.h> // AES and PCLMULQDQ
  ]]])[

]m4_pushdef(
  [body],
  [[[
    __m128i x = _mm_setzero_si128();
    x = _mm_aesdec_si128(x, x);
    x = _mm_aesdeclast_si128(x, x);
    x = _mm_aesenc_si128(x, x);
    x = _mm_aesenclast_si128(x, x);
    x = _mm_aesimc_si128(x);
    x = _mm_aeskeygenassist_si128(x, 0);
    (void)x;
  ]]])[

old_CFLAGS=$CFLAGS

CFLAGS="$CFLAGS -maes"

]AC_LANG_PUSH([C])[
]GATBPS_CHECK_COMPILE(
  [CFLAGS += -maes (compile 2)],
  [HAVE_CFLAG_MAES_COMPILE_2],
  prologue,
  body,
  [1
    && HAVE_CFLAG_MAES_COMPILE_1
  ])[
]AC_LANG_POP([C])[

]GATBPS_ARG_WITH_BOOL(
  [CFLAGS += -maes (cross)],
  [WITH_CROSS_CFLAG_MAES],
  [cross-cflag-maes],
  [no],
  [assume that CFLAGS += -maes is available on the host system when cross compiling],
  [assume that CFLAGS += -maes is unavailable on the host system when cross compiling])[

]AC_LANG_PUSH([C])[
]GATBPS_CHECK_RUN(
  [CFLAGS += -maes (run)],
  [HAVE_CFLAG_MAES],
  prologue,
  body,
  [gatbps_cv_WITH_CROSS_CFLAG_MAES],
  [1
    && HAVE_CFLAG_MAES_COMPILE_2
  ])[
]AC_LANG_POP([C])[

case $HAVE_CFLAG_MAES in
  0)
    CFLAGS=$old_CFLAGS
  ;;
esac

]m4_popdef([body])[
]m4_popdef([prologue])[

:;}]])
