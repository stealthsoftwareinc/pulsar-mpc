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

AC_DEFUN_ONCE([DEFINE_HAVE_AES_NI], [{ :

  AC_REQUIRE([DEFINE_HAVE_CFLAG_MAES])
  AC_REQUIRE([DEFINE_WITH_AES_NI])

  GATBPS_SOFT_REQUIRE([DEFINE_HAVE_CFLAG_MSSE])
  GATBPS_SOFT_REQUIRE([DEFINE_HAVE_CFLAG_MSSE2])
  GATBPS_SOFT_REQUIRE([DEFINE_HAVE_CXXFLAG_MAES])
  GATBPS_SOFT_REQUIRE([DEFINE_HAVE_CXXFLAG_MSSE])
  GATBPS_SOFT_REQUIRE([DEFINE_HAVE_CXXFLAG_MSSE2])
  GATBPS_SOFT_REQUIRE([DEFINE_WITH_AES_NI_OR_DIE])
  GATBPS_SOFT_REQUIRE([DEFINE_WITH_SSE])
  GATBPS_SOFT_REQUIRE([DEFINE_WITH_SSE2])

  GATBPS_CHECK_EXPR(
    [for AES-NI],
    [HAVE_AES_NI],
    (1
      && [HAVE_CFLAG_MAES]
      && [WITH_AES_NI]

      && GATBPS_SOFT_VAR([HAVE_CFLAG_MSSE])
      && GATBPS_SOFT_VAR([HAVE_CFLAG_MSSE2])
      && GATBPS_SOFT_VAR([HAVE_CXXFLAG_MAES])
      && GATBPS_SOFT_VAR([HAVE_CXXFLAG_MSSE])
      && GATBPS_SOFT_VAR([HAVE_CXXFLAG_MSSE2])
      && GATBPS_SOFT_VAR([WITH_SSE])
      && GATBPS_SOFT_VAR([WITH_SSE2])
    ))

  [
    case $HAVE_AES_NI$][{WITH_AES_NI_OR_DIE-1} in 01)
      ]GATBPS_ERROR([
        --with-aes-ni-or-die
        was specified but
        AES-NI
        was not detected.
      ])[
    esac
  ]

}])
