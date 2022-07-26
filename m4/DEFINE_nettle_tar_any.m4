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
AC_DEFUN([DEFINE_nettle_tar_any], [[{

#
# The block that contains this comment is the expansion of the
# DEFINE_nettle_tar_any macro.
#

]m4_ifdef(
  [DEFINE_nettle_tar_any_HAS_BEEN_CALLED],
  [gatbps_fatal([
    DEFINE_nettle_tar_any has already been called
  ])],
  [m4_define([DEFINE_nettle_tar_any_HAS_BEEN_CALLED])])[

]m4_if(
  m4_eval([$# != 0]),
  [1],
  [gatbps_fatal([
    DEFINE_nettle_tar_any requires exactly 0 arguments
    ($# ]m4_if([$#], [1], [[was]], [[were]])[ given)
  ])])[

]m4_define(
  [nettle_tar_any_default],
  [[build-aux/downloads/nettle-3.4.tar.gz]])[

case $][{nettle_tar_any+is_set} in
  '')
    nettle_tar_any=']nettle_tar_any_default['
  ;;
esac
readonly nettle_tar_any

]AC_ARG_VAR(
  [nettle_tar_any],
  [
    the nettle-*.tar.* file to use (default:
    nettle_tar_any=']nettle_tar_any_default[')
  ])[

:;}]])[]dnl
