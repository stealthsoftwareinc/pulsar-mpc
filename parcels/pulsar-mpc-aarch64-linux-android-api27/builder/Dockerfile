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

FROM ubuntu:latest

ARG ARCH
ARG LEVEL

RUN : \
  && DEBIAN_FRONTEND=noninteractive \
  && export DEBIAN_FRONTEND \
  && apt-get -q -y update \
  && apt-get -q -y install \
    autoconf \
    automake \
    cmake \
    file \
    g++ \
    gcc \
    git \
    jq \
    libgmp-dev \
    libtool \
    lzip \
    m4 \
    make \
    nettle-dev \
    openjdk-8-jdk \
    openjdk-8-jre \
    texinfo \
    unzip \
    xz-utils \
;

RUN mkdir \
  /x \
  /x/native \
  /x/overlay \
  /x/overlay/circuits \
  /x/overlay/shared \
  /x/overlay/static \
  /x/shared \
  /x/static \
;

COPY ndk.zip /x/

RUN : \
  && mkdir /x/ndk.tmp \
  && unzip -qq /x/ndk.zip -d /x/ndk.tmp \
  && mv /x/ndk.tmp/* /x/ndk \
  && rmdir /x/ndk.tmp \
;

# COPY openssl.tar.any /x/
#
# RUN : \
#   && mkdir /x/openssl.tmp \
#   && cd /x/openssl.tmp \
#   && tar xf /x/openssl.tar.any \
#   && mv /x/openssl.tmp/* /x/shared/openssl \
#   && cd /x/shared/openssl \
#   && rmdir /x/openssl.tmp \
#   && ANDROID_NDK_HOME=/x/ndk \
#   && export ANDROID_NDK_HOME \
#   && PATH=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH \
#   && export PATH \
#   && SYSTEM=` \
#        case $ARCH in \
#          aarch64 ) echo android-arm64  ;; \
#          x86_64  ) echo android-x86_64 ;; \
#          *) \
#            printf 'unknown $ARCH: %s\n' "$ARCH" >&2; \
#            exit 1; \
#          ;; \
#        esac; \
#      ` \
#   && ./Configure \
#     -D__ANDROID_API__=$LEVEL \
#     shared \
#     no-tests \
#     --prefix=/usr \
#     $SYSTEM \
#   && make \
#   && make DESTDIR=/x/overlay/shared install \
#   && rm /x/overlay/shared/usr/lib/*.a \
# ;
#
# RUN : \
#   && mkdir /x/openssl.tmp \
#   && cd /x/openssl.tmp \
#   && tar xf /x/openssl.tar.any \
#   && mv /x/openssl.tmp/* /x/static/openssl \
#   && cd /x/static/openssl \
#   && rmdir /x/openssl.tmp \
#   && ANDROID_NDK_HOME=/x/ndk \
#   && export ANDROID_NDK_HOME \
#   && PATH=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH \
#   && export PATH \
#   && SYSTEM=` \
#        case $ARCH in \
#          aarch64 ) echo android-arm64  ;; \
#          x86_64  ) echo android-x86_64 ;; \
#          *) \
#            printf 'unknown $ARCH: %s\n' "$ARCH" >&2; \
#            exit 1; \
#          ;; \
#        esac; \
#      ` \
#   && ./Configure \
#     -D__ANDROID_API__=$LEVEL \
#     -static \
#     no-shared \
#     no-tests \
#     --prefix=/usr \
#     $SYSTEM \
#   && make \
#   && make DESTDIR=/x/overlay/static install \
# ;

COPY gmp.tar.any /x/

RUN : \
  && mkdir /x/gmp.tmp \
  && cd /x/gmp.tmp \
  && tar xf /x/gmp.tar.any \
  && mv /x/gmp.tmp/* /x/shared/gmp \
  && cd /x/shared/gmp \
  && rmdir /x/gmp.tmp \
  && export PATH=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH \
  && CFLAGS= \
  && CFLAGS="$CFLAGS -fPIC" \
  && CXXFLAGS= \
  && CXXFLAGS="$CXXFLAGS -fPIC" \
  && ./configure \
    --build=x86_64-unknown-linux-gnu \
    --disable-static \
    --enable-shared \
    --host=$ARCH-linux-android \
    --prefix=/usr \
    CC=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang \
    CFLAGS="$CFLAGS" \
    CPPFLAGS='-I/x/overlay/shared/usr/include' \
    CXX=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang++ \
    CXXFLAGS="$CXXFLAGS" \
    LDFLAGS='-L/x/overlay/shared/usr/lib' \
  && make \
  && make DESTDIR=/x/overlay/shared install \
  && cp -L -R /x/overlay/shared/usr/lib /x/overlay/shared/usr/lib.flat \
  && rm -f -r /x/overlay/shared/usr/lib \
  && mv -f /x/overlay/shared/usr/lib.flat /x/overlay/shared/usr/lib \
  && rm -f -r \
    /x/overlay/shared/usr/lib/*.la \
    /x/overlay/shared/usr/lib/*.so.* \
    /x/overlay/shared/usr/lib/pkgconfig \
;

# RUN : \
#   && mkdir /x/gmp.tmp \
#   && cd /x/gmp.tmp \
#   && tar xf /x/gmp.tar.any \
#   && mv /x/gmp.tmp/* /x/static/gmp \
#   && cd /x/static/gmp \
#   && rmdir /x/gmp.tmp \
#   && export PATH=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH \
#   && CFLAGS= \
#   && CFLAGS="$CFLAGS -fPIE" \
#   && CXXFLAGS= \
#   && CXXFLAGS="$CXXFLAGS -fPIE" \
#   && ./configure \
#     --build=x86_64-unknown-linux-gnu \
#     --disable-shared \
#     --enable-static \
#     --host=$ARCH-linux-android \
#     --prefix=/usr \
#     CC=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang \
#     CFLAGS="$CFLAGS" \
#     CPPFLAGS='-I/x/overlay/static/usr/include' \
#     CXX=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang++ \
#     CXXFLAGS="$CXXFLAGS" \
#     LDFLAGS='-L/x/overlay/static/usr/lib -static -static-libstdc++' \
#   && make \
#   && make DESTDIR=/x/overlay/static install \
#   && rm -f /x/overlay/static/usr/lib/*.la \
# ;

COPY nettle.tar.any /x/

RUN : \
  && mkdir /x/nettle.tmp \
  && cd /x/nettle.tmp \
  && tar xf /x/nettle.tar.any \
  && mv /x/nettle.tmp/* /x/shared/nettle \
  && cd /x/shared/nettle \
  && rmdir /x/nettle.tmp \
  && export PATH=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH \
  && CFLAGS= \
  && CFLAGS="$CFLAGS -fPIC" \
  && CXXFLAGS= \
  && CXXFLAGS="$CXXFLAGS -fPIC" \
  && ./configure \
    --build=x86_64-unknown-linux-gnu \
    --disable-static \
    --enable-shared \
    --host=$ARCH-linux-android \
    --prefix=/usr \
    CC=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang \
    CFLAGS="$CFLAGS" \
    CPPFLAGS='-I/x/overlay/shared/usr/include' \
    CXX=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang++ \
    CXXFLAGS="$CXXFLAGS" \
    LDFLAGS='-L/x/overlay/shared/usr/lib' \
  && make \
    LIBNETTLE_FILE=libnettle.so \
    LIBNETTLE_SONAME=libnettle.so \
  && make DESTDIR=/x/overlay/shared install \
  && cp -L -R /x/overlay/shared/usr/lib /x/overlay/shared/usr/lib.flat \
  && rm -f -r /x/overlay/shared/usr/lib \
  && mv -f /x/overlay/shared/usr/lib.flat /x/overlay/shared/usr/lib \
  && rm -f -r \
    /x/overlay/shared/usr/lib/*.la \
    /x/overlay/shared/usr/lib/*.so.* \
    /x/overlay/shared/usr/lib/*hogweed* \
    /x/overlay/shared/usr/lib/pkgconfig \
;

# RUN : \
#   && mkdir /x/nettle.tmp \
#   && cd /x/nettle.tmp \
#   && tar xf /x/nettle.tar.any \
#   && mv /x/nettle.tmp/* /x/static/nettle \
#   && cd /x/static/nettle \
#   && rmdir /x/nettle.tmp \
#   && export PATH=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH \
#   && CFLAGS= \
#   && CFLAGS="$CFLAGS -fPIE" \
#   && CXXFLAGS= \
#   && CXXFLAGS="$CXXFLAGS -fPIE" \
#   && ./configure \
#     --build=x86_64-unknown-linux-gnu \
#     --disable-shared \
#     --enable-static \
#     --host=$ARCH-linux-android \
#     --prefix=/usr \
#     CC=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang \
#     CFLAGS="$CFLAGS" \
#     CPPFLAGS='-I/x/overlay/static/usr/include' \
#     CXX=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang++ \
#     CXXFLAGS="$CXXFLAGS" \
#     LDFLAGS='-L/x/overlay/static/usr/lib -static -static-libstdc++' \
#   && make \
#   && make DESTDIR=/x/overlay/static install \
#   && rm -f /x/overlay/static/usr/lib/*.la \
# ;
#
# COPY rabbitmq-c.tar.any /x/
#
# RUN : \
#   && mkdir /x/rabbitmq-c.tmp \
#   && cd /x/rabbitmq-c.tmp \
#   && tar xf /x/rabbitmq-c.tar.any \
#   && mv /x/rabbitmq-c.tmp/* /x/shared/rabbitmq-c \
#   && cd /x/shared/rabbitmq-c \
#   && rmdir /x/rabbitmq-c.tmp \
#   && sed -i \
#     's/CONF_MFLAGS_DEFAULT_SECTION/& | CONF_MFLAGS_IGNORE_MISSING_FILE/' \
#     librabbitmq/amqp_openssl.c \
#   && mkdir build \
#   && cd build \
#   && ABI=` \
#        case $ARCH in \
#          aarch64) echo arm64-v8a ;; \
#          *) echo $ARCH ;; \
#        esac; \
#      ` \
#   && CFLAGS= \
#   && CFLAGS="$CFLAGS -fPIC" \
#   && CXXFLAGS= \
#   && CXXFLAGS="$CXXFLAGS -fPIC" \
#   && cmake \
#     -DANDROID_ABI=$ABI \
#     -DANDROID_PLATFORM=$LEVEL \
#     -DANDROID_TOOLCHAIN=clang \
#     -DBUILD_API_DOCS=OFF \
#     -DBUILD_EXAMPLES=OFF \
#     -DBUILD_SHARED_LIBS=ON \
#     -DBUILD_STATIC_LIBS=OFF \
#     -DBUILD_TESTS=OFF \
#     -DBUILD_TOOLS=OFF \
#     -DBUILD_TOOLS_DOCS=OFF \
#     -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
#     -DCMAKE_C_FLAGS="$CFLAGS" \
#     -DCMAKE_INSTALL_PREFIX=/usr \
#     -DCMAKE_TOOLCHAIN_FILE=/x/ndk/build/cmake/android.toolchain.cmake \
#     -DENABLE_SSL_SUPPORT=ON \
#     -DOPENSSL_CRYPTO_LIBRARY=/x/overlay/shared/usr/lib/libcrypto.so \
#     -DOPENSSL_INCLUDE_DIR=/x/overlay/shared/usr/include \
#     -DOPENSSL_SSL_LIBRARY=/x/overlay/shared/usr/lib/libssl.so \
#     -DOPENSSL_USE_STATIC_LIBS=FALSE \
#     .. \
#   && make \
#   && make DESTDIR=/x/overlay/shared install \
#   && rm -f /x/overlay/shared/usr/lib/*.la \
# ;
#
# RUN : \
#   && mkdir /x/rabbitmq-c.tmp \
#   && cd /x/rabbitmq-c.tmp \
#   && tar xf /x/rabbitmq-c.tar.any \
#   && mv /x/rabbitmq-c.tmp/* /x/static/rabbitmq-c \
#   && cd /x/static/rabbitmq-c \
#   && rmdir /x/rabbitmq-c.tmp \
#   && sed -i \
#     's/CONF_MFLAGS_DEFAULT_SECTION/& | CONF_MFLAGS_IGNORE_MISSING_FILE/' \
#     librabbitmq/amqp_openssl.c \
#   && mkdir build \
#   && cd build \
#   && ABI=` \
#        case $ARCH in \
#          aarch64) echo arm64-v8a ;; \
#          *) echo $ARCH ;; \
#        esac; \
#      ` \
#   && CFLAGS= \
#   && CFLAGS="$CFLAGS -fPIE" \
#   && CXXFLAGS= \
#   && CXXFLAGS="$CXXFLAGS -fPIE" \
#   && cmake \
#     -DANDROID_ABI=$ABI \
#     -DANDROID_PLATFORM=$LEVEL \
#     -DANDROID_TOOLCHAIN=clang \
#     -DBUILD_API_DOCS=OFF \
#     -DBUILD_EXAMPLES=OFF \
#     -DBUILD_SHARED_LIBS=OFF \
#     -DBUILD_STATIC_LIBS=ON \
#     -DBUILD_TESTS=OFF \
#     -DBUILD_TOOLS=OFF \
#     -DBUILD_TOOLS_DOCS=OFF \
#     -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
#     -DCMAKE_C_FLAGS="$CFLAGS" \
#     -DCMAKE_EXE_LINKER_FLAGS='-static' \
#     -DCMAKE_INSTALL_PREFIX=/usr \
#     -DCMAKE_TOOLCHAIN_FILE=/x/ndk/build/cmake/android.toolchain.cmake \
#     -DENABLE_SSL_SUPPORT=ON \
#     -DOPENSSL_CRYPTO_LIBRARY=/x/overlay/static/usr/lib/libcrypto.a \
#     -DOPENSSL_INCLUDE_DIR=/x/overlay/static/usr/include \
#     -DOPENSSL_SSL_LIBRARY=/x/overlay/static/usr/lib/libssl.a \
#     -DOPENSSL_USE_STATIC_LIBS=TRUE \
#     .. \
#   && make \
#   && make DESTDIR=/x/overlay/static install \
#   && rm -f /x/overlay/static/usr/lib/*.la \
# ;

COPY bmc.tar.any /x/

RUN : \
  && mkdir /x/bmc.tmp \
  && cd /x/bmc.tmp \
  && tar xf /x/bmc.tar.any \
  && mv /x/bmc.tmp/* /x/shared/bmc \
  && cd /x/shared/bmc \
  && rmdir /x/bmc.tmp \
  && export PATH=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH \
  && case $ARCH in x86_64) \
       x=; \
       x="$x --with-aes-ni-or-die"; \
       x="$x --with-cross-cflag-maes"; \
       x="$x --with-cross-cxxflag-maes"; \
       with_aes_ni_or_die=$x; \
     ;; *) \
       with_aes_ni_or_die=; \
     esac \
  && CFLAGS= \
  && CPPFLAGS= \
  && CPPFLAGS="$CPPFLAGS -I/usr/lib/jvm/java-8-openjdk-amd64/include" \
  && CPPFLAGS="$CPPFLAGS -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux" \
  && CPPFLAGS="$CPPFLAGS -I/x/overlay/shared/usr/include" \
  && CXXFLAGS= \
  && EXE_CFLAGS= \
  && EXE_CFLAGS="$EXE_CFLAGS -fPIE" \
  && EXE_CXXFLAGS= \
  && EXE_CXXFLAGS="$EXE_CXXFLAGS -fPIE" \
  && EXE_LDFLAGS= \
  && EXE_LDFLAGS="$EXE_LDFLAGS -pie" \
  && LIB_CFLAGS= \
  && LIB_CFLAGS="$LIB_CFLAGS -fPIC" \
  && LIB_CXXFLAGS= \
  && LIB_CXXFLAGS="$LIB_CXXFLAGS -fPIC" \
  && LIB_LDFLAGS= \
  && ./configure \
    $with_aes_ni_or_die \
    --build=x86_64-unknown-linux-gnu \
    --disable-static \
    --enable-shared \
    --host=$ARCH-linux-android \
    --prefix=/usr \
    CC=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang \
    CFLAGS="$CFLAGS" \
    CPPFLAGS="$CPPFLAGS" \
    CXX=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang++ \
    CXXFLAGS="$CXXFLAGS" \
    EXE_CFLAGS="$EXE_CFLAGS" \
    EXE_CXXFLAGS="$EXE_CXXFLAGS" \
    EXE_LDFLAGS="$EXE_LDFLAGS" \
    LDFLAGS='-L/x/overlay/shared/usr/lib' \
    LIB_CFLAGS="$LIB_CFLAGS" \
    LIB_CXXFLAGS="$LIB_CXXFLAGS" \
    LIB_LDFLAGS="$LIB_LDFLAGS" \
  && make \
  && make DESTDIR=/x/overlay/shared install \
  && cp -L -R /x/overlay/shared/usr/lib /x/overlay/shared/usr/lib.flat \
  && rm -f -r /x/overlay/shared/usr/lib \
  && mv -f /x/overlay/shared/usr/lib.flat /x/overlay/shared/usr/lib \
  && rm -f -r \
    /x/overlay/shared/usr/lib/*.la \
    /x/overlay/shared/usr/lib/*.so.* \
    /x/overlay/shared/usr/lib/pkgconfig \
;

# RUN : \
#   && mkdir /x/bmc.tmp \
#   && cd /x/bmc.tmp \
#   && tar xf /x/bmc.tar.any \
#   && mv /x/bmc.tmp/* /x/static/bmc \
#   && cd /x/static/bmc \
#   && rmdir /x/bmc.tmp \
#   && export PATH=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH \
#   && case $ARCH in x86_64) \
#        x=; \
#        x="$x --with-aes-ni-or-die"; \
#        x="$x --with-cross-cflag-maes"; \
#        x="$x --with-cross-cxxflag-maes"; \
#        with_aes_ni_or_die=$x; \
#      ;; *) \
#        with_aes_ni_or_die=; \
#      esac \
#   && CFLAGS= \
#   && CPPFLAGS= \
#   && CPPFLAGS="$CPPFLAGS -I/usr/lib/jvm/java-8-openjdk-amd64/include" \
#   && CPPFLAGS="$CPPFLAGS -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux" \
#   && CPPFLAGS="$CPPFLAGS -I/x/overlay/static/usr/include" \
#   && CXXFLAGS= \
#   && EXE_CFLAGS= \
#   && EXE_CFLAGS="$EXE_CFLAGS -fPIE" \
#   && EXE_CXXFLAGS= \
#   && EXE_CXXFLAGS="$EXE_CXXFLAGS -fPIE" \
#   && EXE_LDFLAGS= \
#   && EXE_LDFLAGS="$EXE_LDFLAGS -pie" \
#   && LIB_CFLAGS= \
#   && LIB_CFLAGS="$LIB_CFLAGS -fPIE" \
#   && LIB_CXXFLAGS= \
#   && LIB_CXXFLAGS="$LIB_CXXFLAGS -fPIE" \
#   && LIB_LDFLAGS= \
#   && ./configure \
#     $with_aes_ni_or_die \
#     --build=x86_64-unknown-linux-gnu \
#     --disable-shared \
#     --enable-static \
#     --host=$ARCH-linux-android \
#     --prefix=/usr \
#     CC=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang \
#     CFLAGS="$CFLAGS" \
#     CPPFLAGS="$CPPFLAGS" \
#     CXX=/x/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/$ARCH-linux-android$LEVEL-clang++ \
#     CXXFLAGS="$CXXFLAGS" \
#     EXE_CFLAGS="$EXE_CFLAGS" \
#     EXE_CXXFLAGS="$EXE_CXXFLAGS" \
#     EXE_LDFLAGS="$EXE_LDFLAGS" \
#     LDFLAGS='-L/x/overlay/static/usr/lib -static -static-libstdc++' \
#     LIB_CFLAGS="$LIB_CFLAGS" \
#     LIB_CXXFLAGS="$LIB_CXXFLAGS" \
#     LIB_LDFLAGS="$LIB_LDFLAGS" \
#   && make \
#   && make DESTDIR=/x/overlay/static install \
#   && rm -f /x/overlay/static/usr/lib/*.la \
# ;

RUN : \
  && mkdir /x/bmc.tmp \
  && cd /x/bmc.tmp \
  && tar xf /x/bmc.tar.any \
  && mv /x/bmc.tmp/* /x/native/bmc \
  && cd /x/native/bmc \
  && rmdir /x/bmc.tmp \
  && CFLAGS= \
  && CFLAGS="$CFLAGS -march=native" \
  && CPPFLAGS= \
  && CPPFLAGS="$CPPFLAGS -I/usr/lib/jvm/java-8-openjdk-amd64/include" \
  && CPPFLAGS="$CPPFLAGS -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux" \
  && CXXFLAGS= \
  && CXXFLAGS="$CXXFLAGS -march=native" \
  && ./configure \
    --disable-shared \
    --with-aes-ni-or-die \
    CFLAGS="$CFLAGS" \
    CPPFLAGS="$CPPFLAGS" \
    CXXFLAGS="$CXXFLAGS" \
  && make \
;

RUN : \
  && cd /x/native/bmc \
  && for x in src/circuits/*.function; do \
       r='\(.*\)\.function'; \
       x=`expr $x : $r` || exit $?; \
       bin/circuit_builder_main \
         --function_file $x.function \
         --output_file $x.cbg \
       || exit $?; \
       bin/circuit_builder_main \
         --function_file $x.function \
         --add_lookahead 4 \
         --output_file ${x}_lookahead_4.cbg \
       || exit $?; \
     done \
  && cp src/circuits/*.cbg /x/overlay/circuits \
;

RUN : \
  && cp \
    /x/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/$ARCH-linux-android/libc++_shared.so \
    /x/overlay/shared/usr/lib \
;
