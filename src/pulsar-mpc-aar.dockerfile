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

RUN ( : \
  && DEBIAN_FRONTEND=noninteractive \
  && export DEBIAN_FRONTEND \
  && apt-get -q -y update \
  && apt-get -q -y install \
       coreutils \
       openjdk-11-jdk-headless \
       unzip \
)

ARG ANDROID_HOME=/android-home
ARG GITHUB_ACTOR=
ARG GITHUB_MAVEN_PKG_URL=
ARG GITHUB_TOKEN=
ARG JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ARG api

COPY pulsar-mpc.tar /x/
COPY tools.zip /x/
COPY aar /x/aar/

WORKDIR /x

RUN ( : \
  && mkdir pulsar-mpc \
  && cd pulsar-mpc \
  && tar xf ../pulsar-mpc.tar \
  && cd .. \
  && mkdir aar/pulsar-mpc/src/main/assets \
  && mkdir aar/pulsar-mpc/src/main/jniLibs \
  && for x in pulsar-mpc/*/lib/*-api$api; do \
       cp -L -R $x aar/pulsar-mpc/src/main/jniLibs || exit $?; \
       case $x in */lib/x86_64-*) \
         mv -f \
           aar/pulsar-mpc/src/main/jniLibs/x86_64-* \
           aar/pulsar-mpc/src/main/jniLibs/x86_64 \
         || exit $?; \
       ;; */lib/aarch64-*) \
         mv -f \
           aar/pulsar-mpc/src/main/jniLibs/aarch64-* \
           aar/pulsar-mpc/src/main/jniLibs/arm64-v8a \
         || exit $?; \
       esac; \
     done \
  && cp -L -R \
       pulsar-mpc/*/circuits \
       aar/pulsar-mpc/src/main/assets/ThreadMPC \
)

RUN ( : \
  && mkdir tools \
  && cd tools \
  && unzip ../tools.zip \
  && cd .. \
  && yes | tools/*/bin/sdkmanager \
       --sdk_root="$ANDROID_HOME" \
       --licenses \
  && cd aar \
  && ./gradlew --no-daemon assemble \
  && if ${GITHUB_MAVEN_PKG_URL:+:} false; then \
       ./gradlew --no-daemon publish || exit $?; \
     fi \
  && mv -f pulsar-mpc/build/outputs/aar/pulsar-mpc-release.aar .. \
)
