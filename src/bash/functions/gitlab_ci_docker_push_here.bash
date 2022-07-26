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

#
# gitlab_ci_docker_push_here <saved_image> <suffix> <config_h>
#

gitlab_ci_docker_push_here() {

  case $# in
    3)
    ;;
    *)
      sst_barf 'invalid argument count: %d' $#
    ;;
  esac

  local saved_image
  saved_image=$1
  readonly saved_image

  local suffix
  suffix=$2
  readonly suffix

  local config_h
  config_h=$3
  readonly config_h

  local tag
  tag=$(
    config_h_get_string \
      $config_h \
      PACKAGE_VERSION_DOCKER \
    ;
  )
  readonly tag

  local src
  src=$(docker load -q <$saved_image | sed -n '1s/.*: //p')
  readonly src

  local dst
  dst=$CI_REGISTRY_IMAGE/$CI_COMMIT_REF_SLUG$suffix
  readonly dst

  docker tag $src $dst:$tag
  docker tag $src $dst:latest

  docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY <<EOF
$CI_REGISTRY_PASSWORD
EOF

  docker push $dst:$tag
  docker push $dst:latest

}; readonly -f gitlab_ci_docker_push_here
