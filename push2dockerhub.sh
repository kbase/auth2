#!/bin/bash
# 
# This script is intended to be run in the deploy stage of a travis build
# It checks to make sure that this is a not a PR, and that we have the secure
# environment variables available and then checks if this is either the master
# or develop branch, otherwise we don't push anything
#
# sychan@lbl.gov
# 8/31/2017

if ( [ "$TRAVIS_SECURE_ENV_VARS" == "true" ] && [ "$TRAVIS_PULL_REQUEST" == "false" ] ) && \
   ( [ "$TAG" == "latest" ] || [ "$TAG" == "develop" ] ) ; then
    ant dockerimage
    docker login -e $DOCKER_EMAIL -u $DOCKER_USER -p $DOCKER_PASS
    export REPO=kbase/kb_auth2
    # $TRAVIS_BRANCH is a little wonky on pull requests, but it should be okay since we should 
    # never get here on a PR
    export TAG=`if [ "$TRAVIS_BRANCH" == "master" ]; then echo "latest"; else echo $TRAVIS_BRANCH ; fi`
    docker tag $REPO:$TRAVIS_COMMIT $REPO:$TAG
    docker push $REPO:$TAG
fi