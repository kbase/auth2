# Create a self-contained alpine-linux based docker image for auth2

FROM jetty:jre8-alpine
MAINTAINER Steve Chan sychan@lbl.gov

ARG BUILD_DATE
ARG VCS_REF
ARG BRANCH=develop

RUN apk add --update ca-certificates python2 py2-jinja2 py2-yaml py2-pip wget && \
    update-ca-certificates && \
    pip install shinto-cli[yaml]

RUN mkdir /kb

COPY deployment/ /kb/deployment/
COPY jettybase/ /kb/deployment/jettybase/

# The BUILD_DATE value seem to bust the docker cache when the timestamp changes, move to
# the end
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/kbase/auth2.git" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0.0-rc1" \
      us.kbase.vcs-branch=$BRANCH

ENTRYPOINT [ "/kb/deployment/bin/entrypoint.sh" ]