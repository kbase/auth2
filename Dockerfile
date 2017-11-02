FROM kbase/kb_jre:latest

# These ARGs values are passed in via the docker build command
ARG BUILD_DATE
ARG VCS_REF
ARG BRANCH=develop

COPY deployment/ /kb/deployment/
COPY jettybase/ /kb/deployment/jettybase/

# The BUILD_DATE value seem to bust the docker cache when the timestamp changes, move to
# the end
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/kbase/auth2.git" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0.0-rc1" \
      us.kbase.vcs-branch=$BRANCH \
      maintainer="Steve Chan sychan@lbl.gov"

WORKDIR /kb/deployment/jettybase
ENTRYPOINT [ "/kb/deployment/bin/dockerize" ]
CMD [  "-template", "/kb/deployment/conf/.templates/deployment.cfg.templ:/kb/deployment/conf/deployment.cfg", \
       "java", "-DSTOP.PORT=8079", "-DSTOP.KEY=foo", "-Djetty.home=$JETTY_HOME", \
       "-jar", "$JETTY_HOME/start.jar" ]
