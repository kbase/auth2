FROM kbase/sdkbase2 as build

WORKDIR /tmp/auth2

# dependencies take a while to D/L, so D/L & cache before the build so code changes don't cause
# a new D/L
# can't glob *gradle because of the .gradle dir
COPY build.gradle gradlew settings.gradle /tmp/auth2/
COPY gradle/ /tmp/auth2/gradle/
RUN ./gradlew dependencies

# Now build the code
COPY deployment/ /tmp/auth2/deployment/
COPY jettybase/ /tmp/auth2/jettybase/
COPY src /tmp/auth2/src/
COPY templates /tmp/auth2/templates/
COPY war /tmp/auth2/war/
# for the git commit
COPY .git /tmp/auth2/.git/
RUN ./gradlew war

FROM kbase/kb_jre:latest

# These ARGs values are passed in via the docker build command
ARG BUILD_DATE
ARG VCS_REF
ARG BRANCH=develop

COPY --from=build /tmp/auth2/deployment/ /kb/deployment/
COPY --from=build /tmp/auth2/jettybase/ /kb/deployment/jettybase/
COPY --from=build /tmp/auth2/build/libs/auth2.war /kb/deployment/jettybase/webapps/ROOT.war
COPY --from=build /tmp/auth2/templates /kb/deployment/jettybase/templates

# The BUILD_DATE value seem to bust the docker cache when the timestamp changes, move to
# the end
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/kbase/auth2.git" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0.0-rc1" \
      us.kbase.vcs-branch=$BRANCH \
      maintainer="Steve Chan sychan@lbl.gov"

WORKDIR /kb/deployment/jettybase
ENV KB_DEPLOYMENT_CONFIG=/kb/deployment/conf/deployment.cfg

# TODO BUILD update to no longer use dockerize and take env vars (e.g. like Collections).
# TODO BUILD figure out how to add multiple environments as env vars (multiline env vars in rancher?)
# TODO BUILD Use subsections in the ini file / switch to TOML

ENTRYPOINT [ "/kb/deployment/bin/dockerize" ]

# Here are some default params passed to dockerize. They would typically
# be overidden by docker-compose at startup
CMD [  "-template", "/kb/deployment/conf/.templates/deployment.cfg.templ:/kb/deployment/conf/deployment.cfg", \
       "java", "-DSTOP.PORT=8079", "-DSTOP.KEY=foo", "-Djetty.home=$JETTY_HOME", \
       "-jar", "$JETTY_HOME/start.jar" ]
