#!/bin/sh -x
# Shell wrapper for starting jetty
java -DSTOP.PORT=8079 -Djetty.home=$JETTY_HOME -jar $JETTY_HOME/start.jar
