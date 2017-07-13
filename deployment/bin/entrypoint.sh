#!/bin/bash
#
# This entrypoint script defaults to using environment variables to populate
# a jinja2 config template and writing out the config before starting the service
#
# If a first parameter is given it overrides the environment variables for the
# data source and is either a file path or a URL
# If a second parameter is given it overrides the default template and it should be
# either a file path or a URL
#
# If there is a readable file at /run/secrets/auth_data then it will be read in
# and passed as a header for a request to the data source URL, it must be in the
# form "HEADER_NAME:VALUE" that httpie uses for custom headers. For example, to
# set a gitlab private token header you would create a file that contains
# "PRIVATE-TOKEN:mesoextrasecret"
# A readable file at /run/secrets/auth_template is used for custom headers to the
# template URL. Note that they are separated to avoid leaking creds to a URL that
# doesn't require them
#

# Define an error exit function
function error_exit
{
	echo "$1" 1>&2
	exit 1
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Default config template
TEMPLATE=$DIR/../conf/.templates/deployment.cfg.j2

# Default data source is empty, resulting in env variables being used
DATA_SRC=""

# Set empty default values for the auth headers
AUTH_DATA=""
AUTH_TEMPLATE=""

# Auth header secret paths
if [ -r "/run/secrets/auth_data" ]; then
     AUTH_DATA=`cat /run/secrets/auth_data`
fi
if [ -r "/run/secrets/auth_template" ]; then
    AUTH_TEMPLATE=`cat /run/secrets/auth_template`
fi

# If we have a first argument see if it is a file else treat a URL
if [ "$1" ] ; then
    if [ -r $1 ] ; then
        DATA_SRC=$1
    else
        TMPDIR=/tmp/data$$
        mkdir $TMPDIR
        # Fetch the file, and have it error out on any redirects to avoid a 200 response
        # that is just a redirect to a login screen
        wget -q -nd --max-redirect=0 --no-check-certificate --header="${AUTH_DATA}" -P $TMPDIR $1  || \
            error_exit "Error fetching $1"
        DATA_SRC=$TMPDIR/*
    fi
fi

# If we are given a second parameter treat it as a template file path or
# a URL
if [ "$2" ] ; then
    if [ -r $2 ]; then
        TEMPLATE=$2
    else
        TMPDIR2=/tmp/template$$
        mkdir $TMPDIR2
        pushd $TMPDIR2
        wget -q -nd --max-redirect=0 --no-check-certificate --header="${AUTH_TEMPLATE}" -P $TMPDIR2 $2 || \
            error_exit "Error fetching $2"
        popd
        TEMPLATE=$TMPDIR2/*
    fi
fi

export KB_DEPLOYMENT_CONFIG=$DIR/../conf/deployment.cfg

# Crib the jetty start command from the jetty repo info page https://hub.docker.com/r/library/jetty/
/usr/local/bin/j2 $TEMPLATE $DATA_SRC > $KB_DEPLOYMENT_CONFIG && \
cd $DIR/../jettybase/ && \
java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar $JETTY_HOME/start.jar
