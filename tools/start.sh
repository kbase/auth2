# start the auth2 server emitting log to console
# copy me to repo root, run with bash. E.g. bash start.sh
export KB_DEPLOYMENT_CONFIG=`pwd`/deploy.cfg
cd jettybase
java -jar -Djetty.port=9090 /usr/local/share/jetty/start.jar