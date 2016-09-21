Temporary and experimental code for the auth server rewrite. Eventually 
useful code will be migrated (with unit tests & documentation) to kbase/auth2.

Unit tests & documentation for code in this repo is not required.

Current endpoints
-----------------

/admin/localaccount  
create a local account.

/admin/user/&lt;user name&gt;  
View user and modify user roles.

/admin/customroles  
View and add custom roles.

/link  
Link accounts.

/login  
login to a provider based account. Stores a cookie with a token.

/localaccount/login  
login to a local account. Stores a cookie with a token.

/logout  
Self explanatory.

/me  
User page.

/tokens  
list and create tokens

/api/legacy/KBase/Sessions/Login  
the legacy KBase API

/api/legacy/globus  
the legacy globus API. Endpoints are /goauth/token and /users.

Admin notes
-----------
* It is expected that this server always runs behind a reverse proxy (such as
  nginx) that enforces https / TLS and as such the auth server is configured to
  allow cookies to be set over insecure connections.
  * If the reverse proxy rewrites paths for the auth server, cookie path
    rewriting must be enabled for the /login and /link paths. Nginx example:

		location /auth/ {
			proxy_pass http://localhost:20002/;
			proxy_cookie_path /login /auth/login;
			proxy_cookie_path /link /auth/link;
		}

* Get Globus creds [here](https://developers.globus.org)
  * Required scopes are:
    * urn:globus:auth:scope:auth.globus.org:view_identities 
    * email
* Get Google OAuth2 creds [here](https://console.developers.google.com/apis)
  * Note that the Google+ API must be enabled.

Requirements
------------
Java 8 (OpenJDK OK)  
MongoDB 2.4+ (https://www.mongodb.com/)  
Jetty 9.3+ (http://www.eclipse.org/jetty/download.html)
    (see jetty-config.md for version used for testing)  
This repo (git clone https://github.com/kbaseIncubator/auth2proto)  
The jars repo (git clone https://github.com/kbase/jars)  
The two repos above need to be in the same parent folder.

To start server
---------------
start mongodb  
cd into the auth2 repo  
ant build  
copy deploy.cfg.example to deploy.cfg and fill in appropriately  
`export KB_DEPLOYMENT_CONFIG=<path to deploy.cfg>`  
set a root password
`./manageauth -d <path to deploy.cfg> -r`
cd jettybase  
`./jettybase$ java -jar -Djetty.port=<port> <path to jetty install>/start.jar`  

Administer the server
---------------------
Login to a local account as `***ROOT***` with the password you set. Create a
local account and assign it the create administrator role. That account can
then be used to create further administrators (including itself) without
needing to login as root.

Start & stop server w/o a pid
-----------------------------
./jettybase$ java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar ~/jetty/jetty-distribution-9.3.11.v20160721/start.jar  
./jettybase$ java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar ~/jetty/jetty-distribution-9.3.11.v20160721/start.jar --stop  

Omit the stop key to have jetty generate one for you.


