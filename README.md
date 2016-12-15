KBase authentication server
===========================

This repo contains the second iteration of the KBase authentication server.

Current endpoints
-----------------

### UI

UI endpoints are not versioned and not necessarily stable - behavior may change as needed to
support the auth UI.

Note that the current UI is a minimal implementation for the purposes of
testing. In many cases a manual refresh of the page will be required to see
changes. Further, once a checkbox is manually checked or unchecked, that state
will not change, even with a refresh - to see changes reset the form.

/admin  
Global admin tasks - force reset all passwords, revoke all tokens, view a token.

/admin/customroles  
View, add, and delete custom roles.

/admin/config  
View and edit the server configuration.

/admin/localaccount  
Create a local account.

/admin/user/&lt;user name&gt;  
View user, disable user, reset password, force password reset, and modify user roles.

/admin/user/&lt;user name&gt;/tokens;  
View and revoke tokens for a specific user.

/customroles  
View custom roles. This page is publicly viewable to any user with a valid token.

/link  
Link accounts.

/login  
Login to a provider based account. Stores a cookie with a token.

/localaccount/login  
Login to a local account. Stores a cookie with a token.

/localaccount/reset  
Reset the password for a local account.

/logout  
Self explanatory.

/me  
User page. Update name and email address, remove roles.

/tokens  
List, create, and revoke tokens.

### API

API endpoints are versioned and behavior should not change in a backwards incompatible manner
without a change in version.

All API calls require a valid token in the `Authorization` header except legacy API endpoints,
which continue to use their original protocol. All endpoints produce JSON data unless otherwise
noted.

GET /api/V2/me  
See the current user's profile.

PUT /api/V2/me  
Update the current user's email address and display name. Takes form or JSON encoded data with the
keys `display` and `email`. Use the `Content-Type` header to specify input type.

GET /api/V2/users/?list=&lt;comma separated user names&gt;  
Validate a set of user names and get the users' display names. Returns a map of username ->
display name. Any usernames that do not correspond to accounts will not be included in the map.

GET /api/V2/users/search/&lt;prefix&gt;/?fields=&lt;comma separated fields&gt;  
Find users based on a prefix of the username or any parts of the display name, where parts are
delimited by whitespace. By default the search occurs on all fields; setting the fields query
parameter can restrict the search fields and thus possibly speed up the search. Current field names
are `username` and `displayname`; any other field names are ignored. Returns a map of
username -> display name. At most 10,000 names are returned.

GET /api/V2/token  
Introspect a token.

#### Legacy

Endpoints (mostly) identical to the original Globus and KBase auth endpoints are provided for
backwards compatibility.

POST /api/legacy/KBase/Sessions/Login  
The legacy KBase API.

GET /api/legacy/globus  
The legacy globus API. Endpoints are /goauth/token and /users.

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

UI developer notes
------------------
* Some fields are arbitrary text entered by a user. These fields should be HTML-escaped prior to
  display. The fields are noted where they occur in the test UI. Currently the fields include:
  * Custom role descriptions
  * The reason for why a user account was enabled and disabled.

Requirements
------------
Java 8 (OpenJDK OK)  
MongoDB 2.4+ (https://www.mongodb.com/)  
Jetty 9.3+ (http://www.eclipse.org/jetty/download.html)
    (see jetty-config.md for version used for testing)  
This repo (git clone https://github.com/kbase/auth2)  
The jars repo (git clone https://github.com/kbase/jars)  
The two repos above need to be in the same parent folder.

To start server
---------------
start mongodb  
cd into the auth2 repo  
`ant build`  
copy deploy.cfg.example to deploy.cfg and fill in appropriately  
`export KB_DEPLOYMENT_CONFIG=<path to deploy.cfg>`  
`cd jettybase`  
`./jettybase$ java -jar -Djetty.port=<port> <path to jetty install>/start.jar`  

Import Globus users
------------
Use the `manage_auth` script to import Globus users - run with the `--help`
option for instructions. 

Administer the server
---------------------
Set a root password:  
`./manage_auth -d <path to deploy.cfg> -r`  

Login to a local account as `***ROOT***` with the password you set. Create a
local account and assign it the create administrator role. That account can
then be used to create further administrators (including itself) without
needing to login as root.

Start & stop server w/o a pid
-----------------------------
`./jettybase$ java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar ~/jetty/jetty-distribution-9.3.11.v20160721/start.jar`  
`./jettybase$ java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar ~/jetty/jetty-distribution-9.3.11.v20160721/start.jar --stop`  

Omit the stop key to have jetty generate one for you.

Ancient history
---------------

https://github.com/kbaseIncubator/auth2proto
