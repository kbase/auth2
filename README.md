KBase authentication server
===========================

This repo contains the second iteration of the KBase authentication server.

Build status (master):
[![Build Status](https://travis-ci.org/kbase/auth2.svg?branch=master)](https://travis-ci.org/kbase/auth2) [![codecov](https://codecov.io/gh/kbase/auth2/branch/master/graph/badge.svg)](https://codecov.io/gh/kbase/auth2)


Current endpoints
-----------------

### UI

UI endpoints are not versioned and not necessarily stable - behavior may change as needed to
support the auth UI.

Note that the HTML UI supplied in this repo is a minimal implementation for the purposes of
testing. In many cases a manual refresh of the page will be required to see
changes. Further, once a checkbox is manually checked or unchecked that state
will not change, even with a refresh - to see changes reset the form.

/  
General server information including git commit, version, and server time.

/admin  
Global admin tasks - force reset all passwords, revoke all tokens, view a token, search for users.

/admin/customroles  
View, add, and delete custom roles.

/admin/config  
View and edit the server configuration.

/admin/localaccount  
Create a local account.

/admin/user/&lt;user name&gt;  
View user, disable user, reset password, force password reset, and modify user roles.

/admin/user/&lt;user name&gt;/tokens  
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
Update the current user's email address and display name. Takes JSON encoded data with the
keys `display` and `email`.

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

POST /api/V2/token  
Create an agent token. Takes JSON encoded data with the keys `name` for a required token name
string and `customcontext` for an optional map of user-supplied creation context to be saved
with the token, and returned when the token is queried.

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

Requirements
------------
Java 8 (OpenJDK OK)  
Apache Ant (http://ant.apache.org/)  
MongoDB 2.6+ (https://www.mongodb.com/)  
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
copy `deploy.cfg.example` to `deploy.cfg` and fill in appropriately  
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
needing to login as root. The root account can then be disabled.

Start & stop server w/o a pid
-----------------------------
`./jettybase$ java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar ~/jetty/jetty-distribution-9.3.11.v20160721/start.jar`  
`./jettybase$ java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar ~/jetty/jetty-distribution-9.3.11.v20160721/start.jar --stop`  

Omit the stop key to have jetty generate one for you.

Developer notes
---------------

### Adding and releasing code

* Adding code
  * All code additions and updates must be made as pull requests directed at the develop branch.
    * All tests must pass and all new code must be covered by tests.
    * All new code must be documented appropriately
      * Javadoc
      * General documentation if appropriate
      * Release notes
* Releases
  * The master branch is the stable branch. Releases are made from the develop branch to the master
    branch.
  * Update the version as per the semantic version rules in `src/us/kbase/auth2/ui/Root.java`.
  * Tag the version in git and github.

### Running tests

* Copy `test.cfg.example` to `test.cfg` and fill in the values appropriately.
  * If it works as is start buying lottery tickets immediately.
* `ant test`

### UI

* Some fields are arbitrary text entered by a user. These fields should be HTML-escaped prior to
  display. Currently the fields include:
  * Custom role descriptions
  * The reason for why a user account was enabled and disabled.
  * User display names and email addresses.
  * Token names
  * Token custom context
  
Use common sense when displaying a field from the server regarding whether the field should be
html escaped or not.
  
### Templates

All the HTML templates for the test UI are in the /templates directory and are
[mustache](https://mustache.github.io/) templates.

### Exception mapping

In `us.kbase.auth2.lib.exceptions`:  
`AuthException` and subclasses other than the below - 400  
`AuthenticationException` and subclasses - 401  
`UnauthorizedException` and subclasses - 403  
`NoDataException` and subclasses - 404  

`JsonMappingException` (from [Jackson](https://github.com/FasterXML/jackson)) - 400  

Anything else is mapped to 500.

Ancient history
---------------

https://github.com/kbaseIncubator/auth2proto
