# KBase authentication server

This repo contains the second iteration of the KBase authentication server.

Build status (master):
[![Build Status](https://travis-ci.org/kbase/auth2.svg?branch=master)](https://travis-ci.org/kbase/auth2) [![codecov](https://codecov.io/gh/kbase/auth2/branch/master/graph/badge.svg)](https://codecov.io/gh/kbase/auth2)


## Current endpoints

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
Logs the user out.  
Removes the user's token from the database as well as any temporary link tokens associated with
the user. Removes the login, temporary login, and temporary link cookies except if JSON output
is requested, in which case it is expected that the UI manages the login token
(but not the temporary tokens).

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

Tokens are opaque strings - no particular structure should be assumed, and token string contents
may change without notice.

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

### Test Mode

Test mode allows integration of the auth service into test harnesses for dependent services and
applications by providing endpoints for creating test users, tokens, and roles on the fly. A
subset of the API above is supported (see below).

To enable test mode, add the following line to the service `deploy.cfg` file:

	test-mode-enabled=true

Test mode should never be enabled for production services.

All test mode data is stored in separate collections from the standard data in the service data
stores, and is automatically deleted one hour after creation. Test mode user accounts have no
passwords and no linked identities and so logging into test mode accounts is impossible,
although tokens can be created arbitrarily. Note that test mode user accounts are more or less
arbitrarily specified as local accounts in the API.

Test mode data is only accessible via endpoints under the `/testmode` root endpoint.

#### Standard endpoints

These endpoints mimic the behavior of the standard API endpoints above, but only interact with
test mode data.

GET /testmode  

GET /testmode/api/V2/me  

GET /testmode/api/V2/token  

GET /testmode/api/V2/users  

POST /testmode/api/legacy/KBase/Sessions/Login  

GET /testmode/api/legacy/globus  

#### Data manipulation endpoints

These endpoints allow a test harness to create and modify test mode users, tokens, and roles.
No authentication is required.

POST /testmode/api/V2/testmodeonly/user  
Create a user. Takes JSON encoded data with the keys `user` for the user name and `display` for
the user's display name.

GET /testmode/api/V2/testmodeonly/user/&lt;username&gt;  
Get a user's data.

POST /testmode/api/V2/testmodeonly/token  
Create a token. The user to which the token is assigned must exist. Takes JSON encoded data with
the keys `user` for the user name, `name` for an optional token name, and `type` for the token
type. `type` is one of `Login`, `Agent`, `Dev`, or `Serv`.

POST /testmode/api/V2/testmodeonly/customroles  
Create a custom role. Takes JSON encoded data with the keys `id` for the role id and `desc` for
the role description. Posting a role with an existing ID overwrites the description of the role.

GET /testmode/api/V2/testmodeonly/customroles  
Get the list of extant custom roles.

PUT /testmode/api/V2/testmodeonly/userroles  
Set a user's roles, overwriting any current roles. Takes JSON encoded data with the keys `user`
for the user name of the user to modify, `roles` for a list of built-in roles to grant to the
user, and `customroles` for a list of custom role ids to grant to the user. Allowed `roles` are
`DevToken`, `ServToken`, `Admin`, and `CreateAdmin`. Note that these roles don't grant
any actual privileges in test mode. Omitting `roles` and `customroles` removes all roles from
the user.

DELETE /testmode/api/V2/testmodeonly/clear  
Removes all test mode data from the system.

## Admin notes

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
* Get OrcID creds [here](https://orcid.org/content/register-client-application-0)
  * Note that only the public API has been tested with the auth server.
* In version 0.6.0, the canonicalization algorithm for user display names changed and the
  database needs to be updated.
  * See the `--recanonicalize-display-names` option for the `manage_auth` script. This can
    be run while the server is live **after** updating to version 0.6.0.
  * Once the names have been recanonicalized, the `--remove-recanonicalization-flag` can be
    used to remove flags set on database objects to avoid reprocessing if the recanonicalize
    process does not complete.

## Requirements

Java 8 (OpenJDK OK)  
Apache Ant (http://ant.apache.org/)  
MongoDB 2.6+ (https://www.mongodb.com/)  
Jetty 9.3+ (http://www.eclipse.org/jetty/download.html)
    (see jetty-config.md for version used for testing)  
This repo (git clone https://github.com/kbase/auth2)  
The jars repo (git clone https://github.com/kbase/jars)  
The two repos above need to be in the same parent folder.

## To start server

start mongodb  
if using mongo auth, create a mongo user  
cd into the auth2 repo  
`ant build`  
copy `deploy.cfg.example` to `deploy.cfg` and fill in appropriately  
`export KB_DEPLOYMENT_CONFIG=<path to deploy.cfg>`  
`cd jettybase`  
`./jettybase$ java -jar -Djetty.port=<port> <path to jetty install>/start.jar`  

## Administer the server

Set a root password:  
`./manage_auth -d <path to deploy.cfg> -r`  

Login to a local account as `***ROOT***` with the password you set. Create a
local account and assign it the create administrator role. That account can
then be used to create further administrators (including itself) without
needing to login as root. The root account can then be disabled.

## Start & stop server w/o a pid

`./jettybase$ java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar ~/jetty/jetty-distribution-9.3.11.v20160721/start.jar`  
`./jettybase$ java -DSTOP.PORT=8079 -DSTOP.KEY=foo -jar ~/jetty/jetty-distribution-9.3.11.v20160721/start.jar --stop`  

Omit the stop key to have jetty generate one for you.

## Developer notes

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
  * Update the version as per the semantic version rules in
    `src/us/kbase/auth2/service/common/ServiceCommon.java`.
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

## Ancient history

https://github.com/kbaseIncubator/auth2proto
