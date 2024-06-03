# Authentication Service MKII release notes

## 0.7.2

* Fixed a bug where usernames with underscores would not be matched in username searches if an
  underscore was an interior character of a search prefix.
* Fixed a bug where a MongoDB error would be thrown if a user search prefix resulted in no search
  terms if it had no valid characters for the requested search, whether user name or display
  name. Now a service error is thrown.

## 0.7.1

* Publishes a shadow jar on jitpack.io for supporting tests in other repos.

## 0.7.0

* BACKWARDS INCOMPATIBILITY - the auth server now logs to stdout vs. syslog.
* The the `fatTestJar` Gradle task has been replaced with the `shadowJar` task, which builds
  a shadowed version of the test fat jar.

## 0.6.1

* Gradle has replaced Ant as the build tool. As a consequence, all the built artifacts
  are now located in the `build` directory, including the `manage_auth` script.
* The MongoDB clients have been updated to the most recent version and the service tested
  against Mongo 7.
* Added the ``mongo-retrywrites`` configuration setting in ``deploy.cfg``, defaulting to
  ``false``.
* The docker-compose file has been updated to start an auth server in test mode.

## 0.6.0

* ADMIN ACTION REQUIRED - after the server is upgraded, use the `manage_auth` script to
  recanonicalize the user display names. See the [README.md](./README.md#admin-notes) file.
* ADMIN OPTIONAL ACTION - on first startup, the service will build a sparse index on the `anonid`
  field in the `users` collection. If there are many users this could take some time. The
  index could be built in the background while the server is running to reduce or avoid
  downtime by starting the new version of the service pointed at the same database or manually
  creating the index in the MongoDB shell.
* User anonymous IDs have been added and are visible in the various endpoints that return
  user information.
* The `/api/V2/admin/anonids` endpoint has been added to translate anonymous IDs to user names.
* The user search API endpoint has been improved to allow for multiple tokens (e.g. "Dave Smith")
  in the search prefix. The prefix will be tokenized prior to search.

## 0.5.0

* BACKWARDS INCOMPATIBILITY - any in flight login or link flows will fail after the server is
  upgraded to 0.5.0.
* ADMIN ACTION REQUIRED - before starting the upgraded server, remove all data from the `tempdata`
  collection to avoid server errors for in flight login or link flows.
* Added PKCE to the login and link OAuth2 flows for Google and Globus.
  * See https://www.oauth.com/oauth2-servers/pkce/ for details.
  * OrcID currently does not support PKCE, see https://github.com/ORCID/ORCID-Source/issues/5977
* The OAuth2 state value is now stored in the database rather than in a cookie.

## 0.4.3

* Added the ability for the test auth controller to authenticate to MongoDB.

## 0.4.2

* Fixed a bug decoding Google JWT tokens, which could very rarely prevent users from
  logging in.

## 0.4.1

* Added a `/testmode` endpoint that mimics the standard root endpoint.
* The service is now tested against OpenJDK 8 and 11.
  * Note that the compiler compliance level must still be set at 1.8. The server fails to
    start if the compliance level is 11, likely due to out of date jars, including, possibly,
    jersey repackaged asm jars.

## 0.4.0

* CONFIGURATION CHANGE - the `identity-provider-Google-custom-people-api-host`
  configuration key has been removed. (see below).
* The Google People API does not return the email address for a small subset of users for,
  at this time, unknown reasons. The Google Identity Provider has been altered to extract
  user information (the Google unique user ID, the user display name, and the user email address /
  user name) from the JWT provided at the end of the OAuth2 login flow rather than using the
  People API.

## 0.3.0

* CONFIGURATION CHANGE - the `identity-provider-Google-custom-people-api-host`
  configuration key is now required for the Google identity provider (see below).
* The Google identity provider has been updated to no longer use the soon to be removed
  Google+ People API, and now uses the stand alone People API. This requires two changes on 
  update: 1) The configuration key noted above must be set in the `deploy.cfg` file. The
  `deploy.cfg.example` file has an example setting. 2) The People API must be enabled
  for the project corresponding to the Google client ID and client secret.

## 0.2.8

* Added a customizable config block to the deployment template.

## 0.2.7

* Update the MongoDB client to 3.8.2 to fix https://jira.mongodb.org/browse/JAVA-2383.

## 0.2.6

* CONFIGURATION CHANGE - there is a new required `deploy.cfg` parameter, `environment-header`
  (see below).
* The service can now support multiple alternate environments with different redirect urls
  along with the default environment.
  When starting a login or link flow, a custom header or an `environment` form parameter can
  be sent to the endpoint to specify the environment to use for the flow. The header takes
  precedence over the form parameter and is specified in the `deploy.cfg` file.
  Environments are configured in the `deploy.cfg` file - see `deploy.cfg.example` for an
  example. Each identity provider will need to specify login and link redirect urls for each
  environment. Additionally, in the `/admin/config/` configuration endpoint, optional redirect
  URLs equivalent to the default environment redirect urls can be configured.

## 0.2.5

* OrcID is now supported as an identity provider. See `deploy.cfg.example` for a
  configuration example.

## 0.2.4

* CONFIGURATION CHANGE - the templates directory is now configurable. Add
  `template-dir = templates` to any existing configuration files to preserve current
  behavior. The purpose of this change is primarily to allow other applications to
  test the server with the templates in a non-standard location.

## 0.2.3

* Add an endpoint for getting user display names in test mode.

## 0.2.2

* Add helpers for running the auth service in a separate java process during tests.

## 0.2.1

* As the Globus Nexus endpoint has been retired, the Globus user import functionality no longer
  works and has been removed.
* Added dockerfile that is compatible with automated docker build practices. A successful
  TravisCI build pushes the docker image to dockerhub.
* Added test mode (see documentation).

## 0.2.0

* BACKWARDS INCOMPATIBILITY: after upgrading to 0.2.0, all login and link in process tokens will
  be invalid. Users will need to restart the login or linking processes.
* The `temptokens` MongoDB collection is no longer used and may be deleted.
* The user identity is now tracked throughout the linking process to reduce the possibility
  of another user hijacking said process. This could occur if user A starts, but does not complete,
  the linking process, and user B logs in while the link-in-process cookie has not expired.
* Temporary tokens are scoped to one of three operation stages: link start, link complete,
  and login. Attempting to use a temporary token in an inappropriate scope will throw an error.
* Link and login temporary tokens are now session tokens so that they're removed on browser exit.
  The tokens still expire normally server side.
* the `POST /logout` endpoint now returns JSON if requested and also deletes any temporary link
  tokens associated with the user from the database. Any temporary link or temporary login
  cookies are removed. If JSON is requested, the login cookie is not removed, unlike with an
  HTML response.
  
## 0.1.1

* the `/link/choice` endpoint now returns the linked identities and the account to which they are
  linked. If all identities are linked an error is not thrown.

## 0.1.0

* Initial release
