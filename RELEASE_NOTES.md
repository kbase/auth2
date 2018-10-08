Authentication Service MKII release notes
=========================================

0.2.6
-----
* The service can now support multiple alternate environments with different redirect urls
  along with the default environment.
  When starting a login or link flow, an `environment` form parameter can be sent to the 
  endpoint to specify the environment to use for the flow.
  Environments are configured in the `deploy.cfg` file - see `deploy.cfg.example` for an
  example. Each identity provider will need to specify login and link redirect urls for each
  environment. Additionally, in the `/admin/config/` configuration endpoint, optional redirect
  urls equivalent to the default environment redirect urls can be configured.

0.2.5
-----
* OrcID is now supported as an identity provider. See `deploy.cfg.example` for a
  configuration example.

0.2.4
-----
* CONFIGURATION CHANGE - the templates directory is now configurable. Add
  `template-dir = templates` to any existing configuration files to preserve current
  behavior. The purpose of this change is primarily to allow other applications to
  test the server with the templates in a non-standard location.

0.2.3
-----
* Add an endpoint for getting user display names in test mode.

0.2.2
-----
* Add helpers for running the auth service in a separate java process during tests.

0.2.1
-----

* As the Globus Nexus endpoint has been retired, the Globus user import functionality no longer
  works and has been removed.
* Added dockerfile that is compatible with automated docker build practices. A successful
  TravisCI build pushes the docker image to dockerhub.
* Added test mode (see documentation).

0.2.0
-----

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
  
0.1.1
-----

* the `/link/choice` endpoint now returns the linked identities and the account to which they are
  linked. If all identities are linked an error is not thrown.

0.1.0
-----

* Initial release
