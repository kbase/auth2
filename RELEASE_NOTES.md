Authentication Service MKII release notes
=========================================

0.1.0
-----

* Initial release

0.1.1
-----

* the `/link/choice` endpoint now returns the linked identities and the account to which they are
  linked. If all identities are linked an error is not thrown.

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
  The tokens still expire after 30m server side.
* the `POST /logout` endpoint now returns JSON if requested and also deletes any temporary link
  tokens associated with the user from the database. Any temporary link or temporary login
  cookies are removed. If JSON is requested, the login cookie is not removed, unlike with an
  HTML response.

0.2.1
-----

* Added dockerfile that is compatible with automated docker build practices
* Docker image is built against alpine JRE for a smaller footprint
* Docker image uses templatized configuration files with default targetted at KBase CI env
* Successful travis build pushes docker image to dockerhub
