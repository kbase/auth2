Authentication Service MKII release notes
=========================================

0.1.0
-----

* Initial release

0.1.1
-----

* the /link/choice endpoint now returns the linked identities and the account to which they are
  linked. If all identities are linked an error is not thrown.

0.2.0
-----

* BACKWARDS INCOMPATIBILITY: after upgrading to 0.2.0, all login and link in process tokens will
  be invalid. Users will need to restart the login or linking processes.
* The temptokens MongoDB collection is no longer used and may be deleted.
* The user identity is now tracked throughout the linking process to reduce the possibility
  of another user hijacking said process. This could occur if user A starts, but does not complete,
  the linking process, and user B logs in while the link-in-process cookie has not expired.
* Temporary tokens are scoped to one of three operation stages: link start, link complete,
  and login. Attempting to use a temporary token in an inappropriate scope will throw an error.
* Login temporary tokens are now session tokens so that they're removed on browser exit. The tokens
  still expire after 30m server side.