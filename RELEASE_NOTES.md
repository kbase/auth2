Authentication Service MKII release notes
=========================================

0.1.0
-----

* Initial release

0.1.1
-----

* the /link/choice endpoint now returns the linked identities and the account to which they are
  linked. If all identities are linked an error is not thrown.

0.1.2
-----

* The user identity is now tracked throughout the linking process to eliminate the possibility
  of another user hijacking said process. This could occur if user A starts, but does not complete,
  the linking process, and user B logs in while the link-in-process cookie has not expired.