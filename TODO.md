Auth2 TODO list
===============

Auth service work
-----------------
* Include users's identities in admin user view
* Complete rich UI (code not in this repo)
  * Currently only covers login, link, me, and tokens.
* TODOs in the codebase
* Read through all remaining prototype code and convert to production worthy
* Code review
  * Steve Chan
* Code analysis:
  * https://www.codacy.com/
  * https://find-sec-bugs.github.io/
* Tests
  * Redo UI/API tests to move most tests to unit test from integration tests
    * Use constructor dependency injection to make UTs easy
    * Minimal integration tests
* Documentation
  * Code documentation
  * Try swagger again - go from code -> docs vs. other way around
  * Server manual, incl user and admin coverage
  * Interaction diagram for login and link flow w/ I/O, cookies, etc. noted.
* General
  * Lock local account for X m after Y failed logins - use sshguard or something here
  * Make server root return endpoints

Future work
-----------

* Memory based data storage
* More identity providers
  * Facebook
  * CiLogon (? already supported via Globus)
* Check user input for obscene or offensive content and reject, find 3rd party code (?)

### 3rd party developers acting on behalf of users (e.g. JGI, sequencing centers)
* OAuth2 endpoint
* -or-
* (simpler) verify user name via KBase login

### Scoped tokens
* Mainly for SDK jobs
* Scoped to read/write specific workspaces only, no other system rights
* Could be scoped for other things if necessary
