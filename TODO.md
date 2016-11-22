Auth2 TODO list
===============

Update core services and SDK modules
------------------------------------
*Note:* not in auth team scope unless specified

Need to use updated server stubs & auth clients, use tokens for magic user
accounts and tests if any, allow setting auth service url

* Shock & Awe - Rich
* Perl auth & server stubs - Keith
* Handle service & manager - Keith
* Narrative (Login UI and Lua) - Bill R. (external to auth team)
* kb_sdk
  * Tests support token vs uid/pwd & setting auth url
  * Recompile & test all SDK modules
* NJSW
* User Profile
  * Update to get and set user name & email from and to auth service
* Service wizard
* Narrative Method Store
* Data Import Export
* Search
* Solar auth
* Bulk IO

Auth service work
-----------------
* UI (1-2 sprints w/ 1-2 FTEs per Bill & Erik)
  * Probably means altering server endpoints in concert with UI development
* 150-200 TODOs in the codebase on average
* Read through all prototype code and convert to production worthy
* A code review by Steve Chan wouldn't be a bad idea
* Tests
  * With mock services for globus and google
* Documentation
  * Code documentation
  * User documentation and education (probably need doc team help here)
  * Login & signup very different
* Admin functionality
  * Find users
  * revoke single / user's / all tokens
  * Disable account (revoke all tokens & prevent logins), record admin and reason
  * Force pwd reset for local accounts (per user and all)
  * Reset local account pwd
* API
  * Token name in config
  * Configure redirect urls for login and link intermediate steps
  * Introspect token (e.g. not the legacy apis, provide complete info)
  * /user/<name> - get user details
  * /me
* Memory based data storage
* Test mode
  * test apis for user creation & admin
  * auto configure server for ease of use
* User import
  * Need list of every username that exists in any KBase data source
    * Needs a new script
  * May need to add a call to the v2 Globus API if looking up the user in the
    Nexus API fails (occurs when user is set to private and not in kbase_users
    group)
* Deploy
  * Dockerization

### Potential work
* Support user lookup by identity provider & id for bulk upload (permitted role)

External dependencies
---------------------
* JGI updates kbase<->JGI account linking (on dev server as of 16/11/18)
* JGI stops using uid/pwd to login for jgidm account

Future work
-----------

### 3rd party developers acting on behalf of users (e.g. JGI, sequencing centers)
* OAuth2 endpoint
* -or-
* (simpler) verify user name via KBase login

### Scoped tokens
* Mainly for SDK jobs
* Scoped to read/write specific workspaces only, no other system rights
* Could be scoped for other things if necessary
