# Auth2 Anonymous tokens

## Problem statement

Currently KBase users must log into KBase in order to view a narrative or download (DL) data from
a narrative. We wish for users that are not logged in to be able view narratives and possibly
download data.

## Background

* When a Narrative docker container is spun up for a user, the narrative launcher expects a KBase
  auth token and assigns the container to the user.
* JSON workspace object DLs go through the Data Import Export (DIE) server, which appears
  to handle anonymous requests correctly based on examination of the code (would need to be
  tested).
* Other DLs go through the Narrative Job Server (NJS), which requires a token - and all KBase
  Software Development Kit (SDK) apps require a token - to create the DL package in Shock.
  * DIE is responsible for DLing the package from Shock for the user in the case of
    non-staging area DLs
      * DIE appears to handle anonymous DLs correctly based on examination of the
        code (would need testing).
      * HOWEVER, the Shock node would need to be publicly readable, and no DL apps
        make that change (because they all expect a token).

## Document purpose

Propose a preliminary design for KBase auth service support of anonymous tokens (ATs)
that allow anonymous users to have a transient identity when interacting with KBase. Discuss how
those tokens would interact with the rest of the KBase infrastructure and what changes would be
necessary.

## Anonymous tokens

* The KBase auth service would be enhanced to offer AT support.
* ATs would have the same fields as regular tokens except that the the `type` would
  always be `Anonymous`.
* ATs would have a random user name assigned upon creation.
  * Could be a concatenated dictionary style name for mnemonic purposes
    (e.g. [https://gfycat.com/shoddydismalamoeba](https://gfycat.com/shoddydismalamoeba)).
      * Need to check collision frequency.
* ATs would exist in a separate token and user namespace from standard tokens.
* ATs could not be used to create other tokens.
* ATs would be prefixed with a string to indicate they are anonymous
  (e.g. `***ANONYMOUS***-[remainder of token goes here]`)
* ATs would be created, introspected, and revoked with separate APIs from normal tokens.
  * Token creation requires no authentication.
  * Test mode would support creation and introspection (token revocation is not supported in
    general via test mode and hasn't been needed so far)
* The administration UI would have AT and user lookup functionality and the ability
  to revoke said tokens.
* The administration UI would have the ability to set the lifetime of ATs. The default lifetime
  could be fairly long since ATs grant few privileges.
* All endpoints except for the AT specific endpoints would respond with an error when
  presented with an AT.
  
## Interactions with KBase infrastructure

* Most KBase core services (including data services) should never see an an AT.
* Narrative / UI:
  * When a user without a KBase cookie in the browser loads the KBase UI, an AT would
    be generated and stored in a cookie (potentially the same cookie).
    * A captcha must be used to ensure we're not spinning up containers for bots.
      * This may or may not require backend support depending on the captcha
        implementation.
  * Starting a narrative would assign the docker container to the username in the AT.
    * Narratives started in this manner would always be read-only to the user and must
      be public.
    * The Narrative backend would not pass the AT on to any services.
  * The UI should show that the user is in anonymous mode, their transient username, and allow
    them to log in normally.
* Downloads (if implemented - not implementing does not change the auth design)
  * All the requirements for the Narrative above are also requirements here, except that the
    Narrative would now pass ATs on to the NJS and Staging service.
  * Note that DLs are significantly more work but are orthogonal to the Narrative work.
  * JSON DLs should work as is as long as the front end does not pass the AT to DIE.
  * Other downloads
    * The NJS would need to understand ATs (to allow for job
      tracking purposes) and have the ability to start jobs with an AT.
      * The NJS or catalog could have a list of apps that may be started with an AT - these
        would presumably be DL apps only.
    * DL apps would have to support running with an AT.
      * Non staging service DL apps would have to be retired, as Shock does not
        allow saving anonymous data -OR -
      * Non-staging service DL apps would have to have a service token with which
        they could create Shock nodes and make them public for anonymous download.
      * Staging service DL apps would have to run with an AT and place
        anonymous data in the correct area.
    * The DIE should work normally for non-staging area DLs as long as the front
      end does not pass the AT to DIE.
    * Alternatively, non-staging area DLs could be deprecated and removed.
      * In this case, the DIE functionality for DLing JSON could probably be
        moved into a different service (NarrativeService?) and DIE retired.
    * The Staging service would need to understand ATs and place folders
      for anonymous users in a separate namespace.
      * The Staging service should not allow anonymous uploads.
    * Note that all of these changes could be made and deployed piecemeal.

## Resourcing

* Resourcing estimate is only for the auth service changes.
* Estimated effort is ~1 week for a developer familiar with the auth codebase.
  * Requires a lot of testing to ensure ATs don't interact negatively with the
    rest of the service.

## Side Nodes

* It is really weird that staging area downloads wind up as narrative cells. That seems to
  just clutter up the Narrative and interrupt the flow of the scientific narrative.
* If we're allowing anyone to spin up Narrative containers, it may be worthwhile to support an
  IP blacklist. This could be implemented at the NGINX level, the auth level, or the auth
  function level (e.g. anonymous token production), depending on performance issues or blacklist
  needs.