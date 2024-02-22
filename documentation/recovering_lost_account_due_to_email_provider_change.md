# Recovering a lost KBase account due to an email provider change

## Document purpose

This document describes the steps that were taken to restore access to a user's KBase account
after their email provider changed.

The document, firstly, will hopefully help resolve similar situations in the future, and secondly,
recommends improvements to the recovery process.

## Background

A user had a government supplied email address (e.g. like lbl.gov) that was provided by Google.
They had a KBase account linked to two identity suppliers - the first was Google, using the 
government address, and the second Globus, using the Google address:

```
          KBase
          |   \
          | Globus
          |   /
         Google
           |
         agency.gov
```

The government agency switched email suppliers away from Google, and so the user could no
longer log into Google using that email address. This meant they could no longer log into Google,
Globus, or KBase.

## Resolution

The user's ultimate email address (e.g. the *.gov address) was the same for the KBase, Google,
and Globus accounts based on examination of the user's record in the auth database, and so it
was decided to treat the address as trusted. **It is not necessarily true** that an email
address in the database can be trusted - KBase email addresses are unverified, and Globus
provides no guarantees about the email records in its database.

The user had an ORCiD that was unused in KBase and provided it to KBase personnel via the
trusted email address, thus making the ORCiD trusted.

The KBase identity ID for the user's ORCiD account was calculated via a small piece of code:

```
package us.kbase.auth2;

import us.kbase.auth2.lib.identity.RemoteIdentityID;

public class TempHelper {

	public static void main(String[] args) {
		final String identityProvider = args[0];
		final String remoteID = args[1];
		final RemoteIdentityID rid = new RemoteIdentityID(identityProvider, remoteID);
		System.out.println(rid);
		System.out.println("Kbase identity ID " + rid.getID());
	}
}
```

When run with `OrcID` and the user's OrcID as the input, the program produces:

```
RemoteIdentityID [provider=OrcID, id=<users's OrcID>]
Kbase identity ID <KBase identity ID>
```

Before making any changes to the Auth database, the user's username was verified as
correct and the user's record inspected. Then the record was updated:

```
kbrs0:PRIMARY> db.users.update(
    {user: "<KBase user name>"},
    {$addToSet: {idents: {id: "<KBase identity ID>",
                          prov: "OrcID",
                          prov_id: "<user's OrcID>",
                          uid: "<user's OrcID>",
                          fullname: "unknown",
                          email: null}}})
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 }) 
```

Note that `uid`, `fullname` and `email` are updated from the identity provider on login. After
the user logged in, the fields were updated as expected - in particular, the email address was
updated to the trusted email.

It is important to be sure that the identity record is not duplicated within with user document.
A unique index on the `idents.id` field prevents two users possessing the same identity
(assuming the ID is correctly calculated), but there is no way to prevent duplicate records in the
same array if the records are not completely identical.

After executing the update query, check the user record in MongoDB for correctness, and
query based on the `idents.prov_id` field to ensure no duplicate records. It is possible,
but improbable, that different identity providers use the same `prov_id` for an account, so
if multiple records result inspect them carefully.

There is a unique index on `user` as well as `idents.id` and so duplicating the user record
should be impossible.

## Recommendations

1. Add an option to the Auth command line tool to add identities to users to avoid incorrect DB
   updates. The CLI could, when possible, query the identity provider to ensure the information
   provided on the command line is correct or pull additional information from the provider.
2. Develop procedures for verifying a user's possession of an account and transferring
   trusted information needed to restore access to an account.
3. Develop and deploy user documentation recommending that users always have at least one
   personal account entirely under their control linked to their KBase account.
4. Similarly, encourage users to have more than one account linked to their KBase account so that
   if they lose access to one account they can log in via the other.
5. Consider account recovery in general. Currently, KBase outsources account handling, and
   therefore account recovery, to third parties (e.g. Google, Globus, OrcID). This is because
   these 3rd parties will always be much better at account security and recovery than KBase will
   be, and user accounts are not a differentiating feature for KBase. However, if users lose
   access to their linked accounts and 3rd party account recovery fails, as in this case,
   we need a plan to respond. This includes verification of ownership of the account,
   verification of ownership of a new account to be linked, and linking the new account, at a
   minimum.
6. Consider implementing account recovery tokens (e.g. similar to GitHub and other sites) that
   allow linking a new identity to an account without logging into the account. This
   needs careful thought and design as leaking tokens would mean an account could be entirely
   hijacked.

See https://www.twilio.com/blog/best-practices-multi-factor-authentication-mfa-account-recovery
for more information around account recovery.

## Appendix: Linking Google and Globus accounts manually

In the case presented here, the user had an unused OrcID account, and since the OrcID unique ID
used by the Auth service to link the user's account to the OrcID account is public, it was
simple to obtain the unique ID. Google and Globus are not so simple.

In the case of Google, to the knowledge of the author, the unique numeric user ID is not available
without the user's token, although the author has not searched extensively. Assuming this is the
case, the user would need to be directed to some sort of website where they could ascertain their
ID and provide it to KBase in some trusted manner.

In the case of Globus, the [Identities API](https://docs.globus.org/api/auth/reference/#identities_api)
may be used to obtain the unique ID for a user. A globus token (any will do) was obtained by
logging into the globus website and copying the bearer token from browser local storage.

Unique Globus IDs can then be determined as shown:

```
~$ ipython
Python 3.6.9 (default, Apr 18 2020, 01:56:04) 
Type 'copyright', 'credits' or 'license' for more information
IPython 7.4.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: import requests                                                         

In [2]: with open('/home/<user>/.globus_token_helpdesk') as f: 
   ...:     globus_token = f.read().strip() 
   ...:                                                                         

In [5]: r = requests.get('https://auth.globus.org/v2/api/identities?usernames=ga
   ...: price@globus.org', headers={'authorization': 'Bearer ' + globus_token}) 

In [6]: r.json()                                                                
Out[6]: 
{'identities': [{'status': 'unused',
   'username': 'gaprice@globus.org',
   'email': None,
   'name': None,
   'id': '<Globus unique ID>',
   'identity_provider': '927d7238-f917-4eb2-9ace-c523fa9ba34e',
   'organization': None}]}
```

Note that usernames at globus may be complex depending on the number of intermediate providers,
e.g. `gaprice@lbl.gov@accounts.google.com`.

Further note that when starting the login flow at KBase, if the user is not already logged in
to Globus, only GlobusID accounts are available for login (which should be changed, in the
author's opinion).
