package us.kbase.auth2.lib;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

public class NewUser extends AuthUser {
	
	//TODO JAVADOC
	//TODO TESTS

	public NewUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final RemoteIdentityWithLocalID remoteIdentity,
			final Date created,
			final Date lastLogin) {
		super(userName, email, displayName, new HashSet<>(Arrays.asList(remoteIdentity)),
				Collections.emptySet(), created, lastLogin, new UserDisabledState());
		if (remoteIdentity == null) {
			throw new NullPointerException("remoteIdentity");
		}
	}

	@Override
	public Set<String> getCustomRoles() {
		return Collections.emptySet();
	}

}
