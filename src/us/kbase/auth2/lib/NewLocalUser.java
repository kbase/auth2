package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.Date;
import java.util.Set;

public class NewLocalUser extends LocalUser {

	//TODO JAVADOC
	//TODO TESTS
	
	public NewLocalUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final Date created,
			final Date lastLogin,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset) {
		super(userName, email, displayName, Collections.emptySet(), created, lastLogin,
				null, null, null, passwordHash, salt, forceReset, null);
	}

	@Override
	public Set<String> getCustomRoles() {
		return Collections.emptySet();
	}

}
