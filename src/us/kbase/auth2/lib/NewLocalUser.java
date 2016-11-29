package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.Date;
import java.util.Set;

public class NewLocalUser extends LocalUser {

	//TODO JAVADOC
	//TODO TESTS
	
	public NewLocalUser(
			final UserName userName,
			final String email,
			final String fullName,
			final Date created,
			final Date lastLogin,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset) {
		super(userName, email, fullName, Collections.emptySet(), created, lastLogin,
				passwordHash, salt, forceReset);
	}

	@Override
	public Set<String> getCustomRoles() {
		return Collections.emptySet();
	}

}
