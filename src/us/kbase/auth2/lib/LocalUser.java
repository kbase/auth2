package us.kbase.auth2.lib;

import java.util.Date;
import java.util.Set;

public class LocalUser extends AuthUser {
	
	//TODO TEST unit test
	//TODO JAVADOC
	
	private final byte[] passwordHash;
	private final byte[] salt;
	private final boolean forceReset;
	
	public LocalUser(
			final UserName userName,
			final String email,
			final String fullName,
			final Set<Role> roles,
			final Set<String> customRoles,
			final Date created,
			final Date lastLogin,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset) {
		super(userName, email, fullName, null, roles, customRoles, created,
				lastLogin);
		// what's the right # here? Have to rely on user to some extent
		if (passwordHash == null || passwordHash.length < 10) {
			throw new IllegalArgumentException(
					"passwordHash missing or too small");
		}
		if (salt == null || salt.length < 2) {
			throw new NullPointerException("salt missing or too small");
		}
		this.passwordHash = passwordHash;
		this.salt = salt;
		this.forceReset = forceReset;
	}

	public byte[] getPasswordHash() {
		return passwordHash;
	}

	public byte[] getSalt() {
		return salt;
	}

	public boolean forceReset() {
		return forceReset;
	}
}
