package us.kbase.auth2.lib;

import java.util.Date;
import java.util.Set;

public abstract class LocalUser extends AuthUser {
	
	//TODO TEST unit test
	//TODO JAVADOC
	
	private final byte[] passwordHash;
	private final byte[] salt;
	private final boolean forceReset;
	private final Long lastReset;
	
	public LocalUser(
			final UserName userName,
			final String email,
			final String fullName,
			final Set<Role> roles,
			final Date created,
			final Date lastLogin,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset,
			final Date lastReset) {
		super(userName, email, fullName, null, roles, created, lastLogin);
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
		this.lastReset = lastReset == null ? null : lastReset.getTime();
	}

	public byte[] getPasswordHash() {
		return passwordHash;
	}

	public byte[] getSalt() {
		return salt;
	}

	public boolean isPwdResetRequired() {
		return forceReset;
	}
	
	public Date getLastPwdReset() {
		return lastReset == null ? null : new Date(lastReset);
	}
}
