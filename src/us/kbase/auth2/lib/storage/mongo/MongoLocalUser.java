package us.kbase.auth2.lib.storage.mongo;

import java.util.Date;
import java.util.Set;

import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

public class MongoLocalUser extends LocalUser {

	//TODO JAVADOC
	//TODO TESTS
	
	//TODO ROLES PERF always get the roles and memoize them. Keep a boolean to see if they've been checked.
	private final MongoStorage storage;
	private Set<String> memoizedCustomRoles;
	
	public MongoLocalUser(
			final UserName userName,
			final String email,
			final String fullName,
			final Set<Role> roles,
			final Date created,
			final Date lastLogin,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset,
			final MongoStorage storage) {
		super(userName, email, fullName, roles, created, lastLogin, passwordHash, salt,
				forceReset);
		this.storage = storage;
	}

	@Override
	public Set<String> getCustomRoles() throws AuthStorageException {
		if (memoizedCustomRoles == null) {
			try {
				memoizedCustomRoles = storage.getCustomRoles(getUserName());
			} catch (NoSuchUserException e) {
				throw new AuthStorageException(
						"This user apparently doesn't exist. Something is very wrong: " +
				e.getMessage(), e);
			}
		}
		return memoizedCustomRoles;
	}

}
