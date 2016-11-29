package us.kbase.auth2.lib.storage.mongo;

import java.util.Collections;
import java.util.Date;
import java.util.Set;

import org.bson.types.ObjectId;

import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

public class MongoLocalUser extends LocalUser {

	//TODO JAVADOC
	//TODO TESTS
	
	private final MongoStorage storage;
	private Set<ObjectId> customRoles;
	private Set<String> memoizedCustomRoles;
	
	MongoLocalUser(
			final UserName userName,
			final String email,
			final String fullName,
			final Set<Role> roles,
			final Set<ObjectId> customRoles,
			final Date created,
			final Date lastLogin,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset,
			final MongoStorage storage) {
		super(userName, email, fullName, roles, created, lastLogin, passwordHash, salt,
				forceReset);
		this.customRoles = customRoles;
		if (customRoles.isEmpty()) {
			memoizedCustomRoles = Collections.emptySet();
		}
		this.storage = storage;
	}

	@Override
	public Set<String> getCustomRoles() throws AuthStorageException {
		if (memoizedCustomRoles == null) {
			memoizedCustomRoles = storage.getCustomRoles(getUserName(), customRoles);
		}
		return memoizedCustomRoles;
	}
}
