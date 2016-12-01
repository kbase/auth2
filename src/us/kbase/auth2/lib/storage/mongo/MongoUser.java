package us.kbase.auth2.lib.storage.mongo;

import java.util.Collections;
import java.util.Date;
import java.util.Set;

import org.bson.types.ObjectId;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityWithID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

public class MongoUser extends AuthUser {

	//TODO JAVADOC
	//TODO TESTS
	
	private final MongoStorage storage;
	private Set<ObjectId> customRoles;
	private Set<String> memoizedCustomRoles = null;
	
	MongoUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final Set<RemoteIdentityWithID> identities,
			final Set<Role> roles,
			final Set<ObjectId> customRoles,
			final Date created,
			final Date lastLogin,
			final MongoStorage storage) {
		super(userName, email, displayName, identities, roles, created, lastLogin);
		this.customRoles = Collections.unmodifiableSet(customRoles);
		if (customRoles.isEmpty()) {
			memoizedCustomRoles = Collections.emptySet();
		}
		this.storage = storage;
	}

	MongoUser(final MongoUser user, final Set<RemoteIdentityWithID> newIDs) {
		super(user.getUserName(), user.getEmail(), user.getDisplayName(), newIDs, user.getRoles(),
				user.getCreated(), user.getLastLogin());
		this.customRoles = user.customRoles;
		this.memoizedCustomRoles = user.memoizedCustomRoles;
		this.storage = user.storage;
	}

	@Override
	public Set<String> getCustomRoles() throws AuthStorageException {
		if (memoizedCustomRoles == null) {
			memoizedCustomRoles = Collections.unmodifiableSet(
					storage.getCustomRoles(getUserName(), customRoles));
		}
		return memoizedCustomRoles;
	}
}
