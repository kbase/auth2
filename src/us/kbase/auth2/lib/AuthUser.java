package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityWithID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

public abstract class AuthUser {

	//TODO TEST unit test
	//TODO JAVADOC
	
	//a local auth user can never have identities, a regular auth user must
	// have at least one
	private final String fullName;
	private final String email;
	private final UserName userName;
	private final Set<Role> roles;
	private final Set<RemoteIdentityWithID> identities;
	private final Date created;
	private final Date lastLogin;
	
	public AuthUser(
			final UserName userName,
			final String email,
			final String fullName,
			Set<RemoteIdentityWithID> identities,
			Set<Role> roles,
			final Date created,
			final Date lastLogin) {
		super();
		//TODO INPUT check for nulls & empty strings - should email & fullName be allowed as null or empty strings?
		this.fullName = fullName;
		this.email = email;
		this.userName = userName;
		if (identities == null) {
			identities = new HashSet<>();
		}
		this.identities = Collections.unmodifiableSet(identities);
		if (roles == null) {
			roles = new HashSet<>();
		}
		this.roles = Collections.unmodifiableSet(roles);
		this.created = created;
		this.lastLogin = lastLogin;
	}

	public boolean isRoot() {
		return userName.isRoot();
	}
	
	public String getFullName() {
		return fullName;
	}

	public String getEmail() {
		return email;
	}

	public UserName getUserName() {
		return userName;
	}

	public boolean isLocal() {
		return identities.isEmpty();
	}

	public Set<Role> getRoles() {
		return roles;
	}

	public abstract Set<String> getCustomRoles() throws AuthStorageException;
	
	public Set<RemoteIdentityWithID> getIdentities() {
		return identities;
	}
	
	public Date getCreated() {
		return created;
	}

	public Date getLastLogin() {
		return lastLogin;
	}

	public RemoteIdentityWithID getIdentity(final RemoteIdentity ri) {
		for (final RemoteIdentityWithID rid: identities) {
			if (rid.getRemoteID().equals(ri.getRemoteID())) {
				return rid;
			}
		}
		return null;
	}
}
