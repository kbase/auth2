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
	private final DisplayName displayName;
	private final EmailAddress email;
	private final UserName userName;
	private final Set<Role> roles;
	private final Set<RemoteIdentityWithID> identities;
	private final long created;
	private final Long lastLogin;
	private final UserDisabledState disabledState;
	
	public AuthUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			Set<RemoteIdentityWithID> identities,
			Set<Role> roles,
			final Date created,
			final Date lastLogin,
			final UserDisabledState disabledState) {
		super();
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		this.userName = userName;
		if (email == null) {
			throw new NullPointerException("email");
		}
		this.email = email;
		if (displayName == null) {
			throw new NullPointerException("displayName");
		}
		this.displayName = displayName;
		if (identities == null) {
			identities = new HashSet<>();
		}
		this.identities = Collections.unmodifiableSet(identities);
		if (roles == null) {
			roles = new HashSet<>();
		}
		this.roles = Collections.unmodifiableSet(roles);
		if (created == null) {
			throw new NullPointerException("created");
		}
		this.created = created.getTime(); // will throw npe
		this.lastLogin = lastLogin == null ? null : lastLogin.getTime();
		if (disabledState == null) {
			throw new NullPointerException("disabledState");
		}
		this.disabledState = disabledState;
	}

	public boolean isRoot() {
		return userName.isRoot();
	}
	
	public DisplayName getDisplayName() {
		return displayName;
	}

	public EmailAddress getEmail() {
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
		return new Date(created);
	}

	public Date getLastLogin() {
		return lastLogin == null ? null : new Date(lastLogin);
	}
	
	public boolean isDisabled() {
		return disabledState.isDisabled();
	}
	
	public String getReasonForDisabled() {
		return disabledState.getDisabledReason();
	}
	
	public UserName getAdminThatToggledEnabledState() {
		return disabledState.getByAdmin();
	}
	
	public Date getEnableToggleDate() {
		return disabledState.getTime();
	}
	
	public UserDisabledState getDisabledState() {
		return disabledState;
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
