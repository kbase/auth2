package us.kbase.test.auth2.lib;

import java.util.Date;
import java.util.Set;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

public class AuthUserSuppliedCRoles extends AuthUser {

	private final Set<String> customRoles;
	
	public AuthUserSuppliedCRoles(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final Set<RemoteIdentityWithLocalID> identities,
			final Set<Role> roles,
			final Set<String> customRoles,
			final Date created,
			final Date lastLogin,
			final UserDisabledState disabledState) {
		super(userName, email, displayName, identities, roles, created, lastLogin,
				disabledState);
		this.customRoles = customRoles;
	}

	@Override
	public Set<String> getCustomRoles() throws AuthStorageException {
		return customRoles;
	}
	
}
