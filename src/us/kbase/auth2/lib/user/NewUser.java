package us.kbase.auth2.lib.user;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

/** A new, non-local user. E.g. the user is associated with exactly one 3rd party identity.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class NewUser extends AuthUser {
	
	/** Create a new user.
	 * @param userName the name of the user.
	 * @param displayName the display name of the user.
	 * @param created the date the user was created.
	 * @param remoteIdentity the 3rd party identity associated with this user.
	 * @param email the email address of the user.
	 * @param policyIDs the policy IDs associated with this user.
	 * @param lastLogin the date of the user's last login. If this time is before the created
	 * date (e.g. the time this constructor is called) it will be silently modified to match
	 * the creation date.
	 */
	private NewUser(
			final UserName userName,
			final DisplayName displayName,
			final Instant created,
			final RemoteIdentityWithLocalID remoteIdentity,
			final EmailAddress email,
			final Set<Role> roles,
			final Set<String> customRoles,
			final Set<PolicyID> policyIDs,
			final Optional<Instant> lastLogin,
			final UserDisabledState disabledState) {
		super(userName, displayName, created, new HashSet<>(Arrays.asList(remoteIdentity)), email,
				roles, customRoles, policyIDs, lastLogin, disabledState);
	}

	/** Get the user's remote identity.
	 * @return the identity.
	 */
	public RemoteIdentityWithLocalID getIdentity() {
		if (getIdentities().size() != 1) {
			// this is untestable without some nutty reflection stuff, look into it later
			// should never happen since AuthUser is immutable
			throw new IllegalStateException("new user must have exactly one identity");
		}
		return getIdentities().iterator().next();
	}
	
	/** Get a builder for a new standard user.
	 * @param userName the user's user name.
	 * @param displayName the user's display name.
	 * @param created the user's creation date.
	 * @param remoteIdentity the remote identity associated with the user.
	 * @return a builder.
	 */
	public static Builder getBuilder(
			final UserName userName,
			final DisplayName displayName,
			final Instant created,
			final RemoteIdentityWithLocalID remoteIdentity) {
		return new Builder(userName, displayName, created, remoteIdentity);
	}
	
	/** A NewUser builder.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder extends AbstractBuilder<Builder> {

		private final RemoteIdentityWithLocalID remoteIdentity;
		
		private Builder(
				final UserName userName,
				final DisplayName displayName,
				final Instant created,
				final RemoteIdentityWithLocalID remoteIdentity) {
			super(userName, displayName, created);
			if (UserName.ROOT.equals(userName)) {
				throw new IllegalArgumentException("Standard users cannot be root");
			}
			nonNull(remoteIdentity, "remoteIdentity");
			this.remoteIdentity = remoteIdentity;
		}
		
		Builder getThis() {
			return this;
		}
		
		/** Build the user.
		 * @return the user.
		 */
		public NewUser build() {
			return new NewUser(userName, displayName, created, remoteIdentity, email, roles,
					customRoles, policyIDs, lastLogin, disabledState);
		}
		
	}
	
}
