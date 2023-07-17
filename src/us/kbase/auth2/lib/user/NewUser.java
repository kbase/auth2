package us.kbase.auth2.lib.user;

import static java.util.Objects.requireNonNull;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;

/** A new, non-local user. E.g. the user is associated with exactly one 3rd party identity.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class NewUser extends AuthUser {
	
	private NewUser(
			final UserName userName,
			final UUID anonymousID,
			final DisplayName displayName,
			final Instant created,
			final RemoteIdentity remoteIdentity,
			final EmailAddress email,
			final Set<Role> roles,
			final Set<String> customRoles,
			final Map<PolicyID, Instant> policyIDs,
			final Optional<Instant> lastLogin,
			final UserDisabledState disabledState) {
		super(userName, anonymousID, displayName, created,
				new HashSet<>(Arrays.asList(remoteIdentity)), email,
				roles, customRoles, policyIDs, lastLogin, disabledState);
	}

	/** Get the user's remote identity.
	 * @return the identity.
	 */
	public RemoteIdentity getIdentity() {
		if (getIdentities().size() != 1) {
			// this is untestable without some nutty reflection stuff, look into it later
			// should never happen since AuthUser is immutable
			throw new IllegalStateException("new user must have exactly one identity");
		}
		return getIdentities().iterator().next();
	}
	
	/** Get a builder for a new standard user.
	 * @param userName the user's user name.
	 * @param anonymousID the user's anonymized ID. The calling code is responsible for ensuring
	 * these IDs are unique per user.
	 * @param displayName the user's display name.
	 * @param created the user's creation date.
	 * @param remoteIdentity the remote identity associated with the user.
	 * @return a builder.
	 */
	public static Builder getBuilder(
			final UserName userName,
			final UUID anonymousID,
			final DisplayName displayName,
			final Instant created,
			final RemoteIdentity remoteIdentity) {
		return new Builder(userName, anonymousID, displayName, created, remoteIdentity);
	}
	
	/** A NewUser builder.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder extends AbstractBuilder<Builder> {

		private final RemoteIdentity remoteIdentity;
		
		private Builder(
				final UserName userName,
				final UUID anonymousID,
				final DisplayName displayName,
				final Instant created,
				final RemoteIdentity remoteIdentity) {
			super(userName, anonymousID, displayName, created);
			if (UserName.ROOT.equals(userName)) {
				throw new IllegalArgumentException("Standard users cannot be root");
			}
			requireNonNull(remoteIdentity, "remoteIdentity");
			this.remoteIdentity = remoteIdentity;
		}
		
		Builder getThis() {
			return this;
		}
		
		/** Build the user.
		 * @return the user.
		 */
		public NewUser build() {
			return new NewUser(userName, anonymousID, displayName, created, remoteIdentity, email,
					roles, customRoles, policyIDs, lastLogin, disabledState);
		}
		
	}
	
}
