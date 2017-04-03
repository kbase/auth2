package us.kbase.auth2.lib.user;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;

/** A local user.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class LocalUser extends AuthUser {
	
	private final boolean forceReset;
	private final Optional<Instant> lastReset;
	
	private LocalUser(
			final UserName userName,
			final DisplayName displayName,
			final Instant created,
			final EmailAddress email,
			final Set<Role> roles,
			final Set<String> customRoles,
			final Map<PolicyID, Instant> policyIDs,
			final Optional<Instant> lastLogin,
			final UserDisabledState disabledState,
			final boolean forceReset,
			final Optional<Instant> lastReset) {
		super(userName, displayName, created, Collections.emptySet(), email, roles, customRoles,
				policyIDs, lastLogin, disabledState);
		this.forceReset = forceReset;
		this.lastReset = lastReset;
	}

	/** Check if a password reset is required on next login.
	 * @return true if a reset is required, or false otherwise.
	 */
	public boolean isPwdResetRequired() {
		return forceReset;
	}
	
	/** The date of the last password reset.
	 * @return the last password reset date or null if the password has never been reset.
	 */
	public Optional<Instant> getLastPwdReset() {
		return lastReset;
	}

	@Override
	public final int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + (forceReset ? 1231 : 1237);
		result = prime * result + ((lastReset == null) ? 0 : lastReset.hashCode());
		return result;
	}

	@Override
	public final boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		LocalUser other = (LocalUser) obj;
		if (forceReset != other.forceReset) {
			return false;
		}
		if (lastReset == null) {
			if (other.lastReset != null) {
				return false;
			}
		} else if (!lastReset.equals(other.lastReset)) {
			return false;
		}
		return true;
	}
	
	/** Get a builder for a local user.
	 * 
	 * Note that the password hash and salt arrays are not copied when building, so any changes
	 * to those arrays will be reflected in the user class. This can be useful for clearing the
	 * array data when no longer needed.
	 * 
	 * @param userName the users's user name.
	 * @param displayName the user's display name.
	 * @param creationDate the user's creation date.
	 * @param passwordHash the hash of the user's password.
	 * @param salt the salt used to hash the password.
	 * @return a builder.
	 */
	public static Builder getLocalUserBuilder(
			final UserName userName,
			final DisplayName displayName,
			final Instant creationDate) {
		return new Builder(userName, displayName, creationDate);
		
	}
	
	/** A LocalUser builder.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder extends AbstractBuilder<Builder> {
		
		private boolean forceReset = false;
		private Optional<Instant> lastReset = Optional.absent();

		private Builder(
				final UserName userName,
				final DisplayName displayName,
				final Instant creationDate) {
			super(userName, displayName, creationDate);
		}

		@Override
		Builder getThis() {
			return this;
		}
		
		/** Mark that that user is required to reset their password on the next login.
		 * @param forceReset true for the user to reset their password.
		 * @return this builder.
		 */
		public Builder withForceReset(final boolean forceReset) {
			this.forceReset = forceReset;
			return this;
		}
		
		/** Set the time of the user's last password reset.
		 * @param lastReset the last time the user reset their password.
		 * @return this builder.
		 */
		public Builder withLastReset(final Instant lastReset) {
			nonNull(lastReset, "lastReset");
			this.lastReset = Optional.of(lastReset);
			return this;
		}
		
		/** Build the user.
		 * @return the user.
		 */
		public LocalUser build() {
			return new LocalUser(userName, displayName, created, email, roles, customRoles,
					policyIDs, lastLogin, disabledState, forceReset, lastReset);
		}
		
	}
}
