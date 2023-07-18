package us.kbase.auth2.lib.user;

import static java.util.Objects.requireNonNull;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;

/** A user in the authentication system.
 * 
 * There are two types of user: local users and standard users. Local users' accounts are managed
 * locally and are not associated with 3rd party identity providers. Standard users' accounts
 * are always associated with at least one 3rd party identity.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class AuthUser {

	private final DisplayName displayName;
	private final EmailAddress email;
	private final UserName userName;
	// TODO ANONID show in admin UI (endpoint?)
	// TODO ANONID add admin method to translate anon IDs to IDs
	// TODO ANONID release notes
	private final UUID anonymousID;
	private final Set<Role> roles;
	private final Set<Role> canGrantRoles;
	private final Set<String> customRoles;
	private final Set<RemoteIdentity> identities;
	private final Map<PolicyID, Instant> policyIDs;
	private final Instant created;
	private final Optional<Instant> lastLogin;
	private final UserDisabledState disabledState;
	
	AuthUser(
			final UserName userName,
			final UUID anonymousID,
			final DisplayName displayName,
			final Instant created,
			final Set<RemoteIdentity> identities,
			final EmailAddress email,
			final Set<Role> roles,
			final Set<String> customRoles,
			final Map<PolicyID, Instant> policyIDs,
			final Optional<Instant> lastLogin,
			final UserDisabledState disabledState) {
		this.userName = userName;
		this.anonymousID = anonymousID;
		this.email = email;
		this.displayName = displayName;
		this.identities = Collections.unmodifiableSet(identities);
		this.roles = Collections.unmodifiableSet(roles);
		this.customRoles = Collections.unmodifiableSet(customRoles);
		this.policyIDs = Collections.unmodifiableMap(policyIDs);
		this.canGrantRoles = Collections.unmodifiableSet(getRoles().stream()
				.flatMap(r -> r.canGrant().stream()).collect(Collectors.toSet()));
		this.created = created;
		this.lastLogin = lastLogin;
		this.disabledState = disabledState;
	}
	
	/** Returns whether this user is the root user.
	 * @return true if the the user is the root user, false otherwise.
	 */
	public boolean isRoot() {
		return userName.isRoot();
	}
	
	/** Returns the users's display name.
	 * @return the display name.
	 */
	public DisplayName getDisplayName() {
		return displayName;
	}

	/** Returns the user's email address.
	 * @return the email address.
	 */
	public EmailAddress getEmail() {
		return email;
	}

	/** Returns the user's user name.
	 * @return the user name.
	 */
	public UserName getUserName() {
		return userName;
	}
	
	/** Returns the anonymized ID for the user.
	 * @return the anonymous ID.
	 */
	public UUID getAnonymousID() {
		return anonymousID;
	}

	/** Returns whether this user is a local user.
	 * @return whether this user is a local user.
	 */
	public boolean isLocal() {
		return identities.isEmpty();
	}

	/** Returns this user's roles.
	 * @return this user's roles.
	 */
	public Set<Role> getRoles() {
		return roles;
	}
	
	/** Returns the roles this user is authorized to grant to other users.
	 * @return roles this user can grant.
	 */
	public Set<Role> getGrantableRoles() {
		return canGrantRoles;
	}

	/** Returns whether the user has a role.
	 * @param role the role to check.
	 * @return true if the user has the role, false otherwise.
	 */
	public boolean hasRole(final Role role) {
		return roles.contains(role);
	}

	/** Get the user's custom roles.
	 * @return the users's custom roles.
	 */
	public Set<String> getCustomRoles() {
		return customRoles;
	}
	
	/** Get the 3rd party identities associated with this user.
	 * @return the user's remote identities.
	 */
	public Set<RemoteIdentity> getIdentities() {
		return identities;
	}
	
	/** Get the set of policyIDs associated with this user.
	 * @return the policy IDs mapped to the time the user agreed to the policy.
	 */
	public Map<PolicyID, Instant> getPolicyIDs() {
		return policyIDs;
	}
	
	/** Get this user's creation date.
	 * @return the creation date.
	 */
	public Instant getCreated() {
		return created;
	}

	/** Get the date of the last login for this user.
	 * @return the last login date, or null if the user has never logged in.
	 */
	public Optional<Instant> getLastLogin() {
		return lastLogin;
	}
	
	/** Returns true if the account for this user is disabled.
	 * @return true if the user account is disabled, false otherwise.
	 */
	public boolean isDisabled() {
		return disabledState.isDisabled();
	}
	
	/** Get the reason the account for this user was disabled.
	 * @return the reason the user account was disabled, or absent if the account is not disabled.
	 */
	public Optional<String> getReasonForDisabled() {
		return disabledState.getDisabledReason();
	}
	
	/** Get the user name of the administrator that enabled or disabled the user account.
	 * @return the administrator that disabled or enabled the account, or absent if the account has
	 * never been disabled.
	 */
	public Optional<UserName> getAdminThatToggledEnabledState() {
		return disabledState.getByAdmin();
	}
	
	/** Get the date of the last time the user account was disabled or enabled.
	 * @return the date of the laste time the user account was disabled or enabled, or absent if
	 * the account has never been disabled.
	 */
	public Optional<Instant> getEnableToggleDate() {
		return disabledState.getTime();
	}
	
	/** Get the user account disabled state.
	 * @return the disabled state.
	 */
	public UserDisabledState getDisabledState() {
		return disabledState;
	}

	/** Get a remote identity associated with this user given a remote identity. The remote
	 * identities are matched based on the identity provider name and account ID. Thus, the two
	 * identities may differ on identity details (e.g. user name, email, and display name).
	 * @param ri the remote identity to match against an identity associated with this user.
	 * @return the matching identity or null if no identities match.
	 */
	public RemoteIdentity getIdentity(final RemoteIdentity ri) {
		for (final RemoteIdentity rid: identities) {
			if (rid.getRemoteID().equals(ri.getRemoteID())) {
				return rid;
			}
		}
		return null;
	}

	@Override
	public int hashCode() {
		return Objects.hash(anonymousID, created, customRoles, disabledState,
				displayName, email, identities, lastLogin, policyIDs, roles, userName);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AuthUser other = (AuthUser) obj;
		return Objects.equals(anonymousID, other.anonymousID)
				&& Objects.equals(created, other.created)
				&& Objects.equals(customRoles, other.customRoles)
				&& Objects.equals(disabledState, other.disabledState)
				&& Objects.equals(displayName, other.displayName)
				&& Objects.equals(email, other.email)
				&& Objects.equals(identities, other.identities)
				&& Objects.equals(lastLogin, other.lastLogin)
				&& Objects.equals(policyIDs, other.policyIDs)
				&& Objects.equals(roles, other.roles)
				&& Objects.equals(userName, other.userName);
	}
	
	/** Get a builder for an AuthUser. This builder can be used to build either local users
	 * or standard users, but the local users will not include password related information.
	 * @param userName the user's user name.
	 * @param anonymousID the user's anonymized ID. The calling code is responsible for ensuring
	 * these IDs are unique per user.
	 * @param displayName the users's display name.
	 * @param creationDate the user's creation date.
	 * @return a builder.
	 */
	public static Builder getBuilder(
			final UserName userName,
			final UUID anonymousID,
			final DisplayName displayName,
			final Instant creationDate) {
		return new Builder(userName, anonymousID, displayName, creationDate);
	}
	
	/** Get a builder for an AuthUser based on a previous AuthUser, but without the latter's
	 * remote identities. This builder can be used to build either local users
	 * or standard users, but the local users will not include password related information.
	 * @param user the user with which to populate the builder.
	 * @return a builder.
	 */
	public static Builder getBuilderWithoutIdentities(final AuthUser user) {
		final Builder b = getBuilder(
						user.getUserName(),
						user.getAnonymousID(),
						user.getDisplayName(),
						user.getCreated())
				.withUserDisabledState(user.getDisabledState())
				.withEmailAddress(user.getEmail());
		if (user.getLastLogin().isPresent()) {
			b.withLastLogin(user.getLastLogin().get());
		}
		for (final Role r: user.getRoles()) {
			b.withRole(r);
		}
		for (final String cr: user.getCustomRoles()) {
			b.withCustomRole(cr);
		}
		for (final Entry<PolicyID, Instant> pid: user.getPolicyIDs().entrySet()) {
			b.withPolicyID(pid.getKey(), pid.getValue());
		}
		return b;
	}
	
	/** An AuthUser builder. This builder can be used to build either local users
	 * or standard users, but the local users will not include password related information.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder extends AbstractBuilder<Builder> {
		
		private final Set<RemoteIdentity> identities = new HashSet<>();
		
		private Builder(
				final UserName userName,
				final UUID anonymousID,
				final DisplayName displayName,
				final Instant creationDate) {
			super(userName, anonymousID, displayName, creationDate);
		}
		
		@Override
		Builder getThis() {
			return this;
		}
		
		/** Add a remote identity to the user.
		 * @param remoteIdentity a remote identity.
		 * @return this builder.
		 */
		public Builder withIdentity(final RemoteIdentity remoteIdentity) {
			if (userName.equals(UserName.ROOT)) {
				throw new IllegalStateException("Root user cannot have identities");
			}
			requireNonNull(remoteIdentity, "remoteIdentity");
			identities.add(remoteIdentity);
			return this;
		}
		
		/** Build the user.
		 * @return the user.
		 */
		public AuthUser build() {
			return new AuthUser(userName, anonymousID, displayName, created, identities, email,
					roles, customRoles, policyIDs, lastLogin, disabledState);
		}
	}
	
	/** A superclass for user builders. This class only implements methods to add values common to
	 *  all users.
	 * @author gaprice@lbl.gov
	 *
	 * @param <T> the type of the builder extending this AbstractBuilder.
	 */
	public abstract static class AbstractBuilder<T extends AbstractBuilder<T>> {
		
		final UserName userName;
		final UUID anonymousID;
		final DisplayName displayName;
		final Instant created;
		EmailAddress email = EmailAddress.UNKNOWN;
		final Set<Role> roles = new TreeSet<>();
		final Set<String> customRoles = new TreeSet<>();
		final Map<PolicyID, Instant> policyIDs = new TreeMap<>();
		Optional<Instant> lastLogin = Optional.empty();
		UserDisabledState disabledState = new UserDisabledState();
		
		AbstractBuilder(
				final UserName userName,
				final UUID anonymousID,
				final DisplayName displayName,
				final Instant created) {
			this.userName = requireNonNull(userName, "userName");
			this.anonymousID = requireNonNull(anonymousID, "anonymousID");
			this.displayName = requireNonNull(displayName, "displayName");
			this.created = requireNonNull(created, "created");
			if (userName.equals(UserName.ROOT)) {
				roles.add(Role.ROOT);
			}
		}
		
		abstract T getThis();
		
		/** Add an email address to the user. Defaults to an unknown email address.
		 * @param email the email address.
		 * @return this builder.
		 */
		public T withEmailAddress(final EmailAddress email) {
			requireNonNull(email, "email");
			this.email = email;
			return getThis();
		}
		
		/** Add a role to the user.
		 * 
		 * Note that only the root user (signified by the root user name) can possess the ROOT
		 * role, and the root user can possess no other roles. 
		 * @param role the role.
		 * @return this builder.
		 */
		public T withRole(final Role role) {
			requireNonNull(role, "role");
			if (UserName.ROOT.equals(userName) && !Role.ROOT.equals(role)) {
				throw new IllegalStateException("Root username must only have the ROOT role");
			}
			if (Role.ROOT.equals(role) && !UserName.ROOT.equals(userName)) {
				throw new IllegalStateException("Non-root username with root role");
			}
			roles.add(role);
			return getThis();
		}
		
		/** Add a custom role to the user.
		 * @param customRole the custom role.
		 * @return this class.
		 */
		public T withCustomRole(final String customRole) {
			requireNonNull(customRole, "customRole");
			customRoles.add(customRole);
			return getThis();
		}
		
		/** Add a policy ID to the user.
		 * @param policyID the policy ID.
		 * @param agreedOn the time at which the policy was agreed to by the user.
		 * @return this builder.
		 */
		public T withPolicyID(final PolicyID policyID, final Instant agreedOn) {
			requireNonNull(policyID, "policyID");
			requireNonNull(agreedOn, "agreedOn");
			policyIDs.put(policyID, agreedOn);
			return getThis();
		}
		
		/** Add the time of the last login to the user.
		 * @param lastLogin the last login time.
		 * @return this builder.
		 */
		public T withLastLogin(final Instant lastLogin) {
			requireNonNull(lastLogin, "lastLogin");
			if (created.isAfter(lastLogin)) {
				this.lastLogin = Optional.of(created);
			} else {
				this.lastLogin = Optional.of(lastLogin);
			}
			return getThis();
		}
		
		/** Add a disabled state indicator to the user. 
		 * @param disabledState the disabled state indicator.
		 * @return this builder.
		 */
		public T withUserDisabledState(final UserDisabledState disabledState) {
			requireNonNull(disabledState, "disabledState");
			this.disabledState = disabledState;
			return getThis();
		}
	}
}
