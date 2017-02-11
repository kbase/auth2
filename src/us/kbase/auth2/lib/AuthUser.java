package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

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
	private final Set<Role> roles;
	private final Set<Role> canGrantRoles;
	private final Set<String> customRoles;
	private final Set<RemoteIdentityWithLocalID> identities;
	private final long created;
	private final Long lastLogin;
	private final UserDisabledState disabledState;
	
	/** Create a new user.
	 * @param userName the name of the user.
	 * @param email the email address of the user.
	 * @param displayName the display name of the user.
	 * @param identities any 3rd party identities associated with the user. Empty or null for local
	 * users.
	 * @param roles any roles the user possesses.
	 * @param customRoles any custom roles the user possesses.
	 * @param created the date the user account was created.
	 * @param lastLogin the date of the user's last login. If this time is before the created
	 * date it will be silently modified to match the creation date.
	 * @param disabledState whether the user account is disabled.
	 */
	public AuthUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			Set<RemoteIdentityWithLocalID> identities,
			Set<Role> roles,
			Set<String> customRoles,
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
		Utils.noNulls(identities, "null item in identities");
		this.identities = Collections.unmodifiableSet(new HashSet<>(identities));
		if (roles == null) {
			roles = new HashSet<>();
		}
		Utils.noNulls(roles, "null item in roles");
		this.roles = Collections.unmodifiableSet(new HashSet<>(roles));
		if (customRoles == null) {
			customRoles = new HashSet<>();
		}
		Utils.noNulls(customRoles, "null item in customRoles");
		this.customRoles = Collections.unmodifiableSet(new HashSet<>(customRoles));
		/* this is a little worrisome as there are two sources of truth for root. Maybe
		 * automatically add the role for root? Or have a root user subclass?
		 * This'll do for now
		 */
		if (userName.equals(UserName.ROOT)) {
			if (!(roles.size() == 1 && roles.contains(Role.ROOT))) {
				throw new IllegalStateException("Root username must only have the ROOT role");
			}
			if (!identities.isEmpty()) {
				throw new IllegalStateException("Root user cannot have identities");
			}
		} else if (roles.contains(Role.ROOT)) {
			throw new IllegalStateException("Non-root username with root role");
		}
		this.canGrantRoles = Collections.unmodifiableSet(getRoles().stream()
				.flatMap(r -> r.canGrant().stream()).collect(Collectors.toSet()));
		if (created == null) {
			throw new NullPointerException("created");
		}
		this.created = created.getTime(); // will throw npe
		this.lastLogin = lastLogin == null ? null :
			(lastLogin.before(created) ? created.getTime() : lastLogin.getTime());
		if (disabledState == null) {
			throw new NullPointerException("disabledState");
		}
		this.disabledState = disabledState;
	}
	
	//TODO TEST after EQUALS
	public AuthUser(final AuthUser user, final Set<RemoteIdentityWithLocalID> newIDs) {
		this(user.getUserName(), user.getEmail(), user.getDisplayName(), newIDs, user.getRoles(),
				user.getCustomRoles(), user.getCreated(), user.getLastLogin(),
				user.getDisabledState());
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
	public Set<RemoteIdentityWithLocalID> getIdentities() {
		return identities;
	}
	
	/** Get this user's creation date.
	 * @return the creation date.
	 */
	public Date getCreated() {
		return new Date(created);
	}

	/** Get the date of the last login for this user.
	 * @return the last login date, or null if the user has never logged in.
	 */
	public Date getLastLogin() {
		return lastLogin == null ? null : new Date(lastLogin);
	}
	
	/** Returns true if the account for this user is disabled.
	 * @return true if the user account is disabled, false otherwise.
	 */
	public boolean isDisabled() {
		return disabledState.isDisabled();
	}
	
	/** Get the reason the account for this user was disabled.
	 * @return the reason the user account was disabled, or null if the account is not disabled.
	 */
	public String getReasonForDisabled() {
		return disabledState.getDisabledReason();
	}
	
	/** Get the user name of the administrator that enabled or disabled the user account.
	 * @return the administrator that disabled or enabled the account, or null if the account has
	 * never been disabled.
	 */
	public UserName getAdminThatToggledEnabledState() {
		return disabledState.getByAdmin();
	}
	
	/** Get the date of the last time the user account was disabled or enabled.
	 * @return the date of the laste time the user account was disabled or enabled, or null if the
	 * account has never been disabled.
	 */
	public Date getEnableToggleDate() {
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
	 * identities may differ on identity details (e.g. user name, email, and display name) and the
	 * local UUID assigned to the remote identity (the incoming remote identity may not have a
	 * UUID).
	 * @param ri the remote identity to match against an identity associated with this user.
	 * @return the matching identity or null if no identities match.
	 */
	public RemoteIdentityWithLocalID getIdentity(final RemoteIdentity ri) {
		for (final RemoteIdentityWithLocalID rid: identities) {
			if (rid.getRemoteID().equals(ri.getRemoteID())) {
				return rid;
			}
		}
		return null;
	}
	
	//TODO EQUALS
}
