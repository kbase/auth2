package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

/** Represents the state of a user's login request. This state includes:
 * 
 * 1) The name of the 3rd party identity provider that provided the user's identities
 * 2) The set of user accounts associated with those identities
 * 3) The set of 3rd party identities that are not associated with a user account
 * 4) Whether non-administrator logins are allowed.
 * @author gaprice@lbl.gov
 *
 */
public class LoginState {

	/* separate map for user -> identities from what's already in the AuthUser class because
	 * 1) the AuthUser class may contain identities from multiple providers
	 * 2) depending on the 3rd party account the user logged into, the user may only have access
	 * to a subset of the AuthUser identities, even if they're all from the same provider (e.g.
	 * the user account may be linked to multiple different provider accounts).
	 * 3) Depending on race conditions, it's possible the remote IDs in the AuthUser and
	 * stored in the temporary storage in the DB might have different UUIDs
	 */
	private final Map<UserName, Set<RemoteIdentityWithLocalID>> userIDs = new HashMap<>();
	private final Map<UserName, AuthUser> users = new HashMap<>();
	private final Set<RemoteIdentityWithLocalID> noUser = new HashSet<>();
	private final String provider;
	private final boolean nonAdminLoginAllowed;

	private LoginState(final String provider, final boolean nonAdminLoginAllowed) {
		this.provider = provider;
		this.nonAdminLoginAllowed = nonAdminLoginAllowed;
	}
	
	/** Get the name of the identity provider that provided the identities for the user.
	 * @return the identity provider name.
	 */
	public String getProvider() {
		return provider;
	}
	
	/** Returns whether login is allowed for non-administrators.
	 * @return whether non-administrator login is allowed.
	 */
	public boolean isNonAdminLoginAllowed() {
		return nonAdminLoginAllowed;
	}
	
	/** Returns whether a user is an admin.
	 * @param name the name of the user to check.
	 * @return true if the user is an admin, false otherwise.
	 */
	public boolean isAdmin(final UserName name) {
		checkUser(name);
		return Role.isAdmin(users.get(name).getRoles());
	}
	
	/** Get the set of identities that are not associated with a user account.
	 * @return the set of identities that are not associated with a user account.
	 */
	public Set<RemoteIdentityWithLocalID> getIdentities() {
		return Collections.unmodifiableSet(noUser);
	}
	
	/** Get the names of the user accounts to which the user has login privileges based on the
	 * identities provided by the identity provider.
	 * @return the user names.
	 */
	public Set<UserName> getUsers() {
		return Collections.unmodifiableSet(users.keySet());
	}
	
	/** Get the user information for a given user name.
	 * @param name the user name.
	 * @return the user information.
	 */
	public AuthUser getUser(final UserName name) {
		checkUser(name);
		return users.get(name);
	}

	private void checkUser(final UserName name) {
		if (name == null) {
			throw new NullPointerException("name");
		}
		if (!users.containsKey(name)) {
			throw new IllegalArgumentException("No such user: " + name.getName());
		}
	}
	
	/** Get the remote identities associated with a given user account that granted access to said
	 * account.
	 * 
	 * Note this may be a subset of the identities associated with the account in general, and the
	 * identities in this set may have different UUIDs than the corresponding identities in
	 * the user class.
	 * @param name the user name of the user account.
	 * @return the set of remote identities.
	 */
	public Set<RemoteIdentityWithLocalID> getIdentities(final UserName name) {
		checkUser(name);
		return Collections.unmodifiableSet(userIDs.get(name));
	}
	

	/** A builder for a LoginState instance.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {
		
		private final LoginState ls;

		/** Create the builder.
		 * @param provider the name of the identity provider that provided the identities for this
		 * login attempt.
		 * @param nonAdminLoginAllowed true if non-administrators are allowed, false otherwise.
		 */
		public Builder(final String provider, final boolean nonAdminLoginAllowed) {
			if (provider == null || provider.trim().isEmpty()) {
				throw new IllegalArgumentException("provider cannot be null or empty");
			}
			ls = new LoginState(provider, nonAdminLoginAllowed);
		}

		/** Add a remote identity that is not associated with a user account.
		 * @param remoteID the remote identity to add.
		 * @return this builder.
		 */
		public Builder withIdentity(final RemoteIdentityWithLocalID remoteID) {
			// should probably check that the identity doesn't already exist in either of the
			// maps... but eh for now
			if (remoteID == null) {
				throw new NullPointerException("remoteID");
			}
			checkProvider(remoteID);
			ls.noUser.add(remoteID);
			return this;
		}

		private void checkProvider(final RemoteIdentityWithLocalID remoteID) {
			if (!ls.provider.equals(remoteID.getRemoteID().getProvider())) {
				throw new IllegalStateException(
						"Cannot have multiple providers in the same login state");
			}
		}

		/** Add a user account to which the user has access based on a 3rd party identity.
		 * @param user the user account.
		 * @param remoteID the 3rd party identity that grants the user access to the user account.
		 * @return this builder.
		 */
		public Builder withUser(final AuthUser user, final RemoteIdentityWithLocalID remoteID) {
			// should probably check that the identity doesn't already exist in either of the
			// maps... but eh for now
			if (user == null) {
				throw new NullPointerException("user");
			}
			if (remoteID == null) {
				throw new NullPointerException("remoteID");
			}
			checkProvider(remoteID);
			if (user.getIdentity(remoteID) == null) {
				throw new IllegalArgumentException("user does not contain remote ID");
			}
			final UserName name = user.getUserName();
			ls.users.put(name, user);
			if (!ls.userIDs.containsKey(name)) {
				ls.userIDs.put(name, new HashSet<>());
			}
			ls.userIDs.get(name).add(remoteID);
			return this;
		}

		/** Build a new LoginState instance.
		 * @return the new instance.
		 */
		public LoginState build() {
			return ls;
		}
	}
}
