package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.time.Instant;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.user.AuthUser;

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
	 */
	private final Map<UserName, Set<RemoteIdentity>> userIDs;
	private final Map<UserName, AuthUser> users;
	private final Set<RemoteIdentity> noUser;
	private final String provider;
	private final boolean nonAdminLoginAllowed;
	private final Instant expires;

	private LoginState(
			final String provider,
			final boolean nonAdminLoginAllowed,
			final Instant expires,
			final Map<UserName, Set<RemoteIdentity>> userIDs,
			final Map<UserName, AuthUser> users,
			final Set<RemoteIdentity> noUser) {
		this.provider = provider;
		this.nonAdminLoginAllowed = nonAdminLoginAllowed;
		this.expires = expires;
		this.userIDs = Collections.unmodifiableMap(userIDs);
		this.users = Collections.unmodifiableMap(users);
		this.noUser = Collections.unmodifiableSet(noUser);
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
	
	/** When the login state expires from the system.
	 * @return the expiration date.
	 */
	public Instant getExpires() {
		return expires;
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
	public Set<RemoteIdentity> getIdentities() {
		return noUser;
	}
	
	/** Get the names of the user accounts to which the user has login privileges based on the
	 * identities provided by the identity provider.
	 * @return the user names.
	 */
	public Set<UserName> getUsers() {
		return users.keySet();
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
		nonNull(name, "name");
		if (!users.containsKey(name)) {
			throw new IllegalArgumentException("No such user: " + name.getName());
		}
	}
	
	/** Get the remote identities associated with a given user account that granted access to said
	 * account.
	 * 
	 * Note this may be a subset of the identities associated with the account in general.
	 * @param name the user name of the user account.
	 * @return the set of remote identities.
	 */
	public Set<RemoteIdentity> getIdentities(final UserName name) {
		checkUser(name);
		return Collections.unmodifiableSet(userIDs.get(name));
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((expires == null) ? 0 : expires.hashCode());
		result = prime * result + ((noUser == null) ? 0 : noUser.hashCode());
		result = prime * result + (nonAdminLoginAllowed ? 1231 : 1237);
		result = prime * result + ((provider == null) ? 0 : provider.hashCode());
		result = prime * result + ((userIDs == null) ? 0 : userIDs.hashCode());
		result = prime * result + ((users == null) ? 0 : users.hashCode());
		return result;
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
		LoginState other = (LoginState) obj;
		if (expires == null) {
			if (other.expires != null) {
				return false;
			}
		} else if (!expires.equals(other.expires)) {
			return false;
		}
		if (noUser == null) {
			if (other.noUser != null) {
				return false;
			}
		} else if (!noUser.equals(other.noUser)) {
			return false;
		}
		if (nonAdminLoginAllowed != other.nonAdminLoginAllowed) {
			return false;
		}
		if (provider == null) {
			if (other.provider != null) {
				return false;
			}
		} else if (!provider.equals(other.provider)) {
			return false;
		}
		if (userIDs == null) {
			if (other.userIDs != null) {
				return false;
			}
		} else if (!userIDs.equals(other.userIDs)) {
			return false;
		}
		if (users == null) {
			if (other.users != null) {
				return false;
			}
		} else if (!users.equals(other.users)) {
			return false;
		}
		return true;
	}

	/** Create a LoginState builder.
	 * @param provider the name of the identity provider that provided the identities for this
	 * login attempt.
	 * @param nonAdminLoginAllowed true if non-administrators are allowed, false otherwise.
	 * @param expires the date the login state expires.
	 * @return the builder.
	 */
	public static Builder getBuilder(
			final String provider,
			final boolean nonAdminLoginAllowed,
			final Instant expires) {
		return new Builder(provider, nonAdminLoginAllowed, expires);
	}

	/** A builder for a LoginState instance.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {
		
		private final Comparator<RemoteIdentity> REMOTE_IDENTITY_COMPARATOR =
				new Comparator<RemoteIdentity>() {
			
			@Override
			public int compare(final RemoteIdentity ri1, final RemoteIdentity ri2) {
				return ri1.getRemoteID().getID().compareTo(ri2.getRemoteID().getID());
			}
		};

		private final Map<UserName, Set<RemoteIdentity>> userIDs = new HashMap<>();
		private final Map<UserName, AuthUser> users = new TreeMap<>();
		private final Set<RemoteIdentity> noUser = new TreeSet<>(REMOTE_IDENTITY_COMPARATOR);
		private final Instant expires;
		private final String provider;
		private final boolean nonAdminLoginAllowed;
		
		private Builder(
				final String provider,
				final boolean nonAdminLoginAllowed,
				final Instant expires) {
			if (provider == null || provider.trim().isEmpty()) {
				throw new IllegalArgumentException("provider cannot be null or empty");
			}
			nonNull(expires, "expires");
			this.provider = provider;
			this.nonAdminLoginAllowed = nonAdminLoginAllowed;
			this.expires = expires;
		}
		
		/** Add a remote identity that is not associated with a user account.
		 * @param remoteID the remote identity to add.
		 * @return this builder.
		 */
		public Builder withIdentity(final RemoteIdentity remoteID) {
			// should probably check that the identity doesn't already exist in either of the
			// maps... but eh for now
			nonNull(remoteID, "remoteID");
			checkProvider(remoteID);
			noUser.add(remoteID);
			return this;
		}

		private void checkProvider(final RemoteIdentity remoteID) {
			if (!provider.equals(remoteID.getRemoteID().getProviderName())) {
				throw new IllegalStateException(
						"Cannot have multiple providers in the same login state");
			}
		}

		/** Add a user account to which the user has access based on a 3rd party identity.
		 * @param user the user account.
		 * @param remoteID the 3rd party identity that grants the user access to the user account.
		 * @return this builder.
		 */
		public Builder withUser(final AuthUser user, final RemoteIdentity remoteID) {
			// should probably check that the identity doesn't already exist in either of the
			// maps... but eh for now
			nonNull(user, "user");
			nonNull(remoteID, "remoteID");
			checkProvider(remoteID);
			if (user.getIdentity(remoteID) == null) {
				throw new IllegalArgumentException("user does not contain remote ID");
			}
			final UserName name = user.getUserName();
			users.put(name, user);
			if (!userIDs.containsKey(name)) {
				userIDs.put(name, new TreeSet<>(REMOTE_IDENTITY_COMPARATOR));
			}
			userIDs.get(name).add(remoteID);
			return this;
		}

		/** Build a new LoginState instance.
		 * @return the new instance.
		 */
		public LoginState build() {
			return new LoginState(provider, nonAdminLoginAllowed, expires, userIDs, users, noUser);
		}
	}
}
