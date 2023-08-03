package us.kbase.auth2.lib;

import static java.util.Objects.requireNonNull;

import java.time.Instant;
import java.util.Collections;
import java.util.Comparator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.user.AuthUser;

// very similar to login state, but not similar enough to share code easily and maintain a lack
// of coupling.

/** A set of remote identities possessed by a user that may be linked to the user's account, and,
 * for informational purposes, remote identities that are already linked to accounts.
 * @author gaprice@lbl.gov
 *
 */
public class LinkIdentities {
	
	private final UserName userName;
	private final Set<RemoteIdentity> idents;
	private final Map<UserName, Set<RemoteIdentity>> linked;
	private final String provider;
	private final Instant expires;

	private LinkIdentities(
			final UserName userName,
			final String provider,
			final Set<RemoteIdentity> ids,
			final Map<UserName, Set<RemoteIdentity>> linked,
			final Instant expires) {
		this.userName = userName;
		this.provider = provider;
		this.idents = Collections.unmodifiableSet(ids);
		this.linked = Collections.unmodifiableMap(linked);
		this.expires = expires;
	}
	
	/** Get the user to which unlinked remote IDs may be added.
	 * @return the user.
	 */
	public UserName getUser() {
		return userName;
	}

	/** Get the unlinked remote identities.
	 * @return the remote identities. May be empty if no linkable identities are available.
	 */
	public Set<RemoteIdentity> getIdentities() {
		return idents;
	}
	
	/** Get the set of users that are associated with linked identities in this set. May include
	 * the user returned by {@link #getUser()}.
	 * @return the users that are linked to a remote identity in this set of identities.
	 */
	public Set<UserName> getLinkedUsers() {
		return linked.keySet();
	}
	
	/** Get the remote identities that are already linked to a user account.
	 * @param userName the user for which identities will be retrieved.
	 * @return the linked remote identities.
	 */
	public Set<RemoteIdentity> getLinkedIdentities(final UserName userName) {
		requireNonNull(userName, "userName");
		if (!linked.containsKey(userName)) {
			throw new IllegalArgumentException("No such user: " + userName.getName());
		}
		return Collections.unmodifiableSet(linked.get(userName));
	}
	
	/** Get the provider of the identities.
	 * @return the provider name.
	 */
	public String getProvider() {
		return provider;
	}
	
	/** Get the time that these link identities expire.
	 * @return the expiration time.
	 */
	public Instant getExpires() {
		return expires;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((expires == null) ? 0 : expires.hashCode());
		result = prime * result + ((idents == null) ? 0 : idents.hashCode());
		result = prime * result + ((linked == null) ? 0 : linked.hashCode());
		result = prime * result + ((provider == null) ? 0 : provider.hashCode());
		result = prime * result + ((userName == null) ? 0 : userName.hashCode());
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
		LinkIdentities other = (LinkIdentities) obj;
		if (expires == null) {
			if (other.expires != null) {
				return false;
			}
		} else if (!expires.equals(other.expires)) {
			return false;
		}
		if (idents == null) {
			if (other.idents != null) {
				return false;
			}
		} else if (!idents.equals(other.idents)) {
			return false;
		}
		if (linked == null) {
			if (other.linked != null) {
				return false;
			}
		} else if (!linked.equals(other.linked)) {
			return false;
		}
		if (provider == null) {
			if (other.provider != null) {
				return false;
			}
		} else if (!provider.equals(other.provider)) {
			return false;
		}
		if (userName == null) {
			if (other.userName != null) {
				return false;
			}
		} else if (!userName.equals(other.userName)) {
			return false;
		}
		return true;
	}
	
	/** Create a LinkIdentities builder.
	 * @param userName the name of the user that was logged in when retrieving the identities.
	 * @param provider the name of the identity provider that provided the identities for this
	 * login attempt.
	 * @param expires the date the identities expire.
	 * @return the builder.
	 */
	public static Builder getBuilder(
			final UserName userName,
			final String provider,
			final Instant expires) {
		return new Builder(userName, provider, expires);
	}
	
	/** A builder for a LinkIdentites instance.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {
		
		static final Comparator<RemoteIdentity> REMOTE_IDENTITY_COMPARATOR =
				LoginState.Builder.REMOTE_IDENTITY_COMPARATOR;

		private final UserName userName;
		private final Set<RemoteIdentity> idents = new TreeSet<>(REMOTE_IDENTITY_COMPARATOR);
		private final Map<UserName, Set<RemoteIdentity>> linked = new TreeMap<>();
		private final String provider;
		private final Instant expires;
		
		private Builder(
				final UserName userName,
				final String provider,
				final Instant expires) {
			if (provider == null || provider.trim().isEmpty()) {
				throw new IllegalArgumentException("provider cannot be null or empty");
			}
			requireNonNull(userName, "userName");
			requireNonNull(expires, "expires");
			this.provider = provider;
			this.expires = expires;
			this.userName = userName;
		}
		
		/** Add a remote identity that is not associated with a user account.
		 * @param remoteID the remote identity to add.
		 * @return this builder.
		 */
		public Builder withIdentity(final RemoteIdentity remoteID) {
			// should probably check that the identity doesn't already exist in either of the
			// maps... but eh for now
			requireNonNull(remoteID, "remoteID");
			checkProvider(remoteID);
			idents.add(remoteID);
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
			requireNonNull(user, "user");
			requireNonNull(remoteID, "remoteID");
			checkProvider(remoteID);
			if (user.getIdentity(remoteID) == null) {
				throw new IllegalArgumentException("user does not contain remote ID");
			}
			final UserName name = user.getUserName();
			if (!linked.containsKey(name)) {
				linked.put(name, new TreeSet<>(REMOTE_IDENTITY_COMPARATOR));
			}
			linked.get(name).add(remoteID);
			return this;
		}

		/** Build a new LinkIdentities instance.
		 * @return the new instance.
		 */
		public LinkIdentities build() {
			return new LinkIdentities(userName, provider, idents, linked, expires);
		}
	}
}
