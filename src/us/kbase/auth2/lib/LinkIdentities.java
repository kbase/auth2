package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.user.AuthUser;

/** A set of remote identities possessed by a user that may be linked to the user's account.
 * As such, remote identities that are already linked to the user's account should not be included.
 * @author gaprice@lbl.gov
 *
 */
public class LinkIdentities {
	
	private final AuthUser user;
	private final Set<RemoteIdentity> idents;
	private final String provider;
	private final Optional<Instant> expires;

	/** Create a set of identities that are linkable to a user account.
	 * @param user the user to which the identities may be linked.
	 * @param ids the remote identities.
	 * @param instant the time the identities expire.
	 */
	public LinkIdentities(
			final AuthUser user,
			final Set<RemoteIdentity> ids,
			final Instant expires) {
		nonNull(user, "user");
		nonNull(expires, "expires");
		if (ids == null || ids.isEmpty()) {
			throw new IllegalArgumentException("No remote IDs provided");
		}
		Utils.noNulls(ids, "null item in ids");
		this.user = user;
		this.idents = Collections.unmodifiableSet(new HashSet<>(ids));
		this.provider = ids.iterator().next().getRemoteID().getProviderName();
		this.expires = Optional.of(expires);
	}
	
	/** Create an empty identity set, implying that no identities were available for linking
	 * from this provider.
	 * @param user the user on which the link was attempted.
	 * @param provider the provider from which the identities were retrieved.
	 */
	public LinkIdentities(
			final AuthUser user,
			final String provider) {
		nonNull(user, "user");
		if (provider == null || provider.trim().isEmpty()) {
			throw new IllegalArgumentException("provider cannot be null or empty");
		}
		this.user = user;
		this.idents = Collections.unmodifiableSet(Collections.emptySet());
		this.provider = provider;
		this.expires = Optional.absent();
	}

	/** Get the user associated with the remote identities.
	 * @return the user.
	 */
	public AuthUser getUser() {
		return user;
	}

	/** Get the remote identities.
	 * @return the remote identities. May be empty if no linkable identities are available.
	 */
	public Set<RemoteIdentity> getIdentities() {
		return idents;
	}
	
	/** Get the provider of the identities.
	 * @return the provider name.
	 */
	public String getProvider() {
		return provider;
	}
	
	/** Get the time that these link identities expire. Absent if there are no identities.
	 * @return the expiration time.
	 */
	public Optional<Instant> getExpires() {
		return expires;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((expires == null) ? 0 : expires.hashCode());
		result = prime * result + ((idents == null) ? 0 : idents.hashCode());
		result = prime * result + ((provider == null) ? 0 : provider.hashCode());
		result = prime * result + ((user == null) ? 0 : user.hashCode());
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
		if (provider == null) {
			if (other.provider != null) {
				return false;
			}
		} else if (!provider.equals(other.provider)) {
			return false;
		}
		if (user == null) {
			if (other.user != null) {
				return false;
			}
		} else if (!user.equals(other.user)) {
			return false;
		}
		return true;
	}
}
