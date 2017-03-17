package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.user.AuthUser;

/** A set of remote identities possessed by a user that may be linked to the user's account.
 * As such, remote identities that are already linked to the user's account should not be included.
 * @author gaprice@lbl.gov
 *
 */
public class LinkIdentities {
	
	private final AuthUser user;
	private final Set<RemoteIdentityWithLocalID> idents;
	private final String provider;

	/** Create a set of identities that are linkable to a user account.
	 * @param user the user to which the identities may be linked.
	 * @param ids the remote identities.
	 */
	public LinkIdentities(
			final AuthUser user,
			Set<RemoteIdentityWithLocalID> ids) {
		nonNull(user, "user");
		if (ids == null || ids.isEmpty()) {
			throw new IllegalArgumentException("No remote IDs provided");
		}
		Utils.noNulls(ids, "null item in ids");
		this.user = user;
		this.idents = Collections.unmodifiableSet(new HashSet<>(ids));
		this.provider = ids.iterator().next().getRemoteID().getProviderName();
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
	public Set<RemoteIdentityWithLocalID> getIdentities() {
		return idents;
	}
	
	/** Get the provider of the identities.
	 * @return the provider name.
	 */
	public String getProvider() {
		return provider;
	}

}
