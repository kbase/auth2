package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

/** A set of remote identities possessed by a user that may be linked to the user's account.
 * As such, remote identities that are already linked to the user's account should not be included.
 * @author gaprice@lbl.gov
 *
 */
public class LinkIdentities {
	
	private final AuthUser user;
	private final Set<RemoteIdentityWithLocalID> idents;

	/** Create a set of identities that are linkable to a user account.
	 * @param user the user to which the identities may be linked.
	 * @param ids the remote identities.
	 */
	public LinkIdentities(
			final AuthUser user,
			Set<RemoteIdentityWithLocalID> ids) {
		if (user == null) {
			throw new NullPointerException("user");
		}
		if (ids == null || ids.isEmpty()) {
			throw new IllegalArgumentException("No remote IDs provided");
		}
		Utils.noNulls(ids, "null item in ids");
		this.user = user;
		this.idents = Collections.unmodifiableSet(new HashSet<>(ids));
	}

	/** Get the user associated with the remote identities.
	 * @return the user.
	 */
	public AuthUser getUser() {
		return user;
	}

	/** Get the remote identities.
	 * @return the remote identities.
	 */
	public Set<RemoteIdentityWithLocalID> getIdentities() {
		return idents;
	}

}
