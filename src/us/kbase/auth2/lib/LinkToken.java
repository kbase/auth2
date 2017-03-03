package us.kbase.auth2.lib;

import us.kbase.auth2.lib.token.TemporaryToken;

/** Provides a token for continuing the account linking process if needed.
 * 
 * If the linking process is concluded and the account linked, then isLinked() will be true and
 * the token will be null.
 * 
 * If there are still more steps to be completed in the linking process, isLinked() will be false
 * and a temporary token supplied which can be used to continue the linking process.
 * @author gaprice@lbl.gov
 *
 */
public class LinkToken {
	
	private final TemporaryToken token;
	private final LinkIdentities idents;
	
	/** Create a LinkToken for the case where the linking process is concluded and no further
	 * actions are required.
	 */
	public LinkToken() {
		this.token = null;
		this.idents = null;
	}
	
	/** Create a LinkToken for the case where more actions are required, and thus a token is
	 * provided to allow continuing with the linking process.
	 * @param token a temporary token associated with the state of the linking process in the auth
	 * storage system.
	 * @param linkIdentities the identities available for linking.
	 */
	public LinkToken(final TemporaryToken token, final LinkIdentities linkIdentities) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		if (linkIdentities == null) {
			throw new NullPointerException("linkIdentities");
		}
		this.idents = linkIdentities;
		this.token = token;
	}

	/** True if the linking process is completed and no further actions are necessary.
	 * @return true if the linking process is complete.
	 */
	public boolean isLinked() {
		return token == null;
	}

	/** Get a temporary token to use to complete the linking process.
	 * @return a temporary token, or null if the linking process is complete.
	 */
	public TemporaryToken getTemporaryToken() {
		return token;
	}
	
	/** Get the identities available for linking.
	 * @return the identities available for linking, or null if linking process is complete.
	 */
	public LinkIdentities getLinkIdentities() {
		return idents;
	}

}
