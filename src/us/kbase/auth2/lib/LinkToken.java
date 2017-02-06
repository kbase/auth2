package us.kbase.auth2.lib;

import us.kbase.auth2.lib.token.TemporaryToken;

/** Provides a token for continuing the account linking process if needed.
 * 
 * If the linking process is concluded and the account linked, then isLinked() will be true and
 * the token will be null.
 * 
 * If there are still more steps to be completed in the linking process, isLinked() will be false
 * and a temporary token supplied which can be used ot continue the linking process.
 * @author gaprice@lbl.gov
 *
 */
public class LinkToken {
	
	private final boolean linked;
	private final TemporaryToken token;
	
	/** Create a LinkToken for the case where the linking process is concluded and no further
	 * actions are required.
	 */
	public LinkToken() {
		this.linked = true;
		this.token = null;
	}
	
	/** Create a LinkToken for the case where more actions are required, and thus a token is
	 * provided to allow continuing with the linking process.
	 * @param token a temporary token associated with the state of the linking process in the auth
	 * storage system.
	 */
	public LinkToken(final TemporaryToken token) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		this.linked = false;
		this.token = token;
	}

	/** True if the linking process is completed and no further actions are necessary.
	 * @return
	 */
	public boolean isLinked() {
		return linked;
	}

	/** Get a temporary token to use to complete the linking process.
	 * @return a token.
	 */
	public TemporaryToken getTemporaryToken() {
		return token;
	}

}
