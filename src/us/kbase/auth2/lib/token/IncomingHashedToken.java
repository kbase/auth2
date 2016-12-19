package us.kbase.auth2.lib.token;

/** A token received from a user that has been hashed. Created by
 * {@link IncomingToken#getHashedToken()}
 * @author gaprice@lbl.gov
 *
 */
public class IncomingHashedToken {
	
	private final String tokenHash;

	IncomingHashedToken(final String tokenHash) {
		// assume the tokenHash is good since this constructor is only called by IncomingToken
		this.tokenHash = tokenHash;
	}

	/** Returns the hashed token.
	 * @return the hashed token.
	 */
	public String getTokenHash() {
		return tokenHash;
	}

}
