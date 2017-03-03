package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkString;

import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** A unhashed token received from a user.
 * @author gaprice@lbl.gov
 *
 */
public class IncomingToken {
	
	private final String token;

	/** Create an incoming token.
	 * @param token the token string
	 * @throws MissingParameterException if the token string is null or empty.
	 */
	public IncomingToken(final String token) throws MissingParameterException {
		checkString(token, "token");
		this.token = token.trim();
	}

	/** Get the token string.
	 * @return the token string.
	 */
	public String getToken() {
		return token;
	}
	
	/** Get the a hashed token based on this token. 
	 * 
	 * Uses the {@link HashedToken#hash(String)} method.
	 * @return a hashed token.
	 */
	public IncomingHashedToken getHashedToken() {
		return new IncomingHashedToken(HashedToken.hash(token));
	}
}
