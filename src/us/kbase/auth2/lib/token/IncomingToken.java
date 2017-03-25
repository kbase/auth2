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
	 * Uses the {@link StoredToken#hash(String)} method.
	 * @return a hashed token.
	 */
	public IncomingHashedToken getHashedToken() {
		return new IncomingHashedToken(StoredToken.hash(token));
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((token == null) ? 0 : token.hashCode());
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
		IncomingToken other = (IncomingToken) obj;
		if (token == null) {
			if (other.token != null) {
				return false;
			}
		} else if (!token.equals(other.token)) {
			return false;
		}
		return true;
	}
	
	
}
