package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.nonNull;

/** A new token associated with a user.
 * @author gaprice@lbl.gov
 *
 */
public class NewToken {

	private final StoredToken st;
	private final String token;
	
	/** Create a new token.
	 * @param storedToken the token that this new token wraps.
	 * @param token the token string.
	 */
	public NewToken(final StoredToken storedToken, final String token) {
		nonNull(storedToken, "storedToken");
		checkStringNoCheckedException(token, "token");
		this.st = storedToken;
		this.token = token;
	}
	
	/** Get the wrapped token.
	 * @return the wrapped token.
	 */
	public StoredToken getStoredToken() {
		return st;
	}

	/** Get the token string.
	 * @return the token string.
	 */
	public String getToken() {
		return token;
	}
	
	/** Gets the hash of the token string.
	 * 
	 * Uses the {@link IncomingToken#hash(String)} method.
	 * @return the hash of the token string.
	 */
	public String getTokenHash() {
		return IncomingToken.hash(token);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((st == null) ? 0 : st.hashCode());
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
		NewToken other = (NewToken) obj;
		if (st == null) {
			if (other.st != null) {
				return false;
			}
		} else if (!st.equals(other.st)) {
			return false;
		}
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
