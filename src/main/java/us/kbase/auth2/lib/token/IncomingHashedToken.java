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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((tokenHash == null) ? 0 : tokenHash.hashCode());
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
		IncomingHashedToken other = (IncomingHashedToken) obj;
		if (tokenHash == null) {
			if (other.tokenHash != null) {
				return false;
			}
		} else if (!tokenHash.equals(other.tokenHash)) {
			return false;
		}
		return true;
	}
}
