package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkString;
import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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
	 * Uses the {@link #hash(String)} method.
	 * @return a hashed token.
	 */
	public IncomingHashedToken getHashedToken() {
		return new IncomingHashedToken(hash(token));
	}
	
	/** Get a SHA-256 hash of a token encoded in Base64.
	 * @param token the token to hash.
	 * @return the hash of the token when encoded as UTF-8 Base64.
	 */
	public static String hash(final String token) {
		return hash(token, false);
	}
		
	/** Get a SHA-256 hash of a token encoded in Base64.
	 * @param token the token to hash.
	 * @param base64URLEncoding encode the token in the Base64 URL variant rather than the
	 * standard variant if true.
	 * @return the hash of the token when encoded as UTF-8 Base64.
	 */
	public static String hash(final String token, final boolean base64URLEncoding) {
		checkStringNoCheckedException(token, "token");
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("This should be impossible", e);
		}
		final byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
		if (base64URLEncoding) {
			return Base64.getUrlEncoder().encodeToString(hash);
		} else {
			return Base64.getEncoder().encodeToString(hash);
		}
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

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("IncomingToken [token=");
		builder.append(token);
		builder.append("]");
		return builder.toString();
	}
}
