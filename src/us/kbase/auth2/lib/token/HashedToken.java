package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import us.kbase.auth2.lib.UserName;

/** A hashed token associated with a user.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class HashedToken {

	private final TokenType type;
	private final UUID id;
	private final String tokenName;
	private final String tokenHash;
	private final UserName userName;
	private final long expirationDate;
	private final long creationDate;
	
	/** Create a hashed token.
	 * @param type the type of the token.
	 * @param tokenName the name of the token, or null to leave the token unnamed.
	 * @param id the ID of the token.
	 * @param tokenHash the hash of the token string.
	 * @param userName the username of the token.
	 * @param creationDate the creation date of the token.
	 * @param expirationDate the expiration date of the token.
	 */
	public HashedToken(
			final TokenType type,
			final String tokenName,
			final UUID id,
			final String tokenHash,
			final UserName userName,
			final Date creationDate,
			final Date expirationDate) {
		checkStringNoCheckedException(tokenHash, "tokenHash");
		if (type == null) {
			throw new NullPointerException("type");
		}
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (expirationDate == null) {
			throw new NullPointerException("expirationDate");
		}
		if (creationDate == null) {
			throw new NullPointerException("creationDate");
		}
		if (creationDate.after(expirationDate)) {
			throw new IllegalArgumentException("expirationDate must be > creationDate");
		}
		if (id == null) {
			throw new NullPointerException("id");
		}
		this.type = type;
		this.tokenName = tokenName; // null ok
		this.tokenHash = tokenHash;
		this.userName = userName;
		this.expirationDate = expirationDate.getTime();
		this.creationDate = creationDate.getTime();
		this.id = id;
	}

	/** Get the type of the token.
	 * @return the token type.
	 */
	public TokenType getTokenType() {
		return type;
	}
	
	/** Get the token's ID.
	 * @return the ID.
	 */
	public UUID getId() {
		return id;
	}
	
	/** Get the name of the token, or null if it is unnamed.
	 * @return the name of the token.
	 */
	public String getTokenName() {
		return tokenName;
	}

	/** Get the token's hash string.
	 * @return the hash string.
	 */
	public String getTokenHash() {
		return tokenHash;
	}

	/** Get the name of the user that possesses this token.
	 * @return the user name.
	 */
	public UserName getUserName() {
		return userName;
	}

	/** Get the date the token was created.
	 * @return the creation date.
	 */
	public Date getCreationDate() {
		return new Date(creationDate);
	}

	/** Get the date the token expires.
	 * @return the expiration date.
	 */
	public Date getExpirationDate() {
		return new Date(expirationDate);
	}

	/** Get a SHA-256 hash of a token.
	 * @param token the token to hash, encoded as UTF-8.
	 * @return the hash of the token.
	 */
	public static String hash(final String token) {
		checkStringNoCheckedException(token, "token");
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("This should be impossible", e);
		}
		final byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(hash);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (creationDate ^ (creationDate >>> 32));
		result = prime * result + (int) (expirationDate ^ (expirationDate >>> 32));
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((tokenHash == null) ? 0 : tokenHash.hashCode());
		result = prime * result + ((tokenName == null) ? 0 : tokenName.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		result = prime * result + ((userName == null) ? 0 : userName.hashCode());
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
		HashedToken other = (HashedToken) obj;
		if (creationDate != other.creationDate) {
			return false;
		}
		if (expirationDate != other.expirationDate) {
			return false;
		}
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		if (tokenHash == null) {
			if (other.tokenHash != null) {
				return false;
			}
		} else if (!tokenHash.equals(other.tokenHash)) {
			return false;
		}
		if (tokenName == null) {
			if (other.tokenName != null) {
				return false;
			}
		} else if (!tokenName.equals(other.tokenName)) {
			return false;
		}
		if (type != other.type) {
			return false;
		}
		if (userName == null) {
			if (other.userName != null) {
				return false;
			}
		} else if (!userName.equals(other.userName)) {
			return false;
		}
		return true;
	}
}
