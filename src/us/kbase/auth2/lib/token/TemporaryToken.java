package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.addNoOverflow;

import java.util.Date;
import java.util.UUID;

/** A temporary token.
 * @author gaprice@lbl.gov
 *
 */
public class TemporaryToken {
	
	private final String token;
	private final long creationDate = new Date().getTime();
	private final long expirationDate;
	private final UUID id = UUID.randomUUID();

	/** Create a new temporary token.
	 * @param token the token string.
	 * @param lifetimeInMS the lifetime of the token in milliseconds.
	 */
	public TemporaryToken(final String token, final long lifetimeInMS) {
		checkStringNoCheckedException(token, "token");
		if (lifetimeInMS < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.token = token;
		this.expirationDate = new Date(addNoOverflow(creationDate, lifetimeInMS)).getTime();
	}

	/** Get the token string.
	 * @return the token string.
	 */
	public String getToken() {
		return token;
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

	/** Get the token's ID.
	 * @return the ID.
	 */
	public UUID getId() {
		return id;
	}

	/** Get a hashed token based on this token.
	 * 
	 * uses the {@link HashedToken#hash(String)} method.
	 * @return a hashed temporary token.
	 */
	public TemporaryHashedToken getHashedToken() {
		return new TemporaryHashedToken(HashedToken.hash(token), id, creationDate, expirationDate);
	}
}
