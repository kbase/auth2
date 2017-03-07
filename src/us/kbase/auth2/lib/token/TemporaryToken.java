package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.addNoOverflow;
import static us.kbase.auth2.lib.Utils.nonNull;

import java.time.Instant;
import java.util.UUID;

/** A temporary token.
 * @author gaprice@lbl.gov
 *
 */
public class TemporaryToken {
	
	private final String token;
	private final Instant creationDate;
	private final Instant expirationDate;
	private final UUID id = UUID.randomUUID();

	/** Create a new temporary token.
	 * @param token the token string.
	 * @param creation the creation date of the token.
	 * @param lifetimeInMS the lifetime of the token in milliseconds.
	 */
	public TemporaryToken(final String token, final Instant creation, final long lifetimeInMS) {
		checkStringNoCheckedException(token, "token");
		nonNull(creation, "creation");
		if (lifetimeInMS < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.token = token;
		this.creationDate = creation;
		this.expirationDate = Instant.ofEpochMilli(
				addNoOverflow(creationDate.toEpochMilli(), lifetimeInMS));
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
	public Instant getCreationDate() {
		return creationDate;
	}

	/** Get the date the token expires.
	 * @return the expiration date.
	 */
	public Instant getExpirationDate() {
		return expirationDate;
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
