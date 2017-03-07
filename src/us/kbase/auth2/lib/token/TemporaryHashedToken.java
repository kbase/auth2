package us.kbase.auth2.lib.token;

import java.time.Instant;
import java.util.UUID;

/** An hashed temporary token.
 * @author gaprice@lbl.gov
 *
 */
public class TemporaryHashedToken {
	
	private final String tokenHash;
	private final Instant created;
	private final Instant expiry;
	private final UUID id;

	TemporaryHashedToken(
			final String tokenHash,
			final UUID id,
			final Instant creationDate,
			final Instant expirationDate) {
		// since this method is only called by TemporaryToken, we assume the inputs are ok
		this.tokenHash = tokenHash;
		this.id = id;
		this.created = creationDate;
		this.expiry = expirationDate;
	}

	/** Get the token hash string.
	 * @return the hash string.
	 */
	public String getTokenHash() {
		return tokenHash;
	}

	/** Get the token's ID.
	 * @return the ID.
	 */
	public UUID getId() {
		return id;
	}

	/** Get the date the token was created.
	 * @return the creation date.
	 */
	public Instant getCreationDate() {
		return created;
	}

	/** Get the date the token expires.
	 * @return the expiration date.
	 */
	public Instant getExpirationDate() {
		return expiry;
	}
}
