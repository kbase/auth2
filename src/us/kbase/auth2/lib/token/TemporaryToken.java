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
	
	private final UUID id;
	private final String token;
	private final Instant creationDate;
	private final Instant expirationDate;

	/** Create a new temporary token.
	 * @param id the token id.
	 * @param token the token string.
	 * @param creation the creation date of the token.
	 * @param lifetimeInMS the lifetime of the token in milliseconds.
	 */
	public TemporaryToken(
			final UUID id,
			final String token,
			final Instant creation,
			final long lifetimeInMS) {
		nonNull(id, "id");
		checkStringNoCheckedException(token, "token");
		nonNull(creation, "creation");
		if (lifetimeInMS < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.id = id;
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
	 * uses the {@link IncomingToken#hash(String)} method.
	 * @return a hashed temporary token.
	 */
	public TemporaryHashedToken getHashedToken() {
		return new TemporaryHashedToken(id, IncomingToken.hash(token),
				creationDate, expirationDate);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((creationDate == null) ? 0 : creationDate.hashCode());
		result = prime * result + ((expirationDate == null) ? 0 : expirationDate.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
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
		TemporaryToken other = (TemporaryToken) obj;
		if (creationDate == null) {
			if (other.creationDate != null) {
				return false;
			}
		} else if (!creationDate.equals(other.creationDate)) {
			return false;
		}
		if (expirationDate == null) {
			if (other.expirationDate != null) {
				return false;
			}
		} else if (!expirationDate.equals(other.expirationDate)) {
			return false;
		}
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
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
