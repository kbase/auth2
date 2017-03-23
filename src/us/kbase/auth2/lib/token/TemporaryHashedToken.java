package us.kbase.auth2.lib.token;

import java.time.Instant;
import java.util.UUID;

/** An hashed temporary token.
 * @author gaprice@lbl.gov
 *
 */
public class TemporaryHashedToken {
	
	private final UUID id;
	private final String tokenHash;
	private final Instant created;
	private final Instant expiry;

	TemporaryHashedToken(
			final UUID id,
			final String tokenHash,
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((created == null) ? 0 : created.hashCode());
		result = prime * result + ((expiry == null) ? 0 : expiry.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
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
		TemporaryHashedToken other = (TemporaryHashedToken) obj;
		if (created == null) {
			if (other.created != null) {
				return false;
			}
		} else if (!created.equals(other.created)) {
			return false;
		}
		if (expiry == null) {
			if (other.expiry != null) {
				return false;
			}
		} else if (!expiry.equals(other.expiry)) {
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
		return true;
	}
}
