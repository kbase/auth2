package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.addNoOverflow;
import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.nonNull;

import java.time.Instant;
import java.util.UUID;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.TokenName;
import us.kbase.auth2.lib.UserName;

/** A new token associated with a user.
 * @author gaprice@lbl.gov
 *
 */
public class NewToken {

	private final UUID id;
	private final TokenType type;
	private final String token;
	private final Optional<TokenName> tokenName;
	private final UserName userName;
	private final Instant expirationDate;
	private final Instant creationDate;
	
	/** Create a new unnamed token.
	 * @param id the token id.
	 * @param type the token type.
	 * @param token the token string.
	 * @param userName the user that possesses the token.
	 * @param creation the date of this token's creation.
	 * @param lifetimeInMS the token's lifetime in milliseconds.
	 */
	public NewToken(
			final UUID id,
			final TokenType type,
			final String token,
			final UserName userName,
			final Instant creation,
			final long lifetimeInMS) {
		nonNull(id, "id");
		checkStringNoCheckedException(token, "token");
		nonNull(type, "type");
		nonNull(userName, "userName");
		nonNull(creation, "creation");
		if (lifetimeInMS < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.id = id;
		this.type = type;
		this.tokenName = Optional.absent();
		this.token = token;
		this.userName = userName;
		this.creationDate = creation;
		this.expirationDate = Instant.ofEpochMilli(
				addNoOverflow(creationDate.toEpochMilli(), lifetimeInMS));
	}
	
	/** Create a new named token.
	 * @param id the token id.
	 * @param type the token type.
	 * @param tokenName the name of the token.
	 * @param token the token string.
	 * @param userName the user that possesses the token.
	 * @param creation the date of this token's creation.
	 * @param lifetimeInMS the token's lifetime in milliseconds.
	 */
	public NewToken(
			final UUID id,
			final TokenType type,
			final TokenName tokenName,
			final String token,
			final UserName userName,
			final Instant creation,
			final long lifetimeInMS) {
		nonNull(id, "id");
		checkStringNoCheckedException(token, "token");
		nonNull(tokenName, "tokenName");
		nonNull(type, "type");
		nonNull(userName, "userName");
		nonNull(creation, "creation");
		if (lifetimeInMS < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.id = id;
		this.type = type;
		this.tokenName = Optional.of(tokenName);
		this.token = token;
		this.userName = userName;
		this.creationDate = creation;
		this.expirationDate = Instant.ofEpochMilli(
				addNoOverflow(creationDate.toEpochMilli(), lifetimeInMS));
	}

	/** Get the token's type.
	 * @return the type.
	 */
	public TokenType getTokenType() {
		return type;
	}
	
	/** Get the token's name, or absent if the token is not named.
	 * @return the token's name.
	 */
	public Optional<TokenName> getTokenName() {
		return tokenName;
	}

	/** Get the token's ID.
	 * @return the ID.
	 */
	public UUID getId() {
		return id;
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

	/** Get the name of the user that possesses the token.
	 * @return the user name.
	 */
	public UserName getUserName() {
		return userName;
	}

	/** Get the date this token was created.
	 * @return the creation date.
	 */
	public Instant getCreationDate() {
		return creationDate;
	}

	/** Get the date this token expires.
	 * @return the expiration date.
	 */
	public Instant getExpirationDate() {
		return expirationDate;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((creationDate == null) ? 0 : creationDate.hashCode());
		result = prime * result + ((expirationDate == null) ? 0 : expirationDate.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((token == null) ? 0 : token.hashCode());
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
		NewToken other = (NewToken) obj;
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
