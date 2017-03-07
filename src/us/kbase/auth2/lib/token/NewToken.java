package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.addNoOverflow;
import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.nonNull;

import java.time.Instant;
import java.util.UUID;

import us.kbase.auth2.lib.UserName;

/** A new token associated with a user.
 * @author gaprice@lbl.gov
 *
 */
public class NewToken {

	private final TokenType type;
	private final String tokenName;
	private final String token;
	private final UserName userName;
	private final Instant expirationDate;
	private final Instant creationDate;
	private final UUID id = UUID.randomUUID();
	
	/** Create a new unnamed token.
	 * @param type the token type.
	 * @param token the token string.
	 * @param userName the user that possesses the token.
	 * @param creation the date of this token's creation.
	 * @param lifetimeInMS the token's lifetime in milliseconds.
	 */
	public NewToken(
			final TokenType type,
			final String token,
			final UserName userName,
			final Instant creation,
			final long lifetimeInMS) {
		checkStringNoCheckedException(token, "token");
		nonNull(type, "type");
		nonNull(userName, "userName");
		nonNull(creation, "creation");
		if (lifetimeInMS < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.type = type;
		this.tokenName = null;
		this.token = token;
		this.userName = userName;
		this.creationDate = creation;
		this.expirationDate = Instant.ofEpochMilli(
				addNoOverflow(creationDate.toEpochMilli(), lifetimeInMS));
	}
	
	/** Create a new named token.
	 * @param type the token type.
	 * @param tokenName the name of the token.
	 * @param token the token string.
	 * @param userName the user that possesses the token.
	 * @param creation the date of this token's creation.
	 * @param lifetimeInMS the token's lifetime in milliseconds.
	 */
	public NewToken(
			final TokenType type,
			final String tokenName,
			final String token,
			final UserName userName,
			final Instant creation,
			final long lifetimeInMS) {
		checkStringNoCheckedException(token, "token");
		checkStringNoCheckedException(tokenName, "tokenName");
		nonNull(type, "type");
		nonNull(userName, "userName");
		nonNull(creation, "creation");
		if (lifetimeInMS < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.type = type;
		this.tokenName = tokenName;
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
	
	/** Get the token's name, or null if the token is not named.
	 * @return the token's name.
	 */
	public String getTokenName() {
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

	/** Get a hashed token based on this token.
	 * 
	 * uses the {@link HashedToken#hash(String)} method.
	 * @return a hashed token.
	 */
	public HashedToken getHashedToken() {
		return new HashedToken(type, tokenName, id, HashedToken.hash(token),
				userName, creationDate, expirationDate);
	}

}
