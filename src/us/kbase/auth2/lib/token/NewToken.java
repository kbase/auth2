package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.addLong;

import java.util.Date;
import java.util.UUID;

import us.kbase.auth2.lib.UserName;

public class NewToken {

	//TODO TEST
	//TODO JAVADOC
	
	private final TokenType type;
	private final String tokenName;
	private final String token;
	private final UserName userName;
	private final Date expirationDate;
	private final Date creationDate = new Date();
	private final UUID id = UUID.randomUUID();
	
	public NewToken(
			final TokenType type,
			final String token,
			final UserName userName,
			final long lifetimeInms) {
		checkStringNoCheckedException(token, "token");
		if (type == null) {
			throw new NullPointerException("type");
		}
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (lifetimeInms < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.type = type;
		this.tokenName = null;
		this.token = token;
		this.userName = userName;
		this.expirationDate = new Date(
				addLong(creationDate.getTime(), lifetimeInms));
	}
	
	public NewToken(
			final TokenType type,
			final String tokenName,
			final String token,
			final UserName userName,
			final long lifetimeInms) {
		checkStringNoCheckedException(token, "token");
		checkStringNoCheckedException(tokenName, "tokenName");
		if (type == null) {
			throw new NullPointerException("type");
		}
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (lifetimeInms < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.type = type;
		this.tokenName = tokenName;
		this.token = token;
		this.userName = userName;
		this.expirationDate = new Date(
				addLong(creationDate.getTime(), lifetimeInms));
	}

	public TokenType getTokenType() {
		return type;
	}
	
	public String getTokenName() {
		return tokenName;
	}

	public UUID getId() {
		return id;
	}

	public String getToken() {
		return token;
	}

	public UserName getUserName() {
		return userName;
	}

	public Date getCreationDate() {
		return creationDate;
	}

	public Date getExpirationDate() {
		return expirationDate;
	}

	public HashedToken getHashedToken() {
		return new HashedToken(type, tokenName, id, HashedToken.hash(token),
				userName, creationDate, expirationDate);
	}

}
