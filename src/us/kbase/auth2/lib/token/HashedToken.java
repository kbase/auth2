package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkString;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import us.kbase.auth2.lib.UserName;

public class HashedToken {
	//TODO TEST
	//TODO JAVADOC

	private final TokenType type;
	private final UUID id;
	private final String tokenName;
	private final String tokenHash;
	private final UserName userName;
	private final long expirationDate;
	private final long creationDate;
	
	public HashedToken(
			final TokenType type,
			final String tokenName,
			final UUID id,
			final String tokenHash,
			final UserName userName,
			final Date creationDate,
			final Date expirationDate) {
		checkString(tokenHash, "tokenHash", true);
		if (type == null) {
			throw new NullPointerException("type");
		}
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		if (expirationDate == null) {
			throw new IllegalArgumentException("expirationDate");
		}
		if (creationDate == null) {
			throw new IllegalArgumentException("creationDate");
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

	public TokenType getTokenType() {
		return type;
	}
	
	public UUID getId() {
		return id;
	}
	
	public String getTokenName() {
		return tokenName;
	}

	public String getTokenHash() {
		return tokenHash;
	}

	public UserName getUserName() {
		return userName;
	}

	public Date getCreationDate() {
		return new Date(creationDate);
	}

	public Date getExpirationDate() {
		return new Date(expirationDate);
	}

	public static String hash(final String token) {
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("This should be impossible", e);
		}
		final byte[] hash = digest.digest(
				token.getBytes(StandardCharsets.UTF_8));
		final String b64hash = Base64.getEncoder().encodeToString(hash);
		return b64hash;
	}

}
