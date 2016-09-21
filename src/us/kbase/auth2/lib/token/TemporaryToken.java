package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkString;
import static us.kbase.auth2.lib.Utils.addLong;

import java.util.Date;
import java.util.UUID;

public class TemporaryToken {
	
	//TODO TEST
	//TODO JAVADOC
	
	private final String token;
	private final Date creationDate = new Date();
	private final Date expirationDate;
	private final UUID id = UUID.randomUUID();

	public TemporaryToken(final String token, final long lifetimeInms) {
		checkString(token, "token", true);
		if (lifetimeInms < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		this.token = token;
		this.expirationDate = new Date(
				addLong(creationDate.getTime(), lifetimeInms));
	}

	public String getToken() {
		return token;
	}
	
	public Date getCreationDate() {
		return creationDate;
	}

	public Date getExpirationDate() {
		return expirationDate;
	}

	public UUID getId() {
		return id;
	}

	public TemporaryHashedToken getHashedToken() {
		return new TemporaryHashedToken(
				HashedToken.hash(token), id, creationDate, expirationDate);
	}
}
