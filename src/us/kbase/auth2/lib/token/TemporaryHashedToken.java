package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.checkString;

import java.util.Date;
import java.util.UUID;

public class TemporaryHashedToken {
	
	//TODO TEST
	//TODO JAVADOC

	private final String tokenHash;
	private final Date created;
	private final Date expiry;
	private final UUID id;

	public TemporaryHashedToken(
			final String tokenHash,
			final UUID id,
			final Date created,
			final Date expiry) {
		super();
		checkString(tokenHash, "tokenHash", true);
		if (created == null) {
			throw new NullPointerException("created");
		}
		if (expiry == null) {
			throw new NullPointerException("expiry");
		}
		if (id == null) {
			throw new NullPointerException("id");
		}
		this.tokenHash = tokenHash;
		this.id = id;
		this.created = created;
		this.expiry = expiry;
	}

	public String getTokenHash() {
		return tokenHash;
	}

	public UUID getId() {
		return id;
	}

	public Date getCreationDate() {
		return created;
	}

	public Date getExpirationDate() {
		return expiry;
	}
}
