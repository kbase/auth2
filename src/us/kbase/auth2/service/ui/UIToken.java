package us.kbase.auth2.service.ui;

import java.util.Date;
import java.util.UUID;

import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.TokenType;

public class UIToken {
	
	//TODO TEST
	//TODO JAVADOC
	
	private final String type;
	private final String id;
	private final long expires;
	private final long created;
	private final String name;
	private final String user;

	public UIToken(final HashedToken token) {
		this(token.getTokenType(), token.getTokenName(), token.getId(),
				token.getUserName(),
				token.getCreationDate(), token.getExpirationDate());
	}

	UIToken(
			final TokenType type,
			final String tokenName,
			final UUID id,
			final UserName userName,
			final Date creationDate,
			final Date expirationDate) {
		this.type = type.getDescription();
		this.id = id.toString();
		this.name = tokenName;
		this.user = userName.getName();
		this.expires = expirationDate.getTime();
		this.created = creationDate.getTime();
	}
	
	public String getType() {
		return type;
	}

	public String getId() {
		return id;
	}

	public long getCreated() {
		return created;
	}

	public long getExpires() {
		return expires;
	}

	public String getName() {
		return name;
	}

	public String getUser() {
		return user;
	}

}
