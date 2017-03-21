package us.kbase.auth2.service.common;

import java.time.Instant;
import java.util.UUID;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.TokenName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.TokenType;

public class ExternalToken {
	
	//TODO TEST
	//TODO JAVADOC
	
	private final String type;
	private final String id;
	private final long expires;
	private final long created;
	private final String name;
	private final String user;

	public ExternalToken(final HashedToken token) {
		this(token.getTokenType(), token.getTokenName(), token.getId(),
				token.getUserName(),
				token.getCreationDate(), token.getExpirationDate());
	}

	ExternalToken(
			final TokenType type,
			final Optional<TokenName> tokenName,
			final UUID id,
			final UserName userName,
			final Instant creationDate,
			final Instant expirationDate) {
		this.type = type.getDescription();
		this.id = id.toString();
		this.name = tokenName.isPresent() ? tokenName.get().getName() : null;
		this.user = userName.getName();
		this.expires = expirationDate.toEpochMilli();
		this.created = creationDate.toEpochMilli();
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
