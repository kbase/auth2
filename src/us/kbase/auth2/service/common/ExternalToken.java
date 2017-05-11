package us.kbase.auth2.service.common;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.Map;

import us.kbase.auth2.lib.token.StoredToken;

public class ExternalToken {
	
	//TODO JAVADOC or swagger
	
	private final String type;
	private final String id;
	private final long expires;
	private final long created;
	private final String name;
	private final String user;
	private final Map<String, String> custom;

	public ExternalToken(final StoredToken storedToken) {
		nonNull(storedToken, "storedToken");
		type = storedToken.getTokenType().getDescription();
		id = storedToken.getId().toString();
		name = storedToken.getTokenName().isPresent() ?
				storedToken.getTokenName().get().getName() : null;
		user = storedToken.getUserName().getName();
		expires = storedToken.getExpirationDate().toEpochMilli();
		created = storedToken.getCreationDate().toEpochMilli();
		custom = storedToken.getContext().getCustomContext();
	}

	public String getType() {
		return type;
	}

	public String getId() {
		return id;
	}

	public long getExpires() {
		return expires;
	}

	public long getCreated() {
		return created;
	}
	
	public String getName() {
		return name;
	}

	public String getUser() {
		return user;
	}

	public Map<String, String> getCustom() {
		return custom;
	}
}
