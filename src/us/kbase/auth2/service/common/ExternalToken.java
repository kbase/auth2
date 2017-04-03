package us.kbase.auth2.service.common;

import java.util.Map;

import us.kbase.auth2.lib.token.StoredToken;

public class ExternalToken {
	
	//TODO TEST
	//TODO JAVADOC
	
	private final String type;
	private final String id;
	private final long expires;
	private final long created;
	private final String name;
	private final String user;
	private final Map<String, String> custom;

	public ExternalToken(final StoredToken st) {
		type = st.getTokenType().getDescription();
		id = st.getId().toString();
		name = st.getTokenName().isPresent() ? st.getTokenName().get().getName() : null;
		user = st.getUserName().getName();
		expires = st.getExpirationDate().toEpochMilli();
		created = st.getCreationDate().toEpochMilli();
		custom = st.getContext().getCustomContext();
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
