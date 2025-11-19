package us.kbase.auth2.service.common;

import static java.util.Objects.requireNonNull;

import java.util.Map;
import java.util.Objects;

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
	private final String mfa;

	public ExternalToken(final StoredToken storedToken) {
		requireNonNull(storedToken, "storedToken");
		type = storedToken.getTokenType().getDescription();
		id = storedToken.getId().toString();
		name = storedToken.getTokenName().isPresent() ?
				storedToken.getTokenName().get().getName() : null;
		user = storedToken.getUserName().getName();
		expires = storedToken.getExpirationDate().toEpochMilli();
		created = storedToken.getCreationDate().toEpochMilli();
		custom = storedToken.getContext().getCustomContext();
		mfa = storedToken.getMFA().getDescription();
	}

	public String getType() {
		return type;
	}
	
	public String getMfa() { // must be Lowercase or templates don't work
		return mfa;
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

	@Override
	public int hashCode() {
		return Objects.hash(created, custom, expires, id, mfa, name, type, user);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ExternalToken other = (ExternalToken) obj;
		return created == other.created
				&& Objects.equals(custom, other.custom)
				&& expires == other.expires
				&& Objects.equals(id, other.id)
				&& Objects.equals(mfa, other.mfa)
				&& Objects.equals(name, other.name)
				&& Objects.equals(type, other.type)
				&& Objects.equals(user, other.user);
	}
}
