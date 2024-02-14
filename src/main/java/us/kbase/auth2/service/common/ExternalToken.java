package us.kbase.auth2.service.common;

import static java.util.Objects.requireNonNull;

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
		requireNonNull(storedToken, "storedToken");
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (created ^ (created >>> 32));
		result = prime * result + ((custom == null) ? 0 : custom.hashCode());
		result = prime * result + (int) (expires ^ (expires >>> 32));
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		result = prime * result + ((user == null) ? 0 : user.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ExternalToken other = (ExternalToken) obj;
		if (created != other.created) {
			return false;
		}
		if (custom == null) {
			if (other.custom != null) {
				return false;
			}
		} else if (!custom.equals(other.custom)) {
			return false;
		}
		if (expires != other.expires) {
			return false;
		}
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		} else if (!name.equals(other.name)) {
			return false;
		}
		if (type == null) {
			if (other.type != null) {
				return false;
			}
		} else if (!type.equals(other.type)) {
			return false;
		}
		if (user == null) {
			if (other.user != null) {
				return false;
			}
		} else if (!user.equals(other.user)) {
			return false;
		}
		return true;
	}
}
