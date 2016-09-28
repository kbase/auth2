package us.kbase.auth2.lib.identity;

public class RemoteIdentityID {

	//TODO TEST
	//TODO JAVADOC
	
	private final String provider;
	private final String id;

	public RemoteIdentityID(final String provider, final String id) {
		if (provider == null || provider.trim().isEmpty()) {
			throw new IllegalArgumentException(
					"provider cannot be null or empty");
		}
		if (id == null || id.trim().isEmpty()) {
			throw new IllegalArgumentException(
					"id cannot be null or empty");
		}
		this.provider = provider.trim();
		this.id = id.trim();
	}
	
	public String getProvider() {
		return provider;
	}
	
	public String getId() {
		return id;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((provider == null) ? 0 : provider.hashCode());
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
		RemoteIdentityID other = (RemoteIdentityID) obj;
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		if (provider == null) {
			if (other.provider != null) {
				return false;
			}
		} else if (!provider.equals(other.provider)) {
			return false;
		}
		return true;
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RemoteIdentityID [provider=");
		builder.append(provider);
		builder.append(", id=");
		builder.append(id);
		builder.append("]");
		return builder.toString();
	}
}
