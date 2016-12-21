package us.kbase.auth2.lib.identity;

/** An ID for a remote identity, consisting of the identity provider's name and a unique, immutable
 * ID for the identity created by the provider.
 * @author gaprice@lbl.gov
 *
 */
public class RemoteIdentityID {

	private final String provider;
	private final String id;

	/** Create a remote identity ID.
	 * @param provider the name of the provider that is providing the identity.
	 * @param id the unique, immutable ID the provider uses for the identity.
	 */
	public RemoteIdentityID(final String provider, final String id) {
		if (provider == null || provider.trim().isEmpty()) {
			throw new IllegalArgumentException("provider cannot be null or empty");
		}
		if (id == null || id.trim().isEmpty()) {
			throw new IllegalArgumentException("id cannot be null or empty");
		}
		this.provider = provider.trim();
		this.id = id.trim();
	}
	
	/** Get the provider name.
	 * @return the provider name.
	 */
	public String getProvider() {
		return provider;
	}
	
	/** Get the identity ID.
	 * @return the identity ID.
	 */
	public String getId() {
		return id;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + id.hashCode();
		result = prime * result + provider.hashCode();
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
		if (!id.equals(other.id)) {
			return false;
		}
		if (!provider.equals(other.provider)) {
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
