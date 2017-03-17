package us.kbase.auth2.lib.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** An ID for a remote identity, consisting of the identity provider's name and a unique, immutable
 * ID for the identity created by the provider.
 * @author gaprice@lbl.gov
 *
 */
public class RemoteIdentityID {

	private String memoizedID = null;
	private final String provider;
	private final String providerIdentID;

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
		this.providerIdentID = id.trim();
	}
	
	/** Get a probabilistically unique ID for the combination of the provider name and provider
	 *  identity id. This id should be not be used for security purposes; always ensure that the
	 *  agent requesting access to the identity is authorized via other means.
	 *  
	 *  Currently this ID is implemented per the pseudocode:
	 *  <p><code>
	 *  md5(getProviderName() + "_" + getProviderIdentityID())
	 *  </code></p>
	 *  
	 *  The ID is subjected to a MD5 digest to prevent abstraction-challenged programmers from
	 *  parsing the ID.
	 */
	public String getID() {
		if (memoizedID == null) {
			final MessageDigest digester;
			try {
				digester = MessageDigest.getInstance("MD5");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("This should be impossible", e);
			}
			final byte[] digest = digester.digest(
					(provider + "_" + providerIdentID).getBytes(StandardCharsets.UTF_8));
			final StringBuilder sb = new StringBuilder();
			for (final byte b : digest) {
				sb.append(String.format("%02x", b));
			}
			memoizedID = sb.toString();
		}
		
		return memoizedID;
	}
	
	/** Get the provider name.
	 * @return the provider name.
	 */
	public String getProviderName() {
		return provider;
	}
	
	/** Get the provider's ID for the identity.
	 * @return the identity ID.
	 */
	public String getProviderIdentityId() {
		return providerIdentID;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((providerIdentID == null) ? 0 : providerIdentID.hashCode());
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
		if (providerIdentID == null) {
			if (other.providerIdentID != null) {
				return false;
			}
		} else if (!providerIdentID.equals(other.providerIdentID)) {
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
		builder.append(providerIdentID);
		builder.append("]");
		return builder.toString();
	}
}
