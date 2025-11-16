package us.kbase.auth2.lib.identity;

import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import us.kbase.auth2.lib.token.MFAStatus;

/** Response data from a 3rd party identity provider. */
public class IdentityProviderResponse {

	private final Set<RemoteIdentity> idents;
	private final MFAStatus mfa;

	private IdentityProviderResponse(final Set<RemoteIdentity> idents, final MFAStatus mfa) {
		// ensure class contents are immutable
		this.idents = Collections.unmodifiableSet(new HashSet<>(idents));
		this.mfa = mfa;
	}	
	
	/** Get the identities from the remote identity response.
	 * @return the identities.
	 */
	public Set<RemoteIdentity> getIdentities() {
		return idents;
	}

	/** Get the multifactor authentication status from the user login.
	 * @return the MFA status.
	 */
	public MFAStatus getMFA() {
		return mfa;
	}

	@Override
	public int hashCode() {
		return Objects.hash(idents, mfa);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		IdentityProviderResponse other = (IdentityProviderResponse) obj;
		return Objects.equals(idents, other.idents) && mfa == other.mfa;
	}

	/** Create the response.
	 * @param identity the identity the provider returned post user login.
	 * @return the response.
	 */
	public static IdentityProviderResponse from(final RemoteIdentity identity) {
		return from(Collections.singleton(requireNonNull(identity, "identity")));
	}

	
	/** Create the response.
	 * @param identities the identities the provider returned post user login.
	 * @return the response.
	 */
	public static IdentityProviderResponse from(final Set<RemoteIdentity> identities) {
		return from(identities, MFAStatus.UNKNOWN);
	}

	/** Create the response.
	 * @param identity the identity the provider returned post user login.
	 * @param mfa the multifactor authentication status of the response.
	 * @return the response.
	 */
	public static IdentityProviderResponse from(
			final RemoteIdentity identity,
			final MFAStatus mfa
	) {
		return from(Collections.singleton(requireNonNull(identity, "identity")), mfa);
	}
	
	
	/** Create the response.
	 * @param identities the identities the provider returned post user login.
	 * @param mfa the multifactor authentication status of the response.
	 * @return the response.
	 */
	public static IdentityProviderResponse from(
			final Set<RemoteIdentity> identities,
			final MFAStatus mfa
	) {
		requireNonNull(identities, "identities");
		if (identities.size() < 1) {
			throw new IllegalArgumentException("Must provide at least one identity");
		}
		return new IdentityProviderResponse(identities, requireNonNull(mfa, "mfa"));
	}
	
}
