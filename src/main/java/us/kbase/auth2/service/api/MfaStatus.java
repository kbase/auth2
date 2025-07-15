package us.kbase.auth2.service.api;

import static us.kbase.auth2.service.common.ServiceCommon.getToken;

import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.user.AuthUser;

/**
 * API endpoint for checking multi-factor authentication status of user tokens.
 * 
 * This endpoint allows clients to determine if a user's current session was 
 * authenticated using multi-factor authentication via supported identity providers.
 */
@Path(APIPaths.API_V2_MFA_STATUS)
public class MfaStatus {

	@Inject
	private Authentication auth;

	/**
	 * Returns the MFA authentication status for the current user token.
	 * 
	 * Checks if the user authenticated using multi-factor authentication through
	 * supported identity providers (currently ORCID with OpenID Connect).
	 * 
	 * @param token the user's authentication token in the Authorization header
	 * @return JSON object containing MFA status information
	 * @throws InvalidTokenException if the token is invalid or expired
	 * @throws AuthStorageException if there's a database access error
	 * @throws NoTokenProvidedException if no token is provided
	 * @throws DisabledUserException if the user account is disabled
	 */
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> getMfaStatus(
			@HeaderParam("Authorization") final String token)
			throws InvalidTokenException, AuthStorageException, NoTokenProvidedException,
				DisabledUserException {
		
		final AuthUser user = auth.getUser(getToken(token));
		
		// Check for ORCID identities with MFA information
		Boolean orcidMfaUsed = null;
		String providerName = null;
		
		final Set<RemoteIdentity> identities = user.getIdentities();
		for (final RemoteIdentity identity : identities) {
			if ("OrcID".equals(identity.getRemoteID().getProviderName())) {
				final Boolean mfaStatus = identity.getDetails().isMfaAuthenticated();
				if (mfaStatus != null) {
					orcidMfaUsed = mfaStatus;
					providerName = identity.getRemoteID().getProviderName();
					break; // Use the first ORCID identity with MFA information
				}
			}
		}
		
		if (orcidMfaUsed != null) {
			return ImmutableMap.of(
				"provider", providerName,
				"mfa_used", orcidMfaUsed,
				"status", orcidMfaUsed ? "mfa_authenticated" : "password_only"
			);
		} else {
			return ImmutableMap.of(
				"provider", "none",
				"mfa_used", (Object) null,
				"status", "no_mfa_info_available"
			);
		}
	}
}