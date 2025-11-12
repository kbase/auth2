package us.kbase.auth2.providers;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.LoggerFactory;

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.MfaStatus;
import us.kbase.auth2.lib.identity.RemoteIdentityID;

/** A factory for a OrcID identity provider.
 * @author gaprice@lbl.gov
 *
 */
public class OrcIDIdentityProviderFactory implements IdentityProviderFactory {

	@Override
	public IdentityProvider configure(final IdentityProviderConfig cfg) {
		return new OrcIDIdentityProvider(cfg);
	}
	
	/** An identity provider for OrcID accounts.
	 *
	 * Multi-Factor Authentication (MFA) Status Handling:
	 * - Uses OpenID Connect JWT tokens to determine MFA status via AMR claims
	 * - Configuration option "orcid-mfa-enabled" (default: true):
	 *   - true: Requires OpenID scope, throws error on malformed JWT
	 *   - false: Skips MFA check, returns MfaStatus.UNKNOWN (for non-member API apps)
	 * - Valid JWT with AMR claim: returns MfaStatus.USED or MfaStatus.NOT_USED based on "mfa" presence
	 *
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class OrcIDIdentityProvider implements IdentityProvider {

		// notes: I haven't been able to find documentation re the OrcID error structure, so I've
		// reversed engineered it by passing bad input. Hopefully what I've got covers all the
		// possibilities.

		/* Get creds: https://sandbox.orcid.org/developer-tools */

		private static final String NAME = "OrcID";
		private static final String SCOPE_OPENID = "openid /authenticate";
		private static final String SCOPE_NO_OPENID = "/authenticate";
		private static final String LOGIN_PATH = "/oauth/authorize";
		private static final String TOKEN_PATH = "/oauth/token";
		private static final String RECORD_PATH = "/v2.1";
		private static final String CFG_MFA_ENABLED = "orcid-mfa-enabled";
		
		//thread safe
		private static final Client CLI = ClientBuilder.newClient();

		private static final ObjectMapper MAPPER = new ObjectMapper();

		private final IdentityProviderConfig cfg;
		
		/** Create an identity provider for OrcID.
		 * @param idc the configuration for this provider.
		 */
		public OrcIDIdentityProvider(final IdentityProviderConfig idc) {
			requireNonNull(idc, "idc");
			if (!OrcIDIdentityProviderFactory.class.getName().equals(
					idc.getIdentityProviderFactoryClassName())) {
				throw new IllegalArgumentException(
						"Configuration class name doesn't match factory class name: " +
						idc.getIdentityProviderFactoryClassName());
			}
			this.cfg = idc;
		}
	
		@Override
		public String getProviderName() {
			return NAME;
		}
		
		@Override
		public Set<String> getEnvironments() {
			return cfg.getEnvironments();
		}

		// state will be url encoded
		@Override
		public URI getLoginURI(
				final String state,
				final String pkceCodeChallenge,
				final boolean link,
				final String environment)
				throws NoSuchEnvironmentException {
			// note that OrcID does not currently implement PKCE so we ignore the code
			// challenge: https://github.com/ORCID/ORCID-Source/issues/5977
			final boolean mfaEnabled = Boolean.parseBoolean(
					cfg.getCustomConfiguation().getOrDefault(CFG_MFA_ENABLED, "true"));
			final String scope = mfaEnabled ? SCOPE_OPENID : SCOPE_NO_OPENID;

			return UriBuilder.fromUri(toURI(cfg.getLoginURL()))
					.path(LOGIN_PATH)
					.queryParam("scope", scope)
					.queryParam("state", state)
					.queryParam("redirect_uri", getRedirectURL(link, environment))
					.queryParam("response_type", "code")
					.queryParam("client_id", cfg.getClientID())
					.build();
		}
		
		private URL getRedirectURL(final boolean link, final String environment)
				throws NoSuchEnvironmentException {
			if (environment == null) {
				return link ? cfg.getLinkRedirectURL() : cfg.getLoginRedirectURL();
			}
			return link ? cfg.getLinkRedirectURL(environment) :
				cfg.getLoginRedirectURL(environment);
		}
		
		//Assumes valid URI in URL form
		private URI toURI(final URL loginURL) {
			try {
				return loginURL.toURI();
			} catch (URISyntaxException e) {
				throw new RuntimeException("This should be impossible", e);
			}
		}
	
		@Override
		public Set<RemoteIdentity> getIdentities(
				final String authcode,
				final String pkceCodeVerifier,
				final boolean link,
				final String environment)
				throws IdentityRetrievalException, NoSuchEnvironmentException {
			// note that OrcID does not currently implement PKCE so we ignore the code
			// verifier: https://github.com/ORCID/ORCID-Source/issues/5977
			if (authcode == null || authcode.trim().isEmpty()) {
				throw new IllegalArgumentException("authcode cannot be null or empty");
			}
			final OrcIDAccessTokenResponse accessToken = getAccessToken(
					authcode, link, environment);
			final RemoteIdentity ri = getIdentity(accessToken);
			return new HashSet<>(Arrays.asList(ri));
		}
	
		private RemoteIdentity getIdentity(final OrcIDAccessTokenResponse accessToken)
				throws IdentityRetrievalException {
			final URI target = UriBuilder.fromUri(toURI(cfg.getApiURL()))
					.path(RECORD_PATH + "/" + accessToken.orcID + "/email").build();
			final Map<String, Object> id = orcIDGetRequest(accessToken.accessToken, target);
			// could do a whooole lot of type checking here. We'll just assume OrcID aren't
			// buttholes that change their API willy nilly
			@SuppressWarnings("unchecked")
			final List<Map<String, Object>> emails = (List<Map<String, Object>>) id.get("email");
			String email;
			if (emails == null || emails.isEmpty()) {
				email = null;
			} else {
				email = (String) emails.get(0).get("email");
			}
			if (email == null || email.trim().isEmpty()) {
				email = null;
			}
			return new RemoteIdentity(
					new RemoteIdentityID(NAME, accessToken.orcID),
					new RemoteIdentityDetails(
							accessToken.orcID,
							accessToken.fullName,
							email,
							accessToken.mfa));
		}
	
		private Map<String, Object> orcIDGetRequest(
				final String accessToken,
				final URI target)
				throws IdentityRetrievalException {
			final WebTarget wt = CLI.target(target);
			Response r = null;
			try {
				r = wt.request(MediaType.APPLICATION_JSON_TYPE)
						.header("Authorization", "Bearer " + accessToken)
						.get();
				return processResponse(r, 200, new ErrorHandler() {
					
					@Override
					public void handleError(final Response r, final Map<String, Object> response)
							throws IdentityRetrievalException {
						throw new IdentityRetrievalException(String.format(
								"%s service returned an error. HTTP code: %s. Error: %s. " +
								"Error description: %s",
								NAME, r.getStatus(), response.get("error"),
								response.get("error_description")));
					}
				});
			} finally {
				if (r != null) {
					r.close();
				}
			}
		}
		
		/**
		 * Parses the Authentication Method Reference (AMR) claim from an OpenID Connect ID token
		 * to determine if multi-factor authentication was used.
		 *
		 * @param jwt the JWT ID token from ORCID
		 * @return MfaStatus indicating whether MFA was used
		 * @throws IdentityRetrievalException if JWT is missing, malformed, or unparseable
		 */
		private MfaStatus parseAmrClaim(final String jwt) throws IdentityRetrievalException {
			if (jwt == null || jwt.trim().isEmpty()) {
				throw new IdentityRetrievalException(
						"No JWT token provided by ORCID. For non-member API applications, " +
						"set orcid-mfa-enabled=false in provider configuration");
			}
			
			// JWT format: header.payload.signature
			final String[] parts = jwt.split("\\.");
			if (parts.length != 3) {
				// Invalid JWT format
				throw new IdentityRetrievalException("Invalid JWT format from ORCID: expected 3 parts, got " + parts.length);
			}

			// Decode the payload (second part) - URL-safe base64
			final String payload;
			try {
				payload = new String(Base64.getUrlDecoder().decode(parts[1]));
			} catch (IllegalArgumentException e) {
				// Base64 decoding failed - invalid JWT format
				LoggerFactory.getLogger(OrcIDIdentityProviderFactory.class).warn("Unable to decode JWT from ORCID: {}", e.getMessage());
				throw new IdentityRetrievalException("Unable to decode JWT from ORCID: " + e.getMessage(), e);
			}

			// Parse JSON payload to extract claims
			final Map<String, Object> claims;
			try {
				@SuppressWarnings("unchecked")
				final Map<String, Object> parsedClaims = MAPPER.readValue(payload, Map.class);
				claims = parsedClaims;
			} catch (IOException e) {
				// JSON parsing failed - malformed payload
				LoggerFactory.getLogger(OrcIDIdentityProviderFactory.class).warn("Unable to parse JWT payload from ORCID: {}", e.getMessage());
				throw new IdentityRetrievalException("Unable to parse JWT payload from ORCID: " + e.getMessage(), e);
			}

			final Object amrClaim = claims.get("amr");
			if (amrClaim == null) {
				// No AMR claim present - MFA status unknown
				return MfaStatus.UNKNOWN;
			} else if (amrClaim instanceof List) {
				// OpenID Connect spec: AMR should be an array of strings
				@SuppressWarnings("unchecked")
				final List<String> amrList = (List<String>) amrClaim;
				return amrList.contains("mfa") ? MfaStatus.USED : MfaStatus.NOT_USED;
			} else if (amrClaim instanceof String) {
				// ORCID may return single string - handle as fallback
				return "mfa".equals(amrClaim) ? MfaStatus.USED : MfaStatus.NOT_USED;
			}

			// AMR claim present but in unexpected format
			throw new IdentityRetrievalException("AMR claim from ORCID in unexpected format: " + amrClaim);
		}
	
		private static class OrcIDAccessTokenResponse {
			
			private final String accessToken;
			private final String fullName;
			private final String orcID;
			private final MfaStatus mfa;
			
			private OrcIDAccessTokenResponse(
					final String accessToken,
					final String fullName,
					final String orcID,
					final MfaStatus mfa)
					throws IdentityRetrievalException {
				if (accessToken == null || accessToken.trim().isEmpty()) {
					throw new IdentityRetrievalException(
							"No access token was returned by " + NAME);
				}
				if (orcID == null || orcID.trim().isEmpty()) {
					throw new IdentityRetrievalException("No id was returned by " + NAME);
				}
				
				this.accessToken = accessToken.trim();
				this.fullName = fullName == null ? null : fullName.trim();
				this.orcID = orcID.trim();
				this.mfa = mfa;
			}
		}
		
		private OrcIDAccessTokenResponse getAccessToken(
				final String authcode,
				final boolean link,
				final String environment)
				throws IdentityRetrievalException, NoSuchEnvironmentException {
			final MultivaluedMap<String, String> formParameters =
					new MultivaluedHashMap<>();
			formParameters.add("code", authcode);
			formParameters.add("redirect_uri", getRedirectURL(link, environment).toString());
			formParameters.add("grant_type", "authorization_code");
			formParameters.add("client_id", cfg.getClientID());
			formParameters.add("client_secret", cfg.getClientSecret());
			
			final URI target = UriBuilder.fromUri(toURI(cfg.getLoginURL()))
					.path(TOKEN_PATH).build();
			
			final Map<String, Object> m;
			try {
				m = orcIDPostRequest(formParameters, target);
			} catch (IdentityRetrievalException e) {
				//hacky. switch to internal exception later
				final String[] msg = e.getMessage().split(":", 2);
				throw new IdentityRetrievalException("Authtoken retrieval failed: " +
						msg[msg.length - 1].trim());
			}

			// Determine MFA status based on configuration
			final boolean mfaEnabled = Boolean.parseBoolean(
					cfg.getCustomConfiguation().getOrDefault(CFG_MFA_ENABLED, "true"));
			final MfaStatus mfaStatus;
			if (!mfaEnabled) {
				// MFA checking disabled - no OpenID scope, so no id_token expected
				mfaStatus = MfaStatus.UNKNOWN;
			} else {
				// MFA checking enabled - parse JWT from id_token
				final String idToken = (String) m.get("id_token");
				mfaStatus = parseAmrClaim(idToken);
			}

			return new OrcIDAccessTokenResponse(
					(String) m.get("access_token"),
					(String) m.get("name"),
					(String) m.get("orcid"),
					mfaStatus);
		}
	
		private Map<String, Object> orcIDPostRequest(
				final MultivaluedMap<String, String> formParameters,
				final URI target)
				throws IdentityRetrievalException {
			final WebTarget wt = CLI.target(target);
			Response r = null;
			try {
				r = wt.request(MediaType.APPLICATION_JSON_TYPE)
						.post(Entity.form(formParameters));
				return processResponse(r, 200, new ErrorHandler() {
					
					@Override
					public void handleError(final Response r, final Map<String, Object> response)
							throws IdentityRetrievalException {
						throw new IdentityRetrievalException(String.format(
								"%s service returned an error. HTTP code: %s. Error: %s. " +
								"Error description: %s",
								NAME, r.getStatus(), response.get("error"),
								response.get("error_description")));
					}
				});
			} finally {
				if (r != null) {
					r.close();
				}
			}
		}
		
		private interface ErrorHandler {
			void handleError(Response r, Map<String, Object> response)
					throws IdentityRetrievalException;
		}
		
		private Map<String, Object> processResponse(
				final Response r,
				final int expectedCode,
				final ErrorHandler handler)
				throws IdentityRetrievalException {
			if (r.getStatus() == expectedCode) {
				try { // could check content-type but same result, so...
					@SuppressWarnings("unchecked")
					final Map<String, Object> m = r.readEntity(Map.class);
					return m;
				} catch (ProcessingException e) { // not json
					// can't get the entity at this point because readEntity closes the stream
					// this should never happen in practice so don't worry about it for now
					throw new IdentityRetrievalException(String.format(
							"Unable to parse response from %s service.", NAME), e);
				}
			}
			if (r.hasEntity()) {
				// we'll assume here that this is small
				final String res = r.readEntity(String.class);
				final Map<String, Object> m;
				try {  // could check content-type but same result, so...
					m = MAPPER.readValue(res, new TypeReference<Map<String, Object>>() {});
				} catch (IOException e) { // bad JSON
					throw new IdentityRetrievalException(String.format(
							"Got unexpected HTTP code and unparseable response from %s service: " +
							"%s.", NAME, r.getStatus()) + getTruncatedEntityBody(res));
				}
				if (m.containsKey("error")) {
					handler.handleError(r, m);
					throw new RuntimeException("error handler didn't handle error");
				} else {
					throw new IdentityRetrievalException(String.format(
							"Got unexpected HTTP code with no error in the response body from " +
							"%s service: %s.", NAME, r.getStatus()));
				}
			}
			throw new IdentityRetrievalException(String.format(
					"Got unexpected HTTP code with no response body from %s service: %s.",
					NAME, r.getStatus()));
		}
	
		private String getTruncatedEntityBody(final String r) {
			if (r.length() > 1000) {
				return " Truncated response: " + r.substring(0, 1000);
			} else {
				return " Response: " + r;
			}
		}
	}
}
