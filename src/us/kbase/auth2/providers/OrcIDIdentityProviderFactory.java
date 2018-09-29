package us.kbase.auth2.providers;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
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

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
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
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class OrcIDIdentityProvider implements IdentityProvider {
		
		// notes: I haven't been able to find documentation re the OrcID error structure, so I've
		// reversed engineered it by passing bad input. Hopefully what I've got covers all the
		// possibilities.
	
		/* Get creds: https://sandbox.orcid.org/developer-tools */
		
		private static final String NAME = "OrcID";
		private static final String SCOPE = "/authenticate";
		private static final String LOGIN_PATH = "/oauth/authorize";
		private static final String TOKEN_PATH = "/oauth/token";
		private static final String RECORD_PATH = "/v2.1";
		
		//thread safe
		private static final Client CLI = ClientBuilder.newClient();
		
		private static final ObjectMapper MAPPER = new ObjectMapper();
		
		private final IdentityProviderConfig cfg;
		
		/** Create an identity provider for OrcID.
		 * @param idc the configuration for this provider.
		 */
		public OrcIDIdentityProvider(final IdentityProviderConfig idc) {
			nonNull(idc, "idc");
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
		public URL getLoginURL(final String state, final boolean link, final String environment)
				throws NoSuchEnvironmentException {
			final URI target = UriBuilder.fromUri(toURI(cfg.getLoginURL()))
					.path(LOGIN_PATH)
					.queryParam("scope", SCOPE)
					.queryParam("state", state)
					.queryParam("redirect_uri", getRedirectURL(link, environment))
					.queryParam("response_type", "code")
					.queryParam("client_id", cfg.getClientID())
					.build();
			return toURL(target);
		}
		
		private URL getRedirectURL(final boolean link, final String environment)
				throws NoSuchEnvironmentException {
			if (environment == null) {
				return link ? cfg.getLinkRedirectURL() : cfg.getLoginRedirectURL();
			}
			return link ? cfg.getLinkRedirectURL(environment) :
				cfg.getLoginRedirectURL(environment);
		}
		
		//Assumes valid URL in URI form
		private URL toURL(final URI baseURI) {
			try {
				return baseURI.toURL();
			} catch (MalformedURLException e) {
				throw new RuntimeException("This should be impossible", e);
			}
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
		public Set<RemoteIdentity> getIdentities(final String authcode, final boolean link)
				throws IdentityRetrievalException {
			if (authcode == null || authcode.trim().isEmpty()) {
				throw new IllegalArgumentException("authcode cannot be null or empty");
			}
			final OrcIDAccessTokenResponse accessToken = getAccessToken(authcode, link);
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
							email));
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
	
		private static class OrcIDAccessTokenResponse {
			
			private final String accessToken;
			private final String fullName;
			private final String orcID;
			
			private OrcIDAccessTokenResponse(
					final String accessToken,
					final String fullName,
					final String orcID)
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
			}
		}
		
		private OrcIDAccessTokenResponse getAccessToken(final String authcode, final boolean link)
				throws IdentityRetrievalException {
			final MultivaluedMap<String, String> formParameters =
					new MultivaluedHashMap<>();
			formParameters.add("code", authcode);
			formParameters.add("redirect_uri", link ?
					cfg.getLinkRedirectURL().toString() :
					cfg.getLoginRedirectURL().toString());
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
			return new OrcIDAccessTokenResponse(
					(String) m.get("access_token"),
					(String) m.get("name"),
					(String) m.get("orcid"));
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
