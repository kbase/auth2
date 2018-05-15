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
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;

/** A factory for a Google identity provider.
 * @author gaprice@lbl.gov
 *
 */
public class GoogleIdentityProviderFactory implements IdentityProviderFactory {

	@Override
	public IdentityProvider configure(final IdentityProviderConfig cfg) {
		return new GoogleIdentityProvider(cfg);
	}
	
	/** An identity provider for Google accounts.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class GoogleIdentityProvider implements IdentityProvider {
	
		/* Get creds: https://console.developers.google.com/apis
		 * Google+ API must be enabled
		 * Docs:
		 * https://developers.google.com/identity/protocols/OAuth2
		 * https://developers.google.com/identity/protocols/OAuth2WebServer
		 * https://developers.google.com/+/web/api/rest/oauth#login-scopes
		 * https://developers.google.com/+/web/api/rest/latest/people/get
		 * https://developers.google.com/+/web/api/rest/latest/people
		 */
		
		private static final String NAME = "Google";
		private static final String SCOPE =
				"https://www.googleapis.com/auth/plus.me profile email";
		private static final String LOGIN_PATH = "/o/oauth2/v2/auth";
		private static final String TOKEN_PATH = "/oauth2/v4/token";
		private static final String IDENTITY_PATH = "/plus/v1/people/me";
		
		//thread safe
		private static final Client CLI = ClientBuilder.newClient();
		
		private static final ObjectMapper MAPPER = new ObjectMapper();
		
		private final IdentityProviderConfig cfg;
		
		/** Create an identity provider for Google.
		 * @param idc the configuration for this provider.
		 */
		public GoogleIdentityProvider(final IdentityProviderConfig idc) {
			nonNull(idc, "idc");
			if (!GoogleIdentityProviderFactory.class.getName().equals(
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
		
		// state will be url encoded
		@Override
		public URL getLoginURL(final String state, final boolean link) {
			final URI target = UriBuilder.fromUri(toURI(cfg.getLoginURL()))
					.path(LOGIN_PATH)
					.queryParam("scope", SCOPE)
					.queryParam("state", state)
					.queryParam("redirect_uri", link ? cfg.getLinkRedirectURL() :
						cfg.getLoginRedirectURL())
					.queryParam("response_type", "code")
					.queryParam("client_id", cfg.getClientID())
					.queryParam("prompt", "select_account")
					.build();
			return toURL(target);
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
			final String accessToken = getAccessToken(authcode, link);
			final RemoteIdentity ri = getIdentity(accessToken);
			return new HashSet<>(Arrays.asList(ri));
		}
	
		private RemoteIdentity getIdentity(final String accessToken)
				throws IdentityRetrievalException {
			final URI target = UriBuilder.fromUri(toURI(cfg.getApiURL()))
					.path(IDENTITY_PATH).build();
			final Map<String, Object> id = googleGetRequest(accessToken, target);
			// could do a whooole lot of type checking here. We'll just assume Google aren't
			// buttholes that change their API willy nilly
			@SuppressWarnings("unchecked")
			final List<Map<String, String>> emails = (List<Map<String, String>>) id.get("emails");
			if (emails == null || emails.isEmpty()) {
				throw new IdentityRetrievalException("No username included in response from " +
						NAME);
			}
			// we'll also just grab the first email and assume that if it's null or empty something
			// is very wrong @ Google
			final String email = emails.get(0).get("value");
			if (email == null || email.trim().isEmpty()) {
				throw new IdentityRetrievalException("No username included in response from " +
						NAME);
			}
			return new RemoteIdentity(
					new RemoteIdentityID(NAME, (String) id.get("id")),
					new RemoteIdentityDetails(
							email, // use email for user id
							(String) id.get("displayName"),
							email));
		}
	
		private Map<String, Object> googleGetRequest(
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
						// ignoring type checking again, assuming that Google aren't jerks
						@SuppressWarnings("unchecked")
						final Map<String, Object> m = (Map<String, Object>) response.get("error");
						// there's more details in the 'errors' key but ignore that for now
						// could log later
						if (m == null || !m.containsKey("message")) {
							throw new IdentityRetrievalException(String.format(
									"Got unexpected HTTP code with null error in the response " +
									"body from %s service: %s.", NAME, r.getStatus()));
						}
						throw new IdentityRetrievalException(String.format(
								"%s service returned an error. HTTP code: %s. Error: %s",
								NAME, r.getStatus(), m.get("message")));
					}
				});
			} finally {
				if (r != null) {
					r.close();
				}
			}
		}
	
		private String getAccessToken(final String authcode, final boolean link)
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
			
			final URI target = UriBuilder.fromUri(toURI(cfg.getApiURL()))
					.path(TOKEN_PATH).build();
			
			final Map<String, Object> m;
			try {
				m = googlePostRequest(formParameters, target);
			} catch (IdentityRetrievalException e) {
				//hacky. switch to internal exception later
				final String[] msg = e.getMessage().split(":", 2);
				throw new IdentityRetrievalException("Authtoken retrieval failed: " +
						msg[msg.length - 1].trim());
			}
			final String token = (String) m.get("access_token");
			if (token == null || token.trim().isEmpty()) {
				throw new IdentityRetrievalException("No access token was returned by " + NAME);
			}
			return token;
		}
	
		private Map<String, Object> googlePostRequest(
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
							"Unable to parse response from %s service.", NAME));
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
