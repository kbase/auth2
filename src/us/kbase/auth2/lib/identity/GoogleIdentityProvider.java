package us.kbase.auth2.lib.identity;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;

/** An identity provider for Google accounts.
 * @author gaprice@lbl.gov
 *
 */
public class GoogleIdentityProvider implements IdentityProvider {

	//TODO TEST
	
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
	
	private final IdentityProviderConfig cfg;
	
	/** Create an identity provider for Google.
	 * @param idc the configuration for this provider.
	 */
	public GoogleIdentityProvider(final IdentityProviderConfig idc) {
		if (idc == null) {
			throw new NullPointerException("idc");
		}
		if (!NAME.equals(idc.getIdentityProviderName())) {
			throw new IllegalArgumentException("Bad config name: " +
					idc.getIdentityProviderName());
		}
		this.cfg = idc;
	}

	@Override
	public String getProviderName() {
		return NAME;
	}
	
	@Override
	public URI getImageURI() {
		return cfg.getImageURI();
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
	public Set<RemoteIdentity> getIdentities(
			final String authcode,
			final boolean link) throws IdentityRetrievalException {
		final String accessToken = getAccessToken(authcode, link);
		final RemoteIdentity ri = getIdentity(accessToken);
		return new HashSet<>(Arrays.asList(ri));
	}

	private RemoteIdentity getIdentity(final String accessToken)
			throws IdentityRetrievalException {
		final URI target = UriBuilder.fromUri(toURI(cfg.getApiURL()))
				.path(IDENTITY_PATH).build();
		final Map<String, Object> id = googleGetRequest(
				accessToken, target);
		if (id.containsKey("error")) {
			//TODO IDPROVERROR better error handling
			throw new IdentityRetrievalException(
					"Provider error: " + id.get("error"));
		}
		@SuppressWarnings("unchecked")
		final List<Map<String, String>> emails =
				(List<Map<String, String>>) id.get("emails");
		final String email = emails.get(0).get("value");
		return new RemoteIdentity(
				new RemoteIdentityID(NAME, (String) id.get("id")),
				new RemoteIdentityDetails(
						email, // use email for user id
						(String) id.get("displayName"),
						email));
	}

	private Map<String, Object> googleGetRequest(
			final String accessToken,
			final URI target) {
		final WebTarget wt = CLI.target(target);
		Response r = null;
		try {
			r = wt.request(MediaType.APPLICATION_JSON_TYPE)
					.header("Authorization", "Bearer " + accessToken)
					.get();
			//TODO TEST with 500s with HTML
			@SuppressWarnings("unchecked")
			final Map<String, Object> mtemp = r.readEntity(Map.class);
			//TODO IDPROVERR handle {error=?} in object and check response code
			return mtemp;
		} finally {
			if (r != null) {
				r.close();
			}
		}
	}

	private String getAccessToken(final String authcode, final boolean link) {
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
		
		final Map<String, Object> m = googlePostRequest(
				formParameters, target);
		return (String) m.get("access_token");
	}

	private Map<String, Object> googlePostRequest(
			final MultivaluedMap<String, String> formParameters,
			final URI target) {
		final WebTarget wt = CLI.target(target);
		Response r = null;
		try {
			r = wt.request(MediaType.APPLICATION_JSON_TYPE)
					.post(Entity.form(formParameters));
			@SuppressWarnings("unchecked")
			//TODO TEST with 500s with HTML
			final Map<String, Object> mtemp = r.readEntity(Map.class);
			//TODO IDPROVERR handle {error=?} in object and check response code
			return mtemp;
		} finally {
			if (r != null) {
				r.close();
			}
		}
	}
	
	/** A configuratator for a Google identity provider.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class GoogleIdentityProviderConfigurator implements
			IdentityProviderConfigurator {

		@Override
		public IdentityProvider configure(final IdentityProviderConfig cfg) {
			return new GoogleIdentityProvider(cfg);
		}

		@Override
		public String getProviderName() {
			return NAME;
		}
	}
}
