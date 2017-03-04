package us.kbase.auth2.lib.identity;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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

/** An identity provider for the <a href="https://globus.org" target="_blank">Globus</a> service.
 * @author gaprice@lbl.gov
 *
 */
public class GlobusIdentityProvider implements IdentityProvider {

	/* Docs: https://docs.globus.org/api/auth/ */
	
	private static final String NAME = "Globus";
	private static final String SCOPE =
			"urn:globus:auth:scope:auth.globus.org:view_identities email";
	private static final String LOGIN_PATH = "/v2/oauth2/authorize";
	private static final String TOKEN_PATH = "/v2/oauth2/token";
	private static final String INTROSPECT_PATH = TOKEN_PATH + "/introspect";
	private static final String IDENTITIES_PATH = "/v2/api/identities";
	
	//thread safe
	private static final Client CLI = ClientBuilder.newClient();
	
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
	private final IdentityProviderConfig cfg;
	
	/** Create a new identity provider for the Globus service.
	 * @param idc the configuration for the provider.
	 */
	public GlobusIdentityProvider(final IdentityProviderConfig idc) {
		if (idc == null) {
			throw new NullPointerException("idc");
		}
		if (!GlobusIdentityProviderConfigurator.class.getName().equals(
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
	
	// state will be url encoded.
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

	private static class Idents {
		public final RemoteIdentity primary;
		public final Set<String> secondaryIDs;
		
		public Idents(RemoteIdentity primary, Set<String> secondaryIDs) {
			super();
			this.primary = primary;
			this.secondaryIDs = secondaryIDs;
		}
	}
	
	@Override
	public Set<RemoteIdentity> getIdentities(final String authcode, final boolean link)
			throws IdentityRetrievalException {
		/* Note authcode only works once. After that globus returns
		 * {error=invalid_grant}
		 */
		if (authcode == null || authcode.trim().isEmpty()) {
			throw new IllegalArgumentException("authcode cannot be null or empty");
		}
		final String accessToken = getAccessToken(authcode, link);
		final Idents idents = getPrimaryIdentity(accessToken);
		final Set<RemoteIdentity> secondaries = getSecondaryIdentities(
				accessToken, idents.secondaryIDs);
		secondaries.add(idents.primary);
		return secondaries;
	}

	private Set<RemoteIdentity> getSecondaryIdentities(
			final String accessToken,
			final Set<String> secondaryIDs)
			throws IdentityRetrievalException {
		if (secondaryIDs.isEmpty()) {
			return new HashSet<>();
		}
		final URI idtarget = UriBuilder.fromUri(toURI(cfg.getApiURL()))
				.path(IDENTITIES_PATH)
				.queryParam("ids", String.join(",", secondaryIDs))
				.build();
		
		final Map<String, Object> ids; 
		try {
			ids = globusGetRequest(accessToken, idtarget);
		} catch (IdentityRetrievalException e) {
			//hacky. switch to internal exception later
			final String[] msg = e.getMessage().split(":", 2);
			throw new IdentityRetrievalException("Secondary identity retrieval failed: " +
					msg[msg.length - 1].trim());
		}
		@SuppressWarnings("unchecked")
		final List<Map<String, String>> sids = (List<Map<String, String>>) ids.get("identities");
		final Set<RemoteIdentity> idents = makeIdentities(sids);
		final Set<String> got = idents.stream().map(i -> i.getRemoteID().getId())
				.collect(Collectors.toSet());
		if (!secondaryIDs.equals(got)) {
			
			throw new IdentityRetrievalException(String.format(
					"Requested secondary identities do not match recieved: %s vs %s",
					sort(secondaryIDs), sort(got)));
		}
		return idents;
	}

	private List<String> sort(final Set<String> s) {
		final List<String> l = new ArrayList<>(s);
		Collections.sort(l);
		return l;
	}

	private Idents getPrimaryIdentity(final String accessToken) throws IdentityRetrievalException {
		
		final URI target = UriBuilder.fromUri(toURI(cfg.getApiURL()))
				.path(INTROSPECT_PATH).build();
		
		final MultivaluedMap<String, String> formParameters = new MultivaluedHashMap<>();
		formParameters.add("token", accessToken);
		formParameters.add("include", "identities_set");
		
		final Map<String, Object> m;
		try {
			// if the token is invalid or not included globus returns a 401 with {"active": false}
			m = globusPostRequest(formParameters, target);
		} catch (IdentityRetrievalException e) {
			//hacky. switch to internal exception later
			final String[] msg = e.getMessage().split(":", 2);
			throw new IdentityRetrievalException("Primary identity retrieval failed: " +
					msg[msg.length - 1].trim());
		}
		// per Globus spec, check that the audience for the requests includes
		// our client
		@SuppressWarnings("unchecked")
		final List<String> audience = (List<String>) m.get("aud");
		if (!audience.contains(cfg.getClientID())) {
			throw new IdentityRetrievalException("The audience for the Globus request does not " +
					"include this client");
		}
		final String id = ((String) m.get("sub")).trim();
		final String username = (String) m.get("username");
		final String name = (String) m.get("name");
		final String email = (String) m.get("email");
		final RemoteIdentity primary = new RemoteIdentity(
				new RemoteIdentityID(NAME, id),
				new RemoteIdentityDetails(username, name, email));
		@SuppressWarnings("unchecked")
		final List<String> secids = (List<String>) m.get("identities_set");
		trim(secids);
		secids.remove(id); // avoids another call to globus if no other ids
		
		return new Idents(primary, new HashSet<>(secids));
	}

	private void trim(final List<String> s) {
		for (int i = 0; i < s.size(); i++) {
			s.set(i, s.get(i).trim());
		}
	}

	private Set<RemoteIdentity> makeIdentities(
			final List<Map<String, String>> sids) {
		final Set<RemoteIdentity> ret = new HashSet<>();
		for (final Map<String, String> id: sids) {
			final String uid = (String) id.get("id");
			final String username = (String) id.get("username");
			final String name = (String) id.get("name");
			final String email = (String) id.get("email");
			final RemoteIdentity rid = new RemoteIdentity(
					new RemoteIdentityID(NAME, uid),
					new RemoteIdentityDetails(username, name, email));
			ret.add(rid);
		}
		return ret;
	}

	private String getAccessToken(final String authcode, final boolean link)
			throws IdentityRetrievalException {
		
		final MultivaluedMap<String, String> formParameters = new MultivaluedHashMap<>();
		formParameters.add("code", authcode);
		formParameters.add("redirect_uri", link ?
				cfg.getLinkRedirectURL().toString() :
				cfg.getLoginRedirectURL().toString());
		formParameters.add("grant_type", "authorization_code");
		
		final URI target = UriBuilder.fromUri(toURI(cfg.getApiURL())).path(TOKEN_PATH).build();
		
		final Map<String, Object> m;
		try {
			m = globusPostRequest(formParameters, target);
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

	private Map<String, Object> globusPostRequest(
			final MultivaluedMap<String, String> formParameters,
			final URI target)
			throws IdentityRetrievalException {
		final String bauth = "Basic " + Base64.getEncoder().encodeToString(
				(cfg.getClientID() + ":" + cfg.getClientSecret()).getBytes());
		final WebTarget wt = CLI.target(target);
		Response r = null;
		try {
			r = wt.request(MediaType.APPLICATION_JSON_TYPE)
					.header("Authorization", bauth)
					.post(Entity.form(formParameters));
			return processResponse(r, 200);
		} finally {
			if (r != null) {
				r.close();
			}
		}
	}
	

	private Map<String, Object> globusGetRequest(
			final String accessToken,
			final URI idtarget)
			throws IdentityRetrievalException {
		final WebTarget wt = CLI.target(idtarget);
		Response r = null;
		try {
			r = wt.request(MediaType.APPLICATION_JSON_TYPE)
					.header("Authorization", "Bearer " + accessToken)
					.get();
			return processResponse(r, 200);
		} finally {
			if (r != null) {
				r.close();
			}
		}
	}
	
	private Map<String, Object> processResponse(final Response r, final int expectedCode)
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
			final String res = r.readEntity(String.class); // we'll assume here that this is small
			final Map<String, Object> m;
			try {  // could check content-type but same result, so...
				m = MAPPER.readValue(res, new TypeReference<Map<String, Object>>() {});
			} catch (IOException e) { // bad JSON
				throw new IdentityRetrievalException(String.format(
						"Got unexpected HTTP code and unparseable response from %s service: %s.",
						NAME, r.getStatus()) + getTruncatedEntityBody(res));
			}
			if (m.containsKey("error")) { // authtoken & primary ID
				throw new IdentityRetrievalException(String.format(
						"%s service returned an error. HTTP code: %s. Error: %s.",
						NAME, r.getStatus(), m.get("error")));
			} else if (m.containsKey("errors")) { // secondary ID
				// all kinds of type checking could be done here; let's just assume Globus doesn't
				// alter their API willy nilly and not do it
				@SuppressWarnings("unchecked")
				final List<Map<String, String>> errors =
						(List<Map<String, String>>) m.get("errors");
				// just deal with the first error for now, change later if necc
				if (errors == null || errors.isEmpty()) {
					throw new IdentityRetrievalException(String.format(
						"Got unexpected HTTP code with null error in the response body from %s " +
						"service: %s.", NAME, r.getStatus()));
				}
				final Map<String, String> err = errors.get(0);
				// could check the keys exist, but then what? null isn't much worse than reporting
				// a missing key. leave as is for now
				throw new IdentityRetrievalException(String.format(
						"%s service returned an error. HTTP code: %s. Error %s: %s; id: %s",
						NAME, r.getStatus(), err.get("code"), err.get("detail"), err.get("id")));
			} else {
				throw new IdentityRetrievalException(String.format(
						"Got unexpected HTTP code with no error in the response body from %s " +
						"service: %s.", NAME, r.getStatus()));
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
	
	/** A configurator for a Globus identity provider.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class GlobusIdentityProviderConfigurator implements
			IdentityProviderConfigurator {

		@Override
		public IdentityProvider configure(final IdentityProviderConfig cfg) {
			return new GlobusIdentityProvider(cfg);
		}

		@Override
		public String getProviderName() {
			return NAME;
		}
	}

}
