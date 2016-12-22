package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.Header;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.identity.GlobusIdentityProvider;
import us.kbase.auth2.lib.identity.GlobusIdentityProvider.GlobusIdentityProviderConfigurator;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.test.auth2.TestCommon;

public class GlobusIdentityProviderTest {
	
	private static final String CONTENT_TYPE = "content-type";
	private static final String APP_JSON = "application/json";
	private static final String GLOBUS = "Globus";
	
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
	private static ClientAndServer mockClientAndServer;
	
	@BeforeClass
	public static void setUpClass() {
		mockClientAndServer = ClientAndServer.startClientAndServer(TestCommon.findFreePort());
	}
	
	@After
	public void tearDownTest() {
		mockClientAndServer.reset();
	}
	
	private static final IdentityProviderConfig CFG;
	static {
		try {
			CFG = new IdentityProviderConfig(
					"Globus",
					new URL("https://login.com"),
					new URL("https://setapiurl.com"),
					"foo",
					"bar",
					new URI("http://image.com"),
					new URL("https://loginredir.com"),
					new URL("https://linkredir.com"));
		} catch (IdentityProviderConfigurationException | URISyntaxException |
				MalformedURLException e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}

	@Test
	public void simpleOperationsWithConfigurator() throws Exception {
		final GlobusIdentityProviderConfigurator gc = new GlobusIdentityProviderConfigurator();
		assertThat("incorrect provider name", gc.getProviderName(), is("Globus"));
		
		final IdentityProvider gip = gc.configure(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Globus"));
		assertThat("incorrect image uri", gip.getImageURI(), is(new URI("http://image.com")));
		assertThat("incorrect login url", gip.getLoginURL("foo2", false),
				is(new URL("https://login.com/v2/oauth2/authorize?" +
						"scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+" +
						"email&state=foo2&redirect_uri=https%3A%2F%2Floginredir.com" +
						"&response_type=code&client_id=foo")));
		assertThat("incorrect link url", gip.getLoginURL("foo3", true),
				is(new URL("https://login.com/v2/oauth2/authorize?" +
						"scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+" +
						"email&state=foo3&redirect_uri=https%3A%2F%2Flinkredir.com" +
						"&response_type=code&client_id=foo")));
		
	}
	
	@Test
	public void simpleOperationsWithoutConfigurator() throws Exception {
		
		final IdentityProvider gip = new GlobusIdentityProvider(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Globus"));
		assertThat("incorrect image uri", gip.getImageURI(), is(new URI("http://image.com")));
		assertThat("incorrect login url", gip.getLoginURL("foo2", false),
				is(new URL("https://login.com/v2/oauth2/authorize?" +
						"scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+" +
						"email&state=foo2&redirect_uri=https%3A%2F%2Floginredir.com" +
						"&response_type=code&client_id=foo")));
		assertThat("incorrect link url", gip.getLoginURL("foo3", true),
				is(new URL("https://login.com/v2/oauth2/authorize?" +
						"scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+" +
						"email&state=foo3&redirect_uri=https%3A%2F%2Flinkredir.com" +
						"&response_type=code&client_id=foo")));
		
	}
	
	@Test
	public void createFail() throws Exception {
		failCreate(null, new NullPointerException("idc"));
		failCreate(new IdentityProviderConfig(
				"foo",
				CFG.getLoginURL(),
				CFG.getApiURL(),
				CFG.getClientID(),
				CFG.getClientSecret(),
				CFG.getImageURI(),
				CFG.getLoginRedirectURL(),
				CFG.getLinkRedirectURL()),
				new IllegalArgumentException("Bad config name: foo"));
	}
	
	private void failCreate(final IdentityProviderConfig cfg, final Exception exception) {
		try {
			new GlobusIdentityProvider(cfg);
			fail("created bad globus id provider");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void getIdentities() throws Exception {
		final String clientID = "clientID";
		final IdentityProvider idp = new GlobusIdentityProvider(new IdentityProviderConfig(
				"Globus",
				new URL("https://login.com"),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				clientID,
				"bar",
				new URI("http://image.com"),
				new URL("https://loginredir.com"),
				new URL("https://linkredir.com")));
		
		
		//TODO NOW TEST validate sent data is valid 
		mockClientAndServer.when(
					new HttpRequest()
						.withMethod("POST")
						.withPath("/v2/oauth2/token"),
					Times.exactly(1)
		//TODO NOW TEST send response like std Globus response
				).respond(
					new HttpResponse()
						.withStatusCode(200)
						.withHeader(new Header(CONTENT_TYPE, APP_JSON))
						.withBody(MAPPER.writeValueAsString(
								ImmutableMap.of("access_token", "footoken"))
						)
				);
		//TODO NOW TEST validate sent data is valid
		mockClientAndServer.when(
					new HttpRequest()
						.withMethod("POST")
						.withPath("/v2/oauth2/token/introspect"),
					Times.exactly(1)
		//TODO NOW TEST send response like std Globus response
				).respond(
					new HttpResponse()
						.withStatusCode(200)
						.withHeader(new Header(CONTENT_TYPE, APP_JSON))
						.withBody(MAPPER.writeValueAsString(
								new ImmutableMap.Builder<String, Object>()
									.put("aud", Arrays.asList(clientID))
									.put("sub", "anID")
									.put("username", "aUsername")
									.put("name", "fullname")
									.put("email", "anEmail")
									.put("identities_set", Arrays.asList("ident1", "ident2"))
									.build())
						)
				);
		final List<Map<String, String>> idents = new LinkedList<>();
		idents.add(ImmutableMap.of("id", "id1", "username", "user1", "name", "name1", "email",
				"email1"));
		idents.add(ImmutableMap.of("id", "id2", "username", "user2", "name", "name2", "email",
				"email2"));
		
		//TODO NOW TEST validate sent data is valid
		mockClientAndServer.when(
					new HttpRequest()
						.withMethod("GET")
						.withPath("/v2/api/identities"),
						Times.exactly(1)
		//TODO NOW TEST send response like std Globus response
				).respond(
					new HttpResponse()
						.withStatusCode(200)
						.withHeader(new Header(CONTENT_TYPE, APP_JSON))
						.withBody(MAPPER.writeValueAsString(ImmutableMap.of(
								"identities", idents))
						)
				);
				
				
		final Set<RemoteIdentity> rids = idp.getIdentities("code", false);
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(GLOBUS, "anID"),
				new RemoteIdentityDetails("aUsername", "fullname", "anEmail")));
		expected.add(new RemoteIdentity(new RemoteIdentityID(GLOBUS, "id1"),
				new RemoteIdentityDetails("user1", "name1", "email1")));
		expected.add(new RemoteIdentity(new RemoteIdentityID(GLOBUS, "id2"),
				new RemoteIdentityDetails("user2", "name2", "email2")));
		assertThat("incorrect ident set", rids, is(expected));
	}
}
