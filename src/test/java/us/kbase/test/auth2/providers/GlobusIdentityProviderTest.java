package us.kbase.test.auth2.providers;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockserver.model.NottableString.not;
import static us.kbase.test.auth2.TestCommon.set;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
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
import org.mockserver.model.Parameter;
import org.mockserver.model.ParameterBody;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.Builder;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;
import us.kbase.auth2.providers.GlobusIdentityProviderFactory;
import us.kbase.auth2.providers.GlobusIdentityProviderFactory.GlobusIdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.test.auth2.TestCommon;

public class GlobusIdentityProviderTest {
	
	private static final String CONTENT_TYPE = "content-type";
	private static final String ACCEPT = "accept";
	private static final String APP_JSON = "application/json";
	private static final String GLOBUS = "Globus";
	
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
	private static final String STRING1000;
	private static final String STRING1001;
	static {
		final String s = "foobarbaz0";
		String r = "";
		for (int i = 0; i < 100; i++) {
			r += s;
		}
		STRING1000 = r;
		STRING1001 = r + "a";
	}
	
	private static ClientAndServer mockClientAndServer;
	
	@BeforeClass
	public static void setUpClass() {
		// comment out these lines to see mockserver logs.
		((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
				.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME))
				.setLevel(ch.qos.logback.classic.Level.OFF);
		((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
				.getLogger("org.mockserver"))
				.setLevel(ch.qos.logback.classic.Level.OFF);
		// the next two instructions will be unnecessary soon. see
		// https://github.com/jamesdbloom/mockserver/issues/318
		((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
				.getLogger("org.mockserver.mockserver"))
				.setLevel(ch.qos.logback.classic.Level.OFF);
		((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
				.getLogger("org.mockserver.proxy"))
				.setLevel(ch.qos.logback.classic.Level.OFF);
		mockClientAndServer = ClientAndServer.startClientAndServer(TestCommon.findFreePort());
	}
	
	@After
	public void tearDownTest() {
		mockClientAndServer.reset();
	}
	
	private static final IdentityProviderConfig CFG;
	static {
		try {
			CFG = IdentityProviderConfig.getBuilder(
					GlobusIdentityProviderFactory.class.getName(),
					new URL("https://login.com"),
					new URL("https://setapiurl.com"),
					"foo",
					"bar",
					new URL("https://loginredir.com"),
					new URL("https://linkredir.com"))
					.withEnvironment("myenv",
							new URL("https://myloginred.com"), new URL("https://mylinkred.com"))
					.build();
		} catch (IdentityProviderConfigurationException | MalformedURLException e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}

	@Test
	public void simpleOperationsWithConfigurator() throws Exception {
		final GlobusIdentityProviderFactory gc = new GlobusIdentityProviderFactory();
		
		final IdentityProvider gip = gc.configure(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Globus"));
		assertThat("incorrect environments", gip.getEnvironments(), is(set("myenv")));
		assertThat("incorrect login url", gip.getLoginURI("foo2", "pkceuhuhuh", false, null),
				is(new URI(
						"https://login.com/v2/oauth2/authorize?"
						+ "scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+"
						+ "email&state=foo2"
						+ "&code_challenge=pkceuhuhuh&code_challenge_method=S256"
						+ "&redirect_uri=https%3A%2F%2Floginredir.com"
						+ "&response_type=code&client_id=foo")));
		assertThat("incorrect link url", gip.getLoginURI("foo3", "pkcemyman", true, null),
				is(new URI(
						"https://login.com/v2/oauth2/authorize?"
						+ "scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+"
						+ "email&state=foo3"
						+ "&code_challenge=pkcemyman&code_challenge_method=S256"
						+ "&redirect_uri=https%3A%2F%2Flinkredir.com"
						+ "&response_type=code&client_id=foo")));
		
		assertThat("incorrect login url", gip.getLoginURI("foo2", "pkcemywoman", false, "myenv"),
				is(new URI(
						"https://login.com/v2/oauth2/authorize?"
						+ "scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+"
						+ "email&state=foo2"
						+ "&code_challenge=pkcemywoman&code_challenge_method=S256"
						+ "&redirect_uri=https%3A%2F%2Fmyloginred.com"
						+ "&response_type=code&client_id=foo")));
		assertThat("incorrect link url", gip.getLoginURI(
				"foo3", "pkcemybarnyardanimal", true, "myenv"),
				is(new URI(
						"https://login.com/v2/oauth2/authorize?"
						+ "scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+"
						+ "email&state=foo3"
						+ "&code_challenge=pkcemybarnyardanimal&code_challenge_method=S256"
						+ "&redirect_uri=https%3A%2F%2Fmylinkred.com"
						+ "&response_type=code&client_id=foo")));
		
	}
	
	@Test
	public void simpleOperationsWithoutConfigurator() throws Exception {
		
		final IdentityProvider gip = new GlobusIdentityProvider(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Globus"));
		assertThat("incorrect environments", gip.getEnvironments(), is(set("myenv")));
		assertThat("incorrect login url", gip.getLoginURI("foo2", "pkceuno", false, null),
				is(new URI(
						"https://login.com/v2/oauth2/authorize?"
						+ "scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+"
						+ "email&state=foo2"
						+ "&code_challenge=pkceuno&code_challenge_method=S256"
						+ "&redirect_uri=https%3A%2F%2Floginredir.com"
						+ "&response_type=code&client_id=foo")));
		assertThat("incorrect link url", gip.getLoginURI("foo3", "pkcedos", true, null),
				is(new URI(
						"https://login.com/v2/oauth2/authorize?"
						+ "scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+"
						+ "email&state=foo3"
						+ "&code_challenge=pkcedos&code_challenge_method=S256"
						+ "&redirect_uri=https%3A%2F%2Flinkredir.com"
						+ "&response_type=code&client_id=foo")));
		
		assertThat("incorrect login url", gip.getLoginURI("foo2", "pkcetres", false, "myenv"),
				is(new URI(
						"https://login.com/v2/oauth2/authorize?"
						+ "scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+"
						+ "email&state=foo2"
						+ "&code_challenge=pkcetres&code_challenge_method=S256"
						+ "&redirect_uri=https%3A%2F%2Fmyloginred.com"
						+ "&response_type=code&client_id=foo")));
		assertThat("incorrect link url", gip.getLoginURI("foo3", "pkcecuatro", true, "myenv"),
				is(new URI(
						"https://login.com/v2/oauth2/authorize?"
						+ "scope=urn%3Aglobus%3Aauth%3Ascope%3Aauth.globus.org%3Aview_identities+"
						+ "email&state=foo3"
						+ "&code_challenge=pkcecuatro&code_challenge_method=S256"
						+ "&redirect_uri=https%3A%2F%2Fmylinkred.com"
						+ "&response_type=code&client_id=foo")));
	}
	
	@Test
	public void createFail() throws Exception {
		failCreate(null, new NullPointerException("idc"));
		failCreate(IdentityProviderConfig.getBuilder(
				"foo",
				CFG.getLoginURL(),
				CFG.getApiURL(),
				CFG.getClientID(),
				CFG.getClientSecret(),
				CFG.getLoginRedirectURL(),
				CFG.getLinkRedirectURL())
				.build(),
				new IllegalArgumentException(
						"Configuration class name doesn't match factory class name: foo"));
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
	public void illegalAuthcode() throws Exception {
		final IdentityProvider idp = new GlobusIdentityProvider(CFG);
		failGetIdentities(idp, null, "pkce", true, new IllegalArgumentException(
				"authcode cannot be null or whitespace only"));
		failGetIdentities(idp, "  \t  \n  ", "pkce", true, new IllegalArgumentException(
				"authcode cannot be null or whitespace only"));
	}
	
	@Test
	public void illegalPKCEVerifier() throws Exception {
		final IdentityProvider idp = new GlobusIdentityProvider(CFG);
		failGetIdentities(idp, "p", null, true, new IllegalArgumentException(
				"pkceCodeVerifier cannot be null or whitespace only"));
		failGetIdentities(idp, "p", "  \t  \n  ", true, new IllegalArgumentException(
				"pkceCodeVerifier cannot be null or whitespace only"));
	}
	
	@Test
	public void noSuchEnvironment() throws Exception {
		final IdentityProvider idp = new GlobusIdentityProvider(CFG);
		
		failGetIdentities(idp, "foo", "pkce", true, "myenv1",
				new NoSuchEnvironmentException("myenv1"));
		failGetIdentities(idp, "foo", "pkce", false, "myenv1",
				new NoSuchEnvironmentException("myenv1"));
	}
	
	@Test
	public void returnsIllegalAuthtoken() throws Exception {
		final IdentityProviderConfig testIDConfig = getTestIDConfig();
		final IdentityProvider idp = new GlobusIdentityProvider(testIDConfig);
		final String redir = testIDConfig.getLoginRedirectURL().toString();
		final String bauth = getBasicAuth(testIDConfig);
		final IdentityRetrievalException e =
				new IdentityRetrievalException("No access token was returned by Globus");
		setUpCallAuthToken("authcode3", "pkce1", null, redir, bauth);
		failGetIdentities(idp, "authcode3", "pkce1", false, e);
		setUpCallAuthToken("authcode3", "pkce2", "     \n    ", redir, bauth);
		failGetIdentities(idp, "authcode3", "pkce2", false, e);
	}
	
	@Test
	public void returnsBadResponseAuthToken() throws Exception {
		final IdentityProviderConfig testIDConfig = getTestIDConfig();
		final IdentityProvider idp = new GlobusIdentityProvider(testIDConfig);
		final String redir = testIDConfig.getLoginRedirectURL().toString();
		final String bauth = getBasicAuth(testIDConfig);
		final String authCode = "foo";
		final String pkce1 = "pkcegoeshere";
		final String pkce2 = "pkcegoeshere2";
		
		setUpCallAuthToken(authCode, pkce1, redir, bauth, APP_JSON, 200, "foo bar");
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Unable to parse response from Globus service."));
		
		setUpCallAuthToken(authCode, pkce1, redir, bauth, "text/html", 200,
				"{\"access_token\":\"foobar\"}");
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Unable to parse response from Globus service."));
		
		setUpCallAuthToken(authCode, pkce2, redir, bauth, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code and unparseable response " +
				"from Globus service: 500. Response: " + STRING1000));
		
		setUpCallAuthToken(authCode, pkce2, redir, bauth, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code and unparseable response " +
				"from Globus service: 500. Truncated response: " + STRING1000));
		
		setUpCallAuthToken(authCode, pkce1, redir, bauth, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code with no response body " +
				"from Globus service: 500."));
		
		setUpCallAuthToken(authCode, pkce2, redir, bauth, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code with no error in the " +
				"response body from Globus service: 500."));
		
		setUpCallAuthToken(authCode, pkce1, redir, bauth, APP_JSON, 500, "{\"error\":\"whee!\"}");
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Globus service returned an error. HTTP code: 500. " +
				"Error: whee!."));
	}
	
	@Test
	public void returnsBadAudience() throws Exception {
		final IdentityProviderConfig testIDConfig = getTestIDConfig();
		final IdentityProvider idp = new GlobusIdentityProvider(testIDConfig);
		final String redir = testIDConfig.getLoginRedirectURL().toString();
		final String bauth = getBasicAuth(testIDConfig);
		final String authCode = "foo2";
		final String authtoken = "footoken";
		setUpCallAuthToken(authCode, "pixydust", authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, MAPPER.writeValueAsString(
				new ImmutableMap.Builder<String, Object>()
					.put("aud", Arrays.asList("thisisabadaudience"))
					.put("sub", "anID")
					.put("username", "aUsername")
					.put("name", "fullname")
					.put("email", "anEmail")
					.put("identities_set",
							Arrays.asList("ident1", "anID", "ident2"))
					.build()));
		failGetIdentities(idp, authCode, "pixydust", false, new IdentityRetrievalException(
				"The audience for the Globus request does not include this client"));
	}
	
	@Test
	public void returnsBadResponsePrimaryID() throws Exception {
		final IdentityProviderConfig testIDConfig = getTestIDConfig();
		final IdentityProvider idp = new GlobusIdentityProvider(testIDConfig);
		final String redir = testIDConfig.getLoginRedirectURL().toString();
		final String bauth = getBasicAuth(testIDConfig);
		final String authCode = "foo";
		final String authtoken = "bartoken";
		final String pkce1 = "pkceisgettingold";
		final String pkce2 = "andmusty";
		
		setUpCallAuthToken(authCode, pkce1, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, "bleah");
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Primary identity retrieval failed: Unable to parse response from Globus " +
				"service."));
		
		setUpCallAuthToken(authCode, pkce2, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, "text/html", 200, MAPPER.writeValueAsString(
				map("aud", testIDConfig.getClientID())));
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Primary identity retrieval failed: Unable to parse response from Globus " +
				"service."));
		
		setUpCallAuthToken(authCode, pkce1, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Primary identity retrieval failed: Got unexpected HTTP code and unparseable " +
				"response from Globus service: 500. Response: " + STRING1000));
		
		setUpCallAuthToken(authCode, pkce1, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Primary identity retrieval failed: Got unexpected HTTP code and unparseable " +
				"response from Globus service: 500. Truncated response: " + STRING1000));
		
		setUpCallAuthToken(authCode, pkce2, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Primary identity retrieval failed: Got unexpected HTTP code with no response " +
				"body from Globus service: 500."));
		
		setUpCallAuthToken(authCode, pkce2, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Primary identity retrieval failed: Got unexpected HTTP code with no error in " +
				"the response body from Globus service: 500."));
		
		setUpCallAuthToken(authCode, pkce1, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 500, "{\"error\":\"whee!\"}");
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Primary identity retrieval failed: Globus service returned an error. " +
				"HTTP code: 500. Error: whee!."));
	}
	
	@Test
	public void returnsBadSecondaryIdentityList() throws Exception {
		final IdentityProviderConfig testIDConfig = getTestIDConfig();
		final IdentityProvider idp = new GlobusIdentityProvider(testIDConfig);
		final String redir = testIDConfig.getLoginRedirectURL().toString();
		final String bauth = getBasicAuth(testIDConfig);
		final String authCode = "foo";
		final String authtoken = "bartoken";
		
		setUpCallAuthToken(authCode, "pixygodimsotiredofthis", authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, MAPPER.writeValueAsString(
				new ImmutableMap.Builder<String, Object>()
				.put("aud", Arrays.asList(testIDConfig.getClientID()))
				.put("sub", "anID")
				.put("username", "aUsername")
				.put("name", "fullname")
				.put("email", "anEmail")
				.put("identities_set",
						Arrays.asList("id1  ", "anID", "\nid2"))
				.build()));
		
		final List<Map<String, Object>> idents = new LinkedList<>();
		idents.add(map("id", "id1", "username", "user1", "name", "name1", "email", null));
		idents.add(map("id", "id2", "username", "user2", "name", null, "email", "email2"));
		idents.add(map("id", "id3", "username", "user3", "name", "name3", "email", "email3"));
		setupCallSecondaryID(authtoken, "^id2,id1|id1,id2$", APP_JSON, 200,
				MAPPER.writeValueAsString(ImmutableMap.of("identities", idents)));
		
		failGetIdentities(idp, authCode, "pixygodimsotiredofthis", false,
				new IdentityRetrievalException(
						"Requested secondary identities do not match recieved: " +
						"[id1, id2] vs [id1, id2, id3]"));
	}
	
	@Test
	public void returnsBadResponseSecondaryID() throws Exception {
		final IdentityProviderConfig testIDConfig = getTestIDConfig();
		final IdentityProvider idp = new GlobusIdentityProvider(testIDConfig);
		final String redir = testIDConfig.getLoginRedirectURL().toString();
		final String bauth = getBasicAuth(testIDConfig);
		final String authCode = "foo5";
		final String pkce1 = "pkceyetagain";
		final String pkce2 = "pkceandagain";
		final String authtoken = "bartoken5";
		final String idRegex = "^id1$";
		final String primaryResp = MAPPER.writeValueAsString(
				new ImmutableMap.Builder<String, Object>()
				.put("aud", Arrays.asList(testIDConfig.getClientID()))
				.put("sub", "anID")
				.put("username", "aUsername")
				.put("name", "fullname")
				.put("email", "anEmail")
				.put("identities_set",
						Arrays.asList("id1  ", "anID"))
				.build());
		
		setUpCallAuthToken(authCode, pkce1, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, APP_JSON, 200, "bleah");
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Unable to parse response from Globus " +
				"service."));
		
		setUpCallAuthToken(authCode, pkce2, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, "text/html", 200, MAPPER.writeValueAsString(
				map("identities", new ArrayList<String>())));
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Unable to parse response from Globus " +
				"service."));
		
		setUpCallAuthToken(authCode, pkce2, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Got unexpected HTTP code and unparseable " +
				"response from Globus service: 500. Response: " + STRING1000));
		
		setUpCallAuthToken(authCode, pkce1, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Got unexpected HTTP code and unparseable " +
				"response from Globus service: 500. Truncated response: " + STRING1000));
		
		setUpCallAuthToken(authCode, pkce2, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Got unexpected HTTP code with no response " +
				"body from Globus service: 500."));
		
		setUpCallAuthToken(authCode, pkce2, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Got unexpected HTTP code with no error in " +
				"the response body from Globus service: 500."));
		
		setUpCallAuthToken(authCode, pkce1, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, APP_JSON, 500, MAPPER.writeValueAsString(
				map("errors", null)));
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Got unexpected HTTP code with null error " +
				"in the response body from Globus service: 500."));
		
		setUpCallAuthToken(authCode, pkce1, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, APP_JSON, 500, MAPPER.writeValueAsString(
				map("errors", new ArrayList<String>())));
		failGetIdentities(idp, authCode, pkce1, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Got unexpected HTTP code with null error " +
				"in the response body from Globus service: 500."));
		
		setUpCallAuthToken(authCode, pkce2, authtoken, redir, bauth);
		setUpCallPrimaryID(authtoken, bauth, APP_JSON, 200, primaryResp);
		setupCallSecondaryID(authtoken, idRegex, APP_JSON, 500, MAPPER.writeValueAsString(
				map("errors", Arrays.asList(
						map("code", "code1", "id", "id1", "detail", "detail1")))));
		failGetIdentities(idp, authCode, pkce2, false, new IdentityRetrievalException(
				"Secondary identity retrieval failed: Globus service returned an error. " +
				"HTTP code: 500. Error code1: detail1; id: id1"));
	}

	private void setUpCallPrimaryID(
			final String authtoken,
			final String bauth,
			final String contentType,
			final int retcode,
			final String primaryReturn)
			throws Exception {
		setUpCallPrimaryID(authtoken, bauth, contentType, retcode, primaryReturn, true);
	}
	
	private void setUpCallPrimaryID(
			final String authtoken,
			final String bauth,
			final String contentType,
			final int retcode,
			final String primaryReturn,
			final boolean includeIdentitiesSet)
			throws Exception {
		final HttpResponse resp = new HttpResponse()
				.withStatusCode(retcode)
				.withHeader(new Header(CONTENT_TYPE, contentType));
		if (primaryReturn != null) {
			resp.withBody(primaryReturn);
		}
		final ParameterBody parameterBody;
		if (includeIdentitiesSet) {
			parameterBody = new ParameterBody(
					new Parameter("include", "identities_set"),
					new Parameter("token", authtoken));
		} else {
			parameterBody = new ParameterBody(
					new Parameter("token", authtoken),
					new Parameter(not("include"), not("identities_set")));
		}
		mockClientAndServer.when(
				new HttpRequest()
					.withMethod("POST")
					.withPath("/v2/oauth2/token/introspect")
					.withHeader(ACCEPT, APP_JSON)
					.withHeader("Authorization", bauth)
					.withBody(parameterBody),
				Times.exactly(1)
			).respond(
				resp
			);
	}

	private void failGetIdentities(
			final IdentityProvider idp,
			final String authcode,
			final String pkce,
			final boolean link,
			final Exception exception) throws Exception {
		failGetIdentities(idp, authcode, pkce, link, null, exception);
	}
	
	private void failGetIdentities(
			final IdentityProvider idp,
			final String authcode,
			final String pkce,
			final boolean link,
			final String env,
			final Exception exception) throws Exception {
		try {
			idp.getIdentities(authcode, pkce, link, env);
			fail("got identities with bad setup");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}

	private IdentityProviderConfig getTestIDConfig()
			throws IdentityProviderConfigurationException, MalformedURLException,
			URISyntaxException {
		return getTestIDConfig(Collections.emptyMap());
	}
	
	private IdentityProviderConfig getTestIDConfig(final Map<String, String> customConfig)
			throws MalformedURLException, IdentityProviderConfigurationException {
		final Builder b =  IdentityProviderConfig.getBuilder(
				GlobusIdentityProviderFactory.class.getName(),
				new URL("https://login.com"),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"foo",
				"bar",
				new URL("https://loginredir.com"),
				new URL("https://linkredir.com"))
				.withEnvironment("myenv", new URL("https://lor2.com"), new URL("https://li2.com"));
		for (final String k: customConfig.keySet()) {
			b.withCustomConfiguration(k, customConfig.get(k));
		}
		return b.build();
	}

	private String getBasicAuth(final IdentityProviderConfig idconfig) {
		return "Basic " + Base64.getEncoder().encodeToString(
				(idconfig.getClientID() + ":" + idconfig.getClientSecret()).getBytes());
	}

	private void setUpCallAuthToken(
			final String authCode,
			final String pkceVerifier,
			final String authtoken,
			final String redirect,
			final String basicAuth)
			throws Exception {
		mockClientAndServer.when(
				new HttpRequest()
					.withMethod("POST")
					.withPath("/v2/oauth2/token")
					.withHeader(ACCEPT, APP_JSON)
					.withHeader("Authorization", basicAuth)
					.withBody(new ParameterBody(
							new Parameter("code", authCode),
							new Parameter("code_verifier", pkceVerifier),
							new Parameter("grant_type", "authorization_code"),
							new Parameter("redirect_uri", redirect))
					),
				Times.exactly(1)
			).respond(
				new HttpResponse()
					.withStatusCode(200)
					.withHeader(CONTENT_TYPE, APP_JSON)
					.withBody(MAPPER.writeValueAsString(map("access_token", authtoken)))
			);
	}
	
	private void setUpCallAuthToken(
			final String authCode,
			final String pkceVerifier,
			final String redirect,
			final String basicAuth,
			final String contentType,
			final int retcode,
			final String response) {
		final HttpResponse resp = new HttpResponse()
					.withStatusCode(retcode)
					.withHeader(CONTENT_TYPE, contentType);
		if (response != null) {
			resp.withBody(response);
		}
		mockClientAndServer.when(
				new HttpRequest()
					.withMethod("POST")
					.withPath("/v2/oauth2/token")
					.withHeader(ACCEPT, APP_JSON)
					.withHeader("Authorization", basicAuth)
					.withBody(new ParameterBody(
							new Parameter("code", authCode),
							new Parameter("code_verifier", pkceVerifier),
							new Parameter("grant_type", "authorization_code"),
							new Parameter("redirect_uri", redirect))
					),
				Times.exactly(1)
			).respond(resp);
	}
	
	@Test
	public void getIdentityWithSecondariesAndLoginURLAndEnvironment() throws Exception {
		final String authCode = "authcode";
		final IdentityProviderConfig testIDConfig = getTestIDConfig(
				ImmutableMap.of("ignore-secondary-identities", "ntrue"));
		final IdentityProvider idp = new GlobusIdentityProvider(testIDConfig);
		final String bauth = getBasicAuth(testIDConfig);
		final String token = "footoken";
		final int respCode = 200;

		setUpCallAuthToken(authCode, "pixypixy", token, "https://lor2.com", bauth);
		setUpCallPrimaryID(token, bauth, APP_JSON, respCode, MAPPER.writeValueAsString(
				new ImmutableMap.Builder<String, Object>()
						.put("aud", Arrays.asList(testIDConfig.getClientID()))
						.put("sub", "anID")
						.put("username", "aUsername")
						.put("name", "fullname")
						.put("email", "anEmail")
						.put("identities_set",
								Arrays.asList("id1  ", "anID", "\nid2"))
						.build()));
		
		final List<Map<String, Object>> idents = new LinkedList<>();
		idents.add(map("id", "id1", "username", "user1", "name", "name1", "email", null));
		idents.add(map("id", "id2", "username", "user2", "name", null, "email", "email2"));
		setupCallSecondaryID(token, "^id2,id1|id1,id2$", APP_JSON, respCode,
				MAPPER.writeValueAsString(ImmutableMap.of("identities", idents)));
				
				
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pixypixy", false, "myenv");
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(GLOBUS, "anID"),
				new RemoteIdentityDetails("aUsername", "fullname", "anEmail")));
		expected.add(new RemoteIdentity(new RemoteIdentityID(GLOBUS, "id1"),
				new RemoteIdentityDetails("user1", "name1", null)));
		expected.add(new RemoteIdentity(new RemoteIdentityID(GLOBUS, "id2"),
				new RemoteIdentityDetails("user2", null, "email2")));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	@Test
	public void getIdentityWithSecondariesDisabledAndLoginURL() throws Exception {
		final String authCode = "authcode";
		final IdentityProviderConfig testIDConfig = getTestIDConfig(
				ImmutableMap.of("ignore-secondary-identities", "true"));
		final IdentityProvider idp = new GlobusIdentityProvider(testIDConfig);
		final String bauth = getBasicAuth(testIDConfig);
		final String token = "footoken";
		final int respCode = 200;

		setUpCallAuthToken(authCode, "pkce", token, "https://loginredir.com", bauth);
		setUpCallPrimaryID(token, bauth, APP_JSON, respCode, MAPPER.writeValueAsString(
				new ImmutableMap.Builder<String, Object>()
						.put("aud", Arrays.asList(testIDConfig.getClientID()))
						.put("sub", "anID")
						.put("username", "aUsername")
						.put("name", "fullname")
						.put("email", "anEmail")
						.build()),
				false);
		
		// allow this call to proceed in case there's a bug such that it does
		final List<Map<String, Object>> idents = new LinkedList<>();
		idents.add(map("id", "id1", "username", "user1", "name", "name1", "email", null));
		idents.add(map("id", "id2", "username", "user2", "name", null, "email", "email2"));
		setupCallSecondaryID(token, "^id2,id1|id1,id2$", APP_JSON, respCode,
				MAPPER.writeValueAsString(ImmutableMap.of("identities", idents)));
				
				
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(GLOBUS, "anID"),
				new RemoteIdentityDetails("aUsername", "fullname", "anEmail")));
		assertThat("incorrect ident set", rids, is(expected));
	}

	private void setupCallSecondaryID(
			final String token,
			final String idRegex,
			final String contentType,
			final int respCode,
			final String body) {
		mockClientAndServer.when(
					new HttpRequest()
						.withMethod("GET")
						.withPath("/v2/api/identities")
						.withHeader(ACCEPT, APP_JSON)
						.withHeader("Authorization", "Bearer " + token)
						.withQueryStringParameter("ids", idRegex),
					Times.exactly(1)
				).respond(
					new HttpResponse()
						.withStatusCode(respCode)
						.withHeader(new Header(CONTENT_TYPE, contentType))
						.withBody(body)
				);
	}

	@Test
	public void getIdentityWithoutSecondariesAndLinkURL() throws Exception {
		getIdentityWithoutSecondariesAndLinkURL(null, "https://linkredir2.com");
	}
	
	@Test
	public void getIdentityWithoutSecondariesAndLinkURLAndEnvironment() throws Exception {
		getIdentityWithoutSecondariesAndLinkURL("e1", "https://li.com");
	}

	private void getIdentityWithoutSecondariesAndLinkURL(final String env, final String linkURL)
			throws Exception {
		final String clientID = "clientID2";
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = IdentityProviderConfig.getBuilder(
				GlobusIdentityProviderFactory.class.getName(),
				new URL("https://login2.com"),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				clientID,
				"bar2",
				new URL("https://loginredir2.com"),
				new URL("https://linkredir2.com"))
				.withEnvironment("e1", new URL("http://foo.com"), new URL("https://li.com"))
				.build();
		final IdentityProvider idp = new GlobusIdentityProvider(idconfig);
		final String bauth = getBasicAuth(idconfig);
		
		setUpCallAuthToken(authCode, "pkcepkcepkcepkcepkcepkce", "footoken2", linkURL, bauth);
		setUpCallPrimaryID("footoken2", bauth, APP_JSON, 200, MAPPER.writeValueAsString(
				map("aud", Arrays.asList(clientID),
					"sub", "anID2",
					"username", "aUsername2",
					"name", null,
					"email", null,
					"identities_set", Arrays.asList("anID2  \n"))));
		final Set<RemoteIdentity> rids = idp.getIdentities(
				authCode, "pkcepkcepkcepkcepkcepkce", true, env);
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(GLOBUS, "anID2"),
				new RemoteIdentityDetails("aUsername2", null, null)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	private Map<String, Object> map(final Object... entries) {
		if (entries.length % 2 != 0) {
			throw new IllegalArgumentException();
		}
		final Map<String, Object> ret = new HashMap<>();
		for (int i = 0; i < entries.length; i += 2) {
			ret.put((String) entries[i], entries[i + 1]);
		}
		return ret;
	}
}
