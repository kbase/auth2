package us.kbase.test.auth2.providers;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
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

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.MfaStatus;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;
import us.kbase.auth2.providers.OrcIDIdentityProviderFactory;
import us.kbase.auth2.providers.OrcIDIdentityProviderFactory.OrcIDIdentityProvider;
import us.kbase.test.auth2.TestCommon;

public class OrcIDIdentityProviderTest {
	
	// a lot of code in common with Google and Globus, try to make common class at some point 

	private static final String CONTENT_TYPE = "content-type";
	private static final String ACCEPT = "accept";
	private static final String APP_JSON = "application/json";
	private static final String ORCID = "OrcID";
	
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
					OrcIDIdentityProviderFactory.class.getName(),
					new URL("https://ologin.com"),
					new URL("https://osetapiurl.com"),
					"ofoo",
					"obar",
					new URL("https://ologinredir.com"),
					new URL("https://olinkredir.com"))
					.withEnvironment("myenv",
							new URL("https://myologinred.com"), new URL("https://myolinkred.com"))
					.build();
		} catch (IdentityProviderConfigurationException | MalformedURLException e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}
	
	@Test
	public void simpleOperationsWithConfigurator() throws Exception {
		final OrcIDIdentityProviderFactory gc = new OrcIDIdentityProviderFactory();
		
		final IdentityProvider oip = gc.configure(CFG);
		assertThat("incorrect provider name", oip.getProviderName(), is("OrcID"));
		assertThat("incorrect environments", oip.getEnvironments(), is(set("myenv")));
		assertThat("incorrect login url", oip.getLoginURI("foo3", "pkce", false, null),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=openid+%2Fauthenticate" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fologinredir.com" +
						"&response_type=code&client_id=ofoo")));
		assertThat("incorrect link url", oip.getLoginURI("foo4", "pkce", true, null),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=openid+%2Fauthenticate" +
						"&state=foo4&redirect_uri=https%3A%2F%2Folinkredir.com" +
						"&response_type=code&client_id=ofoo")));
		
		assertThat("incorrect login url", oip.getLoginURI("foo3", "pkce", false, "myenv"),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=openid+%2Fauthenticate" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fmyologinred.com" +
						"&response_type=code&client_id=ofoo")));
		assertThat("incorrect link url", oip.getLoginURI("foo4", "pkce", true, "myenv"),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=openid+%2Fauthenticate" +
						"&state=foo4&redirect_uri=https%3A%2F%2Fmyolinkred.com" +
						"&response_type=code&client_id=ofoo")));
	}
	
	@Test
	public void simpleOperationsWithoutConfigurator() throws Exception {
		
		final IdentityProvider oip = new OrcIDIdentityProvider(CFG);
		assertThat("incorrect provider name", oip.getProviderName(), is("OrcID"));
		assertThat("incorrect environments", oip.getEnvironments(), is(set("myenv")));
		assertThat("incorrect login url", oip.getLoginURI("foo5", "pkce", false, null),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=openid+%2Fauthenticate" +
						"&state=foo5&redirect_uri=https%3A%2F%2Fologinredir.com" +
						"&response_type=code&client_id=ofoo")));
		assertThat("incorrect link url", oip.getLoginURI("foo6", "pkce", true, null),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=openid+%2Fauthenticate" +
						"&state=foo6&redirect_uri=https%3A%2F%2Folinkredir.com" +
						"&response_type=code&client_id=ofoo")));
		
		assertThat("incorrect login url", oip.getLoginURI("foo3", "pkce", false, "myenv"),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=openid+%2Fauthenticate" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fmyologinred.com" +
						"&response_type=code&client_id=ofoo")));
		assertThat("incorrect link url", oip.getLoginURI("foo4", "pkce", true, "myenv"),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=openid+%2Fauthenticate" +
						"&state=foo4&redirect_uri=https%3A%2F%2Fmyolinkred.com" +
						"&response_type=code&client_id=ofoo")));
		
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
			new OrcIDIdentityProvider(cfg);
			fail("created bad globus id provider");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void illegalAuthcode() throws Exception {
		final IdentityProvider idp = new OrcIDIdentityProvider(CFG);
		failGetIdentities(idp, null, "pkce", true, new IllegalArgumentException(
				"authcode cannot be null or empty"));
		failGetIdentities(idp, "  \t  \n  ", "pkce", true, new IllegalArgumentException(
				"authcode cannot be null or empty"));
	}
	
	@Test
	public void noSuchEnvironment() throws Exception {
		final IdentityProvider idp = new OrcIDIdentityProvider(CFG);
		
		failGetIdentities(idp, "foo", "pkce", true, "myenv1",
				new NoSuchEnvironmentException("myenv1"));
		failGetIdentities(idp, "foo", "pkce", false, "myenv1",
				new NoSuchEnvironmentException("myenv1"));
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
		return IdentityProviderConfig.getBuilder(
				OrcIDIdentityProviderFactory.class.getName(),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"ofoo",
				"obar",
				new URL("https://ologinredir.com"),
				new URL("https://olinkredir.com"))
				.withEnvironment("e3", new URL("https://lo.com"), new URL("https://li.com"))
				.build();
	}
	
	@Test
	public void returnsIllegalAuthtokenResponse() throws Exception {
		final IdentityProviderConfig testIDConfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(testIDConfig);
		final String redir = testIDConfig.getLoginRedirectURL().toString();
		final String cliid = testIDConfig.getClientID();
		final String clisec = testIDConfig.getClientSecret();
		final String acode = "authcode6";
		final IdentityRetrievalException e =
				new IdentityRetrievalException("No access token was returned by OrcID");
		
		setUpCallAuthTokenWithJWT(acode, null, redir, cliid, clisec, "name", "fake ID", createJWTWithoutAmr("fake ID"));
		failGetIdentities(idp, acode, "pkce", false, e);
		setUpCallAuthTokenWithJWT(acode, "\t  ", redir, cliid, clisec, "name", "fake ID", createJWTWithoutAmr("fake ID"));
		failGetIdentities(idp, acode, "pkce", false, e);
		
		setUpCallAuthTokenWithJWT(acode, "fake token", redir, cliid, clisec, "my name", null, createJWTWithoutAmr("fake ID"));
		failGetIdentities(idp, acode, "pkce", false, new IdentityRetrievalException(
				"No id was returned by OrcID"));
		setUpCallAuthTokenWithJWT(acode, "fake token", redir, cliid, clisec, "my name", "   \t  \n  ", createJWTWithoutAmr("fake ID"));
		failGetIdentities(idp, acode, "pkce", false, new IdentityRetrievalException(
				"No id was returned by OrcID"));
	}
	
	@Test
	public void returnsBadResponseAuthToken() throws Exception {
		final IdentityProviderConfig cfg = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(cfg);
		final String redir = cfg.getLoginRedirectURL().toString();
		final String cliid = cfg.getClientID();
		final String clisec = cfg.getClientSecret();
		final String authCode = "foo10";
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 200, "foo bar");
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Unable to parse response from OrcID service."));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, "text/html", 200,
				"{\"access_token\":\"foobar\"}");
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Unable to parse response from OrcID service."));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code and unparseable response " +
				"from OrcID service: 500. Response: " + STRING1000));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code and unparseable response " +
				"from OrcID service: 500. Truncated response: " + STRING1000));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code with no response body " +
				"from OrcID service: 500."));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code with no error in the " +
				"response body from OrcID service: 500."));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500,
				"{\"error\":\"whee!\",\"error_description\":\"whoo!\"}");
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Authtoken retrieval failed: OrcID service returned an error. HTTP code: 500. " +
				"Error: whee!. Error description: whoo!"));
	}
	
	@Test
	public void returnsBadResponseIdentity() throws Exception {
		final IdentityProviderConfig cfg = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(cfg);
		final String redir = cfg.getLoginRedirectURL().toString();
		final String cliid = cfg.getClientID();
		final String clisec = cfg.getClientSecret();
		final String authCode = "foo";
		final String authtoken = "bartoken";
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthTokenWithJWT(authCode, authtoken, redir, cliid, clisec, "my name", orcID, createJWTWithoutAmr(orcID));
		setupCallID(authtoken, orcID, APP_JSON, 200, "bleah");
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Unable to parse response from OrcID service."));
		
		setUpCallAuthTokenWithJWT(authCode, authtoken, redir, cliid, clisec, "my name", orcID, createJWTWithoutAmr(orcID));
		setupCallID(authtoken, orcID, "text/html", 200, MAPPER.writeValueAsString(
				map("id", "id1", "displayName", "dispname1", "emails", Arrays.asList(
						map("value", "email1")))));
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Unable to parse response from OrcID service."));
		
		setUpCallAuthTokenWithJWT(authCode, authtoken, redir, cliid, clisec, "my name", orcID, createJWTWithoutAmr(orcID));
		setupCallID(authtoken, orcID, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Got unexpected HTTP code and unparseable " +
				"response from OrcID service: 500. Response: " + STRING1000));
		
		setUpCallAuthTokenWithJWT(authCode, authtoken, redir, cliid, clisec, "my name", orcID, createJWTWithoutAmr(orcID));
		setupCallID(authtoken, orcID, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Got unexpected HTTP code and unparseable " +
				"response from OrcID service: 500. Truncated response: " + STRING1000));
		
		setUpCallAuthTokenWithJWT(authCode, authtoken, redir, cliid, clisec, "my name", orcID, createJWTWithoutAmr(orcID));
		setupCallID(authtoken, orcID, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Got unexpected HTTP code with no response " +
				"body from OrcID service: 500."));
		
		setUpCallAuthTokenWithJWT(authCode, authtoken, redir, cliid, clisec, "my name", orcID, createJWTWithoutAmr(orcID));
		setupCallID(authtoken, orcID, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Got unexpected HTTP code with no error in " +
				"the response body from OrcID service: 500."));
		
		setUpCallAuthTokenWithJWT(authCode, authtoken, redir, cliid, clisec, "my name", orcID, createJWTWithoutAmr(orcID));
		setupCallID(authtoken, orcID, APP_JSON, 401, MAPPER.writeValueAsString(
				map("error", "whee!", "error_description", "whoo!")));
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"OrcID service returned an error. HTTP code: 401. " +
				"Error: whee!. Error description: whoo!"));
	}
	
	@Test
	public void getIdentityWithLoginURL() throws Exception {
		getIdentityWithLoginURL(null, map());
		getIdentityWithLoginURL(null, map("email", null));
		getIdentityWithLoginURL(null, map("email", Collections.emptyList()));
		getIdentityWithLoginURL(null, map("email", Arrays.asList(map())));
		getIdentityWithLoginURL(null, map("email", Arrays.asList(map("email", null))));
		getIdentityWithLoginURL(null, map("email", Arrays.asList(map("email", "   \t   \n "))));
		getIdentityWithLoginURL("email3", map("email", Arrays.asList(map("email", "email3"))));
	}
	
	private void getIdentityWithLoginURL(final String email, final Map<String, Object> response)
			throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthTokenWithJWT(authCode, "footoken3", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, createJWTWithoutAmr(orcID));
		setupCallID("footoken3", orcID, APP_JSON, 200, MAPPER.writeValueAsString(response));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", email)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	@Test
	public void getIdentityWithLoginURLAndEnvironment() throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthTokenWithJWT(authCode, "footoken3", "https://lo.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, createJWTWithoutAmr(orcID));
		setupCallID("footoken3", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "email7")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, "e3");
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", "email7", MfaStatus.UNKNOWN)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	@Test
	public void getIdentityWithLinkURL() throws Exception {
		getIdentityWithLinkURL(null, map());
		getIdentityWithLinkURL(null, map("email", null));
		getIdentityWithLinkURL(null, map("email", Collections.emptyList()));
		getIdentityWithLinkURL(null, map("email", Arrays.asList(map())));
		getIdentityWithLinkURL(null, map("email", Arrays.asList(map("email", null))));
		getIdentityWithLinkURL(null, map("email", Arrays.asList(map("email", "   \t   \n "))));
		getIdentityWithLinkURL("email1", map("email", Arrays.asList(map("email", "email1"))));
	}

	private void getIdentityWithLinkURL(final String email, final Map<String, Object> response)
			throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = IdentityProviderConfig.getBuilder(
				OrcIDIdentityProviderFactory.class.getName(),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"someclient",
				"bar2",
				new URL("https://ologinredir2.com"),
				new URL("https://olinkredir2.com"))
				.build();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthTokenWithJWT(authCode, "footoken2", "https://olinkredir2.com",
				idconfig.getClientID(), idconfig.getClientSecret(),
				null, orcID, createJWTWithoutAmr(orcID));
		setupCallID("footoken2", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				response));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", true, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, null, email)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	@Test
	public void getIdentityWithLinkURLAndEnvironment() throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = IdentityProviderConfig.getBuilder(
				OrcIDIdentityProviderFactory.class.getName(),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"someclient",
				"bar2",
				new URL("https://ologinredir2.com"),
				new URL("https://olinkredir2.com"))
				.withEnvironment("e3", new URL("https://lo.com"), new URL("https://li.com"))
				.build();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthTokenWithJWT(authCode, "footoken2", "https://li.com",
				idconfig.getClientID(), idconfig.getClientSecret(),
				null, orcID, createJWTWithoutAmr(orcID));
		setupCallID("footoken2", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "email4")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", true, "e3");
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, null, "email4", MfaStatus.UNKNOWN)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	/** Tests MFA detection when AMR array contains "mfa". */
	@Test
	public void getIdentityArrayAmrWithMfa() throws Exception {
		final String authCode = "authcodeWithMfa";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		final String jwt = createValidJWTWithMfa(orcID, true);
		
		setUpCallAuthTokenWithJWT(authCode, "footoken3", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, jwt);
		setupCallID("footoken3", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "mfa@test.com")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", "mfa@test.com", MfaStatus.USED)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	/** Tests MFA detection when AMR array does not contain "mfa". */
	@Test
	public void getIdentityArrayAmrNoMfa() throws Exception {
		final String authCode = "authcodeNoMfa";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		final String jwt = createValidJWTWithMfa(orcID, false);
		
		setUpCallAuthTokenWithJWT(authCode, "footoken4", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, jwt);
		setupCallID("footoken4", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "nomfa@test.com")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", "nomfa@test.com", MfaStatus.NOT_USED)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	/** Tests non-member ORCID accounts without JWTs default to UNKNOWN MFA. */
	@Test
	public void getIdentityWithNoJWT() throws Exception {
		final String authCode = "authcodeNoJWT";
		final IdentityProviderConfig idconfig = IdentityProviderConfig.getBuilder(
				OrcIDIdentityProviderFactory.class.getName(),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"ofoo",
				"obar",
				new URL("https://ologinredir.com"),
				new URL("https://olinkredir.com"))
				.withCustomConfiguration("orcid-mfa-enabled", "false")
				.build();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";

		setUpCallAuthToken(authCode, "footoken5", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID);
		setupCallID("footoken5", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "nojwt@test.com")))));

		// MFA checking disabled - no JWT expected, MFA status should be UNKNOWN
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", "nojwt@test.com", MfaStatus.UNKNOWN)));
		assertThat("incorrect ident set", rids, is(expected));
	}

	@Test
	public void getIdentityWithMissingJWT() throws Exception {
		final String authCode = "authcodeMissingJWT";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";

		// MFA checking enabled but no JWT provided in response
		setUpCallAuthTokenWithJWT(authCode, "footokenNoJWT", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, null);

		try {
			idp.getIdentities(authCode, "pkce", false, null);
			fail("Expected IdentityRetrievalException");
		} catch (IdentityRetrievalException e) {
			assertThat("incorrect exception message", e.getMessage(),
					containsString("No JWT token provided by ORCID. For non-member API applications, " +
							"set orcid-mfa-enabled=false in provider configuration"));
		}
	}

	@Test
	public void getIdentityWithInvalidJWT() throws Exception {
		final String authCode = "authcodeInvalidJWT";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		final String invalidJWT = "invalid.jwt.token";

		setUpCallAuthTokenWithJWT(authCode, "footoken6", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, invalidJWT);
		setupCallID("footoken6", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "invalid@test.com")))));

		try {
			idp.getIdentities(authCode, "pkce", false, null);
			fail("Expected IdentityRetrievalException");
		} catch (IdentityRetrievalException e) {
			assertThat("incorrect exception message", e.getMessage(),
					containsString("Unable to parse JWT payload from ORCID"));
		}
	}
	
	/** Tests AMR claim as string (ORCID allows string or array). */
	@Test
	public void getIdentityStringAmrWithMfa() throws Exception {
		final String authCode = "authcodeStringAmr";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		final String jwt = createJWTWithStringAmr(orcID, "mfa");

		setUpCallAuthTokenWithJWT(authCode, "footoken7", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, jwt);
		setupCallID("footoken7", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "stringmfa@test.com")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", "stringmfa@test.com", MfaStatus.USED)));
		assertThat("incorrect ident set", rids, is(expected));
	}

	/** Tests AMR claim as string without "mfa" value. */
	@Test
	public void getIdentityStringAmrNoMfa() throws Exception {
		final String authCode = "authcodeStringAmrNoMfa";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		final String jwt = createJWTWithStringAmr(orcID, "pwd");

		setUpCallAuthTokenWithJWT(authCode, "footoken8", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, jwt);
		setupCallID("footoken8", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "stringnomfa@test.com")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", "stringnomfa@test.com", MfaStatus.NOT_USED)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	private void setUpCallAuthToken(
			final String authCode,
			final String authtoken,
			final String redirect,
			final String clientID,
			final String clientSecret,
			final String name,
			final String orcID)
			throws Exception {
		mockClientAndServer.when(
				new HttpRequest()
					.withMethod("POST")
					.withPath("/oauth/token")
					.withHeader(ACCEPT, APP_JSON)
					.withBody(new ParameterBody(
							new Parameter("code", authCode),
							new Parameter("grant_type", "authorization_code"),
							new Parameter("redirect_uri", redirect),
							new Parameter("client_id", clientID),
							new Parameter("client_secret", clientSecret))
					),
				Times.exactly(1)
			).respond(
				new HttpResponse()
					.withStatusCode(200)
					.withHeader(CONTENT_TYPE, APP_JSON)
					.withBody(MAPPER.writeValueAsString(map(
							"access_token", authtoken,
							"name", name,
							"orcid", orcID
							)))
			);
	}
	
	private void setUpCallAuthToken(
			final String authCode,
			final String redirect,
			final String clientID,
			final String clientSecret,
			final String contentType,
			final int retcode,
			final String response)
			throws Exception {

		final HttpResponse resp = new HttpResponse()
				.withStatusCode(retcode)
				.withHeader(CONTENT_TYPE, contentType);
		if (response != null) {
			resp.withBody(response);
		}
		mockClientAndServer.when(
				new HttpRequest()
					.withMethod("POST")
					.withPath("/oauth/token")
					.withHeader(ACCEPT, APP_JSON)
					.withBody(new ParameterBody(
							new Parameter("code", authCode),
							new Parameter("grant_type", "authorization_code"),
							new Parameter("redirect_uri", redirect),
							new Parameter("client_id", clientID),
							new Parameter("client_secret", clientSecret))
					),
				Times.exactly(1)
			).respond(resp);
	}
	
	private void setupCallID(
			final String token,
			final String orcID,
			final String contentType,
			final int respCode,
			final String body) {
		mockClientAndServer.when(
					new HttpRequest()
						.withMethod("GET")
						.withPath("/v2.1/" + orcID + "/email")
						.withHeader(ACCEPT, APP_JSON)
						.withHeader("Authorization", "Bearer " + token),
					Times.exactly(1)
				).respond(
					new HttpResponse()
						.withStatusCode(respCode)
						.withHeader(new Header(CONTENT_TYPE, contentType))
						.withBody(body)
				);
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
	
	private void setUpCallAuthTokenWithJWT(
			final String authCode,
			final String authtoken,
			final String redirect,
			final String clientID,
			final String clientSecret,
			final String name,
			final String orcID,
			final String jwt)
			throws Exception {
		mockClientAndServer.when(
				new HttpRequest()
					.withMethod("POST")
					.withPath("/oauth/token")
					.withHeader(ACCEPT, APP_JSON)
					.withBody(new ParameterBody(
							new Parameter("code", authCode),
							new Parameter("grant_type", "authorization_code"),
							new Parameter("redirect_uri", redirect),
							new Parameter("client_id", clientID),
							new Parameter("client_secret", clientSecret))
					),
				Times.exactly(1)
			).respond(
				new HttpResponse()
					.withStatusCode(200)
					.withHeader(CONTENT_TYPE, APP_JSON)
					.withBody(MAPPER.writeValueAsString(map(
							"access_token", authtoken,
							"name", name,
							"orcid", orcID,
							"id_token", jwt
							)))
			);
	}
	
	private String createValidJWTWithMfa(final String orcID, final boolean usedMfa) {
		final String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		final String payload = usedMfa ?
				"{\"sub\":\"" + orcID + "\",\"amr\":[\"mfa\",\"pwd\"]}" :
				"{\"sub\":\"" + orcID + "\",\"amr\":[\"pwd\"]}";
		final String encodedHeader = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(header.getBytes());
		final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(payload.getBytes());
		return encodedHeader + "." + encodedPayload + ".signature";
	}
	
	private String createJWTWithStringAmr(final String orcID, final String amrValue) {
		final String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		final String payload = "{\"sub\":\"" + orcID + "\",\"amr\":\"" + amrValue + "\"}";
		final String encodedHeader = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(header.getBytes());
		final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(payload.getBytes());
		return encodedHeader + "." + encodedPayload + ".signature";
	}
	
	/** Tests JWT with 2 parts instead of 3 is rejected. */
	@Test
	public void getIdentityWithMalformedJWT() throws Exception {
		final String authCode = "authcodeMalformed";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		// Test JWT with only 2 parts
		final String invalidJWT = "header.payload";
		setUpCallAuthTokenWithJWT(authCode, "footoken8", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, invalidJWT);
		setupCallID("footoken8", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "malformed@test.com")))));
		
		try {
			idp.getIdentities(authCode, "pkce", false, null);
			fail("Expected IdentityRetrievalException");
		} catch (IdentityRetrievalException e) {
			assertThat("incorrect exception message", e.getMessage(), 
					containsString("Invalid JWT format from ORCID: expected 3 parts, got 2"));
		}
	}
	
	@Test
	public void getIdentityWithInvalidBase64JWT() throws Exception {
		final String authCode = "authcodeInvalidB64";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		// JWT with invalid base64 in payload
		final String invalidJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid==base64!!.signature";
		setUpCallAuthTokenWithJWT(authCode, "footoken9", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, invalidJWT);
		setupCallID("footoken9", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "invalidb64@test.com")))));
		
		try {
			idp.getIdentities(authCode, "pkce", false, null);
			fail("Expected IdentityRetrievalException");
		} catch (IdentityRetrievalException e) {
			assertThat("incorrect exception message", e.getMessage(), 
					containsString("Unable to decode JWT from ORCID"));
		}
	}
	
	@Test
	public void getIdentityWithMalformedJSONJWT() throws Exception {
		final String authCode = "authcodeMalformedJSON";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		// JWT with invalid JSON in payload
		final String invalidJSON = "{\"sub\":\"" + orcID + "\",\"amr\":}";
		final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(invalidJSON.getBytes());
		final String invalidJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + encodedPayload + ".signature";
		
		setUpCallAuthTokenWithJWT(authCode, "footoken10", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, invalidJWT);
		setupCallID("footoken10", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "malformedjson@test.com")))));
		
		try {
			idp.getIdentities(authCode, "pkce", false, null);
			fail("Expected IdentityRetrievalException");
		} catch (IdentityRetrievalException e) {
			assertThat("incorrect exception message", e.getMessage(), 
					containsString("Unable to parse JWT payload from ORCID"));
		}
	}
	
	@Test
	public void getIdentityWithEmptyAmrJWT() throws Exception {
		final String authCode = "authcodeEmptyAmr";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		final String jwt = createJWTWithEmptyAmr(orcID);
		
		setUpCallAuthTokenWithJWT(authCode, "footoken11", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, jwt);
		setupCallID("footoken11", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "emptyamr@test.com")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", "emptyamr@test.com", MfaStatus.NOT_USED)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	@Test
	public void getIdentityWithNoAmrClaimJWT() throws Exception {
		final String authCode = "authcodeNoAmr";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		final String jwt = createJWTWithoutAmr(orcID);
		
		setUpCallAuthTokenWithJWT(authCode, "footoken12", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, jwt);
		setupCallID("footoken12", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "noamr@test.com")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
				new RemoteIdentityDetails(orcID, "My name", "noamr@test.com", MfaStatus.UNKNOWN)));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	private String createJWTWithEmptyAmr(final String orcID) {
		final String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		final String payload = "{\"sub\":\"" + orcID + "\",\"amr\":[]}";
		final String encodedHeader = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(header.getBytes());
		final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(payload.getBytes());
		return encodedHeader + "." + encodedPayload + ".signature";
	}
	
	private String createJWTWithoutAmr(final String orcID) {
		final String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		final String payload = "{\"sub\":\"" + orcID + "\",\"iss\":\"https://orcid.org\"}";
		final String encodedHeader = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(header.getBytes());
		final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(payload.getBytes());
		return encodedHeader + "." + encodedPayload + ".signature";
	}

	@Test
	public void getIdentityWithInvalidAmrTypeJWT() throws Exception {
		final String authCode = "authcodeInvalidAmrType";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";

		// JWT with AMR claim as object (not array or string) - unexpected format
		final String jwt = createJWTWithObjectAmr(orcID);

		setUpCallAuthTokenWithJWT(authCode, "footokenInvalidAmr", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, jwt);
		setupCallID("footokenInvalidAmr", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "invalidamr@test.com")))));

		try {
			idp.getIdentities(authCode, "pkce", false, null);
			fail("Expected IdentityRetrievalException");
		} catch (IdentityRetrievalException e) {
			assertThat("incorrect exception message", e.getMessage(),
					containsString("AMR claim from ORCID in unexpected format"));
		}
	}

	private String createJWTWithObjectAmr(final String orcID) {
		final String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		// AMR as object instead of array or string - this is an invalid/unexpected format
		final String payload = "{\"sub\":\"" + orcID + "\",\"amr\":{\"method\":\"mfa\"}}";
		final String encodedHeader = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(header.getBytes());
		final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(payload.getBytes());
		return encodedHeader + "." + encodedPayload + ".signature";
	}

	@Test
	public void getLoginURIWithMfaEnabled() throws Exception {
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);

		final URI loginURI = idp.getLoginURI("mystate123", "pkce_challenge", false, null);

		assertThat("incorrect URI host", loginURI.getHost(), is("localhost"));
		assertThat("incorrect URI path", loginURI.getPath(), is("/oauth/authorize"));
		assertThat("incorrect query string", loginURI.getQuery(),
				containsString("scope=openid+/authenticate"));
		assertThat("incorrect query string", loginURI.getQuery(),
				containsString("state=mystate123"));
		assertThat("incorrect query string", loginURI.getQuery(),
				containsString("response_type=code"));
	}

	@Test
	public void getLoginURIWithMfaDisabled() throws Exception {
		// Configure with MFA checking disabled
		final IdentityProviderConfig idconfig = IdentityProviderConfig.getBuilder(
				OrcIDIdentityProviderFactory.class.getName(),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"ofoo",
				"obar",
				new URL("https://ologinredir.com"),
				new URL("https://olinkredir.com"))
				.withCustomConfiguration("orcid-mfa-enabled", "false")
				.build();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);

		final URI loginURI = idp.getLoginURI("mystate456", "pkce_challenge", false, null);

		assertThat("incorrect URI host", loginURI.getHost(), is("localhost"));
		assertThat("incorrect URI path", loginURI.getPath(), is("/oauth/authorize"));
		// When MFA is disabled, should use SCOPE_NO_OPENID which doesn't include "openid"
		assertThat("incorrect query string", loginURI.getQuery(),
				containsString("scope=/authenticate"));
		assertThat("incorrect query string", loginURI.getQuery(),
				containsString("state=mystate456"));
		assertThat("incorrect query string", loginURI.getQuery(),
				containsString("response_type=code"));
		// Verify that "openid" is NOT in the scope when MFA is disabled
		assertThat("scope should not contain openid", loginURI.getQuery(), not(containsString("openid")));
	}

}
