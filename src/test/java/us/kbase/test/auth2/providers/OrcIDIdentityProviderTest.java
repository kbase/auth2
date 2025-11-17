package us.kbase.test.auth2.providers;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.list;
import static us.kbase.test.auth2.TestCommon.set;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.MFAStatus;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.Builder;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;
import us.kbase.auth2.lib.identity.IdentityProviderResponse;
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
	
	private static final IdentityProviderConfig CFG_NO_MFA;
	private static final IdentityProviderConfig CFG_MFA;
	static {
		try {
			Builder base = IdentityProviderConfig.getBuilder(
					OrcIDIdentityProviderFactory.class.getName(),
					new URL("https://ologin.com"),
					new URL("https://osetapiurl.com"),
					"ofoo",
					"obar",
					new URL("https://ologinredir.com"),
					new URL("https://olinkredir.com"))
					.withEnvironment("myenv",
							new URL("https://myologinred.com"), new URL("https://myolinkred.com"));
			CFG_MFA = base.build();
			CFG_NO_MFA = base.withCustomConfiguration("disable-mfa", "true").build();
		} catch (IdentityProviderConfigurationException | MalformedURLException e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}
	
	@Test
	public void simpleOperationsWithConfiguratorWithMFA() throws Exception {
		final OrcIDIdentityProviderFactory gc = new OrcIDIdentityProviderFactory();
		
		final IdentityProvider oip = gc.configure(CFG_MFA);
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
	public void simpleOperationsWithoutConfiguratorWithoutMFA() throws Exception {
		
		final IdentityProvider oip = new OrcIDIdentityProvider(CFG_NO_MFA);
		assertThat("incorrect provider name", oip.getProviderName(), is("OrcID"));
		assertThat("incorrect environments", oip.getEnvironments(), is(set("myenv")));
		assertThat("incorrect login url", oip.getLoginURI("foo5", "pkce", false, null),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=%2Fauthenticate" +
						"&state=foo5&redirect_uri=https%3A%2F%2Fologinredir.com" +
						"&response_type=code&client_id=ofoo")));
		assertThat("incorrect link url", oip.getLoginURI("foo6", "pkce", true, null),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=%2Fauthenticate" +
						"&state=foo6&redirect_uri=https%3A%2F%2Folinkredir.com" +
						"&response_type=code&client_id=ofoo")));
		
		assertThat("incorrect login url", oip.getLoginURI("foo3", "pkce", false, "myenv"),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=%2Fauthenticate" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fmyologinred.com" +
						"&response_type=code&client_id=ofoo")));
		assertThat("incorrect link url", oip.getLoginURI("foo4", "pkce", true, "myenv"),
				is(new URI("https://ologin.com/oauth/authorize?" +
						"scope=%2Fauthenticate" +
						"&state=foo4&redirect_uri=https%3A%2F%2Fmyolinkred.com" +
						"&response_type=code&client_id=ofoo")));
		
	}
	
	@Test
	public void createFail() throws Exception {
		failCreate(null, new NullPointerException("idc"));
		failCreate(IdentityProviderConfig.getBuilder(
				"foo",
				CFG_NO_MFA.getLoginURL(),
				CFG_NO_MFA.getApiURL(),
				CFG_NO_MFA.getClientID(),
				CFG_NO_MFA.getClientSecret(),
				CFG_NO_MFA.getLoginRedirectURL(),
				CFG_NO_MFA.getLinkRedirectURL())
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
		final IdentityProvider idp = new OrcIDIdentityProvider(CFG_NO_MFA);
		failGetIdentities(idp, null, "pkce", true, new IllegalArgumentException(
				"authcode cannot be null or empty"));
		failGetIdentities(idp, "  \t  \n  ", "pkce", true, new IllegalArgumentException(
				"authcode cannot be null or empty"));
	}
	
	@Test
	public void noSuchEnvironment() throws Exception {
		final IdentityProvider idp = new OrcIDIdentityProvider(CFG_NO_MFA);
		
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
	
	private IdentityProviderConfig getTestIDConfig() throws Exception {
		return getTestIDConfig(false);
	}
	
	private IdentityProviderConfig getTestIDConfig(final boolean withMFA) throws Exception {
		final Builder b = IdentityProviderConfig.getBuilder(
				OrcIDIdentityProviderFactory.class.getName(),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"ofoo",
				"obar",
				new URL("https://ologinredir.com"),
				new URL("https://olinkredir.com"))
				.withEnvironment(
						"e3", new URL("https://lo.com"), new URL("https://li.com"));
		if (!withMFA) {
			b.withCustomConfiguration("disable-mfa", "true");
		}
		return b.build();
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
		
		setUpCallAuthToken(acode, null, redir, cliid, clisec, "name", "fake ID");
		failGetIdentities(idp, acode, "pkce", false, e);
		setUpCallAuthToken(acode, "\t  ", redir, cliid, clisec, "name", "fake ID");
		failGetIdentities(idp, acode, "pkce", false, e);
		
		setUpCallAuthToken(acode, "fake token", redir, cliid, clisec, "my name", null);
		failGetIdentities(idp, acode, "pkce", false, new IdentityRetrievalException(
				"No id was returned by OrcID"));
		setUpCallAuthToken(acode, "fake token", redir, cliid, clisec, "my name", "   \t  \n  ");
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
	public void returnsBadResponseJWT() throws Exception {
		final String orcID = "0000-0001-1234-5678";
				
		failParseJWT(null, new IdentityRetrievalException(
				"No JWT token provided by ORCID. For non-member API applications, "
				+ "set disable-mfa to true in provider configuration"
		));
		failParseJWT("  \t   ", new IdentityRetrievalException(
				"No JWT token provided by ORCID. For non-member API applications, "
				+ "set disable-mfa to true in provider configuration"
		));
		failParseJWT("who wrote this bloody token", new IdentityRetrievalException(
				"Invalid JWT format from ORCID: expected 3 parts, got 1")
		);
		failParseJWT("header.payload", new IdentityRetrievalException(
				"Invalid JWT format from ORCID: expected 3 parts, got 2"));
		failParseJWT("invalid.jwt.token", new IdentityRetrievalException(
				"Unable to parse JWT payload from ORCID"
		));
		failParseJWT(
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid==base64!!.signature",
				new IdentityRetrievalException("Unable to decode JWT from ORCID")
		);
		final String invalidJSON = "{\"sub\":\"" + orcID + "\",\"amr\":}";
		final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(invalidJSON.getBytes());
		final String invalidJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + 
				encodedPayload + ".signature";
		failParseJWT(invalidJWT, new IdentityRetrievalException(
				"Unable to parse JWT payload from ORCID")
		);
		failParseJWT(
				jwt(orcID, map("amr", Collections.emptyMap())), new IdentityRetrievalException(
						"AMR claim from ORCID in unexpected format: {}"));
	}
	
	private void failParseJWT(final String jwt, final Exception expected) throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = getTestIDConfig(true);
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthToken(
				authCode,
				"footoken3",
				"https://ologinredir.com",
				idconfig.getClientID(),
				idconfig.getClientSecret(),
				" My name ",
				orcID,
				jwt
		);
		failGetIdentities(
				idp,
				authCode,
				"pkce",
				false,
				expected
		);
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
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec, "my name", orcID);
		setupCallID(authtoken, orcID, APP_JSON, 200, "bleah");
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Unable to parse response from OrcID service."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec, "my name", orcID);
		setupCallID(authtoken, orcID, "text/html", 200, MAPPER.writeValueAsString(
				map("id", "id1", "displayName", "dispname1", "emails", Arrays.asList(
						map("value", "email1")))));
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Unable to parse response from OrcID service."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec, "my name", orcID);
		setupCallID(authtoken, orcID, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Got unexpected HTTP code and unparseable " +
				"response from OrcID service: 500. Response: " + STRING1000));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec, "my name", orcID);
		setupCallID(authtoken, orcID, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Got unexpected HTTP code and unparseable " +
				"response from OrcID service: 500. Truncated response: " + STRING1000));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec, "my name", orcID);
		setupCallID(authtoken, orcID, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Got unexpected HTTP code with no response " +
				"body from OrcID service: 500."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec, "my name", orcID);
		setupCallID(authtoken, orcID, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"Got unexpected HTTP code with no error in " +
				"the response body from OrcID service: 500."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec, "my name", orcID);
		setupCallID(authtoken, orcID, APP_JSON, 401, MAPPER.writeValueAsString(
				map("error", "whee!", "error_description", "whoo!")));
		failGetIdentities(idp, authCode, "pkce", false, new IdentityRetrievalException(
				"OrcID service returned an error. HTTP code: 401. " +
				"Error: whee!. Error description: whoo!"));
	}
	
	@Test
	public void getIdentityWithLoginURL() throws Exception {
		/* For now we only test MFA with login since it's only relevant there and the code
		 * path is identical to linking. The only difference is the redirect url transmitted to
		 * OrcID
		 */
		final String orcID = "0000-0001-1234-5678";
		// MFA checking is skipped 
		getIdentityWithLoginURL(orcID, null, map(), null, MFAStatus.UNKNOWN);
		getIdentityWithLoginURL(
				orcID,
				null,
				map("email", null),
				jwt(orcID, map("iss", "https://orcid.org")),
				MFAStatus.UNKNOWN
		);
		getIdentityWithLoginURL(
				orcID,
				null,
				map("email", Collections.emptyList()),
				jwt(orcID, map("amr", "pwd")),
				MFAStatus.NOT_USED
		);
		getIdentityWithLoginURL(
				orcID,
				null,
				map("email", Arrays.asList(map())),
				jwt(orcID, map("amr", "mfa")),
				MFAStatus.USED
		);
		getIdentityWithLoginURL(
				orcID,
				null,
				map("email", Arrays.asList(map("email", null))),
				jwt(orcID, map("amr", list())),
				MFAStatus.NOT_USED
		);
		getIdentityWithLoginURL(
				orcID,
				null,
				map("email", Arrays.asList(map("email", "   \t   \n "))),
				jwt(orcID, map("amr", list("pwd"))),
				MFAStatus.NOT_USED
		);
		getIdentityWithLoginURL(
				orcID,
				"email3",
				map("email", Arrays.asList(map("email", "email3"))),
				jwt(orcID, map("amr", list("pwd", "mfa"))),
				MFAStatus.USED
		);
	}
	
	private void getIdentityWithLoginURL(
			final String orcID,
			final String email,
			final Map<String, Object> identityResponse,
			final String jwt,
			final MFAStatus mfa
	) throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = getTestIDConfig(jwt != null);
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		
		setUpCallAuthToken(authCode, "footoken3", "https://ologinredir.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID, jwt
		);
		setupCallID(
				"footoken3", orcID, APP_JSON, 200, MAPPER.writeValueAsString(identityResponse)
		);
		final IdentityProviderResponse ipr = idp.getIdentities(authCode, "pkce", false, null);
		assertThat("incorrect ident set", ipr, is(IdentityProviderResponse.from(
				new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
						new RemoteIdentityDetails(orcID, "My name", email)
				),
				mfa
		)));
	}
	
	@Test
	public void getIdentityWithLoginURLAndEnvironment() throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthToken(authCode, "footoken3", "https://lo.com",
				idconfig.getClientID(), idconfig.getClientSecret(), " My name ", orcID);
		setupCallID("footoken3", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "email7")))));
		final IdentityProviderResponse ipr = idp.getIdentities(authCode, "pkce", false, "e3");
		assertThat("incorrect ident set", ipr, is(IdentityProviderResponse.from(
				new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
						new RemoteIdentityDetails(orcID, "My name", "email7"))
		)));
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
				.withCustomConfiguration("disable-mfa", "true")
				.build();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthToken(authCode, "footoken2", "https://olinkredir2.com",
				idconfig.getClientID(), idconfig.getClientSecret(),
				null, orcID);
		setupCallID("footoken2", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				response));
		final IdentityProviderResponse ipr = idp.getIdentities(authCode, "pkce", true, null);
		assertThat("incorrect ident set", ipr, is(IdentityProviderResponse.from(
				new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
						new RemoteIdentityDetails(orcID, null, email))
		)));
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
				.withCustomConfiguration("disable-mfa", "true")
				.build();
		final IdentityProvider idp = new OrcIDIdentityProvider(idconfig);
		final String orcID = "0000-0001-1234-5678";
		
		setUpCallAuthToken(authCode, "footoken2", "https://li.com",
				idconfig.getClientID(), idconfig.getClientSecret(),
				null, orcID);
		setupCallID("footoken2", orcID, APP_JSON, 200, MAPPER.writeValueAsString(
				map("email", Arrays.asList(map("email", "email4")))));
		final IdentityProviderResponse ipr = idp.getIdentities(authCode, "pkce", true, "e3");
		assertThat("incorrect ident set", ipr, is(IdentityProviderResponse.from(
				new RemoteIdentity(new RemoteIdentityID(ORCID, orcID),
						new RemoteIdentityDetails(orcID, null, "email4"))
		)));
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
		setUpCallAuthToken(
				authCode, authtoken, redirect, clientID, clientSecret, name, orcID, null
		);
	}
	
	private void setUpCallAuthToken(
			final String authCode,
			final String authtoken,
			final String redirect,
			final String clientID,
			final String clientSecret,
			final String name,
			final String orcID,
			final String idToken
			)
			throws Exception {
		Map<String, Object> resp = map(
				"access_token", authtoken,
				"name", name,
				"orcid", orcID
		);
		if (idToken != null) {
			resp.put("id_token", idToken);
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
			).respond(
				new HttpResponse()
					.withStatusCode(200)
					.withHeader(CONTENT_TYPE, APP_JSON)
					.withBody(MAPPER.writeValueAsString(resp))
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
	
	private String jwt(final String orcID, final Map<String, Object> payload) throws Exception {
		final String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		payload.put("sub", orcID);
		final String paystr = MAPPER.writeValueAsString(payload);
		
		final String encodedHeader = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(header.getBytes());
		final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
				.encodeToString(paystr.getBytes());
		return encodedHeader + "." + encodedPayload + ".signature";
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
