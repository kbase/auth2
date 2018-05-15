package us.kbase.test.auth2.providers;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
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
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;
import us.kbase.auth2.providers.GoogleIdentityProviderFactory;
import us.kbase.auth2.providers.GoogleIdentityProviderFactory.GoogleIdentityProvider;
import us.kbase.test.auth2.TestCommon;

public class GoogleIdentityProviderTest {
	
	// a lot of code in common with Globus, try to make common class at some point 

	private static final String CONTENT_TYPE = "content-type";
	private static final String ACCEPT = "accept";
	private static final String APP_JSON = "application/json";
	private static final String GOOGLE = "Google";
	
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
			CFG = new IdentityProviderConfig(
					GoogleIdentityProviderFactory.class.getName(),
					new URL("https://glogin.com"),
					new URL("https://gsetapiurl.com"),
					"gfoo",
					"gbar",
					new URL("https://gloginredir.com"),
					new URL("https://glinkredir.com"),
					Collections.emptyMap());
		} catch (IdentityProviderConfigurationException | MalformedURLException e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}
	
	@Test
	public void simpleOperationsWithConfigurator() throws Exception {
		final GoogleIdentityProviderFactory gc = new GoogleIdentityProviderFactory();
		
		final IdentityProvider gip = gc.configure(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Google"));
		assertThat("incorrect login url", gip.getLoginURL("foo3", false),
				is(new URL("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplus.me+profile+email" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fgloginredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		assertThat("incorrect link url", gip.getLoginURL("foo4", true),
				is(new URL("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplus.me+profile+email" +
						"&state=foo4&redirect_uri=https%3A%2F%2Fglinkredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
	}
	
	@Test
	public void simpleOperationsWithoutConfigurator() throws Exception {
		
		final IdentityProvider gip = new GoogleIdentityProvider(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Google"));
		assertThat("incorrect login url", gip.getLoginURL("foo5", false),
				is(new URL("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplus.me+profile+email" +
						"&state=foo5&redirect_uri=https%3A%2F%2Fgloginredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		assertThat("incorrect link url", gip.getLoginURL("foo6", true),
				is(new URL("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplus.me+profile+email" +
						"&state=foo6&redirect_uri=https%3A%2F%2Fglinkredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		
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
				CFG.getLoginRedirectURL(),
				CFG.getLinkRedirectURL(),
				Collections.emptyMap()),
				new IllegalArgumentException(
						"Configuration class name doesn't match factory class name: foo"));
	}
	
	private void failCreate(final IdentityProviderConfig cfg, final Exception exception) {
		try {
			new GoogleIdentityProvider(cfg);
			fail("created bad globus id provider");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void illegalAuthcode() throws Exception {
		final IdentityProvider idp = new GoogleIdentityProvider(CFG);
		failGetIdentities(idp, null, true, new IllegalArgumentException(
				"authcode cannot be null or empty"));
		failGetIdentities(idp, "  \t  \n  ", true, new IllegalArgumentException(
				"authcode cannot be null or empty"));
	}
	
	private void failGetIdentities(
			final IdentityProvider idp,
			final String authcode,
			final boolean link,
			final Exception exception) throws Exception {
		try {
			idp.getIdentities(authcode, link);
			fail("got identities with bad setup");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	private IdentityProviderConfig getTestIDConfig()
			throws IdentityProviderConfigurationException, MalformedURLException,
			URISyntaxException {
		return new IdentityProviderConfig(
				GoogleIdentityProviderFactory.class.getName(),
				new URL("https://glogin.com"),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"gfoo",
				"gbar",
				new URL("https://gloginredir.com"),
				new URL("https://glinkredir.com"),
				Collections.emptyMap());
	}
	
	@Test
	public void returnsIllegalAuthtoken() throws Exception {
		final IdentityProviderConfig testIDConfig = getTestIDConfig();
		final IdentityProvider idp = new GoogleIdentityProvider(testIDConfig);
		final String redir = testIDConfig.getLoginRedirectURL().toString();
		final IdentityRetrievalException e =
				new IdentityRetrievalException("No access token was returned by Google");
		setUpCallAuthToken("authcode6", null, redir,
				testIDConfig.getClientID(), testIDConfig.getClientSecret());
		failGetIdentities(idp, "authcode6", false, e);
		setUpCallAuthToken("authcode6", "\t  ", redir,
				testIDConfig.getClientID(), testIDConfig.getClientSecret());
		failGetIdentities(idp, "authcode6", false, e);
	}
	
	@Test
	public void returnsBadResponseAuthToken() throws Exception {
		final IdentityProviderConfig cfg = getTestIDConfig();
		final IdentityProvider idp = new GoogleIdentityProvider(cfg);
		final String redir = cfg.getLoginRedirectURL().toString();
		final String cliid = cfg.getClientID();
		final String clisec = cfg.getClientSecret();
		final String authCode = "foo10";
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 200, "foo bar");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Unable to parse response from Google service."));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, "text/html", 200,
				"{\"access_token\":\"foobar\"}");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Unable to parse response from Google service."));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code and unparseable response " +
				"from Google service: 500. Response: " + STRING1000));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code and unparseable response " +
				"from Google service: 500. Truncated response: " + STRING1000));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code with no response body " +
				"from Google service: 500."));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code with no error in the " +
				"response body from Google service: 500."));
		
		setUpCallAuthToken(authCode, redir, cliid, clisec, APP_JSON, 500,
				"{\"error\":\"whee!\",\"error_description\":\"whoo!\"}");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Google service returned an error. HTTP code: 500. " +
				"Error: whee!. Error description: whoo!"));
	}
	
	@Test
	public void returnsBadIdentity() throws Exception {
		final IdentityProviderConfig cfg = getTestIDConfig();
		final IdentityProvider idp = new GoogleIdentityProvider(cfg);
		final String redir = cfg.getLoginRedirectURL().toString();
		final String cliid = cfg.getClientID();
		final String clisec = cfg.getClientSecret();
		final String authCode = "foo11";
		
		setUpCallAuthToken(authCode, "token1", redir, cliid, clisec);
		setupCallID("token1", APP_JSON, 200, MAPPER.writeValueAsString(
				map("id", "id7", "displayName", null, "emails", null)));
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No username included in response from Google"));
		
		setUpCallAuthToken(authCode, "token1", redir, cliid, clisec);
		setupCallID("token1", APP_JSON, 200, MAPPER.writeValueAsString(
				map("id", "id7", "displayName", null, "emails", new ArrayList<String>())));
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No username included in response from Google"));
		
		setUpCallAuthToken(authCode, "token1", redir, cliid, clisec);
		setupCallID("token1", APP_JSON, 200, MAPPER.writeValueAsString(
				map("id", "id7", "displayName", null,
						"emails", Arrays.asList(map("value", null)))));
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No username included in response from Google"));
		
		setUpCallAuthToken(authCode, "token1", redir, cliid, clisec);
		setupCallID("token1", APP_JSON, 200, MAPPER.writeValueAsString(
				map("id", "id7", "displayName", null,
						"emails", Arrays.asList(map("value", " \t \n  ")))));
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No username included in response from Google"));
	}
	
	@Test
	public void returnsBadResponseIdentity() throws Exception {
		final IdentityProviderConfig cfg = getTestIDConfig();
		final IdentityProvider idp = new GoogleIdentityProvider(cfg);
		final String redir = cfg.getLoginRedirectURL().toString();
		final String cliid = cfg.getClientID();
		final String clisec = cfg.getClientSecret();
		final String authCode = "foo";
		final String authtoken = "bartoken";
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, APP_JSON, 200, "bleah");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Unable to parse response from Google service."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, "text/html", 200, MAPPER.writeValueAsString(
				map("id", "id1", "displayName", "dispname1", "emails", Arrays.asList(
						map("value", "email1")))));
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Unable to parse response from Google service."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Got unexpected HTTP code and unparseable " +
				"response from Google service: 500. Response: " + STRING1000));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Got unexpected HTTP code and unparseable " +
				"response from Google service: 500. Truncated response: " + STRING1000));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Got unexpected HTTP code with no response " +
				"body from Google service: 500."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Got unexpected HTTP code with no error in " +
				"the response body from Google service: 500."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, APP_JSON, 401, MAPPER.writeValueAsString(
				map("error", null)));
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Got unexpected HTTP code with null error in the response body from Google " +
				"service: 401."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, APP_JSON, 404, MAPPER.writeValueAsString(
				map("error", new HashMap<String, String>())));
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Got unexpected HTTP code with null error in the response body from Google " +
						"service: 404."));
		
		setUpCallAuthToken(authCode, authtoken, redir, cliid, clisec);
		setupCallID(authtoken, APP_JSON, 400, MAPPER.writeValueAsString(
				map("error", map("message", "foobar"))));
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Google service returned an error. HTTP code: 400. Error: foobar"));
	}
	
	@Test
	public void getIdentityWithLoginURL() throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new GoogleIdentityProvider(idconfig);
		
		setUpCallAuthToken(authCode, "footoken3", "https://gloginredir.com",
				idconfig.getClientID(), idconfig.getClientSecret());
		setupCallID("footoken3", APP_JSON, 200, MAPPER.writeValueAsString(
				map("id", "id7", "displayName", null, "emails", Arrays.asList(
						map("value", "email3")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, false);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(GOOGLE, "id7"),
				new RemoteIdentityDetails("email3", null, "email3")));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	@Test
	public void getIdentityWithLinkURL() throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = new IdentityProviderConfig(
				GoogleIdentityProviderFactory.class.getName(),
				new URL("https://glogin2.com"),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"someclient",
				"bar2",
				new URL("https://gloginredir2.com"),
				new URL("https://glinkredir2.com"),
				Collections.emptyMap());
		final IdentityProvider idp = new GoogleIdentityProvider(idconfig);
		
		setUpCallAuthToken(authCode, "footoken2", "https://glinkredir2.com",
				idconfig.getClientID(), idconfig.getClientSecret());
		setupCallID("footoken2", APP_JSON, 200, MAPPER.writeValueAsString(
				map("id", "id1", "displayName", "dispname1", "emails", Arrays.asList(
						map("value", "email1")))));
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, true);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(GOOGLE, "id1"),
				new RemoteIdentityDetails("email1", "dispname1", "email1")));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	private void setUpCallAuthToken(
			final String authCode,
			final String authtoken,
			final String redirect,
			final String clientID,
			final String clientSecret)
			throws Exception {
		mockClientAndServer.when(
				new HttpRequest()
					.withMethod("POST")
					.withPath("/oauth2/v4/token")
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
					.withBody(MAPPER.writeValueAsString(map("access_token", authtoken)))
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
					.withPath("/oauth2/v4/token")
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
			final String contentType,
			final int respCode,
			final String body) {
		mockClientAndServer.when(
					new HttpRequest()
						.withMethod("GET")
						.withPath("/plus/v1/people/me")
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
}
