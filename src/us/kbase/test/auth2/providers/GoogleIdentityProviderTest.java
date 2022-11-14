package us.kbase.test.auth2.providers;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
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
			CFG = IdentityProviderConfig.getBuilder(
					GoogleIdentityProviderFactory.class.getName(),
					new URL("https://glogin.com"),
					new URL("https://gsetapiurl.com"),
					"gfoo",
					"gbar",
					new URL("https://gloginredir.com"),
					new URL("https://glinkredir.com"))
					.withEnvironment("myenv",
							new URL("https://mygloginred.com"), new URL("https://myglinkred.com"))
					.withCustomConfiguration("people-api-host", "https://gpeople.com")
					.build();
		} catch (IdentityProviderConfigurationException | MalformedURLException e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}
	
	@Test
	public void simpleOperationsWithConfigurator() throws Exception {
		final GoogleIdentityProviderFactory gc = new GoogleIdentityProviderFactory();
		
		final IdentityProvider gip = gc.configure(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Google"));
		assertThat("incorrect environments", gip.getEnvironments(), is(set("myenv")));
		assertThat("incorrect login url", gip.getLoginURI("foo3", false, null),
				is(new URI("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=profile+email" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fgloginredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		assertThat("incorrect link url", gip.getLoginURI("foo4", true, null),
				is(new URI("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=profile+email" +
						"&state=foo4&redirect_uri=https%3A%2F%2Fglinkredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		
		assertThat("incorrect login url", gip.getLoginURI("foo3", false, "myenv"),
				is(new URI("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=profile+email" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fmygloginred.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		assertThat("incorrect link url", gip.getLoginURI("foo4", true, "myenv"),
				is(new URI("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=profile+email" +
						"&state=foo4&redirect_uri=https%3A%2F%2Fmyglinkred.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
	}
	
	@Test
	public void simpleOperationsWithoutConfigurator() throws Exception {
		
		final IdentityProvider gip = new GoogleIdentityProvider(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Google"));
		assertThat("incorrect environments", gip.getEnvironments(), is(set("myenv")));
		assertThat("incorrect login url", gip.getLoginURI("foo5", false, null),
				is(new URI("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=profile+email" +
						"&state=foo5&redirect_uri=https%3A%2F%2Fgloginredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		assertThat("incorrect link url", gip.getLoginURI("foo6", true, null),
				is(new URI("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=profile+email" +
						"&state=foo6&redirect_uri=https%3A%2F%2Fglinkredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		
		assertThat("incorrect login url", gip.getLoginURI("foo3", false, "myenv"),
				is(new URI("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=profile+email" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fmygloginred.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		assertThat("incorrect link url", gip.getLoginURI("foo4", true, "myenv"),
				is(new URI("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=profile+email" +
						"&state=foo4&redirect_uri=https%3A%2F%2Fmyglinkred.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		
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
	
	@Test
	public void noSuchEnvironment() throws Exception {
		final IdentityProvider idp = new GoogleIdentityProvider(CFG);
		
		failGetIdentities(idp, "foo", true, "myenv1", new NoSuchEnvironmentException("myenv1"));
		failGetIdentities(idp, "foo", false, "myenv1", new NoSuchEnvironmentException("myenv1"));
	}
	
	private void failGetIdentities(
			final IdentityProvider idp,
			final String authcode,
			final boolean link,
			final Exception exception) throws Exception {
		failGetIdentities(idp, authcode, link, null, exception);
	}
	
	private void failGetIdentities(
			final IdentityProvider idp,
			final String authcode,
			final boolean link,
			final String env,
			final Exception exception) throws Exception {
		try {
			idp.getIdentities(authcode, link, env);
			fail("got identities with bad setup");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	private IdentityProviderConfig getTestIDConfig()
			throws IdentityProviderConfigurationException, MalformedURLException,
			URISyntaxException {
		return IdentityProviderConfig.getBuilder(
				GoogleIdentityProviderFactory.class.getName(),
				new URL("https://glogin.com"),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"gfoo",
				"gbar",
				new URL("https://gloginredir.com"),
				new URL("https://glinkredir.com"))
				.withEnvironment("e2", new URL("http://lo.com"), new URL("http://li.com"))
				.withCustomConfiguration("people-api-host", "http://localhost:" +
						mockClientAndServer.getPort())
				.build();
	}
	
	@Test
	public void returnsBadResponseOAuth() throws Exception {
		final IdentityProviderConfig cfg = getTestIDConfig();
		final IdentityProvider idp = new GoogleIdentityProvider(cfg);
		final String redir = cfg.getLoginRedirectURL().toString();
		final String cliid = cfg.getClientID();
		final String clisec = cfg.getClientSecret();
		final String authCode = "foo10";
		
		setUpOAuthCall(authCode, redir, cliid, clisec, APP_JSON, 200, "foo bar");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Unable to parse response from Google service."));
		
		setUpOAuthCall(authCode, redir, cliid, clisec, "text/html", 200,
				"{\"access_token\":\"foobar\"}");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Unable to parse response from Google service."));
		
		setUpOAuthCall(authCode, redir, cliid, clisec, APP_JSON, 500, STRING1000);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code and unparseable response " +
				"from Google service: 500. Response: " + STRING1000));
		
		setUpOAuthCall(authCode, redir, cliid, clisec, APP_JSON, 500, STRING1001);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code and unparseable response " +
				"from Google service: 500. Truncated response: " + STRING1000));
		
		setUpOAuthCall(authCode, redir, cliid, clisec, APP_JSON, 500, null);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code with no response body " +
				"from Google service: 500."));
		
		setUpOAuthCall(authCode, redir, cliid, clisec, APP_JSON, 500, "{}");
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Authtoken retrieval failed: Got unexpected HTTP code with no error in the " +
				"response body from Google service: 500."));
		
		setUpOAuthCall(authCode, redir, cliid, clisec, APP_JSON, 500,
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
		
		setUpOAuthCall(authCode, null, redir, cliid, clisec);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No ID token in response from Google"));
		
		setUpOAuthCall(authCode, "    \t    ", redir, cliid, clisec);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No ID token in response from Google"));
		
		setUpOAuthCall(authCode, "foo", redir, cliid, clisec);
		try {
			idp.getIdentities(authCode, false, null);
			fail("got identities with bad setup");
		} catch (Exception got) {
			final String prefix = "10030 Identity retrieval failed: Unable to decode JWT: ";
			assertThat("incorrect exception. trace:\n" + ExceptionUtils.getStackTrace(got),
					got.getMessage(), anyOf(
							is(prefix + "1"),  // java 8
							is(prefix + "Index 1 out of bounds for length 1"))); // java 11
			assertThat("incorrect exception type", got,
					instanceOf(IdentityRetrievalException.class));
		}
		
		setUpOAuthCall(authCode, "foo.7.bar", redir, cliid, clisec);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"Unable to decode JWT: Input byte[] should at least have 2 bytes " +
				"for base64 bytes"));
		
		setUpOAuthCall(authCode, "foo.notjson.bar", redir, cliid, clisec);
		try {
			idp.getIdentities(authCode, false, null);
			fail("got identities with bad setup");
		} catch (IdentityRetrievalException e) {
			assertThat("incorrect error", e.getMessage(), containsString(
					"10030 Identity retrieval failed: Unable to decode JWT: " + 
					"Unexpected character ((CTRL-CHAR, code 158)): expected a valid " +
					"value (number, String, array, object, 'true', 'false' or 'null')\n at " +
					"[Source: "));
			assertThat("incorrect error", e.getMessage(), containsString(" line: 1, column: 2]"));
		}
		
		final Map<String, String> payload = new HashMap<>();
		
		setUpOAuthCall(authCode, "foo." + b64json(payload) + ".bar", redir, cliid, clisec);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No username included in response from Google"));
		
		payload.put("email", null);
		setUpOAuthCall(authCode, "foo." + b64json(payload) + ".bar", redir, cliid, clisec);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No username included in response from Google"));
		
		payload.put("email", "   \t    ");
		setUpOAuthCall(authCode, "foo." + b64json(payload) + ".bar", redir, cliid, clisec);
		failGetIdentities(idp, authCode, false, new IdentityRetrievalException(
				"No username included in response from Google"));
	}
	
	private String b64json(final Map<String, String> payload) throws Exception {
		final String json = MAPPER.writeValueAsString(payload);
		return Base64.getUrlEncoder().encodeToString(json.getBytes());
	}

	@Test
	public void getIdentityWithLoginURL() throws Exception {
		getIdentityWithLoginURL(null, "https://gloginredir.com");
	}

	@Test
	public void getIdentityWithLoginURLAndEnvironment() throws Exception {
		getIdentityWithLoginURL("e2", "http://lo.com");
	}
	
	private void getIdentityWithLoginURL(final String env, final String url) throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = getTestIDConfig();
		final IdentityProvider idp = new GoogleIdentityProvider(idconfig);
		
		final Map<String, String> payload = ImmutableMap.of(
				"sub", "id7",
				"email", "email3");
		
		setUpOAuthCall(authCode, "foo." + b64json(payload) + ".bar", url,
				idconfig.getClientID(), idconfig.getClientSecret());
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, false, env);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(GOOGLE, "id7"),
				new RemoteIdentityDetails("email3", null, "email3")));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	@Test
	public void getIdentityWithLinkURL() throws Exception {
		getIdentityWithLinkURL(null, "https://glinkredir2.com");
	}

	@Test
	public void getIdentityWithLinkURLAndEnvironment() throws Exception {
		getIdentityWithLinkURL("e2", "http://li2.com");
	}

	private void getIdentityWithLinkURL(final String env, final String url) throws Exception {
		final String authCode = "authcode2";
		final IdentityProviderConfig idconfig = IdentityProviderConfig.getBuilder(
				GoogleIdentityProviderFactory.class.getName(),
				new URL("https://glogin2.com"),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"someclient",
				"bar2",
				new URL("https://gloginredir2.com"),
				new URL("https://glinkredir2.com"))
				.withEnvironment("e2", new URL("http://lo.com"), new URL("http://li2.com"))
				.withCustomConfiguration("people-api-host",
						"http://localhost:" + mockClientAndServer.getPort())
				.build();
		final IdentityProvider idp = new GoogleIdentityProvider(idconfig);
		
		final Map<String, String> payload = ImmutableMap.of(
				"sub", "id1",
				"email", "email1",
				"name", "dispname1");
		
		setUpOAuthCall(authCode, "foo." + b64json(payload) + ".bar", url,
				idconfig.getClientID(), idconfig.getClientSecret());
		final Set<RemoteIdentity> rids = idp.getIdentities(authCode, true, env);
		assertThat("incorrect number of idents", rids.size(), is(1));
		final Set<RemoteIdentity> expected = new HashSet<>();
		expected.add(new RemoteIdentity(new RemoteIdentityID(GOOGLE, "id1"),
				new RemoteIdentityDetails("email1", "dispname1", "email1")));
		assertThat("incorrect ident set", rids, is(expected));
	}
	
	private void setUpOAuthCall(
			final String authCode,
			final String idtoken,
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
					.withBody(MAPPER.writeValueAsString(map("id_token", idtoken)))
			);
	}
	
	private void setUpOAuthCall(
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
