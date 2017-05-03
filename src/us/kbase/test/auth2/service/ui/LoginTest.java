package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.service.ServiceTestUtils.enableLogin;
import static us.kbase.test.auth2.service.ServiceTestUtils.enableProvider;
import static us.kbase.test.auth2.service.ServiceTestUtils.enableRedirect;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestHTML;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;
import static us.kbase.test.auth2.service.ServiceTestUtils.setLoginCompleteRedirect;

import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.client.ClientProperties;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TemporaryIdentities;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.common.test.RegexMatcher;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.MockIdentityProviderFactory;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

public class LoginTest {
	
	private static final String DB_NAME = "test_login_ui";
	private static final String COOKIE_NAME = "login-cookie";
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "id1"),
			new RemoteIdentityDetails("user1", "full1", "e1@g.com"));
	
	private static final RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "id2"),
			new RemoteIdentityDetails("user2", "full2", "e2@g.com"));
	
	private static final RemoteIdentity REMOTE3 = new RemoteIdentity(
			new RemoteIdentityID("prov", "id3"),
			new RemoteIdentityDetails("user3", "full3", "e3@g.com"));
	
	private static final Client CLI = ClientBuilder.newClient();
	
	private static MongoStorageTestManager manager = null;
	private static StandaloneAuthServer server = null;
	private static int port = -1;
	private static String host = null;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		TestCommon.stfuLoggers();
		manager = new MongoStorageTestManager(DB_NAME);
		final Path cfgfile = ServiceTestUtils.generateTempConfigFile(manager, DB_NAME, COOKIE_NAME);
		TestCommon.getenv().put("KB_DEPLOYMENT_CONFIG", cfgfile.toString());
		server = new StandaloneAuthServer(KBaseAuthConfig.class.getName());
		new ServerThread(server).start();
		System.out.println("Main thread waiting for server to start up");
		while (server.getPort() == null) {
			Thread.sleep(1000);
		}
		port = server.getPort();
		host = "http://localhost:" + port;
	}
	
	@AfterClass
	public static void afterClass() throws Exception {
		if (server != null) {
			server.stop();
		}
		if (manager != null) {
			manager.destroy();
		}
	}
	
	@Before
	public void beforeTest() throws Exception {
		ServiceTestUtils.resetServer(manager, host, COOKIE_NAME);
	}
	
	@Test
	public void startDisplayLoginDisabled() throws Exception {
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/login/");
		final String res = wt.request().get().readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void startDisplayWithOneProvider() throws Exception {
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		
		final WebTarget wt = CLI.target(host + "/login/");
		final String res = wt.request().get().readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void startDisplayWithTwoProviders() throws Exception {
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableProvider(host, COOKIE_NAME, admintoken, "prov2");
		
		final WebTarget wt = CLI.target(host + "/login/");
		final String res = wt.request().get().readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}

	@Test
	public void suggestName() throws Exception {
		final WebTarget wt = CLI.target(host + "/login/suggestname/***FOOTYPANTS***");
		@SuppressWarnings("unchecked")
		final Map<String, String> res = wt.request().get().readEntity(Map.class);
		assertThat("incorrect expected name", res,
				is(ImmutableMap.of("availablename", "footypants")));
	}
	
	@Test
	public void loginStartMinimalInput() throws Exception {
		final Form form = new Form();
		form.param("provider", "prov1");
		final NewCookie expectedsession = new NewCookie("issessiontoken", "true",
				"/login", null, "session choice", 30 * 60, false);
		final NewCookie expectedredirect = new NewCookie("loginredirect", "no redirect",
				"/login", null, "redirect url", 0, false);

		loginStart(form, expectedsession, expectedredirect);
	}
	
	@Test
	public void loginStartEmptyStrings() throws Exception {
		final Form form = new Form();
		form.param("provider", "prov1");
		form.param("redirecturl", "  \t   \n   ");
		form.param("stayloggedin", "  \t   \n   ");
		final NewCookie expectedsession = new NewCookie("issessiontoken", "true",
				"/login", null, "session choice", 30 * 60, false);
		final NewCookie expectedredirect = new NewCookie("loginredirect", "no redirect",
				"/login", null, "redirect url", 0, false);

		loginStart(form, expectedsession, expectedredirect);
	}
	
	@Test
	public void loginStartWithRedirectAndNonSessionCookie() throws Exception {
		final String redirect = "https://foobar.com/thingy/stuff";
		final Form form = new Form();
		form.param("provider", "prov1");
		form.param("redirecturl", redirect);
		form.param("stayloggedin", "f");
		final NewCookie expectedsession = new NewCookie("issessiontoken", "false",
				"/login", null, "session choice", 30 * 60, false);
		final NewCookie expectedredirect = new NewCookie("loginredirect", redirect,
				"/login", null, "redirect url", 30 * 60, false);

		loginStart(form, expectedsession, expectedredirect);
	}

	private void loginStart(
			final Form form,
			final NewCookie expectedsession,
			final NewCookie expectedredirect)
			throws Exception {
		final IdentityProvider provmock = MockIdentityProviderFactory
				.mocks.get("prov1");
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		
		final String url = "https://foo.com/someurlorother";
		
		final StateMatcher stateMatcher = new StateMatcher();
		when(provmock.getLoginURL(argThat(stateMatcher), eq(false))).thenReturn(new URL(url));
		
		final WebTarget wt = CLI.target(host + "/login/start");
		final Response res = wt.request().post(
				Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(url)));
		
		final NewCookie state = res.getCookies().get("loginstatevar");
		final NewCookie expectedstate = new NewCookie("loginstatevar", stateMatcher.capturedState,
				"/login/complete", null, "loginstate", 30 * 60, false);
		assertThat("incorrect state cookie", state, is(expectedstate));
		
		final NewCookie session = res.getCookies().get("issessiontoken");
		assertThat("incorrect session cookie", session, is(expectedsession));
		
		final NewCookie redirect = res.getCookies().get("loginredirect");
		assertThat("incorrect redirect cookie", redirect, is(expectedredirect));
	}
	
	@Test
	public void loginStartFailNoProvider() throws Exception {
		failLoginStart(new Form(), 400, "Bad Request", new MissingParameterException("provider"));
		
		final Form form = new Form();
		form.param("provider", null);
		failLoginStart(form, 400, "Bad Request", new MissingParameterException("provider"));
		
		final Form form2 = new Form();
		form2.param("provider", "   \t  \n   ");
		failLoginStart(form2, 400, "Bad Request", new MissingParameterException("provider"));
	}
	
	@Test
	public void loginStartFailNoSuchProvider() throws Exception {
		final Form form = new Form();
		form.param("provider", "prov3");
		failLoginStart(form, 401, "Unauthorized", new NoSuchIdentityProviderException("prov3"));
	}
	
	@Test
	public void loginStartFailBadRedirect() throws Exception {
		final Form form = new Form();
		form.param("provider", "fake");
		form.param("redirecturl", "this ain't no gotdamned url");
		failLoginStart(form, 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: this ain't no gotdamned url"));
		
		// toURI chokes on ^s
		final Form form2 = new Form();
		form2.param("provider", "fake");
		form2.param("redirecturl", "https://foobar.com/stuff/thingy?a=^h");
		failLoginStart(form2, 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: https://foobar.com/stuff/thingy?a=^h"));
		
		final Form form3 = new Form();
		form3.param("provider", "fake");
		form3.param("redirecturl", "https://foobar.com/stuff/thingy");
		failLoginStart(form3, 400, "Bad Request", new IllegalParameterException(
				"Post-login redirects are not enabled"));
		
		final IncomingToken adminToken = ServiceTestUtils.getAdminToken(manager);
		enableRedirect(host, adminToken, "https://foobar.com/stuff2/");
		failLoginStart(form3, 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: https://foobar.com/stuff/thingy"));
	}

	private void failLoginStart(
			final Form form,
			final int expectedHTTPCode,
			final String expectedHTTPError,
			final AuthException e)
			throws Exception {
		final WebTarget wt = CLI.target(host + "/login/start");
		final Response res = wt.request().header("Accept", MediaType.APPLICATION_JSON).post(
				Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

		failRequestJSON(res, expectedHTTPCode, expectedHTTPError, e);
	}
	
	@Test
	public void loginCompleteImmediateLoginMinimalInput() throws Exception {
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		loginCompleteImmediateLoginStoreUser(authcode);
		
		final WebTarget wt = loginCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("loginstatevar", state)
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		assertLoginProcessTokensRemoved(res);
		
		final NewCookie token = res.getCookies().get(COOKIE_NAME);
		final NewCookie expectedtoken = new NewCookie(COOKIE_NAME, token.getValue(),
				"/", null, "authtoken", -1, false);
		assertThat("incorrect auth cookie less token", token, is(expectedtoken));
		assertThat("incorrect token", token.getValue(), is(RegexMatcher.matches("[A-Z2-7]{32}")));
		
		loginCompleteImmediateLoginCheckToken(token);
	}
	
	@Test
	public void loginCompleteImmediateLoginEmptyStringInput() throws Exception {
		// also tests that the empty error string is ignored.
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		loginCompleteImmediateLoginStoreUser(authcode);
		
		final WebTarget wt = loginCompleteSetUpWebTargetEmptyError(authcode, state);
		final Response res = wt.request()
				.cookie("loginstatevar", state)
				.cookie("loginredirect", "   \t   ")
				.cookie("issessiontoken", "    \t   ")
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		assertLoginProcessTokensRemoved(res);
		
		final NewCookie token = res.getCookies().get(COOKIE_NAME);
		final NewCookie expectedtoken = new NewCookie(COOKIE_NAME, token.getValue(),
				"/", null, "authtoken", -1, false);
		assertThat("incorrect auth cookie less token", token, is(expectedtoken));
		assertThat("incorrect token", token.getValue(), is(RegexMatcher.matches("[A-Z2-7]{32}")));
		
		loginCompleteImmediateLoginCheckToken(token);
	}
	
	@Test
	public void loginCompleteImmediateLoginRedirectAndTrueSession() throws Exception {
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		loginCompleteImmediateLoginStoreUser(authcode);
		
		final WebTarget wt = loginCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("loginstatevar", state)
				.cookie("loginredirect", "https://foobar.com/thingy/stuff")
				.cookie("issessiontoken", "true")
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://foobar.com/thingy/stuff")));
		
		assertLoginProcessTokensRemoved(res);
		
		final NewCookie token = res.getCookies().get(COOKIE_NAME);
		final NewCookie expectedtoken = new NewCookie(COOKIE_NAME, token.getValue(),
				"/", null, "authtoken", -1, false);
		assertThat("incorrect auth cookie less token", token, is(expectedtoken));
		assertThat("incorrect token", token.getValue(), is(RegexMatcher.matches("[A-Z2-7]{32}")));
		
		loginCompleteImmediateLoginCheckToken(token);
	}
	
	@Test
	public void loginCompleteImmediateLoginRedirectAndFalseSession() throws Exception {
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		loginCompleteImmediateLoginStoreUser(authcode);
		
		final WebTarget wt = loginCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("loginstatevar", state)
				.cookie("loginredirect", "https://foobar.com/thingy/stuff")
				.cookie("issessiontoken", "false")
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://foobar.com/thingy/stuff")));
		
		assertLoginProcessTokensRemoved(res);
		
		final NewCookie token = res.getCookies().get(COOKIE_NAME);
		final NewCookie expectedtoken = new NewCookie(COOKIE_NAME, token.getValue(),
				"/", null, "authtoken", token.getMaxAge(), false);
		assertThat("incorrect auth cookie less token and max age", token, is(expectedtoken));
		assertThat("incorrect token", token.getValue(), is(RegexMatcher.matches("[A-Z2-7]{32}")));
		TestCommon.assertCloseTo(token.getMaxAge(), 14 * 24 * 3600, 10);
		
		loginCompleteImmediateLoginCheckToken(token);
	}

	private void loginCompleteImmediateLoginStoreUser(final String authcode) throws Exception {
		final RemoteIdentity remoteIdentity = loginCompleteSetUpProviderMock(authcode);
		
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("whee"), new DisplayName("dn"), Instant.ofEpochMilli(20000),
					remoteIdentity)
				.build());
	}

	private void loginCompleteImmediateLoginCheckToken(final NewCookie token) throws Exception {
		checkLoginToken(token.getValue(), Collections.emptyMap(), new UserName("whee"));
	}
	
	private void checkLoginToken(
			final Map<String, Object> uitoken,
			final Map<String, String> customContext,
			final UserName userName)
			throws Exception {
		
		assertThat("incorrect token context", uitoken.get("custom"), is(customContext));
		assertThat("incorrect token type", uitoken.get("type"), is("Login"));
		TestCommon.assertCloseToNow((long) uitoken.get("created"));
		assertThat("incorrect expires", uitoken.get("expires"),
				is((long) uitoken.get("created") + 14 * 24 * 3600 * 1000));
		UUID.fromString((String) uitoken.get("id")); // ensures id is a valid uuid
		assertThat("incorrect name", uitoken.get("name"), is((String) null));
		assertThat("incorrect user", uitoken.get("os"), is((String) null));
		assertThat("incorrect user", uitoken.get("osver"), is((String) null));
		assertThat("incorrect user", uitoken.get("agent"), is("Jersey"));
		assertThat("incorrect user", uitoken.get("agentver"), is("2.23.2"));
		assertThat("incorrect user", uitoken.get("device"), is((String) null));
		assertThat("incorrect user", uitoken.get("ip"), is("127.0.0.1"));
		
		checkLoginToken((String) uitoken.get("token"), customContext, userName);
	}
	
	private void checkLoginToken(
			final String token,
			final Map<String, String> customContext,
			final UserName userName)
			throws Exception {
		
		assertThat("incorrect token", token, is(RegexMatcher.matches("[A-Z2-7]{32}")));
		
		final StoredToken st = manager.storage.getToken(
				new IncomingToken(token).getHashedToken());
		
		final TokenCreationContext.Builder build = TokenCreationContext.getBuilder()
				.withIpAddress(InetAddress.getByName("127.0.0.1"))
				.withNullableAgent("Jersey", "2.23.2");
		
		for (final Entry<String, String> e: customContext.entrySet()) {
			build.withCustomContext(e.getKey(), e.getValue());
		}
		
		assertThat("incorrect token context", st.getContext(), is(build.build()));
		assertThat("incorrect token type", st.getTokenType(), is(TokenType.LOGIN));
		TestCommon.assertCloseToNow(st.getCreationDate());
		assertThat("incorrect expires", st.getExpirationDate(),
				is(st.getCreationDate().plusSeconds(14 * 24 * 3600)));
		assertThat("incorrect id", st.getId(), isA(UUID.class));
		assertThat("incorrect name", st.getTokenName(), is(Optional.absent()));
		assertThat("incorrect user", st.getUserName(), is(userName));
	}

	private void assertLoginProcessTokensRemoved(final Response res) {
		final NewCookie expectedstate = new NewCookie("loginstatevar", "no state",
				"/login/complete", null, "loginstate", 0, false);
		final NewCookie statecookie = res.getCookies().get("loginstatevar");
		assertThat("incorrect state cookie", statecookie, is(expectedstate));
		
		final NewCookie expectedsession = new NewCookie("issessiontoken", "no session",
				"/login", null, "session choice", 0, false);
		final NewCookie session = res.getCookies().get("issessiontoken");
		assertThat("incorrect session cookie", session, is(expectedsession));
		
		final NewCookie expectedredirect = new NewCookie("loginredirect", "no redirect",
				"/login", null, "redirect url", 0, false);
		final NewCookie redirect = res.getCookies().get("loginredirect");
		assertThat("incorrect redirect cookie", redirect, is(expectedredirect));
		
		final NewCookie expectedinprocess = new NewCookie("in-process-login-token", "no token",
				"/login", null, "logintoken", 0, false);
		final NewCookie inprocess = res.getCookies().get("in-process-login-token");
		assertThat("incorrect redirect cookie", inprocess, is(expectedinprocess));
	}
	
	@Test
	public void loginCompleteDelayedMinimalInput() throws Exception {
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final RemoteIdentity remoteIdentity = loginCompleteSetUpProviderMock(authcode);
		
		final WebTarget wt = loginCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("loginstatevar", state)
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/login/choice")));
		
		final NewCookie expectedredirect = new NewCookie("loginredirect", "no redirect",
				"/login", null, "redirect url", 0, false);
		final NewCookie redirect = res.getCookies().get("loginredirect");
		assertThat("incorrect redirect cookie", redirect, is(expectedredirect));
		
		final NewCookie expectedsession = new NewCookie("issessiontoken", "no session",
				"/login", null, "session choice", 0, false);
		final NewCookie session = res.getCookies().get("issessiontoken");
		assertThat("incorrect session cookie", session, is(expectedsession));
		
		loginCompleteDelayedCheckTempAndStateCookies(remoteIdentity, res);
	}
	
	@Test
	public void loginCompleteDelayedEmptyStringInputAndAlternateChoiceRedirect() throws Exception {
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		setLoginCompleteRedirect(host, admintoken, "https://whee.com/bleah");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final RemoteIdentity remoteIdentity = loginCompleteSetUpProviderMock(authcode);
		
		final WebTarget wt = loginCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("loginstatevar", state)
				.cookie("loginredirect", "   \t   ")
				.cookie("issessiontoken", "    \t   ")
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://whee.com/bleah")));
		
		final NewCookie expectedredirect = new NewCookie("loginredirect", "no redirect",
				"/login", null, "redirect url", 0, false);
		final NewCookie redirect = res.getCookies().get("loginredirect");
		assertThat("incorrect redirect cookie", redirect, is(expectedredirect));
		
		final NewCookie expectedsession = new NewCookie("issessiontoken", "no session",
				"/login", null, "session choice", 0, false);
		final NewCookie session = res.getCookies().get("issessiontoken");
		assertThat("incorrect session cookie", session, is(expectedsession));
		
		loginCompleteDelayedCheckTempAndStateCookies(remoteIdentity, res);
	}
	
	@Test
	public void loginCompleteDelayedLoginRedirectAndTrueSession() throws Exception {
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		setLoginCompleteRedirect(host, admintoken, "https://whee.com/bleah");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final RemoteIdentity remoteIdentity = loginCompleteSetUpProviderMock(authcode);
		
		final WebTarget wt = loginCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("loginstatevar", state)
				.cookie("loginredirect", "https://foobar.com/thingy/stuff")
				.cookie("issessiontoken", "true")
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://whee.com/bleah")));
		
		final NewCookie redirect = res.getCookies().get("loginredirect");
		final NewCookie expectedredirect = new NewCookie(
				"loginredirect", "https://foobar.com/thingy/stuff",
				"/login", null, "redirect url", redirect.getMaxAge(), false);
		assertThat("incorrect redirect cookie less max age", redirect, is(expectedredirect));
		TestCommon.assertCloseTo(redirect.getMaxAge(), 30 * 60, 10);
		
		final NewCookie session = res.getCookies().get("issessiontoken");
		final NewCookie expectedsession = new NewCookie("issessiontoken", "true",
				"/login", null, "session choice", session.getMaxAge(), false);
		assertThat("incorrect session cookie less max age", session, is(expectedsession));
		TestCommon.assertCloseTo(session.getMaxAge(), 30 * 60, 10);
		
		loginCompleteDelayedCheckTempAndStateCookies(remoteIdentity, res);
	}
	
	@Test
	public void loginCompleteDelayedLoginRedirectAndFalseSession() throws Exception {
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableRedirect(host, admintoken, "https://foobar.com/thingy");
		setLoginCompleteRedirect(host, admintoken, "https://whee.com/bleah");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final RemoteIdentity remoteIdentity = loginCompleteSetUpProviderMock(authcode);
		
		final WebTarget wt = loginCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("loginstatevar", state)
				.cookie("loginredirect", "https://foobar.com/thingy/stuff")
				.cookie("issessiontoken", "false")
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://whee.com/bleah")));
		
		final NewCookie redirect = res.getCookies().get("loginredirect");
		final NewCookie expectedredirect = new NewCookie(
				"loginredirect", "https://foobar.com/thingy/stuff",
				"/login", null, "redirect url", redirect.getMaxAge(), false);
		assertThat("incorrect redirect cookie less max age", redirect, is(expectedredirect));
		TestCommon.assertCloseTo(redirect.getMaxAge(), 30 * 60, 10);
		
		final NewCookie session = res.getCookies().get("issessiontoken");
		final NewCookie expectedsession = new NewCookie("issessiontoken", "false",
				"/login", null, "session choice", session.getMaxAge(), false);
		assertThat("incorrect session cookie less max age", session, is(expectedsession));
		TestCommon.assertCloseTo(session.getMaxAge(), 30 * 60, 10);
		
		loginCompleteDelayedCheckTempAndStateCookies(remoteIdentity, res);
	}

	private void loginCompleteDelayedCheckTempAndStateCookies(
			final RemoteIdentity remoteIdentity,
			final Response res)
			throws Exception {
		
		final NewCookie expectedstate = new NewCookie("loginstatevar", "no state",
				"/login/complete", null, "loginstate", 0, false);
		final NewCookie statecookie = res.getCookies().get("loginstatevar");
		assertThat("incorrect state cookie", statecookie, is(expectedstate));
		
		final NewCookie tempCookie = res.getCookies().get("in-process-login-token");
		final NewCookie expectedtemp = new NewCookie("in-process-login-token",
				tempCookie.getValue(),
				"/login", null, "logintoken", tempCookie.getMaxAge(), false);
		assertThat("incorrect temp cookie less value and max age", tempCookie, is(expectedtemp));
		TestCommon.assertCloseTo(tempCookie.getMaxAge(), 30 * 60, 10);
		
		final TemporaryIdentities tis = manager.storage.getTemporaryIdentities(
				new IncomingToken(tempCookie.getValue()).getHashedToken());
		
		assertThat("incorrect stored ids", tis.getIdentities().get(), is(set(remoteIdentity)));
	}

	private WebTarget loginCompleteSetUpWebTarget(final String authcode, final String state) {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/complete/prov1")
				.queryParam("code", authcode)
				.queryParam("state", state)
				.build();
		
		return CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
	}
	
	private WebTarget loginCompleteSetUpWebTargetEmptyError(
			final String authcode, final String state) {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/complete/prov1")
				.queryParam("code", authcode)
				.queryParam("state", state)
				.queryParam("error", "   \t   ")
				.build();
		
		return CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
	}

	private RemoteIdentity loginCompleteSetUpProviderMock(final String authcode)
			throws IdentityRetrievalException {
		
		final IdentityProvider provmock = MockIdentityProviderFactory.mocks.get("prov1");
		final RemoteIdentity remoteIdentity = new RemoteIdentity(
				new RemoteIdentityID("prov1", "prov1id"),
				new RemoteIdentityDetails("user", "full", "email@email.com"));
		when(provmock.getIdentities(authcode, false)).thenReturn(set(remoteIdentity));
		return remoteIdentity;
	}
	
	@Test
	public void loginCompleteProviderError() throws Exception {
		// the various input paths for the redirect cookie and the session cookie are exactly
		// the same as for the delayed login so not testing them again here
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/complete/prov1")
				.queryParam("error", "errorwhee")
				.build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		final Response res = wt.request()
				.cookie("loginstatevar", "somestate")
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/login/choice")));
		
		final NewCookie expectedredirect = new NewCookie("loginredirect", "no redirect",
				"/login", null, "redirect url", 0, false);
		final NewCookie redirect = res.getCookies().get("loginredirect");
		assertThat("incorrect redirect cookie", redirect, is(expectedredirect));
		
		final NewCookie expectedsession = new NewCookie("issessiontoken", "no session",
				"/login", null, "session choice", 0, false);
		final NewCookie session = res.getCookies().get("issessiontoken");
		assertThat("incorrect session cookie", session, is(expectedsession));
		
		final NewCookie expectedstate = new NewCookie("loginstatevar", "no state",
				"/login/complete", null, "loginstate", 0, false);
		final NewCookie statecookie = res.getCookies().get("loginstatevar");
		assertThat("incorrect state cookie", statecookie, is(expectedstate));
		
		final NewCookie tempCookie = res.getCookies().get("in-process-login-token");
		final NewCookie expectedtemp = new NewCookie("in-process-login-token",
				tempCookie.getValue(),
				"/login", null, "logintoken", tempCookie.getMaxAge(), false);
		assertThat("incorrect temp cookie less value and max age", tempCookie, is(expectedtemp));
		TestCommon.assertCloseTo(tempCookie.getMaxAge(), 30 * 60, 10);
		
		final TemporaryIdentities tis = manager.storage.getTemporaryIdentities(
				new IncomingToken(tempCookie.getValue()).getHashedToken());
		
		assertThat("incorrect error", tis.getError(), is(Optional.of("errorwhee")));
	}
	
	@Test
	public void loginCompleteFailNoStateCookie() throws Exception {
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("issessiontoken", "false");
		
		final MissingParameterException e = new MissingParameterException(
				"Couldn't retrieve state value from cookie");

		failRequestJSON(request.get(), 400, "Bad Request", e);

		request.cookie("loginstatevar", "   \t   ");
		
		failRequestJSON(request.get(), 400, "Bad Request", e);
	}
	
	@Test
	public void loginCompleteFailStateMismatch() throws Exception {
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("issessiontoken", "false")
				.cookie("loginstatevar", "this doesn't match");
		
		failRequestJSON(request.get(), 401, "Unauthorized",
				new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"State values do not match, this may be a CXRF attack"));
	}
	
	@Test
	public void loginCompleteFailNoProviderState() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/complete/prov1")
				.queryParam("code", "foocode")
				.build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("issessiontoken", "false")
				.cookie("loginstatevar", "somestate");
		
		failRequestJSON(request.get(), 401, "Unauthorized",
				new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"State values do not match, this may be a CXRF attack"));
	}
	
	@Test
	public void loginCompleteFailNoAuthcode() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/complete/prov1")
				.queryParam("state", "somestate")
				.build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("issessiontoken", "false")
				.cookie("loginstatevar", "somestate");
		
		failRequestJSON(request.get(), 400, "Bad Request",
				new MissingParameterException("authorization code"));
	}
	
	@Test
	public void loginCompleteFailNoSuchProvider() throws Exception {
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableProvider(host, COOKIE_NAME, admintoken, "prov2");
		
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("loginstatevar", "foobarstate");
		
		failRequestJSON(request.get(), 401, "Unauthorized",
				new NoSuchIdentityProviderException("prov1"));
	}
	
	@Test
	public void loginCompleteFailBadRedirect() throws Exception {
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("loginstatevar", "foobarstate")
				.cookie("loginredirect", "not a url no sir");
		
		failRequestJSON(request.get(), 400, "Bad Request",
				new IllegalParameterException("Illegal redirect URL: not a url no sir"));
		
		// toURI chokes on ^s
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy?a=^h");
		
		failRequestJSON(request.get(), 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: https://foobar.com/stuff/thingy?a=^h"));
		
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy");
		
		failRequestJSON(request.get(), 400, "Bad Request", new IllegalParameterException(
				"Post-login redirects are not enabled"));
		
		final IncomingToken adminToken = ServiceTestUtils.getAdminToken(manager);
		enableRedirect(host, adminToken, "https://foobar.com/stuff2/");
		failRequestJSON(request.get(), 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: https://foobar.com/stuff/thingy"));
	}

	@Test
	public void loginChoice3Create2Login() throws Exception {
		// this tests a bunch of orthogonal test cases. Doesn't make much sense to split it up
		// since there has to be *some* output for the test, might as well include independent
		// cases.
		// tests a choice with 3 options to create an account, 2 options to login with an account,
		// one of which has two linked IDs.
		// tests create accounts having missing email and fullnames and illegal
		// email and fullnames.
		// tests one of the suggested usernames containing a @ and existing in the system.
		// tests one of the users being disabled.
		// tests policy ids.
		// tests with no redirect cookie.
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		final Set<RemoteIdentity> idents = new HashSet<>();
		for (int i = 1; i < 5; i++) {
			idents.add(new RemoteIdentity(new RemoteIdentityID("prov", "id" + i),
					new RemoteIdentityDetails("user" + i, "full" + i, "e" + i + "@g.com")));
		}
		idents.add(new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user&at@bleah.com", null, null)));
		idents.add(new RemoteIdentity(new RemoteIdentityID("prov", "id6"),
				new RemoteIdentityDetails("whee", "foo\nbar", "not an email")));
		
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), idents);
		
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("userat"),
				new DisplayName("f"), Instant.ofEpochMilli(30000)).build(),
				new PasswordHashAndSalt("foobarbazbat".getBytes(), "aaa".getBytes()));
		
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("ruser1"), new DisplayName("disp1"), Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1a", "full1a", "e1a@g.com")))
				.withPolicyID(new PolicyID("foo"), Instant.ofEpochMilli(60000))
				.withPolicyID(new PolicyID("bar"), Instant.ofEpochMilli(70000))
				.build());
		manager.storage.link(new UserName("ruser1"),
				new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2a", "full2a", "e2a@g.com")));
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("ruser2"), new DisplayName("disp2"), Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
						new RemoteIdentityDetails("user3a", "full3a", "e3a@g.com"))).build());
		when(manager.mockClock.instant()).thenReturn(Instant.ofEpochMilli(40000));
		manager.storage.disableAccount(new UserName("ruser2"), new UserName("adminwhee"),
				"Said nasty, but true, things about Steve");
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		enableLogin(host, admintoken);
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final String res = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.get()
				.readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.header("accept", MediaType.APPLICATION_JSON)
				.get()
				.readEntity(Map.class);
		
		final Map<String, Object> expectedJson = new HashMap<>();
		expectedJson.put("pickurl", "pick");
		expectedJson.put("createurl", "create");
		expectedJson.put("cancelurl", "cancel");
		expectedJson.put("suggestnameurl", "suggestname");
		expectedJson.put("redirecturl", null);
		expectedJson.put("expires", 11493000000000L);
		expectedJson.put("creationallowed", true);
		expectedJson.put("provider", "prov");
		expectedJson.put("create", Arrays.asList(
				ImmutableMap.of("provusername", "user4",
						"availablename", "user4",
						"provfullname", "full4",
						"id", "4a3cd1ac3f1ffd5d2fecabcfc1856485",
						"provemail", "e4@g.com"),
				MapBuilder.newHashMap()
						.with("provusername", "user&at@bleah.com")
						.with("availablename", "userat2")
						.with("provfullname", null)
						.with("id", "78f2c2dbc07bfc9838c45f601a92762d")
						.with("provemail", null)
						.build(),
				MapBuilder.newHashMap()
						.with("provusername", "whee")
						.with("availablename", "whee")
						.with("provfullname", null)
						.with("id", "ccf1ab20b4b412c515182c16f6176b3f")
						.with("provemail", null)
						.build()
				));
		expectedJson.put("login", Arrays.asList(
				ImmutableMap.builder()
						.put("adminonly", false)
						.put("loginallowed", true)
						.put("disabled", false)
						.put("policyids", Arrays.asList(
								ImmutableMap.of("id", "bar", "agreedon", 70000),
								ImmutableMap.of("id", "foo", "agreedon", 60000)
						))
						.put("id", "5fbea2e6ce3d02f7cdbde0bc31be8059")
						.put("user", "ruser1")
						.put("provusernames", Arrays.asList("user2", "user1"))
						.build(),
				ImmutableMap.builder()
						.put("adminonly", false)
						.put("loginallowed", false)
						.put("disabled", true)
						.put("policyids", Collections.emptyList())
						.put("id", "de0702aa7927b562e0d6be5b6527cfb2")
						.put("user", "ruser2")
						.put("provusernames", Arrays.asList("user3"))
						.build()
				));
		
		ServiceTestUtils.assertObjectsEqual(json, expectedJson);
	}

	@Test
	public void loginChoice2LoginWithRedirectAndLoginDisabled() throws Exception {
		// tests with redirect cookie
		// tests with login disabled and admin user
		// tests with trailing slash on target

		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		enableRedirect(host, admintoken, "https://foo.com/whee");
		
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		final Set<RemoteIdentity> idents = new HashSet<>();
		for (int i = 1; i < 3; i++) {
			idents.add(new RemoteIdentity(new RemoteIdentityID("prov", "id" + i),
					new RemoteIdentityDetails("user" + i, "full" + i, "e" + i + "@g.com")));
		}
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), idents);
		
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("ruser1"), new DisplayName("disp1"), Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1a", "full1a", "e1a@g.com")))
				.build());
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("ruser2"), new DisplayName("disp2"), Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2a", "full2a", "e2a@g.com")))
				.build());
		manager.storage.updateRoles(new UserName("ruser2"), set(Role.ADMIN), set());
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice/")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final String res = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.cookie("loginredirect", "https://foo.com/whee/bleah")
				.get()
				.readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.cookie("loginredirect", "https://foo.com/whee/bleah")
				.header("accept", MediaType.APPLICATION_JSON)
				.get()
				.readEntity(Map.class);
		
		final Map<String, Object> expectedJson = new HashMap<>();
		expectedJson.put("pickurl", "../pick");
		expectedJson.put("createurl", "../create");
		expectedJson.put("cancelurl", "../cancel");
		expectedJson.put("suggestnameurl", "../suggestname");
		expectedJson.put("redirecturl", "https://foo.com/whee/bleah");
		expectedJson.put("expires", 11493000000000L);
		expectedJson.put("creationallowed", false);
		expectedJson.put("provider", "prov");
		expectedJson.put("create", Collections.emptyList());
		expectedJson.put("login", Arrays.asList(
				ImmutableMap.builder()
						.put("adminonly", true)
						.put("loginallowed", false)
						.put("disabled", false)
						.put("policyids", Collections.emptyList())
						.put("id", "ef0518c79af70ed979907969c6d0a0f7")
						.put("user", "ruser1")
						.put("provusernames", Arrays.asList("user1"))
						.build(),
				ImmutableMap.builder()
						.put("adminonly", false)
						.put("loginallowed", true)
						.put("disabled", false)
						.put("policyids", Collections.emptyList())
						.put("id", "5fbea2e6ce3d02f7cdbde0bc31be8059")
						.put("user", "ruser2")
						.put("provusernames", Arrays.asList("user2"))
						.build()
				));
		
		ServiceTestUtils.assertObjectsEqual(json, expectedJson);
	}
	
	@Test
	public void loginChoice2CreateAndLoginDisabled() throws Exception {
		// tests with login disabled
		// tests with trailing slash on target
		// tests empty string for redirect

		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		final Set<RemoteIdentity> idents = new HashSet<>();
		for (int i = 1; i < 3; i++) {
			idents.add(new RemoteIdentity(new RemoteIdentityID("prov", "id" + i),
					new RemoteIdentityDetails("user" + i, "full" + i, "e" + i + "@g.com")));
		}
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), idents);
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice/")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final String res = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.cookie("loginredirect", "   \t   ")
				.get()
				.readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.cookie("loginredirect", "   \t   ")
				.header("accept", MediaType.APPLICATION_JSON)
				.get()
				.readEntity(Map.class);
		
		final Map<String, Object> expectedJson = new HashMap<>();
		expectedJson.put("pickurl", "../pick");
		expectedJson.put("createurl", "../create");
		expectedJson.put("cancelurl", "../cancel");
		expectedJson.put("suggestnameurl", "../suggestname");
		expectedJson.put("redirecturl", null);
		expectedJson.put("expires", 11493000000000L);
		expectedJson.put("creationallowed", false);
		expectedJson.put("provider", "prov");
		expectedJson.put("create", Arrays.asList(
				ImmutableMap.of("provusername", "user1",
						"availablename", "user1",
						"provfullname", "full1",
						"id", "ef0518c79af70ed979907969c6d0a0f7",
						"provemail", "e1@g.com"),
				ImmutableMap.of("provusername", "user2",
						"availablename", "user2",
						"provfullname", "full2",
						"id", "5fbea2e6ce3d02f7cdbde0bc31be8059",
						"provemail", "e2@g.com")
				));
		expectedJson.put("login", Collections.emptyList());
		
		ServiceTestUtils.assertObjectsEqual(json, expectedJson);
	}
	
	@Test
	public void loginChoice2CreateWithRedirectURL() throws Exception {
		// tests with redirect cookie
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		enableRedirect(host, admintoken, "https://foo.com/whee");
		enableLogin(host, admintoken);

		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		final Set<RemoteIdentity> idents = new HashSet<>();
		for (int i = 1; i < 3; i++) {
			idents.add(new RemoteIdentity(new RemoteIdentityID("prov", "id" + i),
					new RemoteIdentityDetails("user" + i, "full" + i, "e" + i + "@g.com")));
		}
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), idents);
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final String res = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.cookie("loginredirect", "https://foo.com/whee/baz")
				.get()
				.readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.cookie("loginredirect", "https://foo.com/whee/baz")
				.header("accept", MediaType.APPLICATION_JSON)
				.get()
				.readEntity(Map.class);
		
		final Map<String, Object> expectedJson = new HashMap<>();
		expectedJson.put("pickurl", "pick");
		expectedJson.put("createurl", "create");
		expectedJson.put("cancelurl", "cancel");
		expectedJson.put("suggestnameurl", "suggestname");
		expectedJson.put("redirecturl", "https://foo.com/whee/baz");
		expectedJson.put("expires", 11493000000000L);
		expectedJson.put("creationallowed", true);
		expectedJson.put("provider", "prov");
		expectedJson.put("create", Arrays.asList(
				ImmutableMap.of("provusername", "user1",
						"availablename", "user1",
						"provfullname", "full1",
						"id", "ef0518c79af70ed979907969c6d0a0f7",
						"provemail", "e1@g.com"),
				ImmutableMap.of("provusername", "user2",
						"availablename", "user2",
						"provfullname", "full2",
						"id", "5fbea2e6ce3d02f7cdbde0bc31be8059",
						"provemail", "e2@g.com")
				));
		expectedJson.put("login", Collections.emptyList());
		
		ServiceTestUtils.assertObjectsEqual(json, expectedJson);
	}
	
	@Test
	public void loginChoiceFailNoToken() throws Exception {
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		failRequestHTML(wt.request().get(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));

		final Builder res = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(res.get(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));
	}
	
	@Test
	public void loginChoiceFailEmptyToken() throws Exception {
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final Builder res = CLI.target(target).request()
				.cookie("in-process-login-token", "   \t   ");
		
		failRequestHTML(res.get(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));

		res.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(res.get(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));
	}
	
	@Test
	public void loginChoiceFailBadToken() throws Exception {
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder res = wt.request()
				.cookie("in-process-login-token", "foobarbaz");
		
		final Builder jsonrequest = wt.request()
				.cookie("in-process-login-token", "foobarbaz")
				.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestHTML(res.get(), 401, "Unauthorized",
				new InvalidTokenException("Temporary token"));
		
		failRequestJSON(jsonrequest.get(), 401, "Unauthorized",
				new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void loginChoiceFailBadRedirect() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobarbaz")
				.cookie("loginredirect", "not a url no sir");
		
		final Builder jsonrequest = wt.request()
				.cookie("in-process-login-token", "foobarbaz")
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("loginredirect", "not a url no sir");
		
		failRequestHTML(request.get(), 400, "Bad Request",
				new IllegalParameterException("Illegal redirect URL: not a url no sir"));
		failRequestJSON(jsonrequest.get(), 400, "Bad Request",
				new IllegalParameterException("Illegal redirect URL: not a url no sir"));
		
		// toURI chokes on ^s
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy?a=^h");
		jsonrequest.cookie("loginredirect", "https://foobar.com/stuff/thingy?a=^h");
		
		failRequestHTML(request.get(), 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: https://foobar.com/stuff/thingy?a=^h"));
		failRequestJSON(jsonrequest.get(), 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: https://foobar.com/stuff/thingy?a=^h"));
		
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy");
		jsonrequest.cookie("loginredirect", "https://foobar.com/stuff/thingy");
		
		failRequestHTML(request.get(), 400, "Bad Request",
				new IllegalParameterException("Post-login redirects are not enabled"));
		failRequestJSON(jsonrequest.get(), 400, "Bad Request",
				new IllegalParameterException("Post-login redirects are not enabled"));
		
		final IncomingToken adminToken = ServiceTestUtils.getAdminToken(manager);
		enableRedirect(host, adminToken, "https://foobar.com/stuff2/");
		
		failRequestHTML(request.get(), 400, "Bad Request",
				new IllegalParameterException(
						"Illegal redirect URL: https://foobar.com/stuff/thingy"));
		failRequestJSON(jsonrequest.get(), 400, "Bad Request",
				new IllegalParameterException(
						"Illegal redirect URL: https://foobar.com/stuff/thingy"));
	}
	
	@Test
	public void loginCancelPOST() throws Exception {
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), set(
				new RemoteIdentity(new RemoteIdentityID("prov", "id"),
						new RemoteIdentityDetails("user", "full", "e@g.com"))));
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/cancel")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Response res = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.post(null);
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		assertLoginProcessTokensRemoved(res);
		assertNoTempToken(tt);
	}
	
	@Test
	public void loginCancelDELETE() throws Exception {
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), set(
				new RemoteIdentity(new RemoteIdentityID("prov", "id"),
						new RemoteIdentityDetails("user", "full", "e@g.com"))));
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/cancel")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Response res = wt.request()
				.cookie("in-process-login-token", tt.getToken())
				.delete();
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		assertLoginProcessTokensRemoved(res);
		assertNoTempToken(tt);
	}
	
	private void assertNoTempToken(final TemporaryToken tt) throws Exception {
		try {
			manager.storage.getTemporaryIdentities(
					new IncomingToken(tt.getToken()).getHashedToken());
			fail("expected exception getting temp token");
		} catch (NoSuchTokenException e) {
			// pass
		}
	}
	
	@Test
	public void loginCancelFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/cancel")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);

		failRequestJSON(res.post(null), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));
		failRequestJSON(res.delete(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));
	}
	
	@Test
	public void loginPickFormMinimalInput() throws Exception {
		
		final TemporaryToken tt = loginPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/pick").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target);
		
		final Form form = new Form();
		form.param("id", "ef0518c79af70ed979907969c6d0a0f7");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		loginPickOrCreateCheckSessionToken(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("only one identity", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
	}

	@Test
	public void loginPickJSONMinimalInput() throws Exception {
		
		final TemporaryToken tt = loginPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/pick").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target);
		
		final Response res = req.post(Entity.json(
				ImmutableMap.of("id", "ef0518c79af70ed979907969c6d0a0f7")));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		assertLoginProcessTokensRemoved(res);
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect redirect url", response.get("redirecturl"), is((String) null));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> token = (Map<String, Object>) response.get("token");
		checkLoginToken(token, Collections.emptyMap(), new UserName("u1"));
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("only one identity", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
	}
	
	@Test
	public void loginPickFormMaximalInput() throws Exception {
		
		final TemporaryToken tt = loginPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/pick").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target)
				.cookie("loginredirect", "https://foo.com/baz/bat")
				.cookie("issessiontoken", "false");
		
		final Form form = new Form();
		form.param("id", "ef0518c79af70ed979907969c6d0a0f7");
		form.param("linkall", "true");
		form.param("policyids", "foo, bar,  ");
		// tests empty item is ignored
		form.param("customcontext", "   a    , 1   ; b  \t  , 2    ; ;");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://foo.com/baz/bat")));
		
		loginPickOrCreateCheckExtendedToken(res, ImmutableMap.of("a", "1", "b", "2"));
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("expected two identities", u.getIdentities(), is(set(REMOTE1, REMOTE3)));
		assertThat("incorrect policy ids", u.getPolicyIDs().keySet(),
				is(set(new PolicyID("foo"), new PolicyID("bar"))));
		TestCommon.assertCloseToNow(u.getPolicyIDs().get(new PolicyID("foo")));
		TestCommon.assertCloseToNow(u.getPolicyIDs().get(new PolicyID("bar")));
	}
	
	@Test
	public void loginPickJsonMaximalInput() throws Exception {
		
		final TemporaryToken tt = loginPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/pick").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target)
				.cookie("loginredirect", "https://foo.com/baz/bat")
				.cookie("issessiontoken", "false");
		
		final Response res = req.post(Entity.json(
				ImmutableMap.of("id", "ef0518c79af70ed979907969c6d0a0f7",
						"linkall", true,
						"policyids", Arrays.asList("foo", "bar"),
						"customcontext", ImmutableMap.of("a", 1, "b", 2))));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		assertLoginProcessTokensRemoved(res);
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect redirect url", response.get("redirecturl"),
				is("https://foo.com/baz/bat"));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> token = (Map<String, Object>) response.get("token");
		checkLoginToken(token, ImmutableMap.of("a", "1", "b", "2"), new UserName("u1"));
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("expected two identities", u.getIdentities(), is(set(REMOTE1, REMOTE3)));
		assertThat("incorrect policy ids", u.getPolicyIDs().keySet(),
				is(set(new PolicyID("foo"), new PolicyID("bar"))));
		TestCommon.assertCloseToNow(u.getPolicyIDs().get(new PolicyID("foo")));
		TestCommon.assertCloseToNow(u.getPolicyIDs().get(new PolicyID("bar")));
	}
	
	@Test
	public void loginPickFormEmptyStrings() throws Exception {
		
		final TemporaryToken tt = loginPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/pick").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target)
				.cookie("loginredirect", "   \t    ")
				.cookie("issessiontoken", "true");
		
		final Form form = new Form();
		form.param("id", "     ef0518c79af70ed979907969c6d0a0f7     ");
		form.param("policyids", "   \t \n   ");
		form.param("linkall", null);
		form.param("customcontext", "   \t \n   ");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		loginPickOrCreateCheckSessionToken(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("only one identity", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
	}
	
	@Test
	public void loginPickJsonEmptyData() throws Exception {
		
		final TemporaryToken tt = loginPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/pick").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target)
				.cookie("loginredirect", "    \t    ")
				.cookie("issessiontoken", "false");
		
		final Response res = req.post(Entity.json(
				ImmutableMap.of("id", "    ef0518c79af70ed979907969c6d0a0f7    ",
						"linkall", false,
						"policyids", Collections.emptyList(),
						"customcontext", Collections.emptyMap())));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		assertLoginProcessTokensRemoved(res);
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect redirect url", response.get("redirecturl"), is((String) null));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> token = (Map<String, Object>) response.get("token");
		checkLoginToken(token, Collections.emptyMap(), new UserName("u1"));
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("only one identity", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
	}
	
	@Test
	public void loginPickFailBadRedirect() throws Exception {
		loginPickOrCreateFailBadRedirect("/login/pick");
	}

	private void loginPickOrCreateFailBadRedirect(final String path) throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("loginredirect", "not a url no sir");
		final Builder jsonrequest = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("loginredirect", "not a url no sir");
		
		failRequestHTML(request.post(Entity.form(new Form())), 400, "Bad Request",
				new IllegalParameterException("Illegal redirect URL: not a url no sir"));
		failRequestJSON(jsonrequest.post(Entity.json(Collections.emptyMap())), 400, "Bad Request",
				new IllegalParameterException("Illegal redirect URL: not a url no sir"));
		
		// toURI chokes on ^s
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy?a=^h");
		jsonrequest.cookie("loginredirect", "https://foobar.com/stuff/thingy?a=^h");
		
		failRequestHTML(request.post(Entity.form(new Form())), 400, "Bad Request",
				new IllegalParameterException(
						"Illegal redirect URL: https://foobar.com/stuff/thingy?a=^h"));
		failRequestJSON(jsonrequest.post(Entity.json(Collections.emptyMap())), 400, "Bad Request",
				new IllegalParameterException(
						"Illegal redirect URL: https://foobar.com/stuff/thingy?a=^h"));
		
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy");
		jsonrequest.cookie("loginredirect", "https://foobar.com/stuff/thingy");
		
		failRequestHTML(request.post(Entity.form(new Form())), 400, "Bad Request",
				new IllegalParameterException("Post-login redirects are not enabled"));
		failRequestJSON(jsonrequest.post(Entity.json(Collections.emptyMap())), 400, "Bad Request",
				new IllegalParameterException("Post-login redirects are not enabled"));
		
		final IncomingToken adminToken = ServiceTestUtils.getAdminToken(manager);
		enableRedirect(host, adminToken, "https://foobar.com/stuff2/");
		
		failRequestHTML(request.post(Entity.form(new Form())), 400, "Bad Request",
				new IllegalParameterException(
						"Illegal redirect URL: https://foobar.com/stuff/thingy"));
		failRequestJSON(jsonrequest.post(Entity.json(Collections.emptyMap())), 400, "Bad Request",
				new IllegalParameterException(
						"Illegal redirect URL: https://foobar.com/stuff/thingy"));
	}
	
	@Test
	public void loginPickFailBadCustomContextString() throws Exception {
		loginPickOrCreateFailBadCustomContextString("/login/pick");
	}

	private void loginPickOrCreateFailBadCustomContextString(final String path) throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request();
		
		final Form form = new Form();
		form.param("customcontext", " foo, bar, baz ; a, b");
		
		failRequestHTML(request.post(Entity.form(form)), 400, "Bad Request",
				new IllegalParameterException(
						"Bad key/value pair in custom context: foo, bar, baz"));
	}
	
	@Test
	public void loginPickFailNoToken() throws Exception {
		loginPickOrCreateFailNoToken("/login/pick");
	}

	private void loginPickOrCreateFailNoToken(final String path) throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request();
		
		failRequestHTML(request.post(Entity.form(new Form())), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));
		
		request.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(request.post(Entity.json(Collections.emptyMap())), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));
	}
	
	@Test
	public void loginPickFailNoID() throws Exception {
		loginPickOrCreateFailNoID("/login/pick");
	}

	private void loginPickOrCreateFailNoID(final String path) throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobar");
		
		failRequestHTML(request.post(Entity.form(new Form())), 400, "Bad Request",
				new MissingParameterException("id"));
		
		request.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(request.post(Entity.json(Collections.emptyMap())), 400, "Bad Request",
				new MissingParameterException("id"));
	}
	
	@Test
	public void loginPickFailEmptyID() throws Exception {
		loginPickOrCreateFailEmptyID("/login/pick");
	}

	private void loginPickOrCreateFailEmptyID(final String path) throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobar");
		
		final Form form = new Form();
		form.param("id", "    \t    ");
		
		failRequestHTML(request.post(Entity.form(form)), 400, "Bad Request",
				new MissingParameterException("id"));
		
		request.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of("id", "   \t  "))),
				400, "Bad Request", new MissingParameterException("id"));
	}
	
	@Test
	public void loginPickFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobar");
		
		final Form form = new Form();
		form.param("id", "an id");
		
		failRequestHTML(request.post(Entity.form(form)), 401, "Unauthorized",
				new InvalidTokenException("Temporary token"));
		
		request.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of("id", "an id"))),
				401, "Unauthorized", new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void loginPickFailNoJSON() throws Exception {
		loginPickOrCreateFailNoJSON("/login/pick");
	}

	private void loginPickOrCreateFailNoJSON(final String path) throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-login-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(null)),
				400, "Bad Request", new MissingParameterException("JSON body missing"));
	}
	
	@Test
	public void loginPickFailJSONWithAdditionalProperties() throws Exception {
		loginPickOrCreateFailJSONWithAdditionalProperties("/login/pick");
	}

	private void loginPickOrCreateFailJSONWithAdditionalProperties(final String path)
			throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-login-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of("foo", "bar"))),
				400, "Bad Request", new IllegalParameterException(
						"Unexpected parameters in request: foo"));
	}
	
	@Test
	public void loginPickFailBadBoolean() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-login-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"linkall", Collections.emptyList()))),
				400, "Bad Request", new IllegalParameterException(
						"linkall must be a boolean"));
	}
	
	@Test
	public void loginPickFailNullPolicyID() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-login-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"policyids", Arrays.asList("foo", null)))),
				400, "Bad Request", new MissingParameterException("policy id"));
	}
	
	@Test
	public void loginPickFailEmptyPolicyID() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-login-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"policyids", Arrays.asList("foo", "   \t   ")))),
				400, "Bad Request", new MissingParameterException("policy id"));
	}

	private void loginPickOrCreateCheckExtendedToken(
			final Response res,
			final Map<String, String> customContext)
			throws Exception {
		assertLoginProcessTokensRemoved(res);
		
		final NewCookie token = res.getCookies().get(COOKIE_NAME);
		final NewCookie expectedtoken = new NewCookie(COOKIE_NAME, token.getValue(),
				"/", null, "authtoken", token.getMaxAge(), false);
		assertThat("incorrect auth cookie less token", token, is(expectedtoken));
		TestCommon.assertCloseTo(token.getMaxAge(), 14 * 24 * 3600, 10);
		
		checkLoginToken(token.getValue(), customContext, new UserName("u1"));
	}

	private void loginPickOrCreateCheckSessionToken(final Response res)
			throws Exception, MissingParameterException, IllegalParameterException {
		assertLoginProcessTokensRemoved(res);
		
		final NewCookie token = res.getCookies().get(COOKIE_NAME);
		final NewCookie expectedtoken = new NewCookie(COOKIE_NAME, token.getValue(),
				"/", null, "authtoken", -1, false);
		assertThat("incorrect auth cookie less token", token, is(expectedtoken));
		
		checkLoginToken(token.getValue(), Collections.emptyMap(), new UserName("u1"));
	}

	private Builder loginPickOrCreateRequestBuilder(final TemporaryToken tt, final URI target) {
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		final Builder req = wt.request()
				.cookie("in-process-login-token", tt.getToken());
		return req;
	}

	private TemporaryToken loginPickSetup() throws Exception {
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableRedirect(host, admintoken, "https://foo.com/baz");
		
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(),
				set(REMOTE1, REMOTE2, REMOTE3));
		
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("u1"), new DisplayName("d"), Instant.now(), REMOTE1).build());
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("u2"), new DisplayName("d"), Instant.now(), REMOTE2).build());

		return tt;
	}
	
	@Test
	public void loginCreateFormMinimalInput() throws Exception {
		
		final TemporaryToken tt = loginChoiceSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/create").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target);
		
		final Form form = new Form();
		form.param("id", "ef0518c79af70ed979907969c6d0a0f7");
		form.param("user", "u1");
		form.param("display", "disp1");
		form.param("email", "e1@g.com");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		loginPickOrCreateCheckSessionToken(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("only one identity", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("disp1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e1@g.com")));
	}
	
	@Test
	public void loginCreateJSONMinimalInput() throws Exception {
		
		final TemporaryToken tt = loginChoiceSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/create").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target);
		
		final Map<String, String> json = ImmutableMap.of(
				"id", "ef0518c79af70ed979907969c6d0a0f7",
				"user", "u1",
				"display", "disp1",
				"email", "e1@g.com");
		
		final Response res = req.post(Entity.json(json));
		
		assertThat("incorrect response code", res.getStatus(), is(201));
		
		assertLoginProcessTokensRemoved(res);
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect redirect url", response.get("redirecturl"), is((String) null));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> token = (Map<String, Object>) response.get("token");
		checkLoginToken(token, Collections.emptyMap(), new UserName("u1"));
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("only one identity", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("disp1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e1@g.com")));
	}
	
	@Test
	public void loginCreateFormMaximalInput() throws Exception {
		
		final TemporaryToken tt = loginChoiceSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/create").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target)
				.cookie("loginredirect", "https://foo.com/baz/bat")
				.cookie("issessiontoken", "false");
		
		final Form form = new Form();
		form.param("id", "ef0518c79af70ed979907969c6d0a0f7");
		form.param("user", "u1");
		form.param("display", "disp1");
		form.param("email", "e1@g.com");
		form.param("linkall", "true");
		form.param("policyids", "foo, bar,  ");
		// tests empty item is ignored
		form.param("customcontext", "   a    , 1   ; b  \t  , 2    ; ;");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://foo.com/baz/bat")));
		
		loginPickOrCreateCheckExtendedToken(res, ImmutableMap.of("a", "1", "b", "2"));
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("expected two identities", u.getIdentities(), is(set(REMOTE1, REMOTE2)));
		assertThat("incorrect policy ids", u.getPolicyIDs().keySet(),
				is(set(new PolicyID("foo"), new PolicyID("bar"))));
		TestCommon.assertCloseToNow(u.getPolicyIDs().get(new PolicyID("foo")));
		TestCommon.assertCloseToNow(u.getPolicyIDs().get(new PolicyID("bar")));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("disp1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e1@g.com")));
	}
	
	
	@Test
	public void loginCreateJSONMaximalInput() throws Exception {
		
		final TemporaryToken tt = loginChoiceSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/create").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target)
				.cookie("loginredirect", "https://foo.com/baz/bat")
				.cookie("issessiontoken", "false");
		
		final Map<String, Object> json = MapBuilder.<String, Object>newHashMap()
				.with("id", "ef0518c79af70ed979907969c6d0a0f7")
				.with("user", "u1")
				.with("display", "disp1")
				.with("email", "e1@g.com")
				.with("linkall", true)
				.with("policyids", Arrays.asList("foo", "bar"))
				//tests empty item is ignored
				.with("customcontext", ImmutableMap.of("a", 1, "b", 2))
				.build();
		
		final Response res = req.post(Entity.json(json));
		
		assertThat("incorrect response code", res.getStatus(), is(201));
		
		assertLoginProcessTokensRemoved(res);
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect redirect url", response.get("redirecturl"),
				is("https://foo.com/baz/bat"));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> token = (Map<String, Object>) response.get("token");
		checkLoginToken(token, ImmutableMap.of("a", "1", "b", "2"), new UserName("u1"));
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("expected two identities", u.getIdentities(), is(set(REMOTE1, REMOTE2)));
		assertThat("incorrect policy ids", u.getPolicyIDs().keySet(),
				is(set(new PolicyID("foo"), new PolicyID("bar"))));
		TestCommon.assertCloseToNow(u.getPolicyIDs().get(new PolicyID("foo")));
		TestCommon.assertCloseToNow(u.getPolicyIDs().get(new PolicyID("bar")));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("disp1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e1@g.com")));
	}
	
	@Test
	public void loginCreateFormEmptyStrings() throws Exception {
		
		final TemporaryToken tt = loginChoiceSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/create").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target)
				.cookie("loginredirect", "   \t    ")
				.cookie("issessiontoken", "true");
		
		final Form form = new Form();
		form.param("id", "              ef0518c79af70ed979907969c6d0a0f7          ");
		form.param("user", "u1");
		form.param("display", "    disp1    ");
		form.param("email", "    e1@g.com    ");
		form.param("linkall", null);
		form.param("policyids", "   \t \n   ");
		form.param("customcontext", "   \t \n   ");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		loginPickOrCreateCheckSessionToken(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("only one identity", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("disp1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e1@g.com")));
	}
	
	@Test
	public void loginCreateJSONEmptyInput() throws Exception {
		
		final TemporaryToken tt = loginChoiceSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/login/create").build();
		
		final Builder req = loginPickOrCreateRequestBuilder(tt, target)
				.cookie("loginredirect", "   \t    ")
				.cookie("issessiontoken", "true");
		
		final Map<String, Object> json = MapBuilder.<String, Object>newHashMap()
				.with("id", "      ef0518c79af70ed979907969c6d0a0f7       ")
				.with("user", "u1")
				.with("display", "      disp1     ")
				.with("email", "     e1@g.com     ")
				.with("linkall", false)
				.with("policyids", Collections.emptyList())
				//tests empty item is ignored
				.with("customcontext", Collections.emptyMap())
				.build();
		
		final Response res = req.post(Entity.json(json));
		
		assertThat("incorrect response code", res.getStatus(), is(201));
		
		assertLoginProcessTokensRemoved(res);
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect redirect url", response.get("redirecturl"),
				is((String)null));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> token = (Map<String, Object>) response.get("token");
		checkLoginToken(token, Collections.emptyMap(), new UserName("u1"));
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		TestCommon.assertCloseToNow(u.getLastLogin().get());
		assertThat("only one identity", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("disp1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e1@g.com")));
	}
	
	@Test
	public void loginCreateFailBadRedirect() throws Exception {
		loginPickOrCreateFailBadRedirect("/login/create");
	}
	
	@Test
	public void loginCreateFailBadCustomContextString() throws Exception {
		loginPickOrCreateFailBadCustomContextString("/login/create");
	}
	
	@Test
	public void loginCreateFailNoToken() throws Exception {
		loginPickOrCreateFailNoToken("/login/create");
	}
	
	@Test
	public void loginCreateFailNoID() throws Exception {
		loginPickOrCreateFailNoID("/login/create");
	}
	
	@Test
	public void loginCreateFailEmptyID() throws Exception {
		loginPickOrCreateFailEmptyID("/login/create");
	}
	
	@Test
	public void loginCreateFailBadToken() throws Exception {
		
		loginChoiceSetup();
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/create")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobar");
		
		final Form form = new Form();
		form.param("id", "ef0518c79af70ed979907969c6d0a0f7");
		form.param("user", "u1");
		form.param("display", "disp1");
		form.param("email", "e1@g.com");
		
		failRequestHTML(request.post(Entity.form(form)), 401, "Unauthorized",
				new InvalidTokenException("Temporary token"));
		
		request.header("accept", MediaType.APPLICATION_JSON);
		
		final Map<String, String> json = ImmutableMap.of(
				"id", "ef0518c79af70ed979907969c6d0a0f7",
				"user", "u1",
				"display", "disp1",
				"email", "e1@g.com");
		
		failRequestJSON(request.post(Entity.json(json)),
				401, "Unauthorized", new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void loginCreateFailNoJSON() throws Exception {
		loginPickOrCreateFailNoJSON("/login/create");
	}
	
	@Test
	public void loginCreateFailJSONWithAdditionalProperties() throws Exception {
		loginPickOrCreateFailJSONWithAdditionalProperties("/login/create");
	}
	
	@Test
	public void loginCreateFailBadBoolean() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/create")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-login-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"user", "u1",
				"display", "disp1",
				"email", "e1@g.com",
				"linkall", Collections.emptyList()))),
				400, "Bad Request", new IllegalParameterException(
						"linkall must be a boolean"));
	}
	
	@Test
	public void loginCreateFailNullPolicyID() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/create")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-login-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"user", "u1",
				"display", "disp1",
				"email", "e1@g.com",
				"policyids", Arrays.asList("foo", null)))),
				400, "Bad Request", new MissingParameterException("policy id"));
	}
	
	@Test
	public void loginCreateFailEmptyPolicyID() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/create")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-login-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"user", "u1",
				"display", "disp1",
				"email", "e1@g.com",
				"policyids", Arrays.asList("foo", "   \t  ")))),
				400, "Bad Request", new MissingParameterException("policy id"));
	}
	
	@Test
	public void loginCreateFailBadUserID() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/create")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobar");
		
		final Form form = new Form();
		form.param("id", "ef0518c79af70ed979907969c6d0a0f7");
		form.param("user", "Au1");
		form.param("display", "disp1");
		form.param("email", "e1@g.com");
		
		failRequestHTML(request.post(Entity.form(form)), 400, "Bad Request",
				new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
						"Illegal character in user name Au1: A"));
		
		request.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"user", "Au1",
				"display", "disp1",
				"email", "e1@g.com"))),
				400, "Bad Request", new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
						"Illegal character in user name Au1: A"));
	}
	
	@Test
	public void loginCreateFailBadDisplayName() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/create")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobar");
		
		final Form form = new Form();
		form.param("id", "ef0518c79af70ed979907969c6d0a0f7");
		form.param("user", "u1");
		form.param("display", "di\tsp1");
		form.param("email", "e1@g.com");
		
		failRequestHTML(request.post(Entity.form(form)), 400, "Bad Request",
				new IllegalParameterException(
						"display name contains control characters"));
		
		request.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"user", "u1",
				"display", "dis\tp1",
				"email", "e1@g.com"))),
				400, "Bad Request", new IllegalParameterException(
						"display name contains control characters"));
	}
	
	@Test
	public void loginCreateFailBadEmail() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/create")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobar");
		
		final Form form = new Form();
		form.param("id", "ef0518c79af70ed979907969c6d0a0f7");
		form.param("user", "u1");
		form.param("display", "disp1");
		form.param("email", "e1@g.@com");
		
		failRequestHTML(request.post(Entity.form(form)), 400, "Bad Request",
				new IllegalParameterException(ErrorType.ILLEGAL_EMAIL_ADDRESS,
						"e1@g.@com"));
		
		request.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of(
				"id", "whee",
				"user", "u1",
				"display", "disp1",
				"email", "e1@g.@com"))),
				400, "Bad Request", new IllegalParameterException(ErrorType.ILLEGAL_EMAIL_ADDRESS,
						"e1@g.@com"));
	}

	private TemporaryToken loginChoiceSetup() throws Exception {
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		enableLogin(host, admintoken);
		enableRedirect(host, admintoken, "https://foo.com/baz");
		
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(),
				set(REMOTE1, REMOTE2));
		
		return tt;
	}
}
