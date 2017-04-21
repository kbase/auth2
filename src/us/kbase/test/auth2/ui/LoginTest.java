package us.kbase.test.auth2.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
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
import org.ini4j.Ini;
import org.ini4j.Profile.Section;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.TemporaryIdentities;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.common.test.RegexMatcher;
import us.kbase.test.auth2.MockIdentityProviderFactory;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;

public class LoginTest {
	
	private static final String DB_NAME = "test_login_ui";
	private static final String COOKIE_NAME = "login-cookie";
	
	private static final Client CLI = ClientBuilder.newClient();
	
	private static MongoStorageTestManager manager = null;
	private static StandaloneAuthServer server = null;
	private static int port = -1;
	private static String host = null;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		TestCommon.stfuLoggers();
		manager = new MongoStorageTestManager(DB_NAME);
		final Path cfgfile = generateTempConfigFile();
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
		manager.reset(); // destroy any admins that already exist
		//force a config reset
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		final Response r = CLI.target(host + "/admin/config/reset").request()
				.cookie(COOKIE_NAME, admintoken.getToken())
				.post(Entity.entity(null, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("unable to reset server config", r.getStatus(), is(204));
		// destroy the users and config again
		manager.reset();
		insertStandardConfig();
		
		// This is very bad form but it takes too long to start the server up for every test
		// The alternative is to use concrete IdentityProvider implementations with 
		// a mock server they talk to, but that seems like an even bigger pita
		for (final IdentityProvider mock: MockIdentityProviderFactory.mocks.values()) {
			final String name = mock.getProviderName();
			reset(mock);
			when(mock.getProviderName()).thenReturn(name);
		}
	}
	
	// inserts the config that would result on server startup per the config file below
	private static void insertStandardConfig() throws Exception {
		final IdentityProvider prov1 = mock(IdentityProvider.class);
		final IdentityProvider prov2 = mock(IdentityProvider.class);
		when(prov1.getProviderName()).thenReturn("prov1");
		when(prov2.getProviderName()).thenReturn("prov2");
		new Authentication(manager.storage, set(prov1, prov2), AuthExternalConfig.SET_DEFAULT);
	}
	
	private static Path generateTempConfigFile() throws IOException {
		final Ini ini = new Ini();
		final Section sec = ini.add("authserv2");
		sec.add("mongo-host", "localhost:" + manager.mongo.getServerPort());
		sec.add("mongo-db", DB_NAME);
		sec.add("token-cookie-name", COOKIE_NAME);
		// don't bother with logger name
		
		sec.add("identity-providers", "prov1, prov2");
		
		sec.add("identity-provider-prov1-factory", MockIdentityProviderFactory.class.getName());
		sec.add("identity-provider-prov1-login-url", "https://login.prov1.com");
		sec.add("identity-provider-prov1-api-url", "https://api.prov1.com");
		sec.add("identity-provider-prov1-client-id", "prov1clientid");
		sec.add("identity-provider-prov1-client-secret", "prov1secret");
		sec.add("identity-provider-prov1-login-redirect-url",
				"https://loginredirectforprov1.kbase.us");
		sec.add("identity-provider-prov1-link-redirect-url",
				"https://linkredirectforprov1.kbase.us");

		sec.add("identity-provider-prov2-factory", MockIdentityProviderFactory.class.getName());
		sec.add("identity-provider-prov2-login-url", "https://login.prov2.com");
		sec.add("identity-provider-prov2-api-url", "https://api.prov2.com");
		sec.add("identity-provider-prov2-client-id", "prov2clientid");
		sec.add("identity-provider-prov2-client-secret", "prov2secret");
		sec.add("identity-provider-prov2-login-redirect-url",
				"https://loginredirectforprov2.kbase.us");
		sec.add("identity-provider-prov2-link-redirect-url",
				"https://linkredirectforprov2.kbase.us");

		final Path temp = TestCommon.getTempDir();
		final Path deploy = temp.resolve(Files.createTempFile(temp, "cli_test_deploy", ".cfg"));
		ini.store(deploy.toFile());
		deploy.toFile().deleteOnExit();
		System.out.println("Generated temporary config file " + deploy);
		return deploy.toAbsolutePath();
	}

	private void enableLogin(final IncomingToken admintoken) {
		setAdmin(admintoken, ImmutableMap.of("allowlogin", true));
	}

	private void setAdmin(final IncomingToken admintoken, final Map<String, Object> json) {
		final Response r = CLI.target(host + "/admin/config").request()
				.header("authorization", admintoken.getToken())
				.put(Entity.json(json));
		assertThat("failed to set config", r.getStatus(), is(204));
	}

	private void enableProvider(final IncomingToken admintoken, final String prov) {
		final Form providerform = new Form();
		providerform.param("provider", prov);
		providerform.param("enabled", "true");
		final Response rprov = CLI.target(host + "/admin/config/provider").request()
				.cookie(COOKIE_NAME, admintoken.getToken())
				.post(Entity.entity(providerform,
						MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("failed to set provider config", rprov.getStatus(), is(204));
	}
	
	private void enableRedirect(final IncomingToken adminToken, final String redirectURLPrefix) {
		setAdmin(adminToken, ImmutableMap.of("allowedloginredirect", redirectURLPrefix));
	}
	
	private void setLoginCompleteRedirect(
			final IncomingToken adminToken,
			final String loginCompleteRedirectURL) {
		setAdmin(adminToken, ImmutableMap.of("completeloginredirect", loginCompleteRedirectURL));
		
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
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(admintoken, "prov1");
		
		final WebTarget wt = CLI.target(host + "/login/");
		final String res = wt.request().get().readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void startDisplayWithTwoProviders() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(admintoken, "prov1");
		enableProvider(admintoken, "prov2");
		
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
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		
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
		
		final Form form2 = new Form();
		form2.param("provider", "fake");
		form2.param("redirecturl", "https://foobar.com/stuff/thingy");
		failLoginStart(form2, 400, "Bad Request", new IllegalParameterException(
				"Post-login redirects are not enabled"));
		
		final IncomingToken adminToken = UITestUtils.getAdminToken(manager);
		enableRedirect(adminToken, "https://foobar.com/stuff2/");
		failLoginStart(form2, 400, "Bad Request", new IllegalParameterException(
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

		assertThat("incorrect status code", res.getStatus(), is(expectedHTTPCode));

		@SuppressWarnings("unchecked")
		final Map<String, Object> error = res.readEntity(Map.class);
		
		UITestUtils.assertErrorCorrect(expectedHTTPCode, expectedHTTPError, e, error);
	}
	
	@Test
	public void loginCompleteImmediateLoginMinimalInput() throws Exception {
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		
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
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		
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
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		
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
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		
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
		final StoredToken st = manager.storage.getToken(
				new IncomingToken(token.getValue()).getHashedToken());
		
		final TokenCreationContext expectedContext = TokenCreationContext.getBuilder()
				.withIpAddress(InetAddress.getByName("127.0.0.1"))
				.withNullableAgent("Jersey", "2.23.2").build();
		
		assertThat("incorrect token context", st.getContext(), is(expectedContext));
		assertThat("incorrect token type", st.getTokenType(), is(TokenType.LOGIN));
		TestCommon.assertCloseToNow(st.getCreationDate());
		assertThat("incorrect expires", st.getExpirationDate(),
				is(st.getCreationDate().plusSeconds(14 * 24 * 3600)));
		assertThat("incorrect id", st.getId(), isA(UUID.class));
		assertThat("incorrect name", st.getTokenName(), is(Optional.absent()));
		assertThat("incorrect user", st.getUserName(), is(new UserName("whee")));
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
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		
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
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		setLoginCompleteRedirect(admintoken, "https://whee.com/bleah");
		
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
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		setLoginCompleteRedirect(admintoken, "https://whee.com/bleah");
		
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
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableRedirect(admintoken, "https://foobar.com/thingy");
		setLoginCompleteRedirect(admintoken, "https://whee.com/bleah");
		
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

		failLoginComplete(request, 400, "Bad Request", e);

		request.cookie("loginstatevar", "   \t   ");
		
		failLoginComplete(request, 400, "Bad Request", e);
	}
	
	@Test
	public void loginCompleteFailStateMismatch() throws Exception {
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("issessiontoken", "false")
				.cookie("loginstatevar", "this doesn't match");
		
		failLoginComplete(request, 401, "Unauthorized",
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
		
		failLoginComplete(request, 401, "Unauthorized",
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
		
		failLoginComplete(request, 400, "Bad Request",
				new MissingParameterException("authorization code"));
	}
	
	@Test
	public void loginCompleteFailNoSuchProvider() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov2");
		
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("loginstatevar", "foobarstate");
		
		failLoginComplete(request, 401, "Unauthorized",
				new NoSuchIdentityProviderException("prov1"));
	}
	
	@Test
	public void loginCompleteFailBadRedirect() throws Exception {
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("loginstatevar", "foobarstate")
				.cookie("loginredirect", "not a url no sir");
		
		failLoginComplete(request, 400, "Bad Request",
				new IllegalParameterException("Illegal redirect URL: not a url no sir"));
		
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy");
		
		failLoginComplete(request, 400, "Bad Request", new IllegalParameterException(
				"Post-login redirects are not enabled"));
		
		final IncomingToken adminToken = UITestUtils.getAdminToken(manager);
		enableRedirect(adminToken, "https://foobar.com/stuff2/");
		failLoginComplete(request, 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: https://foobar.com/stuff/thingy"));
	}

	private void failLoginComplete(
			final Builder request,
			final int httpCode,
			final String httpStatus,
			final AuthException e) throws Exception {
		
		final Response res = request.get();
		
		assertThat("incorrect status code", res.getStatus(), is(httpCode));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> error = res.readEntity(Map.class);
		
		UITestUtils.assertErrorCorrect(httpCode, httpStatus, e, error);
	}
}
