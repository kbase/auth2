package us.kbase.test.auth2.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
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
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.common.test.RegexMatcher;
import us.kbase.test.auth2.MapBuilder;
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

		failGetJSON(request, 400, "Bad Request", e);

		request.cookie("loginstatevar", "   \t   ");
		
		failGetJSON(request, 400, "Bad Request", e);
	}
	
	@Test
	public void loginCompleteFailStateMismatch() throws Exception {
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("issessiontoken", "false")
				.cookie("loginstatevar", "this doesn't match");
		
		failGetJSON(request, 401, "Unauthorized",
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
		
		failGetJSON(request, 401, "Unauthorized",
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
		
		failGetJSON(request, 400, "Bad Request",
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
		
		failGetJSON(request, 401, "Unauthorized",
				new NoSuchIdentityProviderException("prov1"));
	}
	
	@Test
	public void loginCompleteFailBadRedirect() throws Exception {
		final WebTarget wt = loginCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("loginstatevar", "foobarstate")
				.cookie("loginredirect", "not a url no sir");
		
		failGetJSON(request, 400, "Bad Request",
				new IllegalParameterException("Illegal redirect URL: not a url no sir"));
		
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy");
		
		failGetJSON(request, 400, "Bad Request", new IllegalParameterException(
				"Post-login redirects are not enabled"));
		
		final IncomingToken adminToken = UITestUtils.getAdminToken(manager);
		enableRedirect(adminToken, "https://foobar.com/stuff2/");
		failGetJSON(request, 400, "Bad Request", new IllegalParameterException(
				"Illegal redirect URL: https://foobar.com/stuff/thingy"));
	}

	private void failGetJSON(
			final Builder request,
			final int httpCode,
			final String httpStatus,
			final AuthException e) throws Exception {
		
		final Response res = request.get();
		failRequestJSON(res, httpCode, httpStatus, e);
	}
	
	private void failRequestJSON(
			final Response res,
			final int httpCode,
			final String httpStatus,
			final AuthException e) throws Exception {
		
		assertThat("incorrect status code", res.getStatus(), is(httpCode));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> error = res.readEntity(Map.class);
		
		UITestUtils.assertErrorCorrect(httpCode, httpStatus, e, error);
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
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		enableLogin(admintoken);
		
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
		
		UITestUtils.assertObjectsEqual(json, expectedJson);
	}

	@Test
	public void loginChoice2LoginWithRedirectAndLoginDisabled() throws Exception {
		// tests with redirect cookie
		// tests with login disabled and admin user
		// tests with trailing slash on target

		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		enableRedirect(admintoken, "https://foo.com/whee");
		
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
		
		UITestUtils.assertObjectsEqual(json, expectedJson);
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
		
		UITestUtils.assertObjectsEqual(json, expectedJson);
	}
	
	@Test
	public void loginChoice2CreateWithRedirectURL() throws Exception {
		// tests with redirect cookie
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		enableRedirect(admintoken, "https://foo.com/whee");
		enableLogin(admintoken);

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
		
		UITestUtils.assertObjectsEqual(json, expectedJson);
	}
	
	@Test
	public void loginChoiceFailNoToken() throws Exception {
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder res = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);
		
		failGetJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-login-token"));
	}
	
	@Test
	public void loginChoiceFailBadToken() throws Exception {
		
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder res = wt.request()
				.cookie("in-process-login-token", "foobarbaz")
				.header("accept", MediaType.APPLICATION_JSON);
		
		failGetJSON(res, 401, "Unauthorized", new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void loginChoiceFailBadRedirect() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/login/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.cookie("in-process-login-token", "foobarbaz")
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("loginredirect", "not a url no sir");
		
		failGetJSON(request, 400, "Bad Request",
				new IllegalParameterException("Illegal redirect URL: not a url no sir"));
		
		request.cookie("loginredirect", "https://foobar.com/stuff/thingy");
		
		failGetJSON(request, 400, "Bad Request", new IllegalParameterException(
				"Post-login redirects are not enabled"));
		
		final IncomingToken adminToken = UITestUtils.getAdminToken(manager);
		enableRedirect(adminToken, "https://foobar.com/stuff2/");
		failGetJSON(request, 400, "Bad Request", new IllegalParameterException(
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
			System.out.println(e);
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
}
