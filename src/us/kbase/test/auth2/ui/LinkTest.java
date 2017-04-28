package us.kbase.test.auth2.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.ui.UITestUtils.enableProvider;
import static us.kbase.test.auth2.ui.UITestUtils.failRequestJSON;
import static us.kbase.test.auth2.ui.UITestUtils.setLinkCompleteRedirect;
import static us.kbase.test.auth2.ui.UITestUtils.setPostLinkRedirect;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
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

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.TemporaryIdentities;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.MockIdentityProviderFactory;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;

public class LinkTest {

	private static final String DB_NAME = "test_link_ui";
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
		final Path cfgfile = UITestUtils.generateTempConfigFile(manager, DB_NAME, COOKIE_NAME);
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
		UITestUtils.resetServer(manager, host, COOKIE_NAME);
	}
	
	@Test
	public void linkDisplayNoProviders() throws Exception {
		final NewToken nt = setUpLinkUserAndToken();
		
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/link");
		final String res = wt.request().cookie(COOKIE_NAME, nt.getToken()).get()
				.readEntity(String.class);

		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkDisplayWithOneProvider() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");

		final NewToken nt = setUpLinkUserAndToken();
		
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/link");
		final String res = wt.request().cookie(COOKIE_NAME, nt.getToken()).get()
				.readEntity(String.class);

		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkDisplayWithTwoProviders() throws Exception {
		//also tests trailing slash on url
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableProvider(host, COOKIE_NAME, admintoken, "prov2");

		final NewToken nt = setUpLinkUserAndToken();
		
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/link/");
		final String res = wt.request().cookie(COOKIE_NAME, nt.getToken()).get()
				.readEntity(String.class);

		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkDisplayWithLocalUser() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableProvider(host, COOKIE_NAME, admintoken, "prov2");
		
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("u1"), new DisplayName("d"), Instant.now()).build(),
				new PasswordHashAndSalt("foofoofoofoo".getBytes(), "arp".getBytes()));
		
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("u1"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(100000000000000L))
				.build(),
				"foobar");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());

		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/link");
		final String res = wt.request().cookie(COOKIE_NAME, nt.getToken()).get()
				.readEntity(String.class);

		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}

	@Test
	public void linkDisplayFailNoToken() throws Exception {
		final WebTarget wt = CLI.target(host + "/link");
		final Response res = wt.request().header("accept", MediaType.APPLICATION_JSON).get();

		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void linkDisplayFailNullToken() throws Exception {
		final WebTarget wt = CLI.target(host + "/link");
		final Response res = wt.request().header("accept", MediaType.APPLICATION_JSON)
				.cookie(COOKIE_NAME, null).get();

		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void linkDisplayFailEmptyToken() throws Exception {
		final WebTarget wt = CLI.target(host + "/link");
		final Response res = wt.request().header("accept", MediaType.APPLICATION_JSON)
				.cookie(COOKIE_NAME, "   \t   ").get();

		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}

	private NewToken setUpLinkUserAndToken() throws Exception {
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("u1"), new DisplayName("d"), Instant.now(), REMOTE1).build());
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("u1"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(100000000000000L))
				.build(),
				"foobar");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		return nt;
	}
	
	@Test
	public void linkStart() throws Exception {
		final Form form = new Form();
		form.param("provider", "prov1");

		final IdentityProvider provmock = MockIdentityProviderFactory
				.mocks.get("prov1");
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		
		final String url = "https://foo.com/someurlorother";
		
		final StateMatcher stateMatcher = new StateMatcher();
		when(provmock.getLoginURL(argThat(stateMatcher), eq(true))).thenReturn(new URL(url));
		
		final WebTarget wt = CLI.target(host + "/link/start");
		final Response res = wt.request().post(
				Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(url)));
		
		final NewCookie state = res.getCookies().get("linkstatevar");
		final NewCookie expectedstate = new NewCookie("linkstatevar", stateMatcher.capturedState,
				"/link/complete", null, "linkstate", 30 * 60, false);
		assertThat("incorrect state cookie", state, is(expectedstate));
	}
	
	@Test
	public void linkStartFailNoProvider() throws Exception {
		failLinkStart(new Form(), 400, "Bad Request", new MissingParameterException("provider"));
		
		final Form form = new Form();
		form.param("provider", null);
		failLinkStart(form, 400, "Bad Request", new MissingParameterException("provider"));
		
		final Form form2 = new Form();
		form2.param("provider", "   \t  \n   ");
		failLinkStart(form2, 400, "Bad Request", new MissingParameterException("provider"));
	}
	
	@Test
	public void linkStartFailNoSuchProvider() throws Exception {
		final Form form = new Form();
		form.param("provider", "prov3");
		failLinkStart(form, 401, "Unauthorized", new NoSuchIdentityProviderException("prov3"));
	}

	private void failLinkStart(
			final Form form,
			final int expectedHTTPCode,
			final String expectedHTTPError,
			final AuthException e)
			throws Exception {
		final WebTarget wt = CLI.target(host + "/link/start");
		final Response res = wt.request().header("Accept", MediaType.APPLICATION_JSON).post(
				Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

		failRequestJSON(res, expectedHTTPCode, expectedHTTPError, e);
	}
	
	@Test
	public void linkCompleteImmediateLinkDefaultRedirect() throws Exception {
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final IdentityProvider provmock = MockIdentityProviderFactory.mocks.get("prov1");
		when(provmock.getIdentities(authcode, true)).thenReturn(set(REMOTE1, REMOTE2));
		
		final NewToken nt = setUpLinkUserAndToken(); //uses REMOTE1
		
		final WebTarget wt = linkCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("linkstatevar", state)
				.cookie(COOKIE_NAME, nt.getToken())
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		assertLinkStateCookieRemoved(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		assertThat("link failed", u.getIdentities(), is(set(REMOTE1, REMOTE2)));
	}
	
	@Test
	public void linkCompleteImmediateLinkCustomRedirect() throws Exception {
		
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		setPostLinkRedirect(host, admintoken, "https://foobar.com/baz");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final IdentityProvider provmock = MockIdentityProviderFactory.mocks.get("prov1");
		when(provmock.getIdentities(authcode, true)).thenReturn(set(REMOTE1, REMOTE3));
		
		final NewToken nt = setUpLinkUserAndToken(); //uses REMOTE1
		
		final WebTarget wt = linkCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("linkstatevar", state)
				.cookie(COOKIE_NAME, nt.getToken())
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://foobar.com/baz")));
		
		assertLinkStateCookieRemoved(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		assertThat("link failed", u.getIdentities(), is(set(REMOTE1, REMOTE3)));
	}
	
	@Test
	public void linkCompleteDelayedNoTokenAndDefaultRedirect() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final IdentityProvider provmock = MockIdentityProviderFactory.mocks.get("prov1");
		when(provmock.getIdentities(authcode, true)).thenReturn(set(REMOTE1));
		
		final WebTarget wt = linkCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("linkstatevar", state)
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/link/choice")));
		
		assertLinkStateCookieRemoved(res);
		
		final String token = assertLinkTempTokenCorrect(res);
		
		final TemporaryIdentities tis = manager.storage.getTemporaryIdentities(
				new IncomingToken(token).getHashedToken());
		
		assertThat("incorrect remote ids", tis.getIdentities().get(), is(set(REMOTE1)));
	}
	
	@Test
	public void linkCompleteDelayedEmptyTokenAndDefaultRedirect() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final IdentityProvider provmock = MockIdentityProviderFactory.mocks.get("prov1");
		when(provmock.getIdentities(authcode, true)).thenReturn(set(REMOTE1));
		
		final WebTarget wt = linkCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("linkstatevar", state)
				.cookie(COOKIE_NAME, "    \t   ")
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/link/choice")));
		
		assertLinkStateCookieRemoved(res);
		
		final String token = assertLinkTempTokenCorrect(res);
		
		final TemporaryIdentities tis = manager.storage.getTemporaryIdentities(
				new IncomingToken(token).getHashedToken());
		
		assertThat("incorrect remote ids", tis.getIdentities().get(), is(set(REMOTE1)));
	}
	
	@Test
	public void linkCompleteDelayedMultipleIdentsAndCustomRedirect() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		setLinkCompleteRedirect(host, admintoken, "https://foobar.com/baz");
		
		final String authcode = "foobarcode";
		final String state = "foobarstate";
		
		final IdentityProvider provmock = MockIdentityProviderFactory.mocks.get("prov1");
		when(provmock.getIdentities(authcode, true)).thenReturn(set(REMOTE1, REMOTE2, REMOTE3));
		
		final NewToken nt = setUpLinkUserAndToken(); // uses REMOTE1
		
		final WebTarget wt = linkCompleteSetUpWebTarget(authcode, state);
		final Response res = wt.request()
				.cookie("linkstatevar", state)
				.cookie(COOKIE_NAME, nt.getToken())
				.get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI("https://foobar.com/baz")));
		
		assertLinkStateCookieRemoved(res);
		
		final String token = assertLinkTempTokenCorrect(res);
		
		final TemporaryIdentities tis = manager.storage.getTemporaryIdentities(
				new IncomingToken(token).getHashedToken());
		
		assertThat("incorrect remote ids", tis.getIdentities().get(), is(set(REMOTE2, REMOTE3)));
	}
	
	@Test
	public void linkCompleteProviderError() throws Exception {
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/complete/prov1")
				.queryParam("error", "errorwhee")
				.build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		final Response res = wt.request().get();
		
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/link/choice")));
		
		assertLinkStateCookieRemoved(res);
		
		final String token = assertLinkTempTokenCorrect(res);
		
		final TemporaryIdentities tis = manager.storage.getTemporaryIdentities(
				new IncomingToken(token).getHashedToken());
		
		assertThat("incorrect error", tis.getError(), is(Optional.of("errorwhee")));
	}
	
	@Test
	public void linkCompleteFailNoStateCookie() throws Exception {
		final WebTarget wt = linkCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("issessiontoken", "false");
		
		final MissingParameterException e = new MissingParameterException(
				"Couldn't retrieve state value from cookie");

		failRequestJSON(request.get(), 400, "Bad Request", e);

		request.cookie("linkstatevar", "   \t   ");
		
		failRequestJSON(request.get(), 400, "Bad Request", e);
	}
	
	@Test
	public void linkCompleteFailStateMismatch() throws Exception {
		final WebTarget wt = linkCompleteSetUpWebTarget("foobarcode", "foobarstate");
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("linkstatevar", "this doesn't match");
		
		failRequestJSON(request.get(), 401, "Unauthorized",
				new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"State values do not match, this may be a CXRF attack"));
	}
	
	@Test
	public void linkCompleteFailNoProviderState() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/complete/prov1")
				.queryParam("code", "foocode")
				.build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("linkstatevar", "somestate");
		
		failRequestJSON(request.get(), 401, "Unauthorized",
				new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"State values do not match, this may be a CXRF attack"));
	}
	
	@Test
	public void linkCompleteFailNoAuthcodeNoToken() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/complete/prov1")
				.queryParam("state", "somestate")
				.build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("linkstatevar", "somestate");
		
		failRequestJSON(request.get(), 400, "Bad Request",
				new MissingParameterException("authorization code"));
	}
	
	@Test
	public void linkCompleteFailNoAuthcodeWithToken() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		
		final NewToken nt = setUpLinkUserAndToken();
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/complete/prov1")
				.queryParam("state", "somestate")
				.build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie(COOKIE_NAME, nt.getToken())
				.cookie("linkstatevar", "somestate");
		
		failRequestJSON(request.get(), 400, "Bad Request",
				new MissingParameterException("authorization code"));
	}

	private String assertLinkTempTokenCorrect(final Response res) {
		final NewCookie tempCookie = res.getCookies().get("in-process-link-token");
		final NewCookie expectedtemp = new NewCookie("in-process-link-token",
				tempCookie.getValue(),
				"/link", null, "linktoken", tempCookie.getMaxAge(), false);
		assertThat("incorrect temp cookie less value and max age", tempCookie, is(expectedtemp));
		TestCommon.assertCloseTo(tempCookie.getMaxAge(), 10 * 60, 10);
		final String token = tempCookie.getValue();
		return token;
	}
	
	private WebTarget linkCompleteSetUpWebTarget(final String authcode, final String state) {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/complete/prov1")
				.queryParam("code", authcode)
				.queryParam("state", state)
				.build();
		
		return CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
	}
	
	private void assertLinkStateCookieRemoved(final Response res) {
		final NewCookie expectedstate = new NewCookie("linkstatevar", "no state",
				"/link/complete", null, "linkstate", 0, false);
		final NewCookie statecookie = res.getCookies().get("linkstatevar");
		assertThat("incorrect state cookie", statecookie, is(expectedstate));
	}
	
}
