package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.service.ServiceTestUtils.enableProvider;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestHTML;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;
import static us.kbase.test.auth2.service.ServiceTestUtils.setLinkCompleteRedirect;
import static us.kbase.test.auth2.service.ServiceTestUtils.setPostLinkRedirect;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.TemporaryIdentities;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.ErrorType;
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
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.MockIdentityProviderFactory;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		
		assertThat("incorrect remote ids", tis.getIdentities().get(),
				is(set(REMOTE1, REMOTE2, REMOTE3)));
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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
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
	
	private void assertLinkProcessTokenRemoved(final Response res) {
		final NewCookie expectedinprocess = new NewCookie("in-process-link-token", "no token",
				"/link", null, "linktoken", 0, false);
		final NewCookie inprocess = res.getCookies().get("in-process-link-token");
		assertThat("incorrect redirect cookie", inprocess, is(expectedinprocess));
	}
	
	@Test
	public void linkChoiceHTML() throws Exception {
		linkChoiceHTML("/link/choice", set(REMOTE1, REMOTE2, REMOTE3),
				TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkChoiceHTMLNoLinks() throws Exception {
		linkChoiceHTML("/link/choice", set(REMOTE1),
				TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkChoiceHTMLOnlyLinks() throws Exception {
		linkChoiceHTML("/link/choice", set(REMOTE2, REMOTE3),
				TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkChoiceHTMLTrailingSlash() throws Exception {
		linkChoiceHTML("/link/choice/", set(REMOTE1, REMOTE2, REMOTE3),
				TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}

	private void linkChoiceHTML(
			final String path,
			final Set<RemoteIdentity> storedIDs,
			final String expected) throws Exception {
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), storedIDs);
		
		final NewToken nt = setUpLinkUserAndToken(); // uses REMOTE1
		
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final Response res = wt.request()
				.cookie(COOKIE_NAME, nt.getToken())
				.cookie("in-process-link-token", tt.getToken())
				.get();
		
		final String html = res.readEntity(String.class);
		
		TestCommon.assertNoDiffs(html, expected);
	}
	
	@Test
	public void linkChoiceJSON() throws Exception {
		linkChoiceJSON("/link/choice", "",
				set(REMOTE1, REMOTE2, REMOTE3),
				Arrays.asList(
						ImmutableMap.of("provusername", "user2",
								"id", "5fbea2e6ce3d02f7cdbde0bc31be8059"),
						ImmutableMap.of("provusername", "user3",
								"id", "de0702aa7927b562e0d6be5b6527cfb2")
						),
				Arrays.asList(
						ImmutableMap.of("provusername", "user1",
								"id", "ef0518c79af70ed979907969c6d0a0f7",
								"user", "u1")
						));
	}
	
	@Test
	public void linkChoiceJSONNoLinks() throws Exception {
		linkChoiceJSON("/link/choice", "",
				set(REMOTE1),
				Collections.emptyList(),
				Arrays.asList(
						ImmutableMap.of("provusername", "user1",
								"id", "ef0518c79af70ed979907969c6d0a0f7",
								"user", "u1")
						));
	}
	
	@Test
	public void linkChoiceJSONOnlyLinks() throws Exception {
		linkChoiceJSON("/link/choice", "",
				set(REMOTE2, REMOTE3),
				Arrays.asList(
						ImmutableMap.of("provusername", "user2",
								"id", "5fbea2e6ce3d02f7cdbde0bc31be8059"),
						ImmutableMap.of("provusername", "user3",
								"id", "de0702aa7927b562e0d6be5b6527cfb2")
						),
				Collections.emptyList());
	}
	
	@Test
	public void linkChoiceJSONTrailingSlash() throws Exception {
		linkChoiceJSON("/link/choice/", "../",
				set(REMOTE1, REMOTE2, REMOTE3),
				Arrays.asList(
						ImmutableMap.of("provusername", "user2",
								"id", "5fbea2e6ce3d02f7cdbde0bc31be8059"),
						ImmutableMap.of("provusername", "user3",
								"id", "de0702aa7927b562e0d6be5b6527cfb2")
						),
				Arrays.asList(
						ImmutableMap.of("provusername", "user1",
								"id", "ef0518c79af70ed979907969c6d0a0f7",
								"user", "u1")
						));
	}
	
	private void linkChoiceJSON(
			final String path,
			final String urlprefix,
			final Set<RemoteIdentity> storedIDs,
			final List<Map<String, String>> idents,
			final List<Map<String, String>> linked)
			throws Exception {
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), storedIDs);
		
		final NewToken nt = setUpLinkUserAndToken(); // uses REMOTE1
		
		final URI target = UriBuilder.fromUri(host)
				.path(path)
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final Response res = wt.request()
				.header("Authorization", nt.getToken())
				.cookie("in-process-link-token", tt.getToken())
				.header("accept", MediaType.APPLICATION_JSON)
				.get();
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = res.readEntity(Map.class);
		
		final Map<String, Object> expectedJson = new HashMap<>();
		expectedJson.put("pickurl", urlprefix + "pick");
		expectedJson.put("cancelurl", urlprefix + "cancel");
		expectedJson.put("expires", 11493000000000L);
		expectedJson.put("provider", "prov");
		expectedJson.put("user", "u1");
		expectedJson.put("haslinks", !idents.isEmpty());
		expectedJson.put("idents", idents);
		expectedJson.put("linked", linked);
		
		ServiceTestUtils.assertObjectsEqual(json, expectedJson);
	}
	
	@Test
	public void linkChoiceFailNoUserToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder res = wt.request()
				.cookie("in-process-link-token", "foobar");
		
		failRequestHTML(res.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
		
		failRequestJSON(res.header("accept", MediaType.APPLICATION_JSON).get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void linkChoiceFailEmptyUserToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie("in-process-link-token", "foobar")
				.cookie(COOKIE_NAME, "    \t     ");
		
		failRequestHTML(res.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));

		final Builder res2 = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("Authorization", "    \t   ")
				.cookie("in-process-link-token", "foobar");
		
		failRequestJSON(res2.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void linkChoiceFailBadUserToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie("in-process-link-token", "foobar")
				.cookie(COOKIE_NAME, "foobarbaz");
		
		failRequestHTML(res.get(), 401, "Unauthorized",
				new InvalidTokenException());

		final Builder res2 = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("Authorization", "foobarbaz")
				.cookie("in-process-link-token", "foobar");
		
		failRequestJSON(res2.get(), 401, "Unauthorized",
				new InvalidTokenException());
	}
	
	@Test
	public void linkChoiceFailNoLinkToken() throws Exception {
		final NewToken nt = setUpLinkUserAndToken();
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie(COOKIE_NAME, nt.getToken());
		
		failRequestHTML(res.get(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));

		final Builder res2 = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("Authorization", nt.getToken());
		
		failRequestJSON(res2.get(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));
	}
	
	@Test
	public void linkChoiceFailEmptyLinkToken() throws Exception {
		final NewToken nt = setUpLinkUserAndToken();
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie("in-process-link-token", "     \t    ")
				.cookie(COOKIE_NAME, nt.getToken());
		
		failRequestHTML(res.get(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));

		final Builder res2 = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-link-token", "     \t    ")
				.header("Authorization", nt.getToken());
		
		failRequestJSON(res2.get(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));
	}
	
	@Test
	public void linkChoiceFailBadLinkToken() throws Exception {
		final NewToken nt = setUpLinkUserAndToken();
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/choice")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie("in-process-link-token", "foobarbaz")
				.cookie(COOKIE_NAME, nt.getToken());
		
		failRequestHTML(res.get(), 401, "Unauthorized",
				new InvalidTokenException("Temporary token"));

		final Builder res2 = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-link-token", "foobarbaz")
				.header("Authorization", nt.getToken());
		
		failRequestJSON(res2.get(), 401, "Unauthorized",
				new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void linkCancelPOST() throws Exception {
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), set(
				new RemoteIdentity(new RemoteIdentityID("prov", "id"),
						new RemoteIdentityDetails("user", "full", "e@g.com"))));
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/cancel")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Response res = wt.request()
				.cookie("in-process-link-token", tt.getToken())
				.post(null);
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		assertLinkProcessTokenRemoved(res);
		assertNoTempToken(tt);
	}
	
	@Test
	public void linkCancelDELETE() throws Exception {
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(), set(
				new RemoteIdentity(new RemoteIdentityID("prov", "id"),
						new RemoteIdentityDetails("user", "full", "e@g.com"))));
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/cancel")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Response res = wt.request()
				.cookie("in-process-link-token", tt.getToken())
				.delete();
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		assertLinkProcessTokenRemoved(res);
		assertNoTempToken(tt);
	}
	
	@Test
	public void linkCancelFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/cancel")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);

		failRequestJSON(res.post(null), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));
		failRequestJSON(res.delete(), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));
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
	public void linkPickOneForm() throws Exception {
		final NewToken nt = setUpLinkUserAndToken(); // uses remote1
		final TemporaryToken tt = linkPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/link/pick").build();
		final Builder req = linkPickRequestBuilder(nt, tt, target)
				.cookie(COOKIE_NAME, nt.getToken());
		final Form form = new Form();
		form.param("id", "de0702aa7927b562e0d6be5b6527cfb2");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		assertLinkProcessTokenRemoved(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1, REMOTE3)));
	}
	
	@Test
	public void linkPickOneJSON() throws Exception {
		final NewToken nt = setUpLinkUserAndToken(); // uses remote1
		final TemporaryToken tt = linkPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/link/pick").build();
		final Builder req = linkPickRequestBuilder(nt, tt, target)
				.header("Authorization", nt.getToken());
		
		final Response res = req.post(Entity.json(ImmutableMap.of(
				"id", "de0702aa7927b562e0d6be5b6527cfb2")));
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		
		assertLinkProcessTokenRemoved(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1, REMOTE3)));
	}
	
	@Test
	public void linkPickAllWithAltRedirectForm() throws Exception {
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		
		setPostLinkRedirect(host, admintoken, "https://foo.com/baz");
		
		final NewToken nt = setUpLinkUserAndToken(); // uses remote1
		final TemporaryToken tt = linkPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/link/pick").build();
		final Builder req = linkPickRequestBuilder(nt, tt, target)
				.cookie(COOKIE_NAME, nt.getToken());
		final Form form = new Form();
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI("https://foo.com/baz")));
		
		assertLinkProcessTokenRemoved(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1, REMOTE3, REMOTE2)));
	}
	
	@Test
	public void linkPickAllJSON() throws Exception {
		final NewToken nt = setUpLinkUserAndToken(); // uses remote1
		final TemporaryToken tt = linkPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/link/pick").build();
		final Builder req = linkPickRequestBuilder(nt, tt, target)
				.header("Authorization", nt.getToken());
		
		final Response res = req.post(Entity.json(Collections.emptyMap()));
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		
		assertLinkProcessTokenRemoved(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1, REMOTE3, REMOTE2)));
	}
	
	@Test
	public void linkPickAllEmptyStringForm() throws Exception {
		final NewToken nt = setUpLinkUserAndToken(); // uses remote1
		final TemporaryToken tt = linkPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/link/pick").build();
		final Builder req = linkPickRequestBuilder(nt, tt, target)
				.cookie(COOKIE_NAME, nt.getToken());
		final Form form = new Form();
		form.param("id", "   \t     ");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		
		assertLinkProcessTokenRemoved(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1, REMOTE3, REMOTE2)));
	}
	
	@Test
	public void linkPickOneEmptyStringJSON() throws Exception {
		final NewToken nt = setUpLinkUserAndToken(); // uses remote1
		final TemporaryToken tt = linkPickSetup();
		
		final URI target = UriBuilder.fromUri(host).path("/link/pick").build();
		final Builder req = linkPickRequestBuilder(nt, tt, target)
				.header("Authorization", nt.getToken());
		
		final Response res = req.post(Entity.json(ImmutableMap.of(
				"id", "   \t \n   ")));
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		
		assertLinkProcessTokenRemoved(res);
		
		final AuthUser u = manager.storage.getUser(new UserName("u1"));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1, REMOTE3, REMOTE2)));
	}
	
	@Test
	public void linkPickFailNoUserToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder res = wt.request()
				.cookie("in-process-link-token", "foobar");
		
		final Form form = new Form();
		form.param("id", "de0702aa7927b562e0d6be5b6527cfb2");
		
		failRequestHTML(res.post(Entity.form(form)), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
		
		failRequestJSON(res.header("accept", MediaType.APPLICATION_JSON).post(Entity.json(
				ImmutableMap.of("id", "de0702aa7927b562e0d6be5b6527cfb2"))), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void linkPickFailEmptyUserToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie("in-process-link-token", "foobar")
				.cookie(COOKIE_NAME, "    \t     ");
		
		final Form form = new Form();
		form.param("id", "de0702aa7927b562e0d6be5b6527cfb2");
		
		failRequestHTML(res.post(Entity.form(form)), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));

		final Builder res2 = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("Authorization", "    \t   ")
				.cookie("in-process-link-token", "foobar");
		
		failRequestJSON(res2.post(Entity.json(
				ImmutableMap.of("id", "de0702aa7927b562e0d6be5b6527cfb2"))), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void linkPickFailBadUserToken() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie("in-process-link-token", "foobar")
				.cookie(COOKIE_NAME, "foobarbaz");
		
		final Form form = new Form();
		form.param("id", "de0702aa7927b562e0d6be5b6527cfb2");
		
		failRequestHTML(res.post(Entity.form(form)), 401, "Unauthorized",
				new InvalidTokenException());

		final Builder res2 = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("Authorization", "foobarbaz")
				.cookie("in-process-link-token", "foobar");
		
		failRequestJSON(res2.post(Entity.json(
				ImmutableMap.of("id", "de0702aa7927b562e0d6be5b6527cfb2"))), 401, "Unauthorized",
				new InvalidTokenException());
	}
	
	@Test
	public void linkPickFailNoLinkToken() throws Exception {
		final NewToken nt = setUpLinkUserAndToken();
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie(COOKIE_NAME, nt.getToken());
		
		final Form form = new Form();
		form.param("id", "de0702aa7927b562e0d6be5b6527cfb2");
		
		failRequestHTML(res.post(Entity.form(form)), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));

		final Builder res2 = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("Authorization", nt.getToken());
		
		failRequestJSON(res2.post(Entity.json(
				ImmutableMap.of("id", "de0702aa7927b562e0d6be5b6527cfb2"))), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));
	}
	
	@Test
	public void linkPickFailEmptyLinkToken() throws Exception {
		final NewToken nt = setUpLinkUserAndToken();
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie("in-process-link-token", "   \t   ")
				.cookie(COOKIE_NAME, nt.getToken());
		
		final Form form = new Form();
		form.param("id", "de0702aa7927b562e0d6be5b6527cfb2");
		
		failRequestHTML(res.post(Entity.form(form)), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));

		final Builder res2 = wt.request()
				.cookie("in-process-link-token", "   \t   ")
				.header("accept", MediaType.APPLICATION_JSON)
				.header("Authorization", nt.getToken());
		
		failRequestJSON(res2.post(Entity.json(
				ImmutableMap.of("id", "de0702aa7927b562e0d6be5b6527cfb2"))), 400, "Bad Request",
				new NoTokenProvidedException("Missing in-process-link-token"));
	}
	
	@Test
	public void linkPickFailBadLinkToken() throws Exception {
		final NewToken nt = setUpLinkUserAndToken();
		
		final URI target = UriBuilder.fromUri(host)
				.path("/link/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder res = wt.request()
				.cookie("in-process-link-token", "wheee")
				.cookie(COOKIE_NAME, nt.getToken());
		
		final Form form = new Form();
		form.param("id", "de0702aa7927b562e0d6be5b6527cfb2");
		
		failRequestHTML(res.post(Entity.form(form)), 401, "Unauthorized",
				new InvalidTokenException("Temporary token"));

		final Builder res2 = wt.request()
				.cookie("in-process-link-token", "whee")
				.header("accept", MediaType.APPLICATION_JSON)
				.header("Authorization", nt.getToken());
		
		failRequestJSON(res2.post(Entity.json(
				ImmutableMap.of("id", "de0702aa7927b562e0d6be5b6527cfb2"))), 401, "Unauthorized",
				new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void linkPickFailNoJSON() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-link-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(null)),
				400, "Bad Request", new MissingParameterException("JSON body missing"));
	}
	
	@Test
	public void linkPickFailJSONWithAdditionalProperties() throws Exception {
		final URI target = UriBuilder.fromUri(host)
				.path("/link/pick")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder request = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.cookie("in-process-link-token", "foobar");
		
		failRequestJSON(request.post(Entity.json(ImmutableMap.of("foo", "bar"))),
				400, "Bad Request", new IllegalParameterException(
						"Unexpected parameters in request: foo"));
	}

	private Builder linkPickRequestBuilder(
			final NewToken nt,
			final TemporaryToken tt,
			final URI target) {
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		return wt.request()
				.cookie("in-process-link-token", tt.getToken());
	}
	
	private TemporaryToken linkPickSetup() throws Exception {
		
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(), "this is a token",
				Instant.ofEpochMilli(1493000000000L), 10000000000000L);
		manager.storage.storeIdentitiesTemporarily(tt.getHashedToken(),
				set(REMOTE1, REMOTE2, REMOTE3));
		return tt;
	}
	
}
