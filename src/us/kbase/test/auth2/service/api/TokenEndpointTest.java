package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;

import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

/* Tests the 3 token related endpoints - the standard endpoint and the 2 legacy endpoints.
 * Also covers the API token classes.
 */
public class TokenEndpointTest {

	private static final String DB_NAME = "test_link_ui";
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
	public void getToken() throws Exception {
		final UUID id = UUID.randomUUID();
		final IncomingToken it = new IncomingToken("foobarbaz");
		
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(1000000000000000L))
				.withTokenName(new TokenName("bar"))
				.withContext(TokenCreationContext.getBuilder()
						.withCustomContext("whee", "whoo").build())
				.build(), it.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", it.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("type", "Agent")
				.with("id", id.toString())
				.with("created", 10000)
				.with("expires", 1000000000000000L)
				.with("name", "bar")
				.with("user", "foo")
				.with("custom", ImmutableMap.of("whee", "whoo"))
				.with("cachefor", 300000)
				.build();
		
		assertThat("incorrect token", response, is(expected));
	}
	
	@Test
	public void getTokenFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.get();
		
		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getTokenFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "foo")
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.get();
		
		failRequestJSON(res, 401, "Unauthorized", new InvalidTokenException());
	}
	
	@Test
	public void createTokenNoCustomContext() throws Exception {
		final NewToken nt = setUpUser();
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken());
		
		final Response res = req.post(Entity.json(ImmutableMap.of("name", "whee")));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		ServiceTestUtils.checkReturnedToken(manager, response, Collections.emptyMap(),
				new UserName("foo"), TokenType.AGENT, "whee", 7 * 24 * 3600 * 1000, false);
	}
	
	@Test
	public void createTokenWithCustomContext() throws Exception {
		final NewToken nt = setUpUser();
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken());
		
		final Response res = req.post(Entity.json(ImmutableMap.of(
				"name", "whee",
				"customcontext", ImmutableMap.of("foo", "bar"))));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		ServiceTestUtils.checkReturnedToken(manager, response, ImmutableMap.of("foo", "bar"),
				new UserName("foo"), TokenType.AGENT, "whee", 7 * 24 * 3600 * 1000, false);
	}
	
	@Test
	public void createTokenFailNoJSON() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "foo")
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.post(Entity.json(null));
		
		failRequestJSON(res, 400, "Bad Request",
				new MissingParameterException("JSON body missing"));
	}
	
	@Test
	public void createTokenFailExtraParams() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "foo")
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.post(Entity.json(ImmutableMap.of("foo", "bar")));
		
		failRequestJSON(res, 400, "Bad Request",
				new IllegalParameterException("Unexpected parameters in request: foo"));
	}
	
	@Test
	public void createTokenFailNoTokenName() throws Exception {
		final NewToken nt = setUpUser();
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken())
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.post(Entity.json(ImmutableMap.of("name", "   \t    ")));
		
		failRequestJSON(res, 400, "Bad Request", new MissingParameterException("token name"));
	}
	
	@Test
	public void createTokenFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.post(Entity.json(ImmutableMap.of("name", "whee")));
		
		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void createTokenFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/token").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "foo")
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.post(Entity.json(ImmutableMap.of("name", "whee")));
		
		failRequestJSON(res, 401, "Unauthorized", new InvalidTokenException());
	}
	
	private NewToken setUpUser() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.ofEpochMilli(10000))
				.withEmailAddress(new EmailAddress("f@g.com")).build(),
				new PasswordHashAndSalt("foobarbazbing".getBytes(), "zz".getBytes()));
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L))
				.build(),
				"foobarbaz");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		return nt;
	}
	
	@Test
	public void globusTokenXHeader() throws Exception {
		globusToken("x-globus-goauthtoken");
	}
	
	@Test
	public void globusTokenStdHeader() throws Exception {
		globusToken("globus-goauthtoken");
	}

	private void globusToken(final String header) throws Exception {
		final UUID id = UUID.randomUUID();
		final IncomingToken it = new IncomingToken("foobarbaz");
		
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(1000000000000000L))
				.withTokenName(new TokenName("bar"))
				.withContext(TokenCreationContext.getBuilder()
						.withCustomContext("whee", "whoo").build())
				.build(), it.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/legacy/globus/goauth/token")
				.queryParam("grant_type", "client_credentials")
				.build();

		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header(header, it.getToken());
		
		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		final long expiresIn = (long) response.get("expires_in");
		response.remove("expires_in");
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("access_token", it.getToken())
				.with("client_id", "foo")
				.with("expiry", 1000000000000L)
				.with("issued_on", 10)
				.with("lifetime", 999999999990L)
				.with("refresh_token", "")
				.with("scopes", Collections.emptyList())
				.with("token_id", id.toString())
				.with("token_type", "Bearer")
				.with("user_name", "foo")
				.build();
		assertThat("incorrect token", response, is(expected));
		
		final long expectedExpiresIn = 1000000000000000L - Instant.now().toEpochMilli();
		TestCommon.assertCloseTo(expiresIn * 1000, expectedExpiresIn, 10000);
	}
	
	@Test
	public void globusTokenFailGrantType() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/legacy/globus/goauth/token")
				.queryParam("grant_type", "whee")
				.build();

		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.get();
		
		failRequestJSON(res, 400, "Bad Request", new AuthException(ErrorType.UNSUPPORTED_OP,
				"Only client_credentials grant_type supported. Got whee"));
	}
	
	@Test
	public void globusTokenFailNoToken() throws Exception {
		final UnauthorizedException e = new UnauthorizedException(ErrorType.NO_TOKEN);
		globusTokenFailToken("x-globus-goauthtoken", null, e);
		globusTokenFailToken("x-globus-goauthtoken", "  \t    ", e);
		globusTokenFailToken("globus-goauthtoken", null, e);
		globusTokenFailToken("globus-goauthtoken", "   \t    ", e);
	}
	
	private void globusTokenFailToken(
			final String header,
			final String token,
			final AuthException exception)
			throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/legacy/globus/goauth/token")
				.queryParam("grant_type", "client_credentials")
				.build();

		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header(header, token)
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.get();
		
		failRequestJSON(res, 403, "Forbidden", exception);
	}
	
	@Test
	public void globusTokenFailBadToken() throws Exception {
		final UnauthorizedException e = new UnauthorizedException(
				ErrorType.INVALID_TOKEN, "Authentication failed");
		globusTokenFailToken("x-globus-goauthtoken", "foobar", e);
		globusTokenFailToken("globus-goauthtoken", "foobar", e);
	}
	
	@Test
	public void kbaseDummyGetEndpoint() throws Exception {
		final URI target = UriBuilder.fromUri(host).path(
				"/api/legacy/KBase/Sessions/Login").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(401));
		
		assertThat("incorrect response", res.readEntity(String.class),
				is("This GET method is just here for compatibility with " +
				"the old java client and does nothing useful. Here's the compatibility part: " +
				"\"user_id\": null"));
	}
	
	@Test
	public void kbaseDummyPostEndpoint() throws Exception {
		final URI target = UriBuilder.fromUri(host).path(
				"/api/legacy/KBase/Sessions/Login").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);
		final Response res = req.post(null);
		
		failRequestJSON(res, 400, "Bad Request", new MissingParameterException("token"));
	}
	
	@Test
	public void kbaseTokenNoFields() throws Exception {
		final NewToken nt = setUpUser();
		kbaseTokenSuccess(null, nt, ImmutableMap.of("user_id", "foo"));
	}
	
	@Test
	public void kbaseTokenAllFields() throws Exception {
		final NewToken nt = setUpUser();
		kbaseTokenSuccess("token, name   \t   , email  ", nt,
				ImmutableMap.of(
						"user_id", "foo",
						"name", "bar",
						"email", "f@g.com",
						"token", nt.getToken()));
	}
	
	@Test
	public void kbaseTokenTokenField() throws Exception {
		final NewToken nt = setUpUser();
		kbaseTokenSuccess("token   \t    ", nt,
				ImmutableMap.of(
						"user_id", "foo",
						"token", nt.getToken()));
	}
	
	@Test
	public void kbaseTokenNameField() throws Exception {
		final NewToken nt = setUpUser();
		kbaseTokenSuccess(" name    ", nt,
				ImmutableMap.of(
						"user_id", "foo",
						"name", "bar"));
	}
	
	@Test
	public void kbaseTokenEmailField() throws Exception {
		final NewToken nt = setUpUser();
		kbaseTokenSuccess("  \t   , email  ", nt,
				ImmutableMap.of(
						"user_id", "foo",
						"email", "f@g.com"));
	}
	
	@Test
	public void kbaseTokenFailNoToken() throws Exception {
		kbaseTokenFailNoToken(new Form());
	}
	
	@Test
	public void kbaseTokenFailEmptyToken() throws Exception {
		final Form form = new Form();
		form.param("token", "   \t    ");
		kbaseTokenFailNoToken(form);
	}

	private void kbaseTokenFailNoToken(final Form form) throws Exception {
		final URI target = UriBuilder.fromUri(host).path(
				"/api/legacy/KBase/Sessions/Login").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.post(Entity.form(form));
		
		failRequestJSON(res, 400, "Bad Request", new MissingParameterException("token"));
	}
	
	@Test
	public void kbaseTokenFailBadTokenNoFields() throws Exception {
		// pulls the token from the db
		kbaseTokenFailBadToken(null);
	}

	@Test
	public void kbaseTokenFailBadTokenAllFields() throws Exception {
		// pulls the user from the db
		kbaseTokenFailBadToken("email, token, name");
	}
	
	private void kbaseTokenFailBadToken(final String fields) throws Exception {
		final URI target = UriBuilder.fromUri(host).path(
				"/api/legacy/KBase/Sessions/Login").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Form form = new Form();
		form.param("token", "foobar");
		form.param("fields", fields);
		
		final Response res = req.post(Entity.form(form));
		
		failRequestJSON(res, 401, "Unauthorized", new InvalidTokenException());
	}

	private void kbaseTokenSuccess(
			final String fields,
			final NewToken nt,
			final Map<String, Object> expected) throws Exception {
		final URI target = UriBuilder.fromUri(host).path(
				"/api/legacy/KBase/Sessions/Login").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		final Form form = new Form();
		form.param("token", nt.getToken() + "    ");
		form.param("fields", fields);
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect response", response, is(expected));
	}
}
