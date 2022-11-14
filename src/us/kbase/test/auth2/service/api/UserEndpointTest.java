package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.apache.commons.io.IOUtils;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

/* tests the various user lookup methods, including legacy globus, the /me endpoint, and the
 * /users endpoints
 */
public class UserEndpointTest {

	private static final String DB_NAME = "test_user_api";
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
	public void testModeFail() throws Exception {
		// get user
		final URI target2 = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/user/foo")
				.build();
		final WebTarget wt2 = CLI.target(target2);
		final Builder req2 = wt2.request()
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res2 = req2.get();
		
		assertThat("incorrect response code", res2.getStatus(), is(400));
		
		failRequestJSON(res2, 400, "Bad Request",
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
		
		// create user
		final URI target = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/user/")
				.build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.post(Entity.json(
				ImmutableMap.of("user", "whee", "display", "whoo")));
		
		assertThat("incorrect response code", res.getStatus(), is(400));
		
		failRequestJSON(res, 400, "Bad Request",
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	@Test
	public void getMeMinimalInput() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("foobar"),
				new DisplayName("bleah"), Instant.ofEpochMilli(20000)).build(),
				new PasswordHashAndSalt("foobarbazbing".getBytes(), "aa".getBytes()));
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("foobar")).withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", token.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "foobar")
				.with("local", true)
				.with("display", "bleah")
				.with("email", null)
				.with("created", 20000)
				.with("lastlogin", null)
				.with("customroles", Collections.emptyList())
				.with("roles", Collections.emptyList())
				.with("idents", Collections.emptyList())
				.with("policyids", Collections.emptyList())
				.build();
		
		assertThat("incorrect user structure", response, is(expected));
	}
	
	@Test
	public void getMeMaximalInput() throws Exception {
		manager.storage.setCustomRole(new CustomRole("whoo", "a"));
		manager.storage.setCustomRole(new CustomRole("whee", "b"));
		manager.storage.createUser(NewUser.getBuilder(new UserName("foobar"),
				new DisplayName("bleah"), Instant.ofEpochMilli(20000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id"),
						new RemoteIdentityDetails("user1", "full1", "f@h.com")))
				.withCustomRole("whoo")
				.withCustomRole("whee")
				.withEmailAddress(new EmailAddress("a@g.com"))
				.withLastLogin(Instant.ofEpochMilli(30000))
				.withRole(Role.ADMIN)
				.withRole(Role.DEV_TOKEN)
				.withPolicyID(new PolicyID("wugga"), Instant.ofEpochMilli(40000))
				.withPolicyID(new PolicyID("wubba"), Instant.ofEpochMilli(50000))
				.build());
		manager.storage.link(new UserName("foobar"), new RemoteIdentity(
				new RemoteIdentityID("prov2", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com")));
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("foobar")).withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", token.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "foobar")
				.with("local", false)
				.with("display", "bleah")
				.with("email", "a@g.com")
				.with("created", 20000)
				.with("lastlogin", 30000)
				.with("customroles", Arrays.asList("whee", "whoo"))
				.with("roles", Arrays.asList(
						ImmutableMap.of("id", "Admin", "desc", "Administrator"),
						ImmutableMap.of("id", "DevToken", "desc", "Create developer tokens")))
				.with("idents", Arrays.asList(
						ImmutableMap.of(
								"provider", "prov2",
								"provusername", "user2",
								"id", "57980b7a3440a4342567e060c3e47666"),
						ImmutableMap.of(
								"provider", "prov",
								"provusername", "user1",
								"id", "c20a5e632833ab26d99906fc9cb07d6b")))
				.with("policyids", Arrays.asList(
						ImmutableMap.of("id", "wubba", "agreedon", 50000),
						ImmutableMap.of("id", "wugga", "agreedon", 40000)))
				.build();
		
		assertThat("incorrect user structure", response, is(expected));
	}
	
	@Test
	public void getMeFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
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
	public void getMeFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "foobarbaz")
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.get();
		
		failRequestJSON(res, 401, "Unauthorized", new InvalidTokenException());
	}
	
	@Test
	public void putMeNoUpdate() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("foobar"),
				new DisplayName("bleah"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f@h.com")).build(),
				new PasswordHashAndSalt("foobarbazbing".getBytes(), "aa".getBytes()));
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("foobar")).withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", token.getToken());

		final Response res = req.put(Entity.json(Collections.emptyMap()));
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		
		assertThat("user modified unexpectedly", manager.storage.getUser(new UserName("foobar")),
				is(AuthUser.getBuilder(new UserName("foobar"), new DisplayName("bleah"),
						Instant.ofEpochMilli(20000))
						.withEmailAddress(new EmailAddress("f@h.com"))
						.build()));
	}
	
	@Test
	public void putMeFullUpdate() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("foobar"),
				new DisplayName("bleah"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f@h.com")).build(),
				new PasswordHashAndSalt("foobarbazbing".getBytes(), "aa".getBytes()));
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("foobar")).withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", token.getToken());

		final Response res = req.put(Entity.json(ImmutableMap.of(
				"display", "whee", "email", "x@g.com")));
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		
		assertThat("user not modified", manager.storage.getUser(new UserName("foobar")),
				is(AuthUser.getBuilder(new UserName("foobar"), new DisplayName("whee"),
						Instant.ofEpochMilli(20000))
						.withEmailAddress(new EmailAddress("x@g.com"))
						.build()));
	}
	
	@Test
	public void putMeFailNoJSON() throws Exception {
		// jersey won't allow PUTing null json, bastards
		final URL target = new URL(host + "/api/V2/me");
		final HttpURLConnection conn = (HttpURLConnection) target.openConnection();
		conn.setRequestMethod("PUT");
		conn.setRequestProperty("accept", MediaType.APPLICATION_JSON);

		final int responseCode = conn.getResponseCode();
		final String err = IOUtils.toString(conn.getErrorStream());
		
		assertThat("incorrect error code", responseCode, is(400));
		@SuppressWarnings("unchecked")
		final Map<String, Object> errjson = new ObjectMapper().readValue(err, Map.class);
		
		ServiceTestUtils.assertErrorCorrect(400, "Bad Request",
				new MissingParameterException("JSON body missing"), errjson);
	}
	
	@Test
	public void putMeFailAdditionalProps() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.put(Entity.json(ImmutableMap.of("foo", "bar")));
		
		failRequestJSON(res, 400, "Bad Request",
				new IllegalParameterException("Unexpected parameters in request: foo"));
	}
	
	@Test
	public void putMeFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.put(Entity.json(Collections.emptyMap()));
		
		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void putMeFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "foobarbaz")
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.put(Entity.json(Collections.emptyMap()));
		
		failRequestJSON(res, 401, "Unauthorized", new InvalidTokenException());
	}
	
	@Test
	public void getGlobusUserSelfWithGlobusHeader() throws Exception {
		final PasswordHashAndSalt creds = new PasswordHashAndSalt(
				"foobarbazbing".getBytes(), "aa".getBytes());
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("foobar"),
				new DisplayName("bleah"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f@h.com")).build(),
				creds);
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("foobar")).withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/legacy/globus/users/foobar")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("x-globus-goauthtoken", token.getToken());
		
		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("username", "foobar")
				.with("email_validated", false)
				.with("ssh_pubkeys", new LinkedList<String>())
				.with("resource_type", "users")
				.with("full_name", "bleah")
				.with("organization", null)
				.with("fullname", "bleah")
				.with("user_name", "foobar")
				.with("email", "f@h.com")
				.with("custom_fields", new HashMap<String,String>())
				.build();
		
		assertThat("incorrect user structure", response, is(expected));
	}
	
	@Test
	public void getGlobusUserOtherWithAuthHeader() throws Exception {
		final PasswordHashAndSalt creds = new PasswordHashAndSalt(
				"foobarbazbing".getBytes(), "aa".getBytes());
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("foobar"),
				new DisplayName("bleah"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f@h.com")).build(),
				creds);
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("foobaz"),
				new DisplayName("bleah2"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f2@g.com")).build(),
				creds);
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("foobar")).withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/legacy/globus/users/foobaz")
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "OAuth  \t " + token.getToken() + "   \t   ");
		
		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("username", "foobaz")
				.with("email_validated", false)
				.with("ssh_pubkeys", new LinkedList<String>())
				.with("resource_type", "users")
				.with("full_name", "bleah2")
				.with("organization", null)
				.with("fullname", "bleah2")
				.with("user_name", "foobaz")
				.with("email", null)
				.with("custom_fields", new HashMap<String,String>())
				.build();
		
		assertThat("incorrect user structure", response, is(expected));
	}
	
	@Test
	public void getGlobusUserFailNoToken() throws Exception {
		final UnauthorizedException e = new UnauthorizedException(ErrorType.NO_TOKEN);
		globusUserFailNoToken("x-globus-goauthtoken", null, e);
		globusUserFailNoToken("x-globus-goauthtoken", "  \t    ", e);
		globusUserFailNoToken("authorization", null, e);
		globusUserFailNoToken("authorization", "OAuth       \t   ",
				new UnauthorizedException(ErrorType.NO_TOKEN, "Invalid authorization header"));
	}
	
	private void globusUserFailNoToken(
			final String header,
			final String token,
			final AuthException exception)
			throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/legacy/globus/users/foo")
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
	public void getGlobusUserFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/legacy/globus/users/foo")
				.build();

		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "OAuth foobar")
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response res = req.get();
		
		failRequestJSON(res, 403, "Forbidden",
				new UnauthorizedException(ErrorType.INVALID_TOKEN, "Authentication failed."));
	}
	
	@Test
	public void getUserList() throws Exception {
		getUserList("  baz,  mua  ", ImmutableMap.of("baz", "fuz", "mua", "paz"));
	}
	
	@Test
	public void getUserListEmptyList() throws Exception {
		getUserList("", Collections.emptyMap());
	}
	
	@Test
	public void getUserListWhitespaceList() throws Exception {
		getUserList("    \t    \n   ", Collections.emptyMap());
	}

	private void getUserList(
			final String list,
			final Map<String, String> expected)
			throws Exception {
		final IncomingToken token = setUpUsersForTesting();

		final URI target = UriBuilder.fromUri(host).path("/api/V2/users")
				.queryParam("list", list)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", token.getToken());
		
		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect users", response, is(expected));
	}
	
	private IncomingToken setUpUsersForTesting() throws Exception {
		final PasswordHashAndSalt creds = new PasswordHashAndSalt(
				"foobarbazbing".getBytes(), "aa".getBytes());

		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("foo"),
				new DisplayName("bar"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f@h.com")).build(),
				creds);
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("baz"),
				new DisplayName("fuz"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f@h.com")).build(),
				creds);
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("puz"),
				new DisplayName("mup"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f@h.com")).build(),
				creds);
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("mua"),
				new DisplayName("paz"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f@h.com")).build(),
				creds);
		
		
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("toobar"),
				new DisplayName("bleah2"), Instant.ofEpochMilli(20000))
				.withEmailAddress(new EmailAddress("f2@g.com")).build(),
				creds);
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("toobar")).withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		return token;
	}
	
	@Test
	public void getUserListFailMissingUser() throws Exception {
		failGetUserList(" u1  ,   , u3", "foobar", 400, "Bad Request",
				new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
						"Illegal user name [   ]: 30000 Missing input parameter: user name"));
	}
	
	@Test
	public void getUserListFailIllegalUser() throws Exception {
		failGetUserList(" u1  , aA  , u3", "foobar", 400, "Bad Request",
				new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
						"Illegal user name [ aA  ]: 30010 Illegal user name: " +
						"Illegal character in user name aA: A"));
	}
	
	@Test
	public void getUserListFailBadToken() throws Exception {
		failGetUserList("u1", null, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
		failGetUserList("u1", "boobar", 401, "Unauthorized", new InvalidTokenException());
	}
	
	private void failGetUserList(
			final String list,
			final String token,
			final int code,
			final String error,
			final AuthException e) throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/users")
				.queryParam("list", list)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", token)
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.get();
		
		failRequestJSON(res, code, error, e);
	}
	
	@Test
	public void searchUsersBlankFields() throws Exception {
		searchUsers("f", "   \t ,   ", ImmutableMap.of("foo", "bar", "baz", "fuz"));
	}
	
	@Test
	public void searchUsersUserName() throws Exception {
		searchUsers("f", " username  ,  \t  ", ImmutableMap.of("foo", "bar"));
	}
	
	@Test
	public void searchUsersDisplayName() throws Exception {
		searchUsers("f", "   \t, \t displayname  ", ImmutableMap.of("baz", "fuz"));
	}
	
	@Test
	public void searchUsersBothFields() throws Exception {
		searchUsers("f", " displayname   \t ,   \t username   ",
				ImmutableMap.of("foo", "bar", "baz", "fuz"));
	}
	
	private void searchUsers(
			final String prefix,
			final String fields,
			final Map<String, String> expected)
			throws Exception {
		final IncomingToken token = setUpUsersForTesting();

		final URI target = UriBuilder.fromUri(host).path("/api/V2/users/search/" + prefix)
				.queryParam("fields", fields)
				.build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", token.getToken());
		
		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect users", response, is(expected));
	}
	
	@Test
	public void searchUsersFailBadToken() throws Exception {
		failSearchUsers(null, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
		failSearchUsers("foobar", 401, "Unauthorized", new InvalidTokenException());
	}
	
	private void failSearchUsers(
			final String token,
			final int code,
			final String error,
			final AuthException e) throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/users/search/f").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", token)
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.get();
		
		failRequestJSON(res, code, error, e);
	}
	
}
