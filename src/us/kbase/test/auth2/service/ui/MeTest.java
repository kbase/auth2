package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestHTML;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;

import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

public class MeTest {

	private static final String DB_NAME = "test_me_ui";
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
	public void getMeMinimalInput() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(new UserName("foobar"),
				new DisplayName("bleah"), Instant.ofEpochMilli(20000)).build(),
				new PasswordHashAndSalt("foobarbazbing".getBytes(), "aa".getBytes()));
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("foobar")).withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
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
				.with("roleurl", "me/roles")
				.with("unlinkurl", "me/unlink")
				.with("userupdateurl", "me")
				.with("hasroles", false)
				.with("unlink", false)
				.build();
		
		assertThat("incorrect user structure", response, is(expected));
		
		final Builder reqhtml = wt.request()
				.cookie(COOKIE_NAME, token.getToken());
		final Response reshtml = reqhtml.get();
		assertThat("incorrect response code", reshtml.getStatus(), is(200));
		
		final String html = reshtml.readEntity(String.class);
		
		final String expectedhtml = TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName());
		
		TestCommon.assertNoDiffs(html, expectedhtml);
	}
	
	@Test
	public void getMeMaximalInput() throws Exception {
		manager.storage.setCustomRole(new CustomRole("whoo", "a"));
		manager.storage.setCustomRole(new CustomRole("whee", "b"));
		manager.storage.createUser(NewUser.getBuilder(new UserName("foobar"),
				new DisplayName("bleah"), Instant.ofEpochMilli(20000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
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
		
		final URI target = UriBuilder.fromUri(host).path("/me/").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
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
				.with("roleurl", "roles")
				.with("unlinkurl", "unlink")
				.with("userupdateurl", "")
				.with("hasroles", true)
				.with("unlink", true)
				.build();
		
		assertThat("incorrect user structure", response, is(expected));
		
		final Builder reqhtml = wt.request()
				.cookie(COOKIE_NAME, token.getToken());
		final Response reshtml = reqhtml.get();
		assertThat("incorrect response code", reshtml.getStatus(), is(200));
		
		final String html = reshtml.readEntity(String.class);
		
		System.out.println(html);
		final String expectedhtml = TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName());
		
		TestCommon.assertNoDiffs(html, expectedhtml);
	}
	
	@Test
	public void getMeFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();

		failRequestHTML(req.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));

		req.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(req.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getMeFailInvalidToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/me").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, "foobar");

		failRequestHTML(req.get(), 401, "Unauthorized", new InvalidTokenException());

		final Builder req2 = wt.request()
				.header("authorization", "foobar")
				.header("accept", MediaType.APPLICATION_JSON);

		failRequestJSON(req2.get(), 401, "Unauthorized", new InvalidTokenException());
	}
	
}
