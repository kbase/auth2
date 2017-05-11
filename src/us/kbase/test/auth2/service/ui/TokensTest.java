package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestHTML;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;

import java.net.InetAddress;
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
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.token.IncomingToken;
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

public class TokensTest {
	
	private static final String DB_NAME = "test_tokens_ui";
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
		final Path cfgfile = ServiceTestUtils.generateTempConfigFile(
				manager, DB_NAME, COOKIE_NAME);
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
	public void getTokensMinimalInput() throws Exception {
		final String id = "edc1dcbb-d370-4660-a639-01a72f0d578a";

		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("whoo"), new DisplayName("d"), Instant.ofEpochMilli(10000))
				.build(),
				new PasswordHashAndSalt("fobarbazbing".getBytes(), "aa".getBytes()));
		
		final IncomingToken token = new IncomingToken("whoop");
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id),
						new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());

		final Response res = req.get();
		final String html = res.readEntity(String.class);
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
		
		final Builder reqjson = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("authorization", token.getToken());

		final Response resjson = reqjson.get();
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = resjson.readEntity(Map.class);
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "whoo")
				.with("dev", false)
				.with("service", false)
				.with("current", MapBuilder.newHashMap()
						.with("type", "Login")
						.with("id", id)
						.with("expires", 1000000000010000L)
						.with("created", 10000)
						.with("name", null)
						.with("user", "whoo")
						.with("custom", Collections.emptyMap())
						.with("os", null)
						.with("osver", null)
						.with("agent", null)
						.with("agentver", null)
						.with("device", null)
						.with("ip", null)
						.build())
				.with("tokens", Collections.emptyList())
				.with("revokeurl", "tokens/revoke/")
				.with("createurl", "tokens/create")
				.with("revokeallurl", "tokens/revokeall")
				.build();
		
		assertThat("incorrect token get reponse", json, is(expected));
	}
	
	@Test
	public void getTokensMaximalInput() throws Exception {
		final String id = "edc1dcbb-d370-4660-a639-01a72f0d578a";
		final String id2 = "8351a73a-d4c7-4c00-9a7d-012ace5d9519";
		final String id3 = "653cc5ce-37e6-4e61-ac25-48831657f257";

		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("whoo"), new DisplayName("d"), Instant.ofEpochMilli(10000))
				.withRole(Role.DEV_TOKEN)
				.withRole(Role.SERV_TOKEN)
				.build(),
				new PasswordHashAndSalt("fobarbazbing".getBytes(), "aa".getBytes()));
		
		final IncomingToken token = new IncomingToken("whoop");
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id),
						new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.withTokenName(new TokenName("wugga"))
				.withContext(TokenCreationContext.getBuilder()
						.withCustomContext("foo", "bar")
						.withIpAddress(InetAddress.getByName("127.0.0.3"))
						.withNullableAgent("ag", "agv")
						.withNullableDevice("dev")
						.withNullableOS("o", "osv")
						.build())
				.build(),
				token.getHashedToken().getTokenHash());
		
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.AGENT, UUID.fromString(id2),
						new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 2000000000000000L)
				.withContext(TokenCreationContext.getBuilder()
						.withCustomContext("baz", "bat")
						.withNullableAgent("ag2", "agv2")
						.withNullableDevice("dev2")
						.build())
				.build(),
				"somehash");
		
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.DEV, UUID.fromString(id3),
						new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(30000), 3000000000000000L)
				.withTokenName(new TokenName("whee"))
				.withContext(TokenCreationContext.getBuilder()
						.withIpAddress(InetAddress.getByName("127.0.0.42"))
						.withNullableDevice("dev3")
						.build())
				.build(),
				"somehash2");
		
		final URI target = UriBuilder.fromUri(host).path("/tokens/").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());

		final Response res = req.get();
		final String html = res.readEntity(String.class);
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
		
		final Builder reqjson = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("authorization", token.getToken());

		final Response resjson = reqjson.get();
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = resjson.readEntity(Map.class);
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "whoo")
				.with("dev", true)
				.with("service", true)
				.with("current", MapBuilder.newHashMap()
						.with("type", "Login")
						.with("id", id)
						.with("expires", 1000000000010000L)
						.with("created", 10000)
						.with("name", "wugga")
						.with("user", "whoo")
						.with("custom", ImmutableMap.of("foo", "bar"))
						.with("os", "o")
						.with("osver", "osv")
						.with("agent", "ag")
						.with("agentver", "agv")
						.with("device", "dev")
						.with("ip", "127.0.0.3")
						.build())
				.with("tokens", Arrays.asList(
						MapBuilder.newHashMap()
								.with("type", "Developer")
								.with("id", id3)
								.with("expires", 3000000000030000L)
								.with("created", 30000)
								.with("name", "whee")
								.with("user", "whoo")
								.with("custom", Collections.emptyMap())
								.with("os", null)
								.with("osver", null)
								.with("agent", null)
								.with("agentver", null)
								.with("device", "dev3")
								.with("ip", "127.0.0.42")
								.build(),
						MapBuilder.newHashMap()
								.with("type", "Agent")
								.with("id", id2)
								.with("expires", 2000000000020000L)
								.with("created", 20000)
								.with("name", null)
								.with("user", "whoo")
								.with("custom", ImmutableMap.of("baz", "bat"))
								.with("os", null)
								.with("osver", null)
								.with("agent", "ag2")
								.with("agentver", "agv2")
								.with("device", "dev2")
								.with("ip", null)
								.build()))
				.with("revokeurl", "revoke/")
				.with("createurl", "create")
				.with("revokeallurl", "revokeall")
				.build();
		
		assertThat("incorrect token get reponse", json, is(expected));
	}
	
	@Test
	public void getTokensFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();

		failRequestHTML(req.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));

		req.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(req.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getTokensFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, "foobar");

		failRequestHTML(req.get(), 401, "Unauthorized", new InvalidTokenException());

		final Builder req2 = wt.request()
				.header("authorization", "boobar")
				.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(req2.get(), 401, "Unauthorized", new InvalidTokenException());
	}

}
