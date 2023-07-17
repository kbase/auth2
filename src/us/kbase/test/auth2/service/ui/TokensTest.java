package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestHTML;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;
import static us.kbase.test.auth2.TestCommon.inst;
import static us.kbase.test.auth2.TestCommon.set;

import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
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
	
	private static final UUID UID = UUID.randomUUID();
	
	private static final String DB_NAME = "test_tokens_ui";
	private static final String COOKIE_NAME = "login-cookie";
	
	private static final Client CLI = ClientBuilder.newClient();
	
	private static MongoStorageTestManager manager = null;
	private static StandaloneAuthServer server = null;
	private static int port = -1;
	private static String host = null;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
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
				new UserName("whoo"), UID, new DisplayName("d"), inst(10000)).build(),
				new PasswordHashAndSalt("fobarbazbing".getBytes(), "aa".getBytes()));
		
		final IncomingToken token = new IncomingToken("whoop");
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());

		final Response res = req.get();
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
		
		final Builder reqjson = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("authorization", token.getToken());

		final Response resjson = reqjson.get();
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = resjson.readEntity(Map.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
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
				.with("createurl", "tokens")
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
				new UserName("whoo"), UID, new DisplayName("d"), Instant.ofEpochMilli(10000))
				.withRole(Role.SERV_TOKEN)
				.build(),
				new PasswordHashAndSalt("fobarbazbing".getBytes(), "aa".getBytes()));
		
		final IncomingToken token = new IncomingToken("whoop");
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id), new UserName("whoo"))
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
				TokenType.AGENT, UUID.fromString(id2), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 2000000000000000L)
				.withContext(TokenCreationContext.getBuilder()
						.withCustomContext("baz", "bat")
						.withNullableAgent("ag2", "agv2")
						.withNullableDevice("dev2")
						.build())
				.build(),
				"somehash");
		
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.DEV, UUID.fromString(id3), new UserName("whoo"))
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
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
		
		final Builder reqjson = wt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("authorization", token.getToken());

		final Response resjson = reqjson.get();
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = resjson.readEntity(Map.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
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
				.with("createurl", "")
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
	
	@Test
	public void createTokenMinimalInput() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("whoo"), UID, new DisplayName("d"), Instant.ofEpochMilli(10000))
				.withRole(Role.SERV_TOKEN)
				.build(),
				new PasswordHashAndSalt("fobarbazbing".getBytes(), "aa".getBytes()));
		
		final IncomingToken token = new IncomingToken("whoop");
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(),
						new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		final WebTarget wt = CLI.target(target);

		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());
		
		final Form form = new Form();
		form.param("name", "foo");
		
		final Response res = req.post(Entity.form(form));
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		final String regex = String.format(TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()), "whoo", "foo");
		
		final Pattern p = Pattern.compile(regex);
		
		final Matcher m = p.matcher(html);
		if (!m.matches()) {
			fail("pattern did not match token page");
		}
		final String id = m.group(1);
		final String newtoken = m.group(2);
		final long created = Long.parseLong(m.group(3));
		final long expires = Long.parseLong(m.group(4));

		UUID.fromString(id); // ensures the id is a valid uuid
		TestCommon.assertCloseToNow(created);
		assertThat("incorrect expires", expires, is(created + 90 * 24 * 3600 * 1000L));
		
		ServiceTestUtils.checkStoredToken(manager, newtoken, id, created, Collections.emptyMap(),
				new UserName("whoo"), TokenType.DEV, "foo", 90 * 24 * 3600 * 1000L);
			
		
		final Builder req2 = wt.request()
				.header("authorization", token.getToken())
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response jsonresp = req2.post(Entity.json(ImmutableMap.of("name", "foo")));
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = jsonresp.readEntity(Map.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		ServiceTestUtils.checkReturnedToken(manager, json, Collections.emptyMap(),
				new UserName("whoo"), TokenType.DEV, "foo", 90 * 24 * 3600 * 1000L, true);
	}
	
	@Test
	public void createTokenMaximalInput() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("whoo"), UID, new DisplayName("d"), Instant.ofEpochMilli(10000))
				.withRole(Role.SERV_TOKEN)
				.build(),
				new PasswordHashAndSalt("fobarbazbing".getBytes(), "aa".getBytes()));
		
		final IncomingToken token = new IncomingToken("whoop");
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(),
						new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		final WebTarget wt = CLI.target(target);

		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());
		
		final Form form = new Form();
		form.param("name", "foo");
		form.param("type", "service");
		form.param("customcontext", "foo, bar ; baz, bat");
		
		final Response res = req.post(Entity.form(form));
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		final String regex = String.format(TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()), "whoo", "foo");
		
		final Pattern p = Pattern.compile(regex);
		
		final Matcher m = p.matcher(html);
		if (!m.matches()) {
			fail("pattern did not match token page");
		}
		final String id = m.group(1);
		final String newtoken = m.group(2);
		final long created = Long.parseLong(m.group(3));
		final long expires = Long.parseLong(m.group(4));

		UUID.fromString(id); // ensures the id is a valid uuid
		TestCommon.assertCloseToNow(created);
		assertThat("incorrect expires", expires, is(created + 100_000_000L * 24 * 3600 * 1000L));
		
		ServiceTestUtils.checkStoredToken(manager, newtoken, id, created,
				ImmutableMap.of("foo", "bar", "baz", "bat"),
				new UserName("whoo"), TokenType.SERV, "foo", 100_000_000L * 24 * 3600 * 1000L);
			
		
		final Builder req2 = wt.request()
				.header("authorization", token.getToken())
				.header("accept", MediaType.APPLICATION_JSON);
		
		final Response jsonresp = req2.post(Entity.json(ImmutableMap.of(
				"name", "foo",
				"type", "service",
				"customcontext", ImmutableMap.of("foo", "bar", "baz", "bat"))));
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = jsonresp.readEntity(Map.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		ServiceTestUtils.checkReturnedToken(manager, json,
				ImmutableMap.of("foo", "bar", "baz", "bat"),
				new UserName("whoo"), TokenType.SERV, "foo",
				100_000_000L * 24 * 3600 * 1000L, true);
	}
	
	@Test
	public void createTokensFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();

		failRequestHTML(req.post(Entity.form(new Form())), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));

		req.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(req.post(Entity.json(Collections.emptyMap())), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void createTokensFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, "foobar");

		final Form form = new Form();
		form.param("name", "foo");
		failRequestHTML(req.post(Entity.form(form)), 401, "Unauthorized",
				new InvalidTokenException());

		final Builder req2 = wt.request()
				.header("authorization", "foobar")
				.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(req2.post(Entity.json(ImmutableMap.of("name", "foo"))),
				401, "Unauthorized", new InvalidTokenException());
	}
	
	@Test
	public void createTokensFailNullJSON() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		
		final WebTarget wt = CLI.target(target);

		final Builder req = wt.request()
				.header("authorization", "foobar")
				.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(req.post(Entity.json(null)), 400, "Bad Request", 
				new MissingParameterException("JSON body missing"));
	}
	
	@Test
	public void createTokensFailNullJSONAddlProps() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/tokens").build();
		
		final WebTarget wt = CLI.target(target);

		final Builder req = wt.request()
				.header("authorization", "foobar")
				.header("accept", MediaType.APPLICATION_JSON);
		
		failRequestJSON(req.post(Entity.json(ImmutableMap.of("foo", "bar"))), 400, "Bad Request", 
				new IllegalParameterException("Unexpected parameters in request: foo"));
	}
	
	@Test
	public void revokeToken() throws Exception {
		final String id = "edc1dcbb-d370-4660-a639-01a72f0d578a";
		final String id2 = "8351a73a-d4c7-4c00-9a7d-012ace5d9519";
		final String id3 = "653cc5ce-37e6-4e61-ac25-48831657f257";
		final String id4 = "d1cf14b5-b1b8-4412-8456-db0c4c1525f3";

		final IncomingToken token = new IncomingToken("whoop");
		final StoredToken st1 = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.withTokenName(new TokenName("primary"))
				.build();
		manager.storage.storeToken(st1, token.getHashedToken().getTokenHash());
		
		final StoredToken st2 = StoredToken.getBuilder(
				TokenType.AGENT, UUID.fromString(id2), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 2000000000000000L)
				.withTokenName(new TokenName("2"))
				.build();
		manager.storage.storeToken(st2, "somehash");
		
		final StoredToken st3 = StoredToken.getBuilder(
				TokenType.DEV, UUID.fromString(id3), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(30000), 3000000000000000L)
				.withTokenName(new TokenName("3"))
				.build();
		manager.storage.storeToken(st3, "somehash2");
		
		final StoredToken st4 = StoredToken.getBuilder(
				TokenType.DEV, UUID.fromString(id4), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(40000), 4000000000000000L)
				.withTokenName(new TokenName("4"))
				.build();
		manager.storage.storeToken(st4, "somehash3");
		
		final URI target = UriBuilder.fromUri(host).path("/tokens/revoke/" + id2).build();
		final WebTarget wt = CLI.target(target);

		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());
		
		final Response res = req.post(null);
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		
		final Set<StoredToken> expected = set(st1, st3, st4);
		
		final Set<StoredToken> tokens = manager.storage.getTokens(new UserName("whoo"));
		assertThat("incorrect extant tokens", tokens, is(expected));
		
		final URI target2 = UriBuilder.fromUri(host).path("/tokens/revoke/" + id4).build();
		final WebTarget wt2 = CLI.target(target2);

		final Builder req2 = wt2.request()
				.header("authorization", token.getToken());
		
		final Response res2 = req2.delete();
		
		assertThat("incorrect response code", res2.getStatus(), is(204));
		
		final Set<StoredToken> expected2 = set(st1, st3);
		
		final Set<StoredToken> tokens2 = manager.storage.getTokens(new UserName("whoo"));
		assertThat("incorrect extant tokens", tokens2, is(expected2));
		
	}
	
	@Test
	public void revokeTokenFailNoToken() throws Exception {
		final String id = "edc1dcbb-d370-4660-a639-01a72f0d578a";
		final URI target = UriBuilder.fromUri(host).path("/tokens/revoke/" + id).build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();

		failRequestHTML(req.post(null), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
		
		req.accept(MediaType.APPLICATION_JSON);

		failRequestJSON(req.delete(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void revokeTokenFailInvalidToken() throws Exception {
		final String id = "edc1dcbb-d370-4660-a639-01a72f0d578a";
		final URI target = UriBuilder.fromUri(host).path("/tokens/revoke/" + id).build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, "foobar");

		failRequestHTML(req.post(null), 401, "Unauthorized", new InvalidTokenException());
		
		final Builder req2 = wt.request()
				.header("authorization", "foobar")
				.accept(MediaType.APPLICATION_JSON);

		failRequestJSON(req2.delete(), 401, "Unauthorized", new InvalidTokenException());
	}
	
	@Test
	public void revokeTokenFailNoSuchTokenID() throws Exception {
		
		final String id = "edc1dcbb-d370-4660-a639-01a72f0d578a";
		final String id2 = "8351a73a-d4c7-4c00-9a7d-012ace5d9519";

		final IncomingToken token = new IncomingToken("whoop");
		final StoredToken st1 = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.withTokenName(new TokenName("primary"))
				.build();
		manager.storage.storeToken(st1, token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/tokens/revoke/" + id2).build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());

		failRequestHTML(req.post(null), 404, "Not Found", new NoSuchTokenException(
				String.format("No token %s for user whoo exists", id2)));
		
		final Builder req2 = wt.request()
				.header("authorization", token.getToken())
				.accept(MediaType.APPLICATION_JSON);

		failRequestJSON(req2.delete(), 404, "Not Found", new NoSuchTokenException(
				String.format("No token %s for user whoo exists", id2)));
	}
	
	@Test
	public void revokeAllPOST() throws Exception {
		final String id = "edc1dcbb-d370-4660-a639-01a72f0d578a";
		final String id2 = "8351a73a-d4c7-4c00-9a7d-012ace5d9519";
		final String id3 = "653cc5ce-37e6-4e61-ac25-48831657f257";
		final String id4 = "d1cf14b5-b1b8-4412-8456-db0c4c1525f3";

		final IncomingToken token = new IncomingToken("whoop");
		final StoredToken st1 = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.withTokenName(new TokenName("primary"))
				.build();
		manager.storage.storeToken(st1, token.getHashedToken().getTokenHash());
		
		final StoredToken st2 = StoredToken.getBuilder(
				TokenType.AGENT, UUID.fromString(id2), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 2000000000000000L)
				.withTokenName(new TokenName("2"))
				.build();
		manager.storage.storeToken(st2, "somehash");
		
		final StoredToken st3 = StoredToken.getBuilder(
				TokenType.DEV, UUID.fromString(id3), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(30000), 3000000000000000L)
				.withTokenName(new TokenName("3"))
				.build();
		manager.storage.storeToken(st3, "somehash2");
		
		final StoredToken st4 = StoredToken.getBuilder(
				TokenType.DEV, UUID.fromString(id4), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(40000), 4000000000000000L)
				.withTokenName(new TokenName("4"))
				.build();
		manager.storage.storeToken(st4, "somehash3");
		
		final URI target = UriBuilder.fromUri(host).path("/tokens/revokeall/").build();
		final WebTarget wt = CLI.target(target);

		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());
		
		final Response res = req.post(null);
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		final NewCookie c = res.getCookies().get(COOKIE_NAME);
		final NewCookie exp = new NewCookie(
				COOKIE_NAME, "no token", "/", null, "authtoken", 0, false);
		assertThat("login cookie not removed", c, is(exp));
		
		final Set<StoredToken> tokens = manager.storage.getTokens(new UserName("whoo"));
		assertThat("incorrect extant tokens", tokens, is(set()));
	}
	
	@Test
	public void revokeAllDELETE() throws Exception {
		final String id = "edc1dcbb-d370-4660-a639-01a72f0d578a";
		final String id2 = "8351a73a-d4c7-4c00-9a7d-012ace5d9519";
		final String id3 = "653cc5ce-37e6-4e61-ac25-48831657f257";
		final String id4 = "d1cf14b5-b1b8-4412-8456-db0c4c1525f3";

		final IncomingToken token = new IncomingToken("whoop");
		final StoredToken st1 = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.withTokenName(new TokenName("primary"))
				.build();
		manager.storage.storeToken(st1, token.getHashedToken().getTokenHash());
		
		final StoredToken st2 = StoredToken.getBuilder(
				TokenType.AGENT, UUID.fromString(id2), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 2000000000000000L)
				.withTokenName(new TokenName("2"))
				.build();
		manager.storage.storeToken(st2, "somehash");
		
		final StoredToken st3 = StoredToken.getBuilder(
				TokenType.DEV, UUID.fromString(id3), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(30000), 3000000000000000L)
				.withTokenName(new TokenName("3"))
				.build();
		manager.storage.storeToken(st3, "somehash2");
		
		final StoredToken st4 = StoredToken.getBuilder(
				TokenType.DEV, UUID.fromString(id4), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(40000), 4000000000000000L)
				.withTokenName(new TokenName("4"))
				.build();
		manager.storage.storeToken(st4, "somehash3");
		
		final URI target = UriBuilder.fromUri(host).path("/tokens/revokeall/").build();
		final WebTarget wt = CLI.target(target);

		final Builder req = wt.request()
				.header("authorization", token.getToken());
		
		final Response res = req.delete();
		
		assertThat("incorrect response code", res.getStatus(), is(204));
		
		final Set<StoredToken> tokens = manager.storage.getTokens(new UserName("whoo"));
		assertThat("incorrect extant tokens", tokens, is(set()));
	}
	
	@Test
	public void revokeAllTokensFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/tokens/revokeall/").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();

		failRequestHTML(req.post(null), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
		
		req.accept(MediaType.APPLICATION_JSON);

		failRequestJSON(req.delete(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void revokeAllTokensFailInvalidToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/tokens/revokeall/").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, "foobar");

		failRequestHTML(req.post(null), 401, "Unauthorized", new InvalidTokenException());
		
		final Builder req2 = wt.request()
				.header("authorization", "foobar")
				.accept(MediaType.APPLICATION_JSON);

		failRequestJSON(req2.delete(), 401, "Unauthorized", new InvalidTokenException());
	}
	

}
