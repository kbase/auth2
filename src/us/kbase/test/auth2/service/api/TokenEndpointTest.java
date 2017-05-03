package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;

import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
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
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
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
}
