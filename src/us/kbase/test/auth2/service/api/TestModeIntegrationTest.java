package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

public class TestModeIntegrationTest {
	
	/* Eventually all the other api integration tests should be reduced to the minimum possible
	 * and moved to an API integration test class like this one. The API classes should be modified
	 * to allow for easy instantiation via constructor dependency injection and
	 * most of the current integration tests should be converted to unit tests.
	 */
	
	/* Integration tests for test api API endpoints. Minimal tests to make sure all the layers
	 * communicate correctly.
	 */
	
	private static final String DB_NAME = "test_api_integration";
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
				manager, DB_NAME, COOKIE_NAME, true);
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
	public void createAndGetTestUser() {
		final URI target = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/user/")
				.build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Response res = req.post(Entity.json(
				ImmutableMap.of("user", "whee", "display", "whoo")));

		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		final long created = (long) response.get("created");
		response.remove("created");
		TestCommon.assertCloseToNow(created);
		
		final Map<String, Object> expected = new HashMap<>();
		expected.put("lastlogin", null);
		expected.put("display", "whoo");
		expected.put("roles", Collections.emptyList());
		expected.put("customroles", Collections.emptyList());
		expected.put("policyids", Collections.emptyList());
		expected.put("user", "whee");
		expected.put("local", true);
		expected.put("email", null);
		expected.put("idents", Collections.emptyList());
		
		assertThat("incorrect return", response, is(expected));
		
		final URI target2 = UriBuilder.fromUri(host)
				.path("/testmode/api/V2/testmodeonly/user/whee").build();
		final WebTarget wt2 = CLI.target(target2);
		final Builder req2 = wt2.request();
		
		final Response res2 = req2.get();
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response2 = res2.readEntity(Map.class);
		
		assertThat("incorrect response code", res2.getStatus(), is(200));
		
		expected.put("created", created);
		
		assertThat("incorrect get user", response2, is(expected));
	}
	
	@Test
	public void createAndGetToken() {
		// create user
		final URI utarget = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/user/")
				.build();
		final WebTarget uwt = CLI.target(utarget);
		final Builder ureq = uwt.request();
		
		final Response ures = ureq.post(Entity.json(
				ImmutableMap.of("user", "whee", "display", "whoo")));
		assertThat("user create failed", ures.getStatus(), is(200));
		
		// create token
		final URI target = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/token/")
				.build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Response res = req.post(Entity.json(
				ImmutableMap.of("user", "whee", "type", "Login", "name", "foo")));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		final long created = (long) response.get("created");
		response.remove("created");
		TestCommon.assertCloseToNow(created);
		final long expires = (long) response.get("expires");
		response.remove("expires");
		assertThat("incorrect expires", expires, is(created + (3600 * 1000)));
		final String id = (String) response.get("id");
		response.remove("id");
		final String token = (String) response.get("token");
		response.remove("token");
		
		final Map<String, Object> expected = new HashMap<>();
		expected.put("type", "Login");
		expected.put("name", "foo");
		expected.put("user", "whee");
		expected.put("custom", Collections.emptyMap());
		expected.put("cachefor", 300000);
		
		assertThat("incorrect return", response, is(expected));
		
		// get token
		final URI target2 = UriBuilder.fromUri(host)
				.path("/testmode/api/V2/token").build();
		final WebTarget wt2 = CLI.target(target2);
		final Builder req2 = wt2.request().header("authorization", token);
		
		final Response res2 = req2.get();
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response2 = res2.readEntity(Map.class);
		
		assertThat("incorrect response code", res2.getStatus(), is(200));
		
		expected.put("created", created);
		expected.put("expires", expires);
		expected.put("id", id);
		
		assertThat("incorrect get token", response2, is(expected));
	}
	
}
