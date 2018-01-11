package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

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
import us.kbase.test.auth2.MapBuilder;
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
		System.out.println("started auth server at " + host);
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
		
		final Map<String, Object> response2 = getUser("whee");
		
		expected.put("created", created);
		
		assertThat("incorrect get user", response2, is(expected));
	}

	private Map<String, Object> getUser(final String user) {
		return getUser(user, 200);
	}
	
	private Map<String, Object> getUser(final String user, final int code) {
		final URI target2 = UriBuilder.fromUri(host)
				.path("/testmode/api/V2/testmodeonly/user/" + user).build();
		final WebTarget wt2 = CLI.target(target2);
		final Builder req2 = wt2.request().header("accept", MediaType.APPLICATION_JSON);
		
		final Response res2 = req2.get();
		assertThat("incorrect response code", res2.getStatus(), is(code));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response2 = res2.readEntity(Map.class);
		return response2;
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
		
		final Map<String, Object> response = createToken("whee", "Login", "foo");
		
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
		
		final Map<String, Object> response2 = getToken(token);
		
		expected.put("created", created);
		expected.put("expires", expires);
		expected.put("id", id);
		
		assertThat("incorrect get token", response2, is(expected));
	}
	
	private Map<String, Object> getToken(final String token) {
		return getToken(token, 200);
	}
	
	private Map<String, Object> getToken(final String token, final int code) {
		final URI target2 = UriBuilder.fromUri(host)
				.path("/testmode/api/V2/token").build();
		final WebTarget wt2 = CLI.target(target2);
		final Builder req2 = wt2.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header("authorization", token);
		
		final Response res2 = req2.get();
		assertThat("incorrect response code", res2.getStatus(), is(code));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response2 = res2.readEntity(Map.class);
		return response2;
	}
	

	private Map<String, Object> createToken(
			final String user,
			final String type,
			final String name) {
		final URI target = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/token/")
				.build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Response res = req.post(Entity.json(
				ImmutableMap.of("user", user, "type", type, "name", name)));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		return response;
	}
	
	@Test
	public void me() throws Exception {
		final Map<String, Object> uresponse = createUser("whee", "whoo");
		
		final long created = (long) uresponse.get("created");
		
		// create token
		final URI ttarget = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/token/")
				.build();
		final WebTarget twt = CLI.target(ttarget);
		final Builder treq = twt.request();
		
		final Response tres = treq.post(Entity.json(
				ImmutableMap.of("user", "whee", "type", "Login", "name", "foo")));
		
		assertThat("incorrect response code", tres.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> tresponse = tres.readEntity(Map.class);
		final String token = (String) tresponse.get("token");
		
		// get user from me endpoint
		final URI metarget = UriBuilder.fromUri(host).path("/testmode/api/V2/me").build();
		final WebTarget mewt = CLI.target(metarget);
		final Builder mereq = mewt.request().header("authorization", token);
		
		final Response meres = mereq.get();
		assertThat("incorrect response code", meres.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> meresponse = meres.readEntity(Map.class);
		
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
		expected.put("created", created);
		
		assertThat("incorrect get user", meresponse, is(expected));
	}

	private Map<String, Object> createUser(final String user, final String display) {
		final URI utarget = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/user/")
				.build();
		final WebTarget uwt = CLI.target(utarget);
		final Builder ureq = uwt.request();
		
		final Response ures = ureq.post(Entity.json(
				ImmutableMap.of("user", user, "display", display)));
		assertThat("user create failed", ures.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> uresponse = ures.readEntity(Map.class);
		return uresponse;
	}
	
	@Test
	public void createAndGetCustomRole() throws Exception {
		createCustomRole("thingy", "yay!");
		
		final Map<String, Object> gresponse = listCustomRoles();
		
		assertThat("incorrect roles", gresponse, is(ImmutableMap.of("customroles", Arrays.asList(
				ImmutableMap.of("id", "thingy", "desc", "yay!")))));
	}
	
	private Map<String, Object> listCustomRoles() {
		final URI gtarget = UriBuilder.fromUri(host)
				.path("/testmode/api/V2/testmodeonly/customroles/")
				.build();
		final WebTarget gwt = CLI.target(gtarget);
		final Builder greq = gwt.request();
		
		final Response gres = greq.get();
		assertThat("role create failed", gres.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> gresponse = gres.readEntity(Map.class);
		return gresponse;
	}

	private void createCustomRole(final String id, final String description) {
		final URI ctarget = UriBuilder.fromUri(host)
				.path("/testmode/api/V2/testmodeonly/customroles/")
				.build();
		final WebTarget cwt = CLI.target(ctarget);
		final Builder creq = cwt.request();
		
		final Response cres = creq.post(Entity.json(
				ImmutableMap.of("id", id, "desc", description)));
		assertThat("role create failed", cres.getStatus(), is(204));
	}
	
	@Test
	public void setRoles() {
		final long created = (long) createUser("whee", "whoo").get("created");
		createCustomRole("foo", "baz");
		createCustomRole("bar", "bat");
		
		//set roles
		final URI starget = UriBuilder.fromUri(host)
				.path("/testmode/api/V2/testmodeonly/userroles/")
				.build();
		final WebTarget swt = CLI.target(starget);
		final Builder sreq = swt.request();
		
		final Response sres = sreq.put(Entity.json(ImmutableMap.of(
				"user", "whee",
				"roles", Arrays.asList("Admin", "DevToken"),
				"customroles", Arrays.asList("foo", "bar"))));
		
		assertThat("roles set failed", sres.getStatus(), is(204));
		
		final Map<String, Object> user = getUser("whee");
		
		final Map<String, Object> expected = new HashMap<>();
		expected.put("lastlogin", null);
		expected.put("display", "whoo");
		expected.put("roles", Arrays.asList(
				ImmutableMap.of("id", "Admin", "desc", "Administrator"),
				ImmutableMap.of("id", "DevToken", "desc", "Create developer tokens")));
		expected.put("customroles", Arrays.asList("bar", "foo"));
		expected.put("policyids", Collections.emptyList());
		expected.put("user", "whee");
		expected.put("local", true);
		expected.put("email", null);
		expected.put("idents", Collections.emptyList());
		expected.put("created", created);
		
		assertThat("user modification failed", user, is(expected));
	}
	
	@Test
	public void clear() {
		createUser("foo", "bar");
		createCustomRole("whee", "whoo");
		final String token = (String) createToken("foo", "Login", "myFirstFischerPriceToken")
				.get("token");
		
		getUser("foo");
		getToken(token);
		assertThat("incorrect roles", listCustomRoles(),
				is(ImmutableMap.of("customroles", Arrays.asList(
						ImmutableMap.of("id", "whee", "desc", "whoo")))));
		
		// clear
		final URI starget = UriBuilder.fromUri(host).path("/testmode/api/V2/testmodeonly/clear/")
				.build();
		final WebTarget swt = CLI.target(starget);
		final Builder sreq = swt.request();
		
		final Response sres = sreq.delete();
		
		assertThat("clear failed", sres.getStatus(), is(204));
		
		getUser("foo", 404);
		getToken(token, 401);
		assertThat("incorrect roles", listCustomRoles(),
				is(ImmutableMap.of("customroles", Collections.emptyList())));
		
	}
	
	@Test
	public void globusToken() {
		createUser("foo", "bar");
		final Map<String, Object> token = createToken("foo", "Login", "mytoken");
		final long created = (long) token.get("created");
		final String tok = (String) token.get("token");
		
		final Map<String, Object> got1 = getGlobusToken(tok, "x-globus-goauthtoken");
		final Map<String, Object> got2 = getGlobusToken(tok, "globus-goauthtoken");
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("access_token", tok)
				.with("client_id", "foo")
				.with("expiry", (int) (created / 1000 + 3600))
				.with("expires_in", 3600)
				.with("issued_on", (int) (created / 1000))
				.with("lifetime", 3600)
				.with("refresh_token", "")
				.with("scopes", new LinkedList<String>())
				.with("token_id", token.get("id"))
				.with("token_type", "Bearer")
				.with("user_name", "foo")
				.build();
		
		assertThat("incorrect token", got1, is(expected));
		assertThat("incorrect token", got2, is(expected));
	}

	private Map<String, Object> getGlobusToken(final String tok, final String header) {
		final URI xtarget = UriBuilder.fromUri(host)
				.path("/testmode/api/legacy/globus/goauth/token/")
				.queryParam("grant_type", "client_credentials")
				.build();
		final WebTarget xwt = CLI.target(xtarget);
		final Builder xreq = xwt.request()
				.header("accept", MediaType.APPLICATION_JSON)
				.header(header, tok);
		
		final Response xres = xreq.get();
		
		assertThat("incorrect response code", xres.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> xresponse = xres.readEntity(Map.class);
		return xresponse;
	}

	@Test
	public void globusUser() {
		createUser("foo", "bar");
		final String token = (String) createToken("foo", "Agent", "mytoken").get("token");
		
		final Map<String, Object> got1 = getGlobusUser("authorization", "globus: ", token);
		final Map<String, Object> got2 = getGlobusUser("x-globus-goauthtoken", "", token);
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("username", "foo")
				.with("email_validated", false)
				.with("ssh_pubkeys", Collections.emptyList())
				.with("resource_type", "users")
				.with("full_name", "bar")
				.with("organization", null)
				.with("fullname", "bar")
				.with("user_name", "foo")
				.with("email", null)
				.with("custom_fields", new HashMap<String,String>())
				.build();
		
		assertThat("incorrect user", got1, is(expected));
		assertThat("incorrect user", got2, is(expected));
	}

	private Map<String, Object> getGlobusUser(
			final String header,
			final String headerPrefix,
			final String token) {
		final URI target = UriBuilder.fromUri(host).path("/testmode/api/legacy/globus/users/foo")
				.build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request().header(header, headerPrefix + token);
		
		final Response res = req.get();

		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		return response;
	}
	
	@Test
	public void kbaseDummyEndpoint() {
		final URI target = UriBuilder.fromUri(host)
				.path("/testmode/api/legacy/KBase/Sessions/Login/")
				.build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(401));
		
		assertThat("incorrect kbase dummy endpoint response", res.readEntity(String.class), is(
				"This GET method is just here for compatibility with " +
				"the old java client and does nothing useful. Here's the compatibility part: " +
				"\"user_id\": null"));
		
	}
	
	@Test
	public void kbaseLogin() {
		createUser("foo", "dn");
		final String token = (String) createToken("foo", "Agent", "mytoken").get("token");
		
		final URI target = UriBuilder.fromUri(host)
				.path("/testmode/api/legacy/KBase/Sessions/Login/")
				.build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Form form = new Form();
		form.param("token", token);
		form.param("fields", "token, name");
		
		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		assertThat("incorrect response", res.readEntity(Map.class), is(ImmutableMap.of(
				"token", token, "name", "dn", "user_id", "foo")));
	}
	
}
