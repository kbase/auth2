package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestHTML;

import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

/* Tests the simple endpoints in one module rather than breaking them up into several.
 * root
 * /customroles
 * /localaccount
 * /logout
 */
public class SimpleEndpointsTest {
	
	private static final String DB_NAME = "test_simple_endpoints_ui";
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
	
	/* for next two tests, the value of the git commit from the root endpoint could either be
	 * an error message or a git commit hash depending on the test environment, so both are
	 * allowed
	 */
	private static final String SERVER_VER = "0.1.0-prerelease";
	private static final String GIT_ERR = 
			"Missing git commit file gitcommit, should be in us.kbase.auth2";

	@Test
	public void rootHTML() throws Exception {
		
		final URI target = UriBuilder.fromUri(host).path("/").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request();

		final Response res = req.get();
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		final String regex = TestCommon.getTestExpectedData(
				getClass(), TestCommon.getCurrentMethodName());
		
		final Pattern p = Pattern.compile(regex);
		
		final Matcher m = p.matcher(html);
		if (!m.matches()) {
			fail("pattern did not match token page");
		}
		final String version = m.group(1);
		final long servertime = Long.parseLong(m.group(2));
		final String gitcommit = m.group(3);
		assertThat("version incorrect", version, is(SERVER_VER));
		TestCommon.assertCloseToNow(servertime);
		
		assertGitCommitFromRootAcceptable(gitcommit);
	}

	private void assertGitCommitFromRootAcceptable(final String gitcommit) {
		final boolean giterr = GIT_ERR.equals(gitcommit);
		final Pattern githash = Pattern.compile("[a-f\\d]{40}");
		final Matcher gitmatch = githash.matcher(gitcommit);
		final boolean gitcommitmatch = gitmatch.matches();
		
		assertThat("gitcommithash is neither an appropriate error nor a git commit: [" +
				gitcommit + "]",
				giterr || gitcommitmatch, is(true));
	}
	
	@Test
	public void rootJSON() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request()
				.accept(MediaType.APPLICATION_JSON);

		final Response res = req.get();
		@SuppressWarnings("unchecked")
		final Map<String, Object> json = res.readEntity(Map.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		final long servertime = (long) json.get("servertime");
		json.remove("servertime");
		TestCommon.assertCloseToNow(servertime);
		
		final String gitcommit = (String) json.get("gitcommithash");
		json.remove("gitcommithash");
		assertGitCommitFromRootAcceptable(gitcommit);
		
		final Map<String, Object> expected = ImmutableMap.of("version", SERVER_VER);
		
		assertThat("root json incorrect", json, is(expected));
	}
	
	@Test
	public void customRolesEmpty() throws Exception {
		final IncomingToken token = setUpUserForTests();
		assertCustomRoleHTMLCorrect(token, TestCommon.getCurrentMethodName());
	}
	
	@Test
	public void customRolesFull() throws Exception {
		final IncomingToken token = setUpUserForTests();
		
		manager.storage.setCustomRole(new CustomRole("boo", "bar"));
		manager.storage.setCustomRole(new CustomRole("coo", "bar"));
		manager.storage.setCustomRole(new CustomRole("foo", "bar"));
		manager.storage.setCustomRole(new CustomRole("moo", "bar"));
		manager.storage.setCustomRole(new CustomRole("zoo", "bar"));
		
		final String currentMethodName = TestCommon.getCurrentMethodName();
		assertCustomRoleHTMLCorrect(token, currentMethodName);
	}
	
	@Test
	public void customRolesFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/customroles").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();

		failRequestHTML(req.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void customRolesFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/customroles").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, "foobar");

		failRequestHTML(req.get(), 401, "Unauthorized", new InvalidTokenException());
	}

	private void assertCustomRoleHTMLCorrect(
			final IncomingToken token,
			final String currentMethodName)
			throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/customroles").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());

		final Response res = req.get();
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(
				getClass(), currentMethodName));
	}
	
	private IncomingToken setUpUserForTests() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("whoo"), new DisplayName("d"), Instant.ofEpochMilli(10000)).build(),
				new PasswordHashAndSalt("fobarbazbing".getBytes(), "aa".getBytes()));
		
		final IncomingToken token = new IncomingToken("whoop");
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.build(),
				token.getHashedToken().getTokenHash());
		return token;
	}
}
