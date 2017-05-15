package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestHTML;

import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
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

import org.glassfish.jersey.client.ClientProperties;
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
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.PasswordMismatchException;
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
	
	private final String TEST_USER_PWD = "fobarbazbing";
	
	private IncomingToken setUpUserForTests() throws Exception {
		
		String salt = "whee";
		// for TEST_USER_PWD
		String pwdhashb64 = "yfzvxxMCbKQgoa0e38AmGNZxPJ+lT8PNXPgiR8QkFM0=";
		
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("whoo"), new DisplayName("d"), Instant.ofEpochMilli(10000)).build(),
				new PasswordHashAndSalt(Base64.getDecoder().decode(pwdhashb64), salt.getBytes()));
		
		final IncomingToken token = new IncomingToken("whoop");
		manager.storage.storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("whoo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 1000000000000000L)
				.build(),
				token.getHashedToken().getTokenHash());
		return token;
	}
	
	@Test
	public void logoutDisplay() throws Exception {
		final IncomingToken token = setUpUserForTests();
		final URI target = UriBuilder.fromUri(host).path("/logout").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());

		final Response res = req.get();
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(
				getClass(), TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void logoutDisplayFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/logout").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();

		failRequestHTML(req.get(), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void logoutDisplayFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/logout").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, "foobar");

		failRequestHTML(req.get(), 401, "Unauthorized", new InvalidTokenException());
	}
	
	@Test
	public void logoutWithGoodToken() throws Exception {
		final IncomingToken token = setUpUserForTests();
		final URI target = UriBuilder.fromUri(host).path("/logout").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, token.getToken());

		final Response res = req.post(null);
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		final NewCookie c = res.getCookies().get(COOKIE_NAME);
		final NewCookie exp = new NewCookie(
				COOKIE_NAME, "no token", "/", null, "authtoken", 0, false);
		assertThat("login cookie not removed", c, is(exp));
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(
				getClass(), TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void logoutWithBadToken() throws Exception {
		setUpUserForTests();
		final URI target = UriBuilder.fromUri(host).path("/logout").build();
		
		final WebTarget wt = CLI.target(target);
		
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, "foobar");

		final Response res = req.post(null);
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		final NewCookie c = res.getCookies().get(COOKIE_NAME);
		final NewCookie exp = new NewCookie(
				COOKIE_NAME, "no token", "/", null, "authtoken", 0, false);
		assertThat("login cookie not removed", c, is(exp));
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(
				getClass(), TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void logoutFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/logout").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();

		failRequestHTML(req.post(null), 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void localLoginDisplay() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/localaccount/login").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Response res = req.get();
		final String html = res.readEntity(String.class);
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		TestCommon.assertNoDiffs(html, TestCommon.getTestExpectedData(
				getClass(), TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void localLoginWithReset() throws Exception {
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		ServiceTestUtils.enableLogin(host, admintoken);
		
		setUpUserForTests();
		manager.storage.forcePasswordReset(new UserName("whoo"));
		
		final URI target = UriBuilder.fromUri(host).path("/localaccount/login").build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		
		final Builder req = wt.request();
		
		final Form form = new Form();
		form.param("user", "whoo");
		form.param("pwd", TEST_USER_PWD);

		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect target uri", res.getLocation(),
				is(new URI(host + "/localaccount/reset?user=whoo")));
		assertThat("incorrect response code", res.getStatus(), is(303));
	}
	
	@Test
	public void localLoginSuccessMinimalInput() throws Exception {
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		ServiceTestUtils.enableLogin(host, admintoken);
		
		setUpUserForTests();
		
		final URI target = UriBuilder.fromUri(host).path("/localaccount/login").build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		
		final Builder req = wt.request();
		
		final Form form = new Form();
		form.param("user", "whoo");
		form.param("pwd", TEST_USER_PWD);

		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		assertThat("incorrect response code", res.getStatus(), is(303));

		final NewCookie token = res.getCookies().get(COOKIE_NAME);
		final NewCookie expectedtoken = new NewCookie(COOKIE_NAME, token.getValue(),
				"/", null, "authtoken", -1, false);
		assertThat("incorrect auth cookie less token", token, is(expectedtoken));
		
		ServiceTestUtils.checkStoredToken(manager, token.getValue(), Collections.emptyMap(),
				new UserName("whoo"), TokenType.LOGIN, null, 14 * 24 * 3600 * 1000);
	}
	
	@Test
	public void localLoginSuccessMaximalInput() throws Exception {
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		ServiceTestUtils.enableLogin(host, admintoken);
		
		setUpUserForTests();
		
		final URI target = UriBuilder.fromUri(host).path("/localaccount/login").build();
		
		final WebTarget wt = CLI.target(target).property(ClientProperties.FOLLOW_REDIRECTS, false);
		
		final Builder req = wt.request();
		
		final Form form = new Form();
		form.param("user", "whoo");
		form.param("pwd", TEST_USER_PWD);
		form.param("stayloggedin", "a");
		form.param("customcontext", " foo,  bar;   baz, bat");

		final Response res = req.post(Entity.form(form));
		
		assertThat("incorrect target uri", res.getLocation(), is(new URI(host + "/me")));
		assertThat("incorrect response code", res.getStatus(), is(303));

		final NewCookie token = res.getCookies().get(COOKIE_NAME);
		final NewCookie expectedtoken = new NewCookie(COOKIE_NAME, token.getValue(),
				"/", null, "authtoken", token.getMaxAge(), false);
		assertThat("incorrect auth cookie less token and max age", token, is(expectedtoken));
		TestCommon.assertCloseTo(token.getMaxAge(), 14 * 24 * 3600, 10);
		
		ServiceTestUtils.checkStoredToken(manager, token.getValue(), 
				ImmutableMap.of("foo", "bar", "baz", "bat"),
				new UserName("whoo"), TokenType.LOGIN, null, 14 * 24 * 3600 * 1000);
	}
	
	@Test
	public void localLoginFailNulls() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/localaccount/login").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Form form = new Form();
		form.param("user", null);
		form.param("pwd", TEST_USER_PWD);
		
		final Response res = req.post(Entity.form(form));
		failRequestHTML(res, 400, "Bad Request", new MissingParameterException("user"));
		
		final Form form2 = new Form();
		form2.param("user", "whee");
		form2.param("pwd", null);
		
		final Response res2 = req.post(Entity.form(form2));
		failRequestHTML(res2, 400, "Bad Request", new MissingParameterException("pwd"));
	}
	
	@Test
	public void localLoginFailEmptyString() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/localaccount/login").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Form form = new Form();
		form.param("user", "   \t ");
		form.param("pwd", TEST_USER_PWD);
		
		final Response res = req.post(Entity.form(form));
		failRequestHTML(res, 400, "Bad Request", new MissingParameterException("user"));
		
		final Form form2 = new Form();
		form2.param("user", "whee");
		form2.param("pwd", "   \t ");
		
		final Response res2 = req.post(Entity.form(form2));
		failRequestHTML(res2, 400, "Bad Request", new MissingParameterException("pwd"));
	}
	
	@Test
	public void localLoginFailPwdMismatch() throws Exception {
		setUpUserForTests();
		final URI target = UriBuilder.fromUri(host).path("/localaccount/login").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request();
		
		final Form form = new Form();
		form.param("user", "whoo2");
		form.param("pwd", TEST_USER_PWD);
		
		final Response res = req.post(Entity.form(form));
		failRequestHTML(res, 401, "Unauthorized", new PasswordMismatchException("whoo2"));
	}

	
}
