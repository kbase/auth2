package us.kbase.test.auth2.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;

import org.ini4j.Ini;
import org.ini4j.Profile.Section;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.test.auth2.MockIdentityProviderFactory;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;

public class LoginTest {
	
	//TODO NOW configure travis and build.xml so these tests don't run for each mongo version, just once
	
	private static final String DB_NAME = "test_login_ui";
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
		final Path cfgfile = generateTempConfigFile();
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
		manager.reset(); // destroy any admins that already exist
		//force a config reset
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		final Response r = CLI.target(host + "/admin/config/reset").request()
				.cookie(COOKIE_NAME, admintoken.getToken())
				.post(Entity.entity(null, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("unable to reset server config", r.getStatus(), is(204));
		// destroy the users and config again
		manager.reset();
		insertStandardConfig();
		
		// This is very bad form but it takes too long to start the server up for every test
		// The alternative is to use concrete IdentityProvider implementations with 
		// a mock server they talk to, but that seems like an even bigger pita
		for (final IdentityProvider mock: MockIdentityProviderFactory.mocks.values()) {
			final String name = mock.getProviderName();
			reset(mock);
			when(mock.getProviderName()).thenReturn(name);
		}
	}
	
	// inserts the config that would result on server startup per the config file below
	private static void insertStandardConfig() throws Exception {
		final IdentityProvider prov1 = mock(IdentityProvider.class);
		final IdentityProvider prov2 = mock(IdentityProvider.class);
		when(prov1.getProviderName()).thenReturn("prov1");
		when(prov2.getProviderName()).thenReturn("prov2");
		new Authentication(manager.storage, set(prov1, prov2), AuthExternalConfig.SET_DEFAULT);
	}
	
	private static Path generateTempConfigFile() throws IOException {
		final Ini ini = new Ini();
		final Section sec = ini.add("authserv2");
		sec.add("mongo-host", "localhost:" + manager.mongo.getServerPort());
		sec.add("mongo-db", DB_NAME);
		sec.add("token-cookie-name", COOKIE_NAME);
		// don't bother with logger name
		
		sec.add("identity-providers", "prov1, prov2");
		
		sec.add("identity-provider-prov1-factory", MockIdentityProviderFactory.class.getName());
		sec.add("identity-provider-prov1-login-url", "https://login.prov1.com");
		sec.add("identity-provider-prov1-api-url", "https://api.prov1.com");
		sec.add("identity-provider-prov1-client-id", "prov1clientid");
		sec.add("identity-provider-prov1-client-secret", "prov1secret");
		sec.add("identity-provider-prov1-login-redirect-url",
				"https://loginredirectforprov1.kbase.us");
		sec.add("identity-provider-prov1-link-redirect-url",
				"https://linkredirectforprov1.kbase.us");

		sec.add("identity-provider-prov2-factory", MockIdentityProviderFactory.class.getName());
		sec.add("identity-provider-prov2-login-url", "https://login.prov2.com");
		sec.add("identity-provider-prov2-api-url", "https://api.prov2.com");
		sec.add("identity-provider-prov2-client-id", "prov2clientid");
		sec.add("identity-provider-prov2-client-secret", "prov2secret");
		sec.add("identity-provider-prov2-login-redirect-url",
				"https://loginredirectforprov2.kbase.us");
		sec.add("identity-provider-prov2-link-redirect-url",
				"https://linkredirectforprov2.kbase.us");

		final Path temp = TestCommon.getTempDir();
		final Path deploy = temp.resolve(Files.createTempFile(temp, "cli_test_deploy", ".cfg"));
		ini.store(deploy.toFile());
		deploy.toFile().deleteOnExit();
		System.out.println("Generated temporary config file " + deploy);
		return deploy.toAbsolutePath();
	}

	private void enableLogin(final IncomingToken admintoken) {
		final Form allowloginform = new Form();
		allowloginform.param("allowlogin", "true");
		final Response r = CLI.target(host + "/admin/config/basic").request()
				.cookie(COOKIE_NAME, admintoken.getToken())
				.post(Entity.entity(allowloginform, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("failed to set allow login", r.getStatus(), is(204));
	}

	private void enableProvider(final IncomingToken admintoken, final String prov) {
		final Form providerform = new Form();
		providerform.param("provider", prov);
		providerform.param("enabled", "true");
		final Response rprov = CLI.target(host + "/admin/config/provider").request()
				.cookie(COOKIE_NAME, admintoken.getToken())
				.post(Entity.entity(providerform,
						MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("failed to set provider config", rprov.getStatus(), is(204));
	}

	@Test
	public void startDisplayLoginDisabled() throws Exception {
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/login/");
		final String res = wt.request().get().readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void startDisplayWithOneProvider() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		
		final WebTarget wt = CLI.target(host + "/login/");
		final String res = wt.request().get().readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void startDisplayWithTwoProviders() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		enableProvider(admintoken, "prov2");
		
		final WebTarget wt = CLI.target(host + "/login/");
		final String res = wt.request().get().readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}

	@Test
	public void suggestName() throws Exception {
		final WebTarget wt = CLI.target(host + "/login/suggestname/***FOOTYPANTS***");
		@SuppressWarnings("unchecked")
		final Map<String, String> res = wt.request().get().readEntity(Map.class);
		assertThat("incorrect expected name", res,
				is(ImmutableMap.of("availablename", "footypants")));
	}
	
	@Test
	public void loginStartMinimalInput() throws Exception {
		final IdentityProvider provmock = MockIdentityProviderFactory
				.mocks.get("prov1");
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableLogin(admintoken);
		enableProvider(admintoken, "prov1");
		
		final String url = "https://foo.com/someurlorother";
		
		final StateMatcher stateMatcher = new StateMatcher();
		when(provmock.getLoginURL(argThat(stateMatcher), eq(false))).thenReturn(new URL(url));
		
		final WebTarget wt = CLI.target(host + "/login/start");
		final Form form = new Form();
		form.param("provider", "prov1");
		final Response res = wt.request().post(
				Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("incorrect status code", res.getStatus(), is(303));
		assertThat("incorrect target uri", res.getLocation(), is(new URI(url)));
		
		final NewCookie state = res.getCookies().get("loginstatevar");
		final NewCookie expectedstate = new NewCookie("loginstatevar", stateMatcher.capturedState,
				"/login/complete", null, "loginstate", 30 * 60, false);
		assertThat("incorrect state cookie", state, is(expectedstate));
		
		final NewCookie session = res.getCookies().get("issessiontoken");
		final NewCookie expectedsession = new NewCookie("issessiontoken", "true",
				"/login", null, "session choice", 30 * 60, false);
		assertThat("incorrect session cookie", session, is(expectedsession));
		
		final NewCookie redirect = res.getCookies().get("loginredirect");
		final NewCookie expectedredirect = new NewCookie("loginredirect", "no redirect",
				"/login", null, "redirect url", 0, false);
		assertThat("incorrect redirect cookie", redirect, is(expectedredirect));
		
		//TODO NOW add test with session = false & redirect
	}

}
