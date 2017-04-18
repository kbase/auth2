package us.kbase.test.auth2.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
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
		manager.reset();
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
		insertStandardConfig();
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/login/");
		final String res = wt.request().get().readEntity(String.class);
		
		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void startDisplayWithOneProvider() throws Exception {
		insertStandardConfig();
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
		insertStandardConfig();
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
	public void suggestName() {
		final WebTarget wt = CLI.target(host + "/login/suggestname/***FOOTYPANTS***");
		@SuppressWarnings("unchecked")
		final Map<String, String> res = wt.request().get().readEntity(Map.class);
		assertThat("incorrect expected name", res,
				is(ImmutableMap.of("availablename", "footypants")));
	}

}
