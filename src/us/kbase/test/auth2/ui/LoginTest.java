package us.kbase.test.auth2.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;

import org.ini4j.Ini;
import org.ini4j.Profile.Section;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.test.auth2.MockIdentityProviderFactory;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StartAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StartAuthServer.ServerThread;

public class LoginTest {
	
	//TODO NOW configure travis and build.xml so these tests don't run for each mongo version, just once
	
	private static final String DB_NAME = "test_login_ui";
	
	private static MongoStorageTestManager manager = null;
	private static StartAuthServer server = null;
	private static int port = -1;
	private static String host = null;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		TestCommon.stfuLoggers();
		manager = new MongoStorageTestManager(DB_NAME);
		final Path cfgfile = generateTempConfigFile();
		TestCommon.getenv().put("KB_DEPLOYMENT_CONFIG", cfgfile.toString());
		server = new StartAuthServer(KBaseAuthConfig.class.getName());
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
	
	private static Path generateTempConfigFile() throws IOException {
		final Ini ini = new Ini();
		final Section sec = ini.add("authserv2");
		sec.add("mongo-host", "localhost:" + manager.mongo.getServerPort());
		sec.add("mongo-db", DB_NAME);
		sec.add("token-cookie-name", "setcookiename");
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
	
	@Test
	public void suggestName() {
		final Client cli = ClientBuilder.newClient();
		final WebTarget wt = cli.target(host + "/login/suggestname/***FOOTYPANTS***");
		final Response r = wt.request().get();
		assertThat("incorrect expected name", r.readEntity(Map.class),
				is(ImmutableMap.of("availablename", "footypants")));
	}

}
