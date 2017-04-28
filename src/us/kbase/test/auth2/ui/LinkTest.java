package us.kbase.test.auth2.ui;

import static us.kbase.test.auth2.ui.UITestUtils.enableProvider;
import static us.kbase.test.auth2.ui.UITestUtils.failRequestJSON;

import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;

public class LinkTest {

	private static final String DB_NAME = "test_link_ui";
	private static final String COOKIE_NAME = "login-cookie";
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "id1"),
			new RemoteIdentityDetails("user1", "full1", "e1@g.com"));
	
	private static final RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "id2"),
			new RemoteIdentityDetails("user2", "full2", "e2@g.com"));
	
	private static final RemoteIdentity REMOTE3 = new RemoteIdentity(
			new RemoteIdentityID("prov", "id3"),
			new RemoteIdentityDetails("user3", "full3", "e3@g.com"));
	
	private static final Client CLI = ClientBuilder.newClient();
	
	private static MongoStorageTestManager manager = null;
	private static StandaloneAuthServer server = null;
	private static int port = -1;
	private static String host = null;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		TestCommon.stfuLoggers();
		manager = new MongoStorageTestManager(DB_NAME);
		final Path cfgfile = UITestUtils.generateTempConfigFile(manager, DB_NAME, COOKIE_NAME);
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
		UITestUtils.resetServer(manager, host, COOKIE_NAME);
	}
	
	@Test
	public void linkDisplayNoProviders() throws Exception {
		final NewToken nt = setUpLinkDisplay();
		
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/link");
		final String res = wt.request().cookie(COOKIE_NAME, nt.getToken()).get()
				.readEntity(String.class);

		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkDisplayWithOneProvider() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");

		final NewToken nt = setUpLinkDisplay();
		
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/link");
		final String res = wt.request().cookie(COOKIE_NAME, nt.getToken()).get()
				.readEntity(String.class);

		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkDisplayWithTwoProviders() throws Exception {
		//also tests trailing slash on url
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableProvider(host, COOKIE_NAME, admintoken, "prov2");

		final NewToken nt = setUpLinkDisplay();
		
		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/link/");
		final String res = wt.request().cookie(COOKIE_NAME, nt.getToken()).get()
				.readEntity(String.class);

		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}
	
	@Test
	public void linkDisplayWithLocalUser() throws Exception {
		final IncomingToken admintoken = UITestUtils.getAdminToken(manager);
		
		enableProvider(host, COOKIE_NAME, admintoken, "prov1");
		enableProvider(host, COOKIE_NAME, admintoken, "prov2");
		
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("u1"), new DisplayName("d"), Instant.now()).build(),
				new PasswordHashAndSalt("foofoofoofoo".getBytes(), "arp".getBytes()));
		
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("u1"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(100000000000000L))
				.build(),
				"foobar");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());

		// returns crappy html only
		final WebTarget wt = CLI.target(host + "/link");
		final String res = wt.request().cookie(COOKIE_NAME, nt.getToken()).get()
				.readEntity(String.class);

		TestCommon.assertNoDiffs(res, TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName()));
	}

	@Test
	public void linkDisplayFailNoToken() throws Exception {
		final WebTarget wt = CLI.target(host + "/link");
		final Response res = wt.request().header("accept", MediaType.APPLICATION_JSON).get();

		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void linkDisplayFailNullToken() throws Exception {
		final WebTarget wt = CLI.target(host + "/link");
		final Response res = wt.request().header("accept", MediaType.APPLICATION_JSON)
				.cookie(COOKIE_NAME, null).get();

		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void linkDisplayFailEmptyToken() throws Exception {
		final WebTarget wt = CLI.target(host + "/link");
		final Response res = wt.request().header("accept", MediaType.APPLICATION_JSON)
				.cookie(COOKIE_NAME, "   \t   ").get();

		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}

	private NewToken setUpLinkDisplay() throws Exception {
		manager.storage.createUser(NewUser.getBuilder(
				new UserName("u1"), new DisplayName("d"), Instant.now(), REMOTE1).build());
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("u1"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(100000000000000L))
				.build(),
				"foobar");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		return nt;
	}
	
}
