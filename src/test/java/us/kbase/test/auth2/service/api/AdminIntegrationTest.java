package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static us.kbase.test.auth2.TestCommon.inst;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;

import java.net.URI;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
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
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

public class AdminIntegrationTest {
	
	/*
	 * Keep these integration tests reasonably minimal. There no need to exercise every single
	 * path in the call tree; unit tests are for that.
	 */
	
	private static final UUID UID = UUID.randomUUID();
	private static final UUID UID2 = UUID.randomUUID();
	private static final UUID UID3 = UUID.randomUUID();
	private static final String DB_NAME = "test_admin_api";
	
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
				manager, DB_NAME, "random_cookie_name");
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
		ServiceTestUtils.resetServer(manager, host, "random_cookie_name");
	}
	
	@Test
	public void translateAnonIDsToUserNames() throws Exception {
		// Ensures mutability of map returned from the DAO to the main auth class
		// as root has to be removed.
		final PasswordHashAndSalt pwd = new PasswordHashAndSalt(
				"foobarbazbing".getBytes(), "aa".getBytes());
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("foobar"), UID, new DisplayName("bleah"), inst(20000)).build(),
				pwd);
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("yikes"), UID2, new DisplayName("bleah2"), inst(20000)).build(),
				pwd);
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				UserName.ROOT, UID3, new DisplayName("r"), inst(20000))
				.withRole(Role.ROOT)
				.build(),
				pwd);
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("admin"), UUID.randomUUID(), new DisplayName("a"), inst(20000))
				.withRole(Role.ADMIN)
				.build(),
				pwd);
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("admin")).withLifeTime(inst(10000), inst(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/admin/anonids")
				.queryParam(
						"list",
						String.format("  %s,  %s \t , %s  , %s  ",
								UID2, UID3, UID, UUID.randomUUID()))
				.build();
		
		final Builder req = CLI.target(target).request().header("authorization", token.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect users", response, is(ImmutableMap.of(
				UID.toString(), "foobar", UID2.toString(), "yikes")));
	}
	
	@Test
	public void translateAnonIDsToUserNamesFailNotAdmin() throws Exception {
		manager.storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("admin"), UUID.randomUUID(), new DisplayName("a"), inst(20000))
				.withRole(Role.CREATE_ADMIN)
				.build(),
				new PasswordHashAndSalt("foobarbazbing".getBytes(), "aa".getBytes()));
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(),
				new UserName("admin")).withLifeTime(inst(10000), inst(1000000000000000L)).build(),
				token.getHashedToken().getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/admin/anonids")
				.queryParam(
						"list",
						String.format("  %s,  %s \t , %s  , %s  ",
								UID2, UID3, UID, UUID.randomUUID()))
				.build();
		
		final Builder req = CLI.target(target).request()
				// GDI, Jersey adds a default accept header and I can't figure out how to stop it
				// http://stackoverflow.com/questions/40900870/how-do-i-get-jersey-test-client-to-not-fill-in-a-default-accept-header
				.header("accept", MediaType.APPLICATION_JSON)
				.header("authorization", token.getToken());

		failRequestJSON(req.get(), 403, "Forbidden", new UnauthorizedException());
	}
}
