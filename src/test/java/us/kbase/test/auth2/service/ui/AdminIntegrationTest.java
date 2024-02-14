package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestHTML;
import static us.kbase.test.auth2.TestCommon.inst;

import java.net.URI;
import java.nio.file.Path;
import java.util.Set;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.NewUser;
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
	
	private static final UUID UID = UUID.fromString("655c0b66-11ef-433c-8fc7-be2e44a882ba");
	private static final String DB_NAME = "test_admin_ui";
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
	
	@Test
	public void userDisplay() throws Exception {
		final IncomingToken admintoken = userDisplayCreateUser(set(Role.ADMIN));
		userDisplayCreateTargetUser();
		
		final URI target = UriBuilder.fromUri(host).path("/admin/user/foobar").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder reqhtml = wt.request().cookie(COOKIE_NAME, admintoken.getToken());
		final Response reshtml = reqhtml.get();
		assertThat("incorrect response code", reshtml.getStatus(), is(200));
		
		final String html = reshtml.readEntity(String.class);
		
		final String expectedhtml = TestCommon.getTestExpectedData(getClass(),
				TestCommon.getCurrentMethodName());
		
		TestCommon.assertNoDiffs(html, expectedhtml);
	}
	
	@Test
	public void userDisplayFailNotAdmin() throws Exception {
		final IncomingToken admintoken = userDisplayCreateUser(
				set(Role.DEV_TOKEN, Role.SERV_TOKEN));
		userDisplayCreateTargetUser();
		
		final URI target = UriBuilder.fromUri(host).path("/admin/user/foobar").build();
		final WebTarget wt = CLI.target(target);
		final Builder reqhtml = wt.request().cookie(COOKIE_NAME, admintoken.getToken());
		
		failRequestHTML(reqhtml.get(), 403, "Forbidden", new UnauthorizedException());
	}

	public void userDisplayCreateTargetUser() throws Exception {
		manager.storage.setCustomRole(new CustomRole("whoo", "a"));
		manager.storage.setCustomRole(new CustomRole("whee", "b"));
		manager.storage.setCustomRole(new CustomRole("whoop", "c"));
		manager.storage.createUser(
				NewUser.getBuilder(
						new UserName("foobar"),
						UID,
						new DisplayName("bleah"),
						inst(20000),
						new RemoteIdentity(
								new RemoteIdentityID("prov", "id"),
								new RemoteIdentityDetails("user1", "full1", "f@h.com")
						)
				)
				.withCustomRole("whoo")
				.withCustomRole("whee")
				.withEmailAddress(new EmailAddress("a@g.com"))
				.withLastLogin(inst(30000))
				.withRole(Role.ADMIN)
				.withRole(Role.DEV_TOKEN)
				.withPolicyID(new PolicyID("wugga"), inst(40000))
				.withPolicyID(new PolicyID("wubba"), inst(50000))
				.withUserDisabledState(new UserDisabledState(
						"squoze the charmin", new UserName("meanadmin"), inst(70000)))
				.build());
	}

	private IncomingToken userDisplayCreateUser(final Set<Role> roles) throws Exception {
		final NewUser.Builder user = NewUser.getBuilder(
				new UserName("admin"),
				UUID.randomUUID(),
				new DisplayName("admin"),
				inst(20000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "f@j.com"))
		);
		roles.stream().forEach(r -> user.withRole(r));
		manager.storage.createUser(user.build());
		final IncomingToken token = new IncomingToken("whee");
		manager.storage.storeToken(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(inst(10000), inst(1000000000000000L))
						.build(),
				token.getHashedToken().getTokenHash());
		return token;
	}
	
}
