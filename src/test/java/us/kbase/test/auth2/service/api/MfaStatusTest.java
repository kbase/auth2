package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static us.kbase.test.auth2.TestCommon.inst;
import static us.kbase.test.auth2.service.ServiceTestUtils.failRequestJSON;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

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

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;
import us.kbase.test.auth2.service.ServiceTestUtils;

public class MfaStatusTest {

	private static final String DB_NAME = "test_mfa_status_api";
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
		final java.nio.file.Path cfgfile = ServiceTestUtils.generateTempConfigFile(manager, DB_NAME, COOKIE_NAME);
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
	public void getMfaStatusWithMfaTrue() throws Exception {
		final NewToken nt = setUpUserWithMfa(true);
		final URI target = UriBuilder.fromUri(host).path("/api/V2/mfastatus").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect provider", response.get("provider"), is("OrcID"));
		assertThat("incorrect mfa_used", response.get("mfa_used"), is(true));
		assertThat("incorrect status", response.get("status"), is("mfa_authenticated"));
	}
	
	@Test
	public void getMfaStatusWithMfaFalse() throws Exception {
		final NewToken nt = setUpUserWithMfa(false);
		final URI target = UriBuilder.fromUri(host).path("/api/V2/mfastatus").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect provider", response.get("provider"), is("OrcID"));
		assertThat("incorrect mfa_used", response.get("mfa_used"), is(false));
		assertThat("incorrect status", response.get("status"), is("password_only"));
	}
	
	@Test
	public void getMfaStatusWithMfaNull() throws Exception {
		final NewToken nt = setUpUserWithMfa(null);
		final URI target = UriBuilder.fromUri(host).path("/api/V2/mfastatus").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect provider", response.get("provider"), is("none"));
		assertThat("incorrect mfa_used", response.get("mfa_used"), is((Object) null));
		assertThat("incorrect status", response.get("status"), is("no_mfa_info_available"));
	}
	
	@Test
	public void getMfaStatusFailNoToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/mfastatus").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.get();
		
		failRequestJSON(res, 400, "Bad Request",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getMfaStatusFailBadToken() throws Exception {
		final URI target = UriBuilder.fromUri(host).path("/api/V2/mfastatus").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", "invalidtoken")
				.header("accept", MediaType.APPLICATION_JSON);

		final Response res = req.get();
		
		failRequestJSON(res, 401, "Unauthorized", new InvalidTokenException());
	}
	
	private NewToken setUpUserWithMfa(final Boolean mfaAuthenticated) throws Exception {
		final RemoteIdentity remoteId = new RemoteIdentity(
				new RemoteIdentityID("OrcID", "testid123"),
				new RemoteIdentityDetails("testuser", "Test User", "test@example.com", mfaAuthenticated));
		
		manager.storage.createUser(us.kbase.auth2.lib.user.NewUser.getBuilder(
				new UserName("testuser"), UUID.randomUUID(), new DisplayName("Test User"), inst(10000), remoteId)
				.withEmailAddress(new EmailAddress("test@example.com")).build());
		
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("testuser"))
				.withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L))
				.build(),
				"testtokenvalue");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		return nt;
	}
	
	@Test
	public void getMfaStatusWithNonOrcidProvider() throws Exception {
		final RemoteIdentity remoteId = new RemoteIdentity(
				new RemoteIdentityID("Google", "googleid123"),
				new RemoteIdentityDetails("googleuser", "Google User", "google@example.com", true));
		
		manager.storage.createUser(us.kbase.auth2.lib.user.NewUser.getBuilder(
				new UserName("googleuser"), UUID.randomUUID(), new DisplayName("Google User"), inst(10000), remoteId)
				.withEmailAddress(new EmailAddress("google@example.com")).build());
		
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("googleuser"))
				.withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L))
				.build(),
				"googletokenvalue");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/mfastatus").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect provider", response.get("provider"), is("none"));
		assertThat("incorrect mfa_used", response.get("mfa_used"), is((Object) null));
		assertThat("incorrect status", response.get("status"), is("no_mfa_info_available"));
	}
	
	@Test
	public void getMfaStatusWithMultipleOrcidIdentities() throws Exception {
		final RemoteIdentity orcidId1 = new RemoteIdentity(
				new RemoteIdentityID("OrcID", "0000-0001-1234-5678"),
				new RemoteIdentityDetails("orciduser1", "ORCID User 1", "orcid1@example.com", false));
		
		final RemoteIdentity orcidId2 = new RemoteIdentity(
				new RemoteIdentityID("OrcID", "0000-0001-1234-9999"),
				new RemoteIdentityDetails("orciduser2", "ORCID User 2", "orcid2@example.com", true));
		
		manager.storage.createUser(us.kbase.auth2.lib.user.NewUser.getBuilder(
				new UserName("multiorciduser"), UUID.randomUUID(), new DisplayName("Multi ORCID User"), inst(10000), orcidId1)
				.withEmailAddress(new EmailAddress("multi@example.com")).build());
		
		// Link second ORCID identity
		manager.storage.link(new UserName("multiorciduser"), orcidId2);
		
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("multiorciduser"))
				.withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L))
				.build(),
				"multiorcidtokenvalue");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/mfastatus").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		// Should return first ORCID identity with MFA info (false in this case)
		assertThat("incorrect provider", response.get("provider"), is("OrcID"));
		assertThat("incorrect mfa_used", response.get("mfa_used"), is(false));
		assertThat("incorrect status", response.get("status"), is("password_only"));
	}
	
	@Test
	public void getMfaStatusWithNoIdentities() throws Exception {
		// This test is theoretical - in practice users always have at least one identity
		// But we test the edge case for completeness
		final RemoteIdentity tempId = new RemoteIdentity(
				new RemoteIdentityID("TempProvider", "tempid123"),
				new RemoteIdentityDetails("tempuser", "Temp User", "temp@example.com", null));
		
		manager.storage.createUser(us.kbase.auth2.lib.user.NewUser.getBuilder(
				new UserName("noidentuser"), UUID.randomUUID(), new DisplayName("No Ident User"), inst(10000), tempId)
				.withEmailAddress(new EmailAddress("noident@example.com")).build());
		
		// Manually remove all identities (simulating edge case)
		// Note: This would be impossible in normal operation
		manager.storage.unlink(new UserName("noidentuser"), tempId.getRemoteID());
		
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("noidentuser"))
				.withLifeTime(Instant.ofEpochMilli(10000),
						Instant.ofEpochMilli(1000000000000000L))
				.build(),
				"noidenttokenvalue");
		manager.storage.storeToken(nt.getStoredToken(), nt.getTokenHash());
		
		final URI target = UriBuilder.fromUri(host).path("/api/V2/mfastatus").build();
		
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("authorization", nt.getToken());

		final Response res = req.get();
		
		assertThat("incorrect response code", res.getStatus(), is(200));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> response = res.readEntity(Map.class);
		
		assertThat("incorrect provider", response.get("provider"), is("none"));
		assertThat("incorrect mfa_used", response.get("mfa_used"), is((Object) null));
		assertThat("incorrect status", response.get("status"), is("no_mfa_info_available"));
	}
}