package us.kbase.test.auth2.service;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.ini4j.Ini;
import org.ini4j.Profile.Section;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.TextNode;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import de.danielbechler.diff.ObjectDifferBuilder;
import de.danielbechler.diff.node.DiffNode;
import de.danielbechler.diff.node.ToMapPrintingVisitor;
import de.danielbechler.diff.path.NodePath;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.common.test.RegexMatcher;
import us.kbase.test.auth2.MockIdentityProviderFactory;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.TestCommon;

public class ServiceTestUtils {
	
	private static final Client CLI = ClientBuilder.newClient();
	
	/** Set up a root account and an admin account and return a token for the admin.
	 * @param manager the mongo test manger containing the mongo storage instance that will be
	 * affected.
	 * @return a new token for an admin called 'admin' with CREATE_ADMIN and ADMIN roles.
	 * @throws Exception if bad things happen.
	 */
	public static IncomingToken getAdminToken(final MongoStorageTestManager manager)
			throws Exception {
		final String rootpwd = "foobarwhoowhee";
		when(manager.mockClock.instant()).thenReturn(Instant.now());
		final Authentication auth = new Authentication(
				manager.storage, set(), AuthExternalConfig.SET_DEFAULT, false);
		auth.createRoot(new Password(rootpwd.toCharArray()));
		final String roottoken = auth.localLogin(UserName.ROOT,
				new Password(rootpwd.toCharArray()),
				TokenCreationContext.getBuilder().build()).getToken().get().getToken();
		final Password admintemppwd = auth.createLocalUser(
				new IncomingToken(roottoken), new UserName("admin"), new DisplayName("a"),
				new EmailAddress("f@g.com"));
		auth.updateRoles(new IncomingToken(roottoken), new UserName("admin"),
				set(Role.CREATE_ADMIN), set());
		final String adminpwd = "foobarwhoowhee2";
		auth.localPasswordChange(new UserName("admin"), admintemppwd,
				new Password(adminpwd.toCharArray()));
		final String admintoken = auth.localLogin(new UserName("admin"),
				new Password(adminpwd.toCharArray()), TokenCreationContext.getBuilder().build())
				.getToken().get().getToken();
		auth.updateRoles(new IncomingToken(admintoken), new UserName("admin"), set(Role.ADMIN),
				set());
		return new IncomingToken(admintoken);
	}

	public static void failRequestJSON(
			final Response res,
			final int httpCode,
			final String httpStatus,
			final AuthException e)
			throws Exception {
		
		assertThat("incorrect status code", res.getStatus(), is(httpCode));
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> error = res.readEntity(Map.class);
		
		assertErrorCorrect(httpCode, httpStatus, e, error);
	}
	
	public static void assertErrorCorrect(
			final int expectedHTTPCode,
			final String expectedHTTPStatus,
			final AuthException expectedException,
			final Map<String, Object> error) {
		
		final Map<String, Object> innerExpected = new HashMap<>();
		innerExpected.put("httpcode", expectedHTTPCode);
		innerExpected.put("httpstatus", expectedHTTPStatus);
		innerExpected.put("appcode", expectedException.getErr().getErrorCode());
		innerExpected.put("apperror", expectedException.getErr().getError());
		innerExpected.put("message", expectedException.getMessage());
		
		final Map<String, Object> expected = ImmutableMap.of("error", innerExpected);
		
		if (!error.containsKey("error")) {
			fail("error object has no error key");
		}
		
		@SuppressWarnings("unchecked")
		final Map<String, Object> inner = (Map<String, Object>) error.get("error");
		
		final String callid = (String) inner.get("callid");
		final long time = (long) inner.get("time");
		inner.remove("callid");
		inner.remove("time");
		
		assertThat("incorrect error structure less callid and time", error, is(expected));
		assertThat("incorrect call id", callid, RegexMatcher.matches("\\d{16}"));
		TestCommon.assertCloseToNow(time);
	}
	
	public static void failRequestHTML(
			final Response res,
			final int httpCode,
			final String httpStatus,
			final AuthException e)
			throws Exception {
		assertThat("incorrect status code", res.getStatus(), is(httpCode));
		final String html = res.readEntity(String.class);
		final Document doc = Jsoup.parse(html);
		assertErrorCorrect(httpCode, httpStatus, e, doc);
	}

	public static void assertErrorCorrect(
			final int expectedHttpCode,
			final String expectedHttpStatus,
			final AuthException e,
			final Document doc) {
		
		final Element title = doc.getElementsByTag("title").first();
		assertThat("incorrect title", title.html(),
				is(expectedHttpCode + " " + expectedHttpStatus));
		
		final Element body = doc.getElementsByTag("body").first();
		final List<TextNode> breaks = body.textNodes();
		
		assertThat("incorrect line 1", body.child(0).html(), is(
				"Note that in a proper UI, the error message and exception should " +
				"be HTML-escaped."));
		assertThat("incorrect line 2", body.child(1).html(), is(
				"Gee whiz, I sure am sorry, but an error occurred. Gosh!"));
		final String timestamp = breaks.get(2).getWholeText();
		assertThat("incorrect timestamp prefix", timestamp,
				RegexMatcher.matches("^\\s*Timestamp: \\d+"));
		TestCommon.assertCloseToNow(Long.parseLong(timestamp.trim().split("\\s+")[1].trim()));
		assertThat("incorrect call id", breaks.get(3).getWholeText(),
				RegexMatcher.matches("^\\s*Call ID: \\d{16}"));
		assertThat("incorrect http code", breaks.get(4).getWholeText(),
				RegexMatcher.matches("^\\s*Http code: " + expectedHttpCode));
		assertThat("incorrect http status", breaks.get(5).getWholeText(),
				RegexMatcher.matches("^\\s*Http status: " + expectedHttpStatus));
		assertThat("incorrect application code", breaks.get(6).getWholeText(),
				RegexMatcher.matches("^\\s*Application code: " + e.getErr().getErrorCode()));
		assertThat("incorrect application error", breaks.get(7).getWholeText(),
				RegexMatcher.matches("^\\s*Application error: " + e.getErr().getError()));
		assertThat("incorrect message", breaks.get(8).getWholeText(),
				RegexMatcher.matches("^\\s*Message: " + Pattern.quote(e.getMessage())));
	}
	
	// note ObjectDiffer does NOT check sorted lists are sorted
	// this really kind of sucks, but it's better for large shallow objects
	// easy enough to do a straight equals if needed
	public static void assertObjectsEqual(final Object got, final Object expected) {
		final DiffNode diff = ObjectDifferBuilder.buildDefault().compare(got, expected);
		final ToMapPrintingVisitor visitor = new ToMapPrintingVisitor(got, expected);
		diff.visit(visitor);
		
		assertThat("non empty structure diff", visitor.getMessages(),
				is(ImmutableMap.of(NodePath.withRoot(), "Property at path '/' has not changed")));
	}
	
	public static void checkReturnedToken(
			final MongoStorageTestManager manager,
			final Map<String, Object> uitoken,
			final Map<String, String> customContext,
			final UserName userName,
			final TokenType type,
			final String name,
			final long lifetime,
			final boolean checkAgentContext)
			throws Exception {
		
		assertThat("incorrect token context", uitoken.get("custom"), is(customContext));
		assertThat("incorrect token type", uitoken.get("type"), is(type.getDescription()));
		final long created = (long) uitoken.get("created");
		TestCommon.assertCloseToNow(created);
		assertThat("incorrect expires", uitoken.get("expires"),
				is((long) uitoken.get("created") + lifetime));
		final String id = (String) uitoken.get("id");
		UUID.fromString(id); // ensures id is a valid uuid
		assertThat("incorrect name", uitoken.get("name"), is(name));
		if (checkAgentContext) {
			assertThat("incorrect os", uitoken.get("os"), is((String) null));
			assertThat("incorrect osver", uitoken.get("osver"), is((String) null));
			assertThat("incorrect agent", uitoken.get("agent"), is("Jersey"));
			assertThat("incorrect agentver", uitoken.get("agentver"), is("2.23.2"));
			assertThat("incorrect device", uitoken.get("device"), is((String) null));
			assertThat("incorrect ip", uitoken.get("ip"), is("127.0.0.1"));
		}
		
		checkStoredToken(manager, (String) uitoken.get("token"), id, created, customContext,
				userName, type, name, lifetime);
	}
	
	public static void checkStoredToken(
			final MongoStorageTestManager manager,
			final String token,
			final String id,
			final long created,
			final Map<String, String> customContext,
			final UserName userName,
			final TokenType type,
			final String name,
			final long lifetime)
			throws Exception {
		
		assertThat("incorrect token", token, is(RegexMatcher.matches("[A-Z2-7]{32}")));
		
		final StoredToken st = manager.storage.getToken(
				new IncomingToken(token).getHashedToken());
		
		final TokenCreationContext.Builder build = TokenCreationContext.getBuilder()
				.withIpAddress(InetAddress.getByName("127.0.0.1"))
				.withNullableAgent("Jersey", "2.23.2");
		
		for (final Entry<String, String> e: customContext.entrySet()) {
			build.withCustomContext(e.getKey(), e.getValue());
		}
		
		final Optional<TokenName> tn;
		if (name == null) {
			tn = Optional.absent();
		} else {
			tn = Optional.of(new TokenName(name));
		}
		
		assertThat("incorrect token context", st.getContext(), is(build.build()));
		assertThat("incorrect token type", st.getTokenType(), is(type));
		assertThat("incorrect created", st.getCreationDate(), is(Instant.ofEpochMilli(created)));
		assertThat("incorrect expires", st.getExpirationDate(),
				is(st.getCreationDate().plusMillis(lifetime)));
		assertThat("incorrect id", st.getId(), is(UUID.fromString(id)));
		assertThat("incorrect name", st.getTokenName(), is(tn));
		assertThat("incorrect user", st.getUserName(), is(userName));
	}
	
	// combine with above somehow?
	public static void checkStoredToken(
			final MongoStorageTestManager manager,
			final String token,
			final Map<String, String> customContext,
			final UserName userName,
			final TokenType type,
			final String name,
			final long lifetime)
			throws Exception {
		
		assertThat("incorrect token", token, is(RegexMatcher.matches("[A-Z2-7]{32}")));
		
		final StoredToken st = manager.storage.getToken(
				new IncomingToken(token).getHashedToken());
		
		final TokenCreationContext.Builder build = TokenCreationContext.getBuilder()
				.withIpAddress(InetAddress.getByName("127.0.0.1"))
				.withNullableAgent("Jersey", "2.23.2");
		
		for (final Entry<String, String> e: customContext.entrySet()) {
			build.withCustomContext(e.getKey(), e.getValue());
		}
		
		final Optional<TokenName> tn;
		if (name == null) {
			tn = Optional.absent();
		} else {
			tn = Optional.of(new TokenName(name));
		}
		
		assertThat("incorrect token context", st.getContext(), is(build.build()));
		assertThat("incorrect token type", st.getTokenType(), is(type));
		TestCommon.assertCloseToNow(st.getCreationDate());
		assertThat("incorrect expires", st.getExpirationDate(),
				is(st.getCreationDate().plusMillis(lifetime)));
		assertThat("incorrect id", st.getId(), isA(UUID.class));
		assertThat("incorrect name", st.getTokenName(), is(tn));
		assertThat("incorrect user", st.getUserName(), is(userName));
	}
	
	public static void resetServer(
			final MongoStorageTestManager manager,
			final String host,
			final String cookieName)
			throws Exception {
		manager.reset(); // destroy any admins that already exist
		//force a config reset
		final IncomingToken admintoken = getAdminToken(manager);
		final Response r = CLI.target(host + "/admin/config/reset").request()
				.cookie(cookieName, admintoken.getToken())
				.post(Entity.entity(null, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("unable to reset server config", r.getStatus(), is(204));
		// destroy the users and config again
		manager.reset();
		insertStandardConfig(manager);
		
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
	private static void insertStandardConfig(final MongoStorageTestManager manager)
			throws Exception {
		final IdentityProvider prov1 = mock(IdentityProvider.class);
		final IdentityProvider prov2 = mock(IdentityProvider.class);
		when(prov1.getProviderName()).thenReturn("prov1");
		when(prov2.getProviderName()).thenReturn("prov2");
		new Authentication(manager.storage, set(prov1, prov2), AuthExternalConfig.SET_DEFAULT,
				false);
	}
	
	public static Path generateTempConfigFile(
			final MongoStorageTestManager manager,
			final String dbName,
			final String cookieName) throws IOException {
		final Ini ini = new Ini();
		final Section sec = ini.add("authserv2");
		sec.add("mongo-host", "localhost:" + manager.mongo.getServerPort());
		sec.add("mongo-db", dbName);
		sec.add("token-cookie-name", cookieName);
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
	
	public static void enableLogin(final String host, final IncomingToken admintoken) {
		setAdmin(host, admintoken, ImmutableMap.of("allowlogin", true));
	}
	
	public static void ignoreIpHeaders(final String host, final IncomingToken admintoken) {
		setAdmin(host, admintoken, ImmutableMap.of("ignoreip", true));
	}

	private static void setAdmin(
			final String host,
			final IncomingToken admintoken,
			final Map<String, Object> json) {
		final Response r = CLI.target(host + "/admin/config").request()
				.header("authorization", admintoken.getToken())
				.post(Entity.json(json));
		assertThat("failed to set config", r.getStatus(), is(204));
	}

	public static void enableProvider(
			final String host,
			final String cookieName,
			final IncomingToken admintoken,
			final String prov) {
		final Form providerform = new Form();
		providerform.param("provider", prov);
		providerform.param("enabled", "true");
		final Response rprov = CLI.target(host + "/admin/config/provider").request()
				.cookie(cookieName, admintoken.getToken())
				.post(Entity.entity(providerform,
						MediaType.APPLICATION_FORM_URLENCODED_TYPE));
		assertThat("failed to set provider config", rprov.getStatus(), is(204));
	}
	
	public static void enableRedirect(
			final String host,
			final IncomingToken adminToken,
			final String redirectURLPrefix) {
		setAdmin(host, adminToken, ImmutableMap.of("allowedloginredirect", redirectURLPrefix));
	}
	
	public static void setLoginCompleteRedirect(
			final String host,
			final IncomingToken adminToken,
			final String loginCompleteRedirectURL) {
		setAdmin(host, adminToken,
				ImmutableMap.of("completeloginredirect", loginCompleteRedirectURL));
	}
	
	public static void setLinkCompleteRedirect(
			final String host,
			final IncomingToken adminToken,
			final String linkCompleteRedirectURL) {
		setAdmin(host, adminToken,
				ImmutableMap.of("completelinkredirect", linkCompleteRedirectURL));
	}
	
	public static void setPostLinkRedirect(
			final String host,
			final IncomingToken adminToken,
			final String postLinkRedirectURL) {
		setAdmin(host, adminToken,
				ImmutableMap.of("postlinkredirect", postLinkRedirectURL));
	}
}
