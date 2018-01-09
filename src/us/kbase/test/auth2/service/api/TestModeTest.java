package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.core.Response;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.ViewableUser;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.api.APIToken;
import us.kbase.auth2.service.api.NewAPIToken;
import us.kbase.auth2.service.api.TestMode;
import us.kbase.auth2.service.api.TestMode.CreateTestUser;
import us.kbase.auth2.service.api.TestMode.CustomRoleCreate;
import us.kbase.auth2.service.api.TestMode.UserRolesSet;
import us.kbase.auth2.service.api.TestMode.CreateTestToken;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.TestCommon;

public class TestModeTest {

	/* Since the TestMode class is only intended to be instantiated by the Jersey framework,
	 * we do not test for null constructor inputs.
	 */
	
	@Test
	public void createUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new UserName("foobar"))).thenReturn(AuthUser.getBuilder(
				new UserName("foobar"), new DisplayName("foo bar"), Instant.ofEpochMilli(10000))
				.build());
		
		final Map<String, Object> au = tm.createTestUser(new CreateTestUser("foobar", "foo bar"));
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "foobar")
				.with("display", "foo bar")
				.with("created", 10000L)
				.with("lastlogin", null)
				.with("roles", Collections.emptyList())
				.with("customroles", Collections.emptySet())
				.with("policyids", Collections.emptyList())
				.with("local", true)
				.with("email", null)
				.with("idents", Collections.emptyList())
				.build();
		
		assertThat("incorrect user", au, is(expected));
		
		verify(auth).testModeCreateUser(new UserName("foobar"), new DisplayName("foo bar"));
	}
	
	@Test
	public void createUserFailNull() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		failCreateUser(tm, null, new MissingParameterException("JSON body missing"));
	}
	
	@Test
	public void createUserFailAddlProps() {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		final CreateTestUser ctu = new CreateTestUser("foo", "bar");
		ctu.setAdditionalProperties("whee", "whoo");
		failCreateUser(tm, ctu, new IllegalParameterException(
				"Unexpected parameters in request: whee"));
	}
	
	@Test
	public void createUserFailRootUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		
		doThrow(new UnauthorizedException("Cannot create root user"))
				.when(auth).testModeCreateUser(
						new UserName("***ROOT***"), new DisplayName("root baby"));
		
		final TestMode tm = new TestMode(auth);
		final CreateTestUser ctu = new CreateTestUser("***ROOT***", "root baby");
		failCreateUser(tm, ctu, new UnauthorizedException(
				"Cannot create root user"));
	}
	
	@Test
	public void createUserFailNoSuchUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new UserName("foobar")))
				.thenThrow(new NoSuchUserException("foobar"));
		
		final CreateTestUser ctu = new CreateTestUser("foobar", "foo bar");
		failCreateUser(tm, ctu, new RuntimeException(
				"Neat, user creation is totally busted: 50000 No such user: foobar"));
	}
	
	private void failCreateUser(
			final TestMode tm,
			final CreateTestUser create,
			final Exception expected) {
		try {
			tm.createTestUser(create);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new UserName("foobar"))).thenReturn(AuthUser.getBuilder(
				new UserName("foobar"), new DisplayName("foo bar"), Instant.ofEpochMilli(10000))
				.build());
		
		final Map<String, Object> au = tm.getTestUser("foobar");
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "foobar")
				.with("display", "foo bar")
				.with("created", 10000L)
				.with("lastlogin", null)
				.with("roles", Collections.emptyList())
				.with("customroles", Collections.emptySet())
				.with("policyids", Collections.emptyList())
				.with("local", true)
				.with("email", null)
				.with("idents", Collections.emptyList())
				.build();
		
		assertThat("incorrect user", au, is(expected));
	}
	
	@Test
	public void getUserFailNull() throws Exception {
		final TestMode tm = new TestMode(mock(Authentication.class));
		failGetUser(tm, null, new MissingParameterException("user name"));
	}
	
	@Test
	public void getUserFailNoSuchUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		when(auth.testModeGetUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		failGetUser(tm, "foo", new NoSuchUserException("foo"));
	}
	
	private void failGetUser(
			final TestMode tm,
			final String userName,
			final Exception expected) {
		try {
			tm.getTestUser(userName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void createTokenNoName() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		final UUID uuid = UUID.randomUUID();
		
		when(auth.testModeCreateToken(new UserName("foo"), null, TokenType.DEV))
				.thenReturn(new NewToken(StoredToken.getBuilder(
						TokenType.DEV, uuid, new UserName("foo"))
						.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(20000))
						.build(),
						"a token"));
		
		when(auth.getSuggestedTokenCacheTime()).thenReturn(30000L);
		
		final NewAPIToken token = tm.createTestToken(new CreateTestToken("foo", null, "Dev"));
		
		final NewAPIToken expected = new NewAPIToken(new NewToken(StoredToken.getBuilder(
				TokenType.DEV, uuid, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(20000))
				.build(),
				"a token"), 30000L);
		
		assertThat("incorrect token", token, is(expected));
	}
	
	@Test
	public void createTokenWithName() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		final UUID uuid = UUID.randomUUID();
		
		when(auth.testModeCreateToken(new UserName("foo"), new TokenName("whee"), TokenType.AGENT))
				.thenReturn(new NewToken(StoredToken.getBuilder(
						TokenType.AGENT, uuid, new UserName("foo"))
						.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(20000))
						.withTokenName(new TokenName("whee"))
						.build(),
						"a token"));
		
		when(auth.getSuggestedTokenCacheTime()).thenReturn(30000L);
		
		final NewAPIToken token = tm.createTestToken(new CreateTestToken("foo", "whee", "Agent"));
		
		final NewAPIToken expected = new NewAPIToken(new NewToken(StoredToken.getBuilder(
				TokenType.AGENT, uuid, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(20000))
				.withTokenName(new TokenName("whee"))
				.build(),
				"a token"), 30000L);
		
		assertThat("incorrect token", token, is(expected));
	}
	
	@Test
	public void createTokenFailNoJson() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		failCreateToken(tm, null, new MissingParameterException("JSON body missing"));
	}
	
	@Test
	public void createTokenFailNulls() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		
		failCreateToken(tm, new CreateTestToken(null, "foo", "Dev"),
				new MissingParameterException("user name"));
		failCreateToken(tm, new CreateTestToken("foo", "  \t  \n ", "Dev"),
				new MissingParameterException("token name"));
		failCreateToken(tm, new CreateTestToken("whee", "foo", null),
				new IllegalParameterException("Invalid token type: null"));
	}
	
	@Test
	public void createTokenFailBadTokenType() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		
		failCreateToken(tm, new CreateTestToken("whee", "foo", "Devv"),
				new IllegalParameterException("Invalid token type: Devv"));
	}
	
	@Test
	public void createTokenFailAddlProps() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		final CreateTestToken create = new CreateTestToken("foo", "bar", "baz");
		create.setAdditionalProperties("whee", "whoo");
		failCreateToken(tm, create, new IllegalParameterException(
				"Unexpected parameters in request: whee"));
	}
	
	private void failCreateToken(
			final TestMode tm,
			final CreateTestToken create,
			final Exception expected) {
		try {
			tm.createTestToken(create);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		final UUID uuid = UUID.randomUUID();
		
		when(auth.testModeGetToken(new IncomingToken("a token"))).thenReturn(
				StoredToken.getBuilder(TokenType.DEV, uuid, new UserName("foo"))
						.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(30000))
						.build());
		
		when(auth.getSuggestedTokenCacheTime()).thenReturn(40000L);
		
		final APIToken token = tm.getTestToken("a token");
		
		final APIToken expected = new APIToken(StoredToken.getBuilder(
				TokenType.DEV, uuid, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(30000))
				.build(),
				40000);
		
		assertThat("incorrect token", token, is(expected));
	}
	
	@Test
	public void getTokenFailNull() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		failGetToken(tm, null, new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getTokenFailInvalidToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetToken(new IncomingToken("a token")))
				.thenThrow(new InvalidTokenException());
		
		failGetToken(tm, "a token", new InvalidTokenException());
	}
	
	private void failGetToken(final TestMode tm, final String token, final Exception expected) {
		try {
			tm.getTestToken(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void me() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new IncomingToken("some token"))).thenReturn(
				AuthUser.getBuilder(new UserName("un"), new DisplayName("dn"),
						Instant.ofEpochMilli(10000))
						.build());
		
		final Map<String, Object> got = tm.getTestMe("some token");
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "un")
				.with("display", "dn")
				.with("created", 10000L)
				.with("lastlogin", null)
				.with("roles", Collections.emptyList())
				.with("customroles", Collections.emptySet())
				.with("policyids", Collections.emptyList())
				.with("local", true)
				.with("email", null)
				.with("idents", Collections.emptyList())
				.build();
		
		assertThat("incorrect user", got, is(expected));
	}
	
	@Test
	public void meFailNoToken() throws Exception {
		final TestMode tm = new TestMode(mock(Authentication.class));
		failMe(tm, null, new NoTokenProvidedException("No user token provided"));
		failMe(tm, "  \t  \n  ", new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void meFailInvalidToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new IncomingToken("some token")))
				.thenThrow(new InvalidTokenException("oh noes"));
		
		failMe(tm, "some token", new InvalidTokenException("oh noes"));
	}
	
	private void failMe(final TestMode tm, final String token, final Exception expected) {
		try {
			tm.getTestMe(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getCustomRolesEmpty() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetCustomRoles()).thenReturn(set());
		
		assertThat("incorrect custom roles", tm.getTestCustomRoles(),
				is(ImmutableMap.of("customroles", Collections.emptyList())));
	}
	
	@Test
	public void getCustomRoles() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetCustomRoles()).thenReturn(
				set(new CustomRole("foo", "bar"), new CustomRole("whee", "whoo")));
		
		assertThat("incorrect custom roles", tm.getTestCustomRoles(),
				is(ImmutableMap.of("customroles", Arrays.asList(
						ImmutableMap.of("id", "foo", "desc", "bar"),
						ImmutableMap.of("id", "whee", "desc", "whoo")))));
	}
	
	@Test
	public void setCustomRole() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		tm.createTestCustomRole(new CustomRoleCreate("foo", "bar"));
		
		verify(auth).testModeSetCustomRole(new CustomRole("foo", "bar"));
	}
	
	@Test
	public void setCustomRoleFailNull() throws Exception {
		final TestMode tm = new TestMode(mock(Authentication.class));
		
		failSetCustomRole(tm, null, new MissingParameterException("JSON body missing"));
		failSetCustomRole(tm, new CustomRoleCreate(null, "foo"),
				new MissingParameterException("custom role id"));
		failSetCustomRole(tm, new CustomRoleCreate("bar", null),
				new MissingParameterException("custom role description"));
	}
	
	@Test
	public void setCustomRoleFailAddlArgs() throws Exception {
		final TestMode tm = new TestMode(mock(Authentication.class));
		final CustomRoleCreate create = new CustomRoleCreate("foo", "bar");
		create.setAdditionalProperties("whee", "whoo");
		
		failSetCustomRole(tm, create, new IllegalParameterException(
				"Unexpected parameters in request: whee"));
	}
	
	@Test
	public void setCustomRoleFailNoTestMode() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		doThrow(new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"))
				.when(auth).testModeSetCustomRole(new CustomRole("foo", "bar"));
		
		failSetCustomRole(tm, new CustomRoleCreate("foo", "bar"),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	private void failSetCustomRole(
			final TestMode tm,
			final CustomRoleCreate create,
			final Exception expected) {
		try {
			tm.createTestCustomRole(create);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void setRolesEmptyNulls() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		tm.setTestModeUserRoles(new UserRolesSet("foo", null, null));
		
		verify(auth).testModeSetRoles(
				new UserName("foo"), Collections.emptySet(), Collections.emptySet());
	}
	
	@Test
	public void setRolesEmptyLists() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		tm.setTestModeUserRoles(new UserRolesSet(
				"foo", Collections.emptyList(), Collections.emptyList()));
		
		verify(auth).testModeSetRoles(
				new UserName("foo"), Collections.emptySet(), Collections.emptySet());
	}
	
	@Test
	public void setRoles() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		tm.setTestModeUserRoles(new UserRolesSet(
				"foo", Arrays.asList("DevToken", "Admin"), Arrays.asList("foo", "bar")));
		
		verify(auth).testModeSetRoles(
				new UserName("foo"), set(Role.DEV_TOKEN, Role.ADMIN), set("foo", "bar"));
	}
	
	@Test
	public void setRolesFailNulls() throws Exception {
		final TestMode tm = new TestMode(mock(Authentication.class));
		
		failSetRoles(tm, null, new MissingParameterException("JSON body missing"));
		failSetRoles(tm, new UserRolesSet(null, null, null),
				new MissingParameterException("user name"));
		failSetRoles(tm, new UserRolesSet("foo", Arrays.asList("Admin", null), null),
				new IllegalParameterException("Null item in roles"));
		failSetRoles(tm, new UserRolesSet("foo", null, Arrays.asList("foo", null)),
				new IllegalParameterException("Null item in custom roles"));
	}
	
	@Test
	public void setRolesFailAddlArgs() throws Exception {
		final TestMode tm = new TestMode(mock(Authentication.class));
		
		final UserRolesSet set = new UserRolesSet("foo", null, null);
		set.setAdditionalProperties("whee", "whoo");
		
		failSetRoles(tm, set, new IllegalParameterException(
				"Unexpected parameters in request: whee"));
	}
	
	@Test
	public void setRolesFailBadRole() throws Exception {
		final TestMode tm = new TestMode(mock(Authentication.class));
		
		final UserRolesSet set = new UserRolesSet(
				"foo", Arrays.asList("Admin", "UberAdmin"), null);
		
		failSetRoles(tm, set, new IllegalParameterException(
				"Invalid role id: UberAdmin"));
	}
	
	private void failSetRoles(
			final TestMode tm,
			final UserRolesSet set,
			final Exception expected) {
		try {
			tm.setTestModeUserRoles(set);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void clear() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		tm.clear();
		
		verify(auth).testModeClear();
	}
	
	@Test
	public void globusToken() throws Exception {
		globusToken("fake", "whee!");
		globusToken("whee!", null);
		globusToken("whee!", "   \t  \n  ");
	}

	private void globusToken(final String xtoken, final String token) throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		final Instant future = Instant.now().plus(20, ChronoUnit.SECONDS);
		final UUID id = UUID.randomUUID();
		
		when(auth.testModeGetToken(new IncomingToken("whee!"))).thenReturn(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("goo"))
				.withLifeTime(Instant.ofEpochMilli(10000L), future)
				.build());
		
		final Map<String, Object> got = tm.getGlobusToken(xtoken, token, "client_credentials");
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("access_token", "whee!")
				.with("client_id", "goo")
				.with("expiry", future.toEpochMilli() / 1000)
				.with("expires_in", 20L)
				.with("issued_on", 10L)
				.with("lifetime", future.minusSeconds(10).toEpochMilli() / 1000)
				.with("refresh_token", "")
				.with("scopes", new LinkedList<String>())
				.with("token_id", id.toString())
				.with("token_type", "Bearer")
				.with("user_name", "goo")
				.build();
		
		assertThat("incorrect token", got, is(expected));
	}
	
	@Test
	public void globusTokenFailNullsAndEmpties() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		failGlobusToken(tm, null, null, "client_credentials",
				new UnauthorizedException(ErrorType.NO_TOKEN));
		failGlobusToken(tm, "  \n   \t  ", "  \n   \t  ", "client_credentials",
				new UnauthorizedException(ErrorType.NO_TOKEN));
	}
	
	@Test
	public void globusTokenFailClientCreds() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		failGlobusToken(tm, "foo", "foo", "clientcredentials",
				new AuthException(ErrorType.UNSUPPORTED_OP,
						"Only client_credentials grant_type supported. Got clientcredentials"));
	}
	
	@Test
	public void globusTokenFailInvalidToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetToken(new IncomingToken("whee")))
				.thenThrow(new InvalidTokenException("no token"));
		
		failGlobusToken(tm, "fake", "whee", "client_credentials",
				new UnauthorizedException(ErrorType.INVALID_TOKEN, "Authentication failed"));
	}
	
	private void failGlobusToken(
			final TestMode tm,
			final String xtoken,
			final String token,
			final String grantType,
			final Exception expected) {
		try {
			tm.getGlobusToken(xtoken, token, grantType);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void globusUser() throws Exception {
		globusUser("fake", "globusauth: yay!");
		globusUser("yay!", null);
	}

	private void globusUser(final String xtoken, final String token) throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new IncomingToken("yay!"), new UserName("foo"))).thenReturn(
				new ViewableUser(AuthUser.getBuilder(
						new UserName("foo"), new DisplayName("bar"), Instant.ofEpochMilli(10000))
							.build(),
						true));
		
		final Map<String, Object> user = tm.getGlobusUser(xtoken, token, "foo");
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
			.with("username", "foo")
			.with("email_validated", false)
			.with("ssh_pubkeys", Collections.emptyList())
			.with("resource_type", "users")
			.with("full_name", "bar")
			.with("organization", null)
			.with("fullname", "bar")
			.with("user_name", "foo")
			.with("email", null)
			.with("custom_fields", Collections.emptyMap())
			.build();
		
		assertThat("incorrect user", user, is(expected));
	}
	
	@Test
	public void globusUserFailAuthHeaders() throws Exception {
		final TestMode tm = new TestMode(mock(Authentication.class));
		
		failGlobusUser(tm, null, null, "foo", new UnauthorizedException(ErrorType.NO_TOKEN));
		failGlobusUser(tm, "  \t   \n  ", null, "foo",
				new UnauthorizedException(ErrorType.NO_TOKEN));
		failGlobusUser(tm, "fake", "header: \t    ", "foo",
				new UnauthorizedException(ErrorType.NO_TOKEN, "Invalid authorization header"));
	}
	
	@Test
	public void globusUserFailInvalidToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new IncomingToken("whoo"), new UserName("bar"))).thenThrow(
				new InvalidTokenException("bleah"));
		
		failGlobusUser(tm, "whoo", null, "bar",
				new UnauthorizedException(ErrorType.INVALID_TOKEN, "Authentication failed."));
	}
	
	private void failGlobusUser(
			final TestMode tm,
			final String xtoken,
			final String token,
			final String user,
			final Exception expected) {
		try {
			tm.getGlobusUser(xtoken, token, user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void dummyKBaseGet() {
		final TestMode tm = new TestMode(mock(Authentication.class));
		
		final Response r = tm.kbaseDummyGetMethod();
		
		assertThat("incorrect code", r.getStatus(), is(401));
		assertThat("incorrect reason", r.getStatusInfo().getReasonPhrase(), is("Unauthorized"));
		assertThat("incorrect entity", r.getEntity(), is(
				"This GET method is just here for compatibility with " +
				"the old java client and does nothing useful. Here's the compatibility part: " +
				"\"user_id\": null"));
	}
}
