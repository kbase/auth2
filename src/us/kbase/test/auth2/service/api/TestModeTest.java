package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.api.NewAPIToken;
import us.kbase.auth2.service.api.TestMode;
import us.kbase.auth2.service.api.TestMode.CreateTestUser;
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
}
