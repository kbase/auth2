package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.ViewableUser;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationTestModeUserTest {
	
	/* test clearing test data here because it's as good as anywhere else. */

	private static List<ILoggingEvent> logEvents;
	
	@BeforeClass
	public static void beforeClass() {
		logEvents = AuthenticationTester.setUpSLF4JTestLoggerAppender();
	}
	
	@Before
	public void before() {
		logEvents.clear();
	}
	
	@Test
	public void clearTestData() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		auth.testModeClear();
		
		verify(storage).testModeClear();
	}
	
	@Test
	public void createUser() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final Clock clock = testauth.clockMock;
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		auth.testModeCreateUser(new UserName("foo"), new DisplayName("whee"));
		
		verify(storage).testModeCreateUser(new UserName("foo"), new DisplayName("whee"),
				Instant.ofEpochMilli(10000), Instant.ofEpochMilli(3610000));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, "Created test mode user foo",
				Authentication.class));
	}
	
	@Test
	public void createUserFailInputs() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final Authentication auth = testauth.auth;
		
		final UserName u = new UserName("foo");
		final DisplayName d = new DisplayName("bar");
		
		failCreateUser(auth, null, d, new NullPointerException("userName"));
		failCreateUser(auth, u, null, new NullPointerException("displayName"));
		failCreateUser(auth, UserName.ROOT, d,
				new UnauthorizedException("Cannot create root user"));
	}
	
	@Test
	public void createUserFailUserExists() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final Authentication auth = testauth.auth;
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		
		final UserName u = new UserName("foo");
		final DisplayName d = new DisplayName("bar");
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		doThrow(new UserExistsException("foo")).when(storage).testModeCreateUser(
				u, d, Instant.ofEpochMilli(10000), Instant.ofEpochMilli(3610000));

		failCreateUser(auth, u, d, new UserExistsException("foo"));
	}
	
	@Test
	public void createUserFailNoTestMode() throws Exception {
		failCreateUser(initTestMocks(false).auth, new UserName("u"), new DisplayName("d"),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	private void failCreateUser(
			final Authentication auth,
			final UserName userName,
			final DisplayName displayName,
			final Exception expected) {
		try {
			auth.testModeCreateUser(userName, displayName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getUserByToken() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		when(storage.testModeGetToken(t.getHashedToken())).thenReturn(StoredToken.getBuilder(
				TokenType.AGENT, UUID.randomUUID(), new UserName("whee"))
				.withLifeTime(Instant.ofEpochMilli(10000), 20000)
				.build());
		
		when(storage.testModeGetUser(new UserName("whee"))).thenReturn(AuthUser.getBuilder(
				new UserName("whee"), new DisplayName("d"), Instant.ofEpochMilli(10000)).build());
		
		assertThat("incorrect user", auth.testModeGetUser(t), is(AuthUser.getBuilder(
				new UserName("whee"), new DisplayName("d"), Instant.ofEpochMilli(10000)).build()));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Test mode user whee accessed their user data", Authentication.class));
	}
	
	@Test
	public void getUserByTokenFailNull() throws Exception {
		failGetUserByToken(initTestMocks(true).auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void getUserByTokenFailInvalidToken() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.testModeGetToken(t.getHashedToken()))
				.thenThrow(new NoSuchTokenException("No token"));
		
		failGetUserByToken(auth, t, new InvalidTokenException());
	}
	
	@Test
	public void getUserByTokenFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		when(storage.testModeGetToken(t.getHashedToken())).thenReturn(StoredToken.getBuilder(
				TokenType.AGENT, UUID.randomUUID(), new UserName("whee"))
				.withLifeTime(Instant.ofEpochMilli(10000), 20000)
				.build());
		
		when(storage.testModeGetUser(new UserName("whee")))
				.thenThrow(new NoSuchUserException("whee"));
		
		failGetUserByToken(auth, t, new NoSuchUserException("whee"));
	}
	
	@Test
	public void getUserByTokenFailNoTestMode() throws Exception {
		failGetUserByToken(initTestMocks(false).auth, new IncomingToken("t"),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}

	
	private void failGetUserByToken(
			final Authentication auth,
			final IncomingToken token,
			final Exception expected) {
		try {
			auth.testModeGetUser(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getUserByName() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.testModeGetUser(new UserName("whee1"))).thenReturn(AuthUser.getBuilder(
				new UserName("whee1"), new DisplayName("d"), Instant.ofEpochMilli(10000)).build());
		
		assertThat("incorrect user", auth.testModeGetUser(new UserName("whee1")),
				is(AuthUser.getBuilder(
						new UserName("whee1"), new DisplayName("d"), Instant.ofEpochMilli(10000))
						.build()));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Accessed user data for test mode user whee1 by user name",
				Authentication.class));
	}
	
	@Test
	public void getUserByNameFailNoTestMode() throws Exception {
		failGetUserByName(initTestMocks(false).auth, new UserName("t"),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	@Test
	public void getUserByNameFailNull() throws Exception {
		failGetUserByName(initTestMocks(true).auth, null, new NullPointerException("userName"));
	}
	
	@Test
	public void getUserByNameFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.testModeGetUser(new UserName("whee")))
				.thenThrow(new NoSuchUserException("whee"));
		
		failGetUserByName(auth, new UserName("whee"), new NoSuchUserException("whee"));
	}
	
	private void failGetUserByName(
			final Authentication auth,
			final UserName userName,
			final Exception expected) {
		try {
			auth.testModeGetUser(userName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getOtherUser() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("tok");
		
		when(storage.testModeGetToken(t.getHashedToken())).thenReturn(StoredToken.getBuilder(
				TokenType.SERV, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.testModeGetUser(new UserName("bar"))).thenReturn(AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("d"), Instant.now())
				.withEmailAddress(new EmailAddress("f@p.com")).build());
		
		when(storage.testModeGetUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("g"), Instant.ofEpochMilli(10000))
				.withEmailAddress(new EmailAddress("x@y.com")).build());
		
		final ViewableUser vu = auth.testModeGetUser(t, new UserName("foo"));
		
		assertThat("incorrect user", vu, is(new ViewableUser(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("g"), Instant.ofEpochMilli(10000))
				.withEmailAddress(new EmailAddress("x@y.com")).build(), false)));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Test user bar accessed test user foo's user data", Authentication.class));
	}
	
	@Test
	public void getOtherUserSameUser() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("tok");
		
		when(storage.testModeGetToken(t.getHashedToken())).thenReturn(StoredToken.getBuilder(
				TokenType.SERV, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.testModeGetUser(new UserName("bar"))).thenReturn(AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("d"), Instant.now())
				.withEmailAddress(new EmailAddress("f@p.com")).build());
		
		when(storage.testModeGetUser(new UserName("bar"))).thenReturn(AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("d"), Instant.ofEpochMilli(10000))
				.withEmailAddress(new EmailAddress("f@p.com")).build());
		
		final ViewableUser vu = auth.testModeGetUser(t, new UserName("bar"));
		
		assertThat("incorrect user", vu, is(new ViewableUser(AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("d"), Instant.ofEpochMilli(10000))
				.withEmailAddress(new EmailAddress("f@p.com")).build(), true)));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Test user bar accessed test user bar's user data", Authentication.class));
	}
	
	@Test
	public void getOtherUserFailNulls() throws Exception {
		final Authentication auth = initTestMocks(true).auth;
		
		failGetOtherUser(auth, null, new UserName("u"), new NullPointerException("token"));
		failGetOtherUser(auth, new IncomingToken("t"), null, new NullPointerException("userName"));
	}
	
	@Test
	public void getOtherUserFailNoTestMode() throws Exception {
		failGetOtherUser(initTestMocks(false).auth, new IncomingToken("t"), new UserName("u"),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	@Test
	public void getOtherUserFailInvalidToken() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("tok");
		
		when(storage.testModeGetToken(t.getHashedToken()))
				.thenThrow(new NoSuchTokenException("no token"));
		
		failGetOtherUser(auth, t, new UserName("u"), new InvalidTokenException());
	}
	
	@Test
	public void getOtherUserFailNoTokenUser() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("tok");
		
		when(storage.testModeGetToken(t.getHashedToken())).thenReturn(StoredToken.getBuilder(
				TokenType.SERV, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.testModeGetUser(new UserName("bar")))
				.thenThrow(new NoSuchUserException("bar"));
		
		failGetOtherUser(auth, t, new UserName("u"), new NoSuchUserException("bar"));
	}
	
	@Test
	public void getOtherUserFailNoTargetUser() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("tok");
		
		when(storage.testModeGetToken(t.getHashedToken())).thenReturn(StoredToken.getBuilder(
				TokenType.SERV, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.testModeGetUser(new UserName("bar"))).thenReturn(AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("d"), Instant.now())
				.withEmailAddress(new EmailAddress("f@p.com")).build());
		
		when(storage.testModeGetUser(new UserName("foo")))
				.thenThrow(new NoSuchUserException("foo"));
		
		failGetOtherUser(auth, t, new UserName("foo"), new NoSuchUserException("foo"));
	}
	
	private void failGetOtherUser(
			final Authentication auth,
			final IncomingToken token,
			final UserName userName,
			final Exception expected) {
		try {
			auth.testModeGetUser(token, userName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
}
