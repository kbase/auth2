package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationTestModeTokenTest {
	
	private static final UUID UID = UUID.randomUUID();
	
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
	public void createTokenWithoutName() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final Clock clock = testauth.clockMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		final UUID id = UUID.randomUUID();
		
		when(storage.testModeGetUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("d"), Instant.now()).build());
		when(rand.randomUUID()).thenReturn(id);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		when(rand.getToken()).thenReturn("whee");
		
		final NewToken nt = auth.testModeCreateToken(new UserName("foo"), null, TokenType.AGENT);
		
		assertThat("incorrect token", nt, is(new NewToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(3610000))
				.build(),
				"whee")));
		
		verify(storage).testModeStoreToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(3610000))
				.build(),
				IncomingToken.hash("whee"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Created test mode AGENT token %s for user foo", id),
				Authentication.class));
	}
	
	@Test
	public void createTokenWithName() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final Clock clock = testauth.clockMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		final UUID id = UUID.randomUUID();
		
		when(storage.testModeGetUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("d"), Instant.now()).build());
		when(rand.randomUUID()).thenReturn(id);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		when(rand.getToken()).thenReturn("whee");
		
		final NewToken nt = auth.testModeCreateToken(
				new UserName("foo"), new TokenName("tok"), TokenType.SERV);
		
		assertThat("incorrect token", nt, is(new NewToken(StoredToken.getBuilder(
				TokenType.SERV, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(3610000))
				.withTokenName(new TokenName("tok"))
				.build(),
				"whee")));
		
		verify(storage).testModeStoreToken(StoredToken.getBuilder(
				TokenType.SERV, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(3610000))
				.withTokenName(new TokenName("tok"))
				.build(),
				IncomingToken.hash("whee"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Created test mode SERV token %s for user foo", id),
				Authentication.class));
	}
	
	@Test
	public void createTokenFailNulls() throws Exception {
		final Authentication auth = initTestMocks(true).auth;
		failCreateToken(auth, null, TokenType.DEV, new NullPointerException("userName"));
		failCreateToken(auth, new UserName("u"), null, new NullPointerException("tokenType"));
	}
	
	@Test
	public void createTokenFailNoTestMode() throws Exception {
		failCreateToken(initTestMocks(false).auth, new UserName("u"), TokenType.DEV,
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	@Test
	public void createTokenFailNoUser() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.testModeGetUser(new UserName("foo")))
				.thenThrow(new NoSuchUserException("foo"));
		
		failCreateToken(auth, new UserName("foo"), TokenType.AGENT,
				new NoSuchUserException("foo"));
	}
	
	private void failCreateToken(
			final Authentication auth,
			final UserName userName,
			final TokenType tokenType,
			final Exception expected) {
		try {
			auth.testModeCreateToken(userName, null, tokenType);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getToken() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foo");
		final UUID id = UUID.randomUUID();
		
		when(storage.testModeGetToken(t.getHashedToken())).thenReturn(StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
				.withLifeTime(Instant.ofEpochMilli(10000), 30000)
				.build());
		
		final StoredToken st = auth.testModeGetToken(t);
		
		assertThat("incorrect token", st, is(StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(40000))
				.build()));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"User bar accessed LOGIN test token %s", id), Authentication.class));
	}
	
	@Test
	public void getTokenFailNull() throws Exception {
		failGetToken(initTestMocks(true).auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void getTokenFailNoTestMode() throws Exception {
		failGetToken(initTestMocks(false).auth, new IncomingToken("foo"),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	@Test
	public void getTokenFailInvalidToken() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("bar");
		
		when(storage.testModeGetToken(t.getHashedToken()))
				.thenThrow(new NoSuchTokenException("no token"));
		
		failGetToken(auth, t, new InvalidTokenException());
	}

	private void failGetToken(
			final Authentication auth,
			final IncomingToken token,
			final Exception expected) {
		try {
			auth.testModeGetToken(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
}
