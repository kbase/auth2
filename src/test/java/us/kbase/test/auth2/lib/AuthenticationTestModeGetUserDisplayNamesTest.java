package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationTestModeGetUserDisplayNamesTest {
	
	// these tests, much like the method they test, are nearly identical to the standard
	// non-testmode code. I don't like it but don't have a better solution for now.
	
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
	public void getDisplayNamesSet() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("dfoo"));
		expected.put(new UserName("bar"), new DisplayName("dbar"));

		final UUID uuid = UUID.randomUUID();
		when(storage.testModeGetToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, uuid, new UserName("foo"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.testModeGetUserDisplayNames(
				set(new UserName("foo"), new UserName("bar"))))
			.thenReturn(expected);
				
		
		final Map<UserName, DisplayName> disp = auth.testModeGetUserDisplayNames(
				token, set(new UserName("foo"), new UserName("bar")));
		
		assertThat("incorrect display names", disp, is(expected));
		
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "User foo accessed LOGIN test token " + uuid,
						Authentication.class),
				new LogEvent(Level.INFO, "Test mode user foo looked up display names",
						Authentication.class));
	}
	
	@Test
	public void getDisplayNamesEmptySet() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final UUID uuid = UUID.randomUUID();
		when(storage.testModeGetToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, uuid, new UserName("foo"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		
		final Map<UserName, DisplayName> disp = auth.testModeGetUserDisplayNames(
				token, Collections.emptySet());
		
		assertThat("incorrect display names", disp, is(new HashMap<>()));
		
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "User foo accessed LOGIN test token " + uuid,
						Authentication.class));
	}
	
	@Test
	public void getDisplayNamesSetFailNoTestMode() throws Exception {
		failGetDisplayNamesSet(initTestMocks(false).auth, new IncomingToken("foo"), set(),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	@Test
	public void getDisplayNamesSetFailNulls() throws Exception {
		final Authentication auth = initTestMocks(true).auth;
		
		failGetDisplayNamesSet(auth, null, Collections.emptySet(),
				new NullPointerException("token"));
		failGetDisplayNamesSet(auth, new IncomingToken("token"), null,
				new NullPointerException("userNames"));
		failGetDisplayNamesSet(auth, new IncomingToken("token"), set(new UserName("foo"), null),
				new NullPointerException("Null name in userNames"));
	}
	
	@Test
	public void getDisplayNamesSetFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.testModeGetToken(token.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failGetDisplayNamesSet(auth, token, Collections.emptySet(), new InvalidTokenException());
	}
	
	@Test
	public void getDisplayNamesSetFailTooManyUsers() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final Set<UserName> users = new HashSet<>();
		for (int i = 0; i < 10001; i++) {
			users.add(new UserName("u" + i));
		}
		
		when(storage.testModeGetToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.now(), Instant.now()).build());
				
		failGetDisplayNamesSet(auth, token, users,
				new IllegalParameterException("User count exceeds maximum of 10000"));
	}
	
	private void failGetDisplayNamesSet(
			final Authentication auth,
			final IncomingToken token,
			final Set<UserName> names,
			final Exception e) {
		try {
			auth.testModeGetUserDisplayNames(token, names);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
