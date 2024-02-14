package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

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
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationUserUpdateTest {
	
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
	public void updateUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
			.withLifeTime(Instant.now(), 10000).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		auth.updateUser(token, UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("bar"))
				.withEmail(new EmailAddress("f@h.com")).build());
		
		verify(storage).updateUser(new UserName("foo"), UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("bar"))
				.withEmail(new EmailAddress("f@h.com")).build());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Updated user details for user foo. Display name: bar Email: f@h.com",
				Authentication.class));
	}
	
	@Test
	public void updateUserDisplayOnly() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
			.withLifeTime(Instant.now(), 10000).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		auth.updateUser(token, UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("bar")).build());
		
		verify(storage).updateUser(new UserName("foo"), UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("bar")).build());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Updated user details for user foo. Display name: bar",
				Authentication.class));
	}
	
	@Test
	public void updateUserEmailOnly() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
			.withLifeTime(Instant.now(), 10000).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		auth.updateUser(token, UserUpdate.getBuilder()
				.withEmail(new EmailAddress("f@h.com")).build());
		
		verify(storage).updateUser(new UserName("foo"), UserUpdate.getBuilder()
				.withEmail(new EmailAddress("f@h.com")).build());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Updated user details for user foo. Email: f@h.com",
				Authentication.class));
	}
	
	@Test
	public void updateUserNoop() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
			.withLifeTime(Instant.now(), 10000).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		auth.updateUser(new IncomingToken("foobar"), UserUpdate.getBuilder().build()); //noop
		
		assertThat("Expected no log events", logEvents.isEmpty(), is(true));
	}
	
	@Test
	public void updateUserFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failUpdateUser(auth, null, UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("foo")).build(),
				new NullPointerException("token"));
		failUpdateUser(auth, new IncomingToken("foo"), null, new NullPointerException("update"));
	}
	
	@Test
	public void updateUserExecuteStandardTokenCheckingTests() throws Exception {
		AuthenticationTester.executeStandardTokenCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.updateUser(getIncomingToken(), UserUpdate.getBuilder().build());
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "update user";
			}
		});
	}
	
	@Test
	public void updateUserFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final StoredToken htoken = StoredToken.getBuilder(
					TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.now(), 10).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		doThrow(new NoSuchUserException("foo")).when(storage).updateUser(new UserName("foo"),
				UserUpdate.getBuilder()
					.withEmail(new EmailAddress("f@h.com")).build());
		
		failUpdateUser(auth, token, UserUpdate.getBuilder()
					.withEmail(new EmailAddress("f@h.com")).build(), new RuntimeException(
							"There seems to be an error in the " +
									"storage system. Token was valid, but no user"));
	}

	private void failUpdateUser(
			final Authentication auth,
			final IncomingToken token,
			final UserUpdate update,
			final Exception e) {
		try {
			auth.updateUser(token, update);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
