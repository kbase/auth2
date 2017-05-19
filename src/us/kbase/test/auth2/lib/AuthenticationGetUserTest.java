package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;

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
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.ViewableUser;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationGetUserTest {
	
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
	public void getUser() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("whee"), new DisplayName("foo"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		getUser(user);
	}
	
	@Test
	public void getUserFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetUser(auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void getUserExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getUser(token);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get user";
			}
		}, set(), set());
	}
	
	private void getUser(final AuthUser user) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");

		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.AGENT, UUID.randomUUID(), user.getUserName())
						.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.getUser(user.getUserName())).thenReturn(user);
		
		try {
			final AuthUser got = auth.getUser(token);
			
			assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
					"User %s accessed their user data", user.getUserName().getName()),
					Authentication.class));
		
			assertThat("incorrect user", got, is(user));
		} catch (Throwable th) {
			if (user.isDisabled()) {
				verify(storage).deleteTokens(user.getUserName());
			} else {
				verify(storage, never()).deleteTokens(user.getUserName());
			}
			throw th;
		}
	}
	
	private void failGetUser(
			final Authentication auth,
			final IncomingToken token,
			final Exception e)
			throws Exception {
		try {
			auth.getUser(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getOtherUserSameUser() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("whee"), new DisplayName("foo"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		getOtherUser(user, user, true);
	}
	
	@Test
	public void getOtherUserDiffUser() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("whee"), new DisplayName("foo1"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		final AuthUser target = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("foo1"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		getOtherUser(user, target, false);
	}
	
	@Test
	public void getOtherUserExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getUser(token, new UserName("foo"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get view user";
			}
		}, set(), set());
	}
	
	@Test
	public void getOtherUserFailDisabledDiffUser() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foo1"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		final AuthUser target = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("foo1"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("baz"), Instant.now())).build();
		
		failGetOtherUser(user, target, new NoSuchUserException("foo"));
	}
	
	@Test
	public void getOtherUserFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetOtherUser(auth, null, new UserName("foo"), new NullPointerException("token"));
		failGetOtherUser(auth, new IncomingToken("foo"), null,
				new NullPointerException("userName"));
	}
	
	@Test
	public void getOtherUserFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		

		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("foo1"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build());
		
		when(storage.getUser(new UserName("bar"))).thenThrow(new NoSuchUserException("bar"));
		
		failGetOtherUser(auth, token, new UserName("bar"), new NoSuchUserException("bar"));
	}

	private void getOtherUser(
			final AuthUser user,
			final AuthUser target,
			final boolean includeEmail)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		

		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), user.getUserName())
						.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.getUser(user.getUserName())).thenReturn(user);
		when(storage.getUser(target.getUserName())).thenReturn(target);
		try {
			final ViewableUser vu = auth.getUser(token, target.getUserName());
			
			assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
					"User %s accessed user %s's user data", user.getUserName().getName(),
					target.getUserName().getName()), Authentication.class));
		
			assertThat("incorrect user", vu, is(new ViewableUser(target, includeEmail)));
		} catch (Throwable th) {
			if (user.isDisabled()) {
				verify(storage).deleteTokens(user.getUserName());
			} else {
				verify(storage, never()).deleteTokens(user.getUserName());
			}
			throw th;
		}
	}
	
	private void failGetOtherUser(
			final AuthUser user,
			final AuthUser target,
			final Exception e) {
		try {
			getOtherUser(user, target, false);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failGetOtherUser(
			final Authentication auth,
			final IncomingToken token,
			final UserName user,
			final Exception e) {
		try {
			auth.getUser(token, user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getUserAsAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		getUserAsAdmin(admin, user);
	}
	
	@Test
	public void getUserAsAdminSelf() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		getUserAsAdmin(admin, user);
	}
	
	
	@Test
	public void getUserAsAdminCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		getUserAsAdmin(admin, user);
	}
	
	@Test
	public void getUserAsAdminRoot() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		getUserAsAdmin(admin, user);
	}
	
	@Test
	public void getUserAsAdminExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getUserAsAdmin(token, new UserName("foobar"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get user foobar as admin";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN));
	}
	
	@Test
	public void getUserAsAdminFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetUserAsAdmin(auth, null, new UserName("foo"), new NullPointerException("token"));
		failGetUserAsAdmin(auth, new IncomingToken("foo"), null,
				new NullPointerException("userName"));
	}
	
	@Test
	public void getUserAsAdminFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		final StoredToken token = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin, (AuthUser) null);
		when(storage.getUser(new UserName("bar"))).thenThrow(new NoSuchUserException("bar"));
		
		failGetUserAsAdmin(auth, t, new UserName("bar"), new NoSuchUserException("bar"));
	}

	private void getUserAsAdmin(final AuthUser admin, final AuthUser user) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		final StoredToken token = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), admin.getUserName())
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		if (user.getUserName().equals(admin.getUserName())) {
			when(storage.getUser(admin.getUserName())).thenReturn(admin, user, (AuthUser) null);
		} else {
			when(storage.getUser(admin.getUserName())).thenReturn(admin, (AuthUser) null);
			when(storage.getUser(user.getUserName())).thenReturn(user, (AuthUser) null);
		}
		
		try {
			final AuthUser gotUser = auth.getUserAsAdmin(t, user.getUserName());
			
			assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
					"Admin %s accessed user %s's user data", admin.getUserName().getName(),
					user.getUserName().getName()), Authentication.class));
		
			assertThat("incorrect user", gotUser, is(user));
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			} else {
				verify(storage, never()).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failGetUserAsAdmin(
			final Authentication auth,
			final IncomingToken token,
			final UserName user,
			final Exception e) {
		try {
			auth.getUserAsAdmin(token, user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
