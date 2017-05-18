package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;


public class AuthenticationDisableUserTest {
	
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
	public void disableUser() throws Exception {
		disableUser(new UserName("baz"), new UserName("foo"), Role.ADMIN);
		disableUser(new UserName("baz"), new UserName("foo"), Role.CREATE_ADMIN);
		disableUser(UserName.ROOT, new UserName("foo"), Role.ROOT);
		disableUser(UserName.ROOT, UserName.ROOT, Role.ROOT);
	}
	
	@Test
	public void disableUserFailBadRole() throws Exception {
		failDisableUser(new UserName("baz"), UserName.ROOT, Role.ADMIN,
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Only the root user can disable the root account"));
		failDisableUser(new UserName("baz"), UserName.ROOT, Role.CREATE_ADMIN,
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Only the root user can disable the root account"));
	}
	
	@Test
	public void disableUserFailNullsAndEmpties() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		final UserName un = new UserName("foo");
		final String r = "foo";
		
		failDisableUser(auth, null, un, r, new NullPointerException("token"));
		failDisableUser(auth, token, null, r, new NullPointerException("userName"));
		failDisableUser(auth, token, un, null, new MissingParameterException("reason"));
		failDisableUser(auth, token, un, "   \t    ", new MissingParameterException("reason"));
	}
	
	@Test
	public void disableUserFailLongReason() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		final UserName un = new UserName("foo");
		
		failDisableUser(auth, token, un, TestCommon.LONG1001,
				new IllegalParameterException("reason size greater than limit 1000"));
	}
	
	@Test
	public void disableUserExecuteStandardUserCheckingTests() throws Exception {
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.disableAccount(getIncomingToken(), new UserName("whee"), "reason");
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "disable account whee";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN));
	}
	
	@Test
	public void disableUserFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.now())
				.withRole(Role.ADMIN).build())
				.thenReturn(null);
		
		doThrow(new NoSuchUserException("foo")).when(storage)
				.disableAccount(new UserName("foo"), new UserName("baz"), "foo is suxxor");

		failDisableUser(auth, token, new UserName("foo"), "foo is suxxor",
				new NoSuchUserException("foo"));
		
		verify(storage).deleteTokens(new UserName("foo"));
	}

	private void disableUser(final UserName adminName, final UserName userName, final Role role)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), adminName)
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(adminName)).thenReturn(AuthUser.getBuilder(
				adminName, new DisplayName("foo"), Instant.now())
				.withRole(role).build())
				.thenReturn(null);
		
		auth.disableAccount(token, userName, "foo is suxxor");
		
		verify(storage, times(2)).deleteTokens(userName);
		verify(storage).disableAccount(userName, adminName, "foo is suxxor");
	}
	
	public void failDisableUser(
			final UserName adminName,
			final UserName userName,
			final Role role,
			final Exception e) {
		try {
			disableUser(adminName, userName, role);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	public void failDisableUser(
			final Authentication auth,
			final IncomingToken token,
			final UserName name,
			final String reason,
			final Exception e) {
		try {
			auth.disableAccount(token, name, reason);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void enableUser() throws Exception {
		enableUser(new UserName("baz"), new UserName("foo"), Role.ADMIN);
		enableUser(new UserName("baz"), new UserName("foo"), Role.CREATE_ADMIN);
		enableUser(UserName.ROOT, new UserName("foo"), Role.ROOT);
	}
	
	@Test
	public void enableUserFailBadRole() throws Exception {
		failEnableUser(new UserName("baz"), UserName.ROOT, Role.ADMIN,
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"The root user cannot be enabled via this method"));
		failEnableUser(new UserName("baz"), UserName.ROOT, Role.CREATE_ADMIN,
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"The root user cannot be enabled via this method"));
	}
	
	@Test
	public void enableUserFailNullsAndEmpties() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		final UserName un = new UserName("foo");
		
		failEnableUser(auth, null, un, new NullPointerException("token"));
		failEnableUser(auth, token, null, new NullPointerException("userName"));
	}
	
	@Test
	public void enableUserExecuteStandardUserCheckingTests() throws Exception {
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.enableAccount(getIncomingToken(), new UserName("whee"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "enable account whee";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN));
	}
	
	@Test
	public void enableUserFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.now())
				.withRole(Role.ADMIN).build())
				.thenReturn(null);
		
		doThrow(new NoSuchUserException("foo")).when(storage)
				.enableAccount(new UserName("foo"), new UserName("baz"));

		failEnableUser(auth, token, new UserName("foo"),
				new NoSuchUserException("foo"));
	}
	
	private void enableUser(final UserName adminName, final UserName userName, final Role role)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), adminName)
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(adminName)).thenReturn(AuthUser.getBuilder(
				adminName, new DisplayName("foo"), Instant.now())
				.withRole(role).build())
				.thenReturn(null);
		
		auth.enableAccount(token, userName);
		
		verify(storage).enableAccount(userName, adminName);
	}
	
	private void failEnableUser(
			final UserName adminName,
			final UserName userName,
			final Role role,
			final Exception e) {
		try {
			enableUser(adminName, userName, role);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failEnableUser(
			final Authentication auth,
			final IncomingToken token,
			final UserName userName,
			final Exception e) {
		try {
			auth.enableAccount(token, userName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
