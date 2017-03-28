package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;


public class AuthenticationDisableUserTest {
	
	@Test
	public void disableUser() throws Exception {
		disableUser(new UserName("baz"), new UserName("foo"), Role.ADMIN);
		disableUser(new UserName("baz"), new UserName("foo"), Role.CREATE_ADMIN);
		disableUser(UserName.ROOT, new UserName("foo"), Role.ROOT);
		disableUser(UserName.ROOT, UserName.ROOT, Role.ROOT);
	}
	
	@Test
	public void disableUserFailBadRole() throws Exception {
		failDisableUser(new UserName("baz"), new UserName("foo"), Role.DEV_TOKEN,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
		failDisableUser(new UserName("baz"), new UserName("foo"), Role.SERV_TOKEN,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
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
	public void disableUserFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("user");
		
		when(storage.getToken(token.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failDisableUser(auth, token, new UserName("foo"), "r", new InvalidTokenException());
	}
	
	@Test
	public void disableUserFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.AGENT, UUID.randomUUID(), new UserName("f"))
						.withLifeTime(Instant.now(), 0).build(),
				StoredToken.getBuilder(TokenType.DEV, UUID.randomUUID(), new UserName("f"))
						.withLifeTime(Instant.now(), 0).build(),
				StoredToken.getBuilder(TokenType.SERV, UUID.randomUUID(), new UserName("f"))
						.withLifeTime(Instant.now(), 0).build(),
				null);
		
		failDisableUser(auth, token, new UserName("foo"), "r", new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failDisableUser(auth, token, new UserName("foo"), "r", new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failDisableUser(auth, token, new UserName("foo"), "r", new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void disableUserFailNoUserForToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failDisableUser(auth, token, new UserName("foo"), "r", new RuntimeException(
				"There seems to be an error in the storage system. Token was valid, but no user"));
	}
	
	@Test
	public void disableUserFailDisabledUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now())
				.withUserDisabledState(
						new UserDisabledState("f", new UserName("b"), Instant.now())).build());
		
		failDisableUser(auth, token, new UserName("foo"), "r", new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("foo"));
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
		failEnableUser(new UserName("baz"), new UserName("foo"), Role.DEV_TOKEN,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
		failEnableUser(new UserName("baz"), new UserName("foo"), Role.SERV_TOKEN,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
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
	public void enableUserFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("user");
		
		when(storage.getToken(token.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failEnableUser(auth, token, new UserName("foo"), new InvalidTokenException());
	}
	
	@Test
	public void enableUserFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.AGENT, UUID.randomUUID(), new UserName("f"))
						.withLifeTime(Instant.now(), 0).build(),
				StoredToken.getBuilder(TokenType.DEV, UUID.randomUUID(), new UserName("f"))
						.withLifeTime(Instant.now(), 0).build(),
				StoredToken.getBuilder(TokenType.SERV, UUID.randomUUID(), new UserName("f"))
						.withLifeTime(Instant.now(), 0).build(),
				null);
		
		failEnableUser(auth, token, new UserName("foo"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failEnableUser(auth, token, new UserName("foo"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failEnableUser(auth, token, new UserName("foo"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void enableUserFailNoUserForToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failEnableUser(auth, token, new UserName("foo"), new RuntimeException(
				"There seems to be an error in the storage system. Token was valid, but no user"));
	}
	
	@Test
	public void enableUserFailDisabledUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now())
				.withUserDisabledState(
						new UserDisabledState("f", new UserName("b"), Instant.now())).build());
		
		failEnableUser(auth, token, new UserName("foo"), new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("foo"));
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
