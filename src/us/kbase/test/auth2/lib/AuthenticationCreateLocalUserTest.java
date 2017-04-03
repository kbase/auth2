package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.assertClear;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

import org.junit.Test;


import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LocalUserAnswerMatcher;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationCreateLocalUserTest {

	/* Some of these tests are time sensitive and verify() won't work because the object is
	 * changed after the mocked method is called. Instead use an Answer:
	 * 
	 * http://stackoverflow.com/questions/9085738/can-mockito-verify-parameters-based-on-their-values-at-the-time-of-method-call
	 * 
	 */
	
	private final static Instant NOW = Instant.now();
	
	@Test
	public void createWithAdminUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foo"), NOW)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
				
		create(admin);
	}
	
	@Test
	public void createWithCreateAdminUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foo"), NOW)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		create(admin);
	}
	
	@Test
	public void createWithRootUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("foo"), NOW)
				.withEmailAddress(new EmailAddress("f@g.com")).build();
		
		create(admin);
	}
	
	@Test
	public void createFailWithoutAdminUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foo"), NOW)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		createFail(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	private void createFail(final AuthUser admin, final Exception expected) {
		try {
			create(admin);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}

	private void create(final AuthUser adminUser) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		final IncomingToken token = new IncomingToken("foobar");
		final char[] pwdChar = new char [] {'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'a', 'a'};
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"3TdeAz9GffU+pVH/yqNZrlL8e/nyPkM7VJiVmjzc0Cg=");
		final Instant create = Instant.ofEpochSecond(1000);
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(StoredToken.getBuilder(
						TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(NOW, NOW).build());
		
		when(storage.getUser(new UserName("admin"))).thenReturn(adminUser);
		
		when(rand.getTemporaryPassword(10)).thenReturn(pwdChar);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		when(clock.instant()).thenReturn(create);
		
		final LocalUser expected = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), create)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withForceReset(true).build();
		
		final LocalUserAnswerMatcher matcher = new LocalUserAnswerMatcher(
				expected, new PasswordHashAndSalt(hash, salt));
		
		doAnswer(matcher).when(storage).createLocalUser(
				any(LocalUser.class), any(PasswordHashAndSalt.class));
		
		final Password pwd = auth.createLocalUser(
				token, new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"));
		assertThat("incorrect pwd", pwd.getPassword(), is(pwdChar));
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since createLU returns null
		 * need to ensure the method was actually called and therefore the RootuserAnswerMatcher
		 * ran
		 */
		verify(storage).createLocalUser(any(), any());
	}
	
	@Test
	public void createFailUserExists() throws Exception {
		// mostly for exercising the pwd, hash, and salt clears
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		final IncomingToken token = new IncomingToken("foobar");
		final char[] pwdChar = new char [] {'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'a', 'a'};
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final Instant create = Instant.ofEpochSecond(1000);
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(StoredToken.getBuilder(
						TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(NOW, NOW).build());
		
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foo"), NOW)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin);
		
		when(rand.getTemporaryPassword(10)).thenReturn(pwdChar);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		when(clock.instant()).thenReturn(create);
		
		doThrow(new UserExistsException("foo")).when(storage)
				.createLocalUser(any(LocalUser.class), any(PasswordHashAndSalt.class));
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new UserExistsException("foo"));
	}
	
	@Test
	public void createFailIllegalRole() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		final IncomingToken token = new IncomingToken("foobar");
		final char[] pwdChar = new char [] {'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'a', 'a'};
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final Instant create = Instant.ofEpochSecond(1000);
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(StoredToken.getBuilder(
						TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(NOW, NOW).build());
		
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foo"), NOW)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin);
		
		when(rand.getTemporaryPassword(10)).thenReturn(pwdChar);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		when(clock.instant()).thenReturn(create);
		
		doThrow(new NoSuchRoleException("foo")).when(storage)
				.createLocalUser(any(LocalUser.class), any(PasswordHashAndSalt.class));
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new RuntimeException("didn't supply any roles"));
	}
	
	@Test
	public void createFailRuntimeOnGetPwd() throws Exception {
		// mostly for exercising the pwd, hash, and salt clears
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(StoredToken.getBuilder(
						TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(NOW, NOW).build());

		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foo"), NOW)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin);
		
		when(rand.getTemporaryPassword(10)).thenThrow(new RuntimeException("booga"));
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new RuntimeException("booga"));
	}
	
	@Test
	public void createUserFailDisabledUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(StoredToken.getBuilder(
						TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(NOW, NOW).build());
		
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foo"), NOW)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN)
				.withUserDisabledState(
						new UserDisabledState("disabled", new UserName("foo"), Instant.now()))
				.build();
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin);
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("admin"));
	}
	
	@Test
	public void createUserFailInvalidToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new InvalidTokenException());
	}
	
	@Test
	public void createUserFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.AGENT, UUID.randomUUID(), new UserName("bar"))
						.withLifeTime(NOW, NOW).build(),
				StoredToken.getBuilder(TokenType.DEV, UUID.randomUUID(), new UserName("bar"))
						.withLifeTime(NOW, NOW).build(),
				StoredToken.getBuilder(TokenType.SERV, UUID.randomUUID(), new UserName("bar"))
						.withLifeTime(NOW, NOW).build(),
				null);
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Agent tokens are not allowed for this operation"));
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Developer tokens are not allowed for this operation"));
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void createUserFailNoSuchUser() throws Exception {
		// should never actually happen if db isn't corrupted
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(StoredToken.getBuilder(
						TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(NOW, NOW).build());
		
		when(storage.getUser(new UserName("admin"))).thenThrow(new NoSuchUserException("whee"));
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new RuntimeException("There seems to be an error " +
						"in the storage system. Token was valid, but no user"));
	}
	
	@Test
	public void createUserFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		
		failCreateLocalUser(auth, null, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new NullPointerException("token"));
		
		failCreateLocalUser(auth, new IncomingToken("whee"), null,
				new DisplayName("bar"), new EmailAddress("f@g.com"),
				new NullPointerException("userName"));
		
		failCreateLocalUser(auth, new IncomingToken("whee"), new UserName("foo"),
				null, new EmailAddress("f@g.com"),
				new NullPointerException("displayName"));
		
		failCreateLocalUser(auth, new IncomingToken("whee"), new UserName("foo"),
				new DisplayName("bar"), null,
				new NullPointerException("email"));
	}
	
	@Test
	public void createRootUserFail() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		
		failCreateLocalUser(auth, null, UserName.ROOT, new DisplayName("bar"),
				new EmailAddress("f@g.com"), new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Cannot create ROOT user"));
	}
	
	public void failCreateLocalUser(
			final Authentication auth,
			final IncomingToken token,
			final UserName userName,
			final DisplayName display,
			final EmailAddress email,
			final Exception e) {
		try {
			auth.createLocalUser(token, userName, display, email);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}
