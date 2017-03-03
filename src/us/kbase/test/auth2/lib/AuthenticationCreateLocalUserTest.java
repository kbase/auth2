package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.assertClear;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestAuth;

import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.NewLocalUser;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LocalUserAnswerMatcher;
import us.kbase.test.auth2.lib.AuthenticationTester.TestAuth;

public class AuthenticationCreateLocalUserTest {

	/* Some of these tests are time sensitive and verify() won't work because the object is
	 * changed after the mocked method is called. Instead use an Answer:
	 * 
	 * http://stackoverflow.com/questions/9085738/can-mockito-verify-parameters-based-on-their-values-at-the-time-of-method-call
	 * 
	 */
	
	@Test
	public void createWithAdminUser() throws Exception {
		
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), new Date(), new Date(), new UserDisabledState());
		
		create(admin);
	}
	
	@Test
	public void createWithCreateAdminUser() throws Exception {
		
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo"), Collections.emptySet(), set(Role.CREATE_ADMIN),
				Collections.emptySet(), new Date(), new Date(), new UserDisabledState());
		
		create(admin);
	}
	
	@Test
	public void createWithRootUser() throws Exception {
		
		final AuthUser admin = new AuthUser(UserName.ROOT, new EmailAddress("f@g.com"),
				new DisplayName("foo"), Collections.emptySet(), set(Role.ROOT),
				Collections.emptySet(), new Date(), new Date(), new UserDisabledState());
		
		create(admin);
	}
	
	@Test
	public void createFailWithoutAdminUser() throws Exception {
		
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo"), Collections.emptySet(), set(Role.SERV_TOKEN),
				Collections.emptySet(), new Date(), new Date(), new UserDisabledState());
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
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		final IncomingToken token = new IncomingToken("foobar");
		final char[] pwdChar = new char [] {'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'a', 'a'};
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"3TdeAz9GffU+pVH/yqNZrlL8e/nyPkM7VJiVmjzc0Cg=");
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(TokenType.LOGIN, null, UUID.randomUUID(), "foobarhash",
						new UserName("admin"), new Date(), new Date()));
		
		when(storage.getUser(new UserName("admin"))).thenReturn(adminUser);
		
		when(rand.getTemporaryPassword(10)).thenReturn(pwdChar);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		final NewLocalUser expected = new NewLocalUser(new UserName("foo"),
				new EmailAddress("f@g.com"), new DisplayName("bar"), hash, salt, true);
		
		final LocalUserAnswerMatcher<NewLocalUser> matcher =
				new LocalUserAnswerMatcher<>(expected);
		
		doAnswer(matcher).when(storage).createLocalUser(any(LocalUser.class));
		
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
		verify(storage).createLocalUser(any());
	}
	
	@Test
	public void createUserFailDisabledUser() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(TokenType.LOGIN, null, UUID.randomUUID(), "foobarhash",
						new UserName("admin"), new Date(), new Date()));
		
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo"), Collections.emptySet(), set(Role.SERV_TOKEN),
				Collections.emptySet(), new Date(), new Date(),
				new UserDisabledState("disabled", new UserName("foo"), new Date()));
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin);
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("admin"));
	}
	
	@Test
	public void createUserFailInvalidToken() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new InvalidTokenException());
	}
	
	@Test
	public void createUserFailNoSuchUser() throws Exception {
		// should never actually happen if db isn't corrupted
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(TokenType.LOGIN, null, UUID.randomUUID(), "foobarhash",
						new UserName("admin"), new Date(), new Date()));
		
		when(storage.getUser(new UserName("admin"))).thenThrow(new NoSuchUserException("whee"));
		
		failCreateLocalUser(auth, token, new UserName("foo"), new DisplayName("bar"),
				new EmailAddress("f@g.com"), new RuntimeException("There seems to be an error " +
						"in the storage system. Token was valid, but no user"));
	}
	
	@Test
	public void createUserFailNulls() throws Exception {
		final TestAuth testauth = initTestAuth();
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
		final TestAuth testauth = initTestAuth();
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
