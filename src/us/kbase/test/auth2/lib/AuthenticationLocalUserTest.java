package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.isA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.assertClear;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestAuth;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import us.kbase.auth2.cryptutils.PasswordCrypt;
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
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestAuth;

public class AuthenticationLocalUserTest {

	/* Tests local user creation, login, retrieval, password reset */
	
	/* Some of these tests are time sensitive and verify() won't work because the object is
	 * changed after the mocked method is called. Instead use an Answer:
	 * 
	 * http://stackoverflow.com/questions/9085738/can-mockito-verify-parameters-based-on-their-values-at-the-time-of-method-call
	 * 
	 */
	
	/* The pwd hash is checked by regenerating from the provided salt.
	 * The created date is checked to be within 500 ms of the current time.
	 */
	private class LocalUserAnswerMatcher implements Answer<Void> {

		private final LocalUser user;
		public byte[] savedSalt;
		public byte[] savedHash;
		
		
		public LocalUserAnswerMatcher(final LocalUser user) {
			this.user = user;
		}
		
		@Override
		public Void answer(final InvocationOnMock inv) throws Throwable {
			final LocalUser user = inv.getArgument(0);
			savedSalt = user.getSalt();
			savedHash = user.getPasswordHash();

			/* omg you bad person */
			final Field f = AuthUser.class.getDeclaredField("created");
			f.setAccessible(true);
			f.set(user, this.user.getCreated().getTime());
			assertThat("local user does not match. Created date was not checked.", user,
					is(this.user));
			// may want to consider mocking date generation
			assertThat("creation date not within 500ms",
					TestCommon.dateWithin(user.getCreated(), 500), is(true));
			return null;
		}
		
	}
	
	@Test
	public void create() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		final IncomingToken token = new IncomingToken("foobar");
		final char[] pwdChar = new char [] {'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'a', 'a'};
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		
		/* sort of bogus to use the same pwd gen code from the method under test in the test
		 * but the pwd gen code is tested elsewhere and trying to do this manually
		 * would be a major pain.
		 */
		final byte[] hash = new PasswordCrypt().getEncryptedPassword(pwdChar, salt);
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(TokenType.LOGIN, null, UUID.randomUUID(), "foobarhash",
						new UserName("admin"), new Date(), new Date()));
		
		when(storage.getUser(new UserName("admin")))
				.thenReturn(new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
						new DisplayName("foo"), Collections.emptySet(), set(Role.ADMIN),
						Collections.emptySet(), new Date(), new Date(), new UserDisabledState()));
		
		when(rand.getTemporaryPassword(10)).thenReturn(pwdChar);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		final NewLocalUser expected = new NewLocalUser(new UserName("foo"),
				new EmailAddress("f@g.com"), new DisplayName("bar"), hash, salt, true);
		
		final LocalUserAnswerMatcher matcher = new LocalUserAnswerMatcher(expected);
		
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
	
}
