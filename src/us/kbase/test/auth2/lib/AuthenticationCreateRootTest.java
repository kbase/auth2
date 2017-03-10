package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.initTestAuth;
import static us.kbase.test.auth2.TestCommon.assertClear;
import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;
import java.util.Date;

import org.junit.Test;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;


import us.kbase.auth2.cryptutils.PasswordCrypt;
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.NewRootUser;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LocalUserAnswerMatcher;
import us.kbase.test.auth2.lib.AuthenticationTester.TestAuth;

public class AuthenticationCreateRootTest {
	
	/* Some of these tests are time sensitive and verify() won't work because the object is
	 * changed after the mocked method is called. Instead use an Answer:
	 * 
	 * http://stackoverflow.com/questions/9085738/can-mockito-verify-parameters-based-on-their-values-at-the-time-of-method-call
	 * 
	 */

	@Test
	public void createRoot() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		final Password pwd = new Password("foobarbazbat".toCharArray());
		
		final byte[] salt = new byte[] {5, 5, 5, 5, 5, 5, 5, 5};
		final byte[] hash = AuthenticationTester.fromBase64(
				"0qnwBgrYXUeUg/rDzEIo9//gTYN3c9yxfsCtE9JkviU=");
		
		final NewRootUser exp = new NewRootUser(EmailAddress.UNKNOWN, new DisplayName("root"),
				hash, salt);
		
		final LocalUserAnswerMatcher<NewRootUser> matcher =
				new LocalUserAnswerMatcher<NewRootUser>(exp);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage).createLocalUser(any(NewRootUser.class));
		
		auth.createRoot(pwd);
		
		final char[] clearpwd = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};
		assertThat("password not cleared", pwd.getPassword(), is(clearpwd));
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since createLU returns null
		 * need to ensure the method was actually called and therefore the RootuserAnswerMatcher
		 * ran
		 */
		verify(storage).createLocalUser(any());
	}

	private class ChangePasswordAnswerMatcher implements Answer<Void> {
		
		private final UserName name;
		private final Password pwd;
		private final byte[] salt;
		private final boolean forceReset;
		private byte[] savedSalt;
		private byte[] savedHash;
		
		public ChangePasswordAnswerMatcher(
				final UserName name,
				final Password pwd,
				final byte[] salt,
				final boolean forceReset) {
			this.name = name;
			this.pwd = pwd;
			this.salt = salt;
			this.forceReset = forceReset;
		}

		@Override
		public Void answer(final InvocationOnMock args) throws Throwable {
			final UserName un = args.getArgument(0);
			savedHash = args.getArgument(1);
			savedSalt = args.getArgument(2);
			final boolean forceReset = args.getArgument(3);
			/* sort of bogus to use the same pwd gen code from the method under test in the test
			 * but the pwd gen code is tested elsewhere and trying to do this manually
			 * would be a major pain.
			 */
			final byte[] hash = new PasswordCrypt().getEncryptedPassword(pwd.getPassword(), salt);
			assertThat("incorrect username", un, is(name));
			assertThat("incorrect forcereset", forceReset, is(this.forceReset));
			assertThat("incorrect hash", savedHash, is(hash));
			assertThat("incorrect salt", savedSalt, is(salt));
			return null;
		}
	}
	
	@Test
	public void resetRootPassword() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		final Password pwd = new Password("foobarbazbat".toCharArray());
		// pwd will be cleared before the method call
		final Password pwd2 = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {5, 5, 5, 5, 5, 5, 5, 5};
		
		final ChangePasswordAnswerMatcher matcher =
				new ChangePasswordAnswerMatcher(UserName.ROOT, pwd2, salt, false);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		doThrow(new UserExistsException(UserName.ROOT.getName()))
				.when(storage).createLocalUser(any(NewRootUser.class));
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage).changePassword(
				eq(UserName.ROOT), any(byte[].class), any(byte[].class), eq(false));
		
		when(storage.getUser(UserName.ROOT)).thenReturn(new NewRootUser(EmailAddress.UNKNOWN,
				new DisplayName("root"), new byte[10], new byte[8]));
		
		auth.createRoot(pwd);
		final char[] clearpwd = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};
		assertThat("password not cleared", pwd.getPassword(), is(clearpwd));
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since changepwd returns null
		 * need to ensure the method was actually called and therefore the matcher ran
		 */
		verify(storage).changePassword(
				eq(UserName.ROOT), any(byte[].class), any(byte[].class), eq(false));
	}
	
	@Test
	public void catastrophicFail() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		when(rand.generateSalt()).thenReturn(new byte[8]);
		
		doThrow(new UserExistsException(UserName.ROOT.getName()))
				.when(storage).createLocalUser(any(NewRootUser.class));
		
		// ignore the change password call, tested elsewhere
		when(storage.getUser(UserName.ROOT)).thenThrow(
				new NoSuchUserException(UserName.ROOT.getName()));
		
		try {
			auth.createRoot(new Password("foobarbazbat".toCharArray()));
			fail("expected exception");
		} catch (RuntimeException e) {
			TestCommon.assertExceptionCorrect(e,
					new RuntimeException("OK. This is really bad. I give up."));
		}
	}
	
	@Test
	public void enableRoot() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		when(rand.generateSalt()).thenReturn(new byte[8]);
		
		doThrow(new UserExistsException(UserName.ROOT.getName()))
				.when(storage).createLocalUser(any(NewRootUser.class));
		
		// ignore the change password call, tested elsewhere
		final LocalUser disabled = new LocalUser(UserName.ROOT, EmailAddress.UNKNOWN,
				new DisplayName("root"), set(Role.ROOT), Collections.emptySet(),
				new Date(), new Date(), new UserDisabledState("foo", UserName.ROOT, new Date()),
				new byte[10], new byte[8], false, null);
		when(storage.getUser(UserName.ROOT)).thenReturn(disabled);
		
		auth.createRoot(new Password("foobarbazbat".toCharArray()));
		
		verify(storage).enableAccount(UserName.ROOT, UserName.ROOT);
	}
	
	@Test
	public void nullPwd() throws Exception {
		try {
			initTestAuth().auth.createRoot(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("pwd"));
		}
	}
	
	@Test
	public void validPwd() throws Exception {
		try {
			initTestAuth().auth.createRoot(new Password("12345".toCharArray()));
			fail("expected exception");
		} catch (IllegalPasswordException got) {
			TestCommon.assertExceptionMessageContains(got, "Password is not strong enough.");
		}
	}
}
