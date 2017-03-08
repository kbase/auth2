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
import static us.kbase.test.auth2.lib.AuthenticationTester.fromBase64;
import static us.kbase.test.auth2.TestCommon.assertClear;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;

import org.junit.Test;

import com.google.common.base.Optional;

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
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.ChangePasswordAnswerMatcher;
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
		final Clock clock = testauth.clock;
		
		final Password pwd = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {5, 5, 5, 5, 5, 5, 5, 5};
		final byte[] hash = AuthenticationTester.fromBase64(
				"0qnwBgrYXUeUg/rDzEIo9//gTYN3c9yxfsCtE9JkviU=");
		final Instant create = Instant.ofEpochMilli(1000000006);
		
		
		final NewRootUser exp = new NewRootUser(EmailAddress.UNKNOWN, new DisplayName("root"),
				create, hash, salt);
		
		final LocalUserAnswerMatcher<NewRootUser> matcher =
				new LocalUserAnswerMatcher<NewRootUser>(exp);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		when(clock.instant()).thenReturn(create);
		
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
	
	@Test
	public void resetRootPassword() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		final Clock clock = testauth.clock;
		
		final Password pwd = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {5, 5, 5, 5, 5, 5, 5, 5};
		final byte[] hash = fromBase64("0qnwBgrYXUeUg/rDzEIo9//gTYN3c9yxfsCtE9JkviU=");
		
		final NewRootUser exp = new NewRootUser(EmailAddress.UNKNOWN, new DisplayName("root"),
				Instant.ofEpochMilli(1000), hash, salt);
		
		final ChangePasswordAnswerMatcher matcher =
				new ChangePasswordAnswerMatcher(UserName.ROOT, hash, salt, false);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(1000));
		
		doThrow(new UserExistsException(UserName.ROOT.getName()))
				.when(storage).createLocalUser(exp);
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage).changePassword(UserName.ROOT, hash, salt, false);
		
		when(storage.getUser(UserName.ROOT)).thenReturn(new NewRootUser(EmailAddress.UNKNOWN,
				new DisplayName("root"), Instant.now(), new byte[10], new byte[8]));
		
		auth.createRoot(pwd);
		
		assertClear(pwd);
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since changepwd returns null
		 * need to ensure the method was actually called and therefore the matcher above ran
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
		final Clock clock = testauth.clock;
		
		when(rand.generateSalt()).thenReturn(new byte[8]);
		
		when(clock.instant()).thenReturn(Instant.now());
		
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
		final Clock clock = testauth.clock;
		
		when(rand.generateSalt()).thenReturn(new byte[8]);
		
		when(clock.instant()).thenReturn(Instant.now());
		
		doThrow(new UserExistsException(UserName.ROOT.getName()))
				.when(storage).createLocalUser(any(NewRootUser.class));
		
		// ignore the change password call, tested elsewhere
		final LocalUser disabled = new LocalUser(UserName.ROOT, EmailAddress.UNKNOWN,
				new DisplayName("root"), set(Role.ROOT), Collections.emptySet(),
				Instant.now(), Optional.of(Instant.now()),
				new UserDisabledState("foo", UserName.ROOT, Instant.now()),
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
}
