package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;
import static us.kbase.test.auth2.lib.AuthenticationTester.fromBase64;
import static us.kbase.test.auth2.TestCommon.assertClear;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.ChangePasswordAnswerMatcher;
import us.kbase.test.auth2.lib.AuthenticationTester.LocalUserAnswerMatcher;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationCreateRootTest {
	
	/* Some of these tests are time sensitive and verify() won't work because the object is
	 * changed after the mocked method is called. Instead use an Answer:
	 * 
	 * http://stackoverflow.com/questions/9085738/can-mockito-verify-parameters-based-on-their-values-at-the-time-of-method-call
	 * 
	 */
	
	private static List<ILoggingEvent> logEvents;
	
	private final static UUID UID = UUID.randomUUID();
	
	@BeforeClass
	public static void beforeClass() {
		logEvents = AuthenticationTester.setUpSLF4JTestLoggerAppender();
	}
	
	@Before
	public void before() {
		logEvents.clear();
	}
	
	@Test
	public void createRoot() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		final Password pwd = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {5, 5, 5, 5, 5, 5, 5, 5};
		final byte[] hash = AuthenticationTester.fromBase64(
				"0qnwBgrYXUeUg/rDzEIo9//gTYN3c9yxfsCtE9JkviU=");
		final Instant create = Instant.ofEpochMilli(1000000006);
		
		final UUID uid = UUID.randomUUID();
		final LocalUser exp = LocalUser.getLocalUserBuilder(
				UserName.ROOT, uid, new DisplayName("root"), create).build();
		
		final LocalUserAnswerMatcher matcher = new LocalUserAnswerMatcher(
				exp, new PasswordHashAndSalt(hash, salt));
		
		when(rand.generateSalt()).thenReturn(salt);
		
		when(rand.randomUUID()).thenReturn(uid).thenReturn(null);
		
		when(clock.instant()).thenReturn(create);
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage).createLocalUser(
				any(LocalUser.class), any(PasswordHashAndSalt.class));
		
		auth.createRoot(pwd);
		
		assertClear(pwd);
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since createLU returns null
		 * need to ensure the method was actually called and therefore the LocalUserAnswerMatcher
		 * ran
		 */
		verify(storage).createLocalUser(any(), any());
		
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "created root user", Authentication.class));
	}
	
	@Test
	public void resetRootPassword() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		final Password pwd = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {5, 5, 5, 5, 5, 5, 5, 5};
		final byte[] hash = fromBase64("0qnwBgrYXUeUg/rDzEIo9//gTYN3c9yxfsCtE9JkviU=");
		
		final UUID uid = UUID.randomUUID();
		final LocalUser exp = LocalUser.getLocalUserBuilder(
				UserName.ROOT, uid, new DisplayName("root"), Instant.ofEpochMilli(1000))
				.build();
		
		final ChangePasswordAnswerMatcher matcher =
				new ChangePasswordAnswerMatcher(UserName.ROOT, hash, salt, false);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		when(rand.randomUUID()).thenReturn(uid).thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(1000));
		
		doThrow(new UserExistsException(UserName.ROOT.getName()))
				.when(storage).createLocalUser(eq(exp), any(PasswordHashAndSalt.class));
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage)
				.changePassword(eq(UserName.ROOT), any(PasswordHashAndSalt.class), eq(false));
		
		when(storage.getUser(UserName.ROOT)).thenReturn(LocalUser.getLocalUserBuilder(
				UserName.ROOT, uid, new DisplayName("root"), Instant.now())
				.build());
		
		auth.createRoot(pwd);
		
		assertClear(pwd);
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since changepwd returns null
		 * need to ensure the method was actually called and therefore the matcher above ran
		 */
		verify(storage).changePassword(
				eq(UserName.ROOT), any(PasswordHashAndSalt.class), eq(false));
		
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "changed root user password", Authentication.class));
	}
	
	@Test
	public void catastrophicFail() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		when(rand.generateSalt()).thenReturn(new byte[8]);
		
		when(rand.randomUUID()).thenReturn(UID).thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.now());
		
		doThrow(new UserExistsException(UserName.ROOT.getName()))
				.when(storage).createLocalUser(
						any(LocalUser.class), any(PasswordHashAndSalt.class));
		
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
	public void catastrophicFailOnRole() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		when(rand.generateSalt()).thenReturn(new byte[8]);
		
		when(rand.randomUUID()).thenReturn(UID).thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.now());
		
		doThrow(new NoSuchRoleException("some role")).when(storage).createLocalUser(
				any(LocalUser.class), any(PasswordHashAndSalt.class));
		
		try {
			auth.createRoot(new Password("foobarbazbat".toCharArray()));
			fail("expected exception");
		} catch (RuntimeException e) {
			TestCommon.assertExceptionCorrect(e,
					new RuntimeException("didn't supply any roles"));
		}
	}
	
	@Test
	public void enableRoot() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		final Password pwd = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {5, 5, 5, 5, 5, 5, 5, 5};
		final byte[] hash = AuthenticationTester.fromBase64(
				"0qnwBgrYXUeUg/rDzEIo9//gTYN3c9yxfsCtE9JkviU=");
		final Instant create = Instant.ofEpochMilli(160000000);
		
		final ChangePasswordAnswerMatcher matcher = new ChangePasswordAnswerMatcher(
				UserName.ROOT, hash, salt, false);
		
		when(rand.generateSalt()).thenReturn(salt);
		
		final UUID uid = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(uid).thenReturn(null);
		
		when(clock.instant()).thenReturn(create);
		
		doThrow(new UserExistsException(UserName.ROOT.getName()))
				.when(storage).createLocalUser(
						any(LocalUser.class), any(PasswordHashAndSalt.class));
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage)
				.changePassword(eq(UserName.ROOT), any(PasswordHashAndSalt.class), eq(false));
		
		final LocalUser disabled = LocalUser.getLocalUserBuilder(
				UserName.ROOT, uid, new DisplayName("root"), Instant.now())
				.withUserDisabledState(new UserDisabledState("foo", UserName.ROOT, Instant.now()))
				.build();
		
		when(storage.getUser(UserName.ROOT)).thenReturn(disabled);
		
		auth.createRoot(pwd);
		
		assertClear(pwd);
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		
		verify(storage).enableAccount(UserName.ROOT, UserName.ROOT);
		
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "changed root user password", Authentication.class),
				new LogEvent(Level.INFO, "enabled root user", Authentication.class));
	}
	
	@Test
	public void nullPwd() throws Exception {
		try {
			initTestMocks().auth.createRoot(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("pwd"));
		}
	}
	
	@Test
	public void validPwd() throws Exception {
		try {
			initTestMocks().auth.createRoot(new Password("12345".toCharArray()));
			fail("expected exception");
		} catch (IllegalPasswordException got) {
			TestCommon.assertExceptionMessageContains(got, "Password is not strong enough.");
		}
	}
}
