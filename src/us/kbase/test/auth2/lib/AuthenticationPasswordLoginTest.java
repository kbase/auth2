package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.isA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.assertClear;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.base.Optional;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LocalLoginResult;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.PasswordMismatchException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.ChangePasswordAnswerMatcher;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationPasswordLoginTest {
	
	/* tests anything to do with passwords, including login. */
	
	private static final TokenCreationContext CTX = TokenCreationContext.getBuilder().build();
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));

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
	public void loginStdUser() throws Exception {
		login(true, Collections.emptySet());
	}
	
	@Test
	public void loginAdmin() throws Exception {
		login(false, set(Role.ADMIN));
	}

	private void login(final boolean loginAllowed, final Set<Role> roles) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		final UUID id = UUID.randomUUID();
		
		final NewToken expectedToken = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(4000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("device")
						.build()).build(),
				"this is a token");
		
		final LocalUser.Builder b = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"));
		for (final Role r: roles) {
			b.withRole(r);
		}
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(b.build());
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(loginAllowed, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.randomUUID()).thenReturn(UUID.fromString(id.toString()), (UUID) null);
		
		when(rand.getToken()).thenReturn("this is a token");
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(4000), Instant.ofEpochMilli(6000),
				null);
		
		final LocalLoginResult t = auth.localLogin(new UserName("foo"), p,
				TokenCreationContext.getBuilder().withNullableDevice("device").build());
		
		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(4000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("device")
						.build()).build(),
				"p40z9I2zpElkQqSkhbW6KG3jSgMRFr3ummqjSe7OzOc=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(6000));
		
		assertClear(p);
		assertClear(hash);
		assertClear(salt);
		assertThat("incorrect pwd required", t.isPwdResetRequired(), is(false));
		assertThat("incorrect username", t.getUserName(), is(Optional.absent()));
		assertThat("incorrect token", t.getToken(), is(Optional.of(expectedToken)));
		
//		assertLogEventsCorrect(logEvents,
//				new LogEvent(Level.INFO, "Logged in user foo with token " + id,
//						Authentication.class));
	}
	
	@Test
	public void loginResetRequired() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		final LocalUser exp = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withForceReset(true).build();
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(exp);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		final LocalLoginResult t = auth.localLogin(new UserName("foo"), p,
				TokenCreationContext.getBuilder().withNullableDevice("device").build());
		
		assertClear(p);
		assertClear(hash);
		assertClear(salt);
		assertThat("incorrect pwd required", t.isPwdResetRequired(), is(true));
		assertThat("incorrect username", t.getUserName(), is(Optional.of(new UserName("foo"))));
		assertThat("incorrect token", t.getToken(), is(Optional.absent()));
		
//		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
//				"Local user foo log in attempt. Password reset is required",
//				Authentication.class));
	}
	
	@Test
	public void loginNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		
		final Password password = new Password("foobarbazbat".toCharArray());
		failLogin(auth, null, password, CTX, new NullPointerException("userName"));
		assertClear(password);
		
		failLogin(auth, new UserName("foo"), null, CTX, new NullPointerException("password"));
		failLogin(auth, new UserName("foo"), password, null, new NullPointerException("tokenCtx"));
	}

	@Test
	public void loginFailNoUserOnGetCreds() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getPasswordHashAndSalt(new UserName("foo")))
				.thenThrow(new NoSuchLocalUserException("foo"));
		
		final Password password = new Password("foobarbazbat".toCharArray());
		failLogin(auth, new UserName("foo"), password, CTX,
				new PasswordMismatchException("foo"));
		assertClear(password);
		
	}
	
	@Test
	public void loginFailNoUserOnGetUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		when(storage.getLocalUser(new UserName("foo")))
				.thenThrow(new NoSuchLocalUserException("foo"));
		
		final Password password = new Password("foobarbazbat".toCharArray());
		failLogin(auth, new UserName("foo"), password, CTX,
				new PasswordMismatchException("foo"));
		assertClear(password);
		assertClear(hash);
		assertClear(salt);
	}
	
	@Test
	public void loginFailBadPwd() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbatch".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		failLogin(auth, new UserName("foo"), p, CTX, new PasswordMismatchException("foo"));
		assertClear(p);
		assertClear(hash);
		assertClear(salt);
	}
	
	@Test
	public void loginFailNoLoginAllowed() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		final LocalUser exp = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com")).build();
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(exp);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(false, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		failLogin(auth, new UserName("foo"), p, CTX,
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"User foo cannot log in because non-admin login is disabled"));
		assertClear(p);
		assertClear(hash);
		assertClear(salt);
	}
	
	@Test
	public void loginFailDisabled() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		final LocalUser exp = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("foo"), Instant.now())).build();
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(exp);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		failLogin(auth, new UserName("foo"), p, CTX, new DisabledUserException("foo"));
		assertClear(p);
		assertClear(hash);
		assertClear(salt);
	}
	
	@Test
	public void loginFailCatastrophic() throws Exception {
		// should never happen under normal circumstances
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		final UUID id = UUID.randomUUID();
		
		final LocalUser exp = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com")).build();
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(exp);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.randomUUID()).thenReturn(UUID.fromString(id.toString()), (UUID) null);
		
		when(rand.getToken()).thenReturn("this is a token");
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(4000), Instant.ofEpochMilli(6000),
				null);
		
		doThrow(new NoSuchUserException("foo")).when(storage)
				.setLastLogin(new UserName("foo"), Instant.ofEpochMilli(6000));
		
		failLogin(auth, new UserName("foo"), p, CTX, new AuthStorageException(
				"Something is very broken. User should exist but doesn't: " +
				"50000 No such user: foo"));
		
		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.fromString(id.toString()), new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(4000), 14 * 24 * 3600 * 1000).build(),
				"p40z9I2zpElkQqSkhbW6KG3jSgMRFr3ummqjSe7OzOc=");
		assertClear(p);
		assertClear(hash);
		assertClear(salt);
	}

	private void failLogin(
			final Authentication auth,
			final UserName userName,
			final Password password,
			final TokenCreationContext ctx,
			final Exception e) {
		try {
			auth.localLogin(userName, password, ctx);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void changePasswordStdUser() throws Exception {
		changePassword(Collections.emptySet(), true);
	}
	
	@Test
	public void changePasswordAdminUser() throws Exception {
		changePassword(set(Role.ADMIN), false);
	}
	
	private void changePassword(Set<Role> roles, boolean allowLogin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password pwdold = new Password("foobarbazbat".toCharArray());
		final byte[] saltold = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hashold = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");

		final Password pwdnew = new Password("foobarbazbatbing".toCharArray());
		final byte[] saltnew = new byte[] {1, 1, 3, 4, 5, 6, 7, 8};
		final byte[] hashnew = AuthenticationTester.fromBase64(
				"SL1L2qIybfSLoXzIxUyIpCGR63C3NiROQVZE26GcZo0=");
		
		final LocalUser.Builder b = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"));
		for (final Role r: roles) {
			b.withRole(r);
		}
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hashold, saltold));
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(b.build());
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(allowLogin, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.generateSalt()).thenReturn(saltnew);
		
		final ChangePasswordAnswerMatcher matcher =
				new ChangePasswordAnswerMatcher(new UserName("foo"), hashnew, saltnew, false);
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage).changePassword(
				eq(new UserName("foo")), any(PasswordHashAndSalt.class), eq(false));

		auth.localPasswordChange(new UserName("foo"), pwdold, pwdnew);
		
		assertClear(pwdold);
		assertClear(pwdnew);
		assertClear(hashold);
		assertClear(saltold);
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since changepwd returns null
		 * need to ensure the method was actually called and therefore the matcher above ran
		 */
		verify(storage).changePassword(
				eq(new UserName("foo")), any(PasswordHashAndSalt.class), eq(false));
		
//		assertLogEventsCorrect(logEvents,
//				new LogEvent(Level.INFO, "Password change for local user foo",
//						Authentication.class));
	}
	
	@Test
	public void changePasswordFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		final UserName u = new UserName("foo");
		
		Password po = new Password("foobarbazbing".toCharArray());
		Password pn = new Password("foobarbazbing1".toCharArray());
		failChangePassword(auth, null, po, pn, new NullPointerException("userName"));
		assertClear(po);
		assertClear(pn);
		
		pn = new Password("foobarbazbing1".toCharArray());
		failChangePassword(auth, u, null, pn, new NullPointerException("password"));
		assertClear(pn);
		
		po = new Password("foobarbazbing".toCharArray());
		failChangePassword(auth, u, po, null, new NullPointerException("pwdnew"));
		assertClear(po);
		
	}
	
	@Test
	public void changePasswordFailNoUserOnGetCreds() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getPasswordHashAndSalt(new UserName("foo")))
				.thenThrow(new NoSuchLocalUserException("foo"));
		
		final Password po = new Password("foobarbazbat".toCharArray());
		final Password pn = new Password("foobarbazbat1".toCharArray());
		
		failChangePassword(auth, new UserName("foo"), po, pn,
				new PasswordMismatchException("foo"));
		assertClear(po);
		assertClear(pn);
	}
	
	@Test
	public void changePasswordFailNoUserOnGetUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final byte[] saltold = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hashold = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hashold, saltold));
		
		when(storage.getLocalUser(new UserName("foo")))
				.thenThrow(new NoSuchLocalUserException("foo"));
		
		final Password po = new Password("foobarbazbat".toCharArray());
		final Password pn = new Password("foobarbazbat1".toCharArray());
		
		failChangePassword(auth, new UserName("foo"), po, pn,
				new PasswordMismatchException("foo"));
		assertClear(po);
		assertClear(pn);
		assertClear(hashold);
		assertClear(saltold);
	}
	
	@Test
	public void changePasswordFailFailBadPwd() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final Password po = new Password("foobarbazbatch".toCharArray());
		final Password pn = new Password("foobarbazbatch1".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		failChangePassword(auth, new UserName("foo"), po, pn,
				new PasswordMismatchException("foo"));
		assertClear(po);
		assertClear(pn);
		assertClear(hash);
		assertClear(salt);
	}
	
	@Test
	public void changePasswordFailIdenticalPwd() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		
		final Password po = new Password("foobarbazbatch".toCharArray());
		final Password pn = new Password("foobarbazbatch".toCharArray());
		
		failChangePassword(auth, new UserName("foo"), po, pn, new IllegalPasswordException(
				"Old and new passwords are identical."));
		assertClear(po);
		assertClear(pn);
	}
	
	@Test
	public void changePasswordFailPwdTooSimple() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		
		final Password po = new Password("foobarbazbatch".toCharArray());
		final Password pn = new Password("open".toCharArray());
		
		failChangePassword(auth, new UserName("foo"), po, pn, new IllegalPasswordException(
				"Password is not strong enough. A word by itself is easy to guess."));
		assertClear(po);
		assertClear(pn);
	}
	
	@Test
	public void changePasswordFailNoLoginAllowed() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password po = new Password("foobarbazbat".toCharArray());
		final Password pn = new Password("foobarbazbat1".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");

		final LocalUser exp = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com")).build();
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(exp);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(false, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		failChangePassword(auth, new UserName("foo"), po, pn, new UnauthorizedException(
				ErrorType.UNAUTHORIZED,
				"User foo cannot log in because non-admin login is disabled"));
		assertClear(po);
		assertClear(pn);
		assertClear(hash);
		assertClear(salt);
	}
	
	@Test
	public void changePasswordFailDisabled() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password po = new Password("foobarbazbat".toCharArray());
		final Password pn = new Password("foobarbazbat1".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");

		final LocalUser exp = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("foo"), Instant.now())).build();

		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hash, salt));
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(exp);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		failChangePassword(auth, new UserName("foo"), po, pn, new DisabledUserException("foo"));
		assertClear(po);
		assertClear(pn);
		assertClear(hash);
		assertClear(salt);
	}
	
	@Test
	public void changePasswordFailCatastrophic() throws Exception {
		// should never happen under normal circumstances
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password pwdold = new Password("foobarbazbat".toCharArray());
		final byte[] saltold = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hashold = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");

		final Password pwdnew = new Password("foobarbazbatbing".toCharArray());
		final byte[] saltnew = new byte[] {1, 1, 3, 4, 5, 6, 7, 8};
		
		when(storage.getPasswordHashAndSalt(new UserName("foo"))).thenReturn(
				new PasswordHashAndSalt(hashold, saltold));
		
		final LocalUser exp = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com")).build();
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(exp);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.generateSalt()).thenReturn(saltnew);
		
		doThrow(new NoSuchUserException("foo")).when(storage).changePassword(
				eq(new UserName("foo")), any(PasswordHashAndSalt.class), eq(false));
		
		failChangePassword(auth, new UserName("foo"), pwdold, pwdnew, new AuthStorageException(
				"Sorry, you ceased to exist in the last ~10ms."));
		assertClear(pwdold);
		assertClear(pwdnew);
		assertClear(hashold);
		assertClear(saltold);
	}
	
	private void failChangePassword(
			final Authentication auth,
			final UserName userName,
			final Password pwdold,
			final Password pwdnew,
			final Exception e) {
		try {
			auth.localPasswordChange(userName, pwdold, pwdnew);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void resetPasswordAdminOnStd() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		resetPassword(admin, user);
	}
	
	@Test
	public void resetPasswordSelf() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.ADMIN).build();
		
		resetPassword(admin, user);
	}
	
	@Test
	public void resetPasswordRootOnCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		resetPassword(admin, user);
	}
	
	@Test
	public void resetPasswordRootOnSelf() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		final AuthUser user = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		resetPassword(admin, user);
	}
	
	@Test
	public void resetPasswordCreateOnAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.ADMIN).build();
		
		resetPassword(admin, user);
	}
	
	@Test
	public void resetPasswordFailLocalUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withIdentity(REMOTE1)
				.build();
		
		failResetPassword(admin, user, new NoSuchUserException(
				"foo is not a local user and has no password"));
		
//		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
//				"Admin admin tried to get standard user foo as a local user",
//				Authentication.class));
	}
	
	@Test
	public void resetPasswordFailCreateOnRoot() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		failResetPassword(admin, user, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Only root can reset root password"));
	}
	
	@Test
	public void resetPasswordFailCreateOnCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		failResetPassword(admin, user, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Cannot reset password of user with create administrator role"));
	}
	
	@Test
	public void resetPasswordFailAdminOnAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.ADMIN).build();
		
		failResetPassword(admin, user, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Cannot reset password of user with administrator role"));
	}
	
	@Test
	public void resetPasswordFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;

		failResetPassword(auth, null, new UserName("foo"), new NullPointerException("token"));
		failResetPassword(auth, new IncomingToken("foo"), null,
				new NullPointerException("userName"));
	}
	
	@Test
	public void resetPasswordExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.resetPassword(token, new UserName("whee"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "reset password for user whee";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN));
	}
	
	@Test
	public void resetPasswordFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		final StoredToken token = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin, (AuthUser) null);
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failResetPassword(auth, t, new UserName("foo"), new NoSuchUserException("foo"));
	}
	
	@Test
	public void resetPasswordFailPasswordGen() throws Exception {
		// mostly to exercise the password clearing code, although there's no way to check the
		// clearing occurred
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		final StoredToken token = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin, (AuthUser) null);
		when(storage.getUser(new UserName("foo"))).thenReturn(user, (AuthUser) null);
		
		when(rand.getTemporaryPassword(10)).thenThrow(new RuntimeException("whee"));
		
		failResetPassword(auth, t, new UserName("foo"), new RuntimeException("whee"));
	}
	
	@Test
	public void resetPasswordFailLateNoSuchUser() throws Exception {
		// mostly to exercise the password clearing code, although there's no way to check the
		// clearing occurred
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		final char[] pwd = "foobarbazbat".toCharArray();
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		final StoredToken token = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin, (AuthUser) null);
		when(storage.getUser(new UserName("foo"))).thenReturn(user, (AuthUser) null);
		
		when(rand.getTemporaryPassword(10)).thenReturn(pwd);
		when(rand.generateSalt()).thenReturn(salt);
		
		doThrow(new NoSuchUserException("foo")).when(storage).changePassword(
				eq(new UserName("foo")), any(PasswordHashAndSalt.class), eq(true));
		
		failResetPassword(auth, t, new UserName("foo"), new NoSuchUserException("foo"));
		assertClear(pwd);
	}
	
	private void failResetPassword(
			final AuthUser admin,
			final AuthUser user,
			final Exception e) {
		try {
			resetPassword(admin, user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failResetPassword(
			final Authentication auth,
			final IncomingToken token,
			final UserName userName,
			final Exception e) {
		try {
			auth.resetPassword(token, userName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

	private void resetPassword(final AuthUser admin, final AuthUser user) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		final char[] pwd = "foobarbazbat".toCharArray();
		final char[] pwd_copy = Arrays.copyOf(pwd, pwd.length);
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
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
		
		when(rand.getTemporaryPassword(10)).thenReturn(pwd);
		when(rand.generateSalt()).thenReturn(salt);
		
		final ChangePasswordAnswerMatcher matcher =
				new ChangePasswordAnswerMatcher(user.getUserName(), hash, salt, true);
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage).changePassword(
				eq(user.getUserName()), any(PasswordHashAndSalt.class), eq(true));
		try {
			final Password p = auth.resetPassword(t, user.getUserName());
	
			assertThat("incorrect password", p.getPassword(), is(pwd_copy));
			assertClear(matcher.savedSalt);
			assertClear(matcher.savedHash);
			assertClear(pwd);
			
			/* ensure method was called at least once
			 * Usually not necessary when mocking the call, but since changepwd returns null
			 * need to ensure the method was actually called and therefore the matcher above ran
			 */
			verify(storage).changePassword(
					eq(user.getUserName()), any(PasswordHashAndSalt.class), eq(true));
			
//			assertLogEventsCorrect(logEvents,
//					new LogEvent(Level.INFO, String.format("Admin %s changed user %s's password",
//							admin.getUserName().getName(), user.getUserName().getName()),
//							Authentication.class));
			
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	@Test
	public void forceResetPasswordAdminOnStd() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		forceResetPassword(admin, user);
	}
	
	@Test
	public void forceResetPasswordSelf() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.ADMIN).build();
		
		forceResetPassword(admin, user);
	}
	
	@Test
	public void forceResetPasswordRootOnCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		forceResetPassword(admin, user);
	}
	
	@Test
	public void forceResetPasswordRootOnSelf() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		final AuthUser user = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		forceResetPassword(admin, user);
	}
	
	@Test
	public void forceResetPasswordCreateOnAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.ADMIN).build();
		
		forceResetPassword(admin, user);
	}
	
	@Test
	public void forceResetPasswordFailLocalUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withIdentity(REMOTE1).build();
		
		failForceResetPassword(admin, user, new NoSuchUserException(
				"foo is not a local user and has no password"));
	}
	
	@Test
	public void forceResetPasswordFailCreateOnRoot() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.build();
		
		failForceResetPassword(admin, user, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Only root can reset root password"));
	}
	
	@Test
	public void forceResetPasswordFailCreateOnCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		failForceResetPassword(admin, user, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Cannot reset password of user with create administrator role"));
	}
	
	@Test
	public void forceResetPasswordFailAdminOnAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		final AuthUser user = AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("baz"), Instant.now())
				.withEmailAddress(new EmailAddress("f@goo.com"))
				.withRole(Role.ADMIN).build();
		
		failForceResetPassword(admin, user, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Cannot reset password of user with administrator role"));
	}
	
	@Test
	public void forceResetPasswordFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;

		failForceResetPassword(auth, null, new UserName("foo"), new NullPointerException("token"));
		failForceResetPassword(auth, new IncomingToken("foo"), null,
				new NullPointerException("userName"));
	}
	
	@Test
	public void forceResetPasswordExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.forceResetPassword(token, new UserName("whee"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "force password reset for user whee";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN));
	}
	
	@Test
	public void forceResetPasswordFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		final StoredToken token = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin, (AuthUser) null);
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failForceResetPassword(auth, t, new UserName("foo"), new NoSuchUserException("foo"));
	}

	private void forceResetPassword(final AuthUser admin, final AuthUser user) throws Exception {
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
			auth.forceResetPassword(t, user.getUserName());
			verify(storage).forcePasswordReset(user.getUserName());
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
		
	}
	
	private void failForceResetPassword(
			final AuthUser admin,
			final AuthUser user,
			final Exception e) {
		try {
			forceResetPassword(admin, user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failForceResetPassword(
			final Authentication auth,
			final IncomingToken token,
			final UserName userName,
			final Exception e) {
		try {
			auth.forceResetPassword(token, userName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void forceResetAllPasswordsCreateAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		forceResetAllPasswords(admin);
	}
	
	@Test
	public void forceResetAllPasswordsRoot() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		forceResetAllPasswords(admin);
	}
	
	@Test
	public void forceResetAllPasswordsExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.forceResetAllPasswords(token);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "force password reset for all users";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.ADMIN));
	}
	
	@Test
	public void forceResetAllPasswordsFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;

		failForceResetAllPasswords(auth, null, new NullPointerException("token"));
	}

	private void forceResetAllPasswords(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		final StoredToken token = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), admin.getUserName())
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin, (AuthUser) null);
		try {
			auth.forceResetAllPasswords(t);
			verify(storage).forcePasswordReset();
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failForceResetAllPasswords(
			final Authentication auth,
			final IncomingToken token,
			final Exception e) {
		try {
			auth.forceResetAllPasswords(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
