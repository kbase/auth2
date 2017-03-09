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
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestAuth;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CollectingExternalConfig;
import us.kbase.auth2.lib.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LocalLoginResult;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.ChangePasswordAnswerMatcher;
import us.kbase.test.auth2.lib.AuthenticationTester.TestAuth;

public class AuthenticationPasswordLoginTest {
	
	/* tests anything to do with passwords, including login. */

	@Test
	public void loginStdUser() throws Exception {
		login(true, Collections.emptySet());
	}
	
	@Test
	public void loginAdmin() throws Exception {
		login(false, set(Role.ADMIN));
	}

	private void login(final boolean loginAllowed, final Set<Role> roles) throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		final Clock clock = testauth.clock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		final UUID id = UUID.randomUUID();
		
		final NewToken expectedToken = new NewToken(id, TokenType.LOGIN, "this is a token",
				new UserName("foo"), Instant.ofEpochMilli(4000), 14 * 24 * 3600 * 1000);
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				roles, Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hash, salt, false, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(loginAllowed, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.randomUUID()).thenReturn(UUID.fromString(id.toString()), (UUID) null);
		
		when(rand.getToken()).thenReturn("this is a token");
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(4000), Instant.ofEpochMilli(6000),
				null);
		
		final LocalLoginResult t = auth.localLogin(new UserName("foo"), p);
		
		verify(storage).storeToken(new HashedToken(TokenType.LOGIN, null, t.getToken().getId(),
				"p40z9I2zpElkQqSkhbW6KG3jSgMRFr3ummqjSe7OzOc=", new UserName("foo"),
				Instant.ofEpochMilli(4000), Instant.ofEpochMilli(4000 + 14 * 24 * 3600 * 1000)));
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(6000));
		
		assertClear(p);
		assertThat("incorrect pwd required", t.isPwdResetRequired(), is(false));
		assertThat("incorrect username", t.getUserName(), is((UserName) null));
		assertThat("incorrect token", t.getToken(), is(expectedToken));
	}
	
	@Test
	public void loginResetRequired() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hash, salt, true, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		final LocalLoginResult t = auth.localLogin(new UserName("foo"), p);
		
		assertClear(p);
		assertThat("incorrect pwd required", t.isPwdResetRequired(), is(true));
		assertThat("incorrect username", t.getUserName(), is(new UserName("foo")));
		assertThat("incorrect token", t.getToken(), is((NewToken) null));
	}
	
	@Test
	public void loginNulls() throws Exception {
		final TestAuth testauth = initTestAuth();
		final Authentication auth = testauth.auth;
		
		final Password password = new Password("foobarbazbat".toCharArray());
		failLogin(auth, null, password, new NullPointerException("userName"));
		assertClear(password);
		
		failLogin(auth, new UserName("foo"), null, new NullPointerException("password"));
	}
	
	@Test
	public void loginFailNoUser() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getLocalUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		final Password password = new Password("foobarbazbat".toCharArray());
		failLogin(auth, new UserName("foo"), password,
				new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"Username / password mismatch"));
		assertClear(password);
		
	}
	
	@Test
	public void loginFailBadPwd() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbatch".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hash, salt, false, null));
		
		failLogin(auth, new UserName("foo"), p,
				new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"Username / password mismatch") );
		assertClear(p);
	}
	
	@Test
	public void loginFailNoLoginAllowed() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hash, salt, false, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(false, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		failLogin(auth, new UserName("foo"), p, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Non-admin login is disabled"));
		assertClear(p);
	}
	
	@Test
	public void loginFailDisabled() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null,
				new UserDisabledState("foo", new UserName("foo"), Instant.now()),
				hash, salt, false, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		failLogin(auth, new UserName("foo"), p, new DisabledUserException());
		assertClear(p);
	}
	
	@Test
	public void loginFailCatastrophic() throws Exception {
		// should never happen under normal circumstances
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		final Clock clock = testauth.clock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password p = new Password("foobarbazbat".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		final UUID id = UUID.randomUUID();
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hash, salt, false, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.randomUUID()).thenReturn(UUID.fromString(id.toString()), (UUID) null);
		
		when(rand.getToken()).thenReturn("this is a token");
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(4000), Instant.ofEpochMilli(6000),
				null);
		
		doThrow(new NoSuchUserException("foo")).when(storage)
				.setLastLogin(new UserName("foo"), Instant.ofEpochMilli(6000));
		
		failLogin(auth, new UserName("foo"), p, new AuthStorageException(
				"Something is very broken. User should exist but doesn't: " +
				"50000 No such user: foo"));
		
		verify(storage).storeToken(new HashedToken(TokenType.LOGIN, null,
				UUID.fromString(id.toString()),
				"p40z9I2zpElkQqSkhbW6KG3jSgMRFr3ummqjSe7OzOc=", new UserName("foo"),
				Instant.ofEpochMilli(4000), Instant.ofEpochMilli(4000 + 14 * 24 * 3600 * 1000)));
		assertClear(p);
	}

	private void failLogin(
			final Authentication auth,
			final UserName userName,
			final Password password,
			final Exception e) {
		try {
			auth.localLogin(userName, password);
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
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password pwdold = new Password("foobarbazbat".toCharArray());
		final byte[] saltold = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hashold = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");

		final Password pwdnew = new Password("foobarbazbatbing".toCharArray());
		final byte[] saltnew = new byte[] {1, 1, 3, 4, 5, 6, 7, 8};
		final byte[] hashnew = AuthenticationTester.fromBase64(
				"SL1L2qIybfSLoXzIxUyIpCGR63C3NiROQVZE26GcZo0=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				roles, Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hashold, saltold, false, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(allowLogin, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.generateSalt()).thenReturn(saltnew);
		
		final ChangePasswordAnswerMatcher matcher =
				new ChangePasswordAnswerMatcher(new UserName("foo"), hashnew, saltnew, false);
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage).changePassword(
				new UserName("foo"), hashnew, saltnew, false);
//		
		auth.localPasswordChange(new UserName("foo"), pwdold, pwdnew);
		
		assertClear(pwdold);
		assertClear(pwdnew);
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since changepwd returns null
		 * need to ensure the method was actually called and therefore the matcher above ran
		 */
		verify(storage).changePassword(
				eq(new UserName("foo")), any(byte[].class), any(byte[].class), eq(false));
	}
	
	@Test
	public void changePasswordFailNulls() throws Exception {
		final TestAuth testauth = initTestAuth();
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
	public void changePasswordFailNoUser() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getLocalUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		final Password po = new Password("foobarbazbat".toCharArray());
		final Password pn = new Password("foobarbazbat1".toCharArray());
		
		failChangePassword(auth, new UserName("foo"), po, pn, new AuthenticationException(
				ErrorType.AUTHENTICATION_FAILED, "Username / password mismatch"));
		assertClear(po);
		assertClear(pn);
	}
	
	@Test
	public void changePasswordFailFailBadPwd() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password po = new Password("foobarbazbatch".toCharArray());
		final Password pn = new Password("foobarbazbatch1".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hash, salt, false, null));
		
		failChangePassword(auth, new UserName("foo"), po, pn, new AuthenticationException(
				ErrorType.AUTHENTICATION_FAILED, "Username / password mismatch"));
		assertClear(po);
		assertClear(pn);
	}
	
	@Test
	public void changePasswordFailNoLoginAllowed() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password po = new Password("foobarbazbat".toCharArray());
		final Password pn = new Password("foobarbazbat1".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hash, salt, false, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(false, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		failChangePassword(auth, new UserName("foo"), po, pn, new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Non-admin login is disabled"));
		assertClear(po);
		assertClear(pn);
	}
	
	@Test
	public void changepasswordFailDisabled() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password po = new Password("foobarbazbat".toCharArray());
		final Password pn = new Password("foobarbazbat1".toCharArray());
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null,
				new UserDisabledState("foo", new UserName("foo"), Instant.now()),
				hash, salt, false, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		failChangePassword(auth, new UserName("foo"), po, pn, new DisabledUserException());
		assertClear(po);
		assertClear(pn);
	}
	
	@Test
	public void changePasswordFailCatastrophic() throws Exception {
		// should never happen under normal circumstances
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		AuthenticationTester.setConfigUpdateInterval(auth, 0);
		
		final Password pwdold = new Password("foobarbazbat".toCharArray());
		final byte[] saltold = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hashold = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");

		final Password pwdnew = new Password("foobarbazbatbing".toCharArray());
		final byte[] saltnew = new byte[] {1, 1, 3, 4, 5, 6, 7, 8};
		final byte[] hashnew = AuthenticationTester.fromBase64(
				"SL1L2qIybfSLoXzIxUyIpCGR63C3NiROQVZE26GcZo0=");
		
		when(storage.getLocalUser(new UserName("foo"))).thenReturn(new LocalUser(
				new UserName("foo"), new EmailAddress("f@g.com"), new DisplayName("foo"),
				Collections.emptySet(), Collections.emptySet(),
				Instant.now(), null, new UserDisabledState(), hashold, saltold, false, null));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, null),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.generateSalt()).thenReturn(saltnew);
		
		doThrow(new NoSuchUserException("foo")).when(storage)
				.changePassword(new UserName("foo"), hashnew, saltnew, false);
		
		failChangePassword(auth, new UserName("foo"), pwdold, pwdnew, new AuthStorageException(
				"Sorry, you ceased to exist in the last ~10ms."));
		assertClear(pwdold);
		assertClear(pwdnew);
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
	public void resetPassword() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		final char[] pwd = "foobarbazbat".toCharArray();
		final byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
		final byte[] hash = AuthenticationTester.fromBase64(
				"M0D2KmSM5CoOHojYgbbKQy1UrkLskxrQnWxcaRf3/hs=");
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), Instant.now(), null, new UserDisabledState());
		
		final AuthUser user = new AuthUser(new UserName("foo"), new EmailAddress("f@goo.com"),
				new DisplayName("baz"), Collections.emptySet(), Collections.emptySet(),
				Collections.emptySet(), Instant.now(), null, new UserDisabledState());
		
		final HashedToken token = new HashedToken(TokenType.LOGIN, null, UUID.randomUUID(),
				"wubba", new UserName("admin"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (HashedToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(admin, (AuthUser) null);
		when(storage.getUser(new UserName("foo"))).thenReturn(user, (AuthUser) null);
		
		when(rand.getTemporaryPassword(10)).thenReturn(pwd);
		when(rand.generateSalt()).thenReturn(salt);
		
		final ChangePasswordAnswerMatcher matcher =
				new ChangePasswordAnswerMatcher(new UserName("foo"), hash, salt, true);
		
		// need to check at call time before bytes are cleared
		doAnswer(matcher).when(storage).changePassword(
				new UserName("foo"), hash, salt, true);
	
		final Password p = auth.resetPassword(t, new UserName("foo"));

		assertThat("incorrect password", p.getPassword(), is(pwd));
		assertClear(matcher.savedSalt);
		assertClear(matcher.savedHash);
		
		/* ensure method was called at least once
		 * Usually not necessary when mocking the call, but since changepwd returns null
		 * need to ensure the method was actually called and therefore the matcher above ran
		 */
		verify(storage).changePassword(
				eq(new UserName("foo")), any(byte[].class), any(byte[].class), eq(true));
		
		
	}
}
