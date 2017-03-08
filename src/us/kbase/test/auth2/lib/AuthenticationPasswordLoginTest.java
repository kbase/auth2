package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
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
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CollectingExternalConfig;
import us.kbase.auth2.lib.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LocalLoginResult;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UUIDGenerator;
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
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
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
		final UUIDGenerator uuidGen = testauth.uuid;
		
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
		
		when(uuidGen.randomUUID()).thenReturn(UUID.fromString(id.toString()), (UUID) null);
		
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
	public void nulls() throws Exception {
		final TestAuth testauth = initTestAuth();
		final Authentication auth = testauth.auth;
		failLogin(auth, null, new Password("foobarbazbat".toCharArray()),
				new NullPointerException("userName"));
		failLogin(auth, new UserName("foo"), null, new NullPointerException("password"));
	}
	
	@Test
	public void loginFailNoUser() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getLocalUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failLogin(auth, new UserName("foo"), new Password("foobarbazbat".toCharArray()),
				new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
						"Username / password mismatch"));
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
	}
	
	@Test
	public void loginFailCatastrophic() throws Exception {
		// should never happen under normal circumstances
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		final Clock clock = testauth.clock;
		final UUIDGenerator uuidGen = testauth.uuid;
		
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
		
		when(uuidGen.randomUUID()).thenReturn(UUID.fromString(id.toString()), (UUID) null);
		
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
	
}
