package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TokenName;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationTokenTest {
	
	/* tests token get, create, revoke, and getBare. */
	
	private static final StoredToken TOKEN1;
	private static final StoredToken TOKEN2;
	static {
		try {
		TOKEN1 = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.absent(), new UserName("foo"), Instant.ofEpochMilli(3000),
				Instant.ofEpochMilli(4000));
		TOKEN2 = new StoredToken(UUID.randomUUID(), TokenType.DEV,
				Optional.of(new TokenName("baz")), new UserName("foo"), Instant.ofEpochMilli(5000),
				Instant.ofEpochMilli(6000));
		} catch (Exception e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}
	
	@Test
	public void getToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final Instant now = Instant.now();
		final UUID id = UUID.randomUUID();
		
		final StoredToken expected = new StoredToken(id, TokenType.LOGIN, Optional.absent(),
				new UserName("foo"), now, now);
		
		when(storage.getToken(t.getHashedToken())).thenReturn(expected);
		
		final StoredToken ht = auth.getToken(t);
		assertThat("incorrect token", ht, is(new StoredToken(id, TokenType.LOGIN,
				Optional.absent(), new UserName("foo"), now, now)));
	}
	
	@Test
	public void getTokenFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetToken(auth, null, new NullPointerException("token"));
	}

	
	@Test
	public void getTokenFailNoSuchToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failGetToken(auth, t, new InvalidTokenException());
	}

	private void failGetToken(
			final Authentication auth,
			final IncomingToken t,
			final Exception e) {
		try {
			auth.getToken(t);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTokens() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final Instant now = Instant.now();
		final UUID id = UUID.randomUUID();
		
		final StoredToken expected = new StoredToken(id, TokenType.LOGIN, null,
				new UserName("foo"), now, now);
		
		when(storage.getToken(t.getHashedToken())).thenReturn(expected, (StoredToken) null);
		
		when(storage.getTokens(new UserName("foo"))).thenReturn(set(TOKEN1, TOKEN2));
		
		final TokenSet ts = auth.getTokens(t);
		assertThat("incorrect token set", ts, is(new TokenSet(expected, set(TOKEN2, TOKEN1))));
	}
	
	@Test
	public void getTokensFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetTokens(auth, null, new NullPointerException("token"));
	}

	
	@Test
	public void getTokensFailNoSuchToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failGetTokens(auth, t, new InvalidTokenException());
	}
	
	@Test
	public void getTokensFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				new StoredToken(UUID.randomUUID(), TokenType.AGENT, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.DEV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.SERV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failGetTokens(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Agent tokens are not allowed for this operation"));
		failGetTokens(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Developer tokens are not allowed for this operation"));
		failGetTokens(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Service tokens are not allowed for this operation"));
	}
	
	private void failGetTokens(
			final Authentication auth,
			final IncomingToken t,
			final Exception e) {
		try {
			auth.getTokens(t);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTokensUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		getTokensUser(admin);
	}
	
	@Test
	public void getTokensUserFailNonAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.DEV_TOKEN).build();
		
		failGetTokensUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void getTokensUserFailCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		failGetTokensUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void getTokensUserFailRoot() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		failGetTokensUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void getTokensUserFailDisabled() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.DEV_TOKEN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("baz"), Instant.now())).build();
		
		failGetTokensUser(admin, new DisabledUserException());
	}
	
	@Test
	public void getTokensUserFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		
		failGetTokensUser(auth, null, new UserName("foo"), new NullPointerException("token"));
		failGetTokensUser(auth, new IncomingToken("foo"), null,
				new NullPointerException("userName"));
	}
	
	@Test
	public void getTokensUserFailInvalidToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failGetTokensUser(auth, t, new UserName("bar"), new InvalidTokenException());
	}
	
	@Test
	public void getTokensUserFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				new StoredToken(UUID.randomUUID(), TokenType.AGENT, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.DEV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.SERV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failGetTokensUser(auth, token, new UserName("bar"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failGetTokensUser(auth, token, new UserName("bar"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failGetTokensUser(auth, token, new UserName("bar"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void forceResetAllPasswordsFailCatastrophicNoUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		
		final StoredToken token = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.absent(), new UserName("admin"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenThrow(new NoSuchUserException("admin"));
		
		failGetTokensUser(auth, t, new UserName("bar"), new RuntimeException(
				"There seems to be an error in the storage system. Token was valid, but no user"));
	}

	private void getTokensUser(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		
		final StoredToken token = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.absent(), admin.getUserName(), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin, (AuthUser) null);
		
		when(storage.getTokens(new UserName("foo"))).thenReturn(set(TOKEN1, TOKEN2));
		
		try {
			final Set<StoredToken> tokens = auth.getTokens(t, new UserName("foo"));
			assertThat("incorrect tokens", tokens, is(set(TOKEN1, TOKEN2)));
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failGetTokensUser(final AuthUser admin, final Exception e) {
		try {
			getTokensUser(admin);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failGetTokensUser(
			final Authentication auth,
			final IncomingToken token,
			final UserName name,
			final Exception e) {
		try {
			auth.getTokens(token, name);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getBareToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		when(rand.getToken()).thenReturn("foobar");
		
		assertThat("incorrect token", auth.getBareToken(), is("foobar"));
	}
	
	@Test
	public void revokeSelf() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		
		final StoredToken ht = new StoredToken(id, TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		final Optional<StoredToken> res = auth.revokeToken(t);
		
		verify(storage).deleteToken(new UserName("foo"), id);
		
		assertThat("incorrect token", res, is(Optional.of(ht)));
	}
	
	@Test
	public void revokeSelfNoToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		final Optional<StoredToken> res = auth.revokeToken(t);
		
		assertThat("incorrect token", res, is(Optional.absent()));
	}
	
	@Test
	public void revokeSelfFail() throws Exception {
		final Authentication auth = initTestMocks().auth;
		try {
			auth.revokeToken(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
	}
	
	@Test
	public void revokeToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID target = UUID.randomUUID();
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		auth.revokeToken(t, target);
		
		verify(storage).deleteToken(new UserName("foo"), target);
	}
	
	@Test
	public void revokeTokenFailBadIncomingToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failRevokeToken(auth, t, UUID.randomUUID(), new InvalidTokenException());
	}
	
	@Test
	public void revokeTokenFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				new StoredToken(UUID.randomUUID(), TokenType.AGENT, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.DEV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.SERV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failRevokeToken(auth, token, UUID.randomUUID(), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failRevokeToken(auth, token, UUID.randomUUID(), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failRevokeToken(auth, token, UUID.randomUUID(), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void revokeTokenFailNoSuchToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID target = UUID.randomUUID();
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		doThrow(new NoSuchTokenException(target.toString()))
			.when(storage).deleteToken(new UserName("foo"), target);
		
		failRevokeToken(auth, t, target, new NoSuchTokenException(target.toString()));
	}
	
	@Test
	public void revokeTokenFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeToken(auth, null, UUID.randomUUID(), new NullPointerException("token"));
		failRevokeToken(auth, new IncomingToken("f"), null, new NullPointerException("tokenID"));
	}
	
	private void failRevokeToken(
			final Authentication auth,
			final IncomingToken t,
			final UUID target,
			final Exception e) {
		try {
			auth.revokeToken(t, target);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void revokeTokenAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();

		revokeTokenAdmin(admin);
	}
	
	@Test
	public void revokeTokenAdminFailStdUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		failRevokeTokenAdmin(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeTokenAdminFailCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		failRevokeTokenAdmin(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeTokenAdminFailRoot() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		failRevokeTokenAdmin(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeTokenAdminFailDisabled() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("bar"), Instant.now())).build();
		
		failRevokeTokenAdmin(admin, new DisabledUserException());
	}
	
	@Test
	public void revokeTokenAdminFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeTokenAdmin(auth, null, new UserName("foo"), UUID.randomUUID(),
				new NullPointerException("token"));
		failRevokeTokenAdmin(auth, new IncomingToken("f"), null, UUID.randomUUID(),
				new NullPointerException("userName"));
		failRevokeTokenAdmin(auth, new IncomingToken("f"), new UserName("foo"), null,
				new NullPointerException("tokenID"));
	}
	
	@Test
	public void revokeTokenAdminFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final UUID target = UUID.randomUUID();
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failRevokeTokenAdmin(auth, t, new UserName("foo"), target, new InvalidTokenException());
	}
	
	@Test
	public void revokeTokenAdminFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		final UUID target = UUID.randomUUID();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				new StoredToken(UUID.randomUUID(), TokenType.AGENT, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.DEV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.SERV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failRevokeTokenAdmin(auth, token, new UserName("foo"), target, new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failRevokeTokenAdmin(auth, token, new UserName("foo"), target, new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failRevokeTokenAdmin(auth, token, new UserName("foo"), target, new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void revokeTokenAdminFailCatastropic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID target = UUID.randomUUID();
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failRevokeTokenAdmin(auth, t, new UserName("bar"), target, new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	@Test
	public void revokeTokenAdminFailNoSuchToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final UUID target = UUID.randomUUID();
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(admin);
		
		doThrow(new NoSuchTokenException(target.toString()))
				.when(storage).deleteToken(new UserName("bar"), target);
		
		failRevokeTokenAdmin(auth, t, new UserName("bar"), target,
				new NoSuchTokenException(target.toString()));
	}

	private void revokeTokenAdmin(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID target = UUID.randomUUID();
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				admin.getUserName(), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin);
		
		try {
			auth.revokeToken(t, new UserName("whee"), target);
		
			verify(storage).deleteToken(new UserName("whee"), target);
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failRevokeTokenAdmin(
			final AuthUser admin,
			final Exception e) {
		try {
			revokeTokenAdmin(admin);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failRevokeTokenAdmin(
			final Authentication auth,
			final IncomingToken t,
			final UserName name,
			final UUID target,
			final Exception e) {
		try {
			auth.revokeToken(t, name, target);
			fail("exception expected");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void revokeAllTokensUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		auth.revokeTokens(t);
		
		verify(storage).deleteTokens(new UserName("foo"));
	}
	
	@Test
	public void revokeAllTokensUserFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeAllTokensUser(auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void revokeAllTokensUserFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failRevokeAllTokensUser(auth, t, new InvalidTokenException());
	}
	
	@Test
	public void revokeAllTokensUserFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				new StoredToken(UUID.randomUUID(), TokenType.AGENT, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.DEV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.SERV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failRevokeAllTokensUser(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Agent tokens are not allowed for this operation"));
		failRevokeAllTokensUser(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Developer tokens are not allowed for this operation"));
		failRevokeAllTokensUser(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Service tokens are not allowed for this operation"));
	}
	
	private void failRevokeAllTokensUser(
			final Authentication auth,
			final IncomingToken t,
			final Exception e) {
		try {
			auth.revokeTokens(t);
			fail("expected exceptoin");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

	@Test
	public void revokeAllTokensAdminAll() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		revokeAllTokensAdminAll(admin);
	}
	
	@Test
	public void revokeAllTokensAdminAllFailStdUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		failRevokeAllTokensAdminAll(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeAllTokensAdminAllFailCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		failRevokeAllTokensAdminAll(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeAllTokensAdminAllFailRoot() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		failRevokeAllTokensAdminAll(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeAllTokensAdminAllFailDisabled() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("bar"), Instant.now())).build();
		
		failRevokeAllTokensAdminAll(admin, new DisabledUserException());
	}
	
	@Test
	public void revokeAllTokensAdminAllFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeAllTokensAdminAll(auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void revokeAllTokensAdminAllFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failRevokeAllTokensAdminAll(auth, t, new InvalidTokenException());
	}
	
	@Test
	public void revokeAllTokensAdminAllBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				new StoredToken(UUID.randomUUID(), TokenType.AGENT, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.DEV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.SERV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failRevokeAllTokensAdminAll(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Agent tokens are not allowed for this operation"));
		failRevokeAllTokensAdminAll(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Developer tokens are not allowed for this operation"));
		failRevokeAllTokensAdminAll(auth, token, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void revokeAllTokensAdminAllFailCatastropic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failRevokeAllTokensAdminAll(auth, t, new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	private void revokeAllTokensAdminAll(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				admin.getUserName(), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin);
		
		try {
			auth.revokeAllTokens(t);
		
			verify(storage).deleteTokens();
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failRevokeAllTokensAdminAll(
			final AuthUser admin,
			final Exception e) {
		try {
			revokeAllTokensAdminAll(admin);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failRevokeAllTokensAdminAll(
			final Authentication auth,
			final IncomingToken t,
			final Exception e) {
		try {
			auth.revokeAllTokens(t);
			fail("expected exceptoin");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void revokeAllTokensAdminUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		revokeAllTokensAdminUser(admin);
	}
	
	@Test
	public void revokeAllTokensAdminUserFailStdUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		failRevokeAllTokensAdminUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeAllTokensAdminUserFailCreate() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		failRevokeAllTokensAdminUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeAllTokensAdminUserFailRoot() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				UserName.ROOT, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.build();
		
		failRevokeAllTokensAdminUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void revokeAllTokensAdminUserFailDisabled() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("bar"), Instant.now())).build();
		
		failRevokeAllTokensAdminUser(admin, new DisabledUserException());
	}
	
	@Test
	public void revokeAllTokensAdminUserFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeAllTokensAdminUser(auth, null, new UserName("foo"),
				new NullPointerException("token"));
		failRevokeAllTokensAdminUser(auth, new IncomingToken("f"), null,
				new NullPointerException("userName"));
	}
	
	@Test
	public void revokeAllTokensAdminUserFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failRevokeAllTokensAdminUser(auth, t, new UserName("foo"), new InvalidTokenException());
	}
	
	@Test
	public void revokeAllTokensAdminUserFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				new StoredToken(UUID.randomUUID(), TokenType.AGENT, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.DEV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				new StoredToken(UUID.randomUUID(), TokenType.SERV, null,
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failRevokeAllTokensAdminUser(auth, token, new UserName("foo"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failRevokeAllTokensAdminUser(auth, token, new UserName("foo"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failRevokeAllTokensAdminUser(auth, token, new UserName("foo"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void revokeAllTokensAdminUserFailCatastropic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failRevokeAllTokensAdminUser(auth, t, new UserName("whee"), new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	private void revokeAllTokensAdminUser(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				admin.getUserName(), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin);
		
		try {
			auth.revokeAllTokens(t, new UserName("whee"));
		
			verify(storage).deleteTokens(new UserName("whee"));
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failRevokeAllTokensAdminUser(
			final AuthUser admin,
			final Exception e) {
		try {
			revokeAllTokensAdminUser(admin);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failRevokeAllTokensAdminUser(
			final Authentication auth,
			final IncomingToken t,
			final UserName name,
			final Exception e) {
		try {
			auth.revokeAllTokens(t, name);
			fail("expected exceptoin");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void createAgentToken() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.build();
		
		createToken(user, new HashMap<>(), 7 * 24 * 3600 * 1000L, TokenType.AGENT);
	}
	
	@Test
	public void createAgentTokenWithAltLifeTime() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.build();
		
		final HashMap<TokenLifetimeType, Long> lifetimes = new HashMap<>();
		lifetimes.put(TokenLifetimeType.AGENT, 3 * 24 * 3600 * 1000L);
		createToken(user, lifetimes, 3 * 24 * 3600 * 1000L, TokenType.AGENT);
	}
	
	@Test
	public void createDevToken() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.DEV_TOKEN).build();
		
		createToken(user, new HashMap<>(), 90 * 24 * 3600 * 1000L, TokenType.DEV);
	}
	
	@Test
	public void createDevTokenAltLifetime() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.DEV_TOKEN).build();
		
		final HashMap<TokenLifetimeType, Long> lifetimes = new HashMap<>();
		lifetimes.put(TokenLifetimeType.DEV, 42 * 24 * 3600 * 1000L);
		createToken(user, lifetimes, 42 * 24 * 3600 * 1000L, TokenType.DEV);
	}
	
	@Test
	public void createDevTokenWithServRole() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		createToken(user, new HashMap<>(), 90 * 24 * 3600 * 1000L, TokenType.DEV);
	}
	
	@Test
	public void createServToken() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		createToken(user, new HashMap<>(), 100_000_000L * 24 * 3600 * 1000L, TokenType.SERV);
	}
	
	@Test
	public void createServTokenWithAdminRole() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).build();
		
		createToken(user, new HashMap<>(), 100_000_000L * 24 * 3600 * 1000L, TokenType.SERV);
	}
	
	@Test
	public void createServTokenWithAltLifetime() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		final HashMap<TokenLifetimeType, Long> lifetimes = new HashMap<>();
		lifetimes.put(TokenLifetimeType.SERV, 24 * 24 * 3600 * 1000L);
		createToken(user, lifetimes, 24 * 24 * 3600 * 1000L, TokenType.SERV);
	}
	
	@Test
	public void createTokenFailDisabledUser() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.SERV_TOKEN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("baz"), Instant.now())).build();
		
		failCreateToken(user, TokenType.AGENT, new DisabledUserException());
	}
	
	@Test
	public void createTokenFailNoDevRole() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		failCreateToken(user, TokenType.DEV, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"User foo is not authorized to create this token type."));
	}
	
	@Test
	public void createTokenFailNoServRole() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.DEV_TOKEN)
				.withRole(Role.CREATE_ADMIN).build();
		
		failCreateToken(user, TokenType.SERV, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"User foo is not authorized to create this token type."));
	}
	
	@Test
	public void createTokenFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failCreateToken(auth, null, new TokenName("foo"), TokenType.DEV,
				new NullPointerException("token"));
		failCreateToken(auth, new IncomingToken("foo"), null, TokenType.DEV,
				new NullPointerException("tokenName"));
		failCreateToken(auth, new IncomingToken("foo"), new TokenName("bar"), null,
				new NullPointerException("tokenType"));
	}
	
	@Test
	public void createTokenFailCreateLogin() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failCreateToken(auth, new IncomingToken("foo"), new TokenName("bar"), TokenType.LOGIN,
				new IllegalArgumentException(
						"Cannot create a login token without logging in"));
	}
	
	@Test
	public void createTokenFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failCreateToken(auth, t, new TokenName("foo"), TokenType.DEV, new InvalidTokenException());
	}
	
	@Test
	public void createTokenFailWithAgentToken() throws Exception {
		createTokenFailWithNonLoginToken(TokenType.AGENT);
	}

	@Test
	public void createTokenFailWithDevToken() throws Exception {
		createTokenFailWithNonLoginToken(TokenType.DEV);
	}
	
	@Test
	public void createTokenFailWithServToken() throws Exception {
		createTokenFailWithNonLoginToken(TokenType.SERV);
	}

	private void createTokenFailWithNonLoginToken(final TokenType tokenType) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken ht = new StoredToken(UUID.randomUUID(), tokenType,
				null, new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		failCreateToken(auth, t, new TokenName("foo"), TokenType.DEV,
				new UnauthorizedException(ErrorType.UNAUTHORIZED, tokenType.getDescription() +
						" tokens are not allowed for this operation"));
	}
	
	@Test
	public void createTokenFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failCreateToken(auth, t, new TokenName("baz"), TokenType.AGENT, new RuntimeException(
				"There seems to be an error in the storage system. Token was valid, but no user"));
	}
	
	private void createToken(
			final AuthUser user,
			final Map<TokenLifetimeType, Long> lifetimes,
			final long expectedLifetime,
			final TokenType tokenType) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final Clock clock = testauth.clockMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final IncomingToken t = new IncomingToken("foobar");
		final UUID id = UUID.randomUUID();
		final Instant time = Instant.ofEpochMilli(100000);
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				user.getUserName(), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(user.getUserName())).thenReturn(user, (AuthUser) null);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, lifetimes),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.randomUUID()).thenReturn(id, (UUID) null);
		when(rand.getToken()).thenReturn("this is a token", (String)null);
		when(clock.instant()).thenReturn(time, (Instant) null);
		
		try {
			final NewToken nt = auth.createToken(t, new TokenName("a name"), tokenType);
			
			final Instant expiration = Instant.ofEpochMilli(time.toEpochMilli() +
					(expectedLifetime));
			verify(storage).storeToken(new StoredToken(id, tokenType,
					Optional.of(new TokenName("a name")), user.getUserName(),
					time, expiration),
					"p40z9I2zpElkQqSkhbW6KG3jSgMRFr3ummqjSe7OzOc=");
			
			final NewToken expected = new NewToken(id, tokenType,
					new TokenName("a name"), "this is a token", user.getUserName(), time,
					expectedLifetime);
			
			assertThat("incorrect token", nt, is(expected));
		} catch (Throwable th) {
			if (user.isDisabled()) {
				verify(storage).deleteTokens(user.getUserName());
			}
			throw th;
		}
	}
	
	private void failCreateToken(
			final AuthUser user,
			final TokenType tokenType,
			final Exception e) {
		try {
			createToken(user, new HashMap<>(), 3L, tokenType);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failCreateToken(
			final Authentication auth,
			final IncomingToken t,
			final TokenName name,
			final TokenType tokenType,
			final Exception e) {
		try {
			auth.createToken(t, name, tokenType);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}
