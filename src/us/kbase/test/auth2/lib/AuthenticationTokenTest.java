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
import java.util.Set;
import java.util.UUID;

import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.common.base.Optional;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TokenName;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestAuth;

public class AuthenticationTokenTest {
	
	/* tests token get, create, revoke, and getBare. */
	
	private static final HashedToken TOKEN1;
	private static final HashedToken TOKEN2;
	static {
		try {
		TOKEN1 = new HashedToken(TokenType.LOGIN, Optional.absent(),
				UUID.randomUUID(), "whee", new UserName("foo"), Instant.ofEpochMilli(3000),
				Instant.ofEpochMilli(4000));
		TOKEN2 = new HashedToken(TokenType.EXTENDED_LIFETIME, Optional.of(new TokenName("baz")),
				UUID.randomUUID(), "whee1", new UserName("foo"), Instant.ofEpochMilli(5000),
				Instant.ofEpochMilli(6000));
		} catch (Exception e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}
	
	@Test
	public void getToken() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final Instant now = Instant.now();
		final UUID id = UUID.randomUUID();
		
		final HashedToken expected = new HashedToken(TokenType.LOGIN, Optional.absent(), id,
				"whee", new UserName("foo"), now, now);
		
		when(storage.getToken(t.getHashedToken())).thenReturn(expected);
		
		final HashedToken ht = auth.getToken(t);
		assertThat("incorrect token", ht, is(new HashedToken(TokenType.LOGIN, Optional.absent(),
				id, "whee", new UserName("foo"), now, now)));
	}
	
	@Test
	public void getTokenFailNull() throws Exception {
		final Authentication auth = initTestAuth().auth;
		failGetToken(auth, null, new NullPointerException("token"));
	}

	
	@Test
	public void getTokenFailNoSuchToken() throws Exception {
		final TestAuth testauth = initTestAuth();
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
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final Instant now = Instant.now();
		final UUID id = UUID.randomUUID();
		
		final HashedToken expected = new HashedToken(TokenType.LOGIN, null, id,
				"whee", new UserName("foo"), now, now);
		
		when(storage.getToken(t.getHashedToken())).thenReturn(expected, (HashedToken) null);
		
		when(storage.getTokens(new UserName("foo"))).thenReturn(set(TOKEN1, TOKEN2));
		
		final TokenSet ts = auth.getTokens(t);
		assertThat("incorrect token set", ts, is(new TokenSet(expected, set(TOKEN2, TOKEN1))));
	}
	
	@Test
	public void getTokensFailNull() throws Exception {
		final Authentication auth = initTestAuth().auth;
		failGetTokens(auth, null, new NullPointerException("token"));
	}

	
	@Test
	public void getTokensFailNoSuchToken() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failGetTokens(auth, t, new InvalidTokenException());
	}
	
	private void failGetTokens(
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
	public void getTokensUser() throws Exception {
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), Instant.now(), null, new UserDisabledState());
		getTokensUser(admin);
	}
	
	@Test
	public void getTokensUserFailNonAdmin() throws Exception {
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), Collections.emptySet(), set(Role.DEV_TOKEN),
				Collections.emptySet(), Instant.now(), null, new UserDisabledState());
		failGetTokensUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void getTokensUserFailCreate() throws Exception {
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), Collections.emptySet(), set(Role.CREATE_ADMIN),
				Collections.emptySet(), Instant.now(), null, new UserDisabledState());
		failGetTokensUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void getTokensUserFailRoot() throws Exception {
		final AuthUser admin = new AuthUser(UserName.ROOT, new EmailAddress("f@g.com"),
				new DisplayName("bar"), Collections.emptySet(), set(Role.ROOT),
				Collections.emptySet(), Instant.now(), null, new UserDisabledState());
		failGetTokensUser(admin, new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void getTokensUserFailDisabled() throws Exception {
		final AuthUser admin = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), Collections.emptySet(), set(Role.DEV_TOKEN),
				Collections.emptySet(), Instant.now(), null,
				new UserDisabledState("foo", new UserName("baz"), Instant.now()));
		failGetTokensUser(admin, new DisabledUserException());
	}
	
	@Test
	public void getTokensUserFailNulls() throws Exception {
		final TestAuth testauth = initTestAuth();
		final Authentication auth = testauth.auth;
		
		failGetTokensUser(auth, null, new UserName("foo"), new NullPointerException("token"));
		failGetTokensUser(auth, new IncomingToken("foo"), null,
				new NullPointerException("userName"));
	}
	
	@Test
	public void getTokensUserFailInvalidToken() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failGetTokensUser(auth, t, new UserName("bar"), new InvalidTokenException());
	}
	
	@Test
	public void forceResetAllPasswordsFailCatastrophicNoUser() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		
		final HashedToken token = new HashedToken(TokenType.LOGIN, Optional.absent(),
				UUID.randomUUID(), "wubba", new UserName("admin"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (HashedToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenThrow(new NoSuchUserException("admin"));
		
		failGetTokensUser(auth, t, new UserName("bar"), new RuntimeException(
				"There seems to be an error in the storage system. Token was valid, but no user"));
	}

	private void getTokensUser(final AuthUser admin) throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		
		final HashedToken token = new HashedToken(TokenType.LOGIN, Optional.absent(),
				UUID.randomUUID(), "wubba", admin.getUserName(), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (HashedToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin, (AuthUser) null);
		
		when(storage.getTokens(new UserName("foo"))).thenReturn(set(TOKEN1, TOKEN2));
		
		try {
			final Set<HashedToken> tokens = auth.getTokens(t, new UserName("foo"));
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
		final TestAuth testauth = initTestAuth();
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGen;
		
		when(rand.getToken()).thenReturn("foobar");
		
		assertThat("incorrect token", auth.getBareToken(), is("foobar"));
	}
	
	@Test
	public void revokeSelf() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		
		final HashedToken ht = new HashedToken(TokenType.LOGIN, null, id, "baz",
				new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (HashedToken) null);
		
		final Optional<HashedToken> res = auth.revokeToken(t);
		
		verify(storage).deleteToken(new UserName("foo"), id);
		
		assertThat("incorrect token", res, is(Optional.of(ht)));
	}
	
	@Test
	public void revokeSelfNoToken() throws Exception {
		final TestAuth testauth = initTestAuth();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		final Optional<HashedToken> res = auth.revokeToken(t);
		
		assertThat("incorrect token", res, is(Optional.absent()));
	}
	
	@Test
	public void revokeSelfFail() throws Exception {
		final Authentication auth = initTestAuth().auth;
		try {
			auth.revokeToken(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
	}
	
	
	//TODO NOW TEST create & revoke
	
}
