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
import java.util.UUID;

import org.junit.Test;
import org.junit.rules.ExpectedException;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.storage.AuthStorage;
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
		TOKEN1 = new HashedToken(TokenType.LOGIN, null,
				UUID.randomUUID(), "whee", new UserName("foo"), Instant.ofEpochMilli(3000),
				Instant.ofEpochMilli(4000));
		TOKEN2 = new HashedToken(TokenType.EXTENDED_LIFETIME, "baz",
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
		
		final HashedToken expected = new HashedToken(TokenType.LOGIN, null, id,
				"whee", new UserName("foo"), now, now);
		
		when(storage.getToken(t.getHashedToken())).thenReturn(expected);
		
		final HashedToken ht = auth.getToken(t);
		assertThat("incorrect token", ht, is(new HashedToken(TokenType.LOGIN, null,
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
}
