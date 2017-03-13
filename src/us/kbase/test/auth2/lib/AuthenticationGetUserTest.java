package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.ViewableUser;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationGetUserTest {
	
	@Test
	public void getUser() throws Exception {
		
		final AuthUser user = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), Instant.now(), Optional.of(Instant.now()),
				new UserDisabledState());
		
		getUser(user);
	}
	
	@Test
	public void getUserFailDisabled() throws Exception {
		final AuthUser user = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), Instant.now(), Optional.of(Instant.now()),
				new UserDisabledState("foo", new UserName("bar"), Instant.now()));
		
		failGetUser(user, new DisabledUserException());
	}
	
	@Test
	public void getUserFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetUser(auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void getUserFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");

		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failGetUser(auth, token, new InvalidTokenException());
	}
	
	@Test
	public void getUserFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");

		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null, "foobarhash",
						new UserName("foo"), Instant.now(), Instant.now()));
		
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failGetUser(auth, token, new RuntimeException("There seems to be an error " +
				"in the storage system. Token was valid, but no user"));
	}

	private void getUser(final AuthUser user) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");

		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null, "foobarhash",
						user.getUserName(), Instant.now(), Instant.now()));
		
		when(storage.getUser(user.getUserName())).thenReturn(user);
		
		try {
			final AuthUser got = auth.getUser(token);
		
			assertThat("incorrect user", got, is(user));
		} catch (Throwable th) {
			if (user.isDisabled()) {
				verify(storage).deleteTokens(user.getUserName());
			} else {
				verify(storage, never()).deleteTokens(user.getUserName());
			}
			throw th;
		}
	}
	
	private void failGetUser(final AuthUser user, final Exception e) {
		try {
			getUser(user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failGetUser(
			final Authentication auth,
			final IncomingToken token,
			final Exception e)
			throws Exception {
		try {
			auth.getUser(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getOtherUserSameUser() throws Exception {
		final AuthUser user = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), Instant.now(), Optional.of(Instant.now()),
				new UserDisabledState());
		
		getOtherUser(user, new UserName("admin"), true);
	}
	
	@Test
	public void getOtherUserDiffUser() throws Exception {
		final AuthUser user = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo1"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), Instant.now(), Optional.of(Instant.now()),
				new UserDisabledState());
		
		getOtherUser(user, new UserName("foo"), false);
	}
	
	@Test
	public void getOtherUserFailDisabledSameUser() throws Exception {
		final AuthUser user = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo1"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), Instant.now(), Optional.of(Instant.now()),
				new UserDisabledState("foo", new UserName("baz"), Instant.now()));
		
		failGetOtherUser(user, new UserName("admin"), new NoSuchUserException("admin"));
	}
	
	@Test
	public void getOtherUserFailDisabledDiffUser() throws Exception {
		final AuthUser user = new AuthUser(new UserName("admin"), new EmailAddress("f@g.com"),
				new DisplayName("foo1"), Collections.emptySet(), set(Role.ADMIN),
				Collections.emptySet(), Instant.now(), Optional.of(Instant.now()),
				new UserDisabledState("foo", new UserName("baz"), Instant.now()));
		
		failGetOtherUser(user, new UserName("foo"), new NoSuchUserException("admin"));
	}
	
	@Test
	public void getOtherUserFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetOtherUser(auth, null, new UserName("foo"), new NullPointerException("token"));
		failGetOtherUser(auth, new IncomingToken("foo"), null,
				new NullPointerException("userName"));
	}
	
	@Test
	public void getOtherUserFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		

		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failGetOtherUser(auth, token, new UserName("foo"), new InvalidTokenException());
	}
	
	@Test
	public void getOtherUserFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		

		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null, "foobarhash",
						new UserName("bar"), Instant.now(), Instant.now()));
		
		when(storage.getUser(new UserName("bar"))).thenThrow(new NoSuchUserException("bar"));
		
		failGetOtherUser(auth, token, new UserName("bar"), new NoSuchUserException("bar"));
	}

	private void getOtherUser(
			final AuthUser user,
			final UserName tokenName,
			final boolean includeEmail)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		

		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null, "foobarhash",
						tokenName, Instant.now(), Instant.now()));
		
		when(storage.getUser(user.getUserName())).thenReturn(user);
		try {
			final ViewableUser vu = auth.getUser(token, user.getUserName());
		
			assertThat("incorrect user", vu, is(new ViewableUser(user, includeEmail)));
		} catch (Throwable th) {
			if (user.isDisabled() && tokenName.equals(user.getUserName())) {
				verify(storage).deleteTokens(user.getUserName());
			} else {
				verify(storage, never()).deleteTokens(user.getUserName());
			}
			throw th;
		}
	}
	
	private void failGetOtherUser(
			final AuthUser user,
			final UserName tokenName,
			final Exception e) {
		try {
			getOtherUser(user, tokenName, false);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failGetOtherUser(
			final Authentication auth,
			final IncomingToken token,
			final UserName user,
			final Exception e) {
		try {
			auth.getUser(token, user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
