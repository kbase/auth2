package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationUserUpdateTest {
	
	private static final UserUpdate UU;
	static {
		try {
			UU = UserUpdate.getBuilder()
					.withDisplayName(new DisplayName("foo")).build();
		} catch (Exception e) {
			throw new RuntimeException("Fix yer tests", e);
		}
	}

	@Test
	public void updateUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		auth.updateUser(token, UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("bar"))
				.withEmail(new EmailAddress("f@g.com")).build());
		
		verify(storage).updateUser(new UserName("foo"), UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("bar"))
				.withEmail(new EmailAddress("f@g.com")).build());
	}
	
	@Test
	public void updateUserNoop() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		auth.updateUser(new IncomingToken("foobar"), UserUpdate.getBuilder().build()); //noop
	}
	
	@Test
	public void updateUserFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failUpdateUser(auth, null, UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("foo")).build(),
				new NullPointerException("token"));
		failUpdateUser(auth, new IncomingToken("foo"), null, new NullPointerException("update"));
	}
	
	@Test
	public void updateUserFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failUpdateUser(auth, token, UU, new InvalidTokenException());
	}
	
	@Test
	public void updateUserFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				new HashedToken(UUID.randomUUID(), TokenType.AGENT, null, "foo",
						new UserName("bar"), Instant.now(), Instant.now()),
				new HashedToken(UUID.randomUUID(), TokenType.DEV, null, "foo",
						new UserName("bar"), Instant.now(), Instant.now()),
				new HashedToken(UUID.randomUUID(), TokenType.SERV, null, "foo",
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failUpdateUser(auth, token, UU, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Agent tokens are not allowed for this operation"));
		failUpdateUser(auth, token, UU, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Developer tokens are not allowed for this operation"));
		failUpdateUser(auth, token, UU, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void updateUserFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("foo"), Instant.now(), Instant.now());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		doThrow(new NoSuchUserException("foo")).when(storage).updateUser(new UserName("foo"),
				UserUpdate.getBuilder()
					.withEmail(new EmailAddress("f@g.com")).build());
		
		failUpdateUser(auth, token, UserUpdate.getBuilder()
					.withEmail(new EmailAddress("f@g.com")).build(), new RuntimeException(
							"There seems to be an error in the " +
									"storage system. Token was valid, but no user"));
	}

	private void failUpdateUser(
			final Authentication auth,
			final IncomingToken token,
			final UserUpdate update,
			final Exception e) {
		try {
			auth.updateUser(token, update);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
