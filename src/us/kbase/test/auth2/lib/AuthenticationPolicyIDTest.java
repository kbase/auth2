package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationPolicyIDTest {
	
	/* Tests policy ID related functions that are not covered as part of other tests, e.g.
	 * login tests and get / create user tests.
	 */
	
	@Test
	public void removePolicyID() throws Exception {
		removePolicyID(new UserName("foo"), Role.ADMIN);
	}
	
	@Test
	public void removePolicyIDFailRole() throws Exception {
		failRemovePolicyID(UserName.ROOT, Role.ROOT,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
		for (final Role r: Arrays.asList(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN)) {
			failRemovePolicyID(new UserName("foo"), r,
					new UnauthorizedException(ErrorType.UNAUTHORIZED));
		}
	}
	
	@Test
	public void removePolicyIDFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRemovePolicyID(auth, null, new PolicyID("foo"), new NullPointerException("token"));
		failRemovePolicyID(auth, new IncomingToken("foo"), null,
				new NullPointerException("policyID"));
	}
	
	@Test
	public void removePolicyIDFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
			
		failRemovePolicyID(auth, token, new PolicyID("bar"), new InvalidTokenException());
	}
	
	@Test
	public void removePolicyIDFailBadTokenType() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.AGENT, UUID.randomUUID(), new UserName("bar"))
						.withLifeTime(Instant.now(), Instant.now()).build(),
				StoredToken.getBuilder(TokenType.DEV, UUID.randomUUID(), new UserName("bar"))
						.withLifeTime(Instant.now(), Instant.now()).build(),
				StoredToken.getBuilder(TokenType.SERV, UUID.randomUUID(), new UserName("bar"))
						.withLifeTime(Instant.now(), Instant.now()).build(),
				null);
		
		failRemovePolicyID(auth, token, new PolicyID("bar"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failRemovePolicyID(auth, token, new PolicyID("bar"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failRemovePolicyID(auth, token, new PolicyID("bar"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void failRemotePolicyIDFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		when(storage.getUser(new UserName("baz"))).thenThrow(new NoSuchUserException("baz"));
			
		failRemovePolicyID(auth, token, new PolicyID("foo"), new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	@Test
	public void removePolicyIDFailDisabled() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("bar"), Instant.now()))
				.build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u);
		
		failRemovePolicyID(auth, token, new PolicyID("fOO"), new DisabledUserException("baz"));
		
		verify(storage).deleteTokens(new UserName("baz"));
	}

	private void removePolicyID(final UserName adminName, final Role adminRole) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), adminName)
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				adminName, new DisplayName("foobar"), Instant.now())
				.withRole(adminRole).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(adminName)).thenReturn(u, (AuthUser) null);
		
		auth.removePolicyID(token, new PolicyID("foo"));
		
		verify(storage).removePolicyID(new PolicyID("foo"));
	}
	
	private void failRemovePolicyID(
			final UserName adminName,
			final Role adminRole,
			final Exception e) {
		try {
			removePolicyID(adminName, adminRole);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failRemovePolicyID(
			final Authentication auth,
			final IncomingToken token,
			final PolicyID pid,
			final Exception e) {
		try {
			auth.removePolicyID(token, pid);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
