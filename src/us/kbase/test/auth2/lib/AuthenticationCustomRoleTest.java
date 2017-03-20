package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
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
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationCustomRoleTest {
	
	@Test
	public void createRole() throws Exception {
		final Role adminRole = Role.ADMIN;
		successCreateRole(new UserName("admin"), adminRole);
	}
	
	@Test
	public void createRoleFailAdmin() throws Exception {
		for (final Role r: Arrays.asList(Role.CREATE_ADMIN, Role.SERV_TOKEN, Role.DEV_TOKEN)) {
			failCreateRole(new UserName("admin"), r,
					new UnauthorizedException(ErrorType.UNAUTHORIZED));
		}
	}
	
	@Test
	public void createRoleFailRoot() throws Exception {
		failCreateRole(UserName.ROOT , Role.ROOT,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void createRoleFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failCreateRole(auth, null, new CustomRole("a", "b"), new NullPointerException("token"));
		failCreateRole(auth, new IncomingToken("foo"), null, new NullPointerException("role"));
	}
	
	@Test
	public void createRoleFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
			
		failCreateRole(auth, token, new CustomRole("a", "b"), new InvalidTokenException());
	}
	
	@Test
	public void createRoleFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		when(storage.getUser(new UserName("baz"))).thenThrow(new NoSuchUserException("baz"));
			
		failCreateRole(auth, token, new CustomRole("a", "b"), new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	@Test
	public void updateRolesFailDisabled() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("bar"), Instant.now()))
				.build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (HashedToken) null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u);
		
		failCreateRole(auth, token, new CustomRole("a", "b"), new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("baz"));
	}

	private void successCreateRole(final UserName adminName, final Role adminRole)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", adminName, Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				adminName, new DisplayName("foobar"), Instant.now())
				.withRole(adminRole).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (HashedToken) null);
		
		when(storage.getUser(adminName)).thenReturn(u, (AuthUser) null);
		
		auth.setCustomRole(token, new CustomRole("id", "desc"));
		
		verify(storage).setCustomRole(new CustomRole("id", "desc"));
	}
	
	private void failCreateRole(
			final UserName admin,
			final Role adminRole,
			final Exception e) {
		
		try {
			successCreateRole(admin, adminRole);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failCreateRole(
			final Authentication auth,
			final IncomingToken token,
			final CustomRole role,
			final Exception e) {
		try {
			auth.setCustomRole(token, role);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
