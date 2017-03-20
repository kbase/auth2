package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationRoleTest {
	
	@Test
	public void removeRoleSuccess() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foobar"), Instant.now())
				.withRole(Role.SERV_TOKEN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, htoken, null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u, (AuthUser) null);
		
		auth.removeRoles(token, set(Role.SERV_TOKEN, Role.ADMIN));
		
		verify(storage).updateRoles(
				new UserName("baz"), Collections.emptySet(), set(Role.ADMIN, Role.SERV_TOKEN));
	}
	
	@Test
	public void removeRoleFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		failRemoveRole(auth, null, set(Role.SERV_TOKEN),
				new NullPointerException("token"));
		
		final IncomingToken token = new IncomingToken("foo");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		failRemoveRole(auth, new IncomingToken("foo"), null,
				new NullPointerException("removeRoles"));
		failRemoveRole(auth, new IncomingToken("foo"), set(Role.ADMIN, null),
				new NullPointerException("Null role in removeRoles"));
	}
	
	@Test
	public void removeRoleFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		failRemoveRole(auth, null, set(Role.SERV_TOKEN),
				new NullPointerException("token"));
		
		final IncomingToken token = new IncomingToken("foo");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		when(storage.getUser(new UserName("baz"))).thenThrow(new NoSuchUserException("baz"));
			
		failRemoveRole(auth, token, set(Role.ADMIN), new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	@Test
	public void removeRoleFailCatastrophic2() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foobar"), Instant.now())
				.withRole(Role.SERV_TOKEN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, htoken, null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u, (AuthUser) null);
		
		doThrow(new NoSuchUserException("baz")).when(storage).updateRoles(
				new UserName("baz"), Collections.emptySet(), set(Role.ADMIN, Role.SERV_TOKEN));
		
		failRemoveRole(auth, token, set(Role.SERV_TOKEN, Role.ADMIN), new RuntimeException(
				"There seems to be an error in the storage system. Token was valid, but no user"));
	}
	
	@Test
	public void removeRoleFailDisabled() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		failRemoveRole(auth, null, set(Role.SERV_TOKEN),
				new NullPointerException("token"));
		
		final IncomingToken token = new IncomingToken("foo");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foobar"), Instant.now())
				.withRole(Role.SERV_TOKEN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("bar"), Instant.now()))
				.build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u);
			
		failRemoveRole(auth, token, set(Role.ADMIN), new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("baz"));
	}
	
	@Test
	public void removeRoleFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
			
		failRemoveRole(auth, token, set(Role.ADMIN), new InvalidTokenException());
	}

	private void failRemoveRole(
			final Authentication auth,
			final IncomingToken token,
			final Set<Role> roles,
			final Exception e) {
		try {
			auth.removeRoles(token, roles);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
