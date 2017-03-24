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
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
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
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
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
		successCreateRole(new UserName("admin"), Role.ADMIN);
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
		failCreateRole(UserName.ROOT, Role.ROOT,
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
	public void createRoleFailBadTokenType() throws Exception {
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
		
		failCreateRole(auth, token, new CustomRole("a", "b"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failCreateRole(auth, token, new CustomRole("a", "b"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failCreateRole(auth, token, new CustomRole("a", "b"), new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
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
	public void createRoleFailDisabled() throws Exception {
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
	
	@Test
	public void deleteRole() throws Exception {
		successDeleteRole(new UserName("admin"), Role.ADMIN);
	}
	
	@Test
	public void deleteRoleFailAdmin() throws Exception {
		for (final Role r: Arrays.asList(Role.CREATE_ADMIN, Role.SERV_TOKEN, Role.DEV_TOKEN)) {
			failDeleteRole(new UserName("admin"), r,
					new UnauthorizedException(ErrorType.UNAUTHORIZED));
		}
	}
	
	@Test
	public void deleteRoleFailRoot() throws Exception {
		failDeleteRole(UserName.ROOT, Role.ROOT,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
	}
	
	@Test
	public void deleteRoleFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failDeleteRole(auth, null, "foo", new NullPointerException("token"));
	
		failDeleteRole(auth, new IncomingToken("foo"), null,
				new MissingParameterException("roleId cannot be null or empty"));
		failDeleteRole(auth, new IncomingToken("foo"), "   \t   ",
				new MissingParameterException("roleId cannot be null or empty"));
	}
	
	@Test
	public void deleteRoleFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
			
		failDeleteRole(auth, token, "foo", new InvalidTokenException());
	}
	
	@Test
	public void deleteRoleFailBadTokenType() throws Exception {
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
		
		failDeleteRole(auth, token, "foo", new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Agent tokens are not allowed for this operation"));
		failDeleteRole(auth, token, "foo", new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Developer tokens are not allowed for this operation"));
		failDeleteRole(auth, token, "foo", new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void deleteRoleFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		when(storage.getUser(new UserName("baz"))).thenThrow(new NoSuchUserException("baz"));
			
		failDeleteRole(auth, token, "foo", new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	@Test
	public void deleteRoleFailDisabled() throws Exception {
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
		
		failDeleteRole(auth, token, "foo", new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("baz"));
	}
	
	private void successDeleteRole(final UserName adminName, final Role adminRole)
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
		
		auth.deleteCustomRole(token, "someRole");

		verify(storage).deleteCustomRole("someRole");
	}
	
	private void failDeleteRole(
			final UserName adminName,
			final Role adminRole,
			final Exception e) {
		try {
			successDeleteRole(adminName, adminRole);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failDeleteRole(
			final Authentication auth,
			final IncomingToken token,
			final String role,
			final Exception e) {
		try {
			auth.deleteCustomRole(token, role);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getCustomRolesAdmin() throws Exception {
		succeedGetCustomRoles(UserName.ROOT, Role.ROOT, true);
		succeedGetCustomRoles(new UserName("foo"), Role.CREATE_ADMIN, true);
		succeedGetCustomRoles(new UserName("foo"), Role.ADMIN, true);
	}
	
	@Test
	public void getCustomRolesStdUser() throws Exception {
		succeedGetCustomRoles(UserName.ROOT, Role.ROOT, true);
		for (final Role r: Arrays.asList(Role.CREATE_ADMIN, Role.ADMIN, Role.SERV_TOKEN,
				Role.DEV_TOKEN)) {
			succeedGetCustomRoles(new UserName("foo"), r, false);
		}
	}
	
	@Test
	public void getCustomRolesFailAdmin() throws Exception {
		failGetCustomRoles(Role.DEV_TOKEN, true,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
		failGetCustomRoles(Role.SERV_TOKEN, true,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
		
	}
	
	@Test
	public void getCustomRolesFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetCustomRoles(auth, (IncomingToken) null, true, new NullPointerException("token"));
		failGetCustomRoles(auth, (IncomingToken) null, false, new NullPointerException("token"));
	}
	
	@Test
	public void getCustomRolesFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
			
		failGetCustomRoles(auth, token, true, new InvalidTokenException());
		failGetCustomRoles(auth, token, false, new InvalidTokenException());
	}
	
	@Test
	public void getCustomRolesFailBadTokenType() throws Exception {
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
				new HashedToken(UUID.randomUUID(), TokenType.AGENT, null, "foo",
						new UserName("bar"), Instant.now(), Instant.now()),
				new HashedToken(UUID.randomUUID(), TokenType.DEV, null, "foo",
						new UserName("bar"), Instant.now(), Instant.now()),
				new HashedToken(UUID.randomUUID(), TokenType.SERV, null, "foo",
						new UserName("bar"), Instant.now(), Instant.now()),
				null);
		
		failGetCustomRoles(auth, token, true, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Agent tokens are not allowed for this operation"));
		failGetCustomRoles(auth, token, true, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Developer tokens are not allowed for this operation"));
		failGetCustomRoles(auth, token, true, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Service tokens are not allowed for this operation"));
		failGetCustomRoles(auth, token, false, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Agent tokens are not allowed for this operation"));
		failGetCustomRoles(auth, token, false, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Developer tokens are not allowed for this operation"));
		failGetCustomRoles(auth, token, false, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void getCustomRolesFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		when(storage.getUser(new UserName("baz"))).thenThrow(new NoSuchUserException("baz"));
			
		failGetCustomRoles(auth, token, true, new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	@Test
	public void getCustomRolesFailDisabled() throws Exception {
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
		
		failGetCustomRoles(auth, token, true, new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("baz"));
	}

	private void succeedGetCustomRoles(final UserName un, final Role r, final boolean forceAdmin)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", un, Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				un, new DisplayName("foobar"), Instant.now())
				.withRole(r).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (HashedToken) null);
		
		when(storage.getUser(un)).thenReturn(u, (AuthUser) null);
		
		when(storage.getCustomRoles()).thenReturn(
				set(new CustomRole("a", "b"), new CustomRole("c", "d")));
		
		final Set<CustomRole> roles = auth.getCustomRoles(token, forceAdmin);
		
		assertThat("incorrect roles", roles,
				is(set(new CustomRole("c", "d"), new CustomRole("a", "b"))));
	}
	
	private void failGetCustomRoles(final Role r, final boolean forceAdmin, final Exception e) {
		try {
			succeedGetCustomRoles(new UserName("wubba"), r, forceAdmin);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failGetCustomRoles(
			final Authentication auth,
			final IncomingToken token,
			final boolean forceAdmin,
			final Exception e) {
		try {
			auth.getCustomRoles(token, forceAdmin);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void updateCustomRole() throws Exception {
		succeedUpdateCustomRole(new UserName("admin"), Role.ADMIN);
	}
	
	@Test
	public void updateCustomRoleFailRole() throws Exception {
		failUpdateCustomRole(UserName.ROOT, Role.ROOT,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
		for (final Role r: Arrays.asList(Role.CREATE_ADMIN, Role.SERV_TOKEN, Role.DEV_TOKEN)) {
			failUpdateCustomRole(new UserName("admin"), r,
					new UnauthorizedException(ErrorType.UNAUTHORIZED));
		}
	}
	
	@Test
	public void updateCustomRoleFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		final IncomingToken t = new IncomingToken("foo");
		final UserName un = new UserName("bar");
		final Set<String> mt = Collections.emptySet();
		
		failUpdateCustomRole(auth, null, un, mt, mt, new NullPointerException("token"));
		failUpdateCustomRole(auth, t, null, mt, mt, new NullPointerException("userName"));
		failUpdateCustomRole(auth, t, un, null, mt, new NullPointerException("addRoles"));
		failUpdateCustomRole(auth, t, un, set("f", null), mt, new NullPointerException(
				"Null role in addRoles"));
		failUpdateCustomRole(auth, t, un, mt, null, new NullPointerException("removeRoles"));
		failUpdateCustomRole(auth, t, un, mt, set("f", null), new NullPointerException(
				"Null role in removeRoles"));
	}
	
	@Test
	public void updateCustomRoleFailIntersection() throws Exception {
		final Authentication auth = initTestMocks().auth;
		final IncomingToken t = new IncomingToken("foo");
		final UserName un = new UserName("bar");
		
		failUpdateCustomRole(auth, t, un, set("foo", "bar"), set("bar", "baz"),
				new IllegalParameterException(
						"One or more roles is to be both removed and added: bar"));
	}
	
	@Test
	public void updateCustomRoleFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failUpdateCustomRole(auth, token, new UserName("bar"), set("foo"), set("bar"),
				new InvalidTokenException());
	}
	
	@Test
	public void updateCustomRoleFailBadTokenType() throws Exception {
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
		
		failUpdateCustomRole(auth, token, new UserName("bar"), set("foo"), set("bar"),
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Agent tokens are not allowed for this operation"));
		failUpdateCustomRole(auth, token, new UserName("bar"), set("foo"), set("bar"),
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Developer tokens are not allowed for this operation"));
		failUpdateCustomRole(auth, token, new UserName("bar"), set("foo"), set("bar"),
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Service tokens are not allowed for this operation"));
	}
	
	@Test
	public void updateCustomRolesFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("baz"), Instant.now(), Instant.now());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		when(storage.getUser(new UserName("baz"))).thenThrow(new NoSuchUserException("baz"));
			
		failUpdateCustomRole(auth, token, new UserName("bar"), set("foo"), set("bar"),
				new RuntimeException("There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	@Test
	public void updateCustomRolesFailDisabled() throws Exception {
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
		
		failUpdateCustomRole(auth, token, new UserName("bar"), set("foo"), set("bar"),
				new DisabledUserException());
		
		verify(storage).deleteTokens(new UserName("baz"));
	}
	
	@Test
	public void updateCustomRolesFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("admin"), Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (HashedToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(u, (AuthUser) null);
		
		doThrow(new NoSuchUserException("whee"))
				.when(storage).updateCustomRoles(new UserName("whee"), set("baz"), set("bat"));
		
		failUpdateCustomRole(auth, token, new UserName("whee"), set("baz"), set("bat"),
				new NoSuchUserException("whee"));
	}
	
	@Test
	public void updateCustomRolesFailNoSuchRole() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", new UserName("admin"), Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("admin"), new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (HashedToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(u, (AuthUser) null);
		
		doThrow(new NoSuchRoleException("bat"))
				.when(storage).updateCustomRoles(new UserName("whee"), set("baz"), set("bat"));
		
		failUpdateCustomRole(auth, token, new UserName("whee"), set("baz"), set("bat"),
				new NoSuchRoleException("bat"));
	}

	private void succeedUpdateCustomRole(final UserName adminUser, final Role withRole)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final HashedToken htoken = new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null,
				"wubba", adminUser, Instant.now(), Instant.now());
		
		final AuthUser u = AuthUser.getBuilder(
				adminUser, new DisplayName("foobar"), Instant.now())
				.withRole(withRole).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (HashedToken) null);
		
		when(storage.getUser(adminUser)).thenReturn(u, (AuthUser) null);
		
		auth.updateCustomRoles(token, new UserName("someuser"), set("foo", "bar"),
				set("baz", "bat"));
		
		verify(storage).updateCustomRoles(new UserName("someuser"), set("foo", "bar"),
				set("baz", "bat"));
	}
	
	private void failUpdateCustomRole(
			final UserName admin,
			final Role withRole,
			final Exception e) {
		try {
			succeedUpdateCustomRole(admin, withRole);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failUpdateCustomRole(
			final Authentication auth,
			final IncomingToken token,
			final UserName name,
			final Set<String> add,
			final Set<String> remove,
			final Exception e) {
		try {
			auth.updateCustomRoles(token, name, add, remove);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
