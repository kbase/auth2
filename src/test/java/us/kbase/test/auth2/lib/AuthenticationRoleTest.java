package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationRoleTest {
	
	private static final UUID UID = UUID.randomUUID();
	
	private static List<ILoggingEvent> logEvents;
	
	@BeforeClass
	public static void beforeClass() {
		logEvents = AuthenticationTester.setUpSLF4JTestLoggerAppender();
	}
	
	@Before
	public void before() {
		logEvents.clear();
	}
	
	@Test
	public void removeRolesSuccess() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.SERV_TOKEN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, htoken, null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u, (AuthUser) null);
		
		auth.removeRoles(token, set(Role.SERV_TOKEN, Role.ADMIN));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User baz removed roles from user baz: Admin, ServToken",
				Authentication.class));
		
		verify(storage).updateRoles(
				new UserName("baz"), Collections.emptySet(), set(Role.ADMIN, Role.SERV_TOKEN));
	}
	
	@Test
	public void removeRolesFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		failRemoveRoles(auth, null, set(Role.SERV_TOKEN),
				new NullPointerException("token"));
		
		final IncomingToken token = new IncomingToken("foo");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		failRemoveRoles(auth, new IncomingToken("foo"), null,
				new NullPointerException("removeRoles"));
		failRemoveRoles(auth, new IncomingToken("foo"), set(Role.ADMIN, null),
				new NullPointerException("Null role in removeRoles"));
	}
	
	// remove roles pulls the token twice so we can't use the automated user tests
	@Test
	public void removeRolesExecuteStandardTokenCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardTokenCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.removeRoles(token, set(Role.ADMIN));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "remove roles";
			}
		});
	}
	
	@Test
	public void removeRolesFailCatastrophic() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken);
		
		when(storage.getUser(new UserName("baz"))).thenThrow(new NoSuchUserException("baz"));
			
		failRemoveRoles(auth, token, set(Role.ADMIN), new RuntimeException(
				"There seems to be an error in the " +
				"storage system. Token was valid, but no user"));
	}
	
	@Test
	public void removeRolesFailCatastrophic2() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.SERV_TOKEN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, htoken, null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u, (AuthUser) null);
		
		doThrow(new NoSuchUserException("baz")).when(storage).updateRoles(
				new UserName("baz"), Collections.emptySet(), set(Role.ADMIN, Role.SERV_TOKEN));
		
		failRemoveRoles(auth, token, set(Role.SERV_TOKEN, Role.ADMIN), new RuntimeException(
				"There seems to be an error in the storage system. Token was valid, but no user"));
	}
	
	@Test
	public void removeRolesFailDisabled() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.SERV_TOKEN)
				.withUserDisabledState(
						new UserDisabledState("foo", new UserName("bar"), Instant.now()))
				.build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, htoken, null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u);
			
		failRemoveRoles(auth, token, set(Role.ADMIN), new DisabledUserException("baz"));
		
		verify(storage).deleteTokens(new UserName("baz"));
	}
	
	@Test
	public void removeRolesFailRoot() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;

		final IncomingToken token = new IncomingToken("foo");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), UserName.ROOT)
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				UserName.ROOT, UID, new DisplayName("foobar"), Instant.now()).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, htoken, null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u);
			
		failRemoveRoles(auth, token, set(Role.ADMIN),
				new UnauthorizedException(ErrorType.UNAUTHORIZED, "Cannot change ROOT roles"));
	}
	
	private void failRemoveRoles(
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
	
	@Test
	public void updateRolesAsStdUserRemove() throws Exception {
		succeedUpdateRoles(new UserName("whee"), new UserName("whee"), Role.DEV_TOKEN,
				Collections.emptySet(), set(Role.DEV_TOKEN));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User whee removed roles from user whee: DevToken", Authentication.class));
	}
	
	@Test
	public void updateRolesAsAdmin() throws Exception {
		succeedUpdateRoles(new UserName("admin"), new UserName("whee"), Role.ADMIN,
				set(Role.DEV_TOKEN), set(Role.SERV_TOKEN));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
					"User admin added roles to user whee: DevToken", Authentication.class),
				new LogEvent(Level.INFO,
					"User admin removed roles from user whee: ServToken", Authentication.class));
	}
	
	@Test
	public void updateRolesAsAdminSelf() throws Exception {
		succeedUpdateRoles(new UserName("admin"), new UserName("admin"), Role.ADMIN,
				set(Role.DEV_TOKEN), set(Role.ADMIN, Role.SERV_TOKEN));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User admin added roles to user admin: DevToken", Authentication.class),
			new LogEvent(Level.INFO,
				"User admin removed roles from user admin: Admin, ServToken",
					Authentication.class));
	}
	
	@Test
	public void updateRolesAsCreateAdminAdd() throws Exception {
		succeedUpdateRoles(new UserName("admin"), new UserName("whee"), Role.CREATE_ADMIN,
				set(Role.ADMIN), Collections.emptySet());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User admin added roles to user whee: Admin", Authentication.class));
	}
	
	@Test
	public void updateRolesAsCreateAdminRemove() throws Exception {
		succeedUpdateRoles(new UserName("admin"), new UserName("whee"), Role.CREATE_ADMIN,
				Collections.emptySet(), set(Role.ADMIN));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User admin removed roles from user whee: Admin", Authentication.class));
	}
	
	@Test
	public void updateRolesAsCreateAdminSelfRemove() throws Exception {
		succeedUpdateRoles(new UserName("admin"), new UserName("admin"), Role.CREATE_ADMIN,
				Collections.emptySet(), set(Role.CREATE_ADMIN));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User admin removed roles from user admin: CreateAdmin", Authentication.class));
	}
	
	@Test
	public void updateRolesAsRootAdd() throws Exception {
		succeedUpdateRoles(UserName.ROOT, new UserName("whee"), Role.ROOT, set(Role.CREATE_ADMIN),
				Collections.emptySet());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User ***ROOT*** added roles to user whee: CreateAdmin", Authentication.class));
	}
	
	@Test
	public void updateRolesAsRootRemove() throws Exception {
		succeedUpdateRoles(UserName.ROOT, new UserName("whee"), Role.ROOT, Collections.emptySet(),
				set(Role.CREATE_ADMIN));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User ***ROOT*** removed roles from user whee: CreateAdmin",
				Authentication.class));
	}
	
	@Test
	public void updateRolesFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		final IncomingToken t = new IncomingToken("foo");
		final UserName u = new UserName("foo");
		final Set<Role> add = set(Role.ADMIN);
		final Set<Role> rem = set(Role.DEV_TOKEN);
		
		failUpdateRoles(auth, null, u, add, rem, new NullPointerException("token"));
		failUpdateRoles(auth, t, null, add, rem, new NullPointerException("userName"));
		failUpdateRoles(auth, t, u, null, rem, new NullPointerException("addRoles"));
		failUpdateRoles(auth, t, u, set(Role.ADMIN, null), rem,
				new NullPointerException("Null role in addRoles"));
		failUpdateRoles(auth, t, u, add, null, new NullPointerException("removeRoles"));
		failUpdateRoles(auth, t, u, add, set(Role.DEV_TOKEN, null),
				new NullPointerException("Null role in removeRoles"));
	}
	
	@Test
	public void updateRolesFailAddAndRemoveSameRole() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failUpdateRoles(auth, new IncomingToken("foo"), new UserName("bar"),
				set(Role.ADMIN, Role.DEV_TOKEN), set(Role.SERV_TOKEN, Role.DEV_TOKEN), 
				new IllegalParameterException("One or more roles is to be both removed and " +
						"added: Create developer tokens"));
	}
	
	@Test
	public void updateRolesFailRoot() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failUpdateRoles(auth, new IncomingToken("foo"), UserName.ROOT,
				set(Role.ADMIN, Role.DEV_TOKEN), set(Role.SERV_TOKEN), 
				new UnauthorizedException(ErrorType.UNAUTHORIZED, "Cannot change ROOT roles"));
	}
	
	@Test
	public void updateRolesExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.updateRoles(token, new UserName("bar"), set(Role.ADMIN), set(Role.DEV_TOKEN));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "update roles for user bar";
			}
		}, set());
	}
	
	@Test
	public void updateRolesFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("baz"), UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.CREATE_ADMIN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(u, (AuthUser) null);
		
		doThrow(new NoSuchUserException("bar")).when(storage).updateRoles(
				new UserName("bar"), set(Role.ADMIN), Collections.emptySet());
		
		failUpdateRoles(auth, token, new UserName("bar"), set(Role.ADMIN), Collections.emptySet(),
				new NoSuchUserException("bar"));
	}
	
	@Test
	public void updateUserFailRoot() throws Exception {
		for (final Role r: Arrays.asList(Role.ROOT, Role.ADMIN, Role.SERV_TOKEN, Role.DEV_TOKEN)) {
			failUpdateRoles(UserName.ROOT, new UserName("foo"), Role.ROOT, set(r),
					Collections.emptySet(), new UnauthorizedException(ErrorType.UNAUTHORIZED,
							"User ***ROOT*** is not authorized to grant role(s): " +
					r.getDescription()));
			failUpdateRoles(UserName.ROOT, new UserName("foo"), Role.ROOT, Collections.emptySet(),
					set(r), new UnauthorizedException(ErrorType.UNAUTHORIZED,
							"User ***ROOT*** is not authorized to remove role(s): " +
									r.getDescription()));
		}
	}
	
	@Test
	public void updateUserFailCreateAdmin() throws Exception {
		for (final Role r: Arrays.asList(Role.ROOT, Role.CREATE_ADMIN, Role.SERV_TOKEN,
				Role.DEV_TOKEN)) {
			failUpdateRoles(new UserName("bleah"), new UserName("foo"), Role.CREATE_ADMIN, set(r),
					Collections.emptySet(), new UnauthorizedException(ErrorType.UNAUTHORIZED,
							"User bleah is not authorized to grant role(s): " +
									r.getDescription()));
			failUpdateRoles(new UserName("bleah"), new UserName("foo"), Role.CREATE_ADMIN,
					Collections.emptySet(), set(r),
							new UnauthorizedException(ErrorType.UNAUTHORIZED,
									"User bleah is not authorized to remove role(s): " +
											r.getDescription()));
		}
	}
	
	@Test
	public void updateUserFailAdmin() throws Exception {
		for (final Role r: Arrays.asList(Role.ROOT, Role.CREATE_ADMIN, Role.ADMIN)) {
			failUpdateRoles(new UserName("bleah"), new UserName("foo"), Role.ADMIN, set(r),
					Collections.emptySet(), new UnauthorizedException(ErrorType.UNAUTHORIZED,
							"User bleah is not authorized to grant role(s): " +
									r.getDescription()));
			failUpdateRoles(new UserName("bleah"), new UserName("foo"), Role.ADMIN,
					Collections.emptySet(), set(r),
							new UnauthorizedException(ErrorType.UNAUTHORIZED,
									"User bleah is not authorized to remove role(s): " +
											r.getDescription()));
		}
	}
	
	private void succeedUpdateRoles(
			final UserName adminUser,
			final UserName targetUser,
			final Role withRole,
			final Set<Role> add,
			final Set<Role> remove)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), adminUser)
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				adminUser, UID, new DisplayName("foobar"), Instant.now())
				.withRole(withRole).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(adminUser)).thenReturn(u, (AuthUser) null);
		
		auth.updateRoles(token, targetUser, add, remove);
		
		verify(storage).updateRoles(targetUser, add, remove);
	}
	
	private void failUpdateRoles(
			final Authentication auth,
			final IncomingToken userToken,
			final UserName userName,
			final Set<Role> add,
			final Set<Role> remove,
			final Exception e)
			throws Exception {
		try {
			auth.updateRoles(userToken, userName, add, remove);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failUpdateRoles(
			final UserName adminUser,
			final UserName targetUser,
			final Role withRole,
			final Set<Role> add,
			final Set<Role> remove,
			final Exception e)
			throws Exception {
		
		try {
			succeedUpdateRoles(adminUser, targetUser, withRole, add, remove);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
