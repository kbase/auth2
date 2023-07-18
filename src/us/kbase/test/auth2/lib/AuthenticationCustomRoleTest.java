package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
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
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationCustomRoleTest {
	
	private static List<ILoggingEvent> logEvents;
	
	private static final UUID UID = UUID.randomUUID();
	
	@BeforeClass
	public static void beforeClass() {
		logEvents = AuthenticationTester.setUpSLF4JTestLoggerAppender();
	}
	
	@Before
	public void before() {
		logEvents.clear();
	}
	
	@Test
	public void createRole() throws Exception {
		final UserName adminName = new UserName("admin");
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), adminName)
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				adminName, UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(adminName)).thenReturn(u, (AuthUser) null);
		
		auth.setCustomRole(token, new CustomRole("id", "desc"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Admin admin set custom role id", Authentication.class));
		
		verify(storage).setCustomRole(new CustomRole("id", "desc"));
	}
	
	@Test
	public void createRoleExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.setCustomRole(token, new CustomRole("baz", "bar"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "set custom role baz";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	@Test
	public void createRoleFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failCreateRole(auth, null, new CustomRole("a", "b"), new NullPointerException("token"));
		failCreateRole(auth, new IncomingToken("foo"), null, new NullPointerException("role"));
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
		final UserName adminName = new UserName("admin");
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), adminName)
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				adminName, UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(adminName)).thenReturn(u, (AuthUser) null);
		
		auth.deleteCustomRole(token, "someRole");
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Admin admin deleted custom role someRole", Authentication.class));
		
		verify(storage).deleteCustomRole("someRole");
	}
	
	@Test
	public void deleteRoleExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.deleteCustomRole(token, "baz");
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "delete custom role baz";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
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
		succeedGetCustomRoles(UserName.ROOT, Role.ROOT, false);
		for (final Role r: Arrays.asList(Role.CREATE_ADMIN, Role.ADMIN, Role.SERV_TOKEN,
				Role.DEV_TOKEN)) {
			succeedGetCustomRoles(new UserName("foo"), r, false);
		}
	}
	
	@Test
	public void getCustomRolesExecuteStandardTokenCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardTokenCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getCustomRoles(token, false);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get custom roles";
			}
		});
	}
	
	@Test
	public void getCustomRolesAsAdminExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getCustomRoles(token, true);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get custom roles as admin";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN));
	}
	
	@Test
	public void getCustomRolesFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetCustomRoles(auth, (IncomingToken) null, true, new NullPointerException("token"));
		failGetCustomRoles(auth, (IncomingToken) null, false, new NullPointerException("token"));
	}
	
	private void succeedGetCustomRoles(final UserName un, final Role r, final boolean forceAdmin)
			throws Exception {
		logEvents.clear();
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), un)
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				un, UID, new DisplayName("foobar"), Instant.now())
				.withRole(r).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(un)).thenReturn(u, (AuthUser) null);
		
		when(storage.getCustomRoles()).thenReturn(
				set(new CustomRole("a", "b"), new CustomRole("c", "d")));
		
		final Set<CustomRole> roles = auth.getCustomRoles(token, forceAdmin);
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"User %s accessed all custom roles", un.getName()), Authentication.class));
		
		assertThat("incorrect roles", roles,
				is(set(new CustomRole("c", "d"), new CustomRole("a", "b"))));
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
		succeedUpdateCustomRole(set("foo", "bar"), set("baz", "bat"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Admin admin added custom roles to user someuser: bar, foo", Authentication.class),
				new LogEvent(Level.INFO,
						"Admin admin removed custom roles from user someuser: bat, baz",
						Authentication.class));
	}
	
	@Test
	public void updateCustomRoleEmpty() throws Exception {
		succeedUpdateCustomRole(set(), set());
		
		assertThat("No log events generated", logEvents.isEmpty(), is(true));
	}
	
	@Test
	public void updateCustomRoleAddOnly() throws Exception {
		succeedUpdateCustomRole(set("foo", "bar"), set());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Admin admin added custom roles to user someuser: bar, foo",
				Authentication.class));
	}
	
	@Test
	public void updateCustomRoleRemoveOnly() throws Exception {
		succeedUpdateCustomRole(set(), set("baz", "bat"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
						"Admin admin removed custom roles from user someuser: bat, baz",
						Authentication.class));
	}
	
	@Test
	public void updateCustomRolesExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.updateCustomRoles(token, new UserName("whee"), set("a", "b"), set("c"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "update custom roles for user whee";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
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
	public void updateCustomRolesFailNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("admin"), UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
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
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("admin"), UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(u, (AuthUser) null);
		
		doThrow(new NoSuchRoleException("bat"))
				.when(storage).updateCustomRoles(new UserName("whee"), set("baz"), set("bat"));
		
		failUpdateCustomRole(auth, token, new UserName("whee"), set("baz"), set("bat"),
				new NoSuchRoleException("bat"));
	}

	private void succeedUpdateCustomRole(
			final Set<String> add,
			final Set<String> remove)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobarbaz");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("admin"), UID, new DisplayName("foobar"), Instant.now())
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(new UserName("admin"))).thenReturn(u, (AuthUser) null);
		
		auth.updateCustomRoles(token, new UserName("someuser"), add, remove);
		
		verify(storage).updateCustomRoles(new UserName("someuser"), add, remove);
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
