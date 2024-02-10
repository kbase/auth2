package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.InOrder;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.TestModeException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationTestModeRoleTest {
	
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
	public void createRole() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final Clock clock = testauth.clockMock;
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		auth.testModeSetCustomRole(new CustomRole("foo", "bar"));
		
		verify(storage).testModeSetCustomRole(
				new CustomRole("foo", "bar"), Instant.ofEpochMilli(3610000));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, "Created test custom role foo",
				Authentication.class));
	}
	
	@Test
	public void createRoleFailNull() throws Exception {
		failCreateRole(initTestMocks(true).auth, null, new NullPointerException("role"));
	}
	
	@Test
	public void createRoleFailNoTestMode() throws Exception {
		failCreateRole(initTestMocks(false).auth, new CustomRole("i", "d"),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	private void failCreateRole(
			final Authentication auth,
			final CustomRole role,
			final Exception expected) {
		try {
			auth.testModeSetCustomRole(role);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getRoles() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.testModeGetCustomRoles()).thenReturn(new HashSet<>(Arrays.asList(
				new CustomRole("i", "d"), new CustomRole("i2", "d2"))));
		
		final Set<CustomRole> roles = auth.testModeGetCustomRoles();
		
		assertThat("incorrect roles", roles, is(new HashSet<>(Arrays.asList(
				new CustomRole("i", "d"), new CustomRole("i2", "d2")))));
		
		assertLogEventsCorrect(logEvents, new LogEvent(
				Level.INFO, "Accessed test mode custom roles", Authentication.class));
	}
	
	@Test
	public void getRoleFail() {
		try {
			initTestMocks(false).auth.testModeGetCustomRoles();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got,
					new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
		}
	}
	
	@Test
	public void setAndRemoveUserRoles() throws Exception {
		final TestMocks testauth = initTestMocks(true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final InOrder order = inOrder(storage, storage);
			
		auth.testModeSetRoles(
				new UserName("foo"), set(Role.ADMIN, Role.DEV_TOKEN), set("bar", "baz"));
		auth.testModeSetRoles(new UserName("foo"), set(), set());

		order.verify(storage).testModeSetRoles(
				new UserName("foo"), set(Role.ADMIN, Role.DEV_TOKEN), set("bar", "baz"));
		order.verify(storage).testModeSetRoles(new UserName("foo"), set(), set());
		
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO,
						"Set roles / custom roles on test user foo: Admin, DevToken / bar, baz",
						Authentication.class),
				new LogEvent(Level.INFO,
						"Set roles / custom roles on test user foo:  / ",
						Authentication.class));
	}
	
	@Test
	public void setUserRolesFailNulls() throws Exception {
		final Authentication auth = initTestMocks(true).auth;
		final UserName u = new UserName("foo");
		
		failSetUserRoles(auth, null, set(), set(), new NullPointerException("userName"));
		failSetUserRoles(auth, u, null, set(), new NullPointerException("roles"));
		failSetUserRoles(auth, u, set(), null, new NullPointerException("customRoles"));
		failSetUserRoles(auth, u, set(Role.ADMIN, null), set(),
				new NullPointerException("Null role in roles"));
		failSetUserRoles(auth, u, set(), set("bar", null),
				new NullPointerException("Null role in customRoles"));
	}
	
	@Test
	public void setUserRolesFailNoTestMode() throws Exception {
		failSetUserRoles(initTestMocks(false).auth, new UserName("foo"), set(), set(),
				new TestModeException(ErrorType.UNSUPPORTED_OP, "Test mode is not enabled"));
	}
	
	private void failSetUserRoles(
			final Authentication auth,
			final UserName userName,
			final Set<Role> roles,
			final Set<String> customRoles,
			final Exception expected) {
		try {
			auth.testModeSetRoles(userName, roles, customRoles);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}

}
