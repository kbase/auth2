package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static us.kbase.test.auth2.TestCommon.set;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.api.Admin;
import us.kbase.auth2.service.api.Admin.UpdateUserRoles;
import us.kbase.test.auth2.TestCommon;

public class AdminTest {
	
	private static final UUID UID1 = UUID.randomUUID();
	private static final UUID UID2 = UUID.randomUUID();
	
	@Test
	public void anonIDsToUserNamesNullAndEmpty() throws Exception {
		anonIdsToUserNamesNullAndEmpty(null);
		anonIdsToUserNamesNullAndEmpty("  \t    \n   ");
	}

	private void anonIdsToUserNamesNullAndEmpty(final String anonIDs) throws Exception {
		final Authentication auth = mock(Authentication.class);
		
		final Admin admin = new Admin(auth);
		
		when(auth.getUserNamesFromAnonymousIDs(new IncomingToken("whee"), set())).thenReturn(
				Collections.emptyMap());
		
		assertThat("incorrect users", admin.anonIDsToUserNames("whee", anonIDs),
				is(Collections.emptyMap()));
		
		// if the when above doesn't match it still returns an empty map so we verify here
		verify(auth).getUserNamesFromAnonymousIDs(new IncomingToken("whee"), set());
	}
	
	@Test
	public void anonIDsToUserNames() throws Exception {
		final Authentication auth = mock(Authentication.class);
		
		final Admin admin = new Admin(auth);
		
		when(auth.getUserNamesFromAnonymousIDs(new IncomingToken("whee"), set(UID2, UID1)))
				.thenReturn(ImmutableMap.of(UID1, new UserName("bar"), UID2, new UserName("foo")));
		
		final Map<String, String> ret = admin.anonIDsToUserNames(
				"whee", String.format("    \t  %s  ,   %s \n ", UID1, UID2));
		
		assertThat("incorrect users", ret,
				is(ImmutableMap.of(UID1.toString(), "bar", UID2.toString(), "foo")));
	}
	
	@Test
	public void anonIDsToUserNamesFailInputs() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final String t = "token";
		final String a = "b8e62d05-1968-4aa0-916d-8815ab69ea15";
		
		anonIDsToUserNamesFail(admin, t, a + ", foobar, " + a, new IllegalParameterException(
				"Illegal anonymous user ID [foobar]: Invalid UUID string: foobar"));
		// error message is different for java 8 & 11. When 8 is gone switch back to exact test
		anonIDsToUserNamesFailContains(admin, t, a + "x", 
				"Illegal anonymous user ID [b8e62d05-1968-4aa0-916d-8815ab69ea15x]: ");
		anonIDsToUserNamesFail(admin, t, a + ",   , " + a, new IllegalParameterException(
				"Illegal anonymous user ID []: Invalid UUID string: "));
		
		anonIDsToUserNamesFail(admin, null, a, new NoTokenProvidedException(
				"No user token provided"));
		anonIDsToUserNamesFail(admin, "   \n   \t ", a, new NoTokenProvidedException(
				"No user token provided"));
	}
	
	private void anonIDsToUserNamesFail(
			final Admin admin,
			final String token,
			final String anonIDs,
			final Exception expected) {
		try {
			admin.anonIDsToUserNames(token, anonIDs);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	private void anonIDsToUserNamesFailContains(
			final Admin admin,
			final String token,
			final String anonIDs,
			final String expected)
			throws Exception {
		try {
			admin.anonIDsToUserNames(token, anonIDs);
			fail("expected exception");
		} catch (IllegalParameterException got) {
			TestCommon.assertExceptionMessageContains(got, expected);
		}
	}

	/* updateUserRoles tests */

	@Test
	public void updateUserRolesNullBody() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		updateUserRolesFail(admin, "token", "username", null,
				new MissingParameterException("JSON body missing"));
	}

	@Test
	public void updateUserRolesInvalidRole() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				Arrays.asList("InvalidRole"), null, null, null);

		updateUserRolesFail(admin, "token", "username", update,
				new IllegalParameterException("Invalid role: InvalidRole"));
	}

	@Test
	public void updateUserRolesNullInRolesList() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				Arrays.asList("Admin", null), null, null, null);

		updateUserRolesFail(admin, "token", "username", update,
				new IllegalParameterException("Null item in roles list"));
	}

	@Test
	public void updateUserRolesNullInCustomRolesList() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				null, null, Arrays.asList("custom1", null), null);

		updateUserRolesFail(admin, "token", "username", update,
				new IllegalParameterException("Null item in custom roles list"));
	}

	@Test
	public void updateUserRolesAdditionalProperties() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(null, null, null, null);
		update.setAdditionalProperties("unexpected", "value");

		updateUserRolesFail(admin, "token", "username", update,
				new IllegalParameterException("Unexpected parameters in request: unexpected"));
	}

	@Test
	public void updateUserRolesSuccess() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				Arrays.asList("Admin"),
				Arrays.asList("DevToken"),
				Arrays.asList("custom1"),
				Arrays.asList("custom2"));

		admin.updateUserRoles("token", "testuser", update);

		verify(auth).updateRoles(
				new IncomingToken("token"),
				new UserName("testuser"),
				set(Role.ADMIN),
				set(Role.DEV_TOKEN));

		verify(auth).updateCustomRoles(
				new IncomingToken("token"),
				new UserName("testuser"),
				set("custom1"),
				set("custom2"));
	}

	@Test
	public void updateUserRolesOnlyBuiltIn() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				Arrays.asList("Admin", "ServToken"), null, null, null);

		admin.updateUserRoles("token", "testuser", update);

		verify(auth).updateRoles(
				new IncomingToken("token"),
				new UserName("testuser"),
				set(Role.ADMIN, Role.SERV_TOKEN),
				Collections.emptySet());

		verify(auth, never()).updateCustomRoles(any(), any(), any(), any());
	}

	@Test
	public void updateUserRolesOnlyCustom() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				null, null, Arrays.asList("custom1"), Arrays.asList("custom2"));

		admin.updateUserRoles("token", "testuser", update);

		verify(auth, never()).updateRoles(any(), any(), any(), any());

		verify(auth).updateCustomRoles(
				new IncomingToken("token"),
				new UserName("testuser"),
				set("custom1"),
				set("custom2"));
	}

	@Test
	public void updateUserRolesEmptyLists() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				Collections.emptyList(), Collections.emptyList(),
				Collections.emptyList(), Collections.emptyList());

		admin.updateUserRoles("token", "testuser", update);

		// Neither method should be called when all lists are empty
		verify(auth, never()).updateRoles(any(), any(), any(), any());
		verify(auth, never()).updateCustomRoles(any(), any(), any(), any());
	}

	@Test
	public void updateUserRolesOnlyRemoveBuiltIn() throws Exception {
		// Tests the second branch of: !addRoles.isEmpty() || !removeRoles.isEmpty()
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				null, Arrays.asList("DevToken"), null, null);

		admin.updateUserRoles("token", "testuser", update);

		verify(auth).updateRoles(
				new IncomingToken("token"),
				new UserName("testuser"),
				Collections.emptySet(),
				set(Role.DEV_TOKEN));

		verify(auth, never()).updateCustomRoles(any(), any(), any(), any());
	}

	@Test
	public void updateUserRolesOnlyRemoveCustom() throws Exception {
		// Tests the second branch of: !addCustomRoles.isEmpty() || !removeCustomRoles.isEmpty()
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				null, null, null, Arrays.asList("customToRemove"));

		admin.updateUserRoles("token", "testuser", update);

		verify(auth, never()).updateRoles(any(), any(), any(), any());

		verify(auth).updateCustomRoles(
				new IncomingToken("token"),
				new UserName("testuser"),
				Collections.emptySet(),
				set("customToRemove"));
	}

	@Test
	public void updateUserRolesNoToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final Admin admin = new Admin(auth);

		final UpdateUserRoles update = new UpdateUserRoles(
				Arrays.asList("Admin"), null, null, null);

		updateUserRolesFail(admin, null, "username", update,
				new NoTokenProvidedException("No user token provided"));
	}

	private void updateUserRolesFail(
			final Admin admin,
			final String token,
			final String userName,
			final UpdateUserRoles update,
			final Exception expected) {
		try {
			admin.updateUserRoles(token, userName, update);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
}
