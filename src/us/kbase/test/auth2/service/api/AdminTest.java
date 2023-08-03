package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.api.Admin;
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
}
