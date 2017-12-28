package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.service.api.TestMode;
import us.kbase.auth2.service.api.TestMode.CreateTestUser;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.TestCommon;

public class TestModeTest {

	/* Since the TestMode class is only intended to be instantiated by the Jersey framework,
	 * we do not test for null constructor inputs.
	 */
	
	@Test
	public void createUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new UserName("foobar"))).thenReturn(AuthUser.getBuilder(
				new UserName("foobar"), new DisplayName("foo bar"), Instant.ofEpochMilli(10000))
				.build());
		
		final Map<String, Object> au = tm.createTestUser(new CreateTestUser("foobar", "foo bar"));
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "foobar")
				.with("display", "foo bar")
				.with("created", 10000L)
				.with("lastlogin", null)
				.with("roles", Collections.emptyList())
				.with("customroles", Collections.emptySet())
				.with("policyids", Collections.emptyList())
				.with("local", true)
				.with("email", null)
				.with("idents", Collections.emptyList())
				.build();
		
		assertThat("incorrect user", au, is(expected));
		
		verify(auth).testModeCreateUser(new UserName("foobar"), new DisplayName("foo bar"));
	}
	
	@Test
	public void createUserFailNull() {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		failCreateUser(tm, null, new MissingParameterException("JSON body missing"));
	}
	
	@Test
	public void createUserFailAddlProps() {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		final CreateTestUser ctu = new CreateTestUser("foo", "bar");
		ctu.setAdditionalProperties("whee", "whoo");
		failCreateUser(tm, ctu, new IllegalParameterException(
				"Unexpected parameters in request: whee"));
	}
	
	@Test
	public void createUserFailRootUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		
		doThrow(new UnauthorizedException("Cannot create root user"))
				.when(auth).testModeCreateUser(
						new UserName("***ROOT***"), new DisplayName("root baby"));
		
		final TestMode tm = new TestMode(auth);
		final CreateTestUser ctu = new CreateTestUser("***ROOT***", "root baby");
		failCreateUser(tm, ctu, new UnauthorizedException(
				"Cannot create root user"));
	}
	
	@Test
	public void createUserFailNoSuchUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new UserName("foobar")))
				.thenThrow(new NoSuchUserException("foobar"));
		
		final CreateTestUser ctu = new CreateTestUser("foobar", "foo bar");
		failCreateUser(tm, ctu, new RuntimeException(
				"Neat, user creation is totally busted: 50000 No such user: foobar"));
	}
	
	private void failCreateUser(
			final TestMode tm,
			final CreateTestUser create,
			final Exception expected) {
		try {
			tm.createTestUser(create);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		
		when(auth.testModeGetUser(new UserName("foobar"))).thenReturn(AuthUser.getBuilder(
				new UserName("foobar"), new DisplayName("foo bar"), Instant.ofEpochMilli(10000))
				.build());
		
		final Map<String, Object> au = tm.getTestUser("foobar");
		
		final Map<String, Object> expected = MapBuilder.<String, Object>newHashMap()
				.with("user", "foobar")
				.with("display", "foo bar")
				.with("created", 10000L)
				.with("lastlogin", null)
				.with("roles", Collections.emptyList())
				.with("customroles", Collections.emptySet())
				.with("policyids", Collections.emptyList())
				.with("local", true)
				.with("email", null)
				.with("idents", Collections.emptyList())
				.build();
		
		assertThat("incorrect user", au, is(expected));
	}
	
	@Test
	public void getUserFailNull() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		failGetUser(tm, null, new MissingParameterException("user name"));
	}
	
	@Test
	public void getUserFailNoSuchUser() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final TestMode tm = new TestMode(auth);
		when(auth.testModeGetUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		failGetUser(tm, "foo", new NoSuchUserException("foo"));
	}
	
	private void failGetUser(
			final TestMode tm,
			final String userName,
			final Exception expected) {
		try {
			tm.getTestUser(userName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
}
