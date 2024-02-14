package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.UserSearchSpec.Builder;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationGetAvailableUserNameTest {
	
	private static final DisplayName DISPNAME;
	static {
		try {
			DISPNAME = new DisplayName("unused");
		} catch (Exception e) {
			throw new RuntimeException("Fix yer tests nub", e);
		}
	}

	private UserSearchSpec getTestSpec(final String searchName) throws Exception {
		final Builder b = UserSearchSpec.getBuilder();

		final Method m = UserSearchSpec.Builder.class.getDeclaredMethod(
				"withSearchRegex", String.class);
		m.setAccessible(true);
		m.invoke(b, "^" + Pattern.quote(searchName) + "\\d*$");
		
		final UserSearchSpec spec = b.withIncludeDisabled(true).withSearchOnUserName(true).build();
		
		return spec;
	}
	
	@Test
	public void failGetAvailableUserName() throws Exception {
		final Authentication auth = initTestMocks().auth;
		try {
			auth.getAvailableUserName(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("suggestedUserName"));
		}
	}

	@Test
	public void getAvailableUserNameNoMatchNum0() throws Exception {
		
		final String suggestedUserName = "  !# 999  45FOO0*(^";
		final String searchName = "foo";
		final Map<UserName, DisplayName> names = new HashMap<>();
		names.put(new UserName("foo1"), DISPNAME);
		names.put(new UserName("foo2"), DISPNAME);
		names.put(new UserName("foo26"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("foo0"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameNoMatchNum1() throws Exception {
		
		final String suggestedUserName = "  !# 999  45FOO1*(^";
		final String searchName = "foo";
		final Map<UserName, DisplayName> names = new HashMap<>();
		names.put(new UserName("foo0"), DISPNAME);
		names.put(new UserName("foo2"), DISPNAME);
		names.put(new UserName("foo26"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("foo1"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameNoMatchNum2() throws Exception {
		
		final String suggestedUserName = "  !# 999  45FOO2*(^";
		final String searchName = "foo";
		final Map<UserName, DisplayName> names = new HashMap<>();
		names.put(new UserName("foo0"), DISPNAME);
		names.put(new UserName("foo1"), DISPNAME);
		names.put(new UserName("foo3"), DISPNAME);
		names.put(new UserName("foo26"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("foo2"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameWithMatch() throws Exception {
		
		final String suggestedUserName = "  !# 999  45FOO*(^";
		final String searchName = "foo";
		final Map<UserName, DisplayName> names = new HashMap<>();
		names.put(new UserName("foo"), DISPNAME);
		names.put(new UserName("foo2"), DISPNAME);
		names.put(new UserName("foo3"), DISPNAME);
		names.put(new UserName("foo5"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("foo4"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameWithNumMatch() throws Exception {
		
		final String suggestedUserName = "  !# 999  45FOO3*(^";
		final String searchName = "foo";
		final Map<UserName, DisplayName> names = new HashMap<>();
		names.put(new UserName("foo2"), DISPNAME);
		names.put(new UserName("foo3"), DISPNAME);
		names.put(new UserName("foo4"), DISPNAME);
		names.put(new UserName("foo6"), DISPNAME);
		names.put(new UserName("foo24"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("foo5"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameWithNumMatchEarly() throws Exception {
		
		final String suggestedUserName = "  !# 999  45FOO3*(^";
		final String searchName = "foo";
		final Map<UserName, DisplayName> names = new HashMap<>();
		names.put(new UserName("foo3"), DISPNAME);
		names.put(new UserName("foo4"), DISPNAME);
		names.put(new UserName("foo6"), DISPNAME);
		names.put(new UserName("foo24"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("foo2"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameWithMatchNoNums() throws Exception {
		
		final String suggestedUserName = "  !# 999  45FOOp*(^";
		final String searchName = "foop";
		final Map<UserName, DisplayName> names = new HashMap<>();
		names.put(new UserName("foop"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("foop2"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameIllegalNameNoNames() throws Exception {
		
		final String suggestedUserName = "  !# 999  45*(^";
		final String searchName = "user";
		final Map<UserName, DisplayName> names = new HashMap<>();
		final Optional<UserName> expected = Optional.of(new UserName("user1"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameIllegalNameWithNames() throws Exception {
		
		final String suggestedUserName = "  !# 999  45*(^";
		final String searchName = "user";
		final Map<UserName, DisplayName> names = new HashMap<>();
		names.put(new UserName("user1"), DISPNAME);
		names.put(new UserName("user2"), DISPNAME);
		names.put(new UserName("user4"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("user3"));

		getAvailableUserName(suggestedUserName, searchName, expected, names);
	}
	
	@Test
	public void getAvailableUserNameMaxNameLength() throws Exception {
		
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < UserName.MAX_NAME_LENGTH - 1; i++) {
			sb.append("a");
		}
		final String searchName = sb.toString();
		
		final String suggestedUserName = searchName + 1;
		
		final Map<UserName, DisplayName> names1 = new HashMap<>();
		for (int i = 1; i < 10; i++) {
			names1.put(new UserName(searchName + i), DISPNAME);
		}
		final Map<UserName, DisplayName> names2 = new HashMap<>();
		names2.put(new UserName("user1"), DISPNAME);
		names2.put(new UserName("user2"), DISPNAME);
		names2.put(new UserName("user4"), DISPNAME);
		final Optional<UserName> expected = Optional.of(new UserName("user3"));

		getAvailableUserName(suggestedUserName, searchName, expected, names1, names2);
	}

	private void getAvailableUserName(
			final String suggestedUserName,
			final String searchName,
			final Optional<UserName> expected,
			final Map<UserName, DisplayName> names1)
			throws Exception {
		getAvailableUserName(suggestedUserName, searchName, expected, names1, null);
	}
	
	private void getAvailableUserName(
			final String suggestedUserName,
			final String searchName,
			final Optional<UserName> expected,
			final Map<UserName, DisplayName> names1,
			final Map<UserName, DisplayName> names2)
			throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final UserSearchSpec spec = getTestSpec(searchName);
		final UserSearchSpec spec2 = getTestSpec("user");
		
		when(storage.getUserDisplayNames(spec, -1)).thenReturn(names1);
		if (names2 != null) {
			when(storage.getUserDisplayNames(spec2, -1)).thenReturn(names2);
		}
		
		final Optional<UserName> available = auth.getAvailableUserName(suggestedUserName);
		
		assertThat("incorrect username", available, is(expected));
	}
	
}
