package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;

import org.junit.Test;

import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.UserSearchSpec.SearchField;
import us.kbase.test.auth2.TestCommon;

public class UserSearchSpecTest {

	@Test
	public void buildWithEverything() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchPrefix("Foo")
				.withSearchOnUserName(true)
				.withSearchOnDisplayName(true)
				.withSearchOnRole(Role.ADMIN)
				.withSearchOnRole(Role.DEV_TOKEN)
				.withSearchOnCustomRole("bar")
				.withSearchOnCustomRole("baz")
				.build();
		
		assertThat("incorrect prefix", uss.getSearchPrefix().get(), is("foo"));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(true));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(true));
		assertThat("incorrect search roles", uss.getSearchRoles(),
				is(set(Role.DEV_TOKEN, Role.ADMIN)));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(set("baz", "bar")));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		
	}
	
	@Test
	public void buildWithNothing() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder().build();
		assertThat("incorrect prefix", uss.getSearchPrefix().isPresent(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(false));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
	}
	
	@Test
	public void buildWithPrefixOnly() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchPrefix("foO").build();
		assertThat("incorrect prefix", uss.getSearchPrefix().get(), is("foo"));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
	}
	
	@Test
	public void buildUserSearch() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchPrefix("foo")
				.withSearchOnUserName(true).build();
		assertThat("incorrect prefix", uss.getSearchPrefix().get(), is("foo"));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(false));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
	}
	
	@Test
	public void buildDisplaySearch() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchPrefix("foo")
				.withSearchOnDisplayName(true)
				.withSearchOnCustomRole("bar")
				.withSearchOnRole(Role.SERV_TOKEN).build();
		assertThat("incorrect prefix", uss.getSearchPrefix().get(), is("foo"));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(true));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(true));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(set(Role.SERV_TOKEN)));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(), is(set("bar")));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.DISPLAYNAME));
	}
	
	@Test
	public void buildCustomRoleSearch() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchOnCustomRole("foo")
				.withSearchOnRole(Role.DEV_TOKEN).build();
		assertThat("incorrect prefix", uss.getSearchPrefix().isPresent(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(false));
		assertThat("incorrect role search", uss.isRoleSearch(), is(true));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(true));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(set(Role.DEV_TOKEN)));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(), is(set("foo")));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.CUSTOMROLE));
	}
	
	@Test
	public void buildRoleSearch() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchOnRole(Role.DEV_TOKEN).build();
		assertThat("incorrect prefix", uss.getSearchPrefix().isPresent(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(false));
		assertThat("incorrect role search", uss.isRoleSearch(), is(true));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(set(Role.DEV_TOKEN)));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.ROLE));
	}
	
	@Test
	public void resetSearch() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder().withSearchPrefix("foo")
				.withSearchOnUserName(false).withSearchOnDisplayName(false).build();
		assertThat("incorrect prefix", uss.getSearchPrefix().get(), is("foo"));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
	}
	
	@Test
	public void immutableRoles() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchOnRole(Role.DEV_TOKEN).build();
		try {
			uss.getSearchRoles().add(Role.ADMIN);
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			//test passed
		}
	}
	
	@Test
	public void immutableCustomRoles() {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchOnCustomRole("foo").build();
		try {
			uss.getSearchCustomRoles().add("bar");
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			//test passed
		}
	}
	
	@Test
	public void addPrefixFail() {
		failAddPrefix(null, new IllegalArgumentException(
				"Prefix cannot be null or the empty string"));
		failAddPrefix("   \t   \n  ", new IllegalArgumentException(
				"Prefix cannot be null or the empty string"));
	}
	
	private void failAddPrefix(final String prefix, final Exception e) {
		try {
			UserSearchSpec.getBuilder().withSearchPrefix(prefix);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void setUserSearchFail() {
		try {
			UserSearchSpec.getBuilder().withSearchOnUserName(true);
			fail("expected exception");
		} catch (IllegalStateException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("Must provide a prefix if a name search is to occur"));
		}
	}
	
	@Test
	public void setDisplaySearchFail() {
		try {
			UserSearchSpec.getBuilder().withSearchOnDisplayName(true);
			fail("expected exception");
		} catch (IllegalStateException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("Must provide a prefix if a name search is to occur"));
		}
	}
	
	@Test
	public void addRoleFail() {
		try {
			UserSearchSpec.getBuilder().withSearchOnRole(null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception mesasge", e.getMessage(), is("role"));
		}
		
	}
	
	@Test
	public void addCustomRoleFail() {
		failAddCustomRole(null, new IllegalArgumentException(
				"Custom role cannot be null or the empty string"));
		failAddCustomRole(" \n \t    ", new IllegalArgumentException(
				"Custom role cannot be null or the empty string"));
	}
	
	private void failAddCustomRole(final String role, final Exception e) {
		try {
			UserSearchSpec.getBuilder().withSearchOnCustomRole(role);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
