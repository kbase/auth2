package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.TestCommon.list;
import static us.kbase.test.auth2.TestCommon.opt;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Optional;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.UserSearchSpec.Builder;
import us.kbase.auth2.lib.UserSearchSpec.SearchField;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.test.auth2.TestCommon;

public class UserSearchSpecTest {
	
	private static final Optional<String> MT = Optional.empty();
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(UserSearchSpec.class).usingGetClass().verify();
	}

	@Test
	public void buildWithEverything() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchPrefix("F*oo bar  *() baz_bat")
				.withSearchOnUserName(true)
				.withSearchOnDisplayName(true)
				.withSearchOnRole(Role.ADMIN)
				.withSearchOnRole(Role.DEV_TOKEN)
				.withSearchOnCustomRole("bar")
				.withSearchOnCustomRole("baz")
				.withIncludeRoot(true)
				.withIncludeDisabled(true)
				.build();
		
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(),
				is(list("foo", "bar", "baz_bat")));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(),
				is(list("foo", "bar", "bazbat")));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(true));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(true));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(true));
		assertThat("incorrect search roles", uss.getSearchRoles(),
				is(set(Role.DEV_TOKEN, Role.ADMIN)));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(set("baz", "bar")));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(true));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(true));
	}
	
	@Test
	public void buildWithNothing() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder().build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list()));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list()));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(false));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(false));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void buildWithPrefixOnly() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchPrefix("foO").build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list("foo")));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list("foo")));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(true));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void buildUserSearch() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchPrefix("foo")
				.withSearchOnUserName(true).build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list("foo")));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list("foo")));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(true));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(false));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void buildDisplaySearch() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchPrefix("foo")
				.withSearchOnDisplayName(true)
				.withSearchOnCustomRole("bar")
				.withSearchOnRole(Role.SERV_TOKEN).build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list("foo")));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list("foo")));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(true));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(true));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(true));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(set(Role.SERV_TOKEN)));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(), is(set("bar")));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.DISPLAYNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void buildCustomRoleSearch() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchOnCustomRole("foo")
				.withSearchOnRole(Role.DEV_TOKEN).build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list()));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list()));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(false));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(false));
		assertThat("incorrect role search", uss.isRoleSearch(), is(true));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(true));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(set(Role.DEV_TOKEN)));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(), is(set("foo")));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.CUSTOMROLE));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void buildRoleSearch() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchOnRole(Role.DEV_TOKEN).build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list()));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list()));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(false));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(false));
		assertThat("incorrect role search", uss.isRoleSearch(), is(true));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(set(Role.DEV_TOKEN)));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.ROLE));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void resetSearch() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder().withSearchPrefix("foo")
				.withSearchOnUserName(false).withSearchOnDisplayName(false).build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list("foo")));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list("foo")));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(true));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void regex() throws Exception {
		final Builder b = UserSearchSpec.getBuilder();
		setRegex(b, "\\Qfoo.bar\\E");
		final UserSearchSpec uss = b.build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list()));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list()));
		assertThat("incorrect regex", uss.getSearchRegex(), is(opt("\\Qfoo.bar\\E")));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(false));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(true));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}

	private void setRegex(final Builder b, final String regex) throws Exception {
		final Method m = UserSearchSpec.Builder.class
				.getDeclaredMethod("withSearchRegex", String.class);
		m.setAccessible(true);
		m.invoke(b, regex);
	}
	
	@Test
	public void prefixToRegex() throws Exception {
		final Builder b = UserSearchSpec.getBuilder().withSearchPrefix("foo");
		setRegex(b, "\\Qfoo.bar\\E");
		final UserSearchSpec uss = b.build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list()));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list()));
		assertThat("incorrect regex", uss.getSearchRegex(), is(opt("\\Qfoo.bar\\E")));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(false));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(true));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void regexToPrefix() throws Exception {
		final Builder b = UserSearchSpec.getBuilder();
		setRegex(b, "\\Qfoo.bar\\E");
		final UserSearchSpec uss = b.withSearchPrefix("foo").build();
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list("foo")));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list("foo")));
		assertThat("incorrect regex", uss.getSearchRegex(), is(MT));
		assertThat("incorrect has prefixes", uss.hasSearchPrefixes(), is(true));
		assertThat("incorrect has regex", uss.hasSearchRegex(), is(false));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(true));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
		assertThat("incorrect role search", uss.isRoleSearch(), is(false));
		assertThat("incorrect custom role search", uss.isCustomRoleSearch(), is(false));
		assertThat("incorrect search roles", uss.getSearchRoles(), is(Collections.emptySet()));
		assertThat("incorrect search custom roles", uss.getSearchCustomRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect orderby", uss.orderBy(), is(SearchField.USERNAME));
		assertThat("incorrect include root", uss.isRootIncluded(), is(false));
		assertThat("incorrect include disabled", uss.isDisabledIncluded(), is(false));
	}
	
	@Test
	public void immutablePrefixes() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder().withSearchPrefix("foo bar").build();
		try {
			uss.getSearchUserNamePrefixes().add("baz");
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			//test passed
		}
		try {
			uss.getSearchDisplayPrefixes().add("baz");
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			//test passed
		}
	}
	
	@Test
	public void immutableRoles() throws Exception {
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
	public void immutableCustomRoles() throws Exception {
		final UserSearchSpec uss = UserSearchSpec.getBuilder()
				.withSearchOnCustomRole("foo").build();
		try {
			uss.getSearchCustomRoles().add("bar");
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			//test passed
		}
	}
	
	private static final String ERR_USER_SEARCH = "The search prefix %s contains no valid "
			+ "username prefix and a user name search was requested";
	
	@Test
	public void buildUserSearchWithInvalidAndValidPrefixes() throws Exception {
		// if the user search spec is good, the display spec must be good. The reverse is not true.
		final Exception e = new IllegalParameterException(String.format(ERR_USER_SEARCH, "98_7"));
		final Builder b = UserSearchSpec.getBuilder()
				.withSearchPrefix("98_7"); // valid display spec, not user spec
		
		// test that no exception is thrown
		UserSearchSpec uss = b.build();
		buildUserSearchWithInvalidAndValidPrefixesAssertOnPass(uss);
		
		buildFail(b.withSearchOnUserName(true), e);
		
		// test that no exception is thrown
		uss = b.withSearchOnDisplayName(true).build();
		buildUserSearchWithInvalidAndValidPrefixesAssertOnPass(uss);
		
		// test that no exception is thrown
		uss = b.withSearchOnUserName(false).build();
		buildUserSearchWithInvalidAndValidPrefixesAssertOnPass(uss);
	}

	private void buildUserSearchWithInvalidAndValidPrefixesAssertOnPass(final UserSearchSpec uss) {
		assertThat("incorrect user prefix", uss.getSearchUserNamePrefixes(), is(list()));
		assertThat("incorrect display prefix", uss.getSearchDisplayPrefixes(), is(list("987")));
		assertThat("incorrect user search", uss.isUserNameSearch(), is(false));
		assertThat("incorrect display name search", uss.isDisplayNameSearch(), is(true));
	}

	private static final String ERR_DISPLAY_SEARCH = "The search prefix &*^(%(^*&) contains only "
			+ "punctuation and a display name search was requested";
	
	@Test
	public void buildDisplaySearchFail() throws Exception {
		// if the user search spec is good, the display spec must be good. The reverse is not true.
		final Exception e = new IllegalParameterException(ERR_DISPLAY_SEARCH);
		final Exception euser = new IllegalParameterException(
				String.format(ERR_USER_SEARCH, ("&*^(%(^*&)")));
		final Builder b = UserSearchSpec.getBuilder()
				.withSearchPrefix("&*^(%(^*&)");
		buildFail(b, e);
		
		buildFail(b.withSearchOnDisplayName(true), e);
		buildFail(b.withSearchOnUserName(true), e);
		buildFail(b.withSearchOnDisplayName(false), euser);
	}

	
	private void buildFail(final Builder b, final Exception expected) {
		try {
			b.build();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void addPrefixFail() {
		failAddPrefix(null, new IllegalArgumentException(
				"prefix cannot be null or whitespace only"));
		failAddPrefix("   \t   \n  ", new IllegalArgumentException(
				"prefix cannot be null or whitespace only"));
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
	public void addRegexFail() throws Exception {
		failAddRegex(null, new IllegalArgumentException(
				"regex cannot be null or whitespace only"));
		failAddRegex("   \t   \n  ", new IllegalArgumentException(
				"regex cannot be null or whitespace only"));
	}
	
	private void failAddRegex(final String regex, final Exception e) throws Exception {
		try {
			setRegex(UserSearchSpec.getBuilder(), regex);
			fail("expected exception");
		} catch (InvocationTargetException got) {
			TestCommon.assertExceptionCorrect((Exception) got.getCause(), e);
		}
	}
	
	@Test
	public void setUserSearchFail() {
		try {
			UserSearchSpec.getBuilder().withSearchOnUserName(true);
			fail("expected exception");
		} catch (IllegalStateException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("Must provide a prefix or regex if a name search is to occur"));
		}
	}
	
	@Test
	public void setDisplaySearchFail() {
		try {
			UserSearchSpec.getBuilder().withSearchOnDisplayName(true);
			fail("expected exception");
		} catch (IllegalStateException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("Must provide a prefix or regex if a name search is to occur"));
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
