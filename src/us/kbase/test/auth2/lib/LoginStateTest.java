package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LoginState;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.test.auth2.TestCommon;

public class LoginStateTest {
	
	private static final Date NOW = new Date();
	
	private static final RemoteIdentityWithLocalID REMOTE1 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715c9"),
			new RemoteIdentityID("prov", "bar"),
			new RemoteIdentityDetails("user", "full", "email"));
	
	private static final RemoteIdentityWithLocalID REMOTE2 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d9"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentityWithLocalID REMOTE3 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c5671539"),
			new RemoteIdentityID("prov", "bar3"),
			new RemoteIdentityDetails("user3", "full3", "email3"));
	
	private final static AuthUser AUTH_USER1;
	private final static AuthUser AUTH_USER2;
	static {
		try {
			AUTH_USER1 = new NewUser(new UserName("foo4"), new EmailAddress("f@g.com"),
					new DisplayName("bar4"), REMOTE1, null);
			AUTH_USER2 = new AuthUserSuppliedCRoles(new UserName("foo5"),
					new EmailAddress("f@g5.com"), new DisplayName("bar5"), set(REMOTE2, REMOTE3),
					set(Role.ADMIN), Collections.emptySet(), NOW, NOW, new UserDisabledState());
		} catch (Exception e) {
			throw new RuntimeException("fix yer tests newb", e);
		}
	}

	@Test
	public void buildMinimal() throws Exception {
		final LoginState ls = new LoginState.Builder("foo", false).build();
		assertThat("incorrect provider", ls.getProvider(), is("foo"));
		assertThat("incorrect non-admin login", ls.isNonAdminLoginAllowed(), is(false));
		assertThat("incorrect num users", ls.getUsers().size(), is(0));
		assertThat("incorrect num identities", ls.getIdentities().size(), is(0));
		
		failStartBuild(null, new IllegalArgumentException("provider cannot be null or empty"));
		failStartBuild("  \t    \n",
				new IllegalArgumentException("provider cannot be null or empty"));
	}
	
	private void failStartBuild(final String provider, final Exception e) {
		try {
			new LoginState.Builder(null, false);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void buildWithIdentities() throws Exception {
		final LoginState ls = new LoginState.Builder("prov", false)
				.withIdentity(REMOTE1).withIdentity(REMOTE2).build();
		assertThat("incorrect provider", ls.getProvider(), is("prov"));
		assertThat("incorrect non-admin login", ls.isNonAdminLoginAllowed(), is(false));
		assertThat("incorrect num users", ls.getUsers().size(), is(0));
		assertThat("incorrect identities", ls.getIdentities(), is(set(REMOTE2, REMOTE1)));
	}
	
	@Test
	public void buildWithUsers() throws Exception {
		final LoginState ls = new LoginState.Builder("prov", true)
				.withUser(AUTH_USER1, REMOTE1).withUser(AUTH_USER2, REMOTE3)
				.withUser(AUTH_USER2, REMOTE2).build();
		assertThat("incorrect provider", ls.getProvider(), is("prov"));
		assertThat("incorrect non-admin login", ls.isNonAdminLoginAllowed(), is(true));
		assertThat("incorrect num identities", ls.getIdentities().size(), is(0));
		assertThat("incorrect user names", ls.getUsers(),
				is(set(new UserName("foo4"), new UserName("foo5"))));
		assertThat("incorrect identities for user", ls.getIdentities(new UserName("foo4")),
				is(set(REMOTE1)));
		assertThat("incorrect identities for user", ls.getIdentities(new UserName("foo5")),
				is(set(REMOTE2, REMOTE3)));
		
		assertThat("incorrect AuthUser", ls.getUser(new UserName("foo4")).getUserName(),
				is(new UserName("foo4")));
		assertThat("incorrect AuthUser", ls.getUser(new UserName("foo4")).getDisplayName(),
				is(new DisplayName("bar4")));
		
		assertThat("incorrect AuthUser", ls.getUser(new UserName("foo5")).getUserName(),
				is(new UserName("foo5")));
		assertThat("incorrect AuthUser", ls.getUser(new UserName("foo5")).getDisplayName(),
				is(new DisplayName("bar5")));
		
		assertThat("incorrect admin", ls.isAdmin(new UserName("foo4")), is(false));
		assertThat("incorrect admin", ls.isAdmin(new UserName("foo5")), is(true));
	}
	
	@Test
	public void buildWithUsersAndIdentities() throws Exception {
		final LoginState ls = new LoginState.Builder("prov", false)
				.withUser(AUTH_USER2, REMOTE3).withIdentity(REMOTE1).build();
		assertThat("incorrect provider", ls.getProvider(), is("prov"));
		assertThat("incorrect non-admin login", ls.isNonAdminLoginAllowed(), is(false));
		assertThat("incorrect identities", ls.getIdentities(), is(set(REMOTE1)));
		
		assertThat("incorrect user names", ls.getUsers(), is(set(new UserName("foo5"))));
		assertThat("incorrect identities for user", ls.getIdentities(new UserName("foo5")),
				is(set(REMOTE3)));
		
		assertThat("incorrect AuthUser", ls.getUser(new UserName("foo5")).getUserName(),
				is(new UserName("foo5")));
		assertThat("incorrect AuthUser", ls.getUser(new UserName("foo5")).getDisplayName(),
				is(new DisplayName("bar5")));
		
		assertThat("incorrect admin", ls.isAdmin(new UserName("foo5")), is(true));
	}
	
	@Test
	public void unmodifiable() throws Exception {
		final LoginState ls = new LoginState.Builder("prov", false)
				.withUser(AUTH_USER2, REMOTE3).withIdentity(REMOTE1).build();
		
		try {
			ls.getIdentities().add(REMOTE2);
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passes
		}
		
		try {
			ls.getUsers().add(new UserName("whee"));
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passes
		}
		
		try {
			ls.getIdentities(new UserName("foo5")).add(REMOTE2);
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passes
		}
	}
	
	private void failAddIdentity(
			final LoginState.Builder b,
			final RemoteIdentityWithLocalID ri, 
			final Exception e) {
		try {
			b.withIdentity(ri);
			fail("excpected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void addIdentityFail() throws Exception {
		failAddIdentity(new LoginState.Builder("prov", false), null,
				new NullPointerException("remoteID"));
		
		failAddIdentity(new LoginState.Builder("prov1", false), REMOTE1, new IllegalStateException(
				"Cannot have multiple providers in the same login state"));
	}
	
	private void failAddUser(
			final LoginState.Builder b,
			final AuthUser u,
			final RemoteIdentityWithLocalID ri,
			final Exception e) {
		try {
			b.withUser(u, ri);
			fail("excpected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void addUserFail() throws Exception {
		failAddUser(new LoginState.Builder("prov", false), null, REMOTE1,
				new NullPointerException("user"));
		
		failAddUser(new LoginState.Builder("prov", false), AUTH_USER1, null,
				new NullPointerException("remoteID"));
		
		failAddUser(new LoginState.Builder("prov1", false), AUTH_USER1, REMOTE1,
				new IllegalStateException(
						"Cannot have multiple providers in the same login state"));
		
		failAddUser(new LoginState.Builder("prov", false), AUTH_USER1, REMOTE2,
				new IllegalArgumentException("user does not contain remote ID"));
	}
	
	@Test
	public void noSuchUser() throws Exception {
		final LoginState ls = new LoginState.Builder("prov", false)
				.withUser(AUTH_USER2, REMOTE3).withIdentity(REMOTE1).build();
		
		try {
			ls.getIdentities(null);
			fail("excpected exception");
		} catch (NullPointerException e) {
			assertThat("correct exception message", e.getMessage(), is("name"));
		}
		try {
			ls.getIdentities(new UserName("foo4"));
			fail("excpected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("No such user: foo4"));
		}
		
		try {
			ls.getUser(null);
			fail("excpected exception");
		} catch (NullPointerException e) {
			assertThat("correct exception message", e.getMessage(), is("name"));
		}
		try {
			ls.getUser(new UserName("foo4"));
			fail("excpected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("No such user: foo4"));
		}
		
		try {
			ls.isAdmin(null);
			fail("excpected exception");
		} catch (NullPointerException e) {
			assertThat("correct exception message", e.getMessage(), is("name"));
		}
		try {
			ls.isAdmin(new UserName("foo4"));
			fail("excpected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("No such user: foo4"));
		}
	}
}
