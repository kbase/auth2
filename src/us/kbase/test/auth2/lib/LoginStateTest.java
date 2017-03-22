package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LoginState;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class LoginStateTest {
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar"),
			new RemoteIdentityDetails("user", "full", "email"));
	
	private static final RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentity REMOTE3 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar3"),
			new RemoteIdentityDetails("user3", "full3", "email3"));
	
	private final static AuthUser AUTH_USER1;
	private final static AuthUser AUTH_USER2;
	static {
		try {
			AUTH_USER1 = NewUser.getBuilder(
					new UserName("foo4"), new DisplayName("bar4"), Instant.now(), REMOTE1)
					.withEmailAddress(new EmailAddress("f@g.com")).build();
			AUTH_USER2 = AuthUser.getBuilder(
					new UserName("foo5"), new DisplayName("bar5"), Instant.now())
					.withEmailAddress(new EmailAddress("f@g5.com"))
					.withIdentity(REMOTE2).withIdentity(REMOTE3)
					.withRole(Role.ADMIN)
					.build();
		} catch (Exception e) {
			throw new RuntimeException("fix yer tests newb", e);
		}
	}
	
	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(LoginState.class).usingGetClass().verify();
	}

	@Test
	public void buildMinimal() throws Exception {
		final LoginState ls = LoginState.getBuilder("foo", false).build();
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
			LoginState.getBuilder(null, false);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void buildWithIdentities() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", false)
				.withIdentity(REMOTE1).withIdentity(REMOTE2).build();
		assertThat("incorrect provider", ls.getProvider(), is("prov"));
		assertThat("incorrect non-admin login", ls.isNonAdminLoginAllowed(), is(false));
		assertThat("incorrect num users", ls.getUsers().size(), is(0));
		assertThat("incorrect identities", ls.getIdentities(), is(set(REMOTE2, REMOTE1)));
	}
	
	@Test
	public void buildWithUsers() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", true)
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
		final LoginState ls = LoginState.getBuilder("prov", false)
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
		final LoginState ls = LoginState.getBuilder("prov", false)
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
			final RemoteIdentity ri, 
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
		failAddIdentity(LoginState.getBuilder("prov", false), null,
				new NullPointerException("remoteID"));
		
		failAddIdentity(LoginState.getBuilder("prov1", false), REMOTE1, new IllegalStateException(
				"Cannot have multiple providers in the same login state"));
	}
	
	private void failAddUser(
			final LoginState.Builder b,
			final AuthUser u,
			final RemoteIdentity ri,
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
		failAddUser(LoginState.getBuilder("prov", false), null, REMOTE1,
				new NullPointerException("user"));
		
		failAddUser(LoginState.getBuilder("prov", false), AUTH_USER1, null,
				new NullPointerException("remoteID"));
		
		failAddUser(LoginState.getBuilder("prov1", false), AUTH_USER1, REMOTE1,
				new IllegalStateException(
						"Cannot have multiple providers in the same login state"));
		
		failAddUser(LoginState.getBuilder("prov", false), AUTH_USER1, REMOTE2,
				new IllegalArgumentException("user does not contain remote ID"));
	}
	
	@Test
	public void noSuchUser() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", false)
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
