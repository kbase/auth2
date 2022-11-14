package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedList;

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
					.withEmailAddress(new EmailAddress("f@h.com")).build();
			AUTH_USER2 = AuthUser.getBuilder(
					new UserName("foo5"), new DisplayName("bar5"), Instant.now())
					.withEmailAddress(new EmailAddress("f@h5.com"))
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
		final LoginState ls = LoginState.getBuilder("foo", false, Instant.ofEpochMilli(1000))
				.build();
		assertThat("incorrect provider", ls.getProvider(), is("foo"));
		assertThat("incorrect non-admin login", ls.isNonAdminLoginAllowed(), is(false));
		assertThat("incorrect num users", ls.getUsers().size(), is(0));
		assertThat("incorrect num identities", ls.getIdentities().size(), is(0));
		assertThat("incorrect expires", ls.getExpires(), is(Instant.ofEpochMilli(1000)));
	}
	
	@Test
	public void buildFailNullsAndEmpties() {
		failStartBuild(null, Instant.now(),
				new IllegalArgumentException("provider cannot be null or empty"));
		failStartBuild("  \t    \n", Instant.now(),
				new IllegalArgumentException("provider cannot be null or empty"));
		failStartBuild("p", null, new NullPointerException("expires"));
	}
	
	private void failStartBuild(
			final String provider,
			final Instant expires,
			final Exception e) {
		try {
			LoginState.getBuilder(provider, false, expires);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void buildWithIdentities() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", false, Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE1).withIdentity(REMOTE2).build();
		assertThat("incorrect provider", ls.getProvider(), is("prov"));
		assertThat("incorrect non-admin login", ls.isNonAdminLoginAllowed(), is(false));
		assertThat("incorrect num users", ls.getUsers().size(), is(0));
		assertThat("incorrect identities", ls.getIdentities(), is(set(REMOTE2, REMOTE1)));
		assertThat("incorrect expires", ls.getExpires(),
				is(Instant.ofEpochMilli(20000)));
	}
	
	@Test
	public void buildWithUsers() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", true, Instant.ofEpochMilli(5000))
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
		assertThat("incorrect expires", ls.getExpires(), is(Instant.ofEpochMilli(5000)));
	}
	
	@Test
	public void buildWithUsersAndIdentities() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", false, Instant.ofEpochMilli(10000))
				.withUser(AUTH_USER2, REMOTE3).withIdentity(REMOTE1)
				.build();
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
		assertThat("incorrect expires", ls.getExpires(),
				is(Instant.ofEpochMilli(10000)));
	}
	
	@Test
	public void sortedUserNames() throws Exception {
		final DisplayName dn = new DisplayName("d");
		final Instant now = Instant.now();
		final LoginState ls = LoginState.getBuilder("prov", false, Instant.now())
				.withUser(AuthUser.getBuilder(new UserName("foo"), dn, now)
						.withIdentity(REMOTE1).build(), REMOTE1)
				.withUser(AuthUser.getBuilder(new UserName("bar"), dn, now)
						.withIdentity(REMOTE2).build(), REMOTE2)
				.withUser(AuthUser.getBuilder(new UserName("baz"), dn, now)
						.withIdentity(REMOTE3).build(), REMOTE3)
				.build();
		
		assertThat("user names aren't sorted", new LinkedList<>(ls.getUsers()),
				is(Arrays.asList(new UserName("bar"), new UserName("baz"), new UserName("foo"))));
	}
	
	@Test
	public void sortedUnlinkedIdentities() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", false, Instant.now())
				.withIdentity(REMOTE3) // id is b5bc5fbd0e014aedb8541109a6536eca
				.withIdentity(REMOTE1) // id is 225fa1634408e1c55c984bd8b199587e
				.withIdentity(REMOTE2) // id is 589bebde3cf9c926f88420769025677b
				.build();
		assertThat("idents aren't sorted", new LinkedList<>(ls.getIdentities()),
				is(Arrays.asList(REMOTE1, REMOTE2, REMOTE3)));
	}
	
	@Test
	public void sortedLinkedIdentities() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("dn"), Instant.now())
				.withIdentity(REMOTE3)
				.withIdentity(REMOTE1)
				.withIdentity(REMOTE2)
				.build();
		
		final LoginState ls = LoginState.getBuilder("prov", false, Instant.now())
				.withUser(u, REMOTE3) // id is b5bc5fbd0e014aedb8541109a6536eca
				.withUser(u, REMOTE1) // id is 225fa1634408e1c55c984bd8b199587e
				.withUser(u, REMOTE2) // id is 589bebde3cf9c926f88420769025677b
				.build();
		assertThat("user idents aren't sorted",
				new LinkedList<>(ls.getIdentities(new UserName("foo"))),
						is(Arrays.asList(REMOTE1, REMOTE2, REMOTE3)));
	}
	
	@Test
	public void unmodifiable() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", false, Instant.now())
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
		failAddIdentity(LoginState.getBuilder("prov", false, Instant.now()), null,
				new NullPointerException("remoteID"));
		
		failAddIdentity(LoginState.getBuilder("prov1", false, Instant.now()), REMOTE1,
				new IllegalStateException(
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
		failAddUser(LoginState.getBuilder("prov", false, Instant.now()), null, REMOTE1,
				new NullPointerException("user"));
		
		failAddUser(LoginState.getBuilder("prov", false, Instant.now()), AUTH_USER1, null,
				new NullPointerException("remoteID"));
		
		failAddUser(LoginState.getBuilder("prov1", false, Instant.now()), AUTH_USER1, REMOTE1,
				new IllegalStateException(
						"Cannot have multiple providers in the same login state"));
		
		failAddUser(LoginState.getBuilder("prov", false, Instant.now()), AUTH_USER1, REMOTE2,
				new IllegalArgumentException("user does not contain remote ID"));
	}
	
	@Test
	public void noSuchUser() throws Exception {
		final LoginState ls = LoginState.getBuilder("prov", false, Instant.now())
				.withUser(AUTH_USER2, REMOTE3).withIdentity(REMOTE1).build();
		
		try {
			ls.getIdentities(null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("correct exception message", e.getMessage(), is("name"));
		}
		try {
			ls.getIdentities(new UserName("foo4"));
			fail("expected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("No such user: foo4"));
		}
		
		try {
			ls.getUser(null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("correct exception message", e.getMessage(), is("name"));
		}
		try {
			ls.getUser(new UserName("foo4"));
			fail("expected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("No such user: foo4"));
		}
		
		try {
			ls.isAdmin(null);
			fail("expected exception");
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
