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
import us.kbase.auth2.lib.LinkIdentities;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;

public class LinkIdentitiesTest {
	
	private final static RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar"),
			new RemoteIdentityDetails("user", "full", "email"));
	
	private final static RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentity REMOTE3 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar3"),
			new RemoteIdentityDetails("user3", "full3", "email3"));
			
	private final static AuthUser AUTH_USER;
	static {
		try {
			AUTH_USER = AuthUser.getBuilder(
					new UserName("foo"), new DisplayName("bar"), Instant.now())
					.withEmailAddress(new EmailAddress("f@g.com"))
					.withIdentity(REMOTE1).build();
		} catch (Exception e) {
			throw new RuntimeException("fix yer tests newb", e);
		}
	}
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(LinkIdentities.class).usingGetClass().verify();
	}
	
	@Test
	public void buildMinimal() throws Exception {
		final LinkIdentities li = LinkIdentities.getBuilder(
				new UserName("foo"), "prov", Instant.ofEpochMilli(10000)).build();
		
		assertThat("incorrect username", li.getUser(), is(new UserName("foo")));
		assertThat("incorrect provider", li.getProvider(), is("prov"));
		assertThat("incorrect expires", li.getExpires(), is(Instant.ofEpochMilli(10000)));
		assertThat("incorrect indets", li.getIdentities(), is(set()));
		assertThat("incorrect linked users", li.getLinkedUsers(), is(set()));
	}
	
	@Test
	public void nullsAndEmpties() throws Exception {
		final Instant i = Instant.ofEpochMilli(10000);
		final UserName u = new UserName("foo");
		failBuildStart(null, "p", i, new NullPointerException("userName"));
		failBuildStart(u, null, i, new IllegalArgumentException(
				"provider cannot be null or empty"));
		failBuildStart(u, "    \t    ", i, new IllegalArgumentException(
				"provider cannot be null or empty"));
		failBuildStart(u, "p", null, new NullPointerException("expires"));
	}
	
	private void failBuildStart(
			final UserName userName,
			final String provider,
			final Instant expires,
			final Exception e) {
		try {
			LinkIdentities.getBuilder(userName, provider, expires);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void buildWithIdentities() throws Exception {
		final LinkIdentities li = LinkIdentities.getBuilder(
				new UserName("whee"), "prov", Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE1).withIdentity(REMOTE2).build();
		
		assertThat("incorrect username", li.getUser(), is(new UserName("whee")));
		assertThat("incorrect provider", li.getProvider(), is("prov"));
		assertThat("incorrect expires", li.getExpires(), is(Instant.ofEpochMilli(10000)));
		assertThat("incorrect indets", li.getIdentities(), is(set(REMOTE1, REMOTE2)));
		assertThat("incorrect linked users", li.getLinkedUsers(), is(set()));
	}
	
	@Test
	public void addIdentityFail() throws Exception {
		final UserName u = new UserName("foo");
		failAddIdentity(LinkIdentities.getBuilder(u, "prov", Instant.now()), null,
				new NullPointerException("remoteID"));
		
		failAddIdentity(LinkIdentities.getBuilder(u, "prov1", Instant.now()), REMOTE1,
				new IllegalStateException(
						"Cannot have multiple providers in the same login state"));
	}

	private void failAddIdentity(
			final LinkIdentities.Builder b,
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
	public void buildWithUsers() throws Exception {
		final RemoteIdentity ri1 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("u1", "f1", "f1@g.com"));
		final RemoteIdentity ri2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("u2", "f2", "f2@g.com"));
		final AuthUser u = AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("d"), Instant.now())
				.withIdentity(ri1)
				.withIdentity(ri2)
				.build();
		final LinkIdentities li = LinkIdentities.getBuilder(
				new UserName("whee"), "prov", Instant.ofEpochMilli(10000))
				.withUser(AUTH_USER, REMOTE1)
				.withUser(u, ri1)
				.withUser(u, ri2)
				.build();
		
		assertThat("incorrect username", li.getUser(), is(new UserName("whee")));
		assertThat("incorrect provider", li.getProvider(), is("prov"));
		assertThat("incorrect expires", li.getExpires(), is(Instant.ofEpochMilli(10000)));
		assertThat("incorrect indets", li.getIdentities(), is(set()));
		assertThat("incorrect linked users", li.getLinkedUsers(),
				is(set(new UserName("bar"), new UserName("foo"))));
		assertThat("incorrect idents", li.getLinkedIdentities(new UserName("foo")),
				is(set(REMOTE1)));
		assertThat("incorrect idents", li.getLinkedIdentities(new UserName("bar")),
				is(set(ri1, ri2)));
	}
	
	@Test
	public void addUserFail() throws Exception {
		final UserName u = new UserName("foo");
		failAddUser(LinkIdentities.getBuilder(u, "prov", Instant.now()), null, REMOTE1,
				new NullPointerException("user"));
		
		failAddUser(LinkIdentities.getBuilder(u, "prov", Instant.now()), AUTH_USER, null,
				new NullPointerException("remoteID"));
		
		failAddUser(LinkIdentities.getBuilder(u, "prov1", Instant.now()), AUTH_USER, REMOTE1,
				new IllegalStateException(
						"Cannot have multiple providers in the same login state"));
		
		failAddUser(LinkIdentities.getBuilder(u, "prov", Instant.now()), AUTH_USER, REMOTE2,
				new IllegalArgumentException("user does not contain remote ID"));
	}
	
	private void failAddUser(
			final LinkIdentities.Builder b,
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
	public void buildWithIdentitiesAndUsers() throws Exception {
		final RemoteIdentity ri1 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("u1", "f1", "f1@g.com"));
		final RemoteIdentity ri2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("u2", "f2", "f2@g.com"));
		final AuthUser u = AuthUser.getBuilder(
				new UserName("bar"), new DisplayName("d"), Instant.now())
				.withIdentity(ri1)
				.withIdentity(ri2)
				.build();
		final LinkIdentities li = LinkIdentities.getBuilder(
				new UserName("whee"), "prov", Instant.ofEpochMilli(10000))
				.withUser(AUTH_USER, REMOTE1)
				.withUser(u, ri1)
				.withUser(u, ri2)
				.withIdentity(REMOTE2)
				.build();
		
		assertThat("incorrect username", li.getUser(), is(new UserName("whee")));
		assertThat("incorrect provider", li.getProvider(), is("prov"));
		assertThat("incorrect expires", li.getExpires(), is(Instant.ofEpochMilli(10000)));
		assertThat("incorrect indets", li.getIdentities(), is(set(REMOTE2)));
		assertThat("incorrect linked users", li.getLinkedUsers(),
				is(set(new UserName("bar"), new UserName("foo"))));
		assertThat("incorrect idents", li.getLinkedIdentities(new UserName("foo")),
				is(set(REMOTE1)));
		assertThat("incorrect idents", li.getLinkedIdentities(new UserName("bar")),
				is(set(ri1, ri2)));
	}
	
	@Test
	public void sortedUserNames() throws Exception {
		final DisplayName dn = new DisplayName("d");
		final Instant now = Instant.now();
		final LinkIdentities ls = LinkIdentities.getBuilder(
				new UserName("fake"), "prov", Instant.now())
				.withUser(AuthUser.getBuilder(new UserName("foo"), dn, now)
						.withIdentity(REMOTE1).build(), REMOTE1)
				.withUser(AuthUser.getBuilder(new UserName("bar"), dn, now)
						.withIdentity(REMOTE2).build(), REMOTE2)
				.withUser(AuthUser.getBuilder(new UserName("baz"), dn, now)
						.withIdentity(REMOTE3).build(), REMOTE3)
				.build();
		
		assertThat("user names aren't sorted", new LinkedList<>(ls.getLinkedUsers()),
				is(Arrays.asList(new UserName("bar"), new UserName("baz"), new UserName("foo"))));
	}
	
	@Test
	public void sortedUnlinkedIdentities() throws Exception {
		final LinkIdentities ls = LinkIdentities.getBuilder(
				new UserName("fake"), "prov", Instant.now())
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
		
		final LinkIdentities ls = LinkIdentities.getBuilder(
				new UserName("fake"), "prov", Instant.now())
				.withUser(u, REMOTE3) // id is b5bc5fbd0e014aedb8541109a6536eca
				.withUser(u, REMOTE1) // id is 225fa1634408e1c55c984bd8b199587e
				.withUser(u, REMOTE2) // id is 589bebde3cf9c926f88420769025677b
				.build();
		assertThat("user idents aren't sorted",
				new LinkedList<>(ls.getLinkedIdentities(new UserName("foo"))),
						is(Arrays.asList(REMOTE1, REMOTE2, REMOTE3)));
	}
	
	@Test
	public void unmodifiable() throws Exception {
		final LinkIdentities ls = LinkIdentities.getBuilder(
				new UserName("fake"), "prov", Instant.now())
				.withUser(AUTH_USER, REMOTE1).withIdentity(REMOTE2).build();
		
		try {
			ls.getIdentities().add(REMOTE2);
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passes
		}
		
		try {
			ls.getLinkedUsers().add(new UserName("whee"));
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passes
		}
		
		try {
			ls.getLinkedIdentities(new UserName("foo")).add(REMOTE2);
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passes
		}
	}
	
	@Test
	public void noSuchUser() throws Exception {
		final LinkIdentities ls = LinkIdentities.getBuilder(
				new UserName("fake"), "prov", Instant.now())
				.withUser(AUTH_USER, REMOTE1).withIdentity(REMOTE3).build();
		
		try {
			ls.getLinkedIdentities(null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("correct exception message", e.getMessage(), is("userName"));
		}
		try {
			ls.getLinkedIdentities(new UserName("foo4"));
			fail("expected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("No such user: foo4"));
		}
	}
}
