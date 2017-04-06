package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import com.google.common.base.Optional;

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
			new RemoteIdentityID("foo", "bar"),
			new RemoteIdentityDetails("user", "full", "email"));
	
	private final static RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("foo1", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
			
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
	public void constructWithIDsSuccess() throws Exception {
		final Set<RemoteIdentity> ids = new HashSet<>();
		ids.add(REMOTE2);
		
		final LinkIdentities li = new LinkIdentities(AUTH_USER, ids, Instant.ofEpochMilli(10000));
		
		//check the user is correct
		assertThat("incorrect username", li.getUser().getUserName(), is(new UserName("foo")));
		assertThat("incorrect email", li.getUser().getEmail(), is(new EmailAddress("f@g.com")));
		assertThat("incorrect displayname", li.getUser().getDisplayName(),
				is(new DisplayName("bar")));
		assertThat("incorrect user id number", li.getUser().getIdentities().size(), is(1));
		assertThat("incorrect user identity", li.getUser().getIdentities().iterator().next(), is(
				new RemoteIdentity(
						new RemoteIdentityID("foo", "bar"),
						new RemoteIdentityDetails("user", "full", "email"))));
		assertThat("incorrect creation date", li.getUser().getCreated(),
				is(AUTH_USER.getCreated()));
		assertThat("incorrect login date", li.getUser().getLastLogin(), is(Optional.absent()));
		
		// check provider is correct
		assertThat("incorrect provider", li.getProvider(), is("foo1"));
		
		// check expires is correct
		assertThat("incorrect expires", li.getExpires(),
				is(Optional.of(Instant.ofEpochMilli(10000))));
		
		//check the identity is correct
		assertThat("incorrect identity number", li.getIdentities().size(), is(1));
		assertThat("incorrect identity", li.getIdentities().iterator().next(), is(
				new RemoteIdentity(
						new RemoteIdentityID("foo1", "bar1"),
						new RemoteIdentityDetails("user1", "full1", "email1"))));
	}
	
	@Test
	public void constructWithoutIDsSuccess() throws Exception {
		final LinkIdentities li = new LinkIdentities(AUTH_USER, "foobar");
		
		//check the user is correct
		assertThat("incorrect username", li.getUser().getUserName(), is(new UserName("foo")));
		assertThat("incorrect email", li.getUser().getEmail(), is(new EmailAddress("f@g.com")));
		assertThat("incorrect displayname", li.getUser().getDisplayName(),
				is(new DisplayName("bar")));
		assertThat("incorrect user id number", li.getUser().getIdentities().size(), is(1));
		assertThat("incorrect user identity", li.getUser().getIdentities().iterator().next(), is(
				new RemoteIdentity(
						new RemoteIdentityID("foo", "bar"),
						new RemoteIdentityDetails("user", "full", "email"))));
		assertThat("incorrect creation date", li.getUser().getCreated(),
				is(AUTH_USER.getCreated()));
		assertThat("incorrect login date", li.getUser().getLastLogin(), is(Optional.absent()));
		
		// check provider is correct
		assertThat("incorrect provider", li.getProvider(), is("foobar"));
		
		// check expires is correct
		assertThat("incorrect expires", li.getExpires(), is(Optional.absent()));
		
		//check the identity is correct
		assertThat("incorrect identity number", li.getIdentities().size(), is(0));
	}
	
	@Test
	public void identitesAreUnmodifiable() throws Exception {
		final Set<RemoteIdentity> ids = new HashSet<>();
		ids.add(REMOTE2);
		
		final LinkIdentities li = new LinkIdentities(AUTH_USER, ids, Instant.now());
		assertThat("incorrect ids size", li.getIdentities().size(), is(1));
		try {
			li.getIdentities().add(REMOTE1);
			fail("mutable identities");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new UnsupportedOperationException());
		}
		assertThat("incorrect ids size", li.getIdentities().size(), is(1));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new HashSet<>(Arrays.asList(REMOTE1)), Instant.now(),
				new NullPointerException("user"));
		failConstruct(AUTH_USER, (Set<RemoteIdentity>) null, Instant.now(),
				new IllegalArgumentException("No remote IDs provided"));
		failConstruct(AUTH_USER, new HashSet<>(), Instant.now(),
				new IllegalArgumentException("No remote IDs provided"));
		failConstruct(AUTH_USER, TestCommon.set(REMOTE1, null), Instant.now(),
				new NullPointerException("null item in ids"));
		failConstruct(AUTH_USER, new HashSet<>(Arrays.asList(REMOTE1)), null,
				new NullPointerException("expires"));
		
		failConstruct(null, "foo", new NullPointerException("user"));
		failConstruct(AUTH_USER, (String) null,
				new IllegalArgumentException("provider cannot be null or empty"));
		failConstruct(AUTH_USER, "    \t \n   ",
				new IllegalArgumentException("provider cannot be null or empty"));
	}
	
	private void failConstruct(
			final AuthUser au,
			final Set<RemoteIdentity> ids,
			final Instant expires,
			final Exception e) {
		try {
			new LinkIdentities(au, ids, expires);
			fail("created bad LinkIdentities");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failConstruct(
			final AuthUser au,
			final String provider,
			final Exception e) {
		try {
			new LinkIdentities(au, provider);
			fail("created bad LinkIdentities");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}
