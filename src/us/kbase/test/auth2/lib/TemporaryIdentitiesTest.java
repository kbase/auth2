package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.TemporaryIdentities;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.test.auth2.TestCommon;

public class TemporaryIdentitiesTest {
	
	private final static RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("foo", "bar"),
			new RemoteIdentityDetails("user", "full", "email"));
	
	private final static RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("foo1", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));

	@Test
	public void equals() {
		EqualsVerifier.forClass(TemporaryIdentities.class).usingGetClass().verify();
	}
	
	@Test
	public void construct() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporaryIdentities ti = new TemporaryIdentities(
				id, now, Instant.ofEpochMilli(10000), set(REMOTE1, REMOTE2));
		
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(Instant.ofEpochMilli(10000)));
		assertThat("incorrect idents", ti.getIdentities(), is(set(REMOTE2, REMOTE1)));
	}
	
	@Test
	public void immutable() throws Exception {
		final TemporaryIdentities ti = new TemporaryIdentities(
				UUID.randomUUID(), Instant.now(), Instant.now(), set());
		
		try {
			ti.getIdentities().add(REMOTE1);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new UnsupportedOperationException());
		}
	}
	
	@Test
	public void constructFailNulls() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant c = Instant.now();
		final Instant e = Instant.ofEpochMilli(10000);
		final Set<RemoteIdentity> ris = Collections.emptySet();
		failConstruct(null, c, e, ris, new NullPointerException("id"));
		failConstruct(id, null, e, ris, new NullPointerException("created"));
		failConstruct(id, c, null, ris, new NullPointerException("expires"));
		failConstruct(id, c, e, null, new NullPointerException("identities"));
		failConstruct(id, c, e, set(REMOTE1, null),
				new NullPointerException("null item in identities"));
		
	}
	
	private void failConstruct(
			final UUID id,
			final Instant created,
			final Instant expires,
			final Set<RemoteIdentity> identities,
			final Exception e) {
		try {
			new TemporaryIdentities(id, created, expires, identities);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
