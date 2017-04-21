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

import com.google.common.base.Optional;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.TemporaryIdentities;
import us.kbase.auth2.lib.exceptions.ErrorType;
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
	public void constructWithIDs() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporaryIdentities ti = new TemporaryIdentities(
				id, now, Instant.ofEpochMilli(10000), set(REMOTE1, REMOTE2));
		
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(Instant.ofEpochMilli(10000)));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.of(set(REMOTE2, REMOTE1))));
		assertThat("incorrect error", ti.getError(), is(Optional.absent()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.absent()));
		assertThat("incorrect has error", ti.hasError(), is(false));
	}
	
	@Test
	public void constructWithError() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporaryIdentities ti = new TemporaryIdentities(
				id, now, Instant.ofEpochMilli(10000), "foo", ErrorType.DISABLED);
		
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(Instant.ofEpochMilli(10000)));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.absent()));
		assertThat("incorrect error", ti.getError(), is(Optional.of("foo")));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.of(ErrorType.DISABLED)));
		assertThat("incorrect has error", ti.hasError(), is(true));
	}
	
	@Test
	public void immutable() throws Exception {
		final TemporaryIdentities ti = new TemporaryIdentities(
				UUID.randomUUID(), Instant.now(), Instant.now(), set());
		
		try {
			ti.getIdentities().get().add(REMOTE1);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new UnsupportedOperationException());
		}
	}
	
	@Test
	public void constructWithIDsFailNulls() throws Exception {
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
	
	@Test
	public void constructWithErrorFailNullsAndEmpties() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant c = Instant.now();
		final Instant e = Instant.ofEpochMilli(10000);
		final String err = "err";
		final ErrorType et = ErrorType.DISABLED;
		failConstruct(null, c, e, err, et, new NullPointerException("id"));
		failConstruct(id, null, e, err, et, new NullPointerException("created"));
		failConstruct(id, c, null, err, et, new NullPointerException("expires"));
		failConstruct(id, c, e, null, et, new IllegalArgumentException("Missing argument: error"));
		failConstruct(id, c, e, "  \t  ", et,
				new IllegalArgumentException("Missing argument: error"));
		failConstruct(id, c, e, err, null, new NullPointerException("errorType"));
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
	
	private void failConstruct(
			final UUID id,
			final Instant created,
			final Instant expires,
			final String error,
			final ErrorType et,
			final Exception e) {
		try {
			new TemporaryIdentities(id, created, expires, error, et);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
