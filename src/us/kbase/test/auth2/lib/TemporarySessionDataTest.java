package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.TemporarySessionData;
import us.kbase.auth2.lib.TemporarySessionData.Operation;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.test.auth2.TestCommon;

public class TemporarySessionDataTest {
	
	private final static RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("foo", "bar"),
			new RemoteIdentityDetails("user", "full", "email"));
	
	private final static RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("foo1", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));

	@Test
	public void equals() {
		EqualsVerifier.forClass(TemporarySessionData.class).usingGetClass().verify();
	}
	
	@Test
	public void constructLogin() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData ti = TemporarySessionData.create(
				id, now, now.plusMillis(100000)).login(set(REMOTE1, REMOTE2));
		
		assertThat("incorrect op", ti.getOperation(), is(Operation.LOGIN));
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(now.plusMillis(100000)));
		assertThat("incorrect user", ti.getUser(), is(Optional.absent()));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.of(set(REMOTE2, REMOTE1))));
		assertThat("incorrect error", ti.getError(), is(Optional.absent()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.absent()));
		assertThat("incorrect has error", ti.hasError(), is(false));
		
		assertImmutable(ti);
	}
	
	@Test
	public void constructWithError() throws Exception {
		// also tests the alternate create() method
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData ti = TemporarySessionData.create(
				id, now, 10000).error("foo", ErrorType.DISABLED);
		
		assertThat("incorrect op", ti.getOperation(), is(Operation.ERROR));
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(now.plusMillis(10000)));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.absent()));
		assertThat("incorrect user", ti.getUser(), is(Optional.absent()));
		assertThat("incorrect error", ti.getError(), is(Optional.of("foo")));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.of(ErrorType.DISABLED)));
		assertThat("incorrect has error", ti.hasError(), is(true));
	}
	
	@Test
	public void constructLinkStart() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData ti = TemporarySessionData.create(
				id, now, now.plusMillis(10000)).link(new UserName("bar"));
		
		assertThat("incorrect op", ti.getOperation(), is(Operation.LINKSTART));
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(now.plusMillis(10000)));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.absent()));
		assertThat("incorrect user", ti.getUser(), is(Optional.of(new UserName("bar"))));
		assertThat("incorrect error", ti.getError(), is(Optional.absent()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.absent()));
		assertThat("incorrect has error", ti.hasError(), is(false));
	}
	
	
	@Test
	public void constructLinkIdents() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData ti = TemporarySessionData.create(
				id, now, now.plusMillis(10000))
				.link(new UserName("bar"), set(REMOTE2, REMOTE1));
		
		assertThat("incorrect op", ti.getOperation(), is(Operation.LINKIDENTS));
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(now.plusMillis(10000)));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.of(set(REMOTE1, REMOTE2))));
		assertThat("incorrect user", ti.getUser(), is(Optional.of(new UserName("bar"))));
		assertThat("incorrect error", ti.getError(), is(Optional.absent()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.absent()));
		assertThat("incorrect has error", ti.hasError(), is(false));
		
		assertImmutable(ti);
	}
	
	@Test
	public void constructExpireOverflows() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant create = Instant.MAX.minusMillis(1000);
		final TemporarySessionData ti = TemporarySessionData.create(id, create, 2000)
				.link(new UserName("bar"), set(REMOTE2, REMOTE1));
		
		assertThat("incorrect op", ti.getOperation(), is(Operation.LINKIDENTS));
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(create));
		assertThat("incorrect expires", ti.getExpires(), is(Instant.MAX));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.of(set(REMOTE1, REMOTE2))));
		assertThat("incorrect user", ti.getUser(), is(Optional.of(new UserName("bar"))));
		assertThat("incorrect error", ti.getError(), is(Optional.absent()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.absent()));
		assertThat("incorrect has error", ti.hasError(), is(false));
		
		assertImmutable(ti);
	}
	
	private void assertImmutable(final TemporarySessionData tsd) {
		try {
			tsd.getIdentities().get().add(new RemoteIdentity(
					new RemoteIdentityID("whoo", "whee"),
					new RemoteIdentityDetails("baz", "bar", "bat")));
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passes
		}
	}

	@Test
	public void constructStepOneFailNulls() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant c = Instant.now();
		final Instant e = c.plusMillis(10);
		failConstructStageOne(null, c, e, new NullPointerException("id"));
		failConstructStageOne(id, null, e, new NullPointerException("created"));
		failConstructStageOne(id, null, 200, new NullPointerException("created"));
		failConstructStageOne(id, c, null, new NullPointerException("expires"));
		failConstructStageOne(id, e, c, new IllegalArgumentException("expires is before created"));
		failConstructStageOne(id, e, -1, new IllegalArgumentException("lifetime must be >= 0"));
	}

	private void failConstructStageOne(
			final UUID id,
			final Instant created,
			final Instant expires,
			final Exception e) {
		try {
			TemporarySessionData.create(id, created, expires);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failConstructStageOne(
			final UUID id,
			final Instant created,
			final long expires,
			final Exception e) {
		try {
			TemporarySessionData.create(id, created, expires);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void constructLoginFailNulls() throws Exception {
		failConstructLogin(null, new NullPointerException("identities"));
		failConstructLogin(set(REMOTE1, null),
				new NullPointerException("null item in identities"));
		failConstructLogin(set(),
				new IllegalArgumentException("empty identities"));
	}
	
	private void failConstructLogin(
			final Set<RemoteIdentity> idents,
			final Exception e) {
		try {
			TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
					.login(idents);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void constructLinkStartFailNulls() throws Exception {
		failConstructLinkStart(null, new NullPointerException("userName"));
	}
	
	private void failConstructLinkStart(
			final UserName name,
			final Exception e) {
		try {
			TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
					.link(name);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void constructLinkIdentsFailNulls() throws Exception {
		final UserName un = new UserName("foo");
		final Set<RemoteIdentity> ids = set(REMOTE1);
		failConstructLinkIdents(null, ids, new NullPointerException("userName"));
		failConstructLinkIdents(un, null, new NullPointerException("identities"));
		failConstructLinkIdents(un, set(REMOTE1, null),
				new NullPointerException("null item in identities"));
		failConstructLinkIdents(un, set(),
				new IllegalArgumentException("empty identities"));
	}
	
	private void failConstructLinkIdents(
			final UserName name,
			final Set<RemoteIdentity> idents,
			final Exception e) {
		try {
			TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
					.link(name, idents);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void constructWithErrorFailNullsAndEmpties() throws Exception {
		final String err = "err";
		final ErrorType et = ErrorType.DISABLED;
		failConstructError(null, et, new IllegalArgumentException("Missing argument: error"));
		failConstructError("  \t  ", et,
				new IllegalArgumentException("Missing argument: error"));
		failConstructError(err, null, new NullPointerException("errorType"));
	}
	
	private void failConstructError(
			final String error,
			final ErrorType et,
			final Exception e) {
		try {
			TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
					.error(error, et);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
