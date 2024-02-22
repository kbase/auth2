package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.inst;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.TestCommon.opt;
import static us.kbase.test.auth2.TestCommon.ES;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

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
	public void constructLoginStart() throws Exception {
		final UUID id = UUID.randomUUID();
		final TemporarySessionData ti = TemporarySessionData.create(id, inst(10000), inst(20000))
				.login("stategoeshere", "pkcegoeshere");
		
		assertThat("incorrect op", ti.getOperation(), is(Operation.LOGINSTART));
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(inst(10000)));
		assertThat("incorrect expires", ti.getExpires(), is(inst(20000)));
		assertThat("incorrect state", ti.getOAuth2State(), is(opt("stategoeshere")));
		assertThat("incorrect pkce", ti.getPKCECodeVerifier(), is(opt("pkcegoeshere")));
		assertThat("incorrect user", ti.getUser(), is(Optional.empty()));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.empty()));
		assertThat("incorrect error", ti.getError(), is(Optional.empty()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.empty()));
		assertThat("incorrect has error", ti.hasError(), is(false));
	}
	
	@Test
	public void constructLoginIdents() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData ti = TemporarySessionData.create(
				id, now, now.plusMillis(100000)).login(set(REMOTE1, REMOTE2));
		
		assertThat("incorrect op", ti.getOperation(), is(Operation.LOGINIDENTS));
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(now.plusMillis(100000)));
		assertThat("incorrect state", ti.getOAuth2State(), is(ES));
		assertThat("incorrect pkce", ti.getPKCECodeVerifier(), is(ES));
		assertThat("incorrect user", ti.getUser(), is(Optional.empty()));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.of(set(REMOTE2, REMOTE1))));
		assertThat("incorrect error", ti.getError(), is(Optional.empty()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.empty()));
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
		assertThat("incorrect state", ti.getOAuth2State(), is(ES));
		assertThat("incorrect pkce", ti.getPKCECodeVerifier(), is(ES));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.empty()));
		assertThat("incorrect user", ti.getUser(), is(Optional.empty()));
		assertThat("incorrect error", ti.getError(), is(Optional.of("foo")));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.of(ErrorType.DISABLED)));
		assertThat("incorrect has error", ti.hasError(), is(true));
	}
	
	@Test
	public void constructLinkStart() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData ti = TemporarySessionData.create(
				id, now, now.plusMillis(10000)).link("somestate", "pkce", new UserName("bar"));
		
		assertThat("incorrect op", ti.getOperation(), is(Operation.LINKSTART));
		assertThat("incorrect id", ti.getId(), is(id));
		assertThat("incorrect created", ti.getCreated(), is(now));
		assertThat("incorrect expires", ti.getExpires(), is(now.plusMillis(10000)));
		assertThat("incorrect state", ti.getOAuth2State(), is(opt("somestate")));
		assertThat("incorrect pkce", ti.getPKCECodeVerifier(), is(opt("pkce")));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.empty()));
		assertThat("incorrect user", ti.getUser(), is(Optional.of(new UserName("bar"))));
		assertThat("incorrect error", ti.getError(), is(Optional.empty()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.empty()));
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
		assertThat("incorrect state", ti.getOAuth2State(), is(ES));
		assertThat("incorrect pkce", ti.getPKCECodeVerifier(), is(ES));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.of(set(REMOTE1, REMOTE2))));
		assertThat("incorrect user", ti.getUser(), is(Optional.of(new UserName("bar"))));
		assertThat("incorrect error", ti.getError(), is(Optional.empty()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.empty()));
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
		assertThat("incorrect state", ti.getOAuth2State(), is(ES));
		assertThat("incorrect pkce", ti.getPKCECodeVerifier(), is(ES));
		assertThat("incorrect idents", ti.getIdentities(), is(Optional.of(set(REMOTE1, REMOTE2))));
		assertThat("incorrect user", ti.getUser(), is(Optional.of(new UserName("bar"))));
		assertThat("incorrect error", ti.getError(), is(Optional.empty()));
		assertThat("incorrect error type", ti.getErrorType(), is(Optional.empty()));
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
	public void constructLoginStartFailBadInput() throws Exception {
		failConstructLoginStart(null, "p",
				new IllegalArgumentException("oauth2State cannot be null or whitespace only"));
		failConstructLoginStart(" \t   ", "p",
				new IllegalArgumentException("oauth2State cannot be null or whitespace only"));
		failConstructLoginStart("s", null, new IllegalArgumentException(
				"pkceCodeVerifier cannot be null or whitespace only"));
		failConstructLoginStart("s", "  \n   \t ", new IllegalArgumentException(
				"pkceCodeVerifier cannot be null or whitespace only"));
	}
	
	private void failConstructLoginStart(
			final String state,
			final String pkce,
			final Exception expected) {
		try {
			TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
					.login(state, pkce);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}

	@Test
	public void constructLoginIdentsFailNulls() throws Exception {
		failConstructLoginIdents(null, new NullPointerException("identities"));
		failConstructLoginIdents(
				set(REMOTE1, null), new NullPointerException("null item in identities"));
		failConstructLoginIdents(set(), new IllegalArgumentException("empty identities"));
	}
	
	private void failConstructLoginIdents(final Set<RemoteIdentity> idents, final Exception e) {
		try {
			TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
					.login(idents);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void constructLinkStartFailBadInput() throws Exception {
		final UserName u = new UserName("foo");
		failConstructLinkStart(null, "pcke", u,
				new IllegalArgumentException("oauth2State cannot be null or whitespace only"));
		failConstructLinkStart(" \t   ", "pkce", u,
				new IllegalArgumentException("oauth2State cannot be null or whitespace only"));
		failConstructLinkStart("state", null, u, new IllegalArgumentException(
				"pkceCodeVerifier cannot be null or whitespace only"));
		failConstructLinkStart("state", " ", u, new IllegalArgumentException(
				"pkceCodeVerifier cannot be null or whitespace only"));
		failConstructLinkStart("state", "pkce", null, new NullPointerException("userName"));
	}
	
	private void failConstructLinkStart(
			final String state,
			final String pkce,
			final UserName name,
			final Exception e) {
		try {
			TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
					.link(state, pkce, name);
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
		failConstructError(
				null, et, new IllegalArgumentException("error cannot be null or whitespace only"));
		failConstructError("  \t  ", et,
				new IllegalArgumentException("error cannot be null or whitespace only"));
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
