package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.identity.IdentityProviderResponse;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.MFAStatus;
import us.kbase.test.auth2.TestCommon;

public class IdentityProviderResponseTest {

	private static final RemoteIdentity IDENT1 = new RemoteIdentity(
			new RemoteIdentityID("p", "i1"),
			new RemoteIdentityDetails("u1", "f", "e")
	);
	private static final RemoteIdentity IDENT2 = new RemoteIdentity(
			new RemoteIdentityID("p", "i2"),
			new RemoteIdentityDetails("u2", "f", "e")
	);
	private static final RemoteIdentity IDENT3 = new RemoteIdentity(
			new RemoteIdentityID("p", "i3"),
			new RemoteIdentityDetails("u3", "f", "e")
	);

	@Test
	public void testEquals() throws Exception {
		EqualsVerifier.forClass(IdentityProviderResponse.class).usingGetClass().verify();
	}
	
	@Test
	public void testConstructWithIdentity() {
		final IdentityProviderResponse response = IdentityProviderResponse.from(IDENT1);
		
		assertThat(response.getIdentities(), is(Collections.singleton(IDENT1)));
		assertThat(response.getMFA(), is(MFAStatus.UNKNOWN));
	}

	@Test
	public void testConstructWithIdentityAndMFA() {
		final IdentityProviderResponse response = IdentityProviderResponse.from(
				IDENT1, MFAStatus.USED);
		
		assertThat(response.getIdentities(), is(Collections.singleton(IDENT1)));
		assertThat(response.getMFA(), is(MFAStatus.USED));
	}

	@Test
	public void testConstructWithMultipleIdentities() {
		final Set<RemoteIdentity> idents = new HashSet<>(Arrays.asList(IDENT1, IDENT2));
		final IdentityProviderResponse response = IdentityProviderResponse.from(idents);
		
		assertThat(response.getIdentities(), is(new HashSet<>(Arrays.asList(IDENT1, IDENT2))));
		assertThat(response.getMFA(), is(MFAStatus.UNKNOWN));
	}

	@Test
	public void testConstructWithMultipleIdentitiesAndMFA() {
		final Set<RemoteIdentity> idents = new HashSet<>(Arrays.asList(IDENT1, IDENT2, IDENT3));
		final IdentityProviderResponse response = IdentityProviderResponse.from(
				idents, MFAStatus.NOT_USED);
		
		assertThat(response.getIdentities(), 
				is(new HashSet<>(Arrays.asList(IDENT1, IDENT2, IDENT3))));
		assertThat(response.getMFA(), is(MFAStatus.NOT_USED));
	}

	@Test
	public void testAllMFAStatuses() {
		for (final MFAStatus status : MFAStatus.values()) {
			final IdentityProviderResponse r1 = IdentityProviderResponse.from(IDENT1, status);
			assertThat(r1.getMFA(), is(status));
			final IdentityProviderResponse r2 = IdentityProviderResponse.from(
					Collections.singleton(IDENT1), status);
			assertThat(r2.getMFA(), is(status));
		}
	}

	@Test
	public void testImmutableIdentities() {
		final Set<RemoteIdentity> idents = new HashSet<>(Arrays.asList(IDENT1, IDENT2));
		final IdentityProviderResponse response = IdentityProviderResponse.from(idents);
		
		// Verify returned set is unmodifiable
		try {
			response.getIdentities().add(IDENT3);
			fail("Expected UnsupportedOperationException");
		} catch (UnsupportedOperationException e) {
			// expected
		}
		
		// Verify original set modification doesn't affect response
		idents.add(IDENT3);
		assertThat(response.getIdentities(), is(new HashSet<>(Arrays.asList(IDENT1, IDENT2))));
	}

	@Test
	public void testFailConstructWithIdentity() {
		try {
			IdentityProviderResponse.from((RemoteIdentity) null);
			fail("Expected NullPointerException");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new NullPointerException("identity"));
		}
	}
	
	@Test
	public void testFailConstructWithIdentitySet() {
		failConstructWithIdentitySet(null, new NullPointerException("identities"));
		failConstructWithIdentitySet(
				Collections.emptySet(),
				new IllegalArgumentException("Must provide at least one identity")
		);
	}
	
	private void failConstructWithIdentitySet(
			final Set<RemoteIdentity> ris,
			final Exception expected
	) {
		try {
			IdentityProviderResponse.from(ris);
			fail("Expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, expected);
		}
	}

	@Test
	public void testFailConstructWithIdentityAndMFA() {
		failConstructWithIdentityAndMFA(
				null, MFAStatus.UNKNOWN, new NullPointerException("identity")
		);
		failConstructWithIdentityAndMFA(IDENT1, null, new NullPointerException("mfa"));
	}
	
	private void failConstructWithIdentityAndMFA(
			final RemoteIdentity ri,
			final MFAStatus mfa,
			final Exception expected
	) {
		try {
			IdentityProviderResponse.from(ri, mfa);
			fail("Expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, expected);
		}
	}

	@Test
	public void testFailConstructWithIdentitySetAndMFA() {
		failConstructWithIdentitySetAndMFA(
				null, MFAStatus.UNKNOWN, new NullPointerException("identities")
		);
		failConstructWithIdentitySetAndMFA(Collections.emptySet(), MFAStatus.UNKNOWN,
				new IllegalArgumentException("Must provide at least one identity")
		);
		failConstructWithIdentitySetAndMFA(Collections.singleton(IDENT1), null,
				new NullPointerException("mfa")
		);
	}
	
	private void failConstructWithIdentitySetAndMFA(
			final Set<RemoteIdentity> ris,
			final MFAStatus mfa,
			final Exception expected
	) {
		try {
			IdentityProviderResponse.from(ris, mfa);
			fail("Expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, expected);
		}
	}

}
