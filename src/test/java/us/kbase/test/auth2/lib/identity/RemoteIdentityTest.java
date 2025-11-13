package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.MfaStatus;
import us.kbase.auth2.lib.identity.RemoteIdentityID;


public class RemoteIdentityTest {
	
	@Test
	public void remoteDetailsWithAllFields() throws Exception {
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("user ", " full", "\temail");
		assertThat("incorrect username", dets.getUsername(), is("user"));
		assertThat("incorrect fullname", dets.getFullname(), is("full"));
		assertThat("incorrect email", dets.getEmail(), is("email"));
		assertThat("incorrect toString()", dets.toString(),
				is("RemoteIdentityDetails [username=user, fullname=full, email=email, mfa=UNKNOWN]"));
	}
	
	@Test
	public void remoteDetailsWithEmptyFields() throws Exception {
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("user", "\t ", " \n");
		assertThat("incorrect username", dets.getUsername(), is("user"));
		assertThat("incorrect fullname", dets.getFullname(), is((String) null));
		assertThat("incorrect email", dets.getEmail(), is((String) null));
		assertThat("incorrect toString()", dets.toString(),
				is("RemoteIdentityDetails [username=user, fullname=null, email=null, mfa=UNKNOWN]"));

		final RemoteIdentityDetails dets2 = new RemoteIdentityDetails("user", null, null);
		assertThat("incorrect username", dets2.getUsername(), is("user"));
		assertThat("incorrect fullname", dets2.getFullname(), is((String) null));
		assertThat("incorrect email", dets2.getEmail(), is((String) null));
		assertThat("incorrect toString()", dets2.toString(),
				is("RemoteIdentityDetails [username=user, fullname=null, email=null, mfa=UNKNOWN]"));
	}
	
	@Test
	public void remoteDetailsFail() throws Exception {
		failCreateDetails(null);
		failCreateDetails("              \n       ");
	}
	
	private void failCreateDetails(final String user) {
		try {
			new RemoteIdentityDetails(user, "foo", "bar");
			fail("created bad details");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception msg", e.getMessage(),
					is("username cannot be null or empty"));
		}
	}
	
	@Test
	public void remoteDetailsEquals() throws Exception {
		EqualsVerifier.forClass(RemoteIdentityDetails.class).usingGetClass().verify();
	}

	@Test
	public void remoteId() throws Exception {
		final RemoteIdentityID id = new RemoteIdentityID("foo", "bar");
		assertThat("incorrect provider name", id.getProviderName(), is("foo"));
		assertThat("incorrect provider id", id.getProviderIdentityId(), is("bar"));
		assertThat("incorrect unique id", id.getID(), is("5c7d96a3dd7a87850a2ef34087565a6e"));
		// check unique id again to check memoization doesn't change result
		assertThat("incorrect unique id", id.getID(), is("5c7d96a3dd7a87850a2ef34087565a6e"));
		assertThat("incorrect toString()", id.toString(),
				is("RemoteIdentityID [provider=foo, id=bar]"));
	}
	
	@Test
	public void remoteIdEquals() throws Exception {
		EqualsVerifier.forClass(RemoteIdentityID.class).usingGetClass()
				.withIgnoredFields("memoizedID").verify();
	}
	
	@Test
	public void remoteIDFail() throws Exception {
		final String providererr = "provider cannot be null or empty";
		final String iderr = "id cannot be null or empty";
		failCreateID(null, "f", providererr);
		failCreateID(" \t", "f", providererr);
		failCreateID("p", null, iderr);
		failCreateID("p", " \n   \t  ", iderr);
		
	}
	
	private void failCreateID(final String provider, final String id, final String exception) {
		try {
			new RemoteIdentityID(provider, id);
			fail("created bad id");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception msg", e.getMessage(),
					is(exception));
		}
	}
	
	@Test
	public void identity() throws Exception {
		final RemoteIdentityID id = new RemoteIdentityID("p", "i");
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("u", "f", "e");
		final RemoteIdentity ri = new RemoteIdentity(id, dets);
		assertThat("incorrect id", ri.getRemoteID(), is(id));
		assertThat("incorrect details", ri.getDetails(), is(dets));
		assertThat("incorrect toString()", ri.toString(),
				is("RemoteIdentity [remoteID=RemoteIdentityID [provider=p, id=i], " +
						"details=RemoteIdentityDetails [username=u, fullname=f, email=e, mfa=UNKNOWN]]"));
	}
	
	@Test
	public void identityEquals() throws Exception {
		EqualsVerifier.forClass(RemoteIdentity.class).usingGetClass().verify();
	}
	
	@Test
	public void identityFail() throws Exception {
		failCreateIdentity(null, new RemoteIdentityDetails("u", "f", "e"), "remoteID");
		failCreateIdentity(new RemoteIdentityID("p", "i"), null, "details");
	}
	
	private void failCreateIdentity(
			final RemoteIdentityID remoteID,
			final RemoteIdentityDetails details,
			final String exception) {
		try {
			new RemoteIdentity(remoteID, details);
			fail("created bad identity");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is(exception));
		}
	}

	@Test
	public void compareToSameProviderSameUsername() throws Exception {
		final RemoteIdentity id1 = new RemoteIdentity(
				new RemoteIdentityID("google", "123"),
				new RemoteIdentityDetails("alice", "Alice", "alice@example.com"));
		final RemoteIdentity id2 = new RemoteIdentity(
				new RemoteIdentityID("google", "456"),
				new RemoteIdentityDetails("alice", "Alice Smith", "alice@gmail.com"));

		assertThat("should be equal when provider and username match", id1.compareTo(id2), is(0));
	}

	@Test
	public void compareToSameProviderDifferentUsername() throws Exception {
		final RemoteIdentity id1 = new RemoteIdentity(
				new RemoteIdentityID("google", "123"),
				new RemoteIdentityDetails("alice", "Alice", "alice@example.com"));
		final RemoteIdentity id2 = new RemoteIdentity(
				new RemoteIdentityID("google", "456"),
				new RemoteIdentityDetails("bob", "Bob", "bob@example.com"));

		assertThat("alice should come before bob", id1.compareTo(id2) < 0, is(true));
		assertThat("bob should come after alice", id2.compareTo(id1) > 0, is(true));
	}

	@Test
	public void compareToDifferentProviderSameUsername() throws Exception {
		final RemoteIdentity id1 = new RemoteIdentity(
				new RemoteIdentityID("globus", "123"),
				new RemoteIdentityDetails("alice", "Alice", "alice@example.com"));
		final RemoteIdentity id2 = new RemoteIdentity(
				new RemoteIdentityID("google", "456"),
				new RemoteIdentityDetails("alice", "Alice", "alice@example.com"));

		assertThat("globus should come before google", id1.compareTo(id2) < 0, is(true));
		assertThat("google should come after globus", id2.compareTo(id1) > 0, is(true));
	}

	@Test
	public void compareToDifferentProviderDifferentUsername() throws Exception {
		final RemoteIdentity id1 = new RemoteIdentity(
				new RemoteIdentityID("globus", "123"),
				new RemoteIdentityDetails("zoe", "Zoe", "zoe@example.com"));
		final RemoteIdentity id2 = new RemoteIdentity(
				new RemoteIdentityID("google", "456"),
				new RemoteIdentityDetails("alice", "Alice", "alice@example.com"));

		// Provider takes precedence: globus < google, regardless of username
		assertThat("globus should come before google", id1.compareTo(id2) < 0, is(true));
		assertThat("google should come after globus", id2.compareTo(id1) > 0, is(true));
	}

	@Test
	public void compareToNullFails() throws Exception {
		final RemoteIdentity id = new RemoteIdentity(
				new RemoteIdentityID("google", "123"),
				new RemoteIdentityDetails("alice", "Alice", "alice@example.com"));

		try {
			id.compareTo(null);
			fail("expected NullPointerException");
		} catch (NullPointerException e) {
			assertThat("incorrect exception msg", e.getMessage(), is("other"));
		}
	}

	@Test
	public void remoteDetailsWithMfaStatuses() throws Exception {
		// Test USED status
		final RemoteIdentityDetails detsUsed = new RemoteIdentityDetails("user", "full", "email", MfaStatus.USED);
		assertThat("incorrect username", detsUsed.getUsername(), is("user"));
		assertThat("incorrect fullname", detsUsed.getFullname(), is("full"));
		assertThat("incorrect email", detsUsed.getEmail(), is("email"));
		assertThat("incorrect mfa status", detsUsed.getMfa(), is(MfaStatus.USED));
		assertThat("toString should contain mfa status", detsUsed.toString(), containsString("mfa=USED"));

		// Test NOT_USED status
		final RemoteIdentityDetails detsNotUsed = new RemoteIdentityDetails("user", "full", "email", MfaStatus.NOT_USED);
		assertThat("incorrect mfa status", detsNotUsed.getMfa(), is(MfaStatus.NOT_USED));
		assertThat("toString should contain mfa status", detsNotUsed.toString(), containsString("mfa=NOT_USED"));

		// Test UNKNOWN status
		final RemoteIdentityDetails detsUnknown = new RemoteIdentityDetails("user", "full", "email", MfaStatus.UNKNOWN);
		assertThat("incorrect mfa status", detsUnknown.getMfa(), is(MfaStatus.UNKNOWN));
		assertThat("toString should contain mfa status", detsUnknown.toString(), containsString("mfa=UNKNOWN"));
	}

	@Test
	public void remoteDetailsMfaFailWithNullUser() throws Exception {
		try {
			new RemoteIdentityDetails(null, "full", "email", MfaStatus.USED);
			fail("created bad details with mfa");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception msg", e.getMessage(),
					is("username cannot be null or empty"));
		}
	}

	@Test
	public void mfaStatusGetDescription() throws Exception {
		assertThat("incorrect Used description", MfaStatus.USED.getDescription(), is("MFA used"));
		assertThat("incorrect NotUsed description", MfaStatus.NOT_USED.getDescription(), is("MFA not used"));
		assertThat("incorrect Unknown description", MfaStatus.UNKNOWN.getDescription(), is("MFA status unknown"));
	}

	@Test
	public void mfaStatusIDsAreStableForSerialization() throws Exception {
		// These IDs are persisted to database via JSON serialization and must never change.
		// Changing these values would break backwards compatibility with existing tokens
		// and user data stored in MongoDB.
		assertThat("USED ID must be stable", MfaStatus.USED.getID(), is("Used"));
		assertThat("NOT_USED ID must be stable", MfaStatus.NOT_USED.getID(), is("NotUsed"));
		assertThat("UNKNOWN ID must be stable", MfaStatus.UNKNOWN.getID(), is("Unknown"));
	}

	@Test
	public void mfaStatusFromIDValidValues() throws Exception {
		assertThat("incorrect fromID for Used", MfaStatus.fromID("Used"), is(MfaStatus.USED));
		assertThat("incorrect fromID for NotUsed", MfaStatus.fromID("NotUsed"), is(MfaStatus.NOT_USED));
		assertThat("incorrect fromID for Unknown", MfaStatus.fromID("Unknown"), is(MfaStatus.UNKNOWN));
	}

	@Test
	public void mfaStatusFromIDNullOrEmpty() throws Exception {
		try {
			MfaStatus.fromID(null);
			fail("expected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("Invalid MFA status: null"));
		}
		try {
			MfaStatus.fromID("");
			fail("expected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("Invalid MFA status: "));
		}
	}

	@Test
	public void mfaStatusFromIDUnrecognized() throws Exception {
		try {
			MfaStatus.fromID("INVALID");
			fail("expected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("Invalid MFA status: INVALID"));
		}
		try {
			MfaStatus.fromID("used");
			fail("expected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is("Invalid MFA status: used"));
		}
	}
}
