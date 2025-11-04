package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;


public class RemoteIdentityTest {
	
	@Test
	public void remoteDetailsWithAllFields() throws Exception {
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("user ", " full", "\temail");
		assertThat("incorrect username", dets.getUsername(), is("user"));
		assertThat("incorrect fullname", dets.getFullname(), is("full"));
		assertThat("incorrect email", dets.getEmail(), is("email"));
		assertThat("incorrect hashcode", dets.hashCode(), is(-1536596969));
		assertThat("incorrect toString()", dets.toString(),
				is("RemoteIdentityDetails [username=user, fullname=full, email=email]"));
	}
	
	@Test
	public void remoteDetailsWithEmptyFields() throws Exception {
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("user", "\t ", " \n");
		assertThat("incorrect username", dets.getUsername(), is("user"));
		assertThat("incorrect fullname", dets.getFullname(), is((String) null));
		assertThat("incorrect email", dets.getEmail(), is((String) null));
		assertThat("incorrect hashcode", dets.hashCode(), is(3629098));
		assertThat("incorrect toString()", dets.toString(),
				is("RemoteIdentityDetails [username=user, fullname=null, email=null]"));
		
		final RemoteIdentityDetails dets2 = new RemoteIdentityDetails("user", null, null);
		assertThat("incorrect username", dets2.getUsername(), is("user"));
		assertThat("incorrect fullname", dets2.getFullname(), is((String) null));
		assertThat("incorrect email", dets2.getEmail(), is((String) null));
		assertThat("incorrect hashcode", dets2.hashCode(), is(3629098));
		assertThat("incorrect toString()", dets2.toString(),
				is("RemoteIdentityDetails [username=user, fullname=null, email=null]"));
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
		assertThat("incorrect hashcode", id.hashCode(), is(3118804));
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
		assertThat("incorrect hashcode", ri.hashCode(), is(4039350));
		assertThat("incorrect toString()", ri.toString(),
				is("RemoteIdentity [remoteID=RemoteIdentityID [provider=p, id=i], " +
						"details=RemoteIdentityDetails [username=u, fullname=f, email=e]]"));
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
}
