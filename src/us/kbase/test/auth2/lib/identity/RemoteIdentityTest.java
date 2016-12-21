package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;


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
		final RemoteIdentityDetails dets = new RemoteIdentityDetails(" foo", "bar ", "\nbaz");
		final RemoteIdentityDetails nulldets = new RemoteIdentityDetails("foo", null, null);
		
		//identity
		assertThat("incorrect equals", dets.equals(dets), is(true));
		//equal
		assertThat("incorrect equals", dets.equals(
				new RemoteIdentityDetails("foo", "bar", "baz")), is(true));
		assertThat("incorrect equals", nulldets.equals(
				new RemoteIdentityDetails("foo", null, null)), is(true));
		//null obj
		assertThat("incorrect equals", dets.equals(null), is(false));
		//class
		assertThat("incorrect equals", dets.equals(new Object()), is(false));

		//unequal user
		assertThat("incorrect equals", dets.equals(
				new RemoteIdentityDetails("fo", "bar", "baz")), is(false));
		
		//null full 1
		assertThat("incorrect equals", dets.equals(
				new RemoteIdentityDetails("foo", null, "baz")), is(false));
		//null full 2
		assertThat("incorrect equals", nulldets.equals(
				new RemoteIdentityDetails("foo", "bar", null)), is(false));
		//unequal full
		assertThat("incorrect equals", dets.equals(
				new RemoteIdentityDetails("foo", "bad", "baz")), is(false));
		
		//null email 1
		assertThat("incorrect equals", dets.equals(
				new RemoteIdentityDetails("foo", "bar", null)), is(false));
		//null email 2
		assertThat("incorrect equals", nulldets.equals(
				new RemoteIdentityDetails("foo", null, "baz")), is(false));
		//unequal email
		assertThat("incorrect equals", dets.equals(
				new RemoteIdentityDetails("foo", "bar", "bad")), is(false));
	}

	@Test
	public void remoteId() throws Exception {
		final RemoteIdentityID id = new RemoteIdentityID("foo", "bar");
		assertThat("incorrect provider name", id.getProvider(), is("foo"));
		assertThat("incorrect provider id", id.getId(), is("bar"));
		assertThat("incorrect hashcode", id.hashCode(), is(3118804));
		assertThat("incorrect toString()", id.toString(),
				is("RemoteIdentityID [provider=foo, id=bar]"));
	}
	
	@Test
	public void remoteIdEquals() throws Exception {
		final RemoteIdentityID id = new RemoteIdentityID("whee", "whoo");
		
		//identity
		assertThat("incorrect equals", id.equals(id), is(true));
		//equal
		assertThat("incorrect equals", id.equals(new RemoteIdentityID("whee", "whoo")), is(true));
		//null obj
		assertThat("incorrect equals", id.equals(null), is(false));
		//class
		assertThat("incorrect equals", id.equals(new Object()), is(false));
		//unequal provider
		assertThat("incorrect equals", id.equals(new RemoteIdentityID("wheo", "whoo")), is(false));
		//unequal id
		assertThat("incorrect equals", id.equals(new RemoteIdentityID("whee", "whoe")), is(false));
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
		
		final RemoteIdentityWithLocalID ril = ri.withID();
		assertThat("incorrect local id class", ril.getID(), is(UUID.class));
		assertThat("incorrect id", ril.getRemoteID(), is(id));
		assertThat("incorrect details", ril.getDetails(), is(dets));
		
		final RemoteIdentityID id2 = new RemoteIdentityID("p2", "i");
		final RemoteIdentityDetails dets2 = new RemoteIdentityDetails("u2", "f", "e");
		final RemoteIdentity ri2 = new RemoteIdentity(id2, dets2);
		
		final UUID uuid = UUID.randomUUID();
		final RemoteIdentityWithLocalID ril2 = ri2.withID(uuid);
		assertThat("incorrect local id class", ril2.getID(), is(uuid));
		assertThat("incorrect id", ril2.getRemoteID(), is(id2));
		assertThat("incorrect details", ril2.getDetails(), is(dets2));
		
		try {
			ri2.withID(null);
			fail("created bad remote id");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("id"));
		}
	}
	
	@Test
	public void identityEquals() throws Exception {
		final RemoteIdentityID id = new RemoteIdentityID("p", "i");
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("u", "f", "e");
		final RemoteIdentity ri = new RemoteIdentity(id, dets);
		
		//identity
		assertThat("incorrect equals", ri.equals(ri), is(true));
		//equal
		assertThat("incorrect equals", ri.equals(new RemoteIdentity(new RemoteIdentityID("p", "i"),
				new RemoteIdentityDetails("u", "f", "e"))), is(true));
		//null obj
		assertThat("incorrect equals", ri.equals(null), is(false));
		//class
		assertThat("incorrect equals", ri.equals(new Object()), is(false));
		//id
		assertThat("incorrect equals", ri.equals(new RemoteIdentity(
				new RemoteIdentityID("q", "i"), dets)), is(false));
		//details
		assertThat("incorrect equals", ri.equals(new RemoteIdentity(
				id, new RemoteIdentityDetails("t", "f", "e"))), is(false));
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
	public void identityLocalID() throws Exception {
		final UUID id = UUID.fromString("8c3a3495-50fe-46aa-8e6b-d447e9ecfa46");
		final RemoteIdentityID rid = new RemoteIdentityID("p", "i");
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("u", "f", "e");
		final RemoteIdentityWithLocalID ri = new RemoteIdentityWithLocalID(id, rid, dets);
		assertThat("incorrect id", ri.getID(), is(id));
		assertThat("incorrect remote id", ri.getRemoteID(), is(rid));
		assertThat("incorrect details", ri.getDetails(), is(dets));
		assertThat("incorrect hashcode", ri.hashCode(), is(-1027993528));
		assertThat("incorrect toString()", ri.toString(),
				is("RemoteIdentityWithLocalID [id=8c3a3495-50fe-46aa-8e6b-d447e9ecfa46, " +
						"getRemoteID()=RemoteIdentityID [provider=p, id=i], " +
						"getDetails()=RemoteIdentityDetails [username=u, fullname=f, email=e]]"));
	}
	
	@Test
	public void identityLocalIDfail() throws Exception {
		final UUID id = UUID.fromString("8c3a3495-50fe-46aa-8e6b-d447e9ecfa46");
		final RemoteIdentityID rid = new RemoteIdentityID("p", "i");
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("u", "f", "e");
		failCreateIdentWithLocalID(null, rid, dets, "id");
		failCreateIdentWithLocalID(id, null, dets, "remoteID");
		failCreateIdentWithLocalID(id, rid, null, "details");
	}
	
	private void failCreateIdentWithLocalID(
			final UUID id,
			final RemoteIdentityID rid,
			final RemoteIdentityDetails dets,
			final String exception) {
		try {
			new RemoteIdentityWithLocalID(id, rid, dets);
			fail("created bad remote id");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is(exception));
		}
	}
	
	@Test
	public void identityLocalIDequals() throws Exception {
		final UUID id = UUID.fromString("8c3a3495-50fe-46aa-8e6b-d447e9ecfa46");
		final RemoteIdentityID rid = new RemoteIdentityID("p", "i");
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("u", "f", "e");
		final RemoteIdentityWithLocalID ri = new RemoteIdentityWithLocalID(id, rid, dets);
		
		//identity
		assertThat("incorrect equals", ri.equals(ri), is(true));
		//equal
		assertThat("incorrect equals", ri.equals(new RemoteIdentityWithLocalID(
				id, new RemoteIdentityID("p", "i"), new RemoteIdentityDetails("u", "f", "e"))),
				is(true));
		//null obj
		assertThat("incorrect equals", ri.equals(null), is(false));
		//class
		assertThat("incorrect equals", ri.equals(new Object()), is(false));
		//id
		assertThat("incorrect equals", ri.equals(new RemoteIdentityWithLocalID(
				UUID.fromString("8c3a3495-50fe-46aa-8e6b-d447e9ecfa47"), rid, dets)), is(false));
		//remote id
		assertThat("incorrect equals", ri.equals(new RemoteIdentityWithLocalID(
				id, new RemoteIdentityID("q", "i"), dets)), is(false));
		//details
		assertThat("incorrect equals", ri.equals(new RemoteIdentityWithLocalID(
				id, rid, new RemoteIdentityDetails("t", "f", "e"))), is(false));
	}
	
}
