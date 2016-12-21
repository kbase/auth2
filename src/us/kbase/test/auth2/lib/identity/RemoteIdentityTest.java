package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.identity.RemoteIdentityDetails;


public class RemoteIdentityTest {
	
	@Test
	public void detailsWithAllFields() throws Exception {
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("user", "full", "email");
		assertThat("incorrect username", dets.getUsername(), is("user"));
		assertThat("incorrect fullname", dets.getFullname(), is("full"));
		assertThat("incorrect email", dets.getEmail(), is("email"));
		assertThat("incorrect hashcode", dets.hashCode(), is(-1536596969));
		assertThat("incorrect toString()", dets.toString(),
				is("RemoteIdentityDetails [username=user, fullname=full, email=email]"));
	}
	
	@Test
	public void detailsWithEmptyFields() throws Exception {
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
	public void detailsFail() throws Exception {
		failCreateDetails(null);
		failCreateDetails("              \n       ");
	}
	
	private void failCreateDetails(final String user) {
		try {
			new RemoteIdentityDetails(user, "foo", "bar");
			fail("created bad user");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception msg", e.getMessage(),
					is("username cannot be null or empty"));
		}
	}
	
	@Test
	public void detailsEquals() throws Exception {
		final RemoteIdentityDetails dets = new RemoteIdentityDetails("foo", "bar", "baz");
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

}
