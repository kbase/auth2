package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.ViewableUser;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

public class ViewableUserTest {
	
	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));

	@Test
	public void constructWithoutEmail() throws Exception {
		final AuthUser u = new NewUser(new UserName("foo"), new EmailAddress("e@f.com"),
				new DisplayName("bar"), REMOTE, Instant.now(), null);
		
		final ViewableUser vu = new ViewableUser(u, false);
		assertThat("incorrect username", vu.getUserName(), is(new UserName("foo")));
		assertThat("incorrect display name", vu.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", vu.getEmail(), is((EmailAddress) null));
	}
	
	@Test
	public void constructWithEmail() throws Exception {
		final AuthUser u = new NewUser(new UserName("foo"), new EmailAddress("e@f.com"),
				new DisplayName("bar"), REMOTE, Instant.now(), null);
		
		final ViewableUser vu = new ViewableUser(u, true);
		assertThat("incorrect username", vu.getUserName(), is(new UserName("foo")));
		assertThat("incorrect display name", vu.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", vu.getEmail(), is(new EmailAddress("e@f.com")));
	}
	
	@Test
	public void constructFail() throws Exception {
		try {
			new ViewableUser(null, true);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("user"));
		}
	}
}
