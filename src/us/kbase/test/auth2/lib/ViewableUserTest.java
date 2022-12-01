package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.Optional;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.ViewableUser;
import us.kbase.auth2.lib.user.AuthUser;

public class ViewableUserTest {
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(ViewableUser.class).usingGetClass().verify();
	}
	
	@Test
	public void constructWithoutEmail() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("e@f.com")).build();
		
		final ViewableUser vu = new ViewableUser(u, false);
		assertThat("incorrect username", vu.getUserName(), is(new UserName("foo")));
		assertThat("incorrect display name", vu.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", vu.getEmail(), is(Optional.empty()));
	}
	
	@Test
	public void constructWithEmail() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("e@f.com")).build();

		final ViewableUser vu = new ViewableUser(u, true);
		assertThat("incorrect username", vu.getUserName(), is(new UserName("foo")));
		assertThat("incorrect display name", vu.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", vu.getEmail(), is(Optional.of(new EmailAddress("e@f.com"))));
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
