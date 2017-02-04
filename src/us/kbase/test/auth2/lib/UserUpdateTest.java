package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserUpdate;

public class UserUpdateTest {

	@Test
	public void noUpdates() {
		final UserUpdate uu = new UserUpdate();
		assertThat("incorrect display name", uu.getDisplayName(), is((DisplayName) null));
		assertThat("incorrect email", uu.getEmail(), is((EmailAddress) null));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(false));
	}
	
	@Test
	public void withDisplay() throws Exception {
		final UserUpdate uu = new UserUpdate().withDisplayName(new DisplayName("foo"));
		assertThat("incorrect display name", uu.getDisplayName(), is(new DisplayName("foo")));
		assertThat("incorrect email", uu.getEmail(), is((EmailAddress) null));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(true));
	}
	
	@Test
	public void withEmail() throws Exception {
		final UserUpdate uu = new UserUpdate().withEmail(new EmailAddress("f@b.com"));
		assertThat("incorrect display name", uu.getDisplayName(), is((DisplayName) null));
		assertThat("incorrect email", uu.getEmail(), is(new EmailAddress("f@b.com")));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(true));
	}

	@Test
	public void withEmailAndDisplay() throws Exception {
		final UserUpdate uu = new UserUpdate().withEmail(new EmailAddress("f@b.com"))
				.withDisplayName(new DisplayName("foo"));
		assertThat("incorrect display name", uu.getDisplayName(), is(new DisplayName("foo")));
		assertThat("incorrect email", uu.getEmail(), is(new EmailAddress("f@b.com")));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(true));
	}

}
