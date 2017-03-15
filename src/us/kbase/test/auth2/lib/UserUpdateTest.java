package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.test.auth2.TestCommon;

public class UserUpdateTest {

	@Test
	public void noUpdates() {
		final UserUpdate uu = new UserUpdate();
		assertThat("incorrect display name", uu.getDisplayName(), is(Optional.absent()));
		assertThat("incorrect email", uu.getEmail(), is(Optional.absent()));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(false));
	}
	
	@Test
	public void withDisplay() throws Exception {
		final UserUpdate uu = new UserUpdate().withDisplayName(new DisplayName("foo"));
		assertThat("incorrect display name", uu.getDisplayName(),
				is(Optional.of(new DisplayName("foo"))));
		assertThat("incorrect email", uu.getEmail(), is(Optional.absent()));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(true));
	}
	
	@Test
	public void withEmail() throws Exception {
		final UserUpdate uu = new UserUpdate().withEmail(new EmailAddress("f@b.com"));
		assertThat("incorrect display name", uu.getDisplayName(), is(Optional.absent()));
		assertThat("incorrect email", uu.getEmail(), is(Optional.of(new EmailAddress("f@b.com"))));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(true));
	}

	@Test
	public void withEmailAndDisplay() throws Exception {
		final UserUpdate uu = new UserUpdate().withEmail(new EmailAddress("f@b.com"))
				.withDisplayName(new DisplayName("foo"));
		assertThat("incorrect display name", uu.getDisplayName(),
				is(Optional.of(new DisplayName("foo"))));
		assertThat("incorrect email", uu.getEmail(), is(Optional.of(new EmailAddress("f@b.com"))));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(true));
	}
	
	@Test
	public void nulls() throws Exception {
		failUpdate(null, new EmailAddress("b@g.com"), new NullPointerException("displayName"));
		failUpdate(new DisplayName("foo"), null, new NullPointerException("email"));
	}

	private void failUpdate(
			final DisplayName displayName,
			final EmailAddress emailAddress,
			final Exception e) {
		try {
			new UserUpdate().withDisplayName(displayName).withEmail(emailAddress);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
