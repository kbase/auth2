package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Optional;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.test.auth2.TestCommon;

public class UserUpdateTest {
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(UserUpdate.class).usingGetClass().verify();
	}

	@Test
	public void noUpdates() {
		final UserUpdate uu = UserUpdate.getBuilder().build();
		assertThat("incorrect display name", uu.getDisplayName(), is(Optional.empty()));
		assertThat("incorrect email", uu.getEmail(), is(Optional.empty()));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(false));
	}
	
	@Test
	public void withDisplay() throws Exception {
		final UserUpdate uu = UserUpdate.getBuilder()
				.withDisplayName(new DisplayName("foo")).build();
		assertThat("incorrect display name", uu.getDisplayName(),
				is(Optional.of(new DisplayName("foo"))));
		assertThat("incorrect email", uu.getEmail(), is(Optional.empty()));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(true));
	}
	
	@Test
	public void withEmail() throws Exception {
		final UserUpdate uu = UserUpdate.getBuilder()
				.withEmail(new EmailAddress("f@b.com")).build();
		assertThat("incorrect display name", uu.getDisplayName(), is(Optional.empty()));
		assertThat("incorrect email", uu.getEmail(), is(Optional.of(new EmailAddress("f@b.com"))));
		assertThat("incorrect hasUpdates", uu.hasUpdates(), is(true));
	}

	@Test
	public void withEmailAndDisplay() throws Exception {
		final UserUpdate uu = UserUpdate.getBuilder().withEmail(new EmailAddress("f@b.com"))
				.withDisplayName(new DisplayName("foo")).build();
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
			UserUpdate.getBuilder().withDisplayName(displayName).withEmail(emailAddress);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
